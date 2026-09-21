//! The order things happen in, and who waits for whom.
//!
//! ```text
//!   axum /v1/logs    ─► resolve ─► convert ─► mpsc<LogRow>    ─► batch ─► logs
//!   axum /v1/metrics ─► resolve ─► convert ─► mpsc<MetricRow> ─► batch ─► metrics
//!   axum /v1/traces  ─► resolve ×2 ─► convert ─► mpsc<SpanRow> ─► batch ─► spans
//!   (one server per tenant)                  (one batcher each, shared by all tenants)
//! ```
//!
//! # Three batchers, not one, and not one per tenant
//!
//! Three because they write different tables and `ClickHouse` wants each insert to be one
//! table's rows. Not one per tenant, because a batcher's whole purpose is to make inserts
//! **few and large**, and splitting by tenant would divide every batch by the number of
//! customers — an MSP with forty tenants would get forty small inserts where it wants one.
//! A row carries its own `tenant_id` and the sort key leads with it.
//!
//! # Why traces resolve twice
//!
//! M8 §2.1: a span ran on a **host** and is work done by a **service**, and the row
//! carries both. They are two resources and therefore two resolutions — of two *different*
//! identities, which is the part that took a schema change to get right. See
//! [`Listener::subjects`].
//!
//! # Where backpressure comes from
//!
//! The handler `send`s into a bounded channel and waits. A slow `ClickHouse` slows the
//! batcher, fills the channel, and makes the handler wait — which makes the exporter wait
//! on its HTTP response, which is what HTTP is for. Nothing is dropped and nothing gets a
//! 429: telling a collector to go away and come back is worse than making it wait.
//!
//! That is the substantive difference from the syslog daemon, where UDP has no back
//! channel and the only honest option is to drop and count.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use opentelemetry_proto::tonic::logs::v1::ResourceLogs;
use opentelemetry_proto::tonic::metrics::v1::ResourceMetrics;
use opentelemetry_proto::tonic::trace::v1::ResourceSpans;
use tokio::sync::mpsc;
use uops_core::{ObservedIdentity, ResourceId, SiteId, TenantId};
use uops_identity::Resolver;
use uops_pipeline::{Attribution, Enrichment, Pipeline, batch};
use uops_store_ch::{ChStore, LogRow, MetricRow, SpanRow};
use uops_store_pg::{PgEnricher, PgStore};

use crate::config::Config;
use crate::routes::Rejected;

/// The one way ingestion can fail here: there is nowhere left to put the rows.
///
/// A unit error would say the same thing and clippy is right that it says it badly — a
/// caller reading `Result<_, ()>` learns nothing about what went wrong, and the next
/// failure mode added would have nowhere to go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Stopped {
    /// The queue to the batcher has closed, which happens only during shutdown. The
    /// caller turns this into a 503, which OTLP defines as retryable — so the exporter
    /// comes back to the next instance rather than dropping the batch.
    #[error("the collector is shutting down")]
    ShuttingDown,
}

/// What the receiver has done, readable from outside it.
#[derive(Debug, Default)]
pub struct Metrics {
    pub log_records: AtomicU64,
    pub data_points: AtomicU64,
    /// Spans stored. It counted discards until M8 gave them somewhere to go.
    pub spans: AtomicU64,
    /// Data points in a metric type this build does not convert, plus points with no
    /// timestamp. Reported to the exporter as well; counted here so an operator can see
    /// it without reading their collector's logs.
    pub unsupported: AtomicU64,
    pub logs_batch: std::sync::Mutex<batch::Stats>,
    pub metrics_batch: std::sync::Mutex<batch::Stats>,
    pub spans_batch: std::sync::Mutex<batch::Stats>,
}

/// One tenant's endpoint: everything a handler needs.
pub struct Listener {
    pub tenant_id: TenantId,
    pub vendor: String,
    pipeline: Arc<Pipeline<PgStore, PgEnricher>>,
    logs: mpsc::Sender<LogRow>,
    metrics: mpsc::Sender<MetricRow>,
    spans: mpsc::Sender<SpanRow>,
    stats: Arc<Metrics>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("tenant_id", &self.tenant_id)
            .finish_non_exhaustive()
    }
}

impl Listener {
    /// Resolve one identity, and fill in the listener's vendor if enrichment had none.
    async fn attributed(&self, observed: &ObservedIdentity) -> Attribution {
        let mut attribution = self.pipeline.attribute(self.tenant_id, observed).await;
        if attribution.vendor.is_empty() {
            attribution.vendor.clone_from(&self.vendor);
        }
        attribution
    }

    /// A payload that said nothing about who sent it.
    ///
    /// The nil resource rather than a new one. `Pipeline::attribute` on an empty identity
    /// creates a resource *every time it is called*, so a hand-rolled exporter with no
    /// host keys and no service name would mint one per export request and fill an
    /// inventory with them. The row is still stored — §M0.2 rule 1 — and the identifiers
    /// it lacks are exactly why nothing could be done with it.
    fn unattributed(&self) -> Attribution {
        Attribution {
            tenant_id: self.tenant_id,
            resource_id: ResourceId::nil(),
            site_id: SiteId::nil(),
            vendor: self.vendor.clone(),
        }
    }

    /// Which host sent this, for the two signals whose rows have one subject.
    async fn host(&self, resource: &std::collections::BTreeMap<String, String>) -> Attribution {
        if let Some(observed) = uops_otlp::observed(resource) {
            return self.attributed(&observed).await;
        }
        // No host keys at all. Falling back to the service is what keeps M3's behaviour:
        // before M8, `service.name` was the host identity's own last-resort identifier and
        // the resource it produced was already a `ResourceKind::Service`. The rows land
        // where they always did; what changed is that the identifier now belongs to the
        // service openly instead of being filed under the host.
        match uops_otlp::service_observed(resource) {
            Some(observed) => self.attributed(&observed).await,
            None => self.unattributed(),
        }
    }

    /// Both of a span's subjects — M8 §2.1.
    ///
    /// Two resolutions of two different identities, and the second is only possible
    /// because `uops_otlp::identifiers` stopped offering `service.name` as a host
    /// identifier: `UNIQUE (tenant_id, kind, value)` means a name claimed by a host could
    /// never afterwards resolve to a service, and every span would carry
    /// `service_id == resource_id` while looking perfectly healthy.
    ///
    /// Once per *resource*, not per span — a request from one service carries hundreds of
    /// spans that all resolve identically.
    async fn subjects(
        &self,
        resource: &std::collections::BTreeMap<String, String>,
    ) -> (Attribution, ResourceId) {
        let service = match uops_otlp::service_observed(resource) {
            Some(observed) => Some(self.attributed(&observed).await),
            None => None,
        };

        let host = match uops_otlp::observed(resource) {
            Some(observed) => self.attributed(&observed).await,
            // The degenerate payload: a service that did not say which machine it runs on.
            // The two columns then hold the same id, which is the honest answer — there is
            // one thing here and it is the service — rather than a host invented to fill a
            // column.
            None => service.clone().unwrap_or_else(|| self.unattributed()),
        };

        (
            host,
            service.map_or_else(ResourceId::nil, |a| a.resource_id),
        )
    }

    /// Resolve, convert and queue one export request's logs.
    ///
    /// # Errors
    ///
    /// `Err(())` when the queue has closed, which means the batcher has stopped and this
    /// process is shutting down. The caller turns that into a 503, which OTLP defines as
    /// retryable — so the exporter comes back to the next instance.
    pub async fn ingest_logs(&self, request: &[ResourceLogs]) -> Result<Rejected, Stopped> {
        let received_at = chrono::Utc::now();
        let batches = uops_otlp::logs::batches(request);
        let mut queued = 0u64;

        for batch in &batches {
            // Once per *resource*, not per record. A request from one host carries
            // hundreds of records that all resolve identically, and asking per record
            // would turn one cache lookup into hundreds.
            let attribution = self.host(&batch.resource).await;

            for row in uops_otlp::logs::to_rows(batch, &attribution, received_at) {
                if self.logs.send(row).await.is_err() {
                    return Err(Stopped::ShuttingDown);
                }
                queued += 1;
            }
        }

        self.stats.log_records.fetch_add(queued, Ordering::Relaxed);
        // Nothing about a log record is unconvertible: a body that could not be read is
        // still a row, which is the same rule the syslog parsers hold.
        Ok(Rejected::default())
    }

    /// Resolve, convert and queue one export request's metrics.
    ///
    /// # Errors
    ///
    /// As [`ingest_logs`](Self::ingest_logs).
    pub async fn ingest_metrics(&self, request: &[ResourceMetrics]) -> Result<Rejected, Stopped> {
        let received_at = chrono::Utc::now();
        let batches = uops_otlp::metrics::batches(request);
        let mut queued = 0u64;
        let mut unsupported = 0u64;

        for batch in &batches {
            let attribution = self.host(&batch.resource).await;

            let converted = uops_otlp::metrics::to_rows(batch, &attribution, received_at);
            unsupported += converted.unsupported;
            for row in converted.rows {
                if self.metrics.send(row).await.is_err() {
                    return Err(Stopped::ShuttingDown);
                }
                queued += 1;
            }
        }

        self.stats.data_points.fetch_add(queued, Ordering::Relaxed);
        self.stats
            .unsupported
            .fetch_add(unsupported, Ordering::Relaxed);

        Ok(Rejected::new(
            unsupported,
            "histograms, exponential histograms and summaries are not stored yet, and a \
             data point with no timestamp cannot be stored at all",
        ))
    }

    /// Resolve, convert and queue one export request's spans.
    ///
    /// The endpoint has accepted and discarded since M3, because SPEC asked it to: an
    /// application whose exporter gets a 404 logs an error every batch forever, and
    /// "traces are not stored yet" must not look like "the endpoint is broken". M8 is
    /// where the discarding stops.
    ///
    /// # Errors
    ///
    /// As [`ingest_logs`](Self::ingest_logs).
    pub async fn ingest_traces(&self, request: &[ResourceSpans]) -> Result<Rejected, Stopped> {
        let received_at = chrono::Utc::now();
        let batches = uops_otlp::traces::batches(request);
        let mut queued = 0u64;

        for batch in &batches {
            let (attribution, service_id) = self.subjects(&batch.resource).await;

            for row in uops_otlp::traces::to_rows(batch, &attribution, service_id, received_at) {
                if self.spans.send(row).await.is_err() {
                    return Err(Stopped::ShuttingDown);
                }
                queued += 1;
            }
        }

        self.stats.spans.fetch_add(queued, Ordering::Relaxed);
        // Nothing about a span is unconvertible. A backwards duration or a missing
        // timestamp is recorded in the row's attributes and stored — the same rule the
        // log path holds, for the same reason.
        Ok(Rejected::default())
    }
}

/// A listener, resolved against the database.
#[derive(Clone, Debug)]
pub struct Bound {
    pub tenant_id: TenantId,
    pub listener: crate::config::Listener,
}

/// Turn the configured slugs into tenant ids, failing on the first one that is not there.
///
/// Before a socket is opened, for the reason the syslog daemon does it: a receiver that
/// bound its ports and then found a slug was mistyped would be accepting telemetry it had
/// nowhere to put.
///
/// # Errors
///
/// Names the slug.
pub async fn resolve_tenants(store: &PgStore, config: &Config) -> Result<Vec<Bound>, String> {
    let mut bound = Vec::with_capacity(config.listeners.len());
    for listener in &config.listeners {
        let tenant_id = store
            .tenant_by_slug(&listener.tenant)
            .await
            .map_err(|e| format!("cannot look up tenant {:?}: {e}", listener.tenant))?
            .ok_or_else(|| {
                format!(
                    "the listener file names tenant {:?}, which does not exist",
                    listener.tenant
                )
            })?;
        bound.push(Bound {
            tenant_id,
            listener: listener.clone(),
        });
    }
    Ok(bound)
}

/// Run until told to stop, then drain.
///
/// # Errors
///
/// A socket that cannot be bound, named.
pub async fn serve(
    store: PgStore,
    telemetry: ChStore,
    config: &Config,
    bound: Vec<Bound>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    serve_with_metrics(
        store,
        telemetry,
        config,
        bound,
        Arc::new(Metrics::default()),
        shutdown,
    )
    .await
}

/// [`serve`], reporting into counters the caller can read while it runs.
// One long function because it is the shutdown ordering, and that ordering is the thing a
// reader needs to check in one place: servers stop, then the channels close, then the
// batchers drain. Split across helpers it would be four functions that each look correct.
#[allow(clippy::too_many_lines)]
pub async fn serve_with_metrics(
    store: PgStore,
    telemetry: ChStore,
    config: &Config,
    bound: Vec<Bound>,
    metrics: Arc<Metrics>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let pipeline = Arc::new(Pipeline::new(
        Resolver::new(store.clone()),
        Enrichment::new(PgEnricher::new(store)),
    ));

    // Separate subdirectories. A segment does not record its row type, so one directory
    // holding both would read a metric back as a log and fail every line — met
    // structurally rather than by a check, because a different path is simply not the
    // same place.
    let logs_wal = open_spill(config, "logs")?;
    let metrics_wal = open_spill(config, "metrics")?;
    let spans_wal = open_spill(config, "spans")?;

    let (logs_tx, logs_rx) = mpsc::channel::<LogRow>(config.queue);
    let (metrics_tx, metrics_rx) = mpsc::channel::<MetricRow>(config.queue);
    let (spans_tx, spans_rx) = mpsc::channel::<SpanRow>(config.queue);

    let logs_batcher = tokio::spawn(batch::run_with_wal(
        telemetry.clone(),
        logs_rx,
        batch::Config::default(),
        logs_wal,
        {
            let metrics = Arc::clone(&metrics);
            move |stats| {
                if let Ok(mut held) = metrics.logs_batch.lock() {
                    *held = stats;
                }
                if stats.rows_dropped > 0 {
                    eprintln!(
                        "uops-collector-otlp: {} log row(s) LOST to a ClickHouse outage",
                        stats.rows_dropped
                    );
                }
            }
        },
    ));

    let metrics_batcher = tokio::spawn(batch::run_with_wal(
        telemetry.clone(),
        metrics_rx,
        batch::Config::default(),
        metrics_wal,
        {
            let metrics = Arc::clone(&metrics);
            move |stats| {
                if let Ok(mut held) = metrics.metrics_batch.lock() {
                    *held = stats;
                }
                if stats.rows_dropped > 0 {
                    eprintln!(
                        "uops-collector-otlp: {} metric row(s) LOST to a ClickHouse outage",
                        stats.rows_dropped
                    );
                }
            }
        },
    ));

    let spans_batcher = tokio::spawn(batch::run_with_wal(
        telemetry,
        spans_rx,
        batch::Config::default(),
        spans_wal,
        {
            let metrics = Arc::clone(&metrics);
            move |stats| {
                if let Ok(mut held) = metrics.spans_batch.lock() {
                    *held = stats;
                }
                if stats.rows_dropped > 0 {
                    eprintln!(
                        "uops-collector-otlp: {} span row(s) LOST to a ClickHouse outage",
                        stats.rows_dropped
                    );
                }
            }
        },
    ));

    let (stop_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let mut servers = Vec::new();

    for bound in bound {
        let listener = Arc::new(Listener {
            tenant_id: bound.tenant_id,
            vendor: bound.listener.vendor.clone(),
            pipeline: Arc::clone(&pipeline),
            logs: logs_tx.clone(),
            metrics: metrics_tx.clone(),
            spans: spans_tx.clone(),
            stats: Arc::clone(&metrics),
        });

        let router = axum::Router::new()
            .route("/v1/logs", axum::routing::post(crate::routes::logs))
            .route("/v1/metrics", axum::routing::post(crate::routes::metrics))
            .route("/v1/traces", axum::routing::post(crate::routes::traces))
            // Without this an unauthenticated endpoint is an allocation somebody else
            // controls. The Collector batches, so the limit is generous rather than tight.
            .layer(axum::extract::DefaultBodyLimit::max(config.max_body))
            .with_state(listener);

        let socket = tokio::net::TcpListener::bind(bound.listener.bind)
            .await
            .map_err(|e| format!("cannot bind {}: {e}", bound.listener.bind))?;
        println!(
            "uops-collector-otlp: {} on {} (/v1/logs, /v1/metrics, /v1/traces)",
            bound.listener.tenant, bound.listener.bind
        );

        let mut stop = stop_tx.subscribe();
        servers.push(tokio::spawn(async move {
            let _ = axum::serve(socket, router)
                .with_graceful_shutdown(async move {
                    let _ = stop.recv().await;
                })
                .await;
        }));
    }

    // Dropped so the batchers end when the last handler is gone. Forgetting this is a
    // shutdown that hangs forever holding a sender nobody will use.
    drop(logs_tx);
    drop(metrics_tx);
    drop(spans_tx);

    shutdown.await;
    println!("uops-collector-otlp: stopping, draining what is in flight");
    let _ = stop_tx.send(());

    for server in servers {
        let _ = server.await;
    }
    for (what, handle) in [
        ("logs", logs_batcher),
        ("metrics", metrics_batcher),
        ("spans", spans_batcher),
    ] {
        match handle.await {
            Ok(stats) => println!(
                "uops-collector-otlp: {what} — {} row(s) in {} insert(s), {} spilled, \
                 {} replayed, {} still on disk, {} lost",
                stats.rows_written,
                stats.batches_written,
                stats.rows_spilled,
                stats.rows_replayed,
                stats.rows_pending,
                stats.rows_dropped
            ),
            Err(e) => return Err(format!("the {what} batcher did not stop cleanly: {e}")),
        }
    }
    Ok(())
}

/// Open one signal's spill directory, if a spill is configured at all.
fn open_spill(config: &Config, signal: &str) -> Result<Option<uops_pipeline::Wal>, String> {
    let Some(root) = &config.spill else {
        return Ok(None);
    };
    let directory = root.join(signal);
    uops_pipeline::Wal::open(uops_pipeline::WalConfig {
        directory: directory.clone(),
        ..uops_pipeline::WalConfig::default()
    })
    .map(Some)
    .map_err(|e| {
        format!(
            "the spill directory {} is unusable: {e}",
            directory.display()
        )
    })
}
