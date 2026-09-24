//! The syslog daemon.
//!
//! Everything below this file has tests; this file is the order those things happen in,
//! which is the part an operator experiences:
//!
//! ```text
//!   read the listener file        fail here — a daemon with nothing bound ingests nothing
//!   connect to PostgreSQL         fail here, saying which host
//!   resolve the tenant slugs      fail here, naming the slug that is not there
//!   enrol, if given a token       fail here, naming the tenant it may not carry
//!   connect to ClickHouse         fail here, saying which host
//!   bind the sockets              fail here, saying which port and what to do about it
//!   receive until told to stop
//!   drain
//! ```
//!
//! # Why enrolment is before the first bind too
//!
//! Same argument as the slugs, one step further along. A collector that bound its ports
//! and *then* found it had not been assigned a customer would be accepting that
//! customer's messages while the server's answer to "who may carry them" was no. Failing
//! first means the message names the tenant, which is what somebody can act on.
//!
//! # Why the slugs are resolved before a socket is opened
//!
//! A daemon that bound its ports and *then* found a slug was mistyped would be accepting
//! messages it had nowhere to put, and its receivers would be counting drops that were
//! really a configuration error. Failing before the first bind means the message names
//! the slug, which is what somebody can act on.
//!
//! # Why it does not migrate
//!
//! Same reason as `uops-server` and `uops-poller`: migrations are DDL and belong to
//! `scripts/db.sh migrate` and `uops-ch-migrate`. A collector that migrated on startup
//! would make N replicas race to alter a schema, and the first thing a syslog daemon does
//! under load is get more replicas.
//!
//! # Why more than one replica *is* safe here, unlike the poller
//!
//! The poller has no lease, so two of them would poll every device twice. This has
//! nothing to schedule: each replica owns its own sockets, and a sender reaches one of
//! them. Two replicas behind a load balancer each resolve identity independently — which
//! costs a second cache warm-up and, briefly, can have both create a provisional resource
//! for the same unknown device. `UNIQUE (tenant_id, kind, value)` makes the second one
//! lose, so the outcome is one resource and one extra review item, not two resources.

use std::process::ExitCode;
use std::sync::Arc;

use uops_collector_syslog::{config::Config, run, shutdown};
use uops_core::TenantId;
use uops_store_ch::{ChClient, ChStore, TelemetryStore};
use uops_store_pg::{Agent, Kind, PgStore, Report};

#[tokio::main]
async fn main() -> ExitCode {
    match start().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // One line, on stderr. Not a panic: a backtrace through tokio's internals
            // tells an operator nothing they can act on, and buries the sentence that
            // does.
            eprintln!("uops-collector-syslog: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn start() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    println!("uops-collector-syslog starting: {}", config.summary());

    let store = PgStore::connect(&config.postgres)
        .await
        // The URL is not repeated here: it carries a password, and the summary above
        // already said everything that is safe to say.
        .map_err(|e| format!("cannot reach PostgreSQL: {e}"))?;

    // Before any socket is bound. See the module docs.
    let bound = run::resolve_tenants(&store, &config).await?;

    // Counters are created here rather than inside `serve` so that the heartbeat below
    // can read them while the daemon runs. `serve_with_metrics` exists for the scale
    // test for the same reason, which is why this needs nothing new.
    let metrics = Arc::new(run::Metrics::default());
    let started_at = chrono::Utc::now();
    let listeners = describe_listeners(&bound);

    // M12 §2.3. Also before the first bind — see the module docs.
    let agent = match config.collector_token.as_deref() {
        Some(token) => {
            let report = report(&metrics, started_at, &listeners);
            let (agent, assigned) = Agent::enrol(
                store.clone(),
                Kind::Syslog,
                &config.collector_name,
                token,
                &report,
            )
            .await
            .map_err(|e| format!("this collector could not enrol: {e}"))?;

            let configured: Vec<(String, TenantId)> = bound
                .iter()
                .map(|b| (b.listener.tenant.clone(), b.tenant_id))
                .collect();
            uops_store_pg::check_assignment(&configured, &assigned).map_err(|e| format!("{e}"))?;

            println!(
                "uops-collector-syslog: enrolled as {}, assigned {} tenant(s)",
                agent.describe(),
                assigned.len()
            );
            Some(agent)
        }
        None => None,
    };

    let telemetry = ChStore::new(ChClient::new(config.clickhouse.clone()));
    let ch = telemetry
        .health()
        .await
        .map_err(|e| format!("cannot reach ClickHouse: {e}"))?;
    println!("uops-collector-syslog: clickhouse {} ready", ch.version);

    // Reporting in is not part of ingesting, so it gets its own task and its own
    // failure: a heartbeat that cannot reach PostgreSQL logs and carries on, and the
    // registry notices the silence. `pending()` rather than a second signal handler —
    // the task is aborted below, once the drain that matters has finished.
    let heartbeat = agent.map(|agent| {
        let metrics = Arc::clone(&metrics);
        let listeners = listeners.clone();
        tokio::spawn(async move {
            agent
                .run(
                    move || report(&metrics, started_at, &listeners),
                    std::future::pending::<()>(),
                )
                .await;
        })
    });

    run::serve_with_metrics(
        store,
        telemetry,
        &config,
        bound,
        metrics,
        shutdown::signal(),
    )
    .await?;

    // After the drain, so the last heartbeat covers everything that was written.
    if let Some(heartbeat) = heartbeat {
        heartbeat.abort();
    }
    println!("uops-collector-syslog: stopped cleanly");
    Ok(())
}

/// What this collector is bound to, for the inventory.
///
/// The tenant *slug* rather than its id: this is read by a person looking at a list of
/// collectors, and a column of UUIDs is a column nobody can use.
fn describe_listeners(bound: &[run::Bound]) -> serde_json::Value {
    serde_json::Value::Array(
        bound
            .iter()
            .map(|b| {
                serde_json::json!({
                    "tenant": b.listener.tenant,
                    "udp": b.listener.udp.map(|a| a.to_string()),
                    "tcp": b.listener.tcp.map(|a| a.to_string()),
                })
            })
            .collect(),
    )
}

/// One heartbeat's worth of truth about this process.
fn report(
    metrics: &run::Metrics,
    started_at: chrono::DateTime<chrono::Utc>,
    listeners: &serde_json::Value,
) -> Report {
    Report {
        hostname: Some(Agent::default_name()),
        // The build's own version, so an upgrade that did not take is visible in the
        // inventory rather than only on the box.
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        reported: Some(listeners.clone()),
        started_at: Some(started_at),
        received: i64::try_from(metrics.received.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(i64::MAX),
        written: i64::try_from(metrics.rows_written()).unwrap_or(i64::MAX),
        lost: i64::try_from(metrics.lost()).unwrap_or(i64::MAX),
    }
}
