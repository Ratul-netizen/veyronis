//! The OTLP receiver.
//!
//! Everything below this file has tests; this file is the order those things happen in:
//!
//! ```text
//!   read the listener file        fail here -- a receiver with nothing bound ingests nothing
//!   connect to PostgreSQL         fail here, saying which host
//!   resolve the tenant slugs      fail here, naming the slug that is not there
//!   connect to ClickHouse         fail here, saying which host
//!   bind the sockets              fail here, saying which address
//!   receive until told to stop
//!   drain
//! ```
//!
//! # Why it does not migrate, and why replicas are safe
//!
//! Both for the same reasons as `uops-collector-syslog`: migrations are DDL and belong to
//! `scripts/db.sh migrate`, and this schedules nothing, so two instances behind a load
//! balancer each resolve independently and `UNIQUE (tenant_id, kind, value)` makes the
//! second creation of a provisional resource lose rather than duplicate.
//!
//! # No KEK
//!
//! An OTLP receiver opens no credentials. It reads a socket and writes rows, so it is not
//! given the key that decrypts every credential in the installation.

use std::process::ExitCode;
use std::sync::Arc;

use uops_collector_otlp::{config::Config, run, shutdown};
use uops_store_ch::{ChClient, ChStore, TelemetryStore};
use uops_store_pg::{Agent, Kind, PgStore, Report};

#[tokio::main]
async fn main() -> ExitCode {
    match start().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("uops-collector-otlp: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn start() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    println!("uops-collector-otlp starting: {}", config.summary());

    let store = PgStore::connect(&config.postgres)
        .await
        .map_err(|e| format!("cannot reach PostgreSQL: {e}"))?;

    // Before any socket is bound.
    let bound = run::resolve_tenants(&store, &config).await?;

    let metrics = Arc::new(run::Metrics::default());
    let started_at = chrono::Utc::now();
    let listeners = describe_listeners(&bound);

    // M12 §2.3, and before the first bind for the same reason the slugs are: a collector
    // that bound its ports and *then* found it may not carry a customer would be
    // accepting that customer's telemetry while the server's answer was no.
    let agent = match config.collector_token.as_deref() {
        Some(token) => {
            let report = report(&metrics, started_at, &listeners);
            let (agent, assigned) = Agent::enrol(
                store.clone(),
                Kind::Otlp,
                &config.collector_name,
                token,
                &report,
            )
            .await
            .map_err(|e| format!("this collector could not enrol: {e}"))?;

            let configured: Vec<(String, uops_core::TenantId)> = bound
                .iter()
                .map(|b| (b.listener.tenant.clone(), b.tenant_id))
                .collect();
            uops_store_pg::check_assignment(&configured, &assigned).map_err(|e| format!("{e}"))?;

            println!(
                "uops-collector-otlp: enrolled as {}, assigned {} tenant(s)",
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
    println!("uops-collector-otlp: clickhouse {} ready", ch.version);

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

    if let Some(heartbeat) = heartbeat {
        heartbeat.abort();
    }
    println!("uops-collector-otlp: stopped cleanly");
    Ok(())
}

/// What this collector is bound to, for the inventory. The tenant *slug*, because this is
/// read by a person looking at a list of collectors.
fn describe_listeners(bound: &[run::Bound]) -> serde_json::Value {
    serde_json::Value::Array(
        bound
            .iter()
            .map(|b| {
                serde_json::json!({
                    "tenant": b.listener.tenant,
                    "bind": b.listener.bind.to_string(),
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
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        reported: Some(listeners.clone()),
        started_at: Some(started_at),
        received: i64::try_from(metrics.received()).unwrap_or(i64::MAX),
        written: i64::try_from(metrics.rows_written()).unwrap_or(i64::MAX),
        lost: i64::try_from(metrics.lost()).unwrap_or(i64::MAX),
    }
}
