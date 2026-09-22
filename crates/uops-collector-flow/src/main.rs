//! `uops-collector-flow` — `NetFlow`, IPFIX and sFlow into `ClickHouse`.
//!
//! ```text
//!   read the listener file        fail here, naming the file
//!   connect to PostgreSQL         fail here, saying which host
//!   connect to ClickHouse         fail here, saying which host
//!   enrol, if given a token       fail here, naming the tenant it may not carry
//!   resolve every tenant slug     fail here, naming the slug
//!   bind every socket             fail here, naming the address
//!   receive until told to stop    write what is buffered on the way out
//! ```
//!
//! Every one of those failures is a startup failure on purpose. A collector that came up
//! with three of its four listeners would be silently losing one customer's flow, and
//! nothing downstream can tell that from a quiet network.

use std::process::ExitCode;
use std::sync::atomic::Ordering::Relaxed;

use uops_collector_flow::{Config, run, shutdown};
use uops_store_ch::{ChClient, ChStore, TelemetryStore};
use uops_store_pg::PgStore;

#[tokio::main]
async fn main() -> ExitCode {
    match start().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("uops-collector-flow: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn start() -> Result<(), String> {
    let config = Config::load()?;

    let store = PgStore::connect(&config.postgres)
        .await
        .map_err(|e| format!("cannot reach PostgreSQL: {e}"))?;

    let telemetry = ChStore::new(ChClient::new(config.clickhouse.clone()));
    let health = telemetry
        .health()
        .await
        .map_err(|e| format!("cannot reach ClickHouse: {e}"))?;
    println!("clickhouse {} ready", health.version);

    // M12 §2.3. The flow collector resolves its own tenants inside `run`, so the
    // assignment check happens here against the configured slugs — which is the same
    // list, one step earlier.
    let stats = std::sync::Arc::new(run::Stats::default());
    let started_at = chrono::Utc::now();
    let listeners = describe_listeners(&config);

    let agent = match config.collector_token.as_deref() {
        Some(token) => {
            let (agent, assigned) = uops_store_pg::Agent::enrol(
                store.clone(),
                uops_store_pg::Kind::Flow,
                &config.collector_name,
                token,
                &report(&stats, started_at, &listeners),
            )
            .await
            .map_err(|e| format!("this collector could not enrol: {e}"))?;

            let mut configured = Vec::with_capacity(config.listeners.len());
            for listener in &config.listeners {
                let id = store
                    .tenant_by_slug(&listener.tenant)
                    .await
                    .map_err(|e| format!("cannot look up tenant {:?}: {e}", listener.tenant))?
                    .ok_or_else(|| {
                        format!(
                            "the listener file names tenant {:?}, which does not exist",
                            listener.tenant
                        )
                    })?;
                configured.push((listener.tenant.clone(), id));
            }
            uops_store_pg::check_assignment(&configured, &assigned).map_err(|e| format!("{e}"))?;

            println!(
                "uops-collector-flow: enrolled as {}, assigned {} tenant(s)",
                agent.describe(),
                assigned.len()
            );
            Some(agent)
        }
        None => None,
    };

    let heartbeat = agent.map(|agent| {
        let stats = std::sync::Arc::clone(&stats);
        let listeners = listeners.clone();
        tokio::spawn(async move {
            agent
                .run(
                    move || report(&stats, started_at, &listeners),
                    std::future::pending::<()>(),
                )
                .await;
        })
    });

    let stats = run::run_with_stats(
        config,
        store,
        telemetry,
        std::sync::Arc::clone(&stats),
        shutdown::signal(),
    )
    .await?;

    if let Some(heartbeat) = heartbeat {
        heartbeat.abort();
    }

    // The last word, because the counters that matter are the ones about loss and they
    // are worth one line in the log of a deploy rather than a metrics endpoint nobody
    // scrapes on the way down.
    println!(
        "uops-collector-flow: {} datagrams, {} flows, {} undecodable, {} awaiting a template, \
         {} dropped by a full queue",
        stats.datagrams.load(Relaxed),
        stats.flows.load(Relaxed),
        stats.undecodable.load(Relaxed),
        stats.awaiting_template.load(Relaxed),
        stats.dropped_queue.load(Relaxed),
    );
    Ok(())
}

/// What this collector is bound to, for the inventory.
fn describe_listeners(config: &Config) -> serde_json::Value {
    serde_json::Value::Array(
        config
            .listeners
            .iter()
            .map(|l| {
                serde_json::json!({
                    "tenant": l.tenant,
                    "udp": l.udp.to_string(),
                })
            })
            .collect(),
    )
}

/// One heartbeat's worth of truth about this process.
fn report(
    stats: &run::Stats,
    started_at: chrono::DateTime<chrono::Utc>,
    listeners: &serde_json::Value,
) -> uops_store_pg::Report {
    uops_store_pg::Report {
        hostname: Some(uops_store_pg::Agent::default_name()),
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        reported: Some(listeners.clone()),
        started_at: Some(started_at),
        // Flows rather than datagrams: a datagram carries many, and the number an
        // operator compares against their exporter's own counter is the flow count.
        received: i64::try_from(stats.flows.load(Relaxed)).unwrap_or(i64::MAX),
        written: i64::try_from(stats.rows_written()).unwrap_or(i64::MAX),
        lost: i64::try_from(stats.lost()).unwrap_or(i64::MAX),
    }
}
