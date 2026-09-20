//! `uops-collector-flow` — `NetFlow`, IPFIX and sFlow into `ClickHouse`.
//!
//! ```text
//!   read the listener file        fail here, naming the file
//!   connect to PostgreSQL         fail here, saying which host
//!   connect to ClickHouse         fail here, saying which host
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

    let stats = run(config, store, telemetry, shutdown::signal()).await?;

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
