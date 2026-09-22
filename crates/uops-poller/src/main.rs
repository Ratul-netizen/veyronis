//! The poller.
//!
//! Everything below this file has tests; this file is the order those things happen in,
//! which is the part that cannot be unit-tested and the part an operator experiences:
//!
//! ```text
//!   read the environment          fail here, before anything is opened
//!   open the key ring             fail here — a poller with no KEK polls nothing
//!   connect to PostgreSQL         fail here, saying which host
//!   connect to ClickHouse         fail here, saying which host
//!   seed the built-in profiles    so a fresh database has something to poll under
//!   load the fleet                fail here if it cannot be read at all
//!   poll until told to stop
//! ```
//!
//! # Why it opens the key ring before it connects to anything
//!
//! A KEK that is missing, malformed, or in a file other accounts can read is a
//! configuration error, and a configuration error should be found before a single
//! connection is made. Doing it in this order means the failure names the variable
//! rather than arriving later as "every device refused the credentials", which sends an
//! operator to look at the network.
//!
//! # Why it seeds profiles and does not migrate
//!
//! Seeding is an upsert of definitions this build ships — data, idempotent, and safe for
//! N replicas to race on. Migrations are DDL and are `scripts/db.sh migrate` and
//! `uops-ch-migrate`, for the reasons `uops-server`'s `main` sets out.
//!
//! # More than one poller is safe, and this paragraph used to say the opposite
//!
//! It said *"there is no lease"*, which was true when M2 wrote it and stopped being true
//! when M12 §2.1 added one. A comment that tells an operator not to run a second replica
//! of something that is safe to replicate is not a harmless stale line: it is the product
//! refusing a capability it has, in the one place somebody looks before deploying.
//!
//! What is actually true: [`run::serve`] claims the `poll` lease and only the holder
//! sends anything. A second poller loads the fleet, stands by, and takes over within one
//! lease period if the first stops — so a takeover is a one-slot gap rather than a reload.
//!
//! Measured by sample count rather than argued: `tests/live.rs`'s
//! `two_pollers_against_one_database_write_the_samples_of_one` runs two against one
//! database and counts rows in `ClickHouse`, then runs the same loop with the lease gate
//! removed and shows the count go up. A duplicated sample is worse than a duplicated
//! packet — every rate computed from `metrics` is then wrong rather than merely doubled —
//! which is why the measurement is in samples and not in polls.

use std::process::ExitCode;
use std::sync::Arc;

use uops_poller::{config::Config, credentials, run, shutdown};
use uops_store_ch::{ChClient, ChStore, TelemetryStore};
use uops_store_pg::PgStore;

#[tokio::main]
async fn main() -> ExitCode {
    match start().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // One line, on stderr, saying what failed. Not a panic: a backtrace through
            // tokio's internals tells an operator nothing they can act on, and buries
            // the sentence that does.
            eprintln!("uops-poller: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn start() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    println!("uops-poller starting: {}", config.summary());

    let store = PgStore::connect(&config.postgres)
        .await
        // The URL is in the summary above, already redacted. Repeating it here
        // unredacted is how a password ends up in a support ticket.
        .map_err(|e| format!("cannot reach PostgreSQL: {e}"))?;
    store
        .health()
        .await
        .map_err(|e| format!("PostgreSQL is reachable but not answering: {e}"))?;

    // After the connection, because it needs the store; before anything is polled,
    // because a poller that cannot open a credential has nothing to do. The error names
    // the variable — see config.rs.
    let vault = credentials::vault(store.clone(), &config)
        .map_err(|e| format!("the key ring could not be opened: {e}"))?;

    let metrics = ChStore::new(ChClient::new(config.clickhouse.clone()));
    let ch = metrics
        .health()
        .await
        .map_err(|e| format!("cannot reach ClickHouse: {e}"))?;
    println!("uops-poller: clickhouse {} ready", ch.version);

    let seeded = store
        .seed_builtin_profiles(&uops_profile::builtin::all()?)
        .await
        .map_err(|e| format!("the built-in profiles could not be seeded: {e}"))?;
    println!("uops-poller: {seeded} built-in profiles up to date");

    // Cloned before the runner takes ownership: the registry heartbeat writes through
    // the same pool rather than opening its own. `PgStore` is an `Arc` around one.
    let store_for_registry = store.clone();

    let runner = Arc::new(run::Runner::new(
        store,
        metrics,
        Arc::new(credentials::Transports::new(vault)),
        config.limits.device_budget,
    ));

    // M12 §2.3. A poller serves no listener, so there is no assignment to check — it is
    // in the registry for visibility alone, which is the thing it most needs: a poller
    // that has stopped produces no error and no drop counter, only metrics that stop
    // arriving for a fleet nobody is looking at.
    let totals = Arc::new(run::Totals::default());
    let started_at = chrono::Utc::now();

    let agent = match config.collector_token.as_deref() {
        Some(token) => {
            let (agent, _assigned) = uops_store_pg::Agent::enrol(
                store_for_registry,
                uops_store_pg::Kind::Poller,
                &config.collector_name,
                token,
                &report(&totals, started_at, &config),
            )
            .await
            .map_err(|e| format!("this poller could not enrol: {e}"))?;
            println!("uops-poller: enrolled as {}", agent.describe());
            Some(agent)
        }
        None => None,
    };

    let heartbeat = agent.map(|agent| {
        let totals = Arc::clone(&totals);
        let reload_every = config.reload_every;
        let device_limit = config.device_limit;
        tokio::spawn(async move {
            agent
                .run(
                    move || describe(&totals, started_at, reload_every, device_limit),
                    std::future::pending::<()>(),
                )
                .await;
        })
    });

    run::serve_with_totals(runner, &config, Arc::clone(&totals), shutdown::signal()).await?;

    if let Some(heartbeat) = heartbeat {
        heartbeat.abort();
    }
    println!("uops-poller: stopped cleanly");
    Ok(())
}

/// One heartbeat's worth of truth about this process, from its configuration.
fn report(
    totals: &run::Totals,
    started_at: chrono::DateTime<chrono::Utc>,
    config: &Config,
) -> uops_store_pg::Report {
    describe(totals, started_at, config.reload_every, config.device_limit)
}

/// The same, from the two settings that describe what this poller is doing.
///
/// Split out because the heartbeat task outlives the borrow of `Config`, and copying two
/// numbers into it beats cloning the whole configuration — which holds a database URL
/// with a password in it.
fn describe(
    totals: &run::Totals,
    started_at: chrono::DateTime<chrono::Utc>,
    reload_every: std::time::Duration,
    device_limit: i64,
) -> uops_store_pg::Report {
    use std::sync::atomic::Ordering::Relaxed;

    uops_store_pg::Report {
        hostname: Some(uops_store_pg::Agent::default_name()),
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        reported: Some(serde_json::json!({
            "reload_every_secs": reload_every.as_secs(),
            "device_limit": device_limit,
        })),
        started_at: Some(started_at),
        // Jobs the wheel handed out, which is the poller's equivalent of a datagram
        // taken off a socket.
        received: i64::try_from(totals.due.load(Relaxed)).unwrap_or(i64::MAX),
        written: i64::try_from(totals.samples.load(Relaxed)).unwrap_or(i64::MAX),
        lost: i64::try_from(totals.failed.load(Relaxed)).unwrap_or(i64::MAX),
    }
}
