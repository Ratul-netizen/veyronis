//! The runner.
//!
//! Everything below this file has tests; this file is the order those things happen in,
//! which is the part that cannot be unit-tested and the part an operator experiences:
//!
//! ```text
//!   read the environment          fail here, before anything is opened
//!   open the key ring             fail here — a runner with no KEK runs nothing
//!   connect to PostgreSQL         fail here, saying which host
//!   make the state directory      fail here — known_hosts has to be writable
//!   close out abandoned runs      a crashed predecessor left some `running`
//!   take the run lease, and work
//! ```
//!
//! # Why it closes out abandoned runs at start-up and does not resume them
//!
//! A run left in `running` by a process that stopped is the one state nothing else
//! corrects: claiming only looks at `ready`. It is marked *failed*, not requeued, because
//! it may already have sent a destructive step and this process does not know which.
//! Re-running it would be the product deciding by itself to send `clear bgp neighbor` a
//! second time — which is exactly what M10 §2.6 refuses to do with a rollback.
//!
//! # Why there is no listener and no port
//!
//! It has nothing to serve. The screens read runs through `uops-server`, from the same
//! `PostgreSQL` this writes to. A health endpoint here would be a second thing to expose
//! on a host whose whole purpose is holding credentials that change an estate.

use std::process::ExitCode;
use std::sync::Arc;

use uops_runner::{config::Config, shutdown, vault};
use uops_store_pg::PgStore;

#[tokio::main]
async fn main() -> ExitCode {
    match start().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // One line, on stderr. Not a panic: a backtrace through tokio's internals
            // tells an operator nothing they can act on, and buries the sentence that
            // does.
            eprintln!("uops-runner: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn start() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    println!("uops-runner starting: {}", config.summary());

    let store = PgStore::connect(&config.postgres)
        .await
        // The URL is in the summary above, already redacted. Repeating it unredacted here
        // is how a password ends up in a support ticket.
        .map_err(|e| format!("cannot reach PostgreSQL: {e}"))?;
    store
        .health()
        .await
        .map_err(|e| format!("PostgreSQL is reachable but not answering: {e}"))?;

    let vault = vault::open(store.clone(), &config)
        .map_err(|e| format!("the key ring could not be opened: {e}"))?;

    // Before the first run rather than lazily, so a state directory that is not writable
    // is a start-up failure naming the variable rather than a step that fails on a device
    // and looks like a network problem.
    tokio::fs::create_dir_all(&config.state_dir)
        .await
        .map_err(|e| {
            format!(
                "UOPS_RUNNER_STATE_DIR ({}) could not be created: {e}",
                config.state_dir.display()
            )
        })?;

    let abandoned = store
        .fail_abandoned_runs(
            chrono::Duration::from_std(config.abandon_after)
                .map_err(|e| format!("UOPS_RUNNER_ABANDON_SECS is out of range: {e}"))?,
        )
        .await
        .map_err(|e| format!("abandoned runs could not be closed out: {e}"))?;
    if abandoned > 0 {
        println!(
            "uops-runner: {abandoned} run(s) left behind by a stopped runner were marked \
             failed. They were not restarted — read their transcripts."
        );
    }

    let transport = uops_runner::Live::new(Arc::new(vault), &config.state_dir);
    uops_runner::run(store, &transport, config.poll_every, shutdown::signal()).await;

    println!("uops-runner: stopped cleanly");
    Ok(())
}
