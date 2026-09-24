//! The runner — M10 §2.9, `docs/M10-automation.md`.
//!
//! Every other process in this product reads. This one writes to somebody else's
//! equipment, and it is a binary of its own for a reason that is not architecture
//! taste: a runbook step is a long, blocking, network-bound operation with an SSH
//! handshake in it, and putting one of those on the API's runtime is how a web request
//! queues behind a device that is not answering.
//!
//! ```text
//!   claim the `run` lease ────┐
//!                             │  one owner across replicas — M12 §2.1
//!   claim a queued run ───────┤
//!                             │  ready → running, one UPDATE — the actual guard
//!   decide ───────────────────┤
//!                             │  approvals fresh? enough? not the starter's own?
//!   execute ──────────────────┤
//!                             │  dry run runs only the read-only steps
//!   record ───────────────────┘
//!                                a rollback is *offered*, never performed
//! ```
//!
//! # Two guards, and only one of them is the lease
//!
//! The lease bounds how many runners are working at all. What makes a queued run execute
//! exactly once is `PgStore::claim_next_run` — one `UPDATE` that the database serialises.
//! A lease that lapsed a millisecond ago while its holder was mid-claim would leave two
//! processes both believing they may work, and the thing that decides between them cannot
//! itself be the lease. M12 §2.3's enrolment token taught this the hard way.
//!
//! # What this crate does not decide
//!
//! Whether a run may proceed is `uops_runbook::decide`. What a runbook may contain is
//! `uops_runbook::validate`. Whether a command is safe to render is
//! `uops_runbook::render`. All three are pure, exhaustively tested without a device, and
//! deliberately not repeated here — a second copy of a safety rule is a second copy that
//! can disagree with the first.

pub mod config;
pub mod execute;
pub mod http;
pub mod live;
pub mod shutdown;
pub mod ssh;
pub mod transport;
pub mod vault;

pub use execute::Report;
pub use live::Live;
pub use transport::{Endpoint, Outcome, Transport};

use std::time::Duration;

use uops_runbook::Decision;
use uops_store_pg::{Claimed, PgStore, RunState};

/// What one turn of the loop did.
///
/// Returned so a test can assert on it, and printed so an operator can see the process is
/// alive without a run having happened.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Turn {
    pub executed: usize,
    /// Runs handed back because their approval had expired while they queued.
    pub returned: usize,
}

impl Turn {
    #[must_use]
    pub const fn did_something(&self) -> bool {
        self.executed > 0 || self.returned > 0
    }
}

/// Take one queued run, if there is one, and see it through.
///
/// Returns `Ok(None)` when the queue was empty, which is the ordinary case and is not an
/// event.
///
/// # Errors
///
/// Whatever the store said. A device failure is not one — it is recorded against the run
/// and the run is marked failed.
pub async fn take_one<T: Transport + ?Sized>(
    store: &PgStore,
    transport: &T,
    now: chrono::DateTime<chrono::Utc>,
) -> uops_core::Result<Option<Turn>> {
    let Some(claimed) = store.claim_next_run().await? else {
        return Ok(None);
    };

    let mut turn = Turn::default();

    // Decided **after** the claim and not before, because the window that matters is the
    // one between approval and execution. A run approved at 09:00 and picked up at 09:20
    // is a run approved against a target list that may no longer be the same estate —
    // M10 §2.5.
    match uops_runbook::decide(&claimed.request(), &claimed.approvals, now) {
        Decision::Approved | Decision::BreakGlass => {}
        Decision::Pending(pending) => {
            // Not a failure. M10 §3: the run *stays pending rather than failing*, because
            // what went wrong is that ten minutes passed, and the operator's next step is
            // to ask somebody again.
            store
                .return_run_to_queue(&claimed.scope(), claimed.id)
                .await?;
            println!(
                "runner: run {} went back to waiting — {}",
                claimed.id,
                pending.describe()
            );
            turn.returned += 1;
            return Ok(Some(turn));
        }
    }

    let report = match execute::run(store, transport, &claimed).await {
        Ok(report) => report,
        Err(e) => {
            // The store failed mid-run. The run is marked failed rather than left
            // `running`, because a run nobody will finish should not look like one in
            // progress — and the message says the product stopped, not the device.
            let why = format!("the runner could not record this run's progress: {e}");
            store
                .set_run_state(&claimed.scope(), claimed.id, RunState::Failed, Some(&why))
                .await?;
            turn.executed += 1;
            return Ok(Some(turn));
        }
    };

    finish(store, &claimed, &report).await?;
    turn.executed += 1;
    Ok(Some(turn))
}

/// Write the run's final state, with the rollback offered rather than taken.
async fn finish(store: &PgStore, claimed: &Claimed, report: &Report) -> uops_core::Result<()> {
    let failure = report.failure.as_ref().map(|why| match &report.rollback {
        // The two sentences M10 §2.6 asks for, in one field because one field is what the
        // list shows: what the author said undoes it, and the honest caveat.
        Some(rollback) => format!(
            "{why}. {rollback}. It has not been run — a rollback is another runbook, and \
             it can fail too."
        ),
        None => why.clone(),
    });

    store
        .set_run_state(
            &claimed.scope(),
            claimed.id,
            report.state,
            failure.as_deref(),
        )
        .await?;
    Ok(())
}

/// Run until `shutdown` resolves.
///
/// Holds the `run` lease while it works and stands down when it does not have it — the
/// same shape the sweeper and the alert engine use, and the same one signal.
pub async fn run<T: Transport + ?Sized, F>(
    store: PgStore,
    transport: &T,
    poll_every: Duration,
    shutdown: F,
) where
    F: Future<Output = ()> + Send,
{
    tokio::pin!(shutdown);

    let me = uops_store_pg::identity();
    let mut holding = false;

    loop {
        match store.claim(uops_store_pg::Job::Run, &me).await {
            Ok(claim) => {
                let now_holding = claim.is_held();
                if now_holding != holding {
                    println!(
                        "runner: {} the run lease as {me}",
                        if now_holding {
                            "holding"
                        } else {
                            "stood down from"
                        }
                    );
                }
                holding = now_holding;
            }
            // Not a lost lease. A database blip that stopped every runner would be a worse
            // outage than the one this prevents — the poller's reasoning, unchanged.
            Err(e) => eprintln!("runner: the lease could not be renewed: {e}"),
        }

        if holding {
            match take_one(&store, transport, chrono::Utc::now()).await {
                Ok(Some(turn)) if turn.did_something() => {
                    // Straight round again: a queue that had one run in it often has two,
                    // and waiting out the interval between them would make a batch of ten
                    // take a minute for no reason.
                    continue;
                }
                Ok(_) => {}
                Err(e) => eprintln!("runner: a run could not be taken: {e}"),
            }
        }

        tokio::select! {
            () = tokio::time::sleep(poll_every) => {}
            () = &mut shutdown => {
                println!("runner: stopping");
                if holding && let Err(e) = store.release(uops_store_pg::Job::Run, &me).await {
                    eprintln!("runner: the lease could not be released: {e}");
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_turn_that_did_nothing_says_so() {
        // The loop uses this to decide whether to come straight round again. An empty turn
        // reading as "did something" would make the runner spin against the database.
        assert!(!Turn::default().did_something());
        assert!(
            Turn {
                executed: 1,
                ..Turn::default()
            }
            .did_something()
        );
        assert!(
            Turn {
                returned: 1,
                ..Turn::default()
            }
            .did_something()
        );
    }
}
