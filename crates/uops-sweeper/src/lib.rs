//! Running discovery jobs when they are due — M5's last piece.
//!
//! ```text
//!   reap     close runs whose process is not coming back      every TURN
//!   ask      which jobs are due, per tenant                   every TURN
//!   claim    start a run, or find somebody else already has   per job
//!   sweep    hand it to uops-discover and record what it found
//!   finish   write the counters, whatever happened
//! ```
//!
//! # The one rule this crate is built around
//!
//! **The scheduler schedules discovery; it does not become another implementation of
//! it.** Everything between `claim` and `finish` is a call into code that already exists
//! and is already tested — `uops_discover::run_with` for the sweep,
//! `PgStore::record_sweep` for the inventory, `PgStore::finish_discovery_run` for the
//! counters. If a behaviour differs between a scheduled sweep and one an operator started
//! by hand, that is a bug in this file rather than a feature of it.
//!
//! [`Sweep`] is the seam. In production it builds SNMP transports from the job's
//! credentials and runs them; in a test it is a closure that returns counters. That is
//! the same shape `uops_poll::run_tick` uses, and for the same reason: a scheduler whose
//! tests need a network is a scheduler nobody tests.
//!
//! # Why there is no wheel
//!
//! `uops-alert` puts a thousand rules in a [`uops_poll::Wheel`] because it has a thousand
//! of them on sixty-second intervals and the wheel is what stops them all waking at once.
//! Discovery jobs are counted in tens and run hourly at their fastest, so the schedule
//! lives entirely in `discovery_job.schedule` and `last_run_at`, and each turn simply
//! asks. `discovery_job_due_idx` was built for that question.
//!
//! The consequence is the one that matters for restarts: **there is no in-memory
//! schedule to lose.** A server that is killed and comes back asks the same question and
//! gets the same answer, which is `PostgreSQL` doing what it is for.
//!
//! [`uops_poll::Wheel`]: https://docs.rs/uops-poll

pub mod live;
pub use live::Live;

use std::time::Duration;

use uops_core::TenantScope;
use uops_store_pg::PgStore;
use uops_store_pg::discovery_jobs::{DiscoveryJob, RunCounts, RunStatus, Trigger};

/// How often the scheduler asks whether anything is due.
///
/// A minute. The shortest interval the schema allows is an hour — migration 0017 refuses
/// less, because the estate does not change every minute — so a finer tick would only
/// cost queries, and a coarser one would make "hourly" mean "within five minutes of
/// hourly" for no gain.
pub const TURN: Duration = Duration::from_mins(1);

/// How long a run may sit in `running` before it is presumed dead.
///
/// The largest sweep the schema permits is 65 536 addresses against four credentials,
/// which at `PROBES_PER_SECOND` is about twenty-two minutes. Two hours is five times
/// that, so a run reaped at this age is one whose process is genuinely gone rather than
/// one that is merely slow — and being wrong in that direction would cancel a sweep that
/// was still working.
pub const STALE_AFTER: Duration = Duration::from_hours(2);

/// How many jobs are swept at once.
///
/// One. A sweep is already internally concurrent and rate-capped — `IN_FLIGHT` probes at
/// `PROBES_PER_SECOND` — and running two at once would double what the customer's network
/// sees while halving neither's duration. The caps are per-sweep, so the only way to
/// honour them across an installation is to have one sweep.
const AT_ONCE: usize = 1;

/// What one turn did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Turn {
    /// Jobs found due across every tenant.
    pub due: usize,
    /// Jobs swept to completion this turn.
    pub swept: usize,
    /// Jobs another process had already claimed. Not a failure — see [`run_job`].
    pub claimed_elsewhere: usize,
    /// Sweeps that failed. The run carries the reason; the scheduler carries on.
    pub failed: usize,
    /// Runs closed because their process did not come back.
    pub reaped: u64,
}

/// What a sweep does, so a test can do something else.
///
/// Returns the counters for the run, or a sentence explaining why it could not. The
/// sentence goes on the run and is what an operator reads.
pub trait Sweep {
    fn sweep(
        &self,
        scope: &TenantScope,
        job: &DiscoveryJob,
        run_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = Result<RunCounts, String>> + Send;
}

/// One turn of the scheduler, over the tenants it is given.
///
/// The caller supplies the tenants rather than this reading them, which is the same seam
/// as [`Sweep`] and pays off the same way: the loop asks `all_tenant_ids` every turn so a
/// tenant created a minute ago is swept, and a test drives its own tenant without walking
/// an entire shared database. It also leaves room for a future scheduler that shards
/// tenants across replicas without having to be taken apart first.
///
/// Never returns an error. A tenant whose jobs cannot be read, a job that cannot be
/// claimed and a sweep that fails are all recorded and stepped over: one broken tenant
/// must not stop discovery for everybody else, which is the same rule `uops-alert`'s
/// cycle follows.
pub async fn turn<S: Sweep + Sync>(
    store: &PgStore,
    sweeper: &S,
    tenants: &[uops_core::TenantId],
) -> Turn {
    let mut report = Turn::default();

    for tenant in tenants.iter().copied() {
        let scope = TenantScope::collector(tenant);

        // Before asking what is due, because a job blocked by a dead run would otherwise
        // never come back — see `reap_stale_runs`.
        if let Ok(n) = store.reap_stale_runs(&scope, STALE_AFTER).await {
            report.reaped += n;
        }

        let Ok(due) = store.due_discovery_jobs(&scope).await else {
            continue;
        };
        report.due += due.len();

        for job in due.iter().take(due.len().max(AT_ONCE)) {
            match run_job(store, sweeper, &scope, job).await {
                Outcome::Swept => report.swept += 1,
                Outcome::Failed => report.failed += 1,
                Outcome::Elsewhere => report.claimed_elsewhere += 1,
            }
        }
    }

    report
}

enum Outcome {
    Swept,
    Failed,
    Elsewhere,
}

/// Claim a job, sweep it, and close the run whatever happened.
///
/// The claim is the `INSERT` into `discovery_run`. Migration 0020 has a unique index over
/// the in-flight run of a job, so a second scheduler — another replica, or this one if a
/// previous sweep is somehow still going — gets a constraint violation instead of a
/// second sweep. That is read as "somebody else has it" rather than reported as an error:
/// it is the mechanism working, not a fault.
async fn run_job<S: Sweep>(
    store: &PgStore,
    sweeper: &S,
    scope: &TenantScope,
    job: &DiscoveryJob,
) -> Outcome {
    let Ok(run) = store
        .start_discovery_run(scope, Some(job.id), &job.ranges, Trigger::Schedule, None)
        .await
    else {
        return Outcome::Elsewhere;
    };

    let (status, counts, error) = match sweeper.sweep(scope, job, run.id).await {
        Ok(counts) => (RunStatus::Succeeded, counts, None),
        Err(why) => (RunStatus::Failed, RunCounts::default(), Some(why)),
    };

    // The run is closed even when the sweep failed, and closing it is what stamps the
    // job's `last_run_at`. Both matter: a run left open blocks the job until the reaper
    // gets to it, and a `last_run_at` that only advanced on success would make a job that
    // fails every time retry every single turn — which is how a broken credential becomes
    // a packet flood. §14 of the schema calls this "the next run is calculated
    // independently of the last one's outcome"; this is where that is true.
    let finished = store
        .finish_discovery_run(scope, run.id, status, counts, error.as_deref())
        .await;

    match (finished, status) {
        (Ok(_), RunStatus::Succeeded) => Outcome::Swept,
        _ => Outcome::Failed,
    }
}

/// The loop.
///
/// Runs until `stop` is cancelled. A turn that takes longer than [`TURN`] — a large sweep
/// does — simply starts the next one when it is done rather than piling up: the interval
/// is a floor on how often the question is asked, not a promise to ask on the second.
///
/// Shutdown is awaited alongside the sleep, so stopping does not wait out the rest of a
/// minute. A sweep already in flight is dropped with the future, and the run it left open
/// is closed by the reaper on the next start — which is why the reaper exists.
///
/// The shutdown is a future rather than a watch channel so that the server passes the
/// same `shutdown::signal()` it gives the alert engine and the listener. One signal, three
/// readers, no third way for this process to be asked to stop.
pub async fn run<S: Sweep + Sync, F>(store: PgStore, sweeper: S, shutdown: F)
where
    F: Future<Output = ()> + Send,
{
    tokio::pin!(shutdown);

    loop {
        // Asked every turn rather than once at start-up, so a tenant created since the
        // process booted is swept without waiting for a restart.
        let tenants = store.all_tenant_ids().await.unwrap_or_default();
        let report = turn(&store, &sweeper, &tenants).await;
        if report.swept > 0 || report.failed > 0 || report.reaped > 0 {
            println!(
                "discovery: {} swept, {} failed, {} runs reaped",
                report.swept, report.failed, report.reaped
            );
        }

        tokio::select! {
            () = tokio::time::sleep(TURN) => {}
            () = &mut shutdown => {
                println!("discovery: stopping");
                return;
            }
        }
    }
}
