//! What the scheduler promises, against a real `PostgreSQL`.
//!
//! The sweep itself is a closure here. That is the whole point of the seam: these are
//! tests of *scheduling* — due, not due, claimed, failed, restarted, shut down — and a
//! scheduler whose tests need a network is a scheduler nobody runs the tests for.
//!
//! What a real sweep does is already covered by `uops-discover`'s 47 tests and
//! `uops-store-pg`'s sweep-ingest suite.

use std::time::Duration;

use uops_core::{CredentialRef, OrgId, TenantId, TenantScope};
use uops_discover::Range;
use uops_store_pg::discovery_jobs::{DiscoveryJob, NewJob, RunCounts, RunStatus, Trigger};
use uops_store_pg::{Config, PgStore};
use uops_sweeper::{STALE_AFTER, Sweep, Turn, turn};

async fn store() -> PgStore {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops@127.0.0.1:5432/uops".into());
    PgStore::connect(&Config {
        url,
        ..Config::default()
    })
    .await
    .expect("connect")
}

/// A tenant of its own per test.
///
/// Necessary here rather than merely tidy: `turn` sweeps *every* tenant, so two tests
/// sharing one would each see the other's jobs.
async fn tenant(store: &PgStore, slug: &str) -> TenantScope {
    let org = OrgId::new();
    let tenant = TenantId::new();
    let unique = tenant.into_uuid().simple().to_string();

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("sched-org-{unique}"))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("sched-{unique}"))
        .bind(format!("{slug}-{unique}"))
        .execute(store.pool())
        .await
        .expect("tenant");

    TenantScope::collector(tenant)
}

fn job(name: &str, schedule: Option<Duration>) -> NewJob {
    NewJob {
        name: name.to_owned(),
        description: String::new(),
        ranges: vec!["192.168.9.0/24".parse::<Range>().expect("a range parses")],
        site_id: None,
        credential_refs: vec![CredentialRef::new()],
        snmp_port: 161,
        skip_silent_hosts: false,
        schedule,
    }
}

/// A sweep that records which jobs it was asked about.
///
/// Per job rather than a bare count, because `turn` walks every tenant and these tests
/// run in parallel against one database: a counter would pick up jobs belonging to
/// whichever other test happened to be running. Recording the id makes each assertion
/// about this test's own job, which is what it meant all along.
struct Fake {
    swept: std::sync::Mutex<Vec<uuid::Uuid>>,
    outcome: Result<RunCounts, String>,
}

impl Fake {
    fn ok() -> Self {
        Self {
            swept: std::sync::Mutex::new(Vec::new()),
            outcome: Ok(RunCounts {
                probed: 254,
                answered: 3,
                created: 1,
                ..RunCounts::default()
            }),
        }
    }

    fn failing(why: &str) -> Self {
        Self {
            swept: std::sync::Mutex::new(Vec::new()),
            outcome: Err(why.to_owned()),
        }
    }

    /// How many times this particular job was swept.
    fn sweeps_of(&self, job: uuid::Uuid) -> usize {
        self.swept
            .lock()
            .expect("not poisoned")
            .iter()
            .filter(|id| **id == job)
            .count()
    }
}

impl Sweep for Fake {
    #[allow(clippy::unused_async_trait_impl)] // The trait is async; this fake has nothing to await.
    async fn sweep(
        &self,
        _scope: &TenantScope,
        job: &DiscoveryJob,
        _run: uuid::Uuid,
    ) -> Result<RunCounts, String> {
        self.swept.lock().expect("not poisoned").push(job.id);
        self.outcome.clone()
    }
}

/// Only this tenant's part of a turn, since `turn` walks them all.
async fn mine(
    store: &PgStore,
    scope: &TenantScope,
) -> (usize, Vec<uops_store_pg::discovery_jobs::DiscoveryRun>) {
    let runs = store.discovery_runs(scope, 50).await.expect("runs");
    (runs.len(), runs)
}

#[tokio::test]
async fn a_job_that_has_never_run_is_due() {
    let store = store().await;
    let scope = tenant(&store, "never").await;
    let created = store
        .create_discovery_job(
            &scope,
            None,
            &job("Nightly", Some(Duration::from_hours(24))),
        )
        .await
        .expect("create");

    let fake = Fake::ok();
    turn(&store, &fake, &[scope.tenant_id()]).await;

    assert_eq!(
        fake.sweeps_of(created.id),
        1,
        "a job with no last run is overdue by definition"
    );
    let (count, runs) = mine(&store, &scope).await;
    assert_eq!(count, 1);
    assert_eq!(runs[0].status, RunStatus::Succeeded);
    assert_eq!(runs[0].trigger, Trigger::Schedule);
    assert_eq!(runs[0].counts.probed, 254);
}

#[tokio::test]
async fn a_job_with_no_schedule_is_never_due() {
    // Manual-only is a normal thing to want — a one-off sweep of a newly acquired site —
    // and a scheduler that swept it anyway would be sweeping networks nobody asked it to.
    let store = store().await;
    let scope = tenant(&store, "manual").await;
    let created = store
        .create_discovery_job(&scope, None, &job("By hand", None))
        .await
        .expect("create");

    let fake = Fake::ok();
    turn(&store, &fake, &[scope.tenant_id()]).await;

    assert_eq!(fake.sweeps_of(created.id), 0);
    assert_eq!(mine(&store, &scope).await.0, 0);
}

#[tokio::test]
async fn a_disabled_job_is_never_due() {
    // Disabling is what an operator reaches for at 3am instead of deleting.
    let store = store().await;
    let scope = tenant(&store, "disabled").await;
    let created = store
        .create_discovery_job(&scope, None, &job("Paused", Some(Duration::from_hours(1))))
        .await
        .expect("create");
    sqlx::query("UPDATE discovery_job SET enabled = false WHERE id = $1")
        .bind(created.id)
        .execute(store.pool())
        .await
        .expect("disable");

    let fake = Fake::ok();
    turn(&store, &fake, &[scope.tenant_id()]).await;
    assert_eq!(fake.sweeps_of(created.id), 0);
}

#[tokio::test]
async fn a_job_swept_recently_is_not_due_again() {
    // The property the whole schedule rests on: a daily job sweeps once a day, not once a
    // minute for the rest of the day.
    let store = store().await;
    let scope = tenant(&store, "recent").await;
    let created = store
        .create_discovery_job(&scope, None, &job("Daily", Some(Duration::from_hours(24))))
        .await
        .expect("create");

    let fake = Fake::ok();
    turn(&store, &fake, &[scope.tenant_id()]).await;
    assert_eq!(fake.sweeps_of(created.id), 1);

    // A second turn a moment later must find nothing.
    turn(&store, &fake, &[scope.tenant_id()]).await;
    assert_eq!(
        fake.sweeps_of(created.id),
        1,
        "the interval has not elapsed"
    );
    assert_eq!(mine(&store, &scope).await.0, 1);
}

#[tokio::test]
async fn a_job_becomes_due_again_once_its_interval_has_passed() {
    let store = store().await;
    let scope = tenant(&store, "elapsed").await;
    let created = store
        .create_discovery_job(&scope, None, &job("Hourly", Some(Duration::from_hours(1))))
        .await
        .expect("create");

    let fake = Fake::ok();
    turn(&store, &fake, &[scope.tenant_id()]).await;
    assert_eq!(fake.sweeps_of(created.id), 1);

    // Wind the clock back rather than waiting an hour.
    sqlx::query("UPDATE discovery_job SET last_run_at = now() - interval '2 hours' WHERE id = $1")
        .bind(created.id)
        .execute(store.pool())
        .await
        .expect("rewind");

    turn(&store, &fake, &[scope.tenant_id()]).await;
    assert_eq!(fake.sweeps_of(created.id), 2);
    assert_eq!(mine(&store, &scope).await.0, 2);
}

#[tokio::test]
async fn a_failed_sweep_still_closes_its_run_and_schedules_the_next_one() {
    // The rule that stops a broken credential becoming a packet flood: the next run is
    // calculated from when this one ran, not from whether it worked. A `last_run_at` that
    // only advanced on success would make a job that fails every time retry every turn.
    let store = store().await;
    let scope = tenant(&store, "broken").await;
    let created = store
        .create_discovery_job(&scope, None, &job("Broken", Some(Duration::from_hours(24))))
        .await
        .expect("create");

    let fake = Fake::failing("no route to 192.168.9.0/24");
    let report = turn(&store, &fake, &[scope.tenant_id()]).await;

    assert_eq!(fake.sweeps_of(created.id), 1);
    assert!(report.failed >= 1);

    let (_, runs) = mine(&store, &scope).await;
    assert_eq!(runs[0].status, RunStatus::Failed);
    assert_eq!(runs[0].error.as_deref(), Some("no route to 192.168.9.0/24"));
    assert!(runs[0].finished_at.is_some(), "a failure is still an end");

    // And it is not immediately due again.
    turn(&store, &fake, &[scope.tenant_id()]).await;
    assert_eq!(
        fake.sweeps_of(created.id),
        1,
        "a failing job must not retry every turn"
    );
}

#[tokio::test]
async fn one_tenants_broken_jobs_do_not_stop_another_tenants() {
    // One customer of an MSP must not be able to stop discovery for the rest.
    let store = store().await;
    let theirs = tenant(&store, "noisy").await;
    let ours = tenant(&store, "quiet").await;
    store
        .create_discovery_job(
            &theirs,
            None,
            &job("Theirs", Some(Duration::from_hours(24))),
        )
        .await
        .expect("theirs");
    store
        .create_discovery_job(&ours, None, &job("Ours", Some(Duration::from_hours(24))))
        .await
        .expect("ours");

    let fake = Fake::failing("everything is on fire");
    turn(&store, &fake, &[theirs.tenant_id(), ours.tenant_id()]).await;

    // Both were attempted; neither stopped the other.
    assert_eq!(mine(&store, &theirs).await.0, 1);
    assert_eq!(mine(&store, &ours).await.0, 1);
}

#[tokio::test]
async fn a_job_already_in_flight_is_not_swept_twice() {
    // Migration 0020's unique index, reached through the scheduler. Two replicas waking
    // on the same job at 02:00 must produce one sweep, not two.
    let store = store().await;
    let scope = tenant(&store, "inflight").await;
    let created = store
        .create_discovery_job(&scope, None, &job("Busy", Some(Duration::from_hours(24))))
        .await
        .expect("create");

    // Somebody else's sweep, still going.
    store
        .start_discovery_run(
            &scope,
            Some(created.id),
            &created.ranges,
            Trigger::Manual,
            None,
        )
        .await
        .expect("the other run");

    let fake = Fake::ok();
    turn(&store, &fake, &[scope.tenant_id()]).await;

    assert_eq!(
        fake.sweeps_of(created.id),
        0,
        "the job is already being swept"
    );
    assert_eq!(
        mine(&store, &scope).await.0,
        1,
        "and no second run was created"
    );
}

#[tokio::test]
async fn a_run_whose_process_died_is_closed_and_the_job_recovers() {
    // Without the reaper an unclean shutdown disables a job permanently: the orphaned
    // `running` row blocks it under 0020's index, and nothing else would ever close it.
    let store = store().await;
    let scope = tenant(&store, "orphan").await;
    let created = store
        .create_discovery_job(
            &scope,
            None,
            &job("Orphaned", Some(Duration::from_hours(1))),
        )
        .await
        .expect("create");

    let orphan = store
        .start_discovery_run(
            &scope,
            Some(created.id),
            &created.ranges,
            Trigger::Schedule,
            None,
        )
        .await
        .expect("start");
    sqlx::query("UPDATE discovery_run SET started_at = now() - interval '3 hours' WHERE id = $1")
        .bind(orphan.id)
        .execute(store.pool())
        .await
        .expect("age it");

    let fake = Fake::ok();
    let report = turn(&store, &fake, &[scope.tenant_id()]).await;

    assert!(report.reaped >= 1);
    let (_, runs) = store
        .discovery_runs(&scope, 50)
        .await
        .map(|r| (r.len(), r))
        .expect("runs");
    let reaped = runs.iter().find(|r| r.id == orphan.id).expect("the orphan");
    assert_eq!(reaped.status, RunStatus::Failed);
    assert!(
        reaped
            .error
            .as_deref()
            .is_some_and(|e| e.contains("stopped")),
        "a reaped run says why: {:?}",
        reaped.error
    );

    // And the job was swept in the same turn, rather than staying blocked.
    assert_eq!(fake.sweeps_of(created.id), 1);
}

#[tokio::test]
async fn a_run_that_is_merely_slow_is_left_alone() {
    // Being wrong in this direction cancels a sweep that is still working. The largest
    // legal sweep is about twenty-two minutes; STALE_AFTER is five times that.
    let store = store().await;
    let scope = tenant(&store, "slow").await;
    let created = store
        .create_discovery_job(&scope, None, &job("Slow", Some(Duration::from_hours(1))))
        .await
        .expect("create");
    let running = store
        .start_discovery_run(
            &scope,
            Some(created.id),
            &created.ranges,
            Trigger::Schedule,
            None,
        )
        .await
        .expect("start");
    sqlx::query(
        "UPDATE discovery_run SET started_at = now() - interval '30 minutes' WHERE id = $1",
    )
    .bind(running.id)
    .execute(store.pool())
    .await
    .expect("age it");

    let fake = Fake::ok();
    turn(&store, &fake, &[scope.tenant_id()]).await;

    let (_, runs) = mine(&store, &scope).await;
    let still = runs.iter().find(|r| r.id == running.id).expect("the run");
    assert_eq!(still.status, RunStatus::Running, "half an hour is not dead");
    assert!(
        STALE_AFTER > Duration::from_mins(22),
        "and the margin is real"
    );
}

#[tokio::test]
async fn the_schedule_survives_a_restart_because_it_was_never_in_memory() {
    // There is no in-memory schedule to lose: a "restart" is a fresh `turn` against the
    // same database, which is exactly what the process does when it comes back.
    let store = store().await;
    let scope = tenant(&store, "restart").await;
    let created = store
        .create_discovery_job(
            &scope,
            None,
            &job("Survivor", Some(Duration::from_hours(1))),
        )
        .await
        .expect("create");

    let before = Fake::ok();
    turn(&store, &before, &[scope.tenant_id()]).await;
    assert_eq!(before.sweeps_of(created.id), 1);

    sqlx::query("UPDATE discovery_job SET last_run_at = now() - interval '2 hours' WHERE id = $1")
        .bind(created.id)
        .execute(store.pool())
        .await
        .expect("rewind");

    // A different scheduler entirely, as after a restart.
    let after = Fake::ok();
    turn(&store, &after, &[scope.tenant_id()]).await;
    assert_eq!(
        after.sweeps_of(created.id),
        1,
        "the new process found the same job due"
    );
}

#[tokio::test]
async fn a_turn_with_nothing_to_do_reports_nothing() {
    let store = store().await;
    let scope = tenant(&store, "idle").await;
    let fake = Fake::ok();
    turn(&store, &fake, &[scope.tenant_id()]).await;
    assert_eq!(Turn::default().swept, 0);
}
