//! Leases against real PostgreSQL — M12 §2.1.
//!
//! The election is a row lock, so there is nothing to unit test: the whole mechanism *is*
//! the database's concurrency control. These run two claims against one row and check
//! that exactly one of them wins, which is the only way to find out.
//!
//! # Why these serialise themselves
//!
//! Giving each test its own job name would be tidier, but the table's `CHECK` names three
//! jobs on purpose: a typo would silently create a lease nobody contends for, which looks
//! exactly like working code. So the tests share the three real rows — and therefore must
//! not run at the same time as each other.
//!
//! `cargo test` runs a file's tests in parallel, so that is enforced here with a lock
//! rather than by remembering to pass `--test-threads=1`. A test suite that is only
//! correct when invoked a particular way is a suite that fails in CI.

use std::sync::Arc;

use chrono::Utc;
use uops_store_pg::{Claim, Config, Job, PgStore, identity};

/// Held for the length of each test, because they contend for the same three rows.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn store() -> PgStore {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into());
    PgStore::connect(&Config {
        url,
        ..Config::default()
    })
    .await
    .expect("connect")
}

/// Put a lease back to unheld, so one test does not decide another's outcome.
async fn reset(store: &PgStore, job: Job) {
    sqlx::query(
        "UPDATE lease SET holder = 'unclaimed', expires_at = to_timestamp(0),
                          acquired_at = to_timestamp(0), takeovers = 0
         WHERE name = $1",
    )
    .bind(job.as_str())
    .execute(store.pool())
    .await
    .expect("reset");
}

#[tokio::test]
async fn one_process_takes_a_free_lease() {
    let _guard = ONE_AT_A_TIME.lock().await;
    let store = store().await;
    reset(&store, Job::Poll).await;

    let claim = store.claim(Job::Poll, "a:1").await.expect("claim");
    assert!(claim.is_held(), "{claim:?}");

    let held = store.lease_holder(Job::Poll).await.expect("read");
    assert_eq!(held.holder, "a:1");
    assert!(held.live);
    assert_eq!(
        held.takeovers, 1,
        "taking it from nobody is still a takeover"
    );
}

#[tokio::test]
async fn a_second_process_is_refused_while_the_first_holds_it() {
    // The whole point. Two pollers against one database must not both poll — that is
    // double the SNMP load on a customer's fleet and duplicate samples in `metrics`.
    let _guard = ONE_AT_A_TIME.lock().await;
    let store = store().await;
    reset(&store, Job::Alert).await;

    assert!(
        store
            .claim(Job::Alert, "a:1")
            .await
            .expect("first")
            .is_held()
    );
    assert_eq!(
        store.claim(Job::Alert, "b:2").await.expect("second"),
        Claim::Taken
    );

    let held = store.lease_holder(Job::Alert).await.expect("read");
    assert_eq!(held.holder, "a:1", "and the first still holds it");
    assert_eq!(held.takeovers, 1, "a refusal is not a takeover");
}

#[tokio::test]
async fn two_processes_starting_together_elect_exactly_one() {
    // The race the row lock decides. Both run the same UPDATE; PostgreSQL serialises
    // them on the row, and the second finds the predicate false because the first has
    // already moved `expires_at` into the future.
    //
    // Sixteen at once rather than two, because a race that only fails sometimes fails
    // less often with two.
    let _guard = ONE_AT_A_TIME.lock().await;
    let store = Arc::new(store().await);
    reset(&store, Job::Sweep).await;

    let mut racers = tokio::task::JoinSet::new();
    for i in 0..16 {
        let store = Arc::clone(&store);
        racers.spawn(async move { store.claim(Job::Sweep, &format!("racer:{i}")).await });
    }

    let mut held = 0;
    while let Some(result) = racers.join_next().await {
        if result.expect("join").expect("claim").is_held() {
            held += 1;
        }
    }

    assert_eq!(held, 1, "exactly one of sixteen holds the lease");
    assert_eq!(
        store
            .lease_holder(Job::Sweep)
            .await
            .expect("read")
            .takeovers,
        1,
        "and the row agrees it changed hands once"
    );
}

#[tokio::test]
async fn a_holder_renews_without_taking_it_from_itself() {
    // `acquired_at` must not move on a renewal, or "how long has this process held it"
    // becomes "how long since the last renewal" and is always ten seconds.
    let _guard = ONE_AT_A_TIME.lock().await;
    let store = store().await;
    reset(&store, Job::Poll).await;

    store.claim(Job::Poll, "a:1").await.expect("claim");
    let first = store.lease_holder(Job::Poll).await.expect("read");

    let renewed = store.claim(Job::Poll, "a:1").await.expect("renew");
    assert!(renewed.is_held());

    let second = store.lease_holder(Job::Poll).await.expect("read");
    assert_eq!(
        second.acquired_at, first.acquired_at,
        "unchanged by a renewal"
    );
    assert_eq!(second.takeovers, 1, "and it did not take it from itself");
    assert!(
        second.expires_at >= first.expires_at,
        "but the claim was extended"
    );
}

#[tokio::test]
async fn an_expired_lease_is_taken_by_whoever_asks_next() {
    // A process that crashes cannot release anything, so the lease has to lapse on its
    // own — the worst case is a gap of one period, recovered without a human.
    let _guard = ONE_AT_A_TIME.lock().await;
    let store = store().await;
    reset(&store, Job::Alert).await;

    store.claim(Job::Alert, "dead:1").await.expect("claim");
    assert_eq!(
        store.claim(Job::Alert, "live:2").await.expect("blocked"),
        Claim::Taken
    );

    // The crash: nothing releases, and the claim simply runs out.
    sqlx::query("UPDATE lease SET expires_at = now() - interval '1 second' WHERE name = $1")
        .bind(Job::Alert.as_str())
        .execute(store.pool())
        .await
        .expect("expire");

    assert!(
        store
            .claim(Job::Alert, "live:2")
            .await
            .expect("take")
            .is_held(),
        "the survivor takes over"
    );
    let held = store.lease_holder(Job::Alert).await.expect("read");
    assert_eq!(held.holder, "live:2");
    assert_eq!(held.takeovers, 2, "and the counter says it changed hands");
}

#[tokio::test]
async fn releasing_hands_over_immediately() {
    // The optimisation a rolling restart wants: the replacement starts working now
    // instead of waiting out a period nobody is using.
    let _guard = ONE_AT_A_TIME.lock().await;
    let store = store().await;
    reset(&store, Job::Sweep).await;

    store.claim(Job::Sweep, "old:1").await.expect("claim");
    store.release(Job::Sweep, "old:1").await.expect("release");

    assert!(
        store
            .claim(Job::Sweep, "new:2")
            .await
            .expect("take")
            .is_held(),
        "no waiting for the period to run out"
    );
}

#[tokio::test]
async fn releasing_a_lease_somebody_else_took_is_not_an_error() {
    // A slow shutdown finishing after a handover. Treating it as an error would mean a
    // process that was already replaced logs a failure on its way out, and somebody
    // investigates the wrong thing.
    let _guard = ONE_AT_A_TIME.lock().await;
    let store = store().await;
    reset(&store, Job::Poll).await;

    store.claim(Job::Poll, "slow:1").await.expect("claim");
    sqlx::query("UPDATE lease SET expires_at = now() - interval '1 second' WHERE name = $1")
        .bind(Job::Poll.as_str())
        .execute(store.pool())
        .await
        .expect("expire");
    store.claim(Job::Poll, "fast:2").await.expect("takeover");

    store.release(Job::Poll, "slow:1").await.expect("no error");

    let held = store.lease_holder(Job::Poll).await.expect("read");
    assert_eq!(held.holder, "fast:2", "and it did not steal the lease back");
    assert!(held.live, "nor end the new holder's claim");
}

#[tokio::test]
async fn the_three_jobs_are_independent() {
    // One process may hold the alert lease while another holds the poll lease — they are
    // separate elections, and a deployment that runs the schedulers as separate binaries
    // depends on it.
    let _guard = ONE_AT_A_TIME.lock().await;
    let store = store().await;
    for job in [Job::Poll, Job::Alert, Job::Sweep] {
        reset(&store, job).await;
    }

    assert!(
        store
            .claim(Job::Poll, "poller:1")
            .await
            .expect("p")
            .is_held()
    );
    assert!(
        store
            .claim(Job::Alert, "alerter:1")
            .await
            .expect("a")
            .is_held()
    );
    assert!(
        store
            .claim(Job::Sweep, "sweeper:1")
            .await
            .expect("s")
            .is_held()
    );

    assert_eq!(
        store.lease_holder(Job::Poll).await.expect("read").holder,
        "poller:1"
    );
    assert_eq!(
        store.lease_holder(Job::Alert).await.expect("read").holder,
        "alerter:1"
    );
}

#[tokio::test]
async fn an_identity_is_new_on_every_start() {
    // A restarted process must not inherit its predecessor's claim by looking like it,
    // which is exactly what a stable identity would allow while the old lease still had
    // time on it. The pid is what makes it new.
    let me = identity();
    assert!(me.contains(':'), "host and pid: {me}");
    assert!(
        me.ends_with(&std::process::id().to_string()),
        "the pid is the part that changes: {me}"
    );
}

#[tokio::test]
async fn the_expiry_is_the_databases_clock_and_not_the_callers() {
    // The property that makes clock skew between two hosts a non-issue: every comparison
    // is `now()` inside the database, so two processes disagreeing about the time cannot
    // both believe they hold a lease.
    let _guard = ONE_AT_A_TIME.lock().await;
    let store = store().await;
    reset(&store, Job::Sweep).await;

    let before = Utc::now();
    let claim = store.claim(Job::Sweep, "a:1").await.expect("claim");
    let Claim::Held { until } = claim else {
        panic!("expected to hold it");
    };

    // Within a period of *this* machine's now, which is a sanity check rather than the
    // mechanism — the number came from the server.
    assert!(until > before, "{until} should be ahead of {before}");
    assert!(
        until < before + chrono::Duration::seconds(120),
        "and not absurdly far ahead: {until}"
    );
}
