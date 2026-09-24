//! The collector registry against real `PostgreSQL` — M12 §2.3.
//!
//! What only these can settle is the part that is a *transaction* rather than a rule: a
//! restart must not spend a use, ten collectors racing one single-use token must produce
//! one collector, and an assignment must not be able to name another organization's
//! tenant. All three compile perfectly when written the wrong way.

use chrono::{Duration, Utc};
use uops_core::{OrgId, TenantId};
use uops_store_pg::{Config, Kind, PgStore, Report};

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

/// An organization with two tenants of its own, so one test's assignment is not another's.
struct Fixture {
    store: PgStore,
    org: OrgId,
    a: TenantId,
    b: TenantId,
}

async fn fixture(slug: &str) -> Fixture {
    let store = store().await;
    let org = OrgId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("col-org-{slug}-{}", org.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("organization");

    let mut tenants = Vec::new();
    for which in ["a", "b"] {
        let id = TenantId::new();
        sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
            .bind(id.into_uuid())
            .bind(org.into_uuid())
            .bind(format!("col-{slug}-{which}"))
            .bind(format!("col-{slug}-{which}-{}", id.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("tenant");
        tenants.push(id);
    }

    Fixture {
        store,
        org,
        a: tenants[0],
        b: tenants[1],
    }
}

fn report() -> Report {
    Report {
        hostname: Some("berlin-01.example.invalid".to_owned()),
        version: Some("0.0.1".to_owned()),
        reported: Some(serde_json::json!({"udp": "0.0.0.0:514"})),
        started_at: Some(Utc::now()),
        received: 10,
        written: 9,
        lost: 1,
    }
}

// ---------------------------------------------------------------------------
// Enrolling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_collector_enrols_and_appears_in_the_inventory() {
    let f = fixture("enrol").await;
    let (token, _) = f
        .store
        .issue_enrolment_token(f.org, "site-berlin", None, None, None, None)
        .await
        .expect("token");

    let enrolled = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .expect("enrol");

    assert_eq!(
        enrolled.org_id, f.org,
        "the token decides whose collector this is"
    );
    assert!(
        enrolled.tenants.is_empty(),
        "a collector that nobody has assigned serves nothing, not everything"
    );

    let inventory = f.store.collectors(f.org).await.expect("inventory");
    assert_eq!(inventory.len(), 1);
    let row = &inventory[0];
    assert_eq!(row.id, enrolled.collector_id);
    assert_eq!(row.kind, Kind::Syslog);
    assert_eq!(row.name, "berlin-01");
    assert_eq!(row.version.as_deref(), Some("0.0.1"));
    assert_eq!(row.received, 10);
    assert!(!row.quiet, "it has just reported");
    assert!(!row.never_reported);
}

#[tokio::test]
async fn restarting_claims_the_same_row_and_spends_no_use() {
    // Enrolment is idempotent on `(org, kind, name)`, which is what removes the identity
    // file. A restart loop must not burn a ten-use token in five minutes.
    let f = fixture("restart").await;
    let (token, id) = f
        .store
        .issue_enrolment_token(f.org, "site", None, None, Some(10), None)
        .await
        .expect("token");

    let first = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .expect("enrol");
    for _ in 0..5 {
        let again = f
            .store
            .enrol(&token, Kind::Syslog, "berlin-01", &report())
            .await
            .expect("re-enrol");
        assert_eq!(again.collector_id, first.collector_id);
    }

    let tokens = f.store.enrolment_tokens(f.org).await.expect("tokens");
    let t = tokens.iter().find(|t| t.id == id).expect("the token");
    assert_eq!(
        t.uses_left,
        Some(9),
        "six enrolments of one collector spent one use"
    );
    assert_eq!(f.store.collectors(f.org).await.unwrap().len(), 1);
}

#[tokio::test]
async fn one_host_may_run_two_kinds_under_one_name() {
    let f = fixture("kinds").await;
    let (token, _) = f
        .store
        .issue_enrolment_token(f.org, "site", None, None, None, None)
        .await
        .expect("token");

    let syslog = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();
    let otlp = f
        .store
        .enrol(&token, Kind::Otlp, "berlin-01", &report())
        .await
        .unwrap();

    assert_ne!(syslog.collector_id, otlp.collector_id);
    assert_eq!(f.store.collectors(f.org).await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_single_use_token_brings_up_one_collector() {
    let f = fixture("single").await;
    let (token, _) = f
        .store
        .issue_enrolment_token(f.org, "one-shot", None, None, Some(1), None)
        .await
        .expect("token");

    f.store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .expect("the first one enrols");

    // Refused *as a refusal*, not as a database error. The `CHECK (uses_left >= 0)` in
    // migration 0025 would stop the second one either way — it is the backstop and it is
    // what makes the count safe under any interleaving — but a constraint violation
    // reaches the log as "storage: ..." and tells the operator holding the console
    // nothing. The condition on the decrement is what turns it into a sentence.
    let second = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-02", &report())
        .await;
    let Err(uops_core::Error::Forbidden(why)) = second else {
        panic!("expected a refusal naming the reason, got {second:?}")
    };
    assert!(why.contains("no uses left"), "{why}");

    // And the first one can still restart, because a restart claims a row rather than
    // creating one. A token that stopped its own collector from coming back would be a
    // token nobody sets a use count on.
    f.store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .expect("the enrolled one restarts");
}

#[tokio::test]
async fn ten_collectors_racing_one_single_use_token_produce_one_collector() {
    // An end-to-end assertion of the outcome, and **not** a proof of the concurrency
    // property — saying which is the point.
    //
    // The interleaving is not forced: the pool decides how much of this actually
    // overlaps, and the test passes under a serial one too. What makes the count safe is
    // in the schema and the statement rather than here — `CHECK (uses_left >= 0)` in
    // migration 0025, and a decrement whose `WHERE` is evaluated under the row lock
    // PostgreSQL takes for it. Returning without committing takes the collector row with
    // it, so a row only survives if a use was actually claimed for it.
    //
    // This test is worth keeping because it exercises all of that under parallel load
    // and would catch an enrolment that leaked rows. It is not worth believing more than
    // that.
    let f = fixture("race").await;
    let (token, _) = f
        .store
        .issue_enrolment_token(f.org, "race", None, None, Some(1), None)
        .await
        .expect("token");

    let mut set = tokio::task::JoinSet::new();
    for n in 0..10 {
        let store = f.store.clone();
        let token = token.clone();
        set.spawn(async move {
            store
                .enrol(&token, Kind::Syslog, &format!("box-{n}"), &report())
                .await
                .is_ok()
        });
    }

    let mut enrolled = 0;
    while let Some(result) = set.join_next().await {
        if result.expect("task") {
            enrolled += 1;
        }
    }

    assert_eq!(
        enrolled, 1,
        "a one-use token enrolled {enrolled} collectors"
    );
    assert_eq!(f.store.collectors(f.org).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_token_that_will_not_do_is_refused() {
    let f = fixture("refuse").await;

    // Unknown.
    assert!(
        f.store
            .enrol("not a token", Kind::Syslog, "x", &report())
            .await
            .is_err()
    );

    // Expired.
    let (expired, _) = f
        .store
        .issue_enrolment_token(
            f.org,
            "expired",
            None,
            Some(Utc::now() - Duration::hours(1)),
            None,
            None,
        )
        .await
        .unwrap();
    assert!(
        f.store
            .enrol(&expired, Kind::Syslog, "x", &report())
            .await
            .is_err()
    );

    // Restricted to another kind. A token handed to a site engineer to bring up a syslog
    // box has no business enrolling a poller.
    let (syslog_only, _) = f
        .store
        .issue_enrolment_token(f.org, "syslog-only", Some(Kind::Syslog), None, None, None)
        .await
        .unwrap();
    assert!(
        f.store
            .enrol(&syslog_only, Kind::Poller, "x", &report())
            .await
            .is_err()
    );
    assert!(
        f.store
            .enrol(&syslog_only, Kind::Syslog, "x", &report())
            .await
            .is_ok()
    );

    // Revoked.
    let (revoked, id) = f
        .store
        .issue_enrolment_token(f.org, "revoked", None, None, None, None)
        .await
        .unwrap();
    assert!(f.store.revoke_enrolment_token(f.org, id).await.unwrap());
    assert!(
        f.store
            .enrol(&revoked, Kind::Syslog, "y", &report())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn revoking_a_token_does_not_stop_the_collectors_it_brought_up() {
    // Enrolment is a bootstrap. A revocation that silently stopped forty running
    // collectors would be a revocation nobody dares perform.
    let f = fixture("revoke-live").await;
    let (token, id) = f
        .store
        .issue_enrolment_token(f.org, "site", None, None, None, None)
        .await
        .unwrap();
    let enrolled = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();

    f.store.revoke_enrolment_token(f.org, id).await.unwrap();

    f.store
        .heartbeat(enrolled.collector_id, &report())
        .await
        .expect("a running collector keeps reporting");
}

// ---------------------------------------------------------------------------
// Assignment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_assignment_comes_back_on_every_heartbeat() {
    // Which is what makes a server-side change take effect within a heartbeat rather
    // than at the collector's next restart.
    let f = fixture("assign").await;
    let (token, _) = f
        .store
        .issue_enrolment_token(f.org, "site", None, None, None, None)
        .await
        .unwrap();
    let enrolled = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();
    assert!(enrolled.tenants.is_empty());

    f.store
        .assign_collector_tenant(f.org, enrolled.collector_id, f.a, None)
        .await
        .unwrap();
    let after = f
        .store
        .heartbeat(enrolled.collector_id, &report())
        .await
        .unwrap();
    assert_eq!(after, vec![f.a]);

    f.store
        .assign_collector_tenant(f.org, enrolled.collector_id, f.b, None)
        .await
        .unwrap();
    let both = f
        .store
        .heartbeat(enrolled.collector_id, &report())
        .await
        .unwrap();
    assert_eq!(both.len(), 2);

    assert!(
        f.store
            .unassign_collector_tenant(f.org, enrolled.collector_id, f.a)
            .await
            .unwrap()
    );
    let one = f
        .store
        .heartbeat(enrolled.collector_id, &report())
        .await
        .unwrap();
    assert_eq!(one, vec![f.b]);
}

#[tokio::test]
async fn assigning_twice_is_not_an_error() {
    let f = fixture("twice").await;
    let (token, _) = f
        .store
        .issue_enrolment_token(f.org, "site", None, None, None, None)
        .await
        .unwrap();
    let enrolled = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();

    for _ in 0..3 {
        f.store
            .assign_collector_tenant(f.org, enrolled.collector_id, f.a, None)
            .await
            .expect("an operator clicking twice is not an error");
    }
    assert_eq!(
        f.store
            .heartbeat(enrolled.collector_id, &report())
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_collector_cannot_be_assigned_another_organizations_tenant() {
    // The boundary that matters. Before this table any collector with database
    // credentials could carry any tenant by editing its own YAML; the point of moving
    // the decision server-side is lost if the server will assign anything.
    let ours = fixture("ours").await;
    let theirs = fixture("theirs").await;

    let (token, _) = ours
        .store
        .issue_enrolment_token(ours.org, "site", None, None, None, None)
        .await
        .unwrap();
    let enrolled = ours
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();

    let refused = ours
        .store
        .assign_collector_tenant(ours.org, enrolled.collector_id, theirs.a, None)
        .await;
    assert!(refused.is_err(), "{refused:?}");

    // Claiming the other organization's id does not help either: the collector half of
    // the composite key stops matching instead.
    let also_refused = ours
        .store
        .assign_collector_tenant(theirs.org, enrolled.collector_id, theirs.a, None)
        .await;
    assert!(also_refused.is_err(), "{also_refused:?}");
}

#[tokio::test]
async fn one_organizations_inventory_is_not_anothers() {
    let ours = fixture("inv-ours").await;
    let theirs = fixture("inv-theirs").await;

    let (token, _) = ours
        .store
        .issue_enrolment_token(ours.org, "site", None, None, None, None)
        .await
        .unwrap();
    ours.store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();

    assert_eq!(ours.store.collectors(ours.org).await.unwrap().len(), 1);
    assert!(
        theirs
            .store
            .collectors(theirs.org)
            .await
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Going quiet
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_collector_that_stops_reporting_goes_quiet() {
    let f = fixture("quiet").await;
    let (token, _) = f
        .store
        .issue_enrolment_token(f.org, "site", None, None, None, None)
        .await
        .unwrap();
    let enrolled = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();

    assert!(!f.store.collectors(f.org).await.unwrap()[0].quiet);

    // Wind the clock back rather than waiting three minutes. `last_seen_at` is the only
    // input, which is what makes the threshold testable at all.
    sqlx::query("UPDATE collector SET last_seen_at = now() - interval '4 minutes' WHERE id = $1")
        .bind(enrolled.collector_id)
        .execute(f.store.pool())
        .await
        .unwrap();

    let row = &f.store.collectors(f.org).await.unwrap()[0];
    assert!(row.quiet, "four minutes of silence is quiet");
    assert!(!row.never_reported);

    // And reporting brings it back, without anything having to clear a flag.
    f.store
        .heartbeat(enrolled.collector_id, &report())
        .await
        .unwrap();
    assert!(!f.store.collectors(f.org).await.unwrap()[0].quiet);
}

#[tokio::test]
async fn a_collector_that_never_reported_is_not_the_same_as_one_that_stopped() {
    // Different problems: a box that enrolled and never sent anything is a
    // misconfiguration, and one that sent and stopped is an outage.
    let f = fixture("never").await;
    let (token, _) = f
        .store
        .issue_enrolment_token(f.org, "site", None, None, None, None)
        .await
        .unwrap();
    let enrolled = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();

    sqlx::query("UPDATE collector SET last_seen_at = NULL WHERE id = $1")
        .bind(enrolled.collector_id)
        .execute(f.store.pool())
        .await
        .unwrap();

    let row = &f.store.collectors(f.org).await.unwrap()[0];
    assert!(row.never_reported);
    assert!(
        !row.quiet,
        "never having reported is not the same as having gone quiet"
    );
}

#[tokio::test]
async fn a_heartbeat_from_a_collector_that_no_longer_exists_is_a_not_found() {
    // Which its caller turns into a re-enrolment rather than a crash.
    let f = fixture("gone").await;
    let err = f.store.heartbeat(uuid::Uuid::now_v7(), &report()).await;
    assert!(matches!(
        err,
        Err(uops_core::Error::NotFound {
            kind: "collector",
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// Retiring
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_retired_collector_that_comes_back_un_retires_itself() {
    // The honest outcome when somebody retires a box and it starts talking again. The
    // alternative is an inventory that hides a running collector.
    let f = fixture("retire").await;
    let (token, _) = f
        .store
        .issue_enrolment_token(f.org, "site", None, None, None, None)
        .await
        .unwrap();
    let enrolled = f
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();
    f.store
        .assign_collector_tenant(f.org, enrolled.collector_id, f.a, None)
        .await
        .unwrap();

    assert!(
        f.store
            .retire_collector(f.org, enrolled.collector_id)
            .await
            .unwrap()
    );
    let row = &f.store.collectors(f.org).await.unwrap()[0];
    assert!(row.retired);
    assert_eq!(
        row.tenants.len(),
        1,
        "retiring does not silently drop what it was carrying"
    );

    f.store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();
    assert!(!f.store.collectors(f.org).await.unwrap()[0].retired);
}

#[tokio::test]
async fn retiring_another_organizations_collector_does_nothing() {
    let ours = fixture("ret-ours").await;
    let theirs = fixture("ret-theirs").await;
    let (token, _) = ours
        .store
        .issue_enrolment_token(ours.org, "site", None, None, None, None)
        .await
        .unwrap();
    let enrolled = ours
        .store
        .enrol(&token, Kind::Syslog, "berlin-01", &report())
        .await
        .unwrap();

    assert!(
        !theirs
            .store
            .retire_collector(theirs.org, enrolled.collector_id)
            .await
            .unwrap(),
        "a collector another organization cannot see is a collector it cannot retire"
    );
    assert!(!ours.store.collectors(ours.org).await.unwrap()[0].retired);
}
