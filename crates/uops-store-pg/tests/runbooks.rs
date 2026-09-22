//! Runbooks against real `PostgreSQL` — M10.
//!
//! `uops-runbook` proves the rules over pure data. What only these can settle is the part
//! that is a *transaction* or a *constraint*: that saving twice writes a second version
//! rather than changing the first, that an approval from the person who started the run
//! does not exist, and that one person cannot approve twice.
//!
//! All three compile perfectly when written the wrong way, and all three are the kind of
//! rule an application enforces right up until somebody writes a row another way.

use uops_core::{ActorId, OrgId, ResourceId, Secret, TenantId, TenantScope};
use uops_query::ast::ResourceSelector;
use uops_runbook::{Action, Approvals, Rollback, Runbook, Step};
use uops_store_pg::{Config, PgStore, RunState};

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

struct Fixture {
    store: PgStore,
    scope: TenantScope,
    starter: ActorId,
    approver: ActorId,
    someone_else: ActorId,
    device: ResourceId,
}

async fn fixture(slug: &str) -> Fixture {
    let store = store().await;
    let org = OrgId::new();
    let tenant = TenantId::new();

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("rb-org-{slug}-{}", tenant.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("rb-{slug}"))
        .bind(format!("rb-{slug}-{}", tenant.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("tenant");

    let hash = uops_secrets::password::hash(&Secret::new("correct horse".to_owned()))
        .expect("hash");
    let mut users = Vec::new();
    for who in ["starter", "approver", "else"] {
        users.push(
            store
                .create_user(
                    org,
                    &format!("{who}-{}@test.invalid", tenant.into_uuid().simple()),
                    who,
                    &hash,
                )
                .await
                .expect("user"),
        );
    }

    let device = ResourceId::new();
    sqlx::query(
        "INSERT INTO resource (id, tenant_id, kind, name, status)
         VALUES ($1, $2, 'device', $3, 'unknown')",
    )
    .bind(device.into_uuid())
    .bind(tenant.into_uuid())
    .bind("core-sw-01")
    .execute(store.pool())
    .await
    .expect("resource");

    Fixture {
        store,
        scope: TenantScope::system(tenant),
        starter: users[0],
        approver: users[1],
        someone_else: users[2],
        device,
    }
}

fn runbook(name: &str, approvals: Approvals) -> Runbook {
    Runbook {
        name: name.to_owned(),
        description: "restart a stuck BGP session".to_owned(),
        targets: ResourceSelector::All,
        steps: vec![Step {
            name: "clear it".to_owned(),
            action: Action::SshCommand {
                command: "clear bgp neighbor {{ peer }}".to_owned(),
                credential: uops_core::CredentialRef::new(),
            },
            destructive: true,
            rollback: Some(Rollback::None {
                because: "a cleared session cannot be un-cleared".to_owned(),
            }),
            expect: None,
            continue_on_error: false,
        }],
        max_targets: 10,
        concurrency: 2,
        approvals,
        maintenance_only: false,
    }
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn saving_twice_writes_a_second_version_and_leaves_the_first() {
    // A run names the version it executed, so "what did this actually do in March" has to
    // have an answer that does not depend on nobody having edited it since.
    let f = fixture("versions").await;

    let first = f
        .store
        .save_runbook(&f.scope, &runbook("restart-bgp", Approvals::One), Some(f.starter))
        .await
        .expect("save");
    assert_eq!(first.version, 1);

    let mut edited = runbook("restart-bgp", Approvals::Two);
    edited.description = "now needs two people".to_owned();
    let second = f
        .store
        .save_runbook(&f.scope, &edited, Some(f.starter))
        .await
        .expect("save again");

    assert_eq!(second.version, 2);
    assert_eq!(second.id, first.id, "the same runbook, a new version");
    assert_ne!(second.version_id, first.version_id);

    // The first version is still readable, and still says what it said.
    let (_, original) = f
        .store
        .runbook_version(&f.scope, first.version_id)
        .await
        .expect("query")
        .expect("version 1 is still there");
    assert_eq!(original.approvals, Approvals::One);
    assert_eq!(original.description, "restart a stuck BGP session");

    // And the listing shows the current one.
    let listed = f.store.runbooks(&f.scope).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].version, 2);
    assert_eq!(listed[0].runbook.approvals, Approvals::Two);
}

#[tokio::test]
async fn a_version_cannot_be_edited_even_by_a_direct_update() {
    // The property the application enforces by never issuing an UPDATE, and the schema
    // enforces regardless — which is the one that holds when somebody writes a row by
    // another route.
    let f = fixture("immutable").await;
    let saved = f
        .store
        .save_runbook(&f.scope, &runbook("restart-bgp", Approvals::One), None)
        .await
        .unwrap();

    let refused = sqlx::query("UPDATE runbook_version SET steps = '[]' WHERE id = $1")
        .bind(saved.version_id)
        .execute(f.store.pool())
        .await;

    let err = refused.expect_err("a version must not be editable");
    assert!(
        err.to_string().contains("save a new version"),
        "the refusal says what to do instead: {err}"
    );
}

#[tokio::test]
async fn a_runbook_survives_the_round_trip_unchanged() {
    // The steps go through `jsonb`, so a field that fails to serialise or deserialise
    // would be a runbook that runs something other than what was reviewed.
    let f = fixture("roundtrip").await;
    let written = runbook("restart-bgp", Approvals::Two);

    let saved = f
        .store
        .save_runbook(&f.scope, &written, None)
        .await
        .unwrap();
    let (_, read_back) = f
        .store
        .runbook_version(&f.scope, saved.version_id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(read_back, written);
}

#[tokio::test]
async fn one_tenants_runbooks_are_not_anothers() {
    let ours = fixture("iso-ours").await;
    let theirs = fixture("iso-theirs").await;

    let saved = ours
        .store
        .save_runbook(&ours.scope, &runbook("restart-bgp", Approvals::One), None)
        .await
        .unwrap();

    assert_eq!(ours.store.runbooks(&ours.scope).await.unwrap().len(), 1);
    assert!(theirs.store.runbooks(&theirs.scope).await.unwrap().is_empty());
    assert!(
        theirs
            .store
            .runbook_version(&theirs.scope, saved.version_id)
            .await
            .unwrap()
            .is_none(),
        "a version another tenant cannot see is one it cannot read"
    );
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

async fn a_run(f: &Fixture) -> uuid::Uuid {
    let saved = f
        .store
        .save_runbook(&f.scope, &runbook("restart-bgp", Approvals::Two), None)
        .await
        .unwrap();
    f.store
        .create_run(
            &f.scope,
            saved.id,
            saved.version_id,
            RunState::AwaitingApproval,
            false,
            &[(f.device, "core-sw-01".to_owned())],
            "sha:abc",
            "the session is stuck",
            f.starter,
            false,
        )
        .await
        .expect("run")
}

#[tokio::test]
async fn the_person_who_started_a_run_cannot_approve_it() {
    // The whole of two-person integrity. Refused here with a sentence, and
    // unrepresentable in the schema regardless — see migration 0026.
    let f = fixture("self-approve").await;
    let run = a_run(&f).await;

    let err = f
        .store
        .approve_run(&f.scope, run, f.starter)
        .await
        .expect_err("self-approval must be refused");
    assert!(matches!(err, uops_core::Error::Forbidden(_)), "{err:?}");
    assert!(err.to_string().contains("cannot approve"), "{err}");

    // And the row does not exist, whatever the application did.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM runbook_approval WHERE run_id = $1")
        .bind(run)
        .fetch_one(f.store.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn one_person_cannot_approve_twice() {
    // Two approvals from one person are one person agreeing twice, which is the exact
    // thing two-person integrity exists to refuse.
    let f = fixture("twice").await;
    let run = a_run(&f).await;

    f.store
        .approve_run(&f.scope, run, f.approver)
        .await
        .expect("the first approval");

    let err = f
        .store
        .approve_run(&f.scope, run, f.approver)
        .await
        .expect_err("the second from the same person must be refused");
    assert!(err.to_string().contains("agreeing twice"), "{err}");
}

#[tokio::test]
async fn two_distinct_people_are_two_approvals() {
    let f = fixture("two-people").await;
    let run = a_run(&f).await;

    f.store.approve_run(&f.scope, run, f.approver).await.unwrap();
    f.store
        .approve_run(&f.scope, run, f.someone_else)
        .await
        .unwrap();

    let runs = f.store.runs(&f.scope, 10).await.unwrap();
    let listed = runs.iter().find(|r| r.id == run).expect("the run");
    assert_eq!(listed.approvals.len(), 2);

    let mut who: Vec<ActorId> = listed.approvals.iter().map(|a| a.approved_by).collect();
    who.sort_by_key(ToString::to_string);
    let mut expected = vec![f.approver, f.someone_else];
    expected.sort_by_key(ToString::to_string);
    assert_eq!(who, expected);
}

#[tokio::test]
async fn a_run_that_is_not_waiting_cannot_be_approved() {
    // Approving a run that has already started is approving something that is happening,
    // which is not what an approval is for.
    let f = fixture("not-waiting").await;
    let run = a_run(&f).await;

    f.store
        .set_run_state(&f.scope, run, RunState::Running, None)
        .await
        .unwrap();

    let err = f
        .store
        .approve_run(&f.scope, run, f.approver)
        .await
        .expect_err("a running run is past approval");
    assert!(err.to_string().contains("not waiting"), "{err}");
}

#[tokio::test]
async fn the_approval_records_what_was_being_looked_at() {
    // A run whose targets changed after approval is not the run that was approved, and
    // the fingerprint is what `uops_runbook::decide` compares.
    let f = fixture("fingerprint").await;
    let run = a_run(&f).await;
    f.store.approve_run(&f.scope, run, f.approver).await.unwrap();

    let runs = f.store.runs(&f.scope, 10).await.unwrap();
    let listed = runs.iter().find(|r| r.id == run).unwrap();
    assert_eq!(listed.approvals[0].targets_fingerprint, "sha:abc");
    assert_eq!(listed.targets_fingerprint, "sha:abc");
}

// ---------------------------------------------------------------------------
// Runs and transcripts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_run_records_why_it_was_started_and_who_by() {
    let f = fixture("why").await;
    let run = a_run(&f).await;

    let runs = f.store.runs(&f.scope, 10).await.unwrap();
    let listed = runs.iter().find(|r| r.id == run).unwrap();

    assert_eq!(listed.reason, "the session is stuck");
    assert_eq!(listed.started_by, f.starter);
    assert_eq!(listed.runbook_name, "restart-bgp");
    assert_eq!(listed.version, 1);
    assert!(!listed.break_glass);
    assert!(!listed.dry_run);
}

#[tokio::test]
async fn a_transcript_is_redacted_on_the_way_in() {
    // Redacted in the store rather than by the caller, so there is no path that writes a
    // raw transcript — a caller that forgot would otherwise be the whole of the
    // protection.
    let f = fixture("redact").await;
    let run = a_run(&f).await;

    f.store
        .record_step(
            &f.scope,
            run,
            f.device,
            0,
            "show config",
            "show running-config",
            false,
            "ok",
            Some("username netops password 7 0822455D0A16"),
            Some(0),
        )
        .await
        .expect("record");

    let stored: String = sqlx::query_scalar("SELECT output FROM runbook_run_step WHERE run_id = $1")
        .bind(run)
        .fetch_one(f.store.pool())
        .await
        .unwrap();

    assert!(!stored.contains("0822455D0A16"), "{stored}");
    assert!(stored.contains("<redacted>"), "{stored}");
    // And the line still says whose password it was.
    assert!(stored.contains("username netops"), "{stored}");
}

#[tokio::test]
async fn a_state_change_stamps_the_clock_it_should() {
    let f = fixture("clock").await;
    let run = a_run(&f).await;

    f.store
        .set_run_state(&f.scope, run, RunState::Running, None)
        .await
        .unwrap();
    let running = f.store.runs(&f.scope, 10).await.unwrap();
    let r = running.iter().find(|r| r.id == run).unwrap();
    assert!(r.started_at.is_some(), "running stamps started_at");
    assert!(r.finished_at.is_none());

    f.store
        .set_run_state(&f.scope, run, RunState::Failed, Some("step 1 failed"))
        .await
        .unwrap();
    let done = f.store.runs(&f.scope, 10).await.unwrap();
    let r = done.iter().find(|r| r.id == run).unwrap();
    assert!(r.finished_at.is_some(), "a terminal state stamps finished_at");
    assert_eq!(r.failure.as_deref(), Some("step 1 failed"));
    assert!(
        r.state.touched_a_device(),
        "failed means a device was touched, which refused does not"
    );
}

#[tokio::test]
async fn retiring_a_runbook_keeps_its_runs() {
    // A run record names the runbook it executed, and that name has to keep resolving.
    let f = fixture("retire").await;
    let run = a_run(&f).await;
    let saved = f.store.runbooks(&f.scope).await.unwrap();
    let id = saved[0].id;

    assert!(f.store.retire_runbook(&f.scope, id).await.unwrap());

    let listed = f.store.runbooks(&f.scope).await.unwrap();
    assert!(listed[0].retired);

    let runs = f.store.runs(&f.scope, 10).await.unwrap();
    assert!(
        runs.iter().any(|r| r.id == run),
        "the run history outlives the runbook being retired"
    );
}
