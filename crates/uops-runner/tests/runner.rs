//! The runner against real `PostgreSQL`, with a scripted transport — M10 §3.
//!
//! # Why the transport is scripted and the database is not
//!
//! The properties these settle are all *orchestration* properties: that a dry run really
//! executes the read-only steps and really does not execute the others, that a failure
//! stops the run and offers the declared rollback rather than performing it, that two
//! runners take one queued run exactly once, that a credential never reaches the record.
//!
//! None of those is about SSH. Every one of them is about what the runner writes, in a
//! transaction, against a schema whose constraints are half the argument. So: the store is
//! real, and the device is a recording of one.
//!
//! What SSH itself does is settled by `tests/live.rs`, against a real server.

use std::sync::Mutex;

use uops_core::{ActorId, CredentialRef, OrgId, ResourceId, Secret, TenantId, TenantScope};
use uops_query::ast::ResourceSelector;
use uops_runbook::{Action, Approvals, Expect, HttpMethod, Rollback, Runbook, Step};
use uops_runner::{Endpoint, Outcome, Transport};
use uops_store_pg::{Config, PgStore, RunState};

// ---- the recording device -------------------------------------------------------

/// A transport that answers from a script and remembers what it was asked.
///
/// The record is what most of these tests assert on: "the destructive step was never
/// sent" is a claim about this list being short, and no amount of reading the run's own
/// rows could prove it — a step recorded `skipped` proves what the runner *wrote*, not
/// what it *sent*.
#[derive(Default)]
struct Scripted {
    sent: Mutex<Vec<String>>,
    /// Commands that fail, by the text they contain.
    fails: Vec<&'static str>,
    /// What every successful command prints.
    says: String,
    /// Credentials the transport was handed, so a test can prove they never leave here.
    credentials: Mutex<Vec<CredentialRef>>,
}

impl Scripted {
    fn new() -> Self {
        Self {
            says: "Neighbor 10.0.0.1 Idle".to_owned(),
            ..Self::default()
        }
    }

    fn failing_on(mut self, needle: &'static str) -> Self {
        self.fails.push(needle);
        self
    }

    fn sent(&self) -> Vec<String> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Transport for Scripted {
    async fn ssh(&self, _to: &Endpoint, command: &str, credential: CredentialRef) -> Outcome {
        self.sent.lock().unwrap().push(command.to_owned());
        self.credentials.lock().unwrap().push(credential);
        if self.fails.iter().any(|needle| command.contains(needle)) {
            return Outcome::exited(1, "% Invalid input detected".to_owned());
        }
        Outcome::exited(0, self.says.clone())
    }

    async fn http(
        &self,
        _to: &Endpoint,
        method: HttpMethod,
        url: &str,
        _body: Option<&str>,
        _credential: Option<CredentialRef>,
    ) -> Outcome {
        self.sent
            .lock()
            .unwrap()
            .push(format!("{} {url}", method.as_str()));
        if self.fails.iter().any(|needle| url.contains(needle)) {
            return Outcome::answered(500, String::new());
        }
        Outcome::answered(200, self.says.clone())
    }
}

// ---- fixture --------------------------------------------------------------------

/// A key nobody else uses, for the advisory lock below. Arbitrary and fixed.
const RUN_QUEUE_LOCK: i64 = 0x7075_6f70_735f_726e;

/// Exclusive use of the run queue, across every test binary at once.
///
/// **This is a property of the thing under test, not a workaround.** `claim_next_run` is
/// deliberately cross-tenant — a runner serves a deployment, not a tenant — so two test
/// binaries against one database are two runners contending for one queue, and each takes
/// the other's runs. `uops-api`'s runbook tests create `ready` runs; this binary's runner
/// claims them, executes them against a scripted device, and then asserts about a run it
/// never queued.
///
/// A `tokio::sync::Mutex` cannot fix that: it is one process. A `PostgreSQL` session
/// advisory lock can, because the contention is in the database and so is the lock.
///
/// Held by a connection of its own rather than one from the pool, so that dropping the
/// guard closes the session and `PostgreSQL` releases the lock — including when a test
/// panics, which is the path a `Drop` written in async Rust cannot reach.
struct QueueLock {
    // Kept alive for the life of the test and never used again. The connection *is* the
    // lock.
    _held: sqlx::PgConnection,
}

impl QueueLock {
    async fn take() -> Self {
        use sqlx::Connection as _;

        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into());
        let mut held = sqlx::PgConnection::connect(&url).await.expect("lock connection");

        // `pg_try_advisory_lock` in a loop rather than `pg_advisory_lock`, so a leaked
        // lock fails with a sentence instead of hanging a test run for ever. Thirty
        // seconds is longer than any test here and far shorter than a CI timeout.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let (got,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(RUN_QUEUE_LOCK)
                .fetch_one(&mut held)
                .await
                .expect("try lock");
            if got {
                return Self { _held: held };
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the run queue is still held after 120s. Another test binary is stuck, or a \
                 connection holding the advisory lock leaked."
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

/// A store for one test.
///
/// **Not** a `static` shared across the binary, and that is worth writing down because it
/// was tried: each `#[tokio::test]` builds its own runtime, a `sqlx` pool belongs to the
/// runtime it was created on, and the second test to use a shared pool blocks on `acquire`
/// for ever with no error. What it looks like from outside is four tests that "have been
/// running for over 60 seconds".
///
/// Four connections rather than the default sixteen. `PostgreSQL`'s own `max_connections`
/// is 100 and every test binary cargo runs in parallel shares it; eleven pools of sixteen
/// is how this suite made the *store's* suite hang.
async fn store() -> PgStore {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into());
    PgStore::connect(&Config {
        url,
        max_connections: 4,
        ..Config::default()
    })
    .await
    .expect("connect")
}

struct Fixture {
    /// Held for the life of the test — see [`QueueLock`].
    _queue: QueueLock,
    store: PgStore,
    scope: TenantScope,
    starter: ActorId,
    approver: ActorId,
    device: ResourceId,
    device_name: String,
}

async fn fixture(slug: &str) -> Fixture {
    let gate = QueueLock::take().await;
    let store = store().await;

    // Start from an empty queue.
    //
    // `claim_next_run` takes the **oldest** `ready` run in the deployment, which is right
    // — a run that has waited longest should go first — and means a development database
    // that has accumulated abandoned `ready` rows from a previous test run hands this one
    // somebody else's work. The symptom is a test that claims a run, sends nothing, and
    // asserts about a runbook it never wrote.
    //
    // Safe under the lock: nothing else that cares about the queue is running. Cancelled
    // rather than deleted, because a run row is referenced by its approvals and its
    // transcript, and because "cancelled" is what these actually are.
    sqlx::query("UPDATE runbook_run SET state = 'cancelled' WHERE state = 'ready'")
        .execute(store.pool())
        .await
        .expect("drain the queue");
    let org = OrgId::new();
    let tenant = TenantId::new();
    let tag = tenant.into_uuid().simple().to_string();

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("rn-org-{slug}-{tag}"))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("rn-{slug}"))
        .bind(format!("rn-{slug}-{tag}"))
        .execute(store.pool())
        .await
        .expect("tenant");

    let hash =
        uops_secrets::password::hash(&Secret::new("correct horse".to_owned())).expect("hash");
    let mut users = Vec::new();
    for who in ["starter", "approver"] {
        users.push(
            store
                .create_user(org, &format!("{who}-{tag}@test.invalid"), who, &hash)
                .await
                .expect("user"),
        );
    }

    let device = ResourceId::new();
    let device_name = "core-sw-01".to_owned();
    sqlx::query(
        "INSERT INTO resource (id, tenant_id, kind, name, status)
         VALUES ($1, $2, 'device', $3, 'unknown')",
    )
    .bind(device.into_uuid())
    .bind(tenant.into_uuid())
    .bind(&device_name)
    .execute(store.pool())
    .await
    .expect("resource");

    // The management address the runner resolves at execution time. Without it every step
    // fails before it is sent, which is itself one of the tests below.
    sqlx::query(
        "INSERT INTO resource_identifier
             (id, tenant_id, resource_id, kind, value, confidence, source)
         VALUES ($1, $2, $3, 'mgmt_ip', $4, 0.80, 'manual')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(tenant.into_uuid())
    .bind(device.into_uuid())
    .bind("10.0.0.1")
    .execute(store.pool())
    .await
    .expect("mgmt_ip");

    Fixture {
        _queue: gate,
        store,
        scope: TenantScope::system(tenant),
        starter: users[0],
        approver: users[1],
        device,
        device_name,
    }
}

/// A runbook with one read-only precondition and one destructive step.
///
/// The shape M10 §2.1's example uses, because it is the shape that makes a dry run mean
/// something: one step that a dry run runs and one it must not.
fn two_step(name: &str, approvals: Approvals) -> Runbook {
    Runbook {
        name: name.to_owned(),
        description: "restart a stuck BGP session".to_owned(),
        targets: ResourceSelector::All,
        steps: vec![
            Step {
                name: "check the session is actually down".to_owned(),
                action: Action::SshCommand {
                    command: "show bgp summary".to_owned(),
                    credential: CredentialRef::new(),
                },
                destructive: false,
                rollback: None,
                expect: Some(Expect::Contains {
                    text: "Idle".to_owned(),
                }),
                continue_on_error: false,
            },
            Step {
                name: "clear it".to_owned(),
                action: Action::SshCommand {
                    command: "clear bgp neighbor {{ resource.address }}".to_owned(),
                    credential: CredentialRef::new(),
                },
                destructive: true,
                rollback: Some(Rollback::None {
                    because: "a cleared session cannot be un-cleared".to_owned(),
                }),
                expect: None,
                continue_on_error: false,
            },
        ],
        max_targets: 10,
        concurrency: 4,
        approvals,
        maintenance_only: false,
    }
}

/// Save a runbook and queue a run of it, ready for a runner to take.
async fn queue(
    fixture: &Fixture,
    runbook: &Runbook,
    dry_run: bool,
    state: RunState,
) -> (uuid::Uuid, uuid::Uuid) {
    let saved = fixture
        .store
        .save_runbook(&fixture.scope, runbook, Some(fixture.starter))
        .await
        .expect("save");
    let run = fixture
        .store
        .create_run(
            &fixture.scope,
            saved.id,
            saved.version_id,
            state,
            dry_run,
            &[(fixture.device, fixture.device_name.clone())],
            "fingerprint-1",
            "the session is stuck",
            fixture.starter,
            false,
        )
        .await
        .expect("create run");
    (saved.id, run)
}

async fn steps_of(fixture: &Fixture, run: uuid::Uuid) -> Vec<(i32, String, String, Option<String>)> {
    sqlx::query_as::<_, (i32, String, String, Option<String>)>(
        "SELECT step_index, name, state::text, output
           FROM runbook_run_step
          WHERE run_id = $1 AND tenant_id = $2
          ORDER BY step_index",
    )
    .bind(run)
    .bind(fixture.scope.tenant_id().into_uuid())
    .fetch_all(fixture.store.pool())
    .await
    .expect("steps")
}

async fn run_row(fixture: &Fixture, run: uuid::Uuid) -> (String, Option<String>) {
    sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT state::text, failure FROM runbook_run WHERE id = $1 AND tenant_id = $2",
    )
    .bind(run)
    .bind(fixture.scope.tenant_id().into_uuid())
    .fetch_one(fixture.store.pool())
    .await
    .expect("run")
}

// ---- the tests ------------------------------------------------------------------

#[tokio::test]
async fn a_dry_run_executes_the_read_only_step_and_does_not_send_the_destructive_one() {
    // M10 §2.2, and the sentence that makes a dry run worth having: it is not a
    // simulation. The `show` really goes to the device, so the precondition is genuinely
    // checked; the `clear` is not sent at all.
    let fixture = fixture("dry").await;
    let (_, run) = queue(&fixture, &two_step("dry", Approvals::None), true, RunState::Ready).await;

    let transport = Scripted::new();
    let turn = uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take")
        .expect("a run was queued");
    assert_eq!(turn.executed, 1);

    // The claim about what was *sent*, which no row in the database could make.
    assert_eq!(transport.sent(), vec!["show bgp summary".to_owned()]);

    let steps = steps_of(&fixture, run).await;
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].2, "ok");
    // Recorded `skipped`, not left `pending`: a step nobody will run is not a step still
    // to come, and a screen showing `pending` for ever is a screen that lies.
    assert_eq!(steps[1].2, "skipped");
    assert!(
        steps[1].3.as_deref().unwrap_or_default().contains("dry run"),
        "{:?}",
        steps[1].3
    );

    assert_eq!(run_row(&fixture, run).await.0, "succeeded");
}

#[tokio::test]
async fn a_real_run_sends_both_steps_with_the_template_substituted() {
    let fixture = fixture("real").await;
    let (_, run) = queue(
        &fixture,
        &two_step("real", Approvals::None),
        false,
        RunState::Ready,
    )
    .await;

    let transport = Scripted::new();
    uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take")
        .expect("queued");

    assert_eq!(
        transport.sent(),
        vec![
            "show bgp summary".to_owned(),
            // The address came from `resource_identifier`, resolved at execution time.
            "clear bgp neighbor 10.0.0.1".to_owned(),
        ]
    );
    assert_eq!(run_row(&fixture, run).await.0, "succeeded");
}

#[tokio::test]
async fn a_failed_step_stops_the_run_and_the_rollback_is_offered_rather_than_performed() {
    // M10 §2.6. The declared rollback appears in what the operator reads, and nothing was
    // sent to undo anything — running more commands into a state the product does not know
    // is how a small outage becomes a large one.
    let fixture = fixture("stop").await;
    let (_, run) = queue(
        &fixture,
        &two_step("stop", Approvals::None),
        false,
        RunState::Ready,
    )
    .await;

    let transport = Scripted::new().failing_on("clear bgp");
    uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take")
        .expect("queued");

    let (state, failure) = run_row(&fixture, run).await;
    assert_eq!(state, "failed");
    let failure = failure.expect("a failed run says why");
    assert!(failure.contains("clear it"), "{failure}");
    assert!(
        failure.contains("a cleared session cannot be un-cleared"),
        "the author's declared rollback is shown: {failure}"
    );
    assert!(
        failure.contains("has not been run"),
        "and it is offered rather than taken: {failure}"
    );

    // Two steps sent, and nothing after. No third command went out to undo anything.
    assert_eq!(transport.sent().len(), 2);
}

#[tokio::test]
async fn an_expectation_that_the_device_does_not_meet_fails_the_step() {
    // A device CLI that prints `% BGP not enabled` and exits zero is the ordinary shape of
    // a failed precondition. An exit code alone would call this run a success and then
    // send the destructive step.
    let fixture = fixture("expect").await;
    let (_, run) = queue(
        &fixture,
        &two_step("expect", Approvals::None),
        false,
        RunState::Ready,
    )
    .await;

    let mut transport = Scripted::new();
    transport.says = "% BGP not enabled".to_owned();
    uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take")
        .expect("queued");

    assert_eq!(run_row(&fixture, run).await.0, "failed");
    // The whole point: the destructive step was never sent.
    assert_eq!(transport.sent(), vec!["show bgp summary".to_owned()]);

    let steps = steps_of(&fixture, run).await;
    assert_eq!(steps[0].2, "failed");
    assert_eq!(steps[1].2, "skipped");
    assert!(
        steps[1].3.as_deref().unwrap_or_default().contains("earlier step failed"),
        "{:?}",
        steps[1].3
    );
}

#[tokio::test]
async fn an_approval_older_than_its_window_sends_the_run_back_to_waiting_rather_than_failing() {
    // M10 §3, and the distinction is the point: what went wrong is that ten minutes
    // passed. The operator's next step is to ask somebody again, not to read a transcript.
    let fixture = fixture("stale").await;
    let (_, run) = queue(
        &fixture,
        &two_step("stale", Approvals::One),
        false,
        RunState::AwaitingApproval,
    )
    .await;

    fixture
        .store
        .approve_run(&fixture.scope, run, fixture.approver)
        .await
        .expect("approve");
    fixture
        .store
        .set_run_state(&fixture.scope, run, RunState::Ready, None)
        .await
        .expect("ready");

    // An hour later.
    let transport = Scripted::new();
    let turn = uops_runner::take_one(
        &fixture.store,
        &transport,
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .await
    .expect("take")
    .expect("queued");

    assert_eq!(turn.returned, 1);
    assert_eq!(turn.executed, 0);
    let (state, failure) = run_row(&fixture, run).await;
    assert_eq!(state, "awaiting_approval");
    assert!(failure.is_none(), "a stale approval is not a failure: {failure:?}");
    assert!(transport.sent().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn a_fresh_approval_lets_the_same_run_through() {
    // The other half of the one above. Without it, "returned to waiting" could be the
    // runner refusing every approved run and the test above would still pass.
    let fixture = fixture("fresh").await;
    let (_, run) = queue(
        &fixture,
        &two_step("fresh", Approvals::One),
        false,
        RunState::AwaitingApproval,
    )
    .await;

    fixture
        .store
        .approve_run(&fixture.scope, run, fixture.approver)
        .await
        .expect("approve");
    fixture
        .store
        .set_run_state(&fixture.scope, run, RunState::Ready, None)
        .await
        .expect("ready");

    let transport = Scripted::new();
    let turn = uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take")
        .expect("queued");
    assert_eq!(turn.executed, 1);
    assert_eq!(run_row(&fixture, run).await.0, "succeeded");
}

#[tokio::test]
async fn two_runners_against_one_database_execute_a_queued_run_once() {
    // M10 §3's last-but-one criterion. The lease is *not* what makes this true — one
    // `UPDATE` that the database serialises is. This test runs with no lease at all, which
    // is what makes it a test of the claim rather than of the lease.
    let fixture = fixture("once").await;
    let (_, run) = queue(
        &fixture,
        &two_step("once", Approvals::None),
        false,
        RunState::Ready,
    )
    .await;

    let one = Scripted::new();
    let two = Scripted::new();
    let (first, second) = tokio::join!(
        uops_runner::take_one(&fixture.store, &one, chrono::Utc::now()),
        uops_runner::take_one(&fixture.store, &two, chrono::Utc::now()),
    );

    let executed = first.expect("first").map_or(0, |t| t.executed)
        + second.expect("second").map_or(0, |t| t.executed);
    assert_eq!(executed, 1, "the run was taken twice");

    // And the device was asked exactly once, which is the claim that matters: a run
    // recorded once having been sent twice would pass an assertion on the row alone.
    assert_eq!(
        one.sent().len() + two.sent().len(),
        2,
        "one runbook of two steps, sent once"
    );
    assert_eq!(run_row(&fixture, run).await.0, "succeeded");
}

#[tokio::test]
async fn a_credential_never_reaches_the_run_record() {
    // M10 §3, and §2.4 from the other side. The reference is handed to the transport and
    // stops there; nothing it names appears in what was rendered or in what was stored.
    let fixture = fixture("cred").await;
    let runbook = two_step("cred", Approvals::None);
    let referenced: Vec<String> = runbook
        .steps
        .iter()
        .filter_map(|s| match &s.action {
            Action::SshCommand { credential, .. } => Some(credential.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(referenced.len(), 2, "the fixture must name two credentials");

    let (_, run) = queue(&fixture, &runbook, false, RunState::Ready).await;
    let transport = Scripted::new();
    uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take")
        .expect("queued");

    // The transport was given them, which is the only place they are allowed to be.
    assert_eq!(transport.credentials.lock().unwrap().len(), 2);

    let rows = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT rendered, output FROM runbook_run_step WHERE run_id = $1",
    )
    .bind(run)
    .fetch_all(fixture.store.pool())
    .await
    .expect("steps");

    for (rendered, output) in rows {
        for reference in &referenced {
            assert!(!rendered.contains(reference.as_str()), "{rendered}");
            assert!(
                !output.as_deref().unwrap_or_default().contains(reference.as_str()),
                "{output:?}"
            );
        }
    }
    let (_, failure) = run_row(&fixture, run).await;
    for reference in &referenced {
        assert!(!failure.as_deref().unwrap_or_default().contains(reference.as_str()));
    }
}

#[tokio::test]
async fn a_target_with_no_management_address_fails_by_name_without_anything_being_sent() {
    let fixture = fixture("noaddr").await;
    sqlx::query("DELETE FROM resource_identifier WHERE resource_id = $1")
        .bind(fixture.device.into_uuid())
        .execute(fixture.store.pool())
        .await
        .expect("delete address");

    let (_, run) = queue(
        &fixture,
        &two_step("noaddr", Approvals::None),
        false,
        RunState::Ready,
    )
    .await;

    let transport = Scripted::new();
    uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take")
        .expect("queued");

    assert!(transport.sent().is_empty());
    let (state, failure) = run_row(&fixture, run).await;
    assert_eq!(state, "failed");
    assert!(
        failure.unwrap_or_default().contains("core-sw-01"),
        "the failure names the device rather than a uuid"
    );
}

#[tokio::test]
async fn an_abandoned_run_is_failed_at_start_up_and_not_restarted() {
    // A run left `running` by a process that stopped is the one state nothing else
    // corrects. It may already have sent a destructive step, and this product does not
    // know which — so it is closed out, not requeued.
    let fixture = fixture("abandon").await;
    let (_, run) = queue(
        &fixture,
        &two_step("abandon", Approvals::None),
        false,
        RunState::Running,
    )
    .await;
    sqlx::query("UPDATE runbook_run SET started_at = now() - interval '2 hours' WHERE id = $1")
        .bind(run)
        .execute(fixture.store.pool())
        .await
        .expect("age it");

    let closed = fixture
        .store
        .fail_abandoned_runs(chrono::Duration::hours(1))
        .await
        .expect("close out");
    assert!(closed >= 1);

    let (state, failure) = run_row(&fixture, run).await;
    assert_eq!(state, "failed");
    let failure = failure.expect("says why");
    assert!(
        failure.contains("not restarted"),
        "the message has to say it will not be re-sent: {failure}"
    );

    // And it is not in the queue: claiming looks at `ready` alone.
    let transport = Scripted::new();
    let taken = uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take");
    assert!(
        taken.is_none() || transport.sent().is_empty(),
        "a closed-out run must not be picked up again"
    );
}

#[tokio::test]
async fn a_runner_takes_nothing_from_a_run_that_is_only_awaiting_approval() {
    // The queue is `ready` and nothing else. A runner that read `awaiting_approval` would
    // execute every destructive run the moment it was created.
    let fixture = fixture("waiting").await;
    queue(
        &fixture,
        &two_step("waiting", Approvals::Two),
        false,
        RunState::AwaitingApproval,
    )
    .await;

    let transport = Scripted::new();
    let taken = uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take");
    assert!(taken.is_none(), "an unapproved run was claimed");
    assert!(transport.sent().is_empty());
}
