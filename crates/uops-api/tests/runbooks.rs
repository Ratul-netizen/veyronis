//! Runbooks and runs, through HTTP — M10 §3.
//!
//! These settle the acceptance criteria that only exist at the API: the blast-radius
//! refusal and the number it reports, the break-glass run being audited as its own kind of
//! event, the dry-run default, and the fact that a run is *recorded* rather than executed
//! by a request.
//!
//! The ones about execution are in `uops-runner`; the ones about the schema are in
//! `uops-store-pg`. Nothing here sends a command anywhere, and that is the property this
//! file is partly about — see `a_started_run_is_recorded_rather_than_executed`.
//!
//! ```bash
//! DATABASE_URL=postgres://uops:uops@localhost:5432/uops \
//!   CLICKHOUSE_USER=uops CLICKHOUSE_PASSWORD=uops \
//!   cargo test -p uops-api --test runbooks
//! ```

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt as _;
use uops_api::{AppState, CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, TENANT_HEADER};
use uops_core::{ActorId, OrgId, ResourceId, Role, Secret, TenantId};
use uops_secrets::password;
use uops_store_pg::{Config, PgStore};

/// A key nobody else uses, for the advisory lock below. Arbitrary and fixed.
const RUN_QUEUE_LOCK: i64 = 0x7075_6f70_735f_726e;

/// Exclusive use of the run queue, across every test binary at once.
///
/// Taken by the two tests below that need a `ready` run to *stay* ready, and by nothing
/// else. Holding it for every test in this file would serialise seventeen of them behind
/// eleven in `uops-runner` — most of which is Argon2 in the fixture, which has nothing to
/// do with the queue.
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

fn telemetry() -> uops_store_ch::ChStore {
    uops_store_ch::ChStore::new(uops_store_ch::ChClient::new(uops_store_ch::ChConfig {
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "uops".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "uops".into()),
        ..uops_store_ch::ChConfig::from_env()
    }))
}

fn app(store: &PgStore) -> Router {
    uops_api::router(AppState::new(store.clone(), telemetry()))
}

struct Fixture {
    store: PgStore,
    org: OrgId,
    tenant: TenantId,
    session: String,
    csrf: String,
    /// The signed-in operator.
    me: ActorId,
    devices: Vec<ResourceId>,
}

async fn fixture(slug: &str, devices: usize) -> Fixture {
    let store = store().await;
    let org = OrgId::new();
    let tenant = TenantId::new();
    let tag = tenant.into_uuid().simple().to_string();

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("rb-org-{slug}-{tag}"))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("rb-{slug}"))
        .bind(format!("rb-{slug}-{tag}"))
        .execute(store.pool())
        .await
        .expect("tenant");

    let email = format!("{slug}-{tag}@example.com");
    let hash = password::hash(&Secret::new("pw".to_owned())).unwrap();
    let me = store
        .create_user(org, &email, "Runbook Test", &hash)
        .await
        .expect("user");
    store
        .grant_role(me, tenant, Role::Operator, None)
        .await
        .expect("role");

    let mut ids = Vec::with_capacity(devices);
    for n in 0..devices {
        let id = ResourceId::new();
        sqlx::query(
            "INSERT INTO resource (id, tenant_id, kind, name, status)
             VALUES ($1, $2, 'device', $3, 'up')",
        )
        .bind(id.into_uuid())
        .bind(tenant.into_uuid())
        .bind(format!("sw-{n:02}"))
        .execute(store.pool())
        .await
        .expect("resource");
        ids.push(id);
    }

    let (session, csrf) = sign_in(&store, &email).await;
    Fixture {
        store,
        org,
        tenant,
        session,
        csrf,
        me,
        devices: ids,
    }
}

async fn sign_in(store: &PgStore, email: &str) -> (String, String) {
    let response = app(store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": email, "password": "pw" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let mut session = String::new();
    let mut csrf = String::new();
    for value in response.headers().get_all(header::SET_COOKIE) {
        let text = value.to_str().unwrap();
        let (pair, _) = text.split_once("; ").unwrap();
        let (name, v) = pair.split_once('=').unwrap();
        if name == SESSION_COOKIE {
            v.clone_into(&mut session);
        } else if name == CSRF_COOKIE {
            v.clone_into(&mut csrf);
        }
    }
    (session, csrf)
}

impl Fixture {
    fn get(&self, path: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header(header::COOKIE, format!("{SESSION_COOKIE}={}", self.session))
            .header(TENANT_HEADER, self.tenant.to_string())
            .body(Body::empty())
            .unwrap()
    }

    fn send(&self, method: &str, path: &str, body: &serde_json::Value) -> Request<Body> {
        self.send_as(&self.session, &self.csrf, method, path, body)
    }

    fn send_as(
        &self,
        session: &str,
        csrf: &str,
        method: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(
                header::COOKIE,
                format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={csrf}"),
            )
            .header(TENANT_HEADER, self.tenant.to_string())
            .header(CSRF_HEADER, csrf)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app(&self.store).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn audit_log(&self) -> Vec<(String, String)> {
        self.store
            .audit_entries(self.tenant, 50)
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.action, e.target))
            .collect()
    }

    /// A second operator, so a run can be approved by somebody other than its starter.
    async fn colleague(&self, name: &str) -> (ActorId, String, String) {
        let email = format!("{name}-{}@example.com", self.tenant.into_uuid().simple());
        let hash = password::hash(&Secret::new("pw".to_owned())).unwrap();
        let user = self
            .store
            .create_user(self.org, &email, name, &hash)
            .await
            .expect("user");
        self.store
            .grant_role(user, self.tenant, Role::Operator, None)
            .await
            .expect("role");
        let (session, csrf) = sign_in(&self.store, &email).await;
        (user, session, csrf)
    }
}

/// A runbook with one read-only step and one destructive one.
fn two_step(name: &str, approvals: &str, max_targets: u32) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "description": "restart a stuck BGP session",
        "targets": { "type": "all" },
        "steps": [
            {
                "name": "check the session is actually down",
                "action": {
                    "kind": "ssh_command",
                    "command": "show bgp summary",
                    "credential": uuid::Uuid::now_v7(),
                },
                "destructive": false,
                "expect": { "kind": "contains", "text": "Idle" },
            },
            {
                "name": "clear it",
                "action": {
                    "kind": "ssh_command",
                    "command": "clear bgp neighbor {{ resource.name }}",
                    "credential": uuid::Uuid::now_v7(),
                },
                "destructive": true,
                "rollback": {
                    "kind": "none",
                    "because": "a cleared session cannot be un-cleared",
                },
            },
        ],
        "max_targets": max_targets,
        "concurrency": 2,
        "approvals": approvals,
        "maintenance_only": false,
    })
}

/// A runbook that changes nothing.
///
/// Needed more often than it looks: `validate` refuses a destructive runbook that requires
/// no approval — which is the right rule and means "a run that is `ready` the moment it is
/// started" can only be built out of read-only steps. Several tests below are about what
/// happens *after* a run is ready, and this is how they get one.
fn read_only(name: &str, max_targets: u32) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "description": "look at a session",
        "targets": { "type": "all" },
        "steps": [{
            "name": "check the session",
            "action": {
                "kind": "ssh_command",
                "command": "show bgp summary",
                "credential": uuid::Uuid::now_v7(),
            },
            "destructive": false,
            "expect": { "kind": "contains", "text": "Idle" },
        }],
        "max_targets": max_targets,
        "concurrency": 2,
        "approvals": "none",
        "maintenance_only": false,
    })
}

// ---- saving --------------------------------------------------------------------

#[tokio::test]
async fn saving_twice_writes_a_second_version_and_leaves_the_first_readable() {
    let f = fixture("versions", 1).await;

    let (status, first) = f
        .call(f.send("POST", "/api/v1/runbooks", &two_step("restart-bgp", "one", 10)))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    assert_eq!(first["version"], 1);

    let mut edited = two_step("restart-bgp", "one", 10);
    edited["description"] = serde_json::json!("now with a reason somebody wrote down");
    let (status, second) = f.call(f.send("POST", "/api/v1/runbooks", &edited)).await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    assert_eq!(second["version"], 2);
    assert_eq!(second["id"], first["id"], "the same runbook, a new version");
    assert_ne!(second["version_id"], first["version_id"]);

    // Version 1 is still there, unchanged — a run that executed it still resolves.
    let (_, v1) = f
        .store
        .runbook_version(
            &uops_core::TenantScope::system(f.tenant),
            first["version_id"].as_str().unwrap().parse().unwrap(),
        )
        .await
        .expect("read")
        .expect("version 1 is still readable");
    assert_eq!(v1.description, "restart a stuck BGP session");
}

#[tokio::test]
async fn a_runbook_that_does_not_validate_is_refused_and_every_problem_is_named() {
    // Not the first problem: an author fixing a runbook one refusal at a time saves six
    // times, which is why `validate` returns a list and why this asserts on the list.
    let f = fixture("invalid", 1).await;

    let bad = serde_json::json!({
        "name": "innocent",
        "description": "",
        "targets": { "type": "all" },
        "steps": [
            {
                // Marked read-only, and it reloads a device.
                "name": "just looking",
                "action": {
                    "kind": "ssh_command",
                    "command": "reload in 5",
                    "credential": uuid::Uuid::now_v7(),
                },
                "destructive": false,
            },
            {
                // Destructive with no rollback declared at all.
                "name": "erase it",
                "action": {
                    "kind": "ssh_command",
                    "command": "write erase",
                    "credential": uuid::Uuid::now_v7(),
                },
                "destructive": true,
            },
        ],
        "max_targets": 10,
        "concurrency": 2,
        "approvals": "none",
        "maintenance_only": false,
    });

    let (status, body) = f.call(f.send("POST", "/api/v1/runbooks", &bad)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let said = body.to_string();
    // The word it matched on, which is what tells the author what to change.
    assert!(said.contains("reload"), "{said}");
    // And the second problem, in the same response.
    assert!(said.contains("erase it") || said.contains("rollback"), "{said}");
    assert!(
        said.matches('•').count() >= 2,
        "every problem, not the first: {said}"
    );
}

// ---- planning ------------------------------------------------------------------

#[tokio::test]
async fn a_plan_names_every_resource_and_renders_every_command() {
    let f = fixture("plan", 3).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &two_step("plan-me", "one", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (status, plan) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/plan"),
            &serde_json::json!({}),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{plan}");

    assert_eq!(plan["targets"].as_array().unwrap().len(), 3);
    // By name. A plan listing UUIDs is a plan nobody reads, and the whole point of the
    // count is that somebody looks at it.
    let names: Vec<&str> = plan["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"sw-00"), "{names:?}");

    // The literal command, substituted. A reviewer reads what would be sent, not a
    // template — a template is what the mistake hides in.
    let rendered = plan["steps"][0]["steps"][1]["rendered"][0].as_str().unwrap();
    assert!(rendered.starts_with("clear bgp neighbor sw-"), "{rendered}");

    // Says what would run, never what would succeed.
    let summary = plan["summary"].as_str().unwrap();
    assert!(summary.starts_with("would run"), "{summary}");
    assert!(!summary.contains("succeed"), "{summary}");
    assert_eq!(plan["destructive_steps"], 3, "one per resource");
}

#[tokio::test]
async fn a_selector_over_the_maximum_does_not_run_and_says_by_how_much() {
    // M10 §3, and the number is the response rather than a log line: "a selector that was
    // meant to match one switch and matches four hundred is the single most common way
    // automation causes an outage".
    let f = fixture("toomany", 5).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &two_step("narrow", "one", 2)))
        .await;
    let id = book["id"].as_str().unwrap();

    for path in [
        format!("/api/v1/runbooks/{id}/plan"),
        format!("/api/v1/runbooks/{id}/runs"),
    ] {
        let (status, body) = f
            .call(f.send(
                "POST",
                &path,
                &serde_json::json!({ "reason": "trying it on" }),
            ))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        let said = body.to_string();
        assert!(said.contains('5') && said.contains('2'), "{said}");
        assert!(said.contains("3 too many"), "by how much: {said}");
    }

    // And nothing was created by the attempt.
    let (_, runs) = f.call(f.get("/api/v1/runs")).await;
    assert_eq!(runs.as_array().unwrap().len(), 0);
}

// ---- starting ------------------------------------------------------------------

#[tokio::test]
async fn a_run_is_a_dry_run_unless_the_client_says_otherwise() {
    // M10 §2.2: the default is the safe one, not a flag that defaults to false and can be
    // omitted. The body below has no `dry_run` at all.
    let f = fixture("default", 1).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &two_step("safe", "one", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (status, run) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "checking the default" }),
        ))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run}");
    assert_eq!(run["dry_run"], true, "the default must be the safe one");
}

#[tokio::test]
async fn a_started_run_is_recorded_rather_than_executed() {
    // A 202 says a row exists. Nothing was sent, nothing is running, and the run's own
    // state is the only thing that says what happened to it — M10 §2.9.
    let f = fixture("recorded", 1).await;
    // Held so `uops-runner`'s suite cannot claim this run out from under the assertion
    // below — the queue is deployment-wide by design.
    let _queue = QueueLock::take().await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &read_only("record", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (status, run) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "a real one", "dry_run": false }),
        ))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(run["state"], "ready", "waiting for a runner, not running");
    assert_eq!(run["touched_a_device"], false);

    // No transcript, because nothing has executed.
    let run_id = run["id"].as_str().unwrap();
    let (_, detail) = f.call(f.get(&format!("/api/v1/runs/{run_id}"))).await;
    assert_eq!(detail["steps"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn a_run_with_no_reason_is_refused() {
    let f = fixture("noreason", 1).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &read_only("why", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (status, body) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "   " }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("why"), "{body}");
}

#[tokio::test]
async fn a_destructive_run_waits_for_an_approval_and_a_dry_run_of_it_does_not() {
    // The asymmetry is the decision: a dry run sends only the steps the author marked as
    // changing nothing, so there is nothing for an approval to be about — and requiring
    // one would teach everybody to approve dry runs without reading them.
    let f = fixture("waits", 1).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &two_step("guarded", "one", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (_, dry) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "just looking", "dry_run": true }),
        ))
        .await;
    assert_eq!(dry["state"], "ready");

    let (_, real) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "doing it", "dry_run": false }),
        ))
        .await;
    assert_eq!(real["state"], "awaiting_approval");
}

// ---- approving -----------------------------------------------------------------

#[tokio::test]
async fn a_run_approved_by_somebody_else_becomes_ready_and_one_approved_by_its_starter_does_not() {
    let f = fixture("approve", 1).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &two_step("two-person", "one", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (_, run) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "the session is stuck", "dry_run": false }),
        ))
        .await;
    let run_id = run["id"].as_str().unwrap().to_owned();

    // The starter's own approval. Refused, and this is the whole of two-person integrity.
    let (status, body) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runs/{run_id}/approve"),
            &serde_json::json!({}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.to_string().contains("cannot approve"), "{body}");

    // Somebody else's.
    let (_, session, csrf) = f.colleague("colleague").await;
    let (status, approved) = f
        .call(f.send_as(
            &session,
            &csrf,
            "POST",
            &format!("/api/v1/runs/{run_id}/approve"),
            &serde_json::json!({}),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["state"], "ready");
    assert_eq!(approved["approvals"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn one_approval_is_not_enough_when_the_runbook_asks_for_two() {
    // A per-runbook setting rather than a global one — §2.5. Requiring two approvals for
    // restarting an interface is how an organisation ends up with a standing exception.
    let f = fixture("twoperson", 1).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &two_step("serious", "two", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (_, run) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "serious change", "dry_run": false }),
        ))
        .await;
    let run_id = run["id"].as_str().unwrap().to_owned();

    let (_, s1, c1) = f.colleague("first").await;
    let (_, after_one) = f
        .call(f.send_as(
            &s1,
            &c1,
            "POST",
            &format!("/api/v1/runs/{run_id}/approve"),
            &serde_json::json!({}),
        ))
        .await;
    assert_eq!(
        after_one["state"], "awaiting_approval",
        "one of two is not enough"
    );

    let (_, s2, c2) = f.colleague("second").await;
    let (_, after_two) = f
        .call(f.send_as(
            &s2,
            &c2,
            "POST",
            &format!("/api/v1/runs/{run_id}/approve"),
            &serde_json::json!({}),
        ))
        .await;
    assert_eq!(after_two["state"], "ready");
    assert_eq!(after_two["approvals"].as_array().unwrap().len(), 2);
}

// ---- break-glass ---------------------------------------------------------------

#[tokio::test]
async fn a_break_glass_run_starts_unapproved_is_audited_as_its_own_event_and_says_so_for_ever() {
    // M10 §3's break-glass criterion, all three clauses. The account is the organization's
    // one emergency account — the same one M12 §2.2 created, which §2.5 asks for by name.
    let f = fixture("breakglass", 1).await;
    sqlx::query("UPDATE app_user SET break_glass = true WHERE id = $1")
        .bind(f.me.into_uuid())
        .execute(f.store.pool())
        .await
        .expect("break glass");

    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &two_step("emergency", "two", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (status, run) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({
                "reason": "outage at 3am, one engineer awake",
                "dry_run": false,
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run}");

    // It succeeded without approval, and the run record says so.
    assert_eq!(run["state"], "ready");
    assert_eq!(run["break_glass"], true);
    assert_eq!(run["approvals"].as_array().unwrap().len(), 0);

    // Its own kind of audit event, not the ordinary one with a flag: an investigation
    // looking for these should be able to filter on the action rather than read every
    // run's detail.
    let log = f.audit_log().await;
    let actions: Vec<&str> = log.iter().map(|(a, _)| a.as_str()).collect();
    assert!(
        actions.contains(&"runbooks.run.break_glass"),
        "{actions:?}"
    );
    assert!(!actions.contains(&"runbooks.run.start"), "{actions:?}");

    // And it stays said: re-reading the run later still reports it unapproved.
    let run_id = run["id"].as_str().unwrap();
    let (_, later) = f.call(f.get(&format!("/api/v1/runs/{run_id}"))).await;
    assert_eq!(later["break_glass"], true);
}

#[tokio::test]
async fn an_ordinary_operator_gets_no_break_glass_and_the_event_says_so() {
    // The other half. Without it, "break-glass works" could be "approval never applies".
    let f = fixture("ordinary", 1).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &two_step("normal", "one", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (_, run) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "ordinary change", "dry_run": false }),
        ))
        .await;
    assert_eq!(run["state"], "awaiting_approval");
    assert_eq!(run["break_glass"], false);

    let actions: Vec<String> = f.audit_log().await.into_iter().map(|(a, _)| a).collect();
    assert!(actions.contains(&"runbooks.run.start".to_owned()), "{actions:?}");
    assert!(
        !actions.contains(&"runbooks.run.break_glass".to_owned()),
        "{actions:?}"
    );
}

// ---- cancelling and retiring ---------------------------------------------------

#[tokio::test]
async fn a_run_can_be_cancelled_before_a_runner_takes_it_and_not_after() {
    // "Cancel" on a run that has already sent something would be a promise this product
    // cannot keep. What it offers at that point is the transcript and the declared
    // rollback — §2.6.
    let f = fixture("cancel", 1).await;
    // A run that a runner claimed would no longer be cancellable, and the queue is
    // deployment-wide by design.
    let _queue = QueueLock::take().await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &read_only("cancellable", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    let (_, run) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "changed my mind", "dry_run": false }),
        ))
        .await;
    let run_id = run["id"].as_str().unwrap().to_owned();

    let (status, cancelled) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runs/{run_id}/cancel"),
            &serde_json::json!({}),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    assert_eq!(cancelled["state"], "cancelled");

    // A second run, taken by a runner, cannot be.
    let (_, running) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "this one goes", "dry_run": false }),
        ))
        .await;
    let running_id: uuid::Uuid = running["id"].as_str().unwrap().parse().unwrap();
    f.store
        .set_run_state(
            &uops_core::TenantScope::system(f.tenant),
            running_id,
            uops_store_pg::RunState::Running,
            None,
        )
        .await
        .expect("running");

    let (status, body) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runs/{running_id}/cancel"),
            &serde_json::json!({}),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("cannot be called back"), "{body}");
}

#[tokio::test]
async fn a_retired_runbook_cannot_be_run_and_its_history_still_reads() {
    let f = fixture("retired", 1).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &read_only("old", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    // A run of it, before retirement, so there is history to keep resolving.
    f.call(f.send(
        "POST",
        &format!("/api/v1/runbooks/{id}/runs"),
        &serde_json::json!({ "reason": "while it lasted" }),
    ))
    .await;

    let (status, _) = f
        .call(f.send("DELETE", &format!("/api/v1/runbooks/{id}"), &serde_json::json!({})))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "one more" }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("retired"), "{body}");

    // The run history still names it. That is the whole reason it is retired rather than
    // deleted.
    let (_, runs) = f.call(f.get("/api/v1/runs")).await;
    assert_eq!(runs.as_array().unwrap().len(), 1);
    assert_eq!(runs[0]["runbook_name"], "old");
}

// ---- roles ---------------------------------------------------------------------

#[tokio::test]
async fn a_viewer_can_read_a_runbook_and_cannot_start_one() {
    let f = fixture("viewer", 1).await;
    let (_, book) = f
        .call(f.send("POST", "/api/v1/runbooks", &read_only("readable", 10)))
        .await;
    let id = book["id"].as_str().unwrap();

    // A distinct local part: the fixture's own user is `viewer-<tenant>@…` because the
    // slug is "viewer", and one email per organization is a unique index.
    let email = format!("read-only-{}@example.com", f.tenant.into_uuid().simple());
    let hash = password::hash(&Secret::new("pw".to_owned())).unwrap();
    let viewer = f
        .store
        .create_user(f.org, &email, "Viewer", &hash)
        .await
        .expect("user");
    f.store
        .grant_role(viewer, f.tenant, Role::Viewer, None)
        .await
        .expect("role");
    let (session, csrf) = sign_in(&f.store, &email).await;

    let reading = Request::builder()
        .uri("/api/v1/runbooks")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
        .header(TENANT_HEADER, f.tenant.to_string())
        .body(Body::empty())
        .unwrap();
    let (status, list) = f.call(reading).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list.as_array().unwrap().len(), 1);

    let (status, body) = f
        .call(f.send_as(
            &session,
            &csrf,
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "not allowed" }),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

// ---- maintenance windows -------------------------------------------------------

#[tokio::test]
async fn a_maintenance_only_runbook_is_refused_outside_a_window_and_allowed_inside_one() {
    // M10 §2.7, and it cuts the opposite way from alerting: an alert is *suppressed*
    // during a window, and an automated change is *only permitted* during one. The default
    // is the conservative one, so this is a per-runbook opt-in.
    let f = fixture("window", 2).await;

    let mut book = read_only("during-work", 10);
    book["maintenance_only"] = serde_json::json!(true);
    let (_, saved) = f.call(f.send("POST", "/api/v1/runbooks", &book)).await;
    let id = saved["id"].as_str().unwrap().to_owned();

    // Outside. The refusal names the devices, because "not in a window" with no names is
    // a message an operator cannot act on.
    let (status, body) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "too early" }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let said = body.to_string();
    assert!(said.contains("maintenance"), "{said}");
    assert!(said.contains("sw-00"), "the refusal names a device: {said}");

    // And the plan says so without refusing, because a plan is a description rather than
    // an attempt — somebody reviewing one before the window opens should still see it.
    let (status, plan) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/plan"),
            &serde_json::json!({}),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{plan}");
    assert!(plan["blocked"].as_str().unwrap().contains("maintenance"));

    // A window covering every target, open now.
    let scope = uops_core::TenantScope::system(f.tenant);
    for device in &f.devices {
        f.store
            .schedule_maintenance(
                &scope,
                None,
                &uops_store_pg::NewWindow {
                    reason: "planned work".to_owned(),
                    target: uops_core::Target::Resource(*device),
                    schedule: uops_core::Schedule {
                        starts_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                        duration_minutes: 60,
                        timezone: "UTC".to_owned(),
                        recurrence: uops_core::Recurrence::Once,
                        until: None,
                    },
                    suppression: uops_core::Suppression::default(),
                },
            )
            .await
            .expect("window");
    }

    let (status, run) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "the window is open" }),
        ))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run}");
}

#[tokio::test]
async fn one_target_outside_the_window_is_enough_to_refuse() {
    // **Every** target, not any of them. "May only run inside a maintenance window" is a
    // statement about the change, and a change that reaches one device nobody scheduled
    // work on is a change outside the window.
    let f = fixture("partial", 2).await;

    let mut book = read_only("all-or-nothing", 10);
    book["maintenance_only"] = serde_json::json!(true);
    let (_, saved) = f.call(f.send("POST", "/api/v1/runbooks", &book)).await;
    let id = saved["id"].as_str().unwrap().to_owned();

    // A window over the first device only.
    f.store
        .schedule_maintenance(
            &uops_core::TenantScope::system(f.tenant),
            None,
            &uops_store_pg::NewWindow {
                reason: "half the work".to_owned(),
                target: uops_core::Target::Resource(f.devices[0]),
                schedule: uops_core::Schedule {
                    starts_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                    duration_minutes: 60,
                    timezone: "UTC".to_owned(),
                    recurrence: uops_core::Recurrence::Once,
                    until: None,
                },
                suppression: uops_core::Suppression::default(),
            },
        )
        .await
        .expect("window");

    let (status, body) = f
        .call(f.send(
            "POST",
            &format!("/api/v1/runbooks/{id}/runs"),
            &serde_json::json!({ "reason": "most of it is fine" }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let said = body.to_string();
    assert!(said.contains("1 of its 2 targets"), "{said}");
}
