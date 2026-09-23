//! Login, logout and `/me`, through the real router against a real database.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt as _;
use uops_api::{AppState, CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE};
use uops_core::{ActorId, OrgId, Role, Secret, TenantId};
use uops_secrets::password;
use uops_store_pg::{Config, PgStore};

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
    org: OrgId,
    tenant: TenantId,
    email: String,
    user: ActorId,
}

async fn fixture(slug: &str) -> Fixture {
    let store = store().await;
    let org = OrgId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("routes-org-{slug}"))
        .execute(store.pool())
        .await
        .expect("organization");

    let tenant = TenantId::new();
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("routes-{slug}"))
        .bind(format!("{slug}-{}", tenant.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("tenant");

    // Unique per test run, because login looks up by address across the deployment.
    let email = format!("{slug}-{}@example.com", tenant.into_uuid().simple());
    let hash = password::hash(&Secret::new("correct horse".to_owned())).unwrap();
    let user = store
        .create_user(org, &email, "Route Test", &hash)
        .await
        .expect("user");
    store
        .grant_role(user, tenant, Role::Operator, None)
        .await
        .expect("role");

    // What a real single-tenant installation has — `docs/self-monitoring.md`. A first run
    // nominates its own tenant in the bootstrap transaction, and migration 0027 backfilled
    // every existing organization that had exactly one. This fixture builds its
    // organization with raw SQL rather than through either, so it does the same thing
    // explicitly; the test that un-nominates is what covers the other shape.
    store
        .nominate_platform_tenant(org, tenant)
        .await
        .expect("platform tenant");

    Fixture {
        store,
        org,
        tenant,
        email,
        user,
    }
}

/// A telemetry store for tests that never query one.
///
/// Constructing it opens no connection — the HTTP client is lazy — so a test that only
/// exercises the control plane costs nothing for holding it. Required rather than
/// optional in `AppState` because an API that cannot answer a query is a different
/// product, not a degraded one.
fn telemetry() -> uops_store_ch::ChStore {
    uops_store_ch::ChStore::new(uops_store_ch::ChClient::new(
        uops_store_ch::ChConfig::from_env(),
    ))
}

fn app(store: &PgStore) -> axum::Router {
    uops_api::router(AppState::new(store.clone(), telemetry()))
}

fn login_request(email: &str, pw: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "email": email, "password": pw }).to_string(),
        ))
        .unwrap()
}

/// Every `Set-Cookie` on a response.
fn cookies(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect()
}

fn value_of(cookies: &[String], name: &str) -> Option<String> {
    cookies.iter().find_map(|c| {
        let (pair, _) = c.split_once("; ")?;
        let (found, value) = pair.split_once('=')?;
        (found == name).then(|| value.to_owned())
    })
}

/// Log in and return the two tokens a browser would now be holding.
async fn sign_in(f: &Fixture) -> (String, String) {
    let response = app(&f.store)
        .oneshot(login_request(&f.email, "correct horse"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let set = cookies(&response);
    (
        value_of(&set, SESSION_COOKIE).expect("session cookie"),
        value_of(&set, CSRF_COOKIE).expect("csrf cookie"),
    )
}

#[tokio::test]
async fn login_sets_a_session_cookie_and_a_csrf_cookie_with_the_right_flags() {
    // The flags ARE the mechanism: an script-readable session cookie turns any XSS into
    // an account takeover, and a script-unreadable CSRF token cannot be echoed into the
    // header that makes double-submit work.
    let f = fixture("flags").await;

    let response = app(&f.store)
        .oneshot(login_request(&f.email, "correct horse"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let set = cookies(&response);
    let session = set.iter().find(|c| c.starts_with(SESSION_COOKIE)).unwrap();
    let csrf = set.iter().find(|c| c.starts_with(CSRF_COOKIE)).unwrap();

    assert!(session.contains("HttpOnly"), "{session}");
    assert!(session.contains("Secure"), "{session}");
    assert!(session.contains("SameSite=Lax"), "{session}");

    assert!(
        !csrf.contains("HttpOnly"),
        "the app must be able to read it: {csrf}"
    );
    assert!(csrf.contains("Secure"), "{csrf}");
}

#[tokio::test]
async fn a_wrong_password_and_an_unknown_address_are_the_same_answer() {
    // Account enumeration: if these differ in status, in body, or in header, an
    // attacker can confirm which addresses have accounts here.
    let f = fixture("enumerate").await;

    let wrong = app(&f.store)
        .oneshot(login_request(&f.email, "wrong horse"))
        .await
        .unwrap();
    let unknown = app(&f.store)
        .oneshot(login_request("nobody-at-all@example.com", "wrong horse"))
        .await
        .unwrap();

    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status(), wrong.status());
    assert!(cookies(&wrong).is_empty(), "a failed login sets no cookie");
    assert!(cookies(&unknown).is_empty());

    let wrong_body = axum::body::to_bytes(wrong.into_body(), 4096).await.unwrap();
    let unknown_body = axum::body::to_bytes(unknown.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        wrong_body, unknown_body,
        "the two failures must be byte-identical"
    );
}

/// The fastest of several attempts. The minimum is the cleanest estimate of what a
/// request actually costs — a mean or a single sample mostly measures scheduler noise,
/// and on a shared CI runner that noise is larger than the signal.
async fn fastest_login(f: &Fixture, email: &str, pw: &str) -> std::time::Duration {
    let mut best = std::time::Duration::MAX;
    for _ in 0..3 {
        let started = std::time::Instant::now();
        let response = app(&f.store)
            .oneshot(login_request(email, pw))
            .await
            .unwrap();
        best = best.min(started.elapsed());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    best
}

#[tokio::test]
async fn an_unknown_address_does_not_answer_faster_than_a_wrong_password() {
    // The oracle everyone forgets. Returning early when the user does not exist skips
    // Argon2 — deliberately slow — so "no such user" comes back in a millisecond and
    // "wrong password" in twenty. That gap is measurable over the internet and is a
    // reliable way to enumerate which addresses have accounts here.
    //
    // The two are COMPARED rather than each being checked against a fixed floor. An
    // earlier version of this test asserted only that the unknown-address path took at
    // least 5ms, and it passed happily with the short-circuit in place: the router and
    // the database round trip alone cost more than that, so the threshold measured
    // everything except the thing it was protecting.
    let f = fixture("timing").await;

    let unknown = fastest_login(&f, "definitely-nobody@example.com", "x").await;
    let wrong = fastest_login(&f, &f.email, "wrong horse").await;

    // Half is deliberately generous. A short-circuit is not a 20% difference, it is an
    // order of magnitude — Argon2 at 19 MiB against a database round trip.
    assert!(
        unknown * 2 >= wrong,
        "an unknown address answered in {unknown:?} against {wrong:?} for a wrong          password — the absent-user path is short-circuiting past the verification,          which lets an attacker enumerate accounts"
    );
}

#[tokio::test]
async fn a_disabled_account_cannot_log_in_even_with_the_right_password() {
    // And is not told that the password was right, because that is also an answer.
    let f = fixture("disabled-login").await;
    f.store.disable_user(f.user).await.unwrap();

    let response = app(&f.store)
        .oneshot(login_request(&f.email, "correct horse"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(cookies(&response).is_empty());
}

#[tokio::test]
async fn me_lists_the_tenants_the_switcher_is_built_from() {
    let f = fixture("me").await;
    let (session, _) = sign_in(&f).await;

    let response = app(&f.store)
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let me: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(me["email"], f.email);
    assert_eq!(me["tenants"][0]["tenant_id"], f.tenant.to_string());
    assert_eq!(me["tenants"][0]["role"], "operator");
    // Whatever else /me grows, it must never carry password material.
    assert!(!body.windows(4).any(|w| w == b"hash"), "{me}");
}

#[tokio::test]
async fn me_without_a_session_is_unauthenticated() {
    let f = fixture("me-anon").await;
    let response = app(&f.store)
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_without_the_csrf_header_is_refused() {
    // The whole point of double-submit: the browser attaches the cookies for any
    // origin, so the cookie alone proves nothing about who initiated the request.
    let f = fixture("logout-csrf").await;
    let (session, csrf) = sign_in(&f).await;

    let response = app(&f.store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={csrf}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn logout_clears_the_cookies_and_ends_the_session() {
    let f = fixture("logout").await;
    let (session, csrf) = sign_in(&f).await;

    let response = app(&f.store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={csrf}"),
                )
                .header(CSRF_HEADER, &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let set = cookies(&response);
    assert!(
        set.iter().all(|c| c.contains("Max-Age=0")),
        "both cookies must be cleared: {set:?}"
    );

    // And the token itself is dead, not merely forgotten by the browser.
    let after = app(&f.store)
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_stolen_cookie_without_the_csrf_token_cannot_mutate() {
    // The attacker's exact position: they can make the browser send its cookies, and
    // they cannot read them. Here the session cookie is present and the CSRF cookie is
    // too — what is missing is the header, because their page could never read it.
    let f = fixture("stolen").await;
    let (session, csrf) = sign_in(&f).await;

    let response = app(&f.store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={csrf}"),
                )
                .header(CSRF_HEADER, "a value the attacker guessed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // And the session is untouched: a refused CSRF check must not have side effects.
    let still = app(&f.store)
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(still.status(), StatusCode::OK);
}

// ---- sign-in records — M11 §2.4 ------------------------------------------------

/// The organization audit entries for this fixture's org, newest first.
async fn sign_in_records(f: &Fixture) -> Vec<(String, String, Option<serde_json::Value>)> {
    f.store
        .org_audit_entries(f.org, 50)
        .await
        .expect("org audit")
        .into_iter()
        .filter(|e| e.action.starts_with("auth.sign_in"))
        .map(|e| (e.action, e.target, e.detail))
        .collect()
}

#[tokio::test]
async fn a_successful_sign_in_is_recorded_against_the_organization() {
    // M11 §2.4. Not in `events`: authentication precedes knowing a tenant — the same fact
    // M12 §2.2 found for SSO — so an organization-level fact goes in the organization
    // audit log rather than into N tenant partitions.
    let f = fixture("signin-ok").await;

    let response = app(&f.store)
        .oneshot(login_request(&f.email, "correct horse"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let records = sign_in_records(&f).await;
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, "auth.sign_in.success");
    assert_eq!(records[0].1, f.email, "the address is the target");
}

#[tokio::test]
async fn a_wrong_password_is_recorded_and_says_which_failure_it_was() {
    // The record an investigation actually reads. "Somebody failed to sign in" is not
    // enough: a wrong password and a disabled account are different events, and a burst of
    // one is a different thing from a burst of the other.
    let f = fixture("signin-bad").await;

    let response = app(&f.store)
        .oneshot(login_request(&f.email, "not the password"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let records = sign_in_records(&f).await;
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, "auth.sign_in.failure");
    let reason = records[0].2.as_ref().expect("a reason");
    assert_eq!(reason["reason"], "the password did not match");
}

#[tokio::test]
async fn a_disabled_account_is_recorded_as_a_different_failure() {
    let f = fixture("signin-disabled").await;
    f.store.disable_user(f.user).await.expect("disable");

    let response = app(&f.store)
        .oneshot(login_request(&f.email, "correct horse"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let records = sign_in_records(&f).await;
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, "auth.sign_in.failure");
    assert_eq!(
        records[0].2.as_ref().expect("a reason")["reason"],
        "the account is disabled"
    );
}

#[tokio::test]
async fn an_address_that_resolves_to_no_user_is_deliberately_not_recorded() {
    // There is no organization to attribute it to, and showing it to *an* organization
    // would tell them about an attempt that was not against them — which in a hosted
    // deployment is a leak between customers. Blind spraying at addresses that do not
    // exist is what the per-IP rate limit on auth endpoints is for.
    let f = fixture("signin-nobody").await;

    let response = app(&f.store)
        .oneshot(login_request("nobody@example.invalid", "whatever"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    assert!(
        sign_in_records(&f).await.is_empty(),
        "an unknown address must not be attributed to this organization"
    );
}

#[tokio::test]
async fn the_record_carries_the_address_the_attempt_came_from() {
    // The field that makes the three shapes in §2.4 distinguishable — many failures from
    // one source is the one worth waking somebody for. It is the first *parseable* hop, so
    // a client that sends junk before a proxy that appends cannot erase itself.
    let f = fixture("signin-ip").await;

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "garbage, 198.51.100.7")
        .body(Body::from(
            serde_json::json!({ "email": f.email, "password": "wrong" }).to_string(),
        ))
        .unwrap();
    let response = app(&f.store).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let entries = f.store.org_audit_entries(f.org, 50).await.expect("audit");
    let record = entries
        .iter()
        .find(|e| e.action == "auth.sign_in.failure")
        .expect("recorded");
    assert_eq!(record.ip.as_deref(), Some("198.51.100.7"));
}

// ---- the installation as a resource — docs/self-monitoring.md -------------------

/// Every security event on this organization's platform resource.
async fn platform_events(f: &Fixture) -> Vec<(String, String, String)> {
    let Some(target) = f
        .store
        .platform_target(f.org)
        .await
        .expect("platform target")
    else {
        return Vec::new();
    };

    let client = uops_store_ch::ChClient::new(uops_store_ch::ChConfig {
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "uops".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "uops".into()),
        ..uops_store_ch::ChConfig::from_env()
    });
    let result = client
        .run(
            "SELECT event_type, summary, attributes['source.ip'] FROM events \
             WHERE resource_id = {resource:UUID} ORDER BY observed_at FORMAT TSV",
            &[("resource", target.resource_id.into_uuid().to_string())],
        )
        .await
        .expect("query ClickHouse");

    result
        .body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let mut cells = line.split('\t');
            (
                cells.next().unwrap_or_default().to_owned(),
                cells.next().unwrap_or_default().to_owned(),
                cells.next().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_new_installation_has_a_resource_for_itself() {
    // `docs/self-monitoring.md` §4: created, not discovered. Identity resolution exists to
    // work out what a thing is from what it says about itself, and the installation does
    // not need to be guessed at.
    let f = fixture("selfres").await;

    let target = f
        .store
        .platform_target(f.org)
        .await
        .expect("read")
        .expect("a first run nominates its own tenant");
    assert_eq!(target.tenant_id, f.tenant, "the only tenant there is");

    let resource = f
        .store
        .resource(&uops_core::TenantScope::system(f.tenant), target.resource_id)
        .await
        .expect("the resource exists");
    assert_eq!(resource.kind, uops_core::ResourceKind::Service);
    assert_eq!(resource.name, "This installation");
}

#[tokio::test]
async fn the_installation_is_not_pollable_and_not_a_runbook_target() {
    // Both fall out of the schema rather than needing a rule: a resource with no `mgmt_ip`
    // identifier does not join in `pollable_devices` and cannot be reached by a runbook
    // step. A product that could be told to SSH into itself is a product with a new class
    // of mistake available to it.
    let f = fixture("selfreach").await;
    let target = f.store.platform_target(f.org).await.unwrap().unwrap();
    let scope = uops_core::TenantScope::system(f.tenant);

    let addresses = f
        .store
        .resource_addresses(&scope, &[target.resource_id])
        .await
        .expect("addresses");
    assert!(
        addresses.is_empty(),
        "the installation must have no management address: {addresses:?}"
    );

    let pollable = f.store.pollable_devices(&scope, 100).await.expect("fleet");
    assert!(
        !pollable.iter().any(|d| d.resource_id == target.resource_id),
        "the installation must not be in the polled fleet"
    );
}

/// Wait for the installation to have `want` events, or give up and return what there is.
///
/// The sign-in event is written **off the request path** on purpose — see `note_sign_in`,
/// where putting a `ClickHouse` round trip inline reintroduced an account-enumeration
/// timing oracle. A test for an intentionally asynchronous write has to wait for it, and a
/// fixed sleep is a flake waiting for a slow day: this polls to a deadline instead, so it
/// is fast when the write is fast and still correct when it is not.
async fn platform_events_eventually(
    f: &Fixture,
    want: usize,
) -> Vec<(String, String, String)> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let found = platform_events(f).await;
        if found.len() >= want || std::time::Instant::now() > deadline {
            return found;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_failed_sign_in_becomes_an_event_on_the_installation() {
    // The whole point of `docs/self-monitoring.md`: the audit row is what an auditor reads,
    // and this is what a rule can fire on.
    let f = fixture("selfevent").await;

    let response = app(&f.store)
        .oneshot(login_request(&f.email, "not the password"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let events = platform_events_eventually(&f, 1).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, "failure");
    assert!(events[0].1.contains(&f.email), "{events:?}");

    // And the audit row is still there. Both, because they answer different questions and
    // are read by different people.
    let audit = f.store.org_audit_entries(f.org, 50).await.expect("audit");
    assert!(audit.iter().any(|e| e.action == "auth.sign_in.failure"));
}

#[tokio::test]
async fn a_successful_sign_in_is_an_event_too_and_carries_the_source() {
    // Not only failures. "Who signed in, from where" is the question an investigation asks
    // after the fact, and a product that recorded only the refusals could not answer it.
    let f = fixture("selfok").await;

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "198.51.100.7")
        .body(Body::from(
            serde_json::json!({ "email": f.email, "password": "correct horse" }).to_string(),
        ))
        .unwrap();
    let response = app(&f.store).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let events = platform_events_eventually(&f, 1).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, "success");
    assert_eq!(events[0].2, "198.51.100.7", "the address is on the event");
}

#[tokio::test]
async fn an_organization_with_no_platform_tenant_gets_the_audit_row_and_no_event() {
    // The honest degradation `docs/self-monitoring.md` §3 promised. An organization with
    // more than one tenant has nominated nothing, and gets exactly the behaviour from
    // before this existed — rather than an event attributed to a tenant it was not about.
    let f = fixture("selfnone").await;

    sqlx::query(
        "UPDATE organization SET platform_tenant_id = NULL, platform_resource_id = NULL \
         WHERE id = $1",
    )
    .bind(f.org.into_uuid())
    .execute(f.store.pool())
    .await
    .expect("un-nominate");

    let response = app(&f.store)
        .oneshot(login_request(&f.email, "wrong"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    assert!(
        f.store.platform_target(f.org).await.unwrap().is_none(),
        "nothing is nominated"
    );
    let audit = f.store.org_audit_entries(f.org, 50).await.expect("audit");
    assert!(
        audit.iter().any(|e| e.action == "auth.sign_in.failure"),
        "the audit row is still written"
    );
}

#[tokio::test]
async fn nominating_a_tenant_twice_keeps_the_first_installation() {
    // Idempotent, and the `UPDATE … WHERE platform_tenant_id IS NULL` is what decides
    // between two replicas racing at first run rather than a check the caller makes first.
    // A second "This installation" in the inventory would be the visible half of a race
    // nobody would think to look for.
    let f = fixture("selftwice").await;
    let first = f.store.platform_target(f.org).await.unwrap().unwrap();

    let again = f
        .store
        .nominate_platform_tenant(f.org, f.tenant)
        .await
        .expect("nominating again is not an error");
    assert_eq!(again, first, "the same installation");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM resource WHERE tenant_id = $1 AND name = 'This installation'",
    )
    .bind(f.tenant.into_uuid())
    .fetch_one(f.store.pool())
    .await
    .expect("count");
    assert_eq!(count, 1, "exactly one installation in the inventory");
}
