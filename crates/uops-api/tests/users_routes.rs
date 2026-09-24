//! Adding a colleague, over HTTP — `docs/user-administration.md`.
//!
//! The acceptance criteria that matter are end-to-end and say so: *"an organization with no
//! SSO and one admin can add a second person, who sets their own password and signs in —
//! with no `psql` at any point."* That is one test here, and it is the one this whole feature
//! exists for. The store tests in `uops-store-pg/tests/users.rs` cover the rules; these cover
//! that the rules are reachable, which is the failure mode this repository keeps producing.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt as _;
use uops_api::cookie::{CSRF_COOKIE, SESSION_COOKIE};
use uops_api::csrf::CSRF_HEADER;
use uops_api::extract::TENANT_HEADER;
use uops_api::state::AppState;
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

fn telemetry() -> uops_store_ch::ChStore {
    uops_store_ch::ChStore::new(uops_store_ch::ChClient::new(
        uops_store_ch::ChConfig::from_env(),
    ))
}

fn app(store: &PgStore) -> axum::Router {
    uops_api::router(AppState::new(store.clone(), telemetry()))
}

/// An organization whose only user is an admin on its only tenant — a first run, in other
/// words, which is the installation this feature is for.
struct World {
    store: PgStore,
    org: OrgId,
    tenant: TenantId,
    admin: ActorId,
    admin_email: String,
}

const ADMIN_PASSWORD: &str = "correct horse battery staple";

impl World {
    async fn new(slug: &str) -> Self {
        let store = store().await;
        let org = OrgId::new();
        sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
            .bind(org.into_uuid())
            .bind(format!("ur-{slug}-{}", org.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("organization");

        let tenant = TenantId::new();
        sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
            .bind(tenant.into_uuid())
            .bind(org.into_uuid())
            .bind(format!("ur-{slug}"))
            .bind(format!("{slug}-{}", tenant.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("tenant");

        let admin_email = format!("admin-{}@example.test", tenant.into_uuid().simple());
        let hash = password::hash(&Secret::new(ADMIN_PASSWORD.to_owned())).expect("hash");
        let admin = store
            .create_user(org, &admin_email, "The Administrator", &hash)
            .await
            .expect("user");
        store
            .grant_role(admin, tenant, Role::Admin, None)
            .await
            .expect("role");

        Self {
            store,
            org,
            tenant,
            admin,
            admin_email,
        }
    }

    /// A second administrator, so the last-admin guard does not refuse what a test is
    /// actually about.
    async fn second_admin(&self) -> (ActorId, String) {
        let email = format!("second-{}@example.test", ActorId::new().into_uuid().simple());
        let hash = password::hash(&Secret::new(ADMIN_PASSWORD.to_owned())).expect("hash");
        let user = self
            .store
            .create_user(self.org, &email, "The Other One", &hash)
            .await
            .expect("user");
        self.store
            .grant_role(user, self.tenant, Role::Admin, None)
            .await
            .expect("role");
        (user, email)
    }
}

/// The session and CSRF cookies a browser would hold after signing in.
async fn sign_in(store: &PgStore, email: &str, pw: &str) -> Option<(String, String)> {
    let response = app(store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": email, "password": pw }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    if response.status() != StatusCode::NO_CONTENT {
        return None;
    }
    let set: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let value = |name: &str| {
        set.iter().find_map(|c| {
            let (pair, _) = c.split_once("; ")?;
            let (found, v) = pair.split_once('=')?;
            (found == name).then(|| v.to_owned())
        })
    };
    Some((value(SESSION_COOKIE)?, value(CSRF_COOKIE)?))
}

struct Session {
    session: String,
    csrf: String,
}

impl Session {
    fn request(&self, method: &str, uri: &str, tenant: Option<TenantId>) -> Request<Body> {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::COOKIE,
                format!(
                    "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                    self.session, self.csrf
                ),
            )
            .header(CSRF_HEADER, &self.csrf)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(t) = tenant {
            b = b.header(TENANT_HEADER, t.to_string());
        }
        b.body(Body::empty()).unwrap()
    }

    fn with_body(
        &self,
        method: &str,
        uri: &str,
        tenant: Option<TenantId>,
        body: &serde_json::Value,
    ) -> Request<Body> {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::COOKIE,
                format!(
                    "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                    self.session, self.csrf
                ),
            )
            .header(CSRF_HEADER, &self.csrf)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(t) = tenant {
            b = b.header(TENANT_HEADER, t.to_string());
        }
        b.body(Body::from(body.to_string())).unwrap()
    }
}

async fn as_admin(w: &World) -> Session {
    let (session, csrf) = sign_in(&w.store, &w.admin_email, ADMIN_PASSWORD)
        .await
        .expect("the administrator signs in");
    Session { session, csrf }
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ---------------------------------------------------------------------------

/// **The criterion this feature exists for.** One organization, one admin, no SSO, no `psql`.
#[tokio::test]
async fn an_administrator_adds_a_colleague_who_signs_in() {
    let w = World::new("adds").await;
    let admin = as_admin(&w).await;
    let email = format!("newcomer-{}@example.test", ActorId::new().into_uuid().simple());

    // 1. Invite them.
    let response = app(&w.store)
        .oneshot(admin.with_body(
            "POST",
            "/api/v1/users",
            None,
            &serde_json::json!({ "email": email, "display_name": "The Newcomer" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let invited = json(response).await;
    let token = invited["link_token"].as_str().expect("the token, once");

    // No account yet, and the invitation is listed as pending.
    let listed = json(
        app(&w.store)
            .oneshot(admin.request("GET", "/api/v1/users", None))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(listed.as_array().map(Vec::len), Some(1), "{listed}");

    let pending = json(
        app(&w.store)
            .oneshot(admin.request("GET", "/api/v1/users/invitations", None))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(pending[0]["email"].as_str(), Some(email.as_str()));

    // 2. They set their own password. Unauthenticated — they have no account to sign in to.
    let response = app(&w.store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/invitations/{token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "password": "a password of my own choosing" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 3. They sign in.
    assert!(
        sign_in(&w.store, &email, "a password of my own choosing")
            .await
            .is_some(),
        "the whole point: a second person is in the installation, and no administrator ever \
         knew their password"
    );

    // 4. And an administrator can give them a role on the tenant.
    let newcomer = w
        .store
        .users_in_org(w.org)
        .await
        .expect("list")
        .into_iter()
        .find(|u| u.email == email)
        .expect("they have an account now");

    let response = app(&w.store)
        .oneshot(admin.with_body(
            "PUT",
            &format!("/api/v1/users/{}/role", newcomer.id),
            Some(w.tenant),
            &serde_json::json!({ "role": "operator" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        w.store.role_for(newcomer.id, w.tenant).await.unwrap(),
        Some(Role::Operator)
    );
}

#[tokio::test]
async fn the_invitation_token_is_returned_once_and_never_again() {
    let w = World::new("once").await;
    let admin = as_admin(&w).await;
    let email = format!("once-{}@example.test", ActorId::new().into_uuid().simple());

    let first = json(
        app(&w.store)
            .oneshot(admin.with_body(
                "POST",
                "/api/v1/users",
                None,
                &serde_json::json!({ "email": email, "display_name": "Once" }),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert!(first["link_token"].is_string());

    // Listing invitations must never carry it: only the hash is stored, and a list that
    // could show it would mean the database held a working invitation in the clear.
    let pending = json(
        app(&w.store)
            .oneshot(admin.request("GET", "/api/v1/users/invitations", None))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        pending[0].get("link_token").is_none() && pending[0].get("token").is_none(),
        "{pending}"
    );
}

#[tokio::test]
async fn a_bad_invitation_is_refused_with_one_sentence() {
    let w = World::new("badtoken").await;

    let response = app(&w.store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/invitations/nothing-anybody-issued")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "password": "a long enough password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let nonsense = json(response).await["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();

    // The property is not that the sentence is vague — it is that two different failures
    // produce the *same* sentence. A token that was real and expired must be indistinguishable
    // from one that never existed, or the response confirms which guesses were once valid.
    let admin = as_admin(&w).await;
    let email = format!("gone-{}@example.test", ActorId::new().into_uuid().simple());
    let invited = json(
        app(&w.store)
            .oneshot(admin.with_body(
                "POST",
                "/api/v1/users",
                None,
                &serde_json::json!({ "email": email, "display_name": "Gone" }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let real = invited["link_token"].as_str().unwrap().to_owned();
    sqlx::query(
        "UPDATE user_invitation
            SET created_at = now() - interval '30 days', expires_at = now() - interval '1 day'
          WHERE id = $1",
    )
    .bind(
        invited["invitation"]
            .as_str()
            .unwrap()
            .parse::<uuid::Uuid>()
            .unwrap(),
    )
    .execute(w.store.pool())
    .await
    .expect("age it");

    let response = app(&w.store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/invitations/{real}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "password": "a long enough password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let expired = json(response).await["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();

    assert_eq!(
        nonsense, expired,
        "an expired invitation and one that never existed must read identically"
    );
}

#[tokio::test]
async fn a_short_password_is_refused_before_the_token_is_spent() {
    let w = World::new("shortpw").await;
    let admin = as_admin(&w).await;
    let email = format!("short-{}@example.test", ActorId::new().into_uuid().simple());

    let invited = json(
        app(&w.store)
            .oneshot(admin.with_body(
                "POST",
                "/api/v1/users",
                None,
                &serde_json::json!({ "email": email, "display_name": "Short" }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let token = invited["link_token"].as_str().unwrap().to_owned();

    let response = app(&w.store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/invitations/{token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "password": "short" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // And the link still works, which is the part worth asserting: refusing the password
    // must not consume the invitation.
    let response = app(&w.store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/invitations/{token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "password": "a password of sufficient length" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_withdrawn_invitation_stops_working() {
    let w = World::new("withdraw").await;
    let admin = as_admin(&w).await;
    let email = format!("wrong-{}@example.test", ActorId::new().into_uuid().simple());

    let invited = json(
        app(&w.store)
            .oneshot(admin.with_body(
                "POST",
                "/api/v1/users",
                None,
                &serde_json::json!({ "email": email, "display_name": "Mistyped" }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let token = invited["link_token"].as_str().unwrap().to_owned();
    let id = invited["invitation"].as_str().unwrap().to_owned();

    let response = app(&w.store)
        .oneshot(admin.request(
            "DELETE",
            &format!("/api/v1/users/invitations/{id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app(&w.store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/invitations/{token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "password": "a password of sufficient length" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a mistyped address is withdrawn, and no account was ever created to tombstone"
    );
}

// ---- suspension -------------------------------------------------------------------

#[tokio::test]
async fn disabling_an_account_stops_a_session_that_was_working() {
    let w = World::new("stops").await;
    let admin = as_admin(&w).await;
    let (leaver, leaver_email) = w.second_admin().await;

    let (session, csrf) = sign_in(&w.store, &leaver_email, ADMIN_PASSWORD)
        .await
        .expect("the leaver signs in");
    let theirs = Session { session, csrf };

    // Working before.
    let response = app(&w.store)
        .oneshot(theirs.request("GET", "/api/v1/me", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app(&w.store)
        .oneshot(admin.request(
            "POST",
            &format!("/api/v1/users/{leaver}/disable"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Refused after, in the same process, with no waiting.
    let response = app(&w.store)
        .oneshot(theirs.request("GET", "/api/v1/me", None))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a departing employee's open tab must stop working now, not in twelve hours"
    );
}

#[tokio::test]
async fn an_administrator_cannot_disable_themselves() {
    let w = World::new("self").await;
    let admin = as_admin(&w).await;
    w.second_admin().await; // so the refusal is about self, not about the last admin

    let response = app(&w.store)
        .oneshot(admin.request(
            "POST",
            &format!("/api/v1/users/{}/disable", w.admin),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_last_administrator_is_refused_with_a_conflict() {
    let w = World::new("lastadmin").await;
    let admin = as_admin(&w).await;

    // The admin is the only one, so demoting them is refused — and it is a 409 rather than a
    // 400, because nothing about the request was wrong.
    let response = app(&w.store)
        .oneshot(admin.with_body(
            "PUT",
            &format!("/api/v1/users/{}/role", w.admin),
            Some(w.tenant),
            &serde_json::json!({ "role": "viewer" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let response = app(&w.store)
        .oneshot(admin.request(
            "DELETE",
            &format!("/api/v1/users/{}/role", w.admin),
            Some(w.tenant),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    assert_eq!(
        w.store.role_for(w.admin, w.tenant).await.unwrap(),
        Some(Role::Admin),
        "and the refusal did not half-apply"
    );
}

#[tokio::test]
async fn a_suspension_is_lifted_and_they_sign_in_again() {
    let w = World::new("lift").await;
    let admin = as_admin(&w).await;
    let (person, email) = w.second_admin().await;

    app(&w.store)
        .oneshot(admin.request(
            "POST",
            &format!("/api/v1/users/{person}/disable"),
            None,
        ))
        .await
        .unwrap();
    assert!(
        sign_in(&w.store, &email, ADMIN_PASSWORD).await.is_none(),
        "a disabled account does not authenticate"
    );

    let response = app(&w.store)
        .oneshot(admin.request("POST", &format!("/api/v1/users/{person}/enable"), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert!(
        sign_in(&w.store, &email, ADMIN_PASSWORD).await.is_some(),
        "an irreversible suspension forces a second account for one person — §4.4"
    );
}

// ---- one's own password -----------------------------------------------------------

#[tokio::test]
async fn changing_ones_own_password_needs_the_current_one() {
    let w = World::new("ownpw").await;
    let admin = as_admin(&w).await;

    let response = app(&w.store)
        .oneshot(admin.with_body(
            "PUT",
            "/api/v1/me/password",
            None,
            &serde_json::json!({ "current": "not the right one", "new": "a long enough one" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a session cookie is not evidence of knowing the secret being replaced"
    );

    let response = app(&w.store)
        .oneshot(admin.with_body(
            "PUT",
            "/api/v1/me/password",
            None,
            &serde_json::json!({
                "current": ADMIN_PASSWORD,
                "new": "a replacement of sufficient length",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert!(
        sign_in(&w.store, &w.admin_email, "a replacement of sufficient length")
            .await
            .is_some()
    );
    assert!(
        sign_in(&w.store, &w.admin_email, ADMIN_PASSWORD)
            .await
            .is_none(),
        "and the old one is gone"
    );
}

#[tokio::test]
async fn changing_a_password_keeps_the_session_that_did_it_and_ends_the_others() {
    let w = World::new("keepsession").await;
    let admin = as_admin(&w).await;

    // A second tab, signed in before the change.
    let (session, csrf) = sign_in(&w.store, &w.admin_email, ADMIN_PASSWORD)
        .await
        .expect("a second session");
    let other_tab = Session { session, csrf };

    let response = app(&w.store)
        .oneshot(admin.with_body(
            "PUT",
            "/api/v1/me/password",
            None,
            &serde_json::json!({
                "current": ADMIN_PASSWORD,
                "new": "a replacement of sufficient length",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app(&w.store)
        .oneshot(admin.request("GET", "/api/v1/me", None))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "being signed out of the tab you are typing in reads as a bug"
    );

    let response = app(&w.store)
        .oneshot(other_tab.request("GET", "/api/v1/me", None))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "somebody changing a password usually believes the old one leaked"
    );
}

// ---- authorisation ----------------------------------------------------------------

#[tokio::test]
async fn an_operator_cannot_reach_the_user_administration_routes() {
    let w = World::new("operator").await;

    let email = format!("op-{}@example.test", ActorId::new().into_uuid().simple());
    let hash = password::hash(&Secret::new(ADMIN_PASSWORD.to_owned())).expect("hash");
    let operator = w
        .store
        .create_user(w.org, &email, "An Operator", &hash)
        .await
        .expect("user");
    w.store
        .grant_role(operator, w.tenant, Role::Operator, None)
        .await
        .expect("role");

    let (session, csrf) = sign_in(&w.store, &email, ADMIN_PASSWORD)
        .await
        .expect("sign in");
    let theirs = Session { session, csrf };

    // `OrgAdmin` requires admin on every tenant, so an operator is refused with a 403 that
    // says what is required rather than a 404 that pretends the route is secret.
    for uri in [
        "/api/v1/users",
        "/api/v1/users/invitations",
    ] {
        let response = app(&w.store)
            .oneshot(theirs.request("GET", uri, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }

    // The role routes are tenant-scoped and need admin on the tenant in the header.
    let response = app(&w.store)
        .oneshot(theirs.request("GET", "/api/v1/tenants/roles", Some(w.tenant)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // But changing their own password needs no role at all.
    let response = app(&w.store)
        .oneshot(theirs.with_body(
            "PUT",
            "/api/v1/me/password",
            None,
            &serde_json::json!({
                "current": ADMIN_PASSWORD,
                "new": "a replacement of sufficient length",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
