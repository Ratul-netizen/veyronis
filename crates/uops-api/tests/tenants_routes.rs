//! Adding a customer, over HTTP — `docs/tenant-lifecycle.md`.
//!
//! The criterion these exist for is §7's first: *"an org-admin creates a second tenant and is
//! granted `admin` on it in the same transaction — asserted by `is_org_admin` still returning
//! true immediately afterwards."* Through the API, that means the administrator who creates a
//! tenant can still reach the routes that require organization-wide admin, which is the thing
//! that would have been destroyed by the first successful use of the feature.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt as _;
use uops_api::cookie::{CSRF_COOKIE, SESSION_COOKIE};
use uops_api::csrf::CSRF_HEADER;
use uops_api::state::AppState;
use uops_core::{ActorId, OrgId, Role, Secret, TenantId};
use uops_secrets::password;
use uops_store_pg::{Config, PgStore};

const PASSWORD: &str = "correct horse battery staple";

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

struct World {
    store: PgStore,
    org: OrgId,
    first: TenantId,
    admin: ActorId,
    email: String,
}

impl World {
    async fn new(slug: &str) -> Self {
        let store = store().await;
        let org = OrgId::new();
        sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
            .bind(org.into_uuid())
            .bind(format!("tr-{slug}-{}", org.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("organization");

        let first = TenantId::new();
        sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
            .bind(first.into_uuid())
            .bind(org.into_uuid())
            .bind(format!("tr-{slug}"))
            .bind(format!("{slug}-{}", first.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("tenant");

        let email = format!("admin-{}@example.test", first.into_uuid().simple());
        let hash = password::hash(&Secret::new(PASSWORD.to_owned())).expect("hash");
        let admin = store
            .create_user(org, &email, "The Administrator", &hash)
            .await
            .expect("user");
        store
            .grant_role(admin, first, Role::Admin, None)
            .await
            .expect("role");

        Self {
            store,
            org,
            first,
            admin,
            email,
        }
    }
}

struct Session {
    session: String,
    csrf: String,
}

impl Session {
    fn build(&self, method: &str, uri: &str, body: Option<serde_json::Value>) -> Request<Body> {
        let b = Request::builder()
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
        match body {
            Some(v) => b.body(Body::from(v.to_string())).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        }
    }
}

async fn sign_in(store: &PgStore, email: &str) -> Session {
    let response = app(store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": email, "password": PASSWORD }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "sign in");

    let set: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let value = |name: &str| {
        set.iter()
            .find_map(|c| {
                let (pair, _) = c.split_once("; ")?;
                let (found, v) = pair.split_once('=')?;
                (found == name).then(|| v.to_owned())
            })
            .expect("cookie")
    };
    Session {
        session: value(SESSION_COOKIE),
        csrf: value(CSRF_COOKIE),
    }
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn slug(label: &str) -> String {
    format!("{label}-{}", ActorId::new().into_uuid().simple())
}

// ---------------------------------------------------------------------------

/// **The criterion this feature is shaped around.** Creating a tenant raises the denominator
/// in `is_org_admin`; if the creator were not granted a role on the new tenant they would lose
/// organization-wide admin the instant it committed, and could never get it back, because
/// creating a tenant requires it.
#[tokio::test]
async fn creating_a_tenant_does_not_lock_the_creator_out_of_the_api() {
    let w = World::new("lockout").await;
    let admin = sign_in(&w.store, &w.email).await;

    let response = app(&w.store)
        .oneshot(admin.build(
            "POST",
            "/api/v1/tenants",
            Some(serde_json::json!({ "name": "Second Customer", "slug": slug("second") })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json(response).await;

    // The route that proves it: `GET /api/v1/tenants` needs admin on *every* tenant, so it
    // would 403 if the grant had not happened in the same transaction.
    let response = app(&w.store)
        .oneshot(admin.build("GET", "/api/v1/tenants", None))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the administrator who just created a tenant can still administer the organization"
    );

    let listed = json(response).await;
    assert_eq!(listed.as_array().map(Vec::len), Some(2), "{listed}");
    assert_eq!(created["members"].as_i64(), Some(1), "its creator");
}

#[tokio::test]
async fn a_new_tenant_appears_in_the_switcher_and_can_be_worked_in() {
    let w = World::new("switcher").await;
    let admin = sign_in(&w.store, &w.email).await;

    let created = json(
        app(&w.store)
            .oneshot(admin.build(
                "POST",
                "/api/v1/tenants",
                Some(serde_json::json!({ "name": "Workable", "slug": slug("workable") })),
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().expect("an id").to_owned();

    // `/me` is what the tenant switcher reads, and it lists only tenants the caller holds a
    // role on — so a tenant that did not grant one would be invisible even to its creator.
    let me = json(
        app(&w.store)
            .oneshot(admin.build("GET", "/api/v1/me", None))
            .await
            .unwrap(),
    )
    .await;
    let tenants = me["tenants"].as_array().expect("tenants");
    assert!(
        tenants
            .iter()
            .any(|t| t["tenant_id"].as_str() == Some(id.as_str())),
        "{me}"
    );

    // And a scoped route answers for it, which is the difference between a row and a tenant.
    let response = app(&w.store)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/resources")
                .header(
                    header::COOKIE,
                    format!(
                        "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                        admin.session, admin.csrf
                    ),
                )
                .header("x-uops-tenant", &id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_malformed_slug_is_explained_rather_than_rejected_by_a_constraint() {
    let w = World::new("badslug").await;
    let admin = sign_in(&w.store, &w.email).await;

    for bad in [
        "Has Capitals",
        "has spaces",
        "-leading",
        "double--hyphen",
        "a",
    ] {
        let response = app(&w.store)
            .oneshot(admin.build(
                "POST",
                "/api/v1/tenants",
                Some(serde_json::json!({ "name": "Bad", "slug": bad })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad:?}");

        let detail = json(response).await["detail"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            detail.contains("lowercase"),
            "somebody is told the rule rather than handed a regular expression: {detail}"
        );
    }
}

#[tokio::test]
async fn a_duplicate_slug_is_a_conflict_not_a_bad_request() {
    let w = World::new("dupe").await;
    let admin = sign_in(&w.store, &w.email).await;
    let taken = slug("taken");

    let response = app(&w.store)
        .oneshot(admin.build(
            "POST",
            "/api/v1/tenants",
            Some(serde_json::json!({ "name": "First", "slug": taken })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app(&w.store)
        .oneshot(admin.build(
            "POST",
            "/api/v1/tenants",
            Some(serde_json::json!({ "name": "Second", "slug": taken })),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "nothing about the input was wrong, so telling them to fix it would misdirect"
    );
}

#[tokio::test]
async fn the_last_tenant_cannot_be_retired() {
    let w = World::new("lasttenant").await;
    let admin = sign_in(&w.store, &w.email).await;

    let response = app(&w.store)
        .oneshot(admin.build("POST", &format!("/api/v1/tenants/{}/retire", w.first), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let detail = json(response).await["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(detail.contains("create another first"), "{detail}");
}

#[tokio::test]
async fn the_platform_tenant_cannot_be_retired_and_says_what_to_do() {
    let w = World::new("platform").await;
    w.store
        .nominate_platform_tenant(w.org, w.first)
        .await
        .expect("nominate");
    let admin = sign_in(&w.store, &w.email).await;

    app(&w.store)
        .oneshot(admin.build(
            "POST",
            "/api/v1/tenants",
            Some(serde_json::json!({ "name": "Spare", "slug": slug("spare") })),
        ))
        .await
        .unwrap();

    let response = app(&w.store)
        .oneshot(admin.build("POST", &format!("/api/v1/tenants/{}/retire", w.first), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let detail = json(response).await["detail"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        detail.contains("Nominate another"),
        "a sentence naming what to do first, not a foreign-key error: {detail}"
    );
}

#[tokio::test]
async fn retiring_removes_a_tenant_from_the_switcher_and_restoring_brings_it_back() {
    let w = World::new("cycle").await;
    let admin = sign_in(&w.store, &w.email).await;

    let created = json(
        app(&w.store)
            .oneshot(admin.build(
                "POST",
                "/api/v1/tenants",
                Some(serde_json::json!({ "name": "Leaving", "slug": slug("leaving") })),
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().expect("id").to_owned();

    let response = app(&w.store)
        .oneshot(admin.build("POST", &format!("/api/v1/tenants/{id}/retire"), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Still listed to an administrator — one who cannot see it cannot restore it — and marked.
    let listed = json(
        app(&w.store)
            .oneshot(admin.build("GET", "/api/v1/tenants", None))
            .await
            .unwrap(),
    )
    .await;
    let row = listed
        .as_array()
        .expect("rows")
        .iter()
        .find(|t| t["id"].as_str() == Some(id.as_str()))
        .expect("a retired tenant is still listed");
    assert!(row["retired_at"].is_string(), "{row}");

    let response = app(&w.store)
        .oneshot(admin.build("POST", &format!("/api/v1/tenants/{id}/restore"), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let listed = json(
        app(&w.store)
            .oneshot(admin.build("GET", "/api/v1/tenants", None))
            .await
            .unwrap(),
    )
    .await;
    let row = listed
        .as_array()
        .expect("rows")
        .iter()
        .find(|t| t["id"].as_str() == Some(id.as_str()))
        .expect("still there");
    assert!(row["retired_at"].is_null(), "{row}");
}

#[tokio::test]
async fn a_tenant_can_be_renamed() {
    let w = World::new("rename").await;
    let admin = sign_in(&w.store, &w.email).await;
    let fresh = slug("renamed");

    let response = app(&w.store)
        .oneshot(admin.build(
            "PATCH",
            &format!("/api/v1/tenants/{}", w.first),
            Some(serde_json::json!({ "name": "A Better Name", "slug": fresh })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let listed = json(
        app(&w.store)
            .oneshot(admin.build("GET", "/api/v1/tenants", None))
            .await
            .unwrap(),
    )
    .await;
    let row = listed
        .as_array()
        .expect("rows")
        .iter()
        .find(|t| t["id"].as_str() == Some(w.first.to_string().as_str()))
        .expect("still there");
    assert_eq!(row["name"].as_str(), Some("A Better Name"));
    assert_eq!(row["slug"].as_str(), Some(fresh.as_str()));
}

#[tokio::test]
async fn an_operator_cannot_create_a_tenant() {
    let w = World::new("operator").await;

    let email = format!("op-{}@example.test", ActorId::new().into_uuid().simple());
    let hash = password::hash(&Secret::new(PASSWORD.to_owned())).expect("hash");
    let operator = w
        .store
        .create_user(w.org, &email, "An Operator", &hash)
        .await
        .expect("user");
    w.store
        .grant_role(operator, w.first, Role::Operator, None)
        .await
        .expect("role");

    let theirs = sign_in(&w.store, &email).await;

    for (method, uri, body) in [
        ("GET", "/api/v1/tenants".to_owned(), None),
        (
            "POST",
            "/api/v1/tenants".to_owned(),
            Some(serde_json::json!({ "name": "Theirs", "slug": slug("theirs") })),
        ),
        ("POST", format!("/api/v1/tenants/{}/retire", w.first), None),
    ] {
        let response = app(&w.store)
            .oneshot(theirs.build(method, &uri, body))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} — a 403 that says what is required, not a 404 pretending the \
             route is secret"
        );
    }

    // And the administrator is unaffected, which is what makes the refusal about the role
    // rather than about the request.
    let admin = sign_in(&w.store, &w.email).await;
    let response = app(&w.store)
        .oneshot(admin.build("GET", "/api/v1/tenants", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = w.admin;
}
