//! M12 §2.2 acceptance: *a user authenticates through an OIDC provider and is
//! provisioned with the role their mapped claim grants*, and *an organization that
//! requires SSO refuses password login for everyone except a break-glass account, and
//! that account's use is an audit event.*
//!
//! # Against a real signature, not a stub
//!
//! The identity provider here is scripted, but the cryptography is not: the test holds a
//! P-256 key, signs the ID token with it, and publishes the matching public key in a
//! JWKS the server fetches. A stub that returned "verified" would test the plumbing and
//! skip the part that decides whether a forged token is accepted — which is the part
//! worth testing, and the part every published OIDC vulnerability has been in.
//!
//! So every negative case below is a *correctly signed* token that fails for exactly one
//! other reason: the wrong audience, a nonce from another sign-in, an expired claim. A
//! token that failed for two reasons would prove nothing about either.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use p256::ecdsa::signature::Signer as _;
use tower::ServiceExt as _;
use uops_api::{AppState, SESSION_COOKIE};
use uops_core::{OrgId, Role, Secret, TenantId};
use uops_oidc::b64;
use uops_oidc::fetch::Fetch;
use uops_secrets::password;
use uops_store_pg::{Config, PgStore};

const ISSUER: &str = "https://idp.test.invalid";
const CLIENT_ID: &str = "uops-test";
const KID: &str = "test-key-1";

// ---------------------------------------------------------------------------
// A scripted identity provider that actually signs
// ---------------------------------------------------------------------------

struct Idp {
    signing: p256::ecdsa::SigningKey,
    /// What the next token exchange hands back. Set per test.
    id_token: std::sync::Mutex<String>,
    /// What the client sent to the token endpoint, so PKCE can be asserted.
    last_form: std::sync::Mutex<Vec<(String, String)>>,
}

impl std::fmt::Debug for Idp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Idp").finish_non_exhaustive()
    }
}

impl Idp {
    fn new() -> Self {
        // A fixed key rather than a random one, so a failure is reproducible. It is a
        // test key in a test file and protects nothing.
        let bytes = [7u8; 32];
        Self {
            signing: p256::ecdsa::SigningKey::from_bytes(&bytes.into()).expect("a valid scalar"),
            id_token: std::sync::Mutex::new(String::new()),
            last_form: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn jwks(&self) -> String {
        let point = self.signing.verifying_key().to_encoded_point(false);
        format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{KID}","alg":"ES256","use":"sig","x":"{}","y":"{}"}}]}}"#,
            b64::encode(point.x().expect("an uncompressed point has x")),
            b64::encode(point.y().expect("an uncompressed point has y")),
        )
    }

    /// Sign a set of claims into a compact JWS.
    fn mint(&self, claims: &str) -> String {
        let header =
            b64::encode(format!(r#"{{"alg":"ES256","kid":"{KID}","typ":"JWT"}}"#).as_bytes());
        let payload = b64::encode(claims.as_bytes());
        let signed = format!("{header}.{payload}");
        let signature: p256::ecdsa::Signature = self.signing.sign(signed.as_bytes());
        format!("{signed}.{}", b64::encode(&signature.to_bytes()))
    }

    fn serve(&self, token: String) {
        *self.id_token.lock().unwrap() = token;
    }
}

impl Fetch for Idp {
    fn get(&self, url: &str) -> uops_oidc::Result<String> {
        if url.ends_with("/.well-known/openid-configuration") {
            return Ok(format!(
                r#"{{"issuer":"{ISSUER}",
                     "authorization_endpoint":"{ISSUER}/authorize",
                     "token_endpoint":"{ISSUER}/token",
                     "jwks_uri":"{ISSUER}/keys"}}"#
            ));
        }
        if url.ends_with("/keys") {
            return Ok(self.jwks());
        }
        Err(uops_oidc::Error::Transport(format!("no route for {url}")))
    }

    fn post_form(
        &self,
        _url: &str,
        form: &[(&str, &str)],
        _basic: Option<(&str, &str)>,
    ) -> uops_oidc::Result<String> {
        *self.last_form.lock().unwrap() = form
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let token = self.id_token.lock().unwrap().clone();
        Ok(format!(r#"{{"id_token":"{token}","token_type":"Bearer"}}"#))
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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

/// An organization with one tenant, and a provider configured against the scripted
/// identity provider.
struct Fixture {
    app: Router,
    store: PgStore,
    org: OrgId,
    tenant: TenantId,
    provider: uuid::Uuid,
    idp: std::sync::Arc<Idp>,
}

async fn fixture() -> Fixture {
    let store = store().await;
    let suffix = uuid::Uuid::now_v7();

    let org = new_org(&store, &format!("SSO Test {suffix}")).await;
    let tenant = new_tenant(&store, org, "SSO Tenant", &format!("sso-{suffix}")).await;

    // A public client: no secret, PKCE alone. That keeps this test independent of
    // whether a KEK is configured, and it is a configuration a real deployment uses.
    let provider = store
        .create_provider(org, "Test SSO", ISSUER, CLIENT_ID, "groups", None)
        .await
        .expect("provider");

    store
        .grant_group(org, provider, "noc", tenant, Role::Operator, None)
        .await
        .expect("grant");

    let idp = std::sync::Arc::new(Idp::new());
    let state = AppState::new(store.clone(), telemetry())
        .allowing_insecure_cookies()
        .with_public_url("https://uops.test.invalid")
        .with_sso(uops_api::sso::Sso::new().with_http(Box::new(SharedIdp(idp.clone()))));

    Fixture {
        app: uops_api::router(state),
        store,
        org,
        tenant,
        provider,
        idp,
    }
}

/// An organization. Inserted directly: it is a fixture rather than anything the API is
/// responsible for creating, which is the same call `isolation.rs` makes.
async fn new_org(store: &PgStore, name: &str) -> OrgId {
    let org = OrgId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(name)
        .execute(store.pool())
        .await
        .expect("organization");
    org
}

async fn new_tenant(store: &PgStore, org: OrgId, name: &str, slug: &str) -> TenantId {
    let tenant = TenantId::new();
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(name)
        .bind(slug)
        .execute(store.pool())
        .await
        .expect("tenant");
    tenant
}

/// The `Fetch` the state holds, forwarding to the `Arc` the test also keeps.
#[derive(Debug)]
struct SharedIdp(std::sync::Arc<Idp>);

impl Fetch for SharedIdp {
    fn get(&self, url: &str) -> uops_oidc::Result<String> {
        self.0.get(url)
    }
    fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> uops_oidc::Result<String> {
        self.0.post_form(url, form, basic)
    }
}

/// What the `start` endpoint put in the browser: the cookie, and the values inside it.
struct Started {
    cookie: String,
    state: String,
    nonce: String,
    verifier: String,
}

async fn start(fixture: &Fixture) -> Started {
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/auth/oidc/{}/start?return_to=%2Fincidents",
                    fixture.provider
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("start");

    assert_eq!(response.status(), StatusCode::SEE_OTHER, "start redirects");
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("a redirect has a location")
        .to_owned();
    assert!(
        location.starts_with(&format!("{ISSUER}/authorize?")),
        "{location}"
    );
    assert!(
        location.contains("code_challenge_method=S256"),
        "{location}"
    );

    let set = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("uops_oidc="))
        .expect("the sign-in cookie")
        .to_owned();
    let value = set
        .split(';')
        .next()
        .and_then(|p| p.split_once('='))
        .map(|(_, v)| v.to_owned())
        .expect("a cookie value");

    let json: serde_json::Value =
        serde_json::from_slice(&b64::decode(&value).expect("base64url")).expect("json");

    // The verifier must not have travelled. Only its hash did.
    let verifier = json["v"].as_str().expect("verifier").to_owned();
    assert!(
        !location.contains(&verifier),
        "the verifier was sent to the provider"
    );

    Started {
        cookie: format!("uops_oidc={value}"),
        state: json["s"].as_str().expect("state").to_owned(),
        nonce: json["n"].as_str().expect("nonce").to_owned(),
        verifier,
    }
}

/// Claims that are entirely correct, before a test spoils exactly one of them.
fn claims(nonce: &str, groups: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    format!(
        r#"{{"iss":"{ISSUER}","sub":"00u-alice","aud":"{CLIENT_ID}","nonce":"{nonce}",
             "exp":{},"iat":{},"email":"alice@test.invalid","email_verified":true,
             "name":"Alice","groups":{groups}}}"#,
        now + 300,
        now - 5,
    )
}

async fn callback(fixture: &Fixture, cookie: &str, state: &str) -> axum::response::Response {
    fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/auth/oidc/callback?code=the-code&state={state}"
                ))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("callback")
}

// ---------------------------------------------------------------------------
// The acceptance criterion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_user_signs_in_and_is_provisioned_with_the_role_their_group_grants() {
    let f = fixture().await;
    let started = start(&f).await;
    f.idp
        .serve(f.idp.mint(&claims(&started.nonce, r#"["noc"]"#)));

    let response = callback(&f, &started.cookie, &started.state).await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a sign-in redirects"
    );
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/incidents"),
        "the browser goes where it was going before it was sent to sign in"
    );

    let cookies: Vec<&str> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with(SESSION_COOKIE)),
        "a session was issued: {cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("uops_oidc=;") || c.contains("uops_oidc=; ")),
        "the sign-in cookie is consumed: {cookies:?}"
    );

    // The account, and the role the mapping granted — which is the criterion.
    let memberships = {
        let user = f
            .store
            .user_credentials(f.org, "alice@test.invalid")
            .await
            .expect("query")
            .expect("the account was provisioned");
        assert!(
            user.password_hash.is_none(),
            "an account provisioned through SSO has no password"
        );
        f.store
            .tenant_memberships(user.user_id)
            .await
            .expect("roles")
    };
    assert_eq!(memberships.len(), 1);
    assert_eq!(memberships[0].tenant_id, f.tenant);
    assert_eq!(memberships[0].role, Role::Operator);

    // PKCE: the verifier the browser never saw travelled to the token endpoint, and it
    // is the one the challenge was built from.
    let form = f.idp.last_form.lock().unwrap().clone();
    let sent: std::collections::HashMap<&str, &str> =
        form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    assert_eq!(sent.get("code_verifier"), Some(&started.verifier.as_str()));
    assert_eq!(sent.get("grant_type"), Some(&"authorization_code"));
    assert_eq!(
        sent.get("redirect_uri"),
        Some(&"https://uops.test.invalid/api/v1/auth/oidc/callback"),
        "the redirect URI is the configured one, not one derived from the request"
    );
}

#[tokio::test]
async fn signing_in_again_reconciles_the_roles_rather_than_adding_to_them() {
    // The provider is authoritative for an account it owns. A user removed from a group
    // there must lose the role here — otherwise the only way to take access away is to
    // find it in this product too, which is the second access list SSO exists to avoid.
    let f = fixture().await;

    let first = start(&f).await;
    f.idp.serve(f.idp.mint(&claims(&first.nonce, r#"["noc"]"#)));
    assert_eq!(
        callback(&f, &first.cookie, &first.state).await.status(),
        StatusCode::SEE_OTHER
    );

    let user = f
        .store
        .user_credentials(f.org, "alice@test.invalid")
        .await
        .unwrap()
        .unwrap()
        .user_id;
    assert_eq!(f.store.tenant_memberships(user).await.unwrap().len(), 1);

    // A second tenant and a second group, granted and then taken away at the provider.
    let other = new_tenant(
        &f.store,
        f.org,
        "Second",
        &format!("second-{}", uuid::Uuid::now_v7()),
    )
    .await;
    f.store
        .grant_group(f.org, f.provider, "sec", other, Role::Viewer, None)
        .await
        .unwrap();

    let second = start(&f).await;
    f.idp
        .serve(f.idp.mint(&claims(&second.nonce, r#"["noc","sec"]"#)));
    assert_eq!(
        callback(&f, &second.cookie, &second.state).await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(f.store.tenant_memberships(user).await.unwrap().len(), 2);

    let third = start(&f).await;
    f.idp.serve(f.idp.mint(&claims(&third.nonce, r#"["sec"]"#)));
    assert_eq!(
        callback(&f, &third.cookie, &third.state).await.status(),
        StatusCode::SEE_OTHER
    );
    let after = f.store.tenant_memberships(user).await.unwrap();
    assert_eq!(after.len(), 1, "the removed group's role is gone");
    assert_eq!(after[0].tenant_id, other);
}

#[tokio::test]
async fn a_user_whose_groups_map_to_nothing_gets_no_account() {
    // Authentication succeeded and authorisation did not, and those are different
    // answers. A default role here would mean that every employee of a 2 000-person
    // company can read a customer's network the day SSO is switched on.
    let f = fixture().await;
    let started = start(&f).await;
    f.idp
        .serve(f.idp.mint(&claims(&started.nonce, r#"["everyone"]"#)));

    let response = callback(&f, &started.cookie, &started.state).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    assert!(
        f.store
            .user_credentials(f.org, "alice@test.invalid")
            .await
            .unwrap()
            .is_none(),
        "no account was created"
    );

    // And the refusal is on the record, because a burst of these is what a security team
    // wants to see and a single one is what an administrator debugging a rollout needs.
    let audit = f.store.org_audit_entries(f.org, 50).await.unwrap();
    assert!(
        audit.iter().any(|e| e.action == "sso.refused"),
        "the refusal was audited: {audit:?}"
    );
}

// ---------------------------------------------------------------------------
// Correctly signed tokens that must still be refused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_token_minted_for_another_application_is_refused() {
    // The check people leave out. Every application behind one Entra ID tenant is signed
    // by the same key, so without it a token for the cafeteria booking system is a valid
    // login here — correctly signed, from the right issuer, and for somebody else.
    let f = fixture().await;
    let started = start(&f).await;
    let claims = claims(&started.nonce, r#"["noc"]"#).replace(CLIENT_ID, "cafeteria");
    f.idp.serve(f.idp.mint(&claims));

    assert_eq!(
        callback(&f, &started.cookie, &started.state).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_token_from_another_sign_in_is_refused() {
    // Replay. The token is valid, signed, unexpired and for this application — it simply
    // belongs to a different sign-in, which is what `nonce` is for.
    let f = fixture().await;
    let a = start(&f).await;
    let b = start(&f).await;

    f.idp.serve(f.idp.mint(&claims(&b.nonce, r#"["noc"]"#)));
    assert_eq!(
        callback(&f, &a.cookie, &a.state).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_callback_this_browser_did_not_start_is_refused() {
    // Login CSRF: an attacker completes a sign-in *as themselves* in the victim's
    // browser, and everything the victim then does happens in the attacker's account.
    let f = fixture().await;
    let victim = start(&f).await;
    let attacker = start(&f).await;

    f.idp
        .serve(f.idp.mint(&claims(&attacker.nonce, r#"["noc"]"#)));
    assert_eq!(
        callback(&f, &victim.cookie, &attacker.state).await.status(),
        StatusCode::UNAUTHORIZED,
        "the state in the URL must match the state in this browser's cookie"
    );
}

#[tokio::test]
async fn a_callback_with_no_sign_in_in_progress_is_refused() {
    let f = fixture().await;
    let started = start(&f).await;
    f.idp
        .serve(f.idp.mint(&claims(&started.nonce, r#"["noc"]"#)));

    assert_eq!(
        callback(&f, "theme=dark", &started.state).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let f = fixture().await;
    let started = start(&f).await;
    let long_ago = chrono::Utc::now().timestamp() - 86_400;
    let stale = format!(
        r#"{{"iss":"{ISSUER}","sub":"00u-alice","aud":"{CLIENT_ID}","nonce":"{}",
             "exp":{},"iat":{},"email":"alice@test.invalid","groups":["noc"]}}"#,
        started.nonce,
        long_ago + 300,
        long_ago,
    );
    f.idp.serve(f.idp.mint(&stale));

    assert_eq!(
        callback(&f, &started.cookie, &started.state).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_unsigned_token_is_refused() {
    // `alg: none` — a header telling the verifier not to check. It must fail even though
    // every claim in it is otherwise perfect.
    let f = fixture().await;
    let started = start(&f).await;
    let header = b64::encode(br#"{"alg":"none"}"#);
    let payload = b64::encode(claims(&started.nonce, r#"["noc"]"#).as_bytes());
    f.idp.serve(format!("{header}.{payload}."));

    assert_eq!(
        callback(&f, &started.cookie, &started.state).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_token_signed_by_the_wrong_key_is_refused() {
    let f = fixture().await;
    let started = start(&f).await;

    let impostor = p256::ecdsa::SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
    let header = b64::encode(format!(r#"{{"alg":"ES256","kid":"{KID}"}}"#).as_bytes());
    let payload = b64::encode(claims(&started.nonce, r#"["noc"]"#).as_bytes());
    let signed = format!("{header}.{payload}");
    let signature: p256::ecdsa::Signature = impostor.sign(signed.as_bytes());
    f.idp
        .serve(format!("{signed}.{}", b64::encode(&signature.to_bytes())));

    assert_eq!(
        callback(&f, &started.cookie, &started.state).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_disabled_provider_cannot_be_used() {
    let f = fixture().await;
    f.store
        .set_provider_enabled(f.org, f.provider, false)
        .await
        .unwrap();

    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/auth/oidc/{}/start", f.provider))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a 404 rather than 'disabled' — which of a company's providers are switched off \
         is not something an unauthenticated caller should learn"
    );
}

// ---------------------------------------------------------------------------
// Requiring SSO, and the one account that may still use a password
// ---------------------------------------------------------------------------

async fn password_login(f: &Fixture, email: &str, password: &str) -> StatusCode {
    f.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"email":"{email}","password":"{password}"}}"#
                )))
                .unwrap(),
        )
        .await
        .expect("login")
        .status()
}

#[tokio::test]
async fn requiring_sso_leaves_exactly_one_password_account_and_audits_its_use() {
    let f = fixture().await;
    let suffix = uuid::Uuid::now_v7();

    let ordinary_email = format!("ordinary-{suffix}@test.invalid");
    let glass_email = format!("glass-{suffix}@test.invalid");
    let hash = password::hash(&Secret::new("correct horse battery".to_owned())).unwrap();

    let ordinary = f
        .store
        .create_user(f.org, &ordinary_email, "Ordinary", &hash)
        .await
        .unwrap();
    f.store
        .grant_role(ordinary, f.tenant, Role::Viewer, None)
        .await
        .unwrap();

    let glass = f
        .store
        .create_user(f.org, &glass_email, "Break glass", &hash)
        .await
        .unwrap();
    f.store.set_break_glass(glass, true).await.unwrap();

    // Before: both work, and neither is remarkable.
    assert_eq!(
        password_login(&f, &ordinary_email, "correct horse battery").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        password_login(&f, &glass_email, "correct horse battery").await,
        StatusCode::NO_CONTENT
    );
    assert!(
        !f.store
            .org_audit_entries(f.org, 50)
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "auth.break_glass"),
        "marking an account break-glass is preparation, not an event"
    );

    f.store.set_require_sso(f.org, true).await.unwrap();

    // After: the ordinary account cannot use its password, and the answer is the same
    // 401 a wrong password gets — not a 403 saying "this organization uses SSO", which
    // would confirm the address exists.
    assert_eq!(
        password_login(&f, &ordinary_email, "correct horse battery").await,
        StatusCode::UNAUTHORIZED
    );

    // The break-glass account still works, and its use is now on the record.
    assert_eq!(
        password_login(&f, &glass_email, "correct horse battery").await,
        StatusCode::NO_CONTENT
    );

    let audit = f.store.org_audit_entries(f.org, 50).await.unwrap();
    let entry = audit
        .iter()
        .find(|e| e.action == "auth.break_glass")
        .expect("the break-glass login was audited");
    assert_eq!(entry.target, glass_email);
    assert_eq!(entry.actor, format!("user:{glass}"));
}

#[tokio::test]
async fn requiring_sso_does_not_break_the_wrong_password_answer() {
    // The refusal is checked *after* the password, so that "this address uses SSO"
    // cannot be read off the response time. Asserted at the level this test can see:
    // both answers are the same status.
    let f = fixture().await;
    let email = format!("ordinary-{}@test.invalid", uuid::Uuid::now_v7());
    let hash = password::hash(&Secret::new("correct horse battery".to_owned())).unwrap();
    f.store
        .create_user(f.org, &email, "Ordinary", &hash)
        .await
        .unwrap();
    f.store.set_require_sso(f.org, true).await.unwrap();

    assert_eq!(
        password_login(&f, &email, "correct horse battery").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        password_login(&f, &email, "the wrong password").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        password_login(&f, "nobody@test.invalid", "anything").await,
        StatusCode::UNAUTHORIZED
    );
}

// ---------------------------------------------------------------------------
// One organization's configuration is not another's
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_admin_of_one_organization_cannot_see_anothers_provider() {
    // The isolation property these routes have, which the tenant-header harness in
    // isolation.rs cannot express: they are organization-scoped rather than
    // tenant-scoped.
    let f = fixture().await;
    let suffix = uuid::Uuid::now_v7();

    let other_org = new_org(&f.store, &format!("Somebody else {suffix}")).await;
    let other_tenant = new_tenant(&f.store, other_org, "Theirs", &format!("theirs-{suffix}")).await;
    let hash = password::hash(&Secret::new("correct horse battery".to_owned())).unwrap();
    let outsider = f
        .store
        .create_user(
            other_org,
            &format!("outsider-{suffix}@test.invalid"),
            "Out",
            &hash,
        )
        .await
        .unwrap();
    f.store
        .grant_role(outsider, other_tenant, Role::Admin, None)
        .await
        .unwrap();

    // They are an admin of their own organization — and `providers` for it is empty,
    // rather than listing ours.
    assert!(f.store.is_org_admin(outsider, other_org).await.unwrap());
    assert!(f.store.providers(other_org).await.unwrap().is_empty());

    // And our provider, named directly, is not theirs.
    assert!(
        f.store
            .provider(other_org, f.provider)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn an_admin_of_one_tenant_is_not_an_admin_of_the_organization() {
    // The privilege escalation this bar exists to close: an MSP gives a customer's own
    // staff the admin role on that customer's tenant, and a weaker rule would let one of
    // them configure the MSP's identity provider and map a group they belong to onto
    // every other customer.
    let f = fixture().await;
    let suffix = uuid::Uuid::now_v7();

    let second = new_tenant(
        &f.store,
        f.org,
        "Another customer",
        &format!("another-{suffix}"),
    )
    .await;

    let hash = password::hash(&Secret::new("correct horse battery".to_owned())).unwrap();
    let one_tenant_admin = f
        .store
        .create_user(
            f.org,
            &format!("local-{suffix}@test.invalid"),
            "Local",
            &hash,
        )
        .await
        .unwrap();
    f.store
        .grant_role(one_tenant_admin, second, Role::Admin, None)
        .await
        .unwrap();

    assert!(
        !f.store.is_org_admin(one_tenant_admin, f.org).await.unwrap(),
        "admin on one of two tenants is not admin of the organization"
    );

    // Give them the other one as well, and they are.
    f.store
        .grant_role(one_tenant_admin, f.tenant, Role::Admin, None)
        .await
        .unwrap();
    assert!(f.store.is_org_admin(one_tenant_admin, f.org).await.unwrap());

    // Demote one of the two, and they stop being.
    f.store
        .grant_role(one_tenant_admin, f.tenant, Role::Operator, None)
        .await
        .unwrap();
    assert!(!f.store.is_org_admin(one_tenant_admin, f.org).await.unwrap());
}

#[tokio::test]
async fn a_disabled_account_is_not_an_organization_admin() {
    // Checked here as well as at login, for the same reason `role_for` checks it: a live
    // session must stop working the moment the account does, and "disable the account"
    // is what somebody reaches for when they need that to be true right now.
    let f = fixture().await;
    let suffix = uuid::Uuid::now_v7();
    let hash = password::hash(&Secret::new("correct horse battery".to_owned())).unwrap();

    let admin = f
        .store
        .create_user(
            f.org,
            &format!("admin-{suffix}@test.invalid"),
            "Admin",
            &hash,
        )
        .await
        .unwrap();
    f.store
        .grant_role(admin, f.tenant, Role::Admin, None)
        .await
        .unwrap();
    assert!(f.store.is_org_admin(admin, f.org).await.unwrap());

    f.store.disable_user(admin).await.unwrap();
    assert!(!f.store.is_org_admin(admin, f.org).await.unwrap());
}
