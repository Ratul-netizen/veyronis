//! Booting an empty installation and logging into it over a real socket.
//!
//! Every layer below this has its own tests. What none of them can assert is the thing
//! an operator actually does on day one: read a password off a terminal and type it into
//! a login form. A first run that creates an account nobody can authenticate as passes
//! every structural check in `uops-store-pg` and leaves an installation nobody can enter.
//!
//! So this test does the whole sequence — migrate, bootstrap, serve on a real port, and
//! `POST /api/v1/auth/login` with the generated credential. It does not go through
//! `main.rs`, which is process-shaped and would want a subprocess to test; it goes
//! through the same functions in the same order.
//!
//! It builds its router with `uops_server::application`, which is what `main.rs` calls.
//! That used to be `router(state)` here and three lines there, and the difference was
//! invisible until the security headers needed testing: a layer added in `main` would
//! have been covered by nothing. Sharing the assembly is what makes
//! `every_response_carries_the_security_headers` below a statement about the product
//! rather than about this file.
//!
//! Like the bootstrap tests in `uops-store-pg`, each case gets a database of its own:
//! "is this installation empty" is a property of the whole installation, and the shared
//! test database is one where the answer is always no.

use uops_api::AppState;
use uops_core::OrgId;
use uops_server::config::FirstRunNames;
use uops_server::firstrun;
use uops_store_ch::{ChClient, ChConfig, ChStore};
use uops_store_pg::{Config as PgConfig, PgStore};

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into())
}

fn names() -> FirstRunNames {
    FirstRunNames {
        org: "Acme".into(),
        tenant: "Production".into(),
        tenant_slug: "production".into(),
        admin_email: "admin@example.invalid".into(),
        admin_name: "Administrator".into(),
    }
}

struct Scratch {
    store: PgStore,
    name: String,
}

impl Scratch {
    async fn new() -> Self {
        let admin = PgStore::connect(&PgConfig {
            url: admin_url(),
            ..PgConfig::default()
        })
        .await
        .expect("connect to admin database");

        let name = format!("uops_boot_{}", OrgId::new().into_uuid().simple());
        // An identifier, which cannot be a bind parameter. A literal prefix and a uuid.
        sqlx::query(&format!(r#"CREATE DATABASE "{name}""#))
            .execute(admin.pool())
            .await
            .expect("create scratch database");

        let base = admin_url()
            .rsplit_once('/')
            .expect("database url has a path")
            .0
            .to_owned();
        let store = PgStore::connect(&PgConfig {
            url: format!("{base}/{name}"),
            ..PgConfig::default()
        })
        .await
        .expect("connect to scratch database");

        sqlx::migrate!("../../migrations")
            .run(store.pool())
            .await
            .expect("migrate scratch database");

        Self { store, name }
    }

    async fn drop_database(self) {
        let Self { store, name } = self;
        store.pool().close().await;
        let admin = PgStore::connect(&PgConfig {
            url: admin_url(),
            ..PgConfig::default()
        })
        .await
        .expect("connect to admin database");
        sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#))
            .execute(admin.pool())
            .await
            .expect("drop scratch database");
    }
}

fn telemetry() -> ChStore {
    ChStore::new(ChClient::new(ChConfig::from_env()))
}

/// Serve the router on an ephemeral port and return its address.
///
/// Port 0, so parallel tests cannot collide on a hard-coded one, and so nothing here
/// depends on a port being free on the machine it runs on.
async fn serve(state: AppState) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local address");
    // `application`, not `router`: the same assembly main.rs serves, so the security
    // headers are in front of this test rather than beside it. No web root — there is no
    // build in a test run, and `web::serve` is right to refuse a directory without one.
    let app = uops_server::application(state, None).expect("assemble the application");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

#[tokio::test]
async fn the_printed_password_logs_in() {
    let scratch = Scratch::new().await;
    let names = names();

    let password = firstrun::bootstrap(&scratch.store, &names)
        .await
        .expect("bootstrap")
        .expect("an empty installation must bootstrap");

    let addr = serve(AppState::new(scratch.store.clone(), telemetry())).await;

    // Exactly what the operator does: the address from the banner, the password from
    // the banner. `expose` is the test standing in for their keyboard.
    let body = serde_json::json!({
        "email": names.admin_email,
        "password": password.expose(),
    })
    .to_string();
    let response = post(&addr, "/api/v1/auth/login", &body).await;

    assert!(
        response.starts_with("HTTP/1.1 204"),
        "the generated password must be accepted:\n{response}"
    );
    assert!(
        response.contains("uops_session="),
        "a successful login must set a session cookie:\n{response}"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_wrong_password_is_refused_by_the_same_server() {
    let scratch = Scratch::new().await;
    let names = names();

    firstrun::bootstrap(&scratch.store, &names)
        .await
        .expect("bootstrap")
        .expect("first run");

    let addr = serve(AppState::new(scratch.store.clone(), telemetry())).await;

    // The negative control for the test above. Without it, a login handler that
    // accepted anything would pass `the_printed_password_logs_in` perfectly.
    let body = serde_json::json!({
        "email": names.admin_email,
        "password": "not-the-generated-password",
    })
    .to_string();
    let response = post(&addr, "/api/v1/auth/login", &body).await;

    assert!(
        response.starts_with("HTTP/1.1 401"),
        "a wrong password must be refused:\n{response}"
    );
    assert!(
        !response.contains("uops_session="),
        "a refused login must not set a session cookie:\n{response}"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_second_boot_announces_nothing() {
    let scratch = Scratch::new().await;
    let names = names();

    assert!(
        firstrun::bootstrap(&scratch.store, &names)
            .await
            .unwrap()
            .is_some(),
        "the first boot of an empty installation must produce a credential"
    );
    assert!(
        firstrun::bootstrap(&scratch.store, &names)
            .await
            .unwrap()
            .is_none(),
        "a second boot must produce no credential — announcing one that belongs to no \
         account is worse than announcing nothing, because someone will type it"
    );

    scratch.drop_database().await;
}

/// The security headers are on a real response, from the router the binary serves.
///
/// `docs/packaging.md` §6.2. The unit tests in `uops_server::headers` assert what the
/// policy *says*; nothing there can tell whether any response carries it, and a policy
/// that is only a constant is the failure this repository keeps finding — built, tested,
/// never called.
///
/// Asserted on a 401 deliberately. A rejected login is the response most likely to be
/// produced by a path that returns early, and an error response without a CSP is a page
/// an injected script would run on. Every response, not the happy one.
#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let scratch = Scratch::new().await;
    let names = names();

    firstrun::run(&scratch.store, &names)
        .await
        .expect("first run");

    let state = AppState::new(scratch.store.clone(), telemetry());
    let addr = serve(state).await;

    let response = post(
        &addr,
        "/api/v1/auth/login",
        r#"{"email":"nobody@example.invalid","password":"wrong"}"#,
    )
    .await;

    assert!(
        response.starts_with("HTTP/1.1 401"),
        "expected the refusal this test is inspecting the headers of, got: {response}"
    );

    // Header names are case-insensitive on the wire and hyper lowercases what it writes,
    // so the comparison is lowercased rather than trusting a spelling.
    let lower = response.to_lowercase();
    for header in [
        "content-security-policy:",
        "x-content-type-options: nosniff",
        "referrer-policy: no-referrer",
        "x-frame-options: deny",
    ] {
        assert!(
            lower.contains(header),
            "no `{header}`: the layer is not applied to what the binary serves: {response}"
        );
    }

    // And the directive that carries the promise, not merely the header's presence: a
    // policy of `default-src *` would satisfy the check above and forbid nothing.
    assert!(
        lower.contains("connect-src 'self'"),
        "the policy is present but does not restrict where the page may connect: {response}"
    );

    scratch.drop_database().await;
}

/// The web app's own page carries the policy too, not just the API.
///
/// This is the ordering claim `uops_server::application` is written around, and it is not
/// obvious enough to leave to reasoning: a layer applies to the fallback registered when it
/// is added, and `web::serve` replaces the fallback. Attach the headers first and the *page*
/// is the one response without a policy — which is the only response where a policy does
/// anything, because the page is what a browser executes script in.
///
/// Served from a directory made here rather than from `web/dist`, so the test does not
/// depend on anybody having run `npm run build`.
#[tokio::test]
async fn the_web_app_page_carries_the_policy_as_well() {
    let scratch = Scratch::new().await;

    let root = std::env::temp_dir().join(format!("uops-web-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("create a web root");
    std::fs::write(root.join("index.html"), "<!doctype html><title>x</title>")
        .expect("write index.html");

    let state = AppState::new(scratch.store.clone(), telemetry());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local address");
    let app = uops_server::application(state, Some(root.as_path())).expect("assemble");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // A deep link, so this goes through the SPA fallback rather than hitting a real file —
    // the path that `web::serve` exists for and the one a reload actually takes.
    let response = get(&addr, "/resources/some-id").await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the SPA fallback did not serve the page: {response}"
    );
    assert!(
        response.to_lowercase().contains("content-security-policy:"),
        "the page has no policy, so the layer was attached before the file service: {response}"
    );

    std::fs::remove_dir_all(&root).ok();
    scratch.drop_database().await;
}

/// A minimal HTTP/1.1 GET, returning the raw response.
async fn get(addr: &std::net::SocketAddr, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

/// A minimal HTTP/1.1 POST, returning the raw response.
///
/// Hand-rolled rather than pulling in a client: the point of this test is that the
/// server speaks HTTP on a socket, and a client library that shares a stack with the
/// server would be testing rather less than it appears to.
async fn post(addr: &std::net::SocketAddr, path: &str, body: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}
