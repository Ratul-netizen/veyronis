//! That the **production loop** settles incidents — M9 §2.1.
//!
//! # Why this test exists, and why the one beside it was not enough
//!
//! `uops-store-pg/tests/incidents.rs` already has
//! `resolving_every_alert_makes_an_incident_quiet_and_never_closed`, which passes and has
//! always passed. It tests `PgStore::quiet_settled_incidents` — the right behaviour of the
//! right function.
//!
//! And for a whole milestone nothing in production called it. The call sat in
//! `Engine::evaluate_tenant`, reached only from `Engine::cycle`, which the run loop does
//! not use — it dispatches one rule at a time through `evaluate_and_deliver`. So every
//! incident stayed `open` for ever, and the store test could not notice because it
//! supplied the call itself.
//!
//! This one runs `uops_alert::run` — the loop the binary runs — and asserts the incident
//! goes quiet without anybody calling the settle function by hand. It is the difference
//! between *is this function right* and *is this function reached*.
//!
//! # Its own database
//!
//! The loop takes the deployment-wide `Job::Alert` lease, so on a shared database it would
//! fight the running server and every other test. `uops-poller/tests/live.rs` established
//! this pattern for exactly that reason: a test of a whole-installation loop gets an
//! installation.

use std::time::Duration;

use chrono::Utc;
use uops_core::{OrgId, ResourceId, TenantId, TenantScope};
use uops_store_ch::{ChClient, ChConfig, ChStore};
use uops_store_pg::{Config as PgConfig, PgStore};

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into())
}

/// A migrated, empty database, and its name so the caller can drop it.
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
        .expect("connect to the admin database");

        // Interpolated rather than bound: `CREATE DATABASE` takes an identifier and
        // identifiers cannot be parameters. The name is a literal prefix and a UUID.
        let name = format!("uops_settle_{}", uuid::Uuid::now_v7().simple());
        sqlx::query(&format!(r#"CREATE DATABASE "{name}""#))
            .execute(admin.pool())
            .await
            .expect("create the scratch database");

        let base = admin_url()
            .rsplit_once('/')
            .expect("the database url has a path")
            .0
            .to_owned();
        let store = PgStore::connect(&PgConfig {
            url: format!("{base}/{name}"),
            ..PgConfig::default()
        })
        .await
        .expect("connect to the scratch database");

        sqlx::migrate!("../../migrations")
            .run(store.pool())
            .await
            .expect("migrate the scratch database");

        Self { store, name }
    }

    async fn discard(self) {
        let Self { store, name } = self;
        store.pool().close().await;
        let admin = PgStore::connect(&PgConfig {
            url: admin_url(),
            ..PgConfig::default()
        })
        .await
        .expect("connect to the admin database");
        sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#))
            .execute(admin.pool())
            .await
            .expect("drop the scratch database");
    }
}

/// A tenant with one resource, one rule, and one alert in the given state.
async fn seed(store: &PgStore, state: &str) -> (TenantScope, uuid::Uuid) {
    let org = OrgId::new();
    let tenant = TenantId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, 'settling')")
        .bind(org.into_uuid())
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, 'estate', 'estate')")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .execute(store.pool())
        .await
        .expect("tenant");

    let scope = TenantScope::system(tenant);
    let resource = ResourceId::new();
    sqlx::query(
        "INSERT INTO resource (id, tenant_id, kind, name, status)
         VALUES ($1, $2, 'device', 'core-sw-01', 'up')",
    )
    .bind(resource.into_uuid())
    .bind(tenant.into_uuid())
    .execute(store.pool())
    .await
    .expect("resource");

    let rule = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO alert_rule (id, tenant_id, name, kind, query, condition, severity, created_by)
         VALUES ($1, $2, 'a device stopped answering', 'threshold', '{}'::jsonb, '{}'::jsonb,
                 'warning', NULL)",
    )
    .bind(rule)
    .bind(tenant.into_uuid())
    .execute(store.pool())
    .await
    .expect("rule");

    let alert = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO alert_state
            (id, tenant_id, rule_id, resource_id, dedup_key, state, since, last_eval)
         VALUES ($1, $2, $3, $4, $5, $6, now(), now())",
    )
    .bind(alert)
    .bind(tenant.into_uuid())
    .bind(rule)
    .bind(resource.into_uuid())
    .bind(format!("{rule}:{resource}"))
    .bind(state)
    .execute(store.pool())
    .await
    .expect("alert");

    (scope, alert)
}

/// Run the real loop for long enough to reach its first settle, then stop it.
///
/// `since_reload` starts *at* `RELOAD` in the loop, so the per-tenant work happens on the
/// first tick rather than sixty seconds in — which is what makes this testable at all.
async fn run_briefly(store: &PgStore) {
    let ch = ChStore::new(ChClient::new(ChConfig {
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "uops".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "uops".into()),
        ..ChConfig::from_env()
    }));
    let engine = uops_alert::Engine::new(store.clone(), ch);
    uops_alert::run(engine, store.clone(), async {
        tokio::time::sleep(Duration::from_secs(6)).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_run_loop_settles_an_incident_whose_alerts_have_all_resolved() {
    let scratch = Scratch::new().await;
    let (scope, alert) = seed(&scratch.store, "ok").await;

    let incident = scratch
        .store
        .open_incident(
            &scope,
            alert,
            "warning",
            "core-sw-01 stopped answering",
            Utc::now(),
            None,
        )
        .await
        .expect("open an incident");

    // Nobody calls `quiet_settled_incidents` here. That is the entire point: the loop must
    // do it, and for a milestone it did not.
    run_briefly(&scratch.store).await;

    let rows = scratch
        .store
        .incidents(&scope, 10)
        .await
        .expect("read back");
    let found = rows
        .iter()
        .find(|r| r.id == incident)
        .expect("the incident is still there");
    assert_eq!(
        found.state, "quiet",
        "the run loop must settle an incident whose alerts have resolved; it was {:?}",
        found.state
    );
    assert!(
        found.quiet_at.is_some(),
        "going quiet records when, because an incident that is quiet with no time is a \
         state nothing can be reasoned about"
    );
    assert!(
        found.closed_at.is_none(),
        "M9 §2.1: a machine never closes an incident — closing is a claim that it is \
         understood, and only a person is in a position to make one"
    );

    scratch.discard().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_incident_with_an_alert_still_firing_is_left_open() {
    // The other half. A settle that fired on everything would close incidents that are
    // still happening, which is worse than never settling at all.
    let scratch = Scratch::new().await;
    let (scope, alert) = seed(&scratch.store, "firing").await;

    let incident = scratch
        .store
        .open_incident(&scope, alert, "critical", "still down", Utc::now(), None)
        .await
        .expect("open an incident");

    run_briefly(&scratch.store).await;

    let rows = scratch
        .store
        .incidents(&scope, 10)
        .await
        .expect("read back");
    let found = rows.iter().find(|r| r.id == incident).expect("present");
    assert_eq!(found.state, "open", "an alert is still firing");
    assert!(found.quiet_at.is_none());

    scratch.discard().await;
}
