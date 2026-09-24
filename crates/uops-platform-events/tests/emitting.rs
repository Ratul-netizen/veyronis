//! The write path, against real `PostgreSQL` and real `ClickHouse`.
//!
//! `seen.rs` decides *whether* something is news; this is the other half — that the event
//! actually lands on the nominated resource and can be read back.
//!
//! # Why this file exists rather than being assumed
//!
//! Both readers this path depends on were written with `AS "org: OrgId"` column aliases,
//! which instruct the `query!` macro and mean nothing in an unchecked `sqlx::query`. Every
//! lookup raised `ColumnNotFound`, the observer logged "could not read platform targets"
//! once per tick, and nothing was ever emitted. The failure was handled, reported, and
//! total — and it would have survived any amount of reading, because the code looks right.
//!
//! So the assertion that matters here is not "did not error". It is that a row came back.

use std::collections::BTreeMap;

use chrono::Utc;
use uops_core::{OrgId, TenantId};
use uops_platform_events::{PlatformEvent, attributes, emit_for_org, emit_to_all};
use uops_store_ch::{ChClient, ChConfig, ChStore};
use uops_store_pg::{Config, PgStore, PlatformTarget};

async fn stores() -> (PgStore, ChStore) {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into());
    let pg = PgStore::connect(&Config {
        url,
        ..Config::default()
    })
    .await
    .expect("connect to PostgreSQL");
    (pg, ChStore::new(ChClient::new(ch_config())))
}

fn ch_config() -> ChConfig {
    ChConfig {
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "uops".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "uops".into()),
        ..ChConfig::from_env()
    }
}

/// An organization with its own tenant and a nominated platform resource.
async fn nominated(pg: &PgStore, slug: &str) -> (OrgId, TenantId, PlatformTarget) {
    let org = OrgId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("emit-org-{slug}-{}", org.into_uuid().simple()))
        .execute(pg.pool())
        .await
        .expect("organization");

    let tenant = TenantId::new();
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("emit-{slug}"))
        .bind(format!("{slug}-{}", tenant.into_uuid().simple()))
        .execute(pg.pool())
        .await
        .expect("tenant");

    let target = pg
        .nominate_platform_tenant(org, tenant)
        .await
        .expect("nominate");
    (org, tenant, target)
}

/// An organization with a tenant and nothing nominated.
async fn unnominated(pg: &PgStore, slug: &str) -> OrgId {
    let org = OrgId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("emit-org-{slug}-{}", org.into_uuid().simple()))
        .execute(pg.pool())
        .await
        .expect("organization");
    org
}

/// `(event_type, severity, source_kind, summary)` for everything on one resource.
async fn events_on(target: &PlatformTarget) -> Vec<(String, String, String, String)> {
    let result = ChClient::new(ch_config())
        .run(
            "SELECT event_type, severity, source_kind, summary FROM events \
             WHERE resource_id = {resource:UUID} ORDER BY observed_at FORMAT TSV",
            &[("resource", target.resource_id.into_uuid().to_string())],
        )
        .await
        .expect("query ClickHouse");

    result
        .body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut cells = line.split('\t');
            let mut next = || cells.next().unwrap_or_default().to_owned();
            (next(), next(), next(), next())
        })
        .collect()
}

fn event(summary: &str) -> PlatformEvent<'static> {
    PlatformEvent {
        category: "process",
        event_type: "end",
        severity: "warn",
        summary: summary.to_owned(),
        attributes: attributes([("collector.name".to_owned(), "test".to_owned())]),
        occurred_at: Utc::now(),
    }
}

#[tokio::test]
async fn an_event_lands_on_the_nominated_resource() {
    let (pg, ch) = stores().await;
    let (org, _, target) = nominated(&pg, "lands").await;

    let emitted = emit_for_org(&pg, &ch, org, event("Collector stopped reporting: test"))
        .await
        .expect("emit");
    assert!(emitted, "the organization has a nominated resource");

    let events = events_on(&target).await;
    assert_eq!(events.len(), 1, "{events:?}");
    let (event_type, severity, source_kind, summary) = &events[0];
    assert_eq!(event_type, "end");
    assert_eq!(severity, "warn");
    // `docs/self-monitoring.md` §4: the product describing something it did itself, where
    // it is the authority — as distinct from a severity invented for a device's message,
    // which M11 §2.8 forbids.
    assert_eq!(source_kind, "self");
    assert_eq!(summary, "Collector stopped reporting: test");
}

#[tokio::test]
async fn an_organization_that_nominated_nothing_is_told_so_rather_than_failing() {
    let (pg, ch) = stores().await;
    let org = unnominated(&pg, "nowhere").await;

    assert!(
        !emit_for_org(&pg, &ch, org, event("no resource for this"))
            .await
            .expect("not an error — there is simply nowhere to put it"),
        "`false` is how the caller learns it was a no-op, and \
         `docs/self-monitoring.md` says those installations retain their existing behaviour"
    );
}

#[tokio::test]
async fn a_deployment_wide_event_reaches_a_nominated_organization() {
    let (pg, ch) = stores().await;
    let (_, _, target) = nominated(&pg, "everyone").await;

    // The lease-handover shape: one event per organization, built from the organization id.
    emit_to_all(&pg, &ch, |_| PlatformEvent {
        category: "process",
        event_type: "change",
        severity: "warn",
        summary: "poll lease changed hands".to_owned(),
        attributes: BTreeMap::new(),
        occurred_at: Utc::now(),
    })
    .await
    .expect("emit to all");

    let events = events_on(&target).await;
    assert!(
        events
            .iter()
            .any(|(kind, _, _, summary)| kind == "change" && summary == "poll lease changed hands"),
        "{events:?}"
    );
}

#[tokio::test]
async fn a_failed_run_resolves_from_its_tenant_to_its_own_resource() {
    let (pg, ch) = stores().await;
    let (org, _, mine) = nominated(&pg, "mine").await;
    let (_, _, theirs) = nominated(&pg, "theirs").await;

    // An ordinary tenant of the first organization — what a failed runbook run carries,
    // rather than the nominated platform tenant itself.
    let ordinary = TenantId::new();
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(ordinary.into_uuid())
        .bind(org.into_uuid())
        .bind("emit-ordinary")
        .bind(format!("ordinary-{}", ordinary.into_uuid().simple()))
        .execute(pg.pool())
        .await
        .expect("tenant");

    let (resolved_org, target) = uops_platform_events::target_for_tenant(&pg, ordinary)
        .await
        .expect("resolve")
        .expect("the owning organization nominated a resource");
    assert_eq!(resolved_org, org);

    uops_platform_events::emit(&ch, target, event("Runbook run failed"))
        .await
        .expect("emit");

    assert_eq!(events_on(&mine).await.len(), 1);
    assert!(
        events_on(&theirs).await.is_empty(),
        "one customer's runbook failure must never appear on another customer's \
         installation resource"
    );
}
