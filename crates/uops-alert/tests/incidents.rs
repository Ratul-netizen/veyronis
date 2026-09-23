//! An alert becoming an incident — M9, `docs/M9-incident.md`, end to end.
//!
//! `uops-incident` proves the rules and `uops-store-pg` proves the queries. What only
//! these can settle is the wiring: that grouping happens on the *entering-firing* edge,
//! that a suppressed alert still lands in the incident, and that the notification the
//! engine reports is the one grouping permitted rather than the one the rule wanted.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use uops_alert::Engine;
use uops_core::alert::{AlertSeverity, Comparison, Condition};
use uops_core::{OrgId, ResourceId, ResourceKind, TenantId, TenantScope};
use uops_query::{AggFunc, Aggregation, Field, Query, ResourceSelector, SignalType, TimeRange};
use uops_store_ch::{ChClient, ChConfig, ChStore, EventRow, MetricRow, MetricStore};
use uops_store_pg::{AlertRule, Config, NewResource, NewRule, PgStore};

async fn stores() -> (PgStore, ChStore) {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into());
    let pg = PgStore::connect(&Config {
        url,
        ..Config::default()
    })
    .await
    .expect("connect to PostgreSQL");

    let ch = ChStore::new(ChClient::new(ChConfig {
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "uops".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "uops".into()),
        ..ChConfig::from_env()
    }));

    (pg, ch)
}

async fn tenant(pg: &PgStore, slug: &str) -> TenantScope {
    let org = OrgId::new();
    let tenant = TenantId::new();
    let unique = tenant.into_uuid().simple().to_string();

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("inc-org-{unique}"))
        .execute(pg.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("inc-{slug}"))
        .bind(format!("{slug}-{unique}"))
        .execute(pg.pool())
        .await
        .expect("tenant");

    TenantScope::collector(tenant)
}

async fn device(pg: &PgStore, scope: &TenantScope, name: &str) -> ResourceId {
    pg.create_resource(scope, &NewResource::new(ResourceKind::Device, name))
        .await
        .expect("device")
        .id
}

/// `downstream` depends on `upstream`.
async fn depends_on(
    pg: &PgStore,
    scope: &TenantScope,
    downstream: ResourceId,
    upstream: ResourceId,
) {
    sqlx::query(
        "INSERT INTO resource_relationship
            (id, tenant_id, source_id, target_id, kind, discovered_by)
         VALUES ($1, $2, $3, $4, 'depends_on', 'test')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(scope.tenant_id().into_uuid())
    .bind(downstream.into_uuid())
    .bind(upstream.into_uuid())
    .execute(pg.pool())
    .await
    .expect("edge");
}

fn sample(tenant: TenantId, resource: ResourceId, value: f64, at: DateTime<Utc>) -> MetricRow {
    MetricRow {
        tenant_id: tenant,
        resource_id: resource,
        site_id: uops_core::SiteId::nil(),
        metric: "system.cpu.utilization".to_owned(),
        observed_at: at,
        ingested_at: at,
        value,
        unit: "1".to_owned(),
        labels: BTreeMap::new(),
    }
}

/// A rule that fires immediately on a breach, over exactly one resource.
///
/// Scoped deliberately. A rule with the default `all` selector evaluates every resource
/// in the tenant, so two rules over two devices produce four alerts — which is correct of
/// the engine and not what these tests are about. Naming the resource is also what makes
/// each rule a distinct *condition*, so grouping is decided by §2.2's topology rule rather
/// than short-circuited by `SameRule`.
fn cpu_rule(name: &str, resource: ResourceId) -> NewRule {
    let end = Utc::now();
    NewRule {
        name: name.to_owned(),
        description: String::new(),
        query: Query {
            aggregations: vec![Aggregation {
                func: AggFunc::Avg,
                field: Some(Field::Value),
                alias: "v".to_owned(),
            }],
            resources: ResourceSelector::Ids {
                ids: vec![resource],
            },
            ..Query::new(
                SignalType::Metric,
                TimeRange::new(end - Duration::minutes(1), end),
            )
        },
        condition: Condition::Threshold {
            op: Comparison::Gt,
            value: 90.0,
            hold_seconds: 0,
        },
        severity: AlertSeverity::Critical,
        enabled: true,
        eval_interval: Duration::seconds(60),
        notify: serde_json::json!([]),
    }
}

async fn rule(pg: &PgStore, scope: &TenantScope, name: &str, on: ResourceId) -> AlertRule {
    pg.create_rule(scope, None, &cpu_rule(name, on))
        .await
        .expect("create rule")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_firing_alert_becomes_an_incident() {
    // The wiring, in one test: an alert entering `firing` is grouped, the incident names
    // it, and the rule that opened it is in the summary.
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "one").await;
    let host = device(&pg, &scope, "rtr-01").await;
    let rule = rule(&pg, &scope, "cpu", host).await;

    let now = Utc::now();
    ch.insert_metrics(&[sample(
        scope.tenant_id(),
        host,
        99.0,
        now - Duration::seconds(10),
    )])
    .await
    .expect("sample");

    let engine = Engine::new(pg.clone(), ch.clone());
    let outcome = engine.evaluate(&scope, &rule, now).await.expect("evaluate");
    assert_eq!(outcome.notifications(), 1, "{:?}", outcome.decisions);

    let incidents = pg.incidents(&scope, 10).await.expect("incidents");
    assert_eq!(incidents.len(), 1, "one alert, one incident");
    assert_eq!(incidents[0].alerts, 1);
    assert_eq!(incidents[0].state, "open");
    assert_eq!(incidents[0].severity, "critical");
    assert_eq!(
        incidents[0].candidate_resource_id,
        Some(host),
        "an incident of one is its own candidate"
    );
    assert!(
        incidents[0].summary.contains("cpu"),
        "the summary names the rule: {}",
        incidents[0].summary
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cascade_is_one_incident_and_names_the_switch() {
    // §2.2 and §2.5 through the engine. Two rules on two resources one hop apart, firing
    // within the join window: one incident, and the resource nothing else depends on is
    // the candidate.
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "cascade").await;
    let switch = device(&pg, &scope, "sw-01").await;
    let host = device(&pg, &scope, "host-01").await;
    depends_on(&pg, &scope, host, switch).await;

    let now = Utc::now();
    for resource in [switch, host] {
        ch.insert_metrics(&[sample(
            scope.tenant_id(),
            resource,
            99.0,
            now - Duration::seconds(10),
        )])
        .await
        .expect("sample");
    }

    let engine = Engine::new(pg.clone(), ch.clone());
    // Two rules, because one rule over two resources would join on `SameRule` and prove
    // something else. These are two conditions that happen to be connected.
    let first = rule(&pg, &scope, "switch-cpu", switch).await;
    let second = rule(&pg, &scope, "host-cpu", host).await;
    engine.evaluate(&scope, &first, now).await.expect("first");
    engine
        .evaluate(&scope, &second, now + Duration::seconds(30))
        .await
        .expect("second");

    let incidents = pg.incidents(&scope, 10).await.expect("incidents");
    assert_eq!(incidents.len(), 1, "one cascade is one incident");
    assert_eq!(incidents[0].alerts, 2);
    assert_eq!(
        incidents[0].candidate_resource_id,
        Some(switch),
        "the switch has nothing above it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn suppression_takes_the_notification_and_never_the_alert() {
    // §2.4, through the engine, with the tenant's flag on. The downstream alert joins the
    // incident and is recorded — what it loses is the page at 4am.
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "supp").await;
    sqlx::query("UPDATE tenant SET suppress_downstream_alerts = true WHERE id = $1")
        .bind(scope.tenant_id().into_uuid())
        .execute(pg.pool())
        .await
        .expect("enable");

    let switch = device(&pg, &scope, "sw-01").await;
    let host = device(&pg, &scope, "host-01").await;
    depends_on(&pg, &scope, host, switch).await;

    let now = Utc::now();
    for resource in [switch, host] {
        ch.insert_metrics(&[sample(
            scope.tenant_id(),
            resource,
            99.0,
            now - Duration::seconds(10),
        )])
        .await
        .expect("sample");
    }

    let engine = Engine::new(pg.clone(), ch.clone());
    let first = rule(&pg, &scope, "switch-cpu", switch).await;
    let second = rule(&pg, &scope, "host-cpu", host).await;

    let cause = engine.evaluate(&scope, &first, now).await.expect("first");
    assert_eq!(cause.notifications(), 1, "the cause notifies");

    let symptom = engine
        .evaluate(&scope, &second, now + Duration::seconds(30))
        .await
        .expect("second");
    assert_eq!(
        symptom.notifications(),
        0,
        "the symptom does not: {:?}",
        symptom.decisions
    );

    let incidents = pg.incidents(&scope, 10).await.expect("incidents");
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].alerts, 2, "both alerts are in it");
    assert_eq!(
        incidents[0].suppressed, 1,
        "and the incident knows which one was silenced"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn with_suppression_off_the_symptom_still_notifies() {
    // The default, and the reason it is the default: §2.4's suppression is the one
    // feature in M9 that can cause a missed outage, so it does not arrive switched on.
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "nosupp").await;
    let switch = device(&pg, &scope, "sw-01").await;
    let host = device(&pg, &scope, "host-01").await;
    depends_on(&pg, &scope, host, switch).await;

    let now = Utc::now();
    for resource in [switch, host] {
        ch.insert_metrics(&[sample(
            scope.tenant_id(),
            resource,
            99.0,
            now - Duration::seconds(10),
        )])
        .await
        .expect("sample");
    }

    let engine = Engine::new(pg.clone(), ch.clone());
    let first = rule(&pg, &scope, "switch-cpu", switch).await;
    let second = rule(&pg, &scope, "host-cpu", host).await;
    engine.evaluate(&scope, &first, now).await.expect("first");
    let symptom = engine
        .evaluate(&scope, &second, now + Duration::seconds(30))
        .await
        .expect("second");

    assert_eq!(symptom.notifications(), 1, "still grouped, still told");

    let incidents = pg.incidents(&scope, 10).await.expect("incidents");
    assert_eq!(incidents[0].alerts, 2);
    assert_eq!(incidents[0].suppressed, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_unrelated_failures_are_two_incidents() {
    // §2.2's other half. Same minute, no topology between them: a busy estate has
    // unrelated failures at the same time, and grouping by time alone would make one
    // enormous incident that is really a clock.
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "unrelated").await;
    let a = device(&pg, &scope, "a").await;
    let b = device(&pg, &scope, "b").await;
    // An edge elsewhere, so the estate *has* topology and these two are simply not on it.
    let c = device(&pg, &scope, "c").await;
    let d = device(&pg, &scope, "d").await;
    depends_on(&pg, &scope, c, d).await;

    let now = Utc::now();
    for resource in [a, b] {
        ch.insert_metrics(&[sample(
            scope.tenant_id(),
            resource,
            99.0,
            now - Duration::seconds(10),
        )])
        .await
        .expect("sample");
    }

    let engine = Engine::new(pg.clone(), ch.clone());
    let first = rule(&pg, &scope, "a-cpu", a).await;
    let second = rule(&pg, &scope, "b-cpu", b).await;
    engine.evaluate(&scope, &first, now).await.expect("first");
    engine
        .evaluate(&scope, &second, now + Duration::seconds(20))
        .await
        .expect("second");

    let incidents = pg.incidents(&scope, 10).await.expect("incidents");
    assert_eq!(incidents.len(), 2, "two failures, two incidents");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resolving_alert_does_not_open_a_second_incident() {
    // `notify` is true on the resolving edge too, and a resolution belongs to the
    // incident its alert already joined. Grouping only on the entering-firing edge is
    // what stops every recovery minting an incident of its own.
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "resolve").await;
    let host = device(&pg, &scope, "rtr-01").await;
    let rule = rule(&pg, &scope, "cpu", host).await;
    let engine = Engine::new(pg.clone(), ch.clone());

    let now = Utc::now();
    ch.insert_metrics(&[sample(
        scope.tenant_id(),
        host,
        99.0,
        now - Duration::seconds(10),
    )])
    .await
    .expect("breach");
    engine.evaluate(&scope, &rule, now).await.expect("fire");

    let later = now + Duration::minutes(2);
    ch.insert_metrics(&[sample(
        scope.tenant_id(),
        host,
        10.0,
        later - Duration::seconds(10),
    )])
    .await
    .expect("recovery");
    let recovered = engine
        .evaluate(&scope, &rule, later)
        .await
        .expect("resolve");
    assert_eq!(recovered.notifications(), 1, "a resolution is still told");

    let incidents = pg.incidents(&scope, 10).await.expect("incidents");
    assert_eq!(incidents.len(), 1, "and it did not open a second incident");
    assert_eq!(incidents[0].alerts, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_incident_goes_quiet_when_its_alerts_resolve() {
    // §2.1: quiet, never closed. The cycle sweeps it; a human closes it.
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "settle").await;
    let host = device(&pg, &scope, "rtr-01").await;
    let rule = rule(&pg, &scope, "cpu", host).await;
    let engine = Engine::new(pg.clone(), ch.clone());

    let now = Utc::now();
    ch.insert_metrics(&[sample(
        scope.tenant_id(),
        host,
        99.0,
        now - Duration::seconds(10),
    )])
    .await
    .expect("breach");
    engine.evaluate(&scope, &rule, now).await.expect("fire");
    assert_eq!(
        pg.incidents(&scope, 10).await.expect("rows")[0].state,
        "open"
    );

    let later = now + Duration::minutes(2);
    ch.insert_metrics(&[sample(
        scope.tenant_id(),
        host,
        10.0,
        later - Duration::seconds(10),
    )])
    .await
    .expect("recovery");
    engine
        .evaluate(&scope, &rule, later)
        .await
        .expect("resolve");

    // The sweep runs once per tenant per cycle, not per rule.
    engine.cycle(later).await.expect("cycle");

    let rows = pg.incidents(&scope, 10).await.expect("rows");
    assert_eq!(rows[0].state, "quiet");
    assert!(rows[0].closed_at.is_none(), "a machine does not close");
}

// ---- detections — M11 §2.3, §3 --------------------------------------------------

/// One security event on a device.
fn security_event(tenant: TenantId, resource: ResourceId, at: DateTime<Utc>) -> EventRow {
    EventRow {
        tenant_id: tenant,
        resource_id: resource,
        site_id: uops_core::SiteId::nil(),
        observed_at: at,
        ingested_at: at,
        source_kind: "syslog".to_owned(),
        source_vendor: "fortinet".to_owned(),
        severity: "warn".to_owned(),
        event_category: "network".to_owned(),
        event_type: "denied".to_owned(),
        summary: "Denied 198.51.100.7 → 10.0.0.5:22".to_owned(),
        attributes: std::collections::BTreeMap::new(),
    }
}

/// `count() > 5` over denied network events on one device.
///
/// `cpu_rule` with the signal and the aggregate changed. Nothing about it says
/// "detection", which is M11 §2.3 in one function.
fn denial_detection(name: &str, resource: ResourceId) -> NewRule {
    let end = Utc::now();
    NewRule {
        name: name.to_owned(),
        description: String::new(),
        query: Query {
            aggregations: vec![Aggregation {
                func: AggFunc::Count,
                field: None,
                alias: "v".to_owned(),
            }],
            resources: ResourceSelector::Ids {
                ids: vec![resource],
            },
            ..Query::new(
                SignalType::Event,
                TimeRange::new(end - Duration::minutes(1), end),
            )
        },
        condition: Condition::Threshold {
            op: Comparison::Gt,
            value: 5.0,
            hold_seconds: 0,
        },
        severity: AlertSeverity::Critical,
        enabled: true,
        eval_interval: Duration::seconds(60),
        notify: serde_json::json!([]),
    }
}

/// M11 §3: a detection firing produces an incident through M9's existing grouping.
///
/// The claim is that M11 adds no incident machinery. So this is
/// `a_firing_alert_becomes_an_incident` with the rule pointed at `events` instead of
/// `metrics` — and if the assertions below had to change, that claim would be false.
#[tokio::test(flavor = "multi_thread")]
async fn a_firing_detection_becomes_an_incident() {
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "detect").await;
    let host = device(&pg, &scope, "fw-01").await;
    let rule = pg
        .create_rule(&scope, None, &denial_detection("denials", host))
        .await
        .expect("create rule");

    let now = Utc::now();
    let rows: Vec<_> = (0..9)
        .map(|n| security_event(scope.tenant_id(), host, now - Duration::seconds(10 + n)))
        .collect();
    uops_store_ch::EventStore::insert_events(&ch, &rows)
        .await
        .expect("events");

    let engine = Engine::new(pg.clone(), ch.clone());
    let outcome = engine.evaluate(&scope, &rule, now).await.expect("evaluate");
    assert_eq!(outcome.notifications(), 1, "{:?}", outcome.decisions);

    let incidents = pg.incidents(&scope, 10).await.expect("incidents");
    assert_eq!(incidents.len(), 1, "one detection, one incident");
    assert_eq!(incidents[0].alerts, 1);
    assert_eq!(incidents[0].state, "open");
    assert_eq!(incidents[0].severity, "critical");
    assert_eq!(
        incidents[0].candidate_resource_id,
        Some(host),
        "the device the events were about"
    );
}

/// M11 §3, second half: topology suppression applies to a detection exactly as it does to
/// any other alert.
///
/// This is `suppression_takes_the_notification_and_never_the_alert` with one of the two
/// rules pointed at `events`. The mixture is the point — a detection downstream of a
/// metric alert has to be suppressed by it, or "security" would be a category the topology
/// rules quietly do not apply to.
#[tokio::test(flavor = "multi_thread")]
async fn topology_suppression_applies_to_a_detection_like_any_other_alert() {
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "detect-suppress").await;
    let switch = device(&pg, &scope, "sw-01").await;
    let host = device(&pg, &scope, "srv-01").await;
    depends_on(&pg, &scope, host, switch).await;

    sqlx::query("UPDATE tenant SET suppress_downstream_alerts = true WHERE id = $1")
        .bind(scope.tenant_id().into_uuid())
        .execute(pg.pool())
        .await
        .expect("suppression on");

    // The cause is an ordinary metric alert on the switch; the symptom is a *detection* on
    // the host behind it.
    let cause = rule(&pg, &scope, "switch cpu", switch).await;
    let symptom = pg
        .create_rule(&scope, None, &denial_detection("host denials", host))
        .await
        .expect("create rule");

    let now = Utc::now();
    ch.insert_metrics(&[sample(
        scope.tenant_id(),
        switch,
        99.0,
        now - Duration::seconds(10),
    )])
    .await
    .expect("sample");
    let rows: Vec<_> = (0..9)
        .map(|n| security_event(scope.tenant_id(), host, now - Duration::seconds(10 + n)))
        .collect();
    uops_store_ch::EventStore::insert_events(&ch, &rows)
        .await
        .expect("events");

    let engine = Engine::new(pg.clone(), ch.clone());
    let upstream = engine.evaluate(&scope, &cause, now).await.expect("evaluate");
    let downstream = engine
        .evaluate(&scope, &symptom, now)
        .await
        .expect("evaluate");

    // One incident for both, and only the cause notified. The detection's alert is still
    // on it — suppression takes the *notification*, never the alert.
    let incidents = pg.incidents(&scope, 10).await.expect("incidents");
    assert_eq!(incidents.len(), 1, "a cascade is one incident: {incidents:?}");
    assert_eq!(incidents[0].alerts, 2, "both alerts are on it");
    assert_eq!(
        incidents[0].candidate_resource_id,
        Some(switch),
        "the switch is upstream, so it is the likely origin"
    );
    assert_eq!(upstream.notifications(), 1, "the cause notifies");
    assert_eq!(
        downstream.notifications(),
        0,
        "the detection behind it does not: {:?}",
        downstream.decisions
    );
}

/// M11 §2.4's open criterion, closed — `docs/self-monitoring.md`.
///
/// # What this test is for
///
/// M11 shipped with *"sign-ins against this product itself are a source of authentication
/// events"* marked `[~]`: they were recorded in the organization audit log and **nothing
/// could fire on them**, because the alert engine evaluates a `Query` against `ClickHouse`
/// under a tenant scope and an audit row has no tenant.
///
/// The decision document's answer is that the installation is a resource. If that answer is
/// right, this test needs no new machinery — the rule is an ordinary rule, the engine is
/// the ordinary engine, and the only thing that changed is that there is now a resource for
/// the events to be about. So the assertions below are the same ones
/// `a_firing_detection_becomes_an_incident` makes about a firewall.
///
/// A security-analytics milestone whose first detection cannot see attacks on the
/// monitoring platform itself is one that missed the target closest to it. This is that
/// detection.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines, reason = "one rule written out in full")]
async fn a_burst_of_failed_sign_ins_against_the_product_fires_a_detection() {
    let (pg, ch) = stores().await;
    let scope = tenant(&pg, "selfauth").await;

    // The installation, as a first run or migration 0027 would have created it.
    let org = sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT org_id FROM tenant WHERE id = $1",
    )
    .bind(scope.tenant_id().into_uuid())
    .fetch_one(pg.pool())
    .await
    .expect("org");
    let platform = pg
        .nominate_platform_tenant(uops_core::OrgId::from_uuid(org), scope.tenant_id())
        .await
        .expect("nominate");

    // `count() > 5` over failed authentications on the installation. Nothing about this
    // rule knows it is about the product rather than about a switch.
    let end = Utc::now();
    let rule = pg
        .create_rule(
            &scope,
            None,
            &NewRule {
                name: "failed sign-ins".to_owned(),
                description: String::new(),
                query: Query {
                    aggregations: vec![Aggregation {
                        func: AggFunc::Count,
                        field: None,
                        alias: "v".to_owned(),
                    }],
                    resources: ResourceSelector::Ids {
                        ids: vec![platform.resource_id],
                    },
                    filter: Some(uops_query::ast::Expr::And {
                        of: vec![
                            uops_query::ast::Expr::Compare {
                                field: Field::EventCategory,
                                cmp: uops_query::ast::CompareOp::Eq,
                                value: uops_query::ast::Value::Str("authentication".to_owned()),
                            },
                            uops_query::ast::Expr::Compare {
                                field: Field::EventType,
                                cmp: uops_query::ast::CompareOp::Eq,
                                value: uops_query::ast::Value::Str("failure".to_owned()),
                            },
                        ],
                    }),
                    ..Query::new(
                        SignalType::Event,
                        TimeRange::new(end - Duration::minutes(1), end),
                    )
                },
                condition: Condition::Threshold {
                    op: Comparison::Gt,
                    value: 5.0,
                    hold_seconds: 0,
                },
                severity: AlertSeverity::Critical,
                enabled: true,
                eval_interval: Duration::seconds(60),
                notify: serde_json::json!([]),
            },
        )
        .await
        .expect("create rule");

    // Nine failures from one address against one account, as the sign-in path writes them.
    let now = Utc::now();
    let rows: Vec<_> = (0..9)
        .map(|n| EventRow {
            tenant_id: scope.tenant_id(),
            resource_id: platform.resource_id,
            site_id: uops_core::SiteId::nil(),
            observed_at: now - Duration::seconds(10 + n),
            ingested_at: now - Duration::seconds(10 + n),
            source_kind: "self".to_owned(),
            source_vendor: String::new(),
            severity: "warn".to_owned(),
            event_category: "authentication".to_owned(),
            event_type: "failure".to_owned(),
            summary: "Failed sign-in for admin@example.com".to_owned(),
            attributes: [
                ("user.name".to_owned(), "admin@example.com".to_owned()),
                ("source.ip".to_owned(), "198.51.100.7".to_owned()),
            ]
            .into_iter()
            .collect(),
        })
        .collect();
    uops_store_ch::EventStore::insert_events(&ch, &rows)
        .await
        .expect("events");

    // A successful sign-in in the same window, which the filter must exclude.
    uops_store_ch::EventStore::insert_events(
        &ch,
        &[EventRow {
            event_type: "success".to_owned(),
            observed_at: now - Duration::seconds(5),
            ..rows[0].clone()
        }],
    )
    .await
    .expect("event");

    let engine = Engine::new(pg.clone(), ch.clone());
    let outcome = engine.evaluate(&scope, &rule, now).await.expect("evaluate");
    assert_eq!(outcome.notifications(), 1, "{:?}", outcome.decisions);

    // And it becomes an incident through M9's grouping, with the installation named as the
    // resource it is about — exactly as a firewall would.
    let incidents = pg.incidents(&scope, 10).await.expect("incidents");
    assert_eq!(incidents.len(), 1, "one detection, one incident");
    assert_eq!(incidents[0].alerts, 1);
    assert_eq!(
        incidents[0].candidate_resource_id,
        Some(platform.resource_id),
        "the incident is about the installation"
    );
}
