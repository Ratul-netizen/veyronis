//! Incidents against real PostgreSQL — M9, `docs/M9-incident.md`.
//!
//! `uops-incident` proves the rules over pure data. What only these can settle is that
//! the queries feeding them return what the rules were written against: the topology
//! walks in particular, where a wrong direction compiles perfectly and produces a
//! plausible, wrong incident.

use chrono::{Duration, Utc};
use uops_core::{ActorId, OrgId, ResourceId, TenantId, TenantScope};
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

/// A tenant of its own per test, so one test's topology is not another's.
async fn tenant(store: &PgStore, slug: &str) -> TenantScope {
    let org = OrgId::new();
    let id = TenantId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("inc-org-{slug}-{}", id.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(id.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("inc-{slug}"))
        .bind(format!("inc-{slug}-{}", id.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("tenant");
    TenantScope::system(id)
}

async fn resource(store: &PgStore, scope: &TenantScope, name: &str) -> ResourceId {
    let id = ResourceId::new();
    sqlx::query(
        "INSERT INTO resource (id, tenant_id, kind, name, status)
         VALUES ($1, $2, 'device', $3, 'unknown')",
    )
    .bind(id.into_uuid())
    .bind(scope.tenant_id().into_uuid())
    .bind(name)
    .execute(store.pool())
    .await
    .expect("resource");
    id
}

/// `downstream` depends on `upstream`.
async fn depends_on(
    store: &PgStore,
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
    .execute(store.pool())
    .await
    .expect("edge");
}

/// A rule and one firing alert on `resource`, returning the alert's id.
async fn firing(
    store: &PgStore,
    scope: &TenantScope,
    resource: ResourceId,
    name: &str,
) -> uuid::Uuid {
    let rule = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO alert_rule (id, tenant_id, name, kind, query, condition, severity, created_by)
         VALUES ($1, $2, $3, 'threshold', '{}'::jsonb, '{}'::jsonb, 'warning', NULL)",
    )
    .bind(rule)
    .bind(scope.tenant_id().into_uuid())
    .bind(name)
    .execute(store.pool())
    .await
    .expect("rule");

    let alert = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO alert_state
            (id, tenant_id, rule_id, resource_id, dedup_key, state, since, last_eval)
         VALUES ($1, $2, $3, $4, $5, 'firing', now(), now())",
    )
    .bind(alert)
    .bind(scope.tenant_id().into_uuid())
    .bind(rule)
    .bind(resource.into_uuid())
    .bind(format!("{rule}:{resource}"))
    .execute(store.pool())
    .await
    .expect("alert");
    alert
}

#[tokio::test]
async fn the_neighbourhood_reaches_two_hosts_under_one_switch() {
    // The pair a union of the two *directed* walks would miss, and the commonest pair in
    // any cascade: two hosts that share a switch are reached only by going up and then
    // down. If this returns one hop instead of two, or misses `sibling` entirely, §2.2
    // never groups the failure that M9 exists for.
    let store = store().await;
    let scope = tenant(&store, "hood").await;

    let switch = resource(&store, &scope, "switch").await;
    let host = resource(&store, &scope, "host").await;
    let sibling = resource(&store, &scope, "sibling").await;
    depends_on(&store, &scope, host, switch).await;
    depends_on(&store, &scope, sibling, switch).await;

    let hood = store.neighbourhood(&scope, host).await.expect("walk");

    assert_eq!(hood.within.get(&host), Some(&0), "itself, at zero");
    assert_eq!(hood.within.get(&switch), Some(&1));
    assert_eq!(
        hood.within.get(&sibling),
        Some(&2),
        "up to the switch and back down: {:?}",
        hood.within
    );
    assert!(hood.estate_has_topology);
}

#[tokio::test]
async fn upstream_is_what_this_resource_depends_on_and_not_the_reverse() {
    // §2.4's suppression is directional, and a walk in the wrong direction compiles
    // perfectly and produces a plausible, wrong incident — the switch's own alert would
    // be suppressed by its hosts'.
    let store = store().await;
    let scope = tenant(&store, "dir").await;

    let switch = resource(&store, &scope, "switch").await;
    let host = resource(&store, &scope, "host").await;
    depends_on(&store, &scope, host, switch).await;

    let from_host = store.neighbourhood(&scope, host).await.expect("walk");
    assert!(
        from_host.upstream.contains(&switch),
        "the host depends on the switch"
    );

    let from_switch = store.neighbourhood(&scope, switch).await.expect("walk");
    assert!(
        !from_switch.upstream.contains(&host),
        "and the switch does not depend on the host: {:?}",
        from_switch.upstream
    );

    assert!(store.is_upstream_of(&scope, switch, host).await.expect("q"));
    assert!(!store.is_upstream_of(&scope, host, switch).await.expect("q"));
}

#[tokio::test]
async fn an_estate_with_no_edges_says_so() {
    // §2.3. Distinct from a resource that happens to have no neighbours, which is the
    // next test — and the difference is what stops the screen calling one the other.
    let store = store().await;
    let scope = tenant(&store, "bare").await;
    let lonely = resource(&store, &scope, "lonely").await;

    let hood = store.neighbourhood(&scope, lonely).await.expect("walk");
    assert!(!hood.estate_has_topology);
    assert_eq!(hood.within.len(), 1, "itself and nothing else");
}

#[tokio::test]
async fn a_resource_with_no_links_in_an_estate_that_has_them_is_a_different_fact() {
    let store = store().await;
    let scope = tenant(&store, "mixed").await;

    let a = resource(&store, &scope, "a").await;
    let b = resource(&store, &scope, "b").await;
    depends_on(&store, &scope, a, b).await;
    let island = resource(&store, &scope, "island").await;

    let hood = store.neighbourhood(&scope, island).await.expect("walk");
    assert!(
        hood.estate_has_topology,
        "the estate has edges; this resource is simply not on them"
    );
    assert_eq!(hood.within.len(), 1);
}

#[tokio::test]
async fn a_cycle_is_walked_once_and_reports_the_shorter_path() {
    // Real networks contain relationship cycles. What this asserts is the *result*: each
    // node appears once, at its nearest depth.
    //
    // It deliberately does not claim to prove the cycle guard. A mutation that removes
    // the guard from `resource_neighbourhood` leaves every test in this file passing,
    // because `max_depth` is 2 and a bounded walk terminates with or without it — the
    // guard bounds the *work*, not the answer, and at two hops there is barely any work
    // to bound. It is still not optional: the radius is a constant somebody will raise,
    // and the cost of a cycle grows exponentially with it.
    //
    // Recorded because a surviving mutation is worth more written down than quietly
    // rationalised.
    let store = store().await;
    let scope = tenant(&store, "cycle").await;

    let a = resource(&store, &scope, "a").await;
    let b = resource(&store, &scope, "b").await;
    depends_on(&store, &scope, a, b).await;
    depends_on(&store, &scope, b, a).await;

    let hood = store.neighbourhood(&scope, a).await.expect("walk");
    assert_eq!(hood.within.len(), 2);
    assert!(store.is_upstream_of(&scope, b, a).await.expect("q"));
}

#[tokio::test]
async fn a_walk_cannot_leave_its_tenant() {
    // Knowing a UUID is not authorization. 0003 made the tenant a parameter filtered at
    // every step for this reason, and the two new walks inherit it — this is the test
    // that they did.
    let store = store().await;
    let mine = tenant(&store, "mine").await;
    let theirs = tenant(&store, "theirs").await;

    let ours = resource(&store, &mine, "ours").await;
    let a = resource(&store, &theirs, "a").await;
    let b = resource(&store, &theirs, "b").await;
    depends_on(&store, &theirs, a, b).await;

    // Their resource id, walked under our scope.
    let hood = store.neighbourhood(&mine, a).await.expect("walk");
    assert!(
        hood.within.is_empty(),
        "a foreign root yields nothing, not this tenant's graph: {:?}",
        hood.within
    );
    assert!(!store.is_upstream_of(&mine, b, a).await.expect("q"));

    let _ = ours;
}

#[tokio::test]
async fn an_incident_opens_with_one_alert_and_reads_back() {
    let store = store().await;
    let scope = tenant(&store, "open").await;
    let host = resource(&store, &scope, "host").await;
    let alert = firing(&store, &scope, host, "cpu").await;

    let id = store
        .open_incident(&scope, alert, "warning", "cpu on host", Utc::now(), None)
        .await
        .expect("open");

    let open = store.open_incidents(&scope).await.expect("list");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].id, id);
    assert!(open[0].resources.contains(&host), "{:?}", open[0]);
    assert_eq!(open[0].rules.len(), 1);

    let listed = store.incidents(&scope, 10).await.expect("rows");
    assert_eq!(listed[0].alerts, 1);
    assert_eq!(listed[0].suppressed, 0);
    assert_eq!(
        listed[0].candidate_resource_id,
        Some(host),
        "an incident of one is its own candidate"
    );
}

#[tokio::test]
async fn an_alert_belongs_to_at_most_one_incident() {
    // §2.1, enforced by the primary key rather than by code — two people working on the
    // same failure without knowing is the thing it prevents.
    let store = store().await;
    let scope = tenant(&store, "once").await;
    let host = resource(&store, &scope, "host").await;
    let alert = firing(&store, &scope, host, "cpu").await;

    let first = store
        .open_incident(&scope, alert, "warning", "one", Utc::now(), None)
        .await
        .expect("open");
    let second = store
        .open_incident(&scope, alert, "warning", "two", Utc::now(), None)
        .await;

    assert!(
        second.is_err(),
        "the same alert cannot open a second incident"
    );

    let joined = store
        .join_incident(&scope, first, alert, true, Some(0), "warning", Utc::now())
        .await;
    assert!(joined.is_err(), "nor join one twice");
}

#[tokio::test]
async fn joining_slides_the_window_and_raises_the_severity() {
    let store = store().await;
    let scope = tenant(&store, "join").await;
    let switch = resource(&store, &scope, "switch").await;
    let host = resource(&store, &scope, "host").await;
    depends_on(&store, &scope, host, switch).await;

    let started = Utc::now() - Duration::minutes(10);
    let first = firing(&store, &scope, switch, "down").await;
    let id = store
        .open_incident(&scope, first, "warning", "switch down", started, None)
        .await
        .expect("open");

    let later = Utc::now();
    let second = firing(&store, &scope, host, "absent").await;
    store
        .join_incident(&scope, id, second, false, Some(1), "critical", later)
        .await
        .expect("join");

    let rows = store.incidents(&scope, 10).await.expect("rows");
    assert_eq!(rows[0].alerts, 2);
    assert_eq!(rows[0].suppressed, 1, "the joined alert did not notify");
    assert_eq!(rows[0].severity, "critical", "severity only rises");
    assert!(rows[0].last_alert_at > started, "the window slid");
}

#[tokio::test]
async fn resolving_every_alert_makes_an_incident_quiet_and_never_closed() {
    // §2.1, and the one a machine must not get wrong: closing is a claim that it is
    // understood, and nothing here is in a position to make it.
    let store = store().await;
    let scope = tenant(&store, "quiet").await;
    let host = resource(&store, &scope, "host").await;
    let alert = firing(&store, &scope, host, "cpu").await;
    store
        .open_incident(&scope, alert, "warning", "cpu", Utc::now(), None)
        .await
        .expect("open");

    // Still firing: nothing settles.
    assert_eq!(
        store
            .quiet_settled_incidents(&scope, Utc::now())
            .await
            .expect("quiet"),
        0
    );

    sqlx::query("UPDATE alert_state SET state = 'resolved' WHERE id = $1")
        .bind(alert)
        .execute(store.pool())
        .await
        .expect("resolve");

    assert_eq!(
        store
            .quiet_settled_incidents(&scope, Utc::now())
            .await
            .expect("quiet"),
        1
    );

    let rows = store.incidents(&scope, 10).await.expect("rows");
    assert_eq!(rows[0].state, "quiet");
    assert!(rows[0].closed_at.is_none(), "a machine does not close");
    assert!(
        store.open_incidents(&scope).await.expect("open").is_empty(),
        "and a quiet incident is no longer a candidate to join"
    );
}

#[tokio::test]
async fn only_a_human_closes_and_only_once() {
    let store = store().await;
    let scope = tenant(&store, "close").await;
    let host = resource(&store, &scope, "host").await;
    let alert = firing(&store, &scope, host, "cpu").await;
    let id = store
        .open_incident(&scope, alert, "warning", "cpu", Utc::now(), None)
        .await
        .expect("open");

    let by = ActorId::new();
    // A user belongs to the org that owns the tenant, which is what `closed_by` points
    // at — an incident closed by somebody outside the org would be a foreign key nobody
    // could explain.
    sqlx::query(
        "INSERT INTO app_user (id, org_id, email, display_name, password_hash)
         SELECT $1, t.org_id, $2, $3, 'x' FROM tenant t WHERE t.id = $4",
    )
    .bind(by.into_uuid())
    .bind(format!(
        "closer-{}@example.invalid",
        by.into_uuid().simple()
    ))
    .bind("Closer")
    .bind(scope.tenant_id().into_uuid())
    .execute(store.pool())
    .await
    .expect("user");

    store
        .close_incident(&scope, id, by, Utc::now())
        .await
        .expect("close");

    let rows = store.incidents(&scope, 10).await.expect("rows");
    assert_eq!(rows[0].state, "closed");
    assert!(rows[0].closed_at.is_some());

    // Twice is not idempotent: it is two people each believing they were the one who
    // understood it.
    assert!(
        store
            .close_incident(&scope, id, by, Utc::now())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn suppression_is_off_until_a_tenant_turns_it_on() {
    // §2.4. The one feature in this milestone that can cause a missed outage does not
    // arrive switched on.
    let store = store().await;
    let scope = tenant(&store, "supp").await;

    assert!(!store.suppression_enabled(&scope).await.expect("read"));

    sqlx::query("UPDATE tenant SET suppress_downstream_alerts = true WHERE id = $1")
        .bind(scope.tenant_id().into_uuid())
        .execute(store.pool())
        .await
        .expect("enable");

    assert!(store.suppression_enabled(&scope).await.expect("read"));
}

#[tokio::test]
async fn one_tenants_incidents_are_invisible_to_another() {
    // The adversarial test every milestone since M7 has used, asked of the new tables.
    let store = store().await;
    let victim = tenant(&store, "victim").await;
    let attacker = tenant(&store, "attacker").await;

    let host = resource(&store, &victim, "host").await;
    let alert = firing(&store, &victim, host, "cpu").await;
    let id = store
        .open_incident(&victim, alert, "critical", "secret", Utc::now(), None)
        .await
        .expect("open");

    assert!(
        store
            .incidents(&attacker, 10)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(
        store
            .open_incidents(&attacker)
            .await
            .expect("open")
            .is_empty()
    );
    assert!(
        store
            .incident_members(&attacker, id)
            .await
            .expect("members")
            .is_empty(),
        "knowing the incident id is not enough"
    );
    assert!(
        store
            .close_incident(&attacker, id, ActorId::new(), Utc::now())
            .await
            .is_err(),
        "and it cannot be closed from outside"
    );

    // And the victim still has it.
    assert_eq!(store.incidents(&victim, 10).await.expect("list").len(), 1);
}
