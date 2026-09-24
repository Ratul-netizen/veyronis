//! Objectives against real `PostgreSQL` — `docs/slo.md`.
//!
//! Almost every test here is about a bound, and the bounds are not fussiness. A target of
//! exactly 1 makes every burn-rate calculation divide by zero; a target of 99 instead of
//! 0.99 is the most common way to get this wrong and would silently define an objective
//! nothing can ever miss. Both are refused by the schema rather than by a handler, so a
//! second caller writing a row by another route cannot introduce them.

use uops_core::{OrgId, ResourceId, TenantId, TenantScope};
use uops_store_pg::{Config, NewSlo, PgStore};

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
    a: TenantId,
    b: TenantId,
}

impl Fixture {
    fn scope_a(&self) -> TenantScope {
        TenantScope::system(self.a)
    }
    fn scope_b(&self) -> TenantScope {
        TenantScope::system(self.b)
    }
}

async fn fixture(slug: &str) -> Fixture {
    let store = store().await;
    let org = OrgId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("slo-org-{slug}-{}", org.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("organization");

    let mut tenants = Vec::new();
    for which in ["a", "b"] {
        let id = TenantId::new();
        sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
            .bind(id.into_uuid())
            .bind(org.into_uuid())
            .bind(format!("slo-{slug}-{which}"))
            .bind(format!("slo-{slug}-{which}-{}", id.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("tenant");
        tenants.push(id);
    }

    Fixture {
        store,
        a: tenants[0],
        b: tenants[1],
    }
}

fn objective(service: uuid::Uuid, target: f32, days: i32) -> NewSlo {
    NewSlo {
        name: format!("{target} over {days}d"),
        description: String::new(),
        service_id: service,
        target,
        window_days: days,
    }
}

#[tokio::test]
async fn an_objective_round_trips() {
    let f = fixture("round").await;
    let service = ResourceId::new().into_uuid();

    let made = f
        .store
        .set_slo(&f.scope_a(), &objective(service, 0.995, 30))
        .await
        .expect("set");

    let listed = f.store.slos(&f.scope_a()).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, made.id);
    assert!((listed[0].target - 0.995).abs() < f32::EPSILON);
    assert_eq!(listed[0].window_days, 30);
}

#[tokio::test]
async fn one_service_may_have_several_windows_but_not_two_of_one() {
    let f = fixture("windows").await;
    let service = ResourceId::new().into_uuid();

    // The ordinary case: a 7-day and a 30-day objective on one service is how burn rate is
    // read, so the window is part of the key.
    f.store
        .set_slo(&f.scope_a(), &objective(service, 0.99, 7))
        .await
        .expect("seven days");
    f.store
        .set_slo(&f.scope_a(), &objective(service, 0.99, 30))
        .await
        .expect("thirty days");

    // Two objectives on one service over one window are two numbers that will be compared,
    // and the comparison has no meaning.
    let clash = f
        .store
        .set_slo(&f.scope_a(), &objective(service, 0.995, 30))
        .await;
    assert!(
        clash.is_err(),
        "a second objective over the same window is refused"
    );

    assert_eq!(f.store.slos(&f.scope_a()).await.expect("list").len(), 2);
}

#[tokio::test]
async fn a_target_of_one_is_refused_because_it_leaves_no_budget() {
    let f = fixture("perfect").await;
    // Every burn rate divides by (1 - target). Refusing this here means the division
    // downstream cannot produce an infinity.
    let refused = f
        .store
        .set_slo(
            &f.scope_a(),
            &objective(ResourceId::new().into_uuid(), 1.0, 30),
        )
        .await;
    assert!(refused.is_err());
}

#[tokio::test]
async fn a_percentage_entered_as_a_proportion_is_refused() {
    let f = fixture("pct").await;
    // 99 rather than 0.99 — the most common way to get this wrong. Left to a float column
    // with no CHECK it would define an objective nothing can ever miss.
    let refused = f
        .store
        .set_slo(
            &f.scope_a(),
            &objective(ResourceId::new().into_uuid(), 99.0, 30),
        )
        .await;
    assert!(refused.is_err());
}

#[tokio::test]
async fn an_objective_below_half_is_refused_as_a_typo() {
    let f = fixture("half").await;
    let refused = f
        .store
        .set_slo(
            &f.scope_a(),
            &objective(ResourceId::new().into_uuid(), 0.5, 30),
        )
        .await;
    assert!(refused.is_err());
}

#[tokio::test]
async fn a_window_outside_the_bounds_is_refused() {
    let f = fixture("window").await;
    let service = ResourceId::new().into_uuid();

    for days in [0, 91, -1] {
        let refused = f
            .store
            .set_slo(&f.scope_a(), &objective(service, 0.99, days))
            .await;
        assert!(refused.is_err(), "{days} days must be refused");
    }

    // The bounds themselves are allowed.
    f.store
        .set_slo(&f.scope_a(), &objective(service, 0.99, 1))
        .await
        .expect("one day");
    f.store
        .set_slo(&f.scope_a(), &objective(service, 0.99, 90))
        .await
        .expect("ninety days");
}

#[tokio::test]
async fn an_objective_may_name_a_service_the_inventory_has_not_catalogued() {
    let f = fixture("uncatalogued").await;
    // A service appears in `service_5m` as soon as a span carries its id, and the
    // inventory row arrives separately. Refusing here would refuse to measure something
    // demonstrably running — which is exactly when somebody sets an objective.
    f.store
        .set_slo(
            &f.scope_a(),
            &objective(ResourceId::new().into_uuid(), 0.99, 30),
        )
        .await
        .expect("a service with no resource row is allowed");
}

#[tokio::test]
async fn one_tenants_objectives_are_invisible_to_another() {
    let f = fixture("iso").await;
    let service = ResourceId::new().into_uuid();

    let mine = f
        .store
        .set_slo(&f.scope_a(), &objective(service, 0.99, 30))
        .await
        .expect("set");

    assert!(
        f.store.slos(&f.scope_b()).await.expect("list").is_empty(),
        "tenant b sees none of tenant a's objectives"
    );

    // The same service id in the other tenant is a different objective, not a conflict:
    // RFC-style shared identifiers do not exist here, but a copied id might.
    f.store
        .set_slo(&f.scope_b(), &objective(service, 0.95, 30))
        .await
        .expect("b may set its own");

    assert!(
        !f.store
            .remove_slo(&f.scope_b(), mine.id)
            .await
            .expect("remove"),
        "b cannot remove a's objective"
    );
    assert_eq!(f.store.slos(&f.scope_a()).await.expect("list").len(), 1);
}

#[tokio::test]
async fn removing_one_that_is_not_there_is_not_an_error() {
    let f = fixture("gone").await;
    let done = f
        .store
        .remove_slo(&f.scope_a(), ResourceId::new().into_uuid())
        .await
        .expect("remove");
    assert!(!done);
}
