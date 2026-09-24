//! Finding the installation resource to write a first-party event to.
//!
//! `docs/self-monitoring.md` §2.3 built `platform_target` — one organization, by id — and it
//! is covered by the sign-in tests in `uops-api`. §4's collector, lease and runbook events
//! need two lookups it does not do: *every* organization that has nominated one, and the
//! organization that owns a given tenant.
//!
//! # Why the second one is the dangerous one
//!
//! `platform_target_for_tenant` is the only place in the product that walks *upward* out of
//! a tenant to its organization without a `TenantScope`. It has to: a runbook run that
//! failed is a row with a tenant, and the event about it belongs to whoever owns that
//! tenant. Nothing about the type system stops it returning the wrong organization, so the
//! test that matters is the one with two of them.

use uops_core::{OrgId, TenantId};
use uops_store_pg::{Config, PgStore};

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into())
}

async fn store() -> PgStore {
    PgStore::connect(&Config {
        url: admin_url(),
        ..Config::default()
    })
    .await
    .expect("connect")
}

async fn org(store: &PgStore, slug: &str) -> OrgId {
    let id = OrgId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(id.into_uuid())
        .bind(format!("platform-org-{slug}-{}", id.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("organization");
    id
}

async fn tenant(store: &PgStore, org: OrgId, slug: &str) -> TenantId {
    let id = TenantId::new();
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(id.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("platform-{slug}"))
        .bind(format!("{slug}-{}", id.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("tenant");
    id
}

/// The regression this file was written for. Both new readers aliased their columns with
/// the `AS "org: OrgId"` form, which is a `query!` *macro* instruction: in an unchecked
/// `sqlx::query` it names the column `org: OrgId` literally, and every `try_get("org")`
/// raised `ColumnNotFound`. The observer therefore logged "could not read platform targets"
/// on every tick and emitted nothing — the failure was handled, reported, and total.
///
/// It reads as working code, which is why the assertion is on a row rather than on an
/// error: any query that returns nothing at all still satisfies "did not error".
#[tokio::test]
async fn a_nominated_organization_is_found_among_every_other() {
    let store = store().await;
    let org = org(&store, "listed").await;
    let tenant = tenant(&store, org, "listed").await;
    let expected = store
        .nominate_platform_tenant(org, tenant)
        .await
        .expect("nominate");

    let all = store.platform_targets().await.expect("read every target");

    let found = all
        .iter()
        .find(|(id, _)| *id == org)
        .map(|(_, target)| target)
        .expect("the organization just nominated is in the list");
    assert_eq!(found.tenant_id, expected.tenant_id);
    assert_eq!(found.resource_id, expected.resource_id);
}

#[tokio::test]
async fn an_organization_that_nominated_nothing_is_absent() {
    let store = store().await;
    let quiet = org(&store, "silent").await;
    tenant(&store, quiet, "silent").await;

    let all = store.platform_targets().await.expect("read every target");

    assert!(
        !all.iter().any(|(id, _)| *id == quiet),
        "an organization with no nominated resource has nowhere to put an event, and \
         saying so by omission is what lets the caller skip it without a branch"
    );
}

#[tokio::test]
async fn a_tenant_resolves_to_its_own_organizations_resource() {
    let store = store().await;

    // Two organizations, each with a nominated resource. One tenant belongs to the first.
    let mine = org(&store, "mine").await;
    let mine_tenant = tenant(&store, mine, "mine").await;
    let expected = store
        .nominate_platform_tenant(mine, mine_tenant)
        .await
        .expect("nominate mine");

    let theirs = org(&store, "theirs").await;
    let their_tenant = tenant(&store, theirs, "theirs").await;
    let not_expected = store
        .nominate_platform_tenant(theirs, their_tenant)
        .await
        .expect("nominate theirs");

    // A third tenant of the first organization: the one a failed runbook run would carry,
    // which is not the nominated platform tenant itself.
    let ordinary = tenant(&store, mine, "ordinary").await;

    let (org_found, target) = store
        .platform_target_for_tenant(ordinary)
        .await
        .expect("resolve")
        .expect("the owning organization has nominated a resource");

    assert_eq!(org_found, mine);
    assert_eq!(target.resource_id, expected.resource_id);
    assert_ne!(
        target.resource_id, not_expected.resource_id,
        "an event about one customer's runbook must never land on another customer's \
         installation resource"
    );
}

#[tokio::test]
async fn a_tenant_whose_organization_nominated_nothing_resolves_to_nothing() {
    let store = store().await;
    let quiet = org(&store, "unnominated").await;
    let ordinary = tenant(&store, quiet, "unnominated").await;

    assert!(
        store
            .platform_target_for_tenant(ordinary)
            .await
            .expect("resolve")
            .is_none(),
        "not an error: the caller is asking where to put an event and \"nowhere\" is a \
         complete answer"
    );
}

#[tokio::test]
async fn a_tenant_that_does_not_exist_resolves_to_nothing() {
    let store = store().await;

    assert!(
        store
            .platform_target_for_tenant(TenantId::new())
            .await
            .expect("resolve")
            .is_none()
    );
}
