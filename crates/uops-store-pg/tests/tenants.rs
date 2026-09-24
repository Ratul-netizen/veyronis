//! Creating and retiring a tenant, against a real PostgreSQL — `docs/tenant-lifecycle.md`.
//!
//! Two of these matter more than the rest.
//!
//! `creating_a_tenant_does_not_lock_the_creator_out` is the one the document was written
//! around: `is_org_admin` requires admin on *every* tenant, so creating one raises the
//! denominator, and an administrator who is not granted a role on the new tenant loses
//! organization-wide admin the instant it commits — permanently, because creating a tenant
//! requires it.
//!
//! `a_retired_tenant_leaves_the_scheduling_loops` is the other half. Four loops call
//! `all_tenant_ids` every turn; without the filter, a tenant somebody had removed would go
//! on being polled and alerted on, which means the product still reaching into a customer's
//! network after being told to stop.

use uops_core::{ActorId, OrgId, Result, Role, Secret, TenantId};
use uops_secrets::password;
use uops_store_pg::{Config, PgStore, TenantChange};

fn url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into())
}

async fn store() -> PgStore {
    PgStore::connect(&Config {
        url: url(),
        ..Config::default()
    })
    .await
    .expect("connect")
}

/// A first run: one organization, one tenant, one administrator on it.
struct World {
    store: PgStore,
    org: OrgId,
    first: TenantId,
    admin: ActorId,
}

impl World {
    async fn new(slug: &str) -> Self {
        let store = store().await;
        let org = OrgId::new();
        sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
            .bind(org.into_uuid())
            .bind(format!("tl-{slug}-{}", org.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("organization");

        let first = TenantId::new();
        sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
            .bind(first.into_uuid())
            .bind(org.into_uuid())
            .bind(format!("tl-{slug}"))
            .bind(format!("{slug}-{}", first.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("tenant");

        let hash = password::hash(&Secret::new("correct horse".to_owned())).expect("hash");
        let admin = store
            .create_user(
                org,
                &format!("admin-{}@example.test", first.into_uuid().simple()),
                "The Administrator",
                &hash,
            )
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
        }
    }

    fn slug(label: &str) -> String {
        format!("{label}-{}", ActorId::new().into_uuid().simple())
    }
}

// ---- creating -----------------------------------------------------------------------

/// **The reason this document exists.** Creating a tenant raises the denominator in
/// `is_org_admin`, so without the grant in the same transaction the creator loses
/// organization-wide admin the instant it commits — and cannot get it back, because creating
/// a tenant requires it.
#[tokio::test]
async fn creating_a_tenant_does_not_lock_the_creator_out() -> Result<()> {
    let w = World::new("lockout").await;
    assert!(
        w.store.is_org_admin(w.admin, w.org).await?,
        "they start as an administrator of the whole organization"
    );

    let created = w
        .store
        .create_tenant(w.org, "Second Customer", &World::slug("second"), w.admin)
        .await?
        .expect("created");

    assert!(
        w.store.is_org_admin(w.admin, w.org).await?,
        "and they still are, which only holds because the grant is in the same transaction"
    );
    assert_eq!(
        w.store.role_for(w.admin, created.id).await?,
        Some(Role::Admin),
        "somebody has to be able to administer a brand-new tenant, and it is whoever made it"
    );
    Ok(())
}

#[tokio::test]
async fn the_grant_names_the_creator_rather_than_nobody() -> Result<()> {
    let w = World::new("provenance").await;
    let created = w
        .store
        .create_tenant(w.org, "Named", &World::slug("named"), w.admin)
        .await?
        .expect("created");

    let granted_by: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT granted_by FROM user_tenant_role WHERE user_id = $1 AND tenant_id = $2",
    )
    .bind(w.admin.into_uuid())
    .bind(created.id.into_uuid())
    .fetch_one(w.store.pool())
    .await
    .expect("read");

    assert_eq!(
        granted_by,
        Some(w.admin.into_uuid()),
        "they granted it to themselves by creating the tenant, which is true and worth saying"
    );
    Ok(())
}

#[tokio::test]
async fn a_new_tenant_is_scheduled_without_a_restart() -> Result<()> {
    let w = World::new("scheduled").await;
    let created = w
        .store
        .create_tenant(w.org, "Fresh", &World::slug("fresh"), w.admin)
        .await?
        .expect("created");

    // What every scheduling loop asks on each turn. `uops-sweeper`'s own docs say why: "the
    // loop asks `all_tenant_ids` every turn so a tenant created a minute ago is swept."
    assert!(
        w.store.all_tenant_ids().await?.contains(&created.id),
        "no restart, no cache invalidation, no fleet reload"
    );
    Ok(())
}

#[tokio::test]
async fn a_malformed_slug_is_refused_by_the_database() -> Result<()> {
    let w = World::new("badslug").await;

    for bad in ["Has Capitals", "has spaces", "-leading", "trailing-", "a", "under_score"] {
        let outcome = w.store.create_tenant(w.org, "Bad", bad, w.admin).await;
        assert!(
            outcome.is_err(),
            "the constraint is in the schema because the route is not the only writer — \
             `bootstrap` writes one too. {bad:?} was accepted"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_slug_is_taken_within_an_organization_and_free_across_them() -> Result<()> {
    let mine = World::new("slugmine").await;
    let theirs = World::new("slugtheirs").await;
    let shared = World::slug("shared");

    assert!(
        mine.store
            .create_tenant(mine.org, "Mine", &shared, mine.admin)
            .await?
            .is_ok()
    );
    assert_eq!(
        mine.store
            .create_tenant(mine.org, "Again", &shared, mine.admin)
            .await?
            .expect_err("refused"),
        TenantChange::SlugTaken
    );
    assert!(
        theirs
            .store
            .create_tenant(theirs.org, "Theirs", &shared, theirs.admin)
            .await?
            .is_ok(),
        "one organization's names are not another's to run out of"
    );
    Ok(())
}

// ---- retiring -----------------------------------------------------------------------

/// The other half of §4.2. Without the filter in `all_tenant_ids` a removed tenant keeps
/// being polled, swept and alerted on — the product still reaching into a customer's network
/// after being told to stop.
#[tokio::test]
async fn a_retired_tenant_leaves_the_scheduling_loops() -> Result<()> {
    let w = World::new("loops").await;
    let created = w
        .store
        .create_tenant(w.org, "Leaving", &World::slug("leaving"), w.admin)
        .await?
        .expect("created");
    assert!(w.store.all_tenant_ids().await?.contains(&created.id));

    assert_eq!(
        w.store.retire_tenant(w.org, created.id).await?,
        TenantChange::Done
    );

    assert!(
        !w.store.all_tenant_ids().await?.contains(&created.id),
        "the loops stop reaching its devices"
    );
    Ok(())
}

#[tokio::test]
async fn retiring_does_not_change_organization_admin() -> Result<()> {
    let w = World::new("orgadmin").await;
    let created = w
        .store
        .create_tenant(w.org, "Temporary", &World::slug("temp"), w.admin)
        .await?
        .expect("created");
    assert!(w.store.is_org_admin(w.admin, w.org).await?);

    // Somebody else holds the new tenant and the creator's role on it is removed, so the
    // creator is no longer admin everywhere.
    let other = w
        .store
        .create_user(
            w.org,
            &format!("other-{}@example.test", ActorId::new().into_uuid().simple()),
            "Somebody Else",
            &password::hash(&Secret::new("correct horse".to_owned())).expect("hash"),
        )
        .await?;
    w.store
        .grant_role(other, created.id, Role::Admin, None)
        .await?;
    w.store.revoke_role(w.admin, created.id).await?;
    assert!(
        !w.store.is_org_admin(w.admin, w.org).await?,
        "they hold admin on one of two tenants"
    );

    // Retiring that tenant restores it, which is the point of the filter in `is_org_admin`:
    // a retired tenant nobody administers must not break `OrgAdmin` for everyone, forever.
    assert_eq!(
        w.store.retire_tenant(w.org, created.id).await?,
        TenantChange::Done
    );
    assert!(
        w.store.is_org_admin(w.admin, w.org).await?,
        "a retired tenant is not one anybody has to hold admin on"
    );
    Ok(())
}

#[tokio::test]
async fn the_last_live_tenant_cannot_be_retired() -> Result<()> {
    let w = World::new("lasttenant").await;

    assert_eq!(
        w.store.retire_tenant(w.org, w.first).await?,
        TenantChange::WouldLeaveNoTenant,
        "an installation with no tenants is one nobody can get back into — `is_org_admin` \
         needs `total > 0`"
    );

    // With a second one it is allowed, so the rule is about the organization keeping one
    // rather than about this tenant being special.
    w.store
        .create_tenant(w.org, "Second", &World::slug("second"), w.admin)
        .await?
        .expect("created");
    assert_eq!(
        w.store.retire_tenant(w.org, w.first).await?,
        TenantChange::Done
    );
    Ok(())
}

#[tokio::test]
async fn the_nominated_platform_tenant_cannot_be_retired() -> Result<()> {
    let w = World::new("platform").await;
    w.store.nominate_platform_tenant(w.org, w.first).await?;
    w.store
        .create_tenant(w.org, "Second", &World::slug("second"), w.admin)
        .await?
        .expect("created");

    assert_eq!(
        w.store.retire_tenant(w.org, w.first).await?,
        TenantChange::IsThePlatformTenant,
        "it carries the installation's own events, and the answer is a sentence naming what \
         to do first rather than a foreign-key violation"
    );
    Ok(())
}

#[tokio::test]
async fn retiring_keeps_everything_that_says_what_the_estate_was() -> Result<()> {
    let w = World::new("keeps").await;
    let created = w
        .store
        .create_tenant(w.org, "Kept", &World::slug("kept"), w.admin)
        .await?
        .expect("created");

    // A site and a resource, which are two of the eight tables whose foreign keys refuse to
    // cascade. Their survival *is* the decision §4.1 records.
    let site = uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext));
    sqlx::query("INSERT INTO site (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(site)
        .bind(created.id.into_uuid())
        .bind("A Building")
        .execute(w.store.pool())
        .await
        .expect("site");
    let resource = uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext));
    sqlx::query(
        "INSERT INTO resource (id, tenant_id, site_id, kind, name, status)
         VALUES ($1, $2, $3, 'device', 'A Switch', 'up')",
    )
    .bind(resource)
    .bind(created.id.into_uuid())
    .bind(site)
    .execute(w.store.pool())
    .await
    .expect("resource");

    assert_eq!(
        w.store.retire_tenant(w.org, created.id).await?,
        TenantChange::Done
    );

    let still: i64 = sqlx::query_scalar("SELECT count(*) FROM resource WHERE tenant_id = $1")
        .bind(created.id.into_uuid())
        .fetch_one(w.store.pool())
        .await
        .expect("count");
    assert_eq!(still, 1, "retirement is not deletion");

    assert!(w.store.restore_tenant(w.org, created.id).await?);
    assert!(
        w.store.all_tenant_ids().await?.contains(&created.id),
        "and it comes back with its estate intact"
    );
    Ok(())
}

#[tokio::test]
async fn another_organizations_tenant_cannot_be_touched() -> Result<()> {
    let mine = World::new("xmine").await;
    let theirs = World::new("xtheirs").await;
    theirs
        .store
        .create_tenant(theirs.org, "Spare", &World::slug("spare"), theirs.admin)
        .await?
        .expect("created");

    assert_eq!(
        mine.store.retire_tenant(mine.org, theirs.first).await?,
        TenantChange::NoSuchTenant
    );
    assert!(!mine.store.restore_tenant(mine.org, theirs.first).await?);
    assert_eq!(
        mine.store
            .rename_tenant(mine.org, theirs.first, "Renamed", &World::slug("renamed"))
            .await?,
        TenantChange::NoSuchTenant
    );

    assert!(
        theirs.store.all_tenant_ids().await?.contains(&theirs.first),
        "and none of it happened"
    );
    Ok(())
}

// ---- renaming -----------------------------------------------------------------------

#[tokio::test]
async fn a_tenant_can_be_renamed_and_keeps_its_id() -> Result<()> {
    let w = World::new("rename").await;
    let fresh = World::slug("renamed");

    assert_eq!(
        w.store.rename_tenant(w.org, w.first, "New Name", &fresh).await?,
        TenantChange::Done
    );

    let listed = w
        .store
        .tenants_in_org(w.org)
        .await?
        .into_iter()
        .find(|t| t.id == w.first)
        .expect("still there");
    assert_eq!(listed.name, "New Name");
    assert_eq!(listed.slug, fresh);
    assert_eq!(
        listed.id, w.first,
        "the id is what every audit row and every header names, and it does not move"
    );
    Ok(())
}

#[tokio::test]
async fn a_rename_cannot_take_another_tenants_slug_including_a_retired_one() -> Result<()> {
    let w = World::new("collide").await;
    let second = w
        .store
        .create_tenant(w.org, "Second", &World::slug("second"), w.admin)
        .await?
        .expect("created");

    assert_eq!(
        w.store
            .rename_tenant(w.org, w.first, "Clash", &second.slug)
            .await?,
        TenantChange::SlugTaken
    );

    // And still taken once it is retired: restoring it must not collide, and reusing a former
    // customer's name would make every audit row that referenced it ambiguous.
    w.store.retire_tenant(w.org, second.id).await?;
    assert_eq!(
        w.store
            .rename_tenant(w.org, w.first, "Clash", &second.slug)
            .await?,
        TenantChange::SlugTaken
    );
    Ok(())
}

#[tokio::test]
async fn the_list_shows_retired_tenants_and_who_would_lose_access() -> Result<()> {
    let w = World::new("list").await;
    let second = w
        .store
        .create_tenant(w.org, "Second", &World::slug("second"), w.admin)
        .await?
        .expect("created");
    w.store.retire_tenant(w.org, second.id).await?;

    let listed = w.store.tenants_in_org(w.org).await?;
    let retired = listed
        .iter()
        .find(|t| t.id == second.id)
        .expect("an administrator who cannot see it cannot restore it");
    assert!(retired.retired_at.is_some());
    assert_eq!(
        retired.members, 1,
        "how many people would lose access, answerable before retiring one"
    );
    assert!(
        listed.first().is_some_and(|t| t.retired_at.is_none()),
        "live ones first: {listed:?}"
    );
    Ok(())
}
