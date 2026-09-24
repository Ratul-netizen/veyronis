//! Per-tenant ingest tokens against a real PostgreSQL — `docs/packaging.md` §4.2.
//!
//! The credential that makes it safe to hand an emitter to a machine somebody else
//! administers. Two of these matter more than the rest:
//!
//! `a_retired_tenants_token_stops_working` — because nothing about the alternative looks like
//! an error. A "removed" customer whose emitters keep writing produces successful inserts and a
//! disk bill, and the installation believes it stopped serving them.
//!
//! `a_token_is_scoped_to_one_tenant` — because the whole reason this table exists is that the
//! listener could not infer a tenant from the payload. A token that authorised two would be
//! worse than no token at all.

use chrono::{Duration, Utc};
use uops_core::{ActorId, OrgId, Result, Secret, TenantId, TenantScope};
use uops_secrets::password;
use uops_store_pg::{Config, PgStore};

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

struct World {
    store: PgStore,
    org: OrgId,
}

impl World {
    async fn new(slug: &str) -> Self {
        let store = store().await;
        let org = OrgId::new();
        sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
            .bind(org.into_uuid())
            .bind(format!("ing-{slug}-{}", org.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("organization");
        Self { store, org }
    }

    async fn tenant(&self, slug: &str) -> TenantId {
        let id = TenantId::new();
        sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
            .bind(id.into_uuid())
            .bind(self.org.into_uuid())
            .bind(format!("ing-{slug}"))
            .bind(format!("{slug}-{}", id.into_uuid().simple()))
            .execute(self.store.pool())
            .await
            .expect("tenant");
        id
    }

    /// Somebody to name as the minter, so `created_by` is a person rather than NULL.
    async fn admin(&self) -> ActorId {
        let hash = password::hash(&Secret::new("correct horse".to_owned())).expect("hash");
        self.store
            .create_user(
                self.org,
                &format!("ing-{}@example.test", ActorId::new().into_uuid().simple()),
                "The Administrator",
                &hash,
            )
            .await
            .expect("user")
    }
}

fn scope(t: TenantId) -> TenantScope {
    TenantScope::system(t)
}

// ---- minting and presenting --------------------------------------------------------

#[tokio::test]
async fn a_minted_token_authorises_its_own_tenant() -> Result<()> {
    let w = World::new("mint").await;
    let tenant = w.tenant("mint").await;
    let by = w.admin().await;

    let issued = w
        .store
        .issue_ingest_token(&scope(tenant), "berlin-hosts", None, Some(by))
        .await?;

    assert_eq!(
        w.store.tenant_for_ingest_token(&issued.token).await?,
        Some(tenant)
    );

    let listed = w.store.ingest_tokens(&scope(tenant)).await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].label, "berlin-hosts");
    assert_eq!(listed[0].created_by, Some(by));
    assert!(listed[0].live(Utc::now()));
    Ok(())
}

#[tokio::test]
async fn the_token_is_never_readable_again() -> Result<()> {
    let w = World::new("once").await;
    let tenant = w.tenant("once").await;

    let issued = w
        .store
        .issue_ingest_token(&scope(tenant), "shown-once", None, None)
        .await?;

    // Only the hash is stored, so nothing the operator can read back carries the token. A
    // stolen database backup must not hand the thief a set of working ingest credentials.
    let stored: Option<String> =
        sqlx::query_scalar("SELECT token_hash::text FROM ingest_token WHERE id = $1")
            .bind(issued.id)
            .fetch_one(w.store.pool())
            .await
            .expect("read");
    let stored = stored.unwrap_or_default();
    assert!(
        !stored.contains(&issued.token),
        "the token itself is in the row"
    );

    let listed = w.store.ingest_tokens(&scope(tenant)).await?;
    assert!(
        !format!("{listed:?}").contains(&issued.token),
        "the listing carries the token"
    );
    Ok(())
}

/// The reason this table exists: the listener could not infer a tenant from the payload.
#[tokio::test]
async fn a_token_is_scoped_to_one_tenant() -> Result<()> {
    let w = World::new("scoped").await;
    let mine = w.tenant("mine").await;
    let theirs = w.tenant("theirs").await;

    let issued = w
        .store
        .issue_ingest_token(&scope(mine), "mine", None, None)
        .await?;

    assert_eq!(
        w.store.tenant_for_ingest_token(&issued.token).await?,
        Some(mine),
        "it authorises the tenant it was minted for"
    );
    assert!(
        w.store.ingest_tokens(&scope(theirs)).await?.is_empty(),
        "and the other tenant cannot even see it"
    );
    // And it cannot be revoked from the other tenant, so an id from a URL proves nothing.
    assert!(
        !w.store
            .revoke_ingest_token(&scope(theirs), issued.id)
            .await?
    );
    assert_eq!(
        w.store.tenant_for_ingest_token(&issued.token).await?,
        Some(mine),
        "the failed revocation did not half-apply"
    );
    Ok(())
}

#[tokio::test]
async fn a_wrong_token_authorises_nothing() -> Result<()> {
    let w = World::new("wrong").await;
    assert_eq!(
        w.store
            .tenant_for_ingest_token("nothing anybody minted")
            .await?,
        None
    );
    Ok(())
}

// ---- revocation and expiry --------------------------------------------------------

#[tokio::test]
async fn revocation_is_immediate() -> Result<()> {
    let w = World::new("revoke").await;
    let tenant = w.tenant("revoke").await;

    let issued = w
        .store
        .issue_ingest_token(&scope(tenant), "leaving", None, None)
        .await?;
    assert!(
        w.store
            .tenant_for_ingest_token(&issued.token)
            .await?
            .is_some()
    );

    assert!(
        w.store
            .revoke_ingest_token(&scope(tenant), issued.id)
            .await?
    );
    assert_eq!(
        w.store.tenant_for_ingest_token(&issued.token).await?,
        None,
        "a revoked token must stop working now, not when something notices"
    );

    assert!(
        !w.store
            .revoke_ingest_token(&scope(tenant), issued.id)
            .await?,
        "revoking twice changed nothing, and says so"
    );

    // Still listed, because "what did we hand out" is a question about history.
    let listed = w.store.ingest_tokens(&scope(tenant)).await?;
    assert_eq!(listed.len(), 1);
    assert!(listed[0].revoked_at.is_some());
    assert!(!listed[0].live(Utc::now()));
    Ok(())
}

#[tokio::test]
async fn an_expired_token_authorises_nothing() -> Result<()> {
    let w = World::new("expired").await;
    let tenant = w.tenant("expired").await;

    let issued = w
        .store
        .issue_ingest_token(
            &scope(tenant),
            "laptop-fleet",
            // Already past: a laptop's token should expire, unlike one in a
            // configuration-management repository.
            Some(Utc::now() - Duration::hours(1)),
            None,
        )
        .await?;

    assert_eq!(w.store.tenant_for_ingest_token(&issued.token).await?, None);
    assert!(!w.store.ingest_tokens(&scope(tenant)).await?[0].live(Utc::now()));
    Ok(())
}

#[tokio::test]
async fn a_token_with_no_expiry_keeps_working() -> Result<()> {
    let w = World::new("forever").await;
    let tenant = w.tenant("forever").await;

    let issued = w
        .store
        .issue_ingest_token(&scope(tenant), "in-config-management", None, None)
        .await?;

    assert!(
        w.store
            .tenant_for_ingest_token(&issued.token)
            .await?
            .is_some(),
        "NULL means it does not expire — the right default for a token that brings up \
         emitters for years"
    );
    Ok(())
}

// ---- the one whose absence would be silent ----------------------------------------

/// A retired tenant's emitters must stop being accepted.
///
/// The same shape as the filter `all_tenant_ids` needed in 0031, and worse: there, a removed
/// customer's devices kept being *polled*, which shows up as traffic. Here the writes succeed,
/// so the installation goes on storing a customer's telemetry and billing the disk for it while
/// believing it stopped.
#[tokio::test]
async fn a_retired_tenants_token_stops_working() -> Result<()> {
    let w = World::new("retired").await;
    let keep = w.tenant("keep").await;
    let going = w.tenant("going").await;
    let by = w.admin().await;

    let issued = w
        .store
        .issue_ingest_token(&scope(going), "still-configured", None, Some(by))
        .await?;
    assert_eq!(
        w.store.tenant_for_ingest_token(&issued.token).await?,
        Some(going)
    );

    // `keep` exists so retiring `going` is not refused as the organization's last tenant.
    let _ = keep;
    assert_eq!(
        w.store.retire_tenant(w.org, going).await?,
        uops_store_pg::TenantChange::Done
    );

    assert_eq!(
        w.store.tenant_for_ingest_token(&issued.token).await?,
        None,
        "a retired customer's emitters are still configured and must stop being accepted"
    );

    // And it comes back with the tenant, because retirement is reversible and the token was
    // never revoked.
    assert!(w.store.restore_tenant(w.org, going).await?);
    assert_eq!(
        w.store.tenant_for_ingest_token(&issued.token).await?,
        Some(going),
        "restoring a tenant restores what it was configured with"
    );
    Ok(())
}

#[tokio::test]
async fn two_tokens_in_one_tenant_need_different_labels() -> Result<()> {
    let w = World::new("labels").await;
    let tenant = w.tenant("labels").await;

    w.store
        .issue_ingest_token(&scope(tenant), "berlin", None, None)
        .await?;
    assert!(
        w.store
            .issue_ingest_token(&scope(tenant), "berlin", None, None)
            .await
            .is_err(),
        "a label is how an operator tells two tokens apart at revocation time, so two with \
         one name is a list nobody can act on"
    );

    // The same label in another tenant is fine: it is that tenant's name for its own token.
    let other = w.tenant("other").await;
    assert!(
        w.store
            .issue_ingest_token(&scope(other), "berlin", None, None)
            .await
            .is_ok()
    );
    Ok(())
}
