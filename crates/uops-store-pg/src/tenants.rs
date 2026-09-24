//! Creating and retiring a tenant — `docs/tenant-lifecycle.md`.
//!
//! Until this module existed the only `INSERT INTO tenant` outside tests was in
//! `bootstrap_first_run`, which runs once, so an installation had exactly one tenant
//! permanently — and `TenantScope`, enforced by the type system and asserted across every
//! route, guarded a boundary production could only ever have one side of.
//!
//! # The lockout this module is shaped around
//!
//! `is_org_admin` is `total > 0 && held == total`: admin on **every** tenant in the
//! organization. Creating a tenant raises `total`. So an administrator who creates one
//! without being granted a role on it holds admin on *n* of *n+1* tenants, loses `OrgAdmin`
//! the instant the insert commits, and cannot get it back — because creating a tenant
//! requires `OrgAdmin`. A feature whose first successful use locks the organization out of
//! its own settings.
//!
//! So [`PgStore::create_tenant`] grants the creator `admin` on the new tenant **in the same
//! transaction**, and it is not optional. That is also the answer to *who administers a
//! brand-new tenant*, which would otherwise need a rule of its own.
//!
//! # Retirement, not deletion
//!
//! §4.1: `DELETE FROM tenant` already fails on any tenant that has ever held a resource,
//! because eight of the twenty-seven foreign keys refuse rather than cascade — and the eight
//! are the identity tables. The schema decided this before anybody wrote it down. What this
//! module adds is the reversible state, and the two filters that make it mean something:
//! `all_tenant_ids` and `is_org_admin`.

use chrono::{DateTime, Utc};
use uops_core::{ActorId, OrgId, Result, Role, TenantId};

use crate::error::map;
use crate::store::PgStore;

/// One tenant, as an administrator sees it.
#[derive(Clone, Debug)]
pub struct TenantRow {
    pub id: TenantId,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    /// Set when retired. Reversible, and not deletion.
    pub retired_at: Option<DateTime<Utc>>,
    /// Whether this is the tenant carrying the installation's own events —
    /// `docs/self-monitoring.md` §4. It cannot be retired while it is.
    pub is_platform: bool,
    /// How many people hold a role on it. Shown so that "who would lose access" is
    /// answerable before retiring one.
    pub members: i64,
}

/// What happened to a change that has to leave an installation usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantChange {
    Done,
    /// No such tenant in this organization.
    NoSuchTenant,
    /// Refused: it is the organization's last live tenant, and an installation with none is
    /// one nobody can get back into — `is_org_admin` needs `total > 0`.
    WouldLeaveNoTenant,
    /// Refused: it is the nominated platform tenant. Nominate another first.
    IsThePlatformTenant,
    /// The slug is taken by another tenant in this organization, including a retired one.
    SlugTaken,
}

impl PgStore {
    /// Every tenant in an organization, including retired ones.
    ///
    /// Retired ones are included for the same reason a suspended user is: an administrator
    /// who cannot see one cannot restore it, and a list that silently omits things is how
    /// somebody concludes a customer was deleted.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn tenants_in_org(&self, org: OrgId) -> Result<Vec<TenantRow>> {
        // tenant-exempt: the list of an organization's tenants cannot itself be filtered by
        // tenant — the same reason `all_tenant_ids` carries this marker.
        let rows = sqlx::query!(
            r#"
            SELECT t.id, t.name, t.slug, t.created_at, t.retired_at,
                   -- `IS NOT DISTINCT FROM`, not `=`: an organization that has nominated
                   -- nothing has a NULL here, and `NULL = t.id` is NULL rather than false,
                   -- which the `!` on the alias would then refuse to decode. Three-valued
                   -- logic, caught by asserting non-null rather than by hoping.
                   (o.platform_tenant_id IS NOT DISTINCT FROM t.id) AS "is_platform!",
                   (SELECT count(*) FROM user_tenant_role r WHERE r.tenant_id = t.id)
                       AS "members!"
              FROM tenant t
              JOIN organization o ON o.id = t.org_id
             WHERE t.org_id = $1
             ORDER BY t.retired_at NULLS FIRST, t.created_at, t.id
            "#,
            org as OrgId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("tenant", org.to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| TenantRow {
                id: r.id.into(),
                name: r.name,
                slug: r.slug,
                created_at: r.created_at,
                retired_at: r.retired_at,
                is_platform: r.is_platform,
                members: r.members,
            })
            .collect())
    }

    /// Create a tenant, and make its creator an administrator of it in the same transaction.
    ///
    /// **The grant is not optional** — see the module docs. Without it the creating
    /// administrator loses `OrgAdmin` the moment this commits, and nothing inside the product
    /// can repair that.
    ///
    /// `granted_by` names the creator, which is true: they granted it to themselves, by
    /// creating the tenant.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said, including [`uops_core::Error::Invalid`] for a slug the
    /// format constraint refuses.
    pub async fn create_tenant(
        &self,
        org: OrgId,
        name: &str,
        slug: &str,
        by: ActorId,
    ) -> Result<std::result::Result<TenantRow, TenantChange>> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("tenant", slug.to_owned(), e))?;

        // Taken by a live *or* retired tenant: nothing releases a retired slug, because
        // restoring one must not collide and because reusing a former customer's name would
        // make every audit row that referenced it ambiguous.
        // tenant-exempt: this creates a tenant, so there is no tenant to scope it to.
        let taken = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM tenant WHERE org_id = $1 AND slug = $2) AS "t!""#,
            org as OrgId,
            slug,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("tenant", slug.to_owned(), e))?;

        if taken {
            return Ok(Err(TenantChange::SlugTaken));
        }

        let id = TenantId::new();

        // tenant-exempt: as above. `bootstrap` carries the same marker for the same
        // statement, and for the same reason.
        let created = sqlx::query!(
            r#"
            INSERT INTO tenant (id, org_id, name, slug)
            VALUES ($1, $2, $3, $4)
            RETURNING created_at
            "#,
            id as TenantId,
            org as OrgId,
            name,
            slug,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("tenant", slug.to_owned(), e))?;

        // The statement `grant_role` runs, shared rather than copied — and the reason this
        // whole function is a transaction. See the module docs for what happens without it.
        Self::grant_role_on(&mut *tx, by, id, Role::Admin, Some(by)).await?;

        tx.commit()
            .await
            .map_err(|e| map("tenant", slug.to_owned(), e))?;

        Ok(Ok(TenantRow {
            id,
            name: name.to_owned(),
            slug: slug.to_owned(),
            created_at: created.created_at,
            retired_at: None,
            is_platform: false,
            members: 1,
        }))
    }

    /// Rename a tenant, or change its slug.
    ///
    /// Both are permitted. `docs/tenant-lifecycle.md` §3.2 declines to declare the slug
    /// immutable, because nothing durable references it: `X-Uops-Tenant` carries a UUID, the
    /// audit and access logs key on `tenant_id`, and the slug reaches the interface only
    /// through the tenant switcher. Inventing immutability would be a rule that reads as a
    /// safeguard and protects nothing.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said, including the format constraint.
    pub async fn rename_tenant(
        &self,
        org: OrgId,
        id: TenantId,
        name: &str,
        slug: &str,
    ) -> Result<TenantChange> {
        // tenant-exempt: the tenant is the bound parameter and the organization is the
        // authorisation, not a filter on somebody's data.
        let taken = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM tenant WHERE org_id = $1 AND slug = $2 AND id <> $3
            ) AS "t!"
            "#,
            org as OrgId,
            slug,
            id as TenantId,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("tenant", slug.to_owned(), e))?;

        if taken {
            return Ok(TenantChange::SlugTaken);
        }

        // tenant-exempt: as above.
        let affected = sqlx::query!(
            r#"UPDATE tenant SET name = $3, slug = $4 WHERE id = $1 AND org_id = $2"#,
            id as TenantId,
            org as OrgId,
            name,
            slug,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("tenant", slug.to_owned(), e))?
        .rows_affected();

        Ok(if affected > 0 {
            TenantChange::Done
        } else {
            TenantChange::NoSuchTenant
        })
    }

    /// Retire a tenant: stop scheduling against it, and hide it.
    ///
    /// **Telemetry is not touched.** §4.3: there is no cross-store transaction, the
    /// `ClickHouse` tables are partitioned by day rather than by tenant, and `tenant_id` is
    /// first in every sort key — so a retired tenant's rows are inert rather than slow, and
    /// they age out on their own. A purge is a separate, explicitly-requested operation that
    /// is not built.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn retire_tenant(&self, org: OrgId, id: TenantId) -> Result<TenantChange> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("tenant", id.to_string(), e))?;

        // The whole decision, in one read, under the transaction that acts on it: does this
        // tenant exist here, is it the nominated platform resource's tenant, and is it the
        // last live one. Read together so the three answers cannot disagree.
        //
        // tenant-exempt: two of the three questions are about the organization, so no single
        // tenant scope could ask them.
        let state = sqlx::query!(
            r#"
            SELECT t.retired_at IS NOT NULL       AS "already!",
                   -- See `tenants_in_org` for why this is not `=`.
                   (o.platform_tenant_id IS NOT DISTINCT FROM t.id)
                                                  AS "is_platform!",
                   (SELECT count(*) FROM tenant others
                     WHERE others.org_id = t.org_id
                       AND others.retired_at IS NULL
                       AND others.id <> t.id)     AS "other_live!"
              FROM tenant t
              JOIN organization o ON o.id = t.org_id
             WHERE t.id = $1 AND t.org_id = $2
               FOR UPDATE OF t
            "#,
            id as TenantId,
            org as OrgId,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map("tenant", id.to_string(), e))?;

        let Some(state) = state else {
            return Ok(TenantChange::NoSuchTenant);
        };

        if state.already {
            return Ok(TenantChange::Done);
        }
        if state.is_platform {
            return Ok(TenantChange::IsThePlatformTenant);
        }
        if state.other_live == 0 {
            return Ok(TenantChange::WouldLeaveNoTenant);
        }

        // tenant-exempt: as above.
        sqlx::query!(
            r#"UPDATE tenant SET retired_at = now() WHERE id = $1 AND org_id = $2"#,
            id as TenantId,
            org as OrgId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("tenant", id.to_string(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("tenant", id.to_string(), e))?;

        Ok(TenantChange::Done)
    }

    /// Bring a retired tenant back.
    ///
    /// Reversible for the same reason a suspension is (`docs/user-administration.md` §4.4):
    /// an irreversible removal forces a workaround that is worse than the thing it works
    /// around — here, a second tenant holding the same customer's estate with its identity
    /// history split across both.
    ///
    /// Its resources, identifiers, credentials, sites and identity decisions are all still
    /// there, because nothing deleted them.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn restore_tenant(&self, org: OrgId, id: TenantId) -> Result<bool> {
        // tenant-exempt: the tenant is the bound parameter and the organization is the
        // authorisation.
        let affected = sqlx::query!(
            r#"
            UPDATE tenant SET retired_at = NULL
             WHERE id = $1 AND org_id = $2 AND retired_at IS NOT NULL
            "#,
            id as TenantId,
            org as OrgId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("tenant", id.to_string(), e))?
        .rows_affected();
        Ok(affected > 0)
    }
}
