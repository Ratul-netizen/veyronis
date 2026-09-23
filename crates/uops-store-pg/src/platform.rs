//! The installation as a resource — `docs/self-monitoring.md`.
//!
//! # Why this exists
//!
//! M11 §2.4 wanted the product's own sign-ins to be detectable and found they could not be:
//! `events` is partitioned by tenant, and authentication precedes knowing one. The decision
//! document costs four ways out and recommends this one — the product monitors an estate,
//! the monitoring platform is part of an estate, and this product already has a type for
//! that.
//!
//! What it buys is that **nothing downstream changes**. A sign-in becomes an ordinary
//! `authentication` event on an ordinary resource in an ordinary tenant, so the Query AST,
//! the alert engine, incidents, the timeline, topology suppression and read auditing all
//! work exactly as they do for a switch.
//!
//! # What it does not do
//!
//! Ship detections. M11 §1's line holds for this product's own events as much as for a
//! customer's: a detection library is a content business. The product ships the events and
//! an organization writes the rule that says how many failures in how long matter to it.

use uops_core::{OrgId, ResourceId, Result, TenantId, TenantScope};

use crate::error::map;
use crate::store::PgStore;

/// Where an organization's platform events go — `docs/self-monitoring.md` §2.3.
///
/// `None` when the organization has nominated no platform tenant, which is every
/// organization with more than one tenant until somebody chooses. That is the honest
/// degradation the decision document promised: no events, exactly the behaviour before this
/// existed, rather than an event attributed to a tenant it was not about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformTarget {
    pub tenant_id: TenantId,
    pub resource_id: ResourceId,
}

impl PlatformTarget {
    /// The scope everything about the installation is written under.
    #[must_use]
    pub const fn scope(&self) -> TenantScope {
        TenantScope::system(self.tenant_id)
    }
}

impl PgStore {
    /// The resource that *is* this installation, for one organization.
    ///
    /// Read on every sign-in, so it is one primary-key lookup and nothing else. The
    /// alternative — finding the resource by name — would be a resource somebody could
    /// rename out from under the product, which is why migration 0027 holds the id.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said. An organization that does not exist is `None` rather
    /// than an error: the caller is asking where to put an event, and "nowhere" is a
    /// complete answer.
    pub async fn platform_target(&self, org: OrgId) -> Result<Option<PlatformTarget>> {
        // tenant-exempt: the nomination is an organization-level fact, and the tenant it
        // names is the answer rather than a filter. The composite foreign key in 0027 is
        // what guarantees the tenant belongs to this organization.
        let row = sqlx::query!(
            r#"
            SELECT platform_tenant_id   AS "tenant: TenantId",
                   platform_resource_id AS "resource: ResourceId"
              FROM organization
             WHERE id = $1
            "#,
            org as OrgId,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("organization", org.to_string(), e))?;

        Ok(row.and_then(|r| match (r.tenant, r.resource) {
            // The schema's CHECK makes the mixed cases unrepresentable; matching on the
            // pair rather than unwrapping one of them is what keeps that true here.
            (Some(tenant_id), Some(resource_id)) => Some(PlatformTarget {
                tenant_id,
                resource_id,
            }),
            _ => None,
        }))
    }

    /// Nominate a tenant as an organization's platform tenant, creating the resource.
    ///
    /// Idempotent: an organization that has already nominated one keeps it, and calling
    /// again is not an error. Two replicas racing at first run must not create two
    /// installations, and the `UPDATE … WHERE platform_tenant_id IS NULL` is what decides
    /// between them rather than a check the caller makes first.
    ///
    /// # Errors
    ///
    /// [`uops_core::Error::Invalid`] when the tenant is not the organization's — which the
    /// schema refuses anyway, and this turns into a sentence.
    pub async fn nominate_platform_tenant(
        &self,
        org: OrgId,
        tenant: TenantId,
    ) -> Result<PlatformTarget> {
        if let Some(existing) = self.platform_target(org).await? {
            return Ok(existing);
        }

        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("organization", org.to_string(), e))?;

        let resource = ResourceId::new();

        // `service`, not `device`: the installation is a logical thing rather than a box.
        // It gets no `mgmt_ip`, so it is not pollable and is not a runbook target — both
        // fall out of the existing schema rather than needing a rule.
        //
        // tenant-exempt: the tenant is a bound parameter, and it is checked against the
        // organization by the composite foreign key on the UPDATE below.
        sqlx::query!(
            r#"
            INSERT INTO resource (id, tenant_id, kind, name, status, attributes)
            VALUES ($1, $2, 'service', 'This installation', 'up',
                    '{"service.name": "uops"}'::jsonb)
            "#,
            resource as ResourceId,
            tenant as TenantId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("resource", "platform".to_owned(), e))?;

        // tenant-exempt: an organization-level column.
        let claimed = sqlx::query!(
            r#"
            UPDATE organization
               SET platform_tenant_id = $2, platform_resource_id = $3
             WHERE id = $1 AND platform_tenant_id IS NULL
            "#,
            org as OrgId,
            tenant as TenantId,
            resource as ResourceId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("organization", org.to_string(), e))?
        .rows_affected();

        if claimed == 0 {
            // Somebody else nominated between the read above and here. Roll back the
            // resource this transaction created — a second "This installation" in the
            // inventory would be the visible half of a race nobody would think to look for.
            tx.rollback()
                .await
                .map_err(|e| map("organization", org.to_string(), e))?;
            return self.platform_target(org).await?.ok_or_else(|| {
                uops_core::Error::Storage(
                    "the platform tenant was claimed and then unset".to_owned(),
                )
            });
        }

        tx.commit()
            .await
            .map_err(|e| map("organization", org.to_string(), e))?;

        Ok(PlatformTarget {
            tenant_id: tenant,
            resource_id: resource,
        })
    }
}
