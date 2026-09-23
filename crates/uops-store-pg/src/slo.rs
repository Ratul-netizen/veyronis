//! Service level objectives, stored — `docs/slo.md`.
//!
//! Definitions only. The indicator is a ratio over `service_5m` and is computed where it is
//! read, for the reason migration 0029 gives: a stored attainment is wrong the moment it is
//! written, and a dashboard reading a stale one is worse than a dashboard that waits a
//! second for a fresh query.
//!
//! # What is deliberately absent
//!
//! Anything that fires. `docs/slo.md` §2.4: an objective describes a target and an alert
//! rule fires, and the thresholds that matter are the organisation's rather than the
//! product's — M11 §1's argument about detections, applied to burn rates. When burn-rate
//! alerting arrives it is an ordinary rule over the same `Query` the screen already runs,
//! not a second evaluation path.

use uops_core::{Result, TenantScope};

use crate::error::map;
use crate::store::PgStore;

/// A stored objective.
#[derive(Clone, Debug)]
pub struct Slo {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    /// The service this is about. Not a foreign key — see migration 0029.
    pub service_id: uuid::Uuid,
    /// As a proportion. `0.995` is "99.5% of requests succeeded".
    pub target: f32,
    /// Rolling, in days.
    pub window_days: i32,
}

/// What a caller supplies to set one.
#[derive(Clone, Debug)]
pub struct NewSlo {
    pub name: String,
    pub description: String,
    pub service_id: uuid::Uuid,
    pub target: f32,
    pub window_days: i32,
}

impl PgStore {
    /// Every objective in the tenant.
    ///
    /// Not paginated: an estate sets objectives in the tens, and the screen reads all of
    /// them to render — the same reasoning `sites` and `subnets` use.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn slos(&self, scope: &TenantScope) -> Result<Vec<Slo>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, name, description, service_id, target, window_days
              FROM slo
             WHERE tenant_id = $1
             ORDER BY name, window_days
            "#,
            scope.tenant_id() as uops_core::TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("slo", String::new(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| Slo {
                id: r.id,
                name: r.name,
                description: r.description,
                service_id: r.service_id,
                target: r.target,
                window_days: r.window_days,
            })
            .collect())
    }

    /// Set an objective.
    ///
    /// # Errors
    ///
    /// A conflict when this service already has an objective over this window. Two
    /// objectives on one service over one window are two numbers that will be compared and
    /// the comparison has no meaning; two *different* windows is the ordinary case.
    pub async fn set_slo(&self, scope: &TenantScope, new: &NewSlo) -> Result<Slo> {
        let row = sqlx::query!(
            r#"
            INSERT INTO slo (tenant_id, name, description, service_id, target, window_days)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, description, service_id, target, window_days
            "#,
            scope.tenant_id() as uops_core::TenantId,
            new.name,
            new.description,
            new.service_id,
            new.target,
            new.window_days,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("slo", new.name.clone(), e))?;

        Ok(Slo {
            id: row.id,
            name: row.name,
            description: row.description,
            service_id: row.service_id,
            target: row.target,
            window_days: row.window_days,
        })
    }

    /// Remove an objective.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said. One that was not there is `Ok(false)`.
    pub async fn remove_slo(&self, scope: &TenantScope, id: uuid::Uuid) -> Result<bool> {
        let done = sqlx::query!(
            "DELETE FROM slo WHERE tenant_id = $1 AND id = $2",
            scope.tenant_id() as uops_core::TenantId,
            id,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("slo", id.to_string(), e))?
        .rows_affected();

        Ok(done > 0)
    }
}
