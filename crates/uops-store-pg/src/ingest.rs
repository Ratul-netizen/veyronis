//! Per-tenant ingest tokens — `docs/packaging.md` §4.2.
//!
//! The credential that makes it safe to hand an emitter to a machine somebody else
//! administers. Until it existed, the OTLP listener authenticated nobody and its trust
//! boundary was the network segment: whatever could reach the port wrote into its tenant.
//!
//! # What a token does and does not authorise
//!
//! It authorises **writing into one tenant**. It does *not* say which resource the sender is —
//! identity resolution decides that from what the payload says about itself, and an unknown
//! emitter becomes a provisional resource and a review item exactly as it does today. A token
//! that also asserted identity would make the resource a field the sender controls, which is
//! the thing `deploy/otlp/listeners.yaml` refuses.
//!
//! # A retired tenant's tokens stop working, and that is not the cascade
//!
//! `ingest_token.tenant_id` cascades, but since migration 0031 a tenant is *retired* rather
//! than deleted, so the cascade almost never fires. What stops a retired customer's emitters is
//! the `retired_at IS NULL` check in [`PgStore::tenant_for_ingest_token`].
//!
//! Leaving it out would be the same defect as leaving it out of `all_tenant_ids`: a tenant
//! somebody had removed would go on accepting telemetry, and the installation would keep
//! billing disk to a customer it believes it stopped serving. That one is worse, because
//! nothing about it looks like an error — the writes succeed.
//!
//! # This is the hot path
//!
//! One indexed probe on `token_hash`, and nothing else. A caller on the ingest path should
//! cache the answer for a short interval rather than ask per request; the store's job is to
//! make the question cheap and to be the authority, not to be asked a hundred thousand times a
//! second.

use chrono::{DateTime, Utc};
use uops_core::{ActorId, Result, TenantId, TenantScope};
use uops_secrets::session;

use crate::error::map;
use crate::store::PgStore;

/// A token, as an operator sees it. Never the token itself.
#[derive(Clone, Debug)]
pub struct IngestToken {
    pub id: uuid::Uuid,
    /// What somebody will recognise in six months.
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<ActorId>,
    /// `None` means it does not expire.
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl IngestToken {
    /// Whether this token would authorise a write right now.
    #[must_use]
    pub fn live(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|at| at > now)
    }
}

/// A token at the one moment it exists in the clear.
#[derive(Clone, Debug)]
pub struct IssuedToken {
    pub id: uuid::Uuid,
    /// Returned **once**. Only the hash is stored, so an operator who loses it mints another.
    pub token: String,
    pub expires_at: Option<DateTime<Utc>>,
}

impl PgStore {
    /// Mint a token for one tenant.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said, including the unique violation for a second token with the
    /// same label in one tenant.
    pub async fn issue_ingest_token(
        &self,
        scope: &TenantScope,
        label: &str,
        expires_at: Option<DateTime<Utc>>,
        by: Option<ActorId>,
    ) -> Result<IssuedToken> {
        let (token, hash) =
            session::issue().map_err(|e| uops_core::Error::Storage(e.to_string()))?;

        let row = sqlx::query!(
            r#"
            INSERT INTO ingest_token (tenant_id, label, token_hash, expires_at, created_by)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
            scope.tenant_id() as TenantId,
            label,
            hash.as_bytes().as_slice(),
            expires_at,
            by as Option<ActorId>,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("ingest token", label.to_owned(), e))?;

        Ok(IssuedToken {
            id: row.id,
            token: token.expose().to_owned(),
            expires_at,
        })
    }

    /// Every token a tenant has, without the tokens.
    ///
    /// Includes revoked and expired ones: an operator asking "what did we hand out" is asking
    /// about history, and a list that hid the revoked ones would answer a different question.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn ingest_tokens(&self, scope: &TenantScope) -> Result<Vec<IngestToken>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, label, created_at, created_by, expires_at, revoked_at
              FROM ingest_token
             WHERE tenant_id = $1
             ORDER BY created_at DESC
            "#,
            scope.tenant_id() as TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("ingest token", scope.tenant_id().to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| IngestToken {
                id: r.id,
                label: r.label,
                created_at: r.created_at,
                created_by: r.created_by.map(Into::into),
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
            })
            .collect())
    }

    /// Revoke one, with immediate effect.
    ///
    /// `false` when there is no such live token in this tenant — which is also the answer for a
    /// token belonging to another tenant, so an id from a URL proves nothing.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn revoke_ingest_token(&self, scope: &TenantScope, id: uuid::Uuid) -> Result<bool> {
        let affected = sqlx::query!(
            r#"
            UPDATE ingest_token SET revoked_at = now()
             WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
            "#,
            id,
            scope.tenant_id() as TenantId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("ingest token", id.to_string(), e))?
        .rows_affected();
        Ok(affected > 0)
    }

    /// The tenant a presented token authorises writing into, if any.
    ///
    /// **The authentication path**, and the only function here that takes no scope: the caller
    /// has a bearer token and no idea which tenant it belongs to, which is the entire question.
    ///
    /// `None` for a token that is wrong, revoked, expired, or whose tenant has been retired.
    /// The caller must not distinguish them — the same rule sign-in follows.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn tenant_for_ingest_token(&self, token: &str) -> Result<Option<TenantId>> {
        let hash = session::hash_of(token);

        // tenant-exempt: the presenter of a token has no tenant until this answers. The join is
        // what restricts the answer, and `t.retired_at IS NULL` is what stops a retired
        // customer's emitters — see the module docs on why that is not the cascade's job.
        let row = sqlx::query_scalar!(
            r#"
            SELECT i.tenant_id
              FROM ingest_token i
              JOIN tenant t ON t.id = i.tenant_id
             WHERE i.token_hash = $1
               AND i.revoked_at IS NULL
               AND (i.expires_at IS NULL OR i.expires_at > now())
               AND t.retired_at IS NULL
            "#,
            hash.as_bytes().as_slice(),
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("ingest token", String::new(), e))?;

        Ok(row.map(Into::into))
    }
}
