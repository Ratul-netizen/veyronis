//! The collector inventory — M12 §2.3.
//!
//! Every route here takes [`OrgAdmin`], for the reason it was introduced in §2.2: a
//! collector assignment decides whose telemetry a box may carry, and in an MSP that is a
//! decision about somebody other than the person making it. Admin on one tenant is not
//! enough.
//!
//! # There is no enrolment route
//!
//! A collector enrols through `PostgreSQL`, which it already holds credentials for — see
//! `uops_store_pg::collectors` and migration 0025 for why that is the honest shape today
//! and what would change it. What is here is the operator's half: minting a token,
//! reading the inventory, and deciding which customers a collector may carry.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use uops_core::TenantId;
use uops_store_pg::Kind;

use crate::csrf::CsrfChecked;
use crate::error::{ApiError, ApiResult};
use crate::extract::OrgAdmin;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct CollectorResponse {
    pub id: String,
    pub kind: &'static str,
    pub name: String,
    pub hostname: Option<String>,
    pub version: Option<String>,
    /// What it says it is bound to. Shape varies by kind — see the `reported` column.
    pub reported: Option<serde_json::Value>,
    pub enrolled_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub received: i64,
    pub written: i64,
    pub lost: i64,
    pub retired: bool,
    /// Computed server-side rather than from `last_seen_at` in the browser: the
    /// threshold is a product decision and a client that applied its own would disagree
    /// with the server about whether a site is down.
    pub quiet: bool,
    /// Enrolled and never reported, which is a misconfiguration rather than an outage.
    pub never_reported: bool,
    pub tenants: Vec<TenantId>,
}

/// `GET /api/v1/collectors`
pub async fn list(
    State(state): State<AppState>,
    admin: OrgAdmin,
) -> ApiResult<Json<Vec<CollectorResponse>>> {
    let rows = state
        .store
        .collectors(admin.org_id)
        .await?
        .into_iter()
        .map(|c| CollectorResponse {
            id: c.id.to_string(),
            kind: c.kind.as_str(),
            name: c.name,
            hostname: c.hostname,
            version: c.version,
            reported: c.reported,
            enrolled_at: c.enrolled_at,
            last_seen_at: c.last_seen_at,
            started_at: c.started_at,
            received: c.received,
            written: c.written,
            lost: c.lost,
            retired: c.retired,
            quiet: c.quiet,
            never_reported: c.never_reported,
            tenants: c.tenants,
        })
        .collect();
    Ok(Json(rows))
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub id: String,
    pub label: String,
    pub kind: Option<&'static str>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub uses_left: Option<i32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked: bool,
}

/// `GET /api/v1/collectors/tokens`
///
/// Without the tokens. Only their hashes are stored, so there is nothing here to return
/// even if it were wise to.
pub async fn list_tokens(
    State(state): State<AppState>,
    admin: OrgAdmin,
) -> ApiResult<Json<Vec<TokenResponse>>> {
    let rows = state
        .store
        .enrolment_tokens(admin.org_id)
        .await?
        .into_iter()
        .map(|t| TokenResponse {
            id: t.id.to_string(),
            label: t.label,
            kind: t.kind.map(Kind::as_str),
            expires_at: t.expires_at,
            uses_left: t.uses_left,
            created_at: t.created_at,
            revoked: t.revoked,
        })
        .collect();
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
pub struct IssueToken {
    pub label: String,
    /// Restrict to one kind of collector, or absent for any.
    pub kind: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Absent means unlimited, which is the right default for a token that lives in a
    /// configuration-management repository and brings up collectors for years.
    pub uses: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct IssuedToken {
    pub id: String,
    /// **Shown once.** Only the hash is stored, so this response is the single moment the
    /// token exists — the same posture as a session token.
    pub token: String,
}

/// `POST /api/v1/collectors/tokens`
pub async fn issue_token(
    State(state): State<AppState>,
    admin: OrgAdmin,
    _csrf: CsrfChecked,
    Json(body): Json<IssueToken>,
) -> ApiResult<Response> {
    let label = body.label.trim();
    if label.is_empty() {
        return Err(ApiError::BadRequest(
            "a token needs a label; it is how somebody works out months later which site \
             this one was for"
                .to_owned(),
        ));
    }
    let kind = match body.kind.as_deref() {
        None => None,
        Some(k) => Some(parse_kind(k)?),
    };
    if body.uses.is_some_and(|n| n < 1) {
        return Err(ApiError::BadRequest(
            "a token with no uses cannot enrol anything; leave it out for unlimited".to_owned(),
        ));
    }

    let (token, id) = state
        .store
        .issue_enrolment_token(
            admin.org_id,
            label,
            kind,
            body.expires_at,
            body.uses,
            Some(admin.user_id),
        )
        .await?;

    // The token itself is never audited — an audit log that records credentials is a
    // second place to steal them from. What is recorded is that one was minted, by whom,
    // and what it can do.
    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "collector.token.issue",
            &id.to_string(),
            Some(serde_json::json!({
                "label": label,
                "kind": kind.map(Kind::as_str),
                "uses": body.uses,
                "expires_at": body.expires_at,
            })),
            None,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(IssuedToken {
            id: id.to_string(),
            token,
        }),
    )
        .into_response())
}

/// `DELETE /api/v1/collectors/tokens/{id}`
///
/// Already-enrolled collectors keep working; see `revoke_enrolment_token`.
pub async fn revoke_token(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    if !state
        .store
        .revoke_enrolment_token(admin.org_id, id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "collector.token.revoke",
            &id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct AssignRequest {
    pub tenant_id: TenantId,
}

/// `POST /api/v1/collectors/{id}/tenants`
///
/// The route that decides whose telemetry a box may carry.
pub async fn assign(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
    Json(body): Json<AssignRequest>,
) -> ApiResult<StatusCode> {
    // Checked before the write, so a collector another organization owns is a 404 rather
    // than a foreign-key error. The composite key would refuse it either way; this is
    // what makes the refusal say the right thing.
    if !known(&state, &admin, id).await? {
        return Err(ApiError::NotFound);
    }

    state
        .store
        .assign_collector_tenant(admin.org_id, id, body.tenant_id, Some(admin.user_id))
        .await?;
    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "collector.assign",
            &id.to_string(),
            Some(serde_json::json!({ "tenant": body.tenant_id.to_string() })),
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/collectors/{id}/tenants`
pub async fn unassign(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    Query(body): Query<AssignRequest>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    if !state
        .store
        .unassign_collector_tenant(admin.org_id, id, body.tenant_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "collector.unassign",
            &id.to_string(),
            Some(serde_json::json!({ "tenant": body.tenant_id.to_string() })),
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/collectors/{id}`
///
/// Retires rather than deletes. A collector that comes back un-retires itself, which is
/// the honest outcome when somebody retires a box and it starts talking again.
pub async fn retire(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    if !state.store.retire_collector(admin.org_id, id).await? {
        return Err(ApiError::NotFound);
    }
    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "collector.retire",
            &id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Whether this organization has a collector with this id.
async fn known(state: &AppState, admin: &OrgAdmin, id: uuid::Uuid) -> ApiResult<bool> {
    Ok(state
        .store
        .collectors(admin.org_id)
        .await?
        .iter()
        .any(|c| c.id == id))
}

fn parse_kind(s: &str) -> ApiResult<Kind> {
    Kind::parse(s).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "{s} is not a kind of collector; they are syslog, otlp, flow and poller"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_four_kinds_parse() {
        for kind in ["syslog", "otlp", "flow", "poller"] {
            assert!(parse_kind(kind).is_ok(), "{kind}");
        }
        assert!(parse_kind("snmp").is_err());
        assert!(parse_kind("Syslog").is_err());
        assert!(parse_kind("").is_err());
    }

    #[test]
    fn the_refusal_lists_the_kinds() {
        // The operator typing this into a console has a console, not the source. The
        // message is where they find out what is allowed.
        let Err(ApiError::BadRequest(why)) = parse_kind("snmp") else {
            panic!("expected a refusal")
        };
        for kind in ["syslog", "otlp", "flow", "poller"] {
            assert!(why.contains(kind), "{why}");
        }
    }
}
