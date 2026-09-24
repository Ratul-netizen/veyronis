//! Ingest tokens — `docs/packaging.md` §4.2.
//!
//! ```text
//!   GET    /ingest/tokens        every token this tenant has, without the tokens
//!   POST   /ingest/tokens        mint one; the only moment it exists in the clear
//!   DELETE /ingest/tokens/{id}   revoke one, with immediate effect
//! ```
//!
//! Tenant-scoped and admin, unlike the collector *enrolment* tokens next door which are
//! organization-level. The difference is what each authorises: an enrolment token brings up a
//! collector, which holds database credentials and can serve any tenant assigned to it, so it
//! is an organization's decision. An ingest token authorises writing into **one** tenant, so it
//! is that tenant's own business and an admin of that tenant may mint one.
//!
//! Admin rather than operator, because a token is a credential: it lets a machine write into
//! this customer's estate until somebody revokes it, and acknowledging an alert is a different
//! kind of act.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use uops_core::{ActorId, Role};

use crate::csrf::CsrfChecked;
use crate::error::{ApiError, ApiResult};
use crate::extract::Caller;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct TokenView {
    pub id: uuid::Uuid,
    /// What somebody will recognise in six months.
    pub label: String,
    pub created_at: String,
    pub created_by: Option<ActorId>,
    /// Absent means it does not expire.
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    /// Whether it would authorise a write right now. Computed here rather than left to the
    /// screen, so "revoked" and "expired" do not each need re-deriving in TypeScript.
    pub live: bool,
}

/// `GET /api/v1/ingest/tokens`
///
/// Includes revoked and expired ones: *what did we hand out* is a question about history, and a
/// list that hid them would answer something else.
pub async fn list(State(state): State<AppState>, caller: Caller) -> ApiResult<Json<Vec<TokenView>>> {
    caller.require(Role::Admin)?;

    let now = chrono::Utc::now();
    let rows = state.store.ingest_tokens(caller.scope()).await?;

    caller.audit().read(
        "ingest.tokens",
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(
        rows.into_iter()
            .map(|t| TokenView {
                // Computed before the move, because `live` reads the fields `label` takes.
                live: t.live(now),
                id: t.id,
                label: t.label,
                created_at: t.created_at.to_rfc3339(),
                created_by: t.created_by,
                expires_at: t.expires_at.map(|d| d.to_rfc3339()),
                revoked_at: t.revoked_at.map(|d| d.to_rfc3339()),
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct NewToken {
    pub label: String,
    /// How many days until it expires. Absent means never, which is right for a token living
    /// in a configuration-management repository.
    pub expires_in_days: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct MintedToken {
    pub id: uuid::Uuid,
    pub expires_at: Option<String>,
    /// **The only moment this exists.** Only its hash is stored, so an operator who loses it
    /// mints another. Returned in the body because the product has no organization-level mail
    /// transport and an air-gapped installation may never have one — the same decision
    /// `docs/user-administration.md` §4.1 made for invitations.
    pub token: String,
}

/// `POST /api/v1/ingest/tokens`
pub async fn mint(
    State(state): State<AppState>,
    caller: Caller,
    _csrf: CsrfChecked,
    Json(body): Json<NewToken>,
) -> ApiResult<(StatusCode, Json<MintedToken>)> {
    caller.require(Role::Admin)?;

    let label = body.label.trim();
    if label.is_empty() {
        return Err(ApiError::BadRequest(
            "a label is required: at revocation time the question is which token this is, and \
             a list of hashes cannot answer it"
                .to_owned(),
        ));
    }

    let expires_at = body
        .expires_in_days
        .filter(|d| *d > 0)
        .map(|d| chrono::Utc::now() + chrono::Duration::days(i64::from(d)));

    let issued = state
        .store
        .issue_ingest_token(caller.scope(), label, expires_at, Some(caller.user_id()))
        .await
        .map_err(|e| match e {
            // The unique violation on (tenant_id, label) is a conflict rather than bad input:
            // nothing about the request was malformed.
            uops_core::Error::Invalid(_) => ApiError::Conflict(
                "a token with that label already exists here. Revoke it, or pick another name"
                    .to_owned(),
            ),
            other => ApiError::Internal(other),
        })?;

    // The label, never the token. The audit log is read by more people than this response is,
    // and a token in it is a working credential sitting in a table.
    caller.audit().wrote(
        "ingest.token.mint",
        issued.id.to_string(),
        None,
        Some(serde_json::json!({ "label": label })),
    );

    Ok((
        StatusCode::CREATED,
        Json(MintedToken {
            id: issued.id,
            expires_at: issued.expires_at.map(|d| d.to_rfc3339()),
            token: issued.token,
        }),
    ))
}

/// `DELETE /api/v1/ingest/tokens/{id}`
///
/// Immediate: the listener asks the store per request and holds no cache, so the next export
/// carrying this token is refused.
pub async fn revoke(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    caller.require(Role::Admin)?;

    if !state.store.revoke_ingest_token(caller.scope(), id).await? {
        return Err(ApiError::NotFound);
    }

    caller
        .audit()
        .wrote("ingest.token.revoke", id.to_string(), None, None);
    Ok(StatusCode::NO_CONTENT)
}
