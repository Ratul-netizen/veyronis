//! Service level objectives — `docs/slo.md`.
//!
//! Definitions in and out. The indicator is computed where it is read, from the same
//! `Query` AST the Services screen uses — §3 of the doc records why that is not a
//! shortcut: putting it here would mean a second code path computing what the Services
//! screen already computes, and SPEC §M0.5 puts this class of arithmetic in the client.
//!
//! # Validation here, constraints in the schema
//!
//! Both, and the duplication is the one this codebase makes on purpose: the `CHECK` in
//! migration 0029 is the guarantee and these are the messages somebody can act on. A
//! target of `99` rather than `0.99` is the most common way to get this wrong, and a
//! constraint violation would tell the operator about a check constraint rather than about
//! their number.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use uops_core::{Error as CoreError, Role};
use uops_store_pg::NewSlo;

use crate::csrf::CsrfChecked;
use crate::error::ApiResult;
use crate::extract::Caller;
use crate::state::AppState;

/// The longest window an objective may cover, in days.
///
/// `service_5m` keeps a year, so this is not a storage limit. Ninety days is where an
/// objective stops being an operational instrument and becomes a business report.
const MAX_WINDOW_DAYS: i32 = 90;

/// One objective.
///
/// No attainment field. The SLI is a ratio over sampled spans and is computed at read
/// time — and `docs/slo.md` §2.2 is explicit that the ratio is sound over a sample while a
/// remaining *count* of errors is not, because the sampling denominator is unknown.
#[derive(Debug, Serialize)]
pub struct SloView {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub service_id: uuid::Uuid,
    pub target: f32,
    pub window_days: i32,
}

/// `GET /api/v1/slos`
pub async fn list(State(state): State<AppState>, caller: Caller) -> ApiResult<Json<Vec<SloView>>> {
    caller.require(Role::Viewer)?;

    let rows = state.store.slos(caller.scope()).await?;
    caller.audit().read(
        "slo.list",
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(
        rows.into_iter()
            .map(|s| SloView {
                id: s.id,
                name: s.name,
                description: s.description,
                service_id: s.service_id,
                target: s.target,
                window_days: s.window_days,
            })
            .collect(),
    ))
}

/// What a client sends to set one.
#[derive(Debug, Deserialize)]
pub struct Objective {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub service_id: uuid::Uuid,
    /// A proportion, not a percentage.
    pub target: f32,
    pub window_days: i32,
}

/// `POST /api/v1/slos`
///
/// Operator, not viewer: an objective is a statement about what the organisation considers
/// acceptable, and everybody reads it.
pub async fn set(
    State(state): State<AppState>,
    caller: Caller,
    _csrf: CsrfChecked,
    Json(body): Json<Objective>,
) -> ApiResult<(StatusCode, Json<SloView>)> {
    caller.require(Role::Operator)?;

    if body.name.trim().is_empty() {
        return Err(CoreError::Invalid("`name` must not be empty".to_owned()).into());
    }

    // The common mistake, named specifically. 99 is not a proportion, and a caller who
    // sent it meant 0.99 — saying so is more useful than reporting a range.
    if body.target > 1.0 {
        return Err(CoreError::Invalid(format!(
            "`target` is a proportion rather than a percentage: {} should be {}",
            body.target,
            body.target / 100.0
        ))
        .into());
    }

    // 1.0 has no error budget at all, and every burn rate divides by (1 - target).
    if !(body.target > 0.5 && body.target < 1.0) {
        return Err(CoreError::Invalid(
            "`target` must be above 0.5 and below 1 — an objective of 1 leaves no error \
             budget, and one below 0.5 tolerates most requests failing"
                .to_owned(),
        )
        .into());
    }

    if !(1..=MAX_WINDOW_DAYS).contains(&body.window_days) {
        return Err(CoreError::Invalid(format!(
            "`window_days` must be between 1 and {MAX_WINDOW_DAYS} — a window of hours is a \
             monitor rather than an objective, and one beyond a quarter is a report"
        ))
        .into());
    }

    let created = state
        .store
        .set_slo(
            caller.scope(),
            &NewSlo {
                name: body.name.trim().to_owned(),
                description: body.description,
                service_id: body.service_id,
                target: body.target,
                window_days: body.window_days,
            },
        )
        .await?;

    caller.audit().wrote(
        "slo.set",
        format!("slo:{}", created.id),
        None,
        Some(serde_json::json!({
            "service_id": created.service_id,
            "target": created.target,
            "window_days": created.window_days,
        })),
    );

    Ok((
        StatusCode::CREATED,
        Json(SloView {
            id: created.id,
            name: created.name,
            description: created.description,
            service_id: created.service_id,
            target: created.target,
            window_days: created.window_days,
        }),
    ))
}

/// `DELETE /api/v1/slos/{id}`
pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    caller.require(Role::Operator)?;

    if !state.store.remove_slo(caller.scope(), id).await? {
        return Err(CoreError::NotFound {
            kind: "slo",
            id: id.to_string(),
        }
        .into());
    }

    caller
        .audit()
        .wrote("slo.remove", format!("slo:{id}"), None, None);

    Ok(StatusCode::NO_CONTENT)
}
