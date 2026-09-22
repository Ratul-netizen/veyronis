//! Incidents — M9, `docs/M9-incident.md`.
//!
//! Four routes, and the shape of them is §2.1: an incident is a human's unit of work.
//!
//! * `GET  /api/v1/incidents`            — the list
//! * `GET  /api/v1/incidents/{id}/timeline` — every signal, one axis
//! * `POST /api/v1/incidents/{id}/ack`   — take responsibility
//! * `POST /api/v1/incidents/{id}/close` — say it is understood
//!
//! # There is no POST that creates one
//!
//! §2.1, and it is a deliberate absence rather than an oversight. An incident that can be
//! raised by hand is the first half of a ticketing system, and §5 says this product is not
//! one — it integrates with the system that already has assignment, SLA clocks and comment
//! threads. Incidents here are produced by the alert engine and by nothing else.
//!
//! # Roles
//!
//! Reading is `Viewer`. Acknowledging and closing are `Operator`, because both are
//! statements a person makes about the estate: *I am holding this* and *this is
//! understood*. Neither changes what is true, which is why neither needs Admin.
//!
//! **Topology suppression is the exception, and takes `Admin`.** Everything else here
//! records what somebody decided about an outage that has already happened; that setting
//! decides whether the product will decline to wake somebody up about a future one, on the
//! strength of a topology it inferred. It is the single thing in M9 that can cause a
//! missed outage — §2.4 — so it sits with the role that manages credentials and users.

use axum::Json;
use axum::extract::{Path, Query as UrlQuery, State};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uops_core::{IncidentId, ResourceId, Role};
use uops_query::{Coverage, TimeRange, resolve, timeline};
use uops_store_ch::TelemetryStore;
use uops_store_pg::{IncidentRow, PgCatalog};

use crate::csrf::CsrfChecked;
use crate::error::{ApiError, ApiResult};
use crate::extract::Caller;
use crate::state::AppState;

/// How many incidents a list returns when the caller does not say.
const DEFAULT_LIMIT: i64 = 50;

/// How far either side of an incident a timeline reaches when the caller does not say.
///
/// Fifteen minutes before it started and fifteen after its last alert. The margin is the
/// point: what happened *just before* is usually the answer, and a timeline that begins
/// exactly at the first alert has cropped it out.
const MARGIN: Duration = Duration::minutes(15);

#[derive(Debug, Deserialize)]
pub struct ListParams {
    #[serde(default)]
    pub limit: Option<i64>,
}

/// One incident as a list row.
#[derive(Debug, Serialize)]
pub struct IncidentView {
    pub id: IncidentId,
    /// `open`, `quiet` or `closed` — §2.1. `quiet` means every alert resolved and nobody
    /// has said it is understood.
    pub state: String,
    pub severity: String,
    /// The **candidate**, never the cause — §2.5. Null when there is none.
    pub candidate_resource_id: Option<ResourceId>,
    /// What to call the candidate. The id when the inventory does not know it, because
    /// an id is a fact and a placeholder is a claim.
    pub candidate_name: Option<String>,
    /// Why there is no candidate, when there is none: `no_topology` or `disconnected`.
    /// Empty when there is one. A screen that says "no likely origin" without saying why
    /// looks broken.
    pub candidate_absent_because: String,
    pub started_at: DateTime<Utc>,
    pub last_alert_at: DateTime<Utc>,
    pub quiet_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub acked_at: Option<DateTime<Utc>>,
    pub summary: String,
    /// How many alerts are in it.
    pub alerts: i64,
    /// How many of those were silenced by §2.4's topology suppression.
    ///
    /// Sent even when zero, and named for what it is: a suppression nobody can see is
    /// indistinguishable from a bug.
    pub suppressed: i64,
}

/// `GET /api/v1/incidents`
pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    UrlQuery(params): UrlQuery<ListParams>,
) -> ApiResult<Json<Vec<IncidentView>>> {
    caller.require(Role::Viewer)?;

    let rows = state
        .store
        .incidents(caller.scope(), params.limit.unwrap_or(DEFAULT_LIMIT))
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(view(&state, &caller, row).await);
    }

    caller.audit().read(
        "incidents.list",
        Some(i64::try_from(out.len()).unwrap_or(i64::MAX)),
    );
    Ok(Json(out))
}

/// Resolve the candidate's name, falling back to its id.
///
/// One lookup per incident rather than a join, because the list is fifty rows and the
/// resource may have been deleted since — in which case the id is still the honest answer
/// and a join would have produced an empty cell.
async fn view(state: &AppState, caller: &Caller, row: IncidentRow) -> IncidentView {
    let candidate_name = match row.candidate_resource_id {
        Some(id) => Some(
            state
                .store
                .resource(caller.scope(), id)
                .await
                .map_or_else(|_| id.to_string(), |r| r.display_name.unwrap_or(r.name)),
        ),
        None => None,
    };

    IncidentView {
        id: row.id,
        state: row.state,
        severity: row.severity,
        candidate_resource_id: row.candidate_resource_id,
        candidate_name,
        candidate_absent_because: row.candidate_absent_because,
        started_at: row.started_at,
        last_alert_at: row.last_alert_at,
        quiet_at: row.quiet_at,
        closed_at: row.closed_at,
        acked_at: row.acked_at,
        summary: row.summary,
        alerts: row.alerts,
        suppressed: row.suppressed,
    }
}

/// One signal's rows, and whether the window reached past what that signal keeps.
#[derive(Debug, Serialize)]
pub struct TrackView {
    pub signal: String,
    /// `whole`, `partial` or `expired` — `uops_query::Coverage`.
    ///
    /// The distinction the timeline exists to preserve: an expired signal is **not** a
    /// quiet one. An empty row with no coverage field reads as "nothing was happening",
    /// which is the opposite of "this is gone".
    pub coverage: String,
    /// Where the rows actually start, when the window was clamped to what survives.
    pub from: Option<DateTime<Utc>>,
    /// How long this signal is kept, in days — so the screen can say *why* it expired
    /// without hard-coding a number that lives in `ch-migrations/`.
    pub retention_days: i64,
    pub columns: Vec<uops_store_ch::Column>,
    pub rows: Vec<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
pub struct TimelineView {
    pub incident: IncidentId,
    /// The window read, which is the incident's plus a margin either side.
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// The resources the incident is about, in the order their alerts joined.
    pub resources: Vec<ResourceId>,
    pub tracks: Vec<TrackView>,
}

#[derive(Debug, Deserialize)]
pub struct TimelineParams {
    #[serde(default)]
    pub start: Option<DateTime<Utc>>,
    #[serde(default)]
    pub end: Option<DateTime<Utc>>,
}

/// `GET /api/v1/incidents/{id}/timeline`
///
/// Every signal for the incident's resources, on one axis — PLAN §6, and the query the
/// M0 sort key was chosen for.
pub async fn timeline_of(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    UrlQuery(params): UrlQuery<TimelineParams>,
) -> ApiResult<Json<TimelineView>> {
    caller.require(Role::Viewer)?;
    let incident = IncidentId::from_uuid(id);

    // The membership is the scope. An incident nobody can see has no members, so this
    // doubles as the tenant check — there is no separate "does it exist" lookup to get
    // out of step with it.
    let members = state
        .store
        .incident_members(caller.scope(), incident)
        .await?;
    if members.is_empty() {
        return Err(ApiError::from(uops_core::Error::NotFound {
            kind: "incident",
            id: incident.to_string(),
        }));
    }

    let resources: Vec<ResourceId> = members.iter().map(|m| m.resource_id).collect();
    let first = members
        .iter()
        .map(|m| m.first_alert_at)
        .min()
        .unwrap_or_else(Utc::now);

    let start = params.start.unwrap_or(first - MARGIN);
    let end = params.end.unwrap_or_else(|| Utc::now() + MARGIN);

    let tracks = timeline(&resources, TimeRange::new(start, end), Utc::now())
        .map_err(|e| ApiError::Internal(e.into()))?;

    let mut out = Vec::with_capacity(tracks.len());
    for track in tracks {
        let (coverage, from) = match track.coverage {
            Coverage::Whole => ("whole", None),
            Coverage::Partial { from } => ("partial", Some(from)),
            Coverage::Expired => ("expired", None),
        };

        // An expired signal is not queried at all — `uops_query::timeline` returns no
        // query for one, and issuing something anyway would spend a scan to learn what
        // the coverage already said.
        let (columns, rows) = match &track.query {
            None => (Vec::new(), Vec::new()),
            Some(query) => {
                let resolved = resolve(
                    &query.resources,
                    caller.scope(),
                    &PgCatalog::new(state.store.clone()),
                )
                .await
                .map_err(|e| ApiError::Internal(e.into()))?;

                let result = state
                    .telemetry
                    .query(query, caller.scope(), &resolved)
                    .await
                    .map_err(|e| ApiError::Internal(e.into()))?;
                (result.columns, result.rows)
            }
        };

        out.push(TrackView {
            signal: track.signal.as_str().to_owned(),
            coverage: coverage.to_owned(),
            from,
            retention_days: uops_query::retention(track.signal).num_days(),
            columns,
            rows,
        });
    }

    caller.audit().read(
        "incidents.timeline",
        Some(i64::try_from(out.iter().map(|t| t.rows.len()).sum::<usize>()).unwrap_or(i64::MAX)),
    );

    Ok(Json(TimelineView {
        incident,
        start,
        end,
        resources,
        tracks: out,
    }))
}

/// `POST /api/v1/incidents/{id}/ack`
///
/// Takes responsibility without changing what is true. The incident stays in the list,
/// still open, with a name against it — the same rule an alert acknowledgement holds.
pub async fn acknowledge(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<Json<IncidentView>> {
    caller.require(Role::Operator)?;
    let incident = IncidentId::from_uuid(id);

    state
        .store
        .acknowledge_incident(caller.scope(), incident, caller.user_id(), Utc::now())
        .await?;

    caller
        .audit()
        .wrote("incidents.ack", incident.to_string(), None, None);
    one(&state, &caller, incident).await
}

/// `POST /api/v1/incidents/{id}/close`
///
/// §2.1: **only a human closes an incident**, because closing is a claim that it is
/// understood and the machine is not in a position to make one. Every alert resolving
/// moves it to `quiet` and stops there.
///
/// Closing twice is an error rather than a no-op. It is not idempotent because it is not
/// a state to converge on — it is two people each believing they were the one who
/// understood it, and the second deserves to be told.
pub async fn close(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<Json<IncidentView>> {
    caller.require(Role::Operator)?;
    let incident = IncidentId::from_uuid(id);

    state
        .store
        .close_incident(caller.scope(), incident, caller.user_id(), Utc::now())
        .await?;

    // The before/after pair is for content changes. Closing carries neither: what
    // changed is the state, and it is in the action.
    caller
        .audit()
        .wrote("incidents.close", incident.to_string(), None, None);
    one(&state, &caller, incident).await
}

/// Whether this tenant lets topology suppression stop a notification — M9 §2.4.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuppressionView {
    pub suppress_downstream_alerts: bool,
}

/// `GET /api/v1/incidents/suppression`
///
/// `Viewer`, because "will this product decide not to page me" is a question anybody
/// carrying a pager is entitled to ask about their own tenant.
pub async fn suppression(
    State(state): State<AppState>,
    caller: Caller,
) -> ApiResult<Json<SuppressionView>> {
    caller.require(Role::Viewer)?;

    let on = state.store.suppression_enabled(caller.scope()).await?;
    caller.audit().read("incidents.suppression", None);

    Ok(Json(SuppressionView {
        suppress_downstream_alerts: on,
    }))
}

/// `PUT /api/v1/incidents/suppression`
///
/// M9 §2.4, and the criterion this route exists for: *"switching it on is a decision with
/// an audit entry rather than a default somebody inherits"*. Until this existed, it was a
/// database update and there was nothing to audit.
///
/// # Why `Admin` and not `Operator`
///
/// Every other write in this module — acknowledging, closing — records what a human
/// decided about an outage that has already happened. This one changes whether the product
/// will decline to wake somebody up about a future one, on the strength of a topology it
/// inferred. It is the single feature in M9 that can cause a **missed outage**, and the
/// role that manages credentials and users is the right one to hold it.
///
/// # Why turning it *off* is audited too
///
/// The obvious reading is that switching it on is the risky direction, so that is the one
/// to record. But the record exists to answer "why did nobody get paged in March", and the
/// answer to that is as often "it was on then and it is off now" as the reverse. An audit
/// trail that only has one edge of a toggle cannot reconstruct what was true at a time.
pub async fn set_suppression(
    State(state): State<AppState>,
    caller: Caller,
    _csrf: CsrfChecked,
    Json(body): Json<SuppressionView>,
) -> ApiResult<Json<SuppressionView>> {
    caller.require(Role::Admin)?;

    let was = state
        .store
        .set_suppression(caller.scope(), body.suppress_downstream_alerts)
        .await?;

    // Both sides, and `changed` explicitly. An operator who clicks the switch twice
    // produces one row that is a decision and one that says nothing happened, and a reader
    // should not have to diff two JSON blobs to tell which is which.
    caller.audit().wrote(
        "incidents.suppression.set",
        format!("tenant:{}", caller.scope().tenant_id()),
        Some(serde_json::json!({ "suppress_downstream_alerts": was })),
        Some(serde_json::json!({
            "suppress_downstream_alerts": body.suppress_downstream_alerts,
            "changed": was != body.suppress_downstream_alerts,
        })),
    );

    Ok(Json(SuppressionView {
        suppress_downstream_alerts: body.suppress_downstream_alerts,
    }))
}

/// Read one incident back, so a mutation returns the same shape the list does and a
/// client can drop it into the row it came from.
async fn one(state: &AppState, caller: &Caller, id: IncidentId) -> ApiResult<Json<IncidentView>> {
    let rows = state.store.incidents(caller.scope(), 500).await?;
    let row = rows
        .into_iter()
        .find(|r| r.id == id)
        .ok_or(uops_core::Error::NotFound {
            kind: "incident",
            id: id.to_string(),
        })?;
    Ok(Json(view(state, caller, row).await))
}
