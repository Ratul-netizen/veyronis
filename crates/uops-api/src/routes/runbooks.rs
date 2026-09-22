//! Runbooks and runs — M10.
//!
//! Every other module in here reads an estate or edits a record about one. This is the
//! only place in the API where a request ends with a command being sent to somebody's
//! core switch, and the shape of the module is set by what that means.
//!
//! # The API does not execute anything
//!
//! `POST /runs` writes a row. `uops-runner` picks it up — M10 §2.9 — because a runbook
//! step is a long, blocking, network-bound operation with an SSH handshake in it, and
//! putting one on the API's runtime is how a web request queues behind a device that is
//! not answering. Every handler here returns in milliseconds and the interesting work
//! happens in another process.
//!
//! That also means **a `202` is not a promise**. It says a run was recorded, and the run's
//! own state is the only thing that says what happened to it.
//!
//! # Roles
//!
//! Reading is `Viewer`. Writing a runbook, planning, starting, approving and cancelling
//! are all `Operator` — `Admin` is not required, because an estate where only
//! administrators may restart an interface is an estate where everybody shares the
//! administrator's password.
//!
//! **Approval is not a role.** It is *a different person*, and no role can substitute for
//! that: `uops_runbook::decide` filters out the starter's own approval, and migration
//! 0026 makes the row unrepresentable. A role check here would look like the rule and be a
//! different one.
//!
//! # What is refused, and where
//!
//! | refusal | decided by |
//! |---|---|
//! | a step that does not validate | `uops_runbook::validate`, at save |
//! | a selector matching more than the maximum | here, before a run exists — §2.7 |
//! | a template that will not render | `uops_runbook::plan`, before a run exists |
//! | a run outside its maintenance window | here — §2.7 |
//! | approving your own run | `PgStore::approve_run` and the schema |
//! | an approval that has expired | the runner, at execution — §2.5 |
//!
//! The last one is deliberately not here. An approval is fresh when it is given and stale
//! when it is used, and the gap between those is the whole point of the window.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uops_core::{ResourceId, Role};
use uops_runbook::{Approvals, Plan, Runbook, Target};
use uops_store_pg::{RunState, RunbookRow};

use crate::csrf::CsrfChecked;
use crate::error::{ApiError, ApiResult};
use crate::extract::Caller;
use crate::state::AppState;

/// How many runs a list returns.
///
/// A run history is append-only and an estate that automates seriously will accumulate
/// thousands. Fifty is a screen; the screen has no paging yet, and a limit that lies about
/// being complete is worse than one that is visibly a window.
const RUN_LIMIT: i64 = 50;

// ---- views ---------------------------------------------------------------------

/// A runbook and its current version, as the list shows it.
#[derive(Debug, Serialize)]
pub struct RunbookView {
    pub id: uuid::Uuid,
    pub version_id: uuid::Uuid,
    pub version: i32,
    pub retired: bool,
    pub created_at: DateTime<Utc>,
    #[serde(flatten)]
    pub runbook: Runbook,
    /// Whether any step changes something. Computed, because it is the first thing
    /// somebody looking at a list of runbooks wants to know and working it out client-side
    /// would be a second copy of the rule.
    pub destructive: bool,
}

fn view(row: RunbookRow) -> RunbookView {
    RunbookView {
        id: row.id,
        version_id: row.version_id,
        version: row.version,
        retired: row.retired,
        created_at: row.created_at,
        destructive: row.runbook.is_destructive(),
        runbook: row.runbook,
    }
}

/// One resource a run would act on.
#[derive(Debug, Serialize)]
pub struct TargetView {
    pub id: ResourceId,
    pub name: String,
}

/// One step, rendered for one resource.
#[derive(Debug, Serialize)]
pub struct PlannedStepView {
    pub name: String,
    pub kind: &'static str,
    pub rendered: Vec<String>,
    pub destructive: bool,
    pub runs_in_dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback: Option<String>,
}

/// What a run would do — the dry-run review screen's whole content.
#[derive(Debug, Serialize)]
pub struct PlanView {
    pub runbook: String,
    pub targets: Vec<TargetView>,
    /// Per target, because a template may render differently for each one.
    pub steps: Vec<PlanStepsView>,
    /// The sentence the confirmation shows.
    ///
    /// Built by `Plan::describe`, which says what *would run* and never what would
    /// succeed. A dry run that claimed to know the effect of `clear bgp neighbor` would be
    /// lying, and a safety feature that lies is worse than none.
    pub summary: String,
    pub total_steps: usize,
    pub destructive_steps: usize,
    /// How many approvals a real run of this would need.
    pub approvals_required: usize,
    /// Why a real run cannot start right now, when it cannot. `None` means it can.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PlanStepsView {
    pub resource: ResourceId,
    pub steps: Vec<PlannedStepView>,
}

fn plan_view(plan: &Plan, approvals: Approvals, blocked: Option<String>) -> PlanView {
    PlanView {
        runbook: plan.runbook.clone(),
        targets: plan
            .targets
            .iter()
            .map(|t| TargetView {
                id: t.id,
                name: t.name.clone(),
            })
            .collect(),
        steps: plan
            .steps
            .iter()
            .map(|(resource, steps)| PlanStepsView {
                resource: *resource,
                steps: steps
                    .iter()
                    .map(|s| PlannedStepView {
                        name: s.name.clone(),
                        kind: s.kind,
                        rendered: s.rendered.clone(),
                        destructive: s.destructive,
                        runs_in_dry_run: s.runs_in_dry_run,
                        rollback: s.rollback.clone(),
                    })
                    .collect(),
            })
            .collect(),
        summary: plan.describe(),
        total_steps: plan.total_steps(),
        destructive_steps: plan.destructive_steps(),
        approvals_required: approvals.count(),
        blocked,
    }
}

/// A run, as the list and the detail screen show it.
#[derive(Debug, Serialize)]
pub struct RunView {
    pub id: uuid::Uuid,
    pub runbook_id: uuid::Uuid,
    pub runbook_name: String,
    pub version: i32,
    pub state: RunState,
    pub dry_run: bool,
    pub targets: serde_json::Value,
    pub reason: String,
    pub started_by: uops_core::ActorId,
    /// Ran without approval. Visible for as long as the run is — M10 §2.5.
    pub break_glass: bool,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    pub approvals: Vec<ApprovalView>,
    /// Whether anything was sent to a device. The first question about a run that did not
    /// succeed, and the reason `refused` is a state of its own.
    pub touched_a_device: bool,
}

#[derive(Debug, Serialize)]
pub struct ApprovalView {
    pub approved_by: uops_core::ActorId,
    pub at: DateTime<Utc>,
}

fn run_view(row: uops_store_pg::RunRow) -> RunView {
    RunView {
        id: row.id,
        runbook_id: row.runbook_id,
        runbook_name: row.runbook_name,
        version: row.version,
        state: row.state,
        dry_run: row.dry_run,
        targets: row.targets,
        reason: row.reason,
        started_by: row.started_by,
        break_glass: row.break_glass,
        created_at: row.created_at,
        started_at: row.started_at,
        finished_at: row.finished_at,
        failure: row.failure,
        touched_a_device: row.state.touched_a_device(),
        approvals: row
            .approvals
            .into_iter()
            .map(|a| ApprovalView {
                approved_by: a.approved_by,
                at: a.at,
            })
            .collect(),
    }
}

// ---- runbooks ------------------------------------------------------------------

/// `GET /api/v1/runbooks`
pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
) -> ApiResult<Json<Vec<RunbookView>>> {
    caller.require(Role::Viewer)?;

    let rows = state.store.runbooks(caller.scope()).await?;
    caller.audit().read(
        "runbooks.list",
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(rows.into_iter().map(view).collect()))
}

/// `GET /api/v1/runbooks/{id}`
pub async fn get(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
) -> ApiResult<Json<RunbookView>> {
    caller.require(Role::Viewer)?;

    let found = state
        .store
        .runbooks(caller.scope())
        .await?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or(uops_core::Error::NotFound {
            kind: "runbook",
            id: id.to_string(),
        })?;

    caller.audit().read("runbooks.get", None);
    Ok(Json(view(found)))
}

/// `POST /api/v1/runbooks`
///
/// Creates a runbook, or saves a new version of one with the same name. There is no PUT:
/// M10 §2.1 — editing writes version *n+1* and leaves *n* readable, because a run names
/// the version it executed and "what did this actually do in March" has to have an answer
/// that does not depend on nobody having edited it since.
pub async fn save(
    State(state): State<AppState>,
    caller: Caller,
    _csrf: CsrfChecked,
    Json(body): Json<Runbook>,
) -> ApiResult<(StatusCode, Json<RunbookView>)> {
    caller.require(Role::Operator)?;

    // Every problem, not the first. An author fixing a runbook one refusal at a time is an
    // author who saves six times, and `validate` was written to return a list for exactly
    // this call site.
    let problems = uops_runbook::validate(&body);
    if !problems.is_empty() {
        return Err(refused(&problems));
    }

    let saved = state
        .store
        .save_runbook(caller.scope(), &body, Some(caller.user_id()))
        .await?;

    caller.audit().wrote(
        "runbooks.save",
        format!("runbook:{}", saved.id),
        None,
        Some(serde_json::json!({
            "name": saved.runbook.name,
            "version": saved.version,
            "steps": saved.runbook.steps.len(),
            "destructive": saved.runbook.is_destructive(),
            "approvals": saved.runbook.approvals.count(),
            "max_targets": saved.runbook.max_targets,
        })),
    );

    Ok((StatusCode::CREATED, Json(view(saved))))
}

/// Turn validation problems into one refusal that names every one of them.
fn refused(problems: &[uops_runbook::Problem]) -> ApiError {
    let mut said = String::from("this runbook was not saved:");
    for problem in problems {
        said.push_str("\n• ");
        said.push_str(&problem.to_string());
    }
    uops_core::Error::Invalid(said).into()
}

/// `DELETE /api/v1/runbooks/{id}`
///
/// Retires rather than deletes. A run record names the runbook it executed and that name
/// has to keep resolving — the same choice a collector and a user get.
pub async fn retire(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    caller.require(Role::Operator)?;

    let gone = state.store.retire_runbook(caller.scope(), id).await?;
    if !gone {
        return Err(uops_core::Error::NotFound {
            kind: "runbook",
            id: id.to_string(),
        }
        .into());
    }

    caller
        .audit()
        .wrote("runbooks.retire", format!("runbook:{id}"), None, None);
    Ok(StatusCode::NO_CONTENT)
}

// ---- planning ------------------------------------------------------------------

/// Resolve a runbook's targets and render every command, or say why not.
///
/// The shared half of `plan` and `start`: a run must never be created from a plan that was
/// not built, and building it twice from two code paths is how the review screen and the
/// run end up describing different things.
async fn build_plan(
    state: &AppState,
    caller: &Caller,
    runbook: &Runbook,
) -> ApiResult<(Plan, Vec<(ResourceId, String)>)> {
    let ids = state
        .store
        .runbook_target_ids(caller.scope(), &runbook.targets)
        .await?;

    // M10 §2.7, and the numbers are the response rather than a log line: "a selector that
    // was meant to match one switch and matches four hundred is the single most common way
    // automation causes an outage". Checked before the names are fetched — see
    // `runbook_target_ids` — so a selector matching forty thousand resources costs one
    // index scan to be told no.
    if ids.len() > runbook.max_targets as usize {
        return Err(uops_core::Error::Invalid(format!(
            "this runbook allows {} resources and its targets resolve to {} — {} too many. \
             Raising the limit is an edit to the runbook, which is a reviewed object.",
            runbook.max_targets,
            ids.len(),
            ids.len() - runbook.max_targets as usize,
        ))
        .into());
    }

    let named = state
        .store
        .runbook_target_names(caller.scope(), &ids)
        .await?;

    let targets: Vec<Target> = named
        .iter()
        .map(|(id, name)| Target {
            id: *id,
            name: name.clone(),
        })
        .collect();

    // The context a template substitutes from. Three values and no credential among them —
    // §2.4 expressed as an absence rather than as a check.
    let plan = uops_runbook::plan(runbook, &targets, |target| {
        let mut context = uops_runbook::Context::new();
        context.insert("resource.name".to_owned(), target.name.clone());
        context.insert("resource.id".to_owned(), target.id.to_string());
        context
    })
    // A plan that will not render is a refusal rather than a failure — see
    // `uops_runbook::error`. `Invalid` is what carries that to the client as a 400 with
    // the sentence the author needs, which names the step.
    .map_err(|e| uops_core::Error::Invalid(e.to_string()))?;

    Ok((plan, named))
}

/// Why a real run cannot start, if it cannot.
///
/// Only the reasons that are true *now* and would still be true in a second. An expired
/// approval is not here: an approval is fresh when given and stale when used, and the gap
/// is the point of the window.
async fn blocked_reason(
    state: &AppState,
    caller: &Caller,
    runbook: &Runbook,
    targets: &[(ResourceId, String)],
) -> ApiResult<Option<String>> {
    if !runbook.maintenance_only {
        return Ok(None);
    }

    // **Every** target has to be inside an open window, not any of them. "May only run
    // inside a maintenance window" is a statement about the change, and a change that
    // reaches one device nobody scheduled work on is a change outside the window.
    //
    // This is the opposite of how a window works for alerting, and deliberately: an alert
    // is *suppressed* during one, and an automated change is *only permitted* during one.
    let now = Utc::now();
    let mut outside = Vec::new();
    for (id, name) in targets {
        if state
            .store
            .maintenance_for(caller.scope(), *id, now)
            .await?
            .is_none()
        {
            outside.push(name.clone());
        }
    }

    if outside.is_empty() {
        return Ok(None);
    }

    outside.sort();
    let named: Vec<&str> = outside.iter().take(3).map(String::as_str).collect();
    Ok(Some(format!(
        "this runbook may only run during maintenance, and {} of its {} targets are not in \
         an open window ({}{})",
        outside.len(),
        targets.len(),
        named.join(", "),
        if outside.len() > named.len() { ", …" } else { "" },
    )))
}

/// `POST /api/v1/runbooks/{id}/plan`
///
/// What a run would do, without creating one. This is the dry-run review screen: the
/// resolved targets by name, the literal command that would be sent to each, and which
/// steps a dry run would actually execute.
///
/// `Operator` rather than `Viewer` even though it writes nothing: planning resolves a
/// selector and renders every command, which is a description of somebody's estate, and it
/// is the screen from which a run is started.
pub async fn plan(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<Json<PlanView>> {
    caller.require(Role::Operator)?;

    let row = current(&state, &caller, id).await?;
    let (plan, named) = build_plan(&state, &caller, &row.runbook).await?;
    let blocked = blocked_reason(&state, &caller, &row.runbook, &named).await?;

    caller.audit().read(
        "runbooks.plan",
        Some(i64::try_from(plan.targets.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(plan_view(&plan, row.runbook.approvals, blocked)))
}

/// The current version of a runbook, refusing a retired one for anything but reading.
async fn current(state: &AppState, caller: &Caller, id: uuid::Uuid) -> ApiResult<RunbookRow> {
    let row = state
        .store
        .runbooks(caller.scope())
        .await?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or(uops_core::Error::NotFound {
            kind: "runbook",
            id: id.to_string(),
        })?;

    if row.retired {
        return Err(uops_core::Error::Invalid(
            "this runbook is retired. Its history is still readable; save it again under a \
             new name to run it."
                .to_owned(),
        )
        .into());
    }
    Ok(row)
}

// ---- runs ----------------------------------------------------------------------

/// What a client sends to start one.
#[derive(Debug, Deserialize)]
pub struct StartRequest {
    /// Why, in the starter's words. Required: a run with no reason is a run nobody can
    /// explain six months later, and the field is free text because a person types it.
    pub reason: String,
    /// **Defaults to a dry run.** M10 §2.2: the default is the safe one, not a flag that
    /// defaults to `false` and can be omitted. A client that means it says so.
    #[serde(default = "yes")]
    pub dry_run: bool,
}

const fn yes() -> bool {
    true
}

/// `POST /api/v1/runbooks/{id}/runs`
///
/// Records a run. Does not execute it — `uops-runner` does, and a `202` says a row exists
/// rather than that anything happened.
///
/// The state it starts in is the whole of this handler's judgement:
///
/// * a **dry run** is `ready`, whatever the runbook requires. It sends only the steps the
///   author marked as changing nothing, so there is nothing for an approval to be about,
///   and requiring one would teach everybody to approve dry runs without reading them;
/// * a runbook requiring **no** approvals is `ready`;
/// * a **break-glass** account is `ready`, with `break_glass` recorded on the run for as
///   long as the run exists and an audit event of its own kind — §2.5;
/// * everything else is `awaiting_approval`.
pub async fn start(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
    Json(body): Json<StartRequest>,
) -> ApiResult<(StatusCode, Json<RunView>)> {
    caller.require(Role::Operator)?;

    if body.reason.trim().is_empty() {
        return Err(uops_core::Error::Invalid(
            "say why this run is happening. It is the first thing anybody reading the \
             record afterwards looks for."
                .to_owned(),
        )
        .into());
    }

    let row = current(&state, &caller, id).await?;
    let (plan, named) = build_plan(&state, &caller, &row.runbook).await?;

    if let Some(why) = blocked_reason(&state, &caller, &row.runbook, &named).await? {
        return Err(uops_core::Error::Invalid(why).into());
    }

    let needs_approval = !body.dry_run && row.runbook.approvals.count() > 0;
    let break_glass = needs_approval && state.store.is_break_glass(caller.user_id()).await?;
    let state_at_start = if needs_approval && !break_glass {
        RunState::AwaitingApproval
    } else {
        RunState::Ready
    };

    let fingerprint = fingerprint_of(&named);
    let run_id = state
        .store
        .create_run(
            caller.scope(),
            row.id,
            row.version_id,
            state_at_start,
            body.dry_run,
            &named,
            &fingerprint,
            body.reason.trim(),
            caller.user_id(),
            break_glass,
        )
        .await?;

    // Two different audit actions, not one with a flag. A break-glass run is a thing
    // somebody has to explain, and an investigation looking for them should be able to
    // filter on the action rather than read every run's detail.
    caller.audit().wrote(
        if break_glass {
            "runbooks.run.break_glass"
        } else {
            "runbooks.run.start"
        },
        format!("run:{run_id}"),
        None,
        Some(serde_json::json!({
            "runbook": row.runbook.name,
            "version": row.version,
            "dry_run": body.dry_run,
            "resources": named.len(),
            "steps": plan.total_steps(),
            "destructive_steps": plan.destructive_steps(),
            "reason": body.reason.trim(),
            "approvals_required": row.runbook.approvals.count(),
            "unapproved": break_glass,
        })),
    );

    let run = one_run(&state, &caller, run_id).await?;
    Ok((StatusCode::ACCEPTED, Json(run)))
}

/// A stable fingerprint over the resolved target list.
///
/// What an approval is *of* — §2.5: a run whose targets changed after approval is not the
/// run that was approved. Over the ids alone and in sorted order, so a rename does not
/// invalidate an approval and a reordering does not either. Names are what a person read;
/// ids are what would be acted on, and those are the ones that must not change.
fn fingerprint_of(targets: &[(ResourceId, String)]) -> String {
    use sha2::{Digest as _, Sha256};

    let mut ids: Vec<String> = targets.iter().map(|(id, _)| id.to_string()).collect();
    ids.sort();

    let mut hasher = Sha256::new();
    for id in &ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

/// How a run list is narrowed.
#[derive(Debug, Deserialize)]
pub struct RunFilter {
    /// Only runs of one runbook.
    #[serde(default)]
    pub runbook: Option<uuid::Uuid>,
}

/// `GET /api/v1/runs`
pub async fn runs(
    State(state): State<AppState>,
    caller: Caller,
    Query(filter): Query<RunFilter>,
) -> ApiResult<Json<Vec<RunView>>> {
    caller.require(Role::Viewer)?;

    let rows = state.store.runs(caller.scope(), RUN_LIMIT).await?;
    let rows: Vec<_> = rows
        .into_iter()
        .filter(|r| filter.runbook.is_none_or(|id| r.runbook_id == id))
        .collect();

    caller.audit().read(
        "runs.list",
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(rows.into_iter().map(run_view).collect()))
}

/// One run, by id.
async fn one_run(state: &AppState, caller: &Caller, id: uuid::Uuid) -> ApiResult<RunView> {
    state
        .store
        .runs(caller.scope(), RUN_LIMIT)
        .await?
        .into_iter()
        .find(|r| r.id == id)
        .map(run_view)
        .ok_or_else(|| {
            uops_core::Error::NotFound {
                kind: "run",
                id: id.to_string(),
            }
            .into()
        })
}

/// One step of a run, against one resource.
#[derive(Debug, Serialize)]
pub struct StepView {
    pub resource_id: ResourceId,
    pub step_index: i32,
    pub name: String,
    /// What was actually sent, rendered. The record an auditor reads, so it is the literal
    /// text rather than the template.
    pub rendered: String,
    pub destructive: bool,
    pub state: String,
    /// Captured output, **already redacted** — `uops_runbook::redact`, applied in the store
    /// on the way in, so there is no path that could serve a raw transcript.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
}

/// A run and its transcript.
#[derive(Debug, Serialize)]
pub struct RunDetailView {
    #[serde(flatten)]
    pub run: RunView,
    pub steps: Vec<StepView>,
}

/// `GET /api/v1/runs/{id}`
pub async fn run(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
) -> ApiResult<Json<RunDetailView>> {
    caller.require(Role::Viewer)?;

    let run = one_run(&state, &caller, id).await?;
    let steps = state.store.run_steps(caller.scope(), id).await?;

    caller.audit().read(
        "runs.get",
        Some(i64::try_from(steps.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(RunDetailView {
        run,
        steps: steps
            .into_iter()
            .map(|s| StepView {
                resource_id: s.resource_id,
                step_index: s.step_index,
                name: s.name,
                rendered: s.rendered,
                destructive: s.destructive,
                state: s.state,
                output: s.output,
                exit_code: s.exit_code,
                finished_at: s.finished_at,
            })
            .collect(),
    }))
}

/// `POST /api/v1/runs/{id}/approve`
///
/// `Operator`, and the rule that matters is not a role: the approver must be somebody
/// other than the starter. That is checked in the store for the message and is
/// unrepresentable in the schema regardless — migration 0026 carries `started_by` on the
/// approval row and binds it by composite foreign key.
pub async fn approve(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<Json<RunView>> {
    caller.require(Role::Operator)?;

    state
        .store
        .approve_run(caller.scope(), id, caller.user_id())
        .await?;

    // Enough approvals now? The arithmetic lives in `uops_runbook::decide`, and asking it
    // rather than reimplementing it here is what keeps this screen and the runner agreeing
    // about whether a run may go. A second copy of the counting rule that disagreed with
    // the first is the worst defect this milestone could have.
    let context = state.store.run_context(caller.scope(), id).await?;
    let request = uops_runbook::Request {
        started_by: context.started_by,
        required: context.runbook.approvals,
        targets_fingerprint: context.targets_fingerprint.clone(),
        break_glass: context.break_glass,
    };

    // `Approved` alone. `BreakGlass` is not a reason to move a run to `ready` from here:
    // the break-glass path is taken when the run is *started*, and reaching it through an
    // approval would mean an emergency account's presence silently promoting somebody
    // else's run.
    if uops_runbook::decide(&request, &context.approvals, Utc::now())
        == uops_runbook::Decision::Approved
    {
        state
            .store
            .set_run_state(caller.scope(), id, RunState::Ready, None)
            .await?;
    }

    let run = one_run(&state, &caller, id).await?;
    caller.audit().wrote(
        "runs.approve",
        format!("run:{id}"),
        None,
        Some(serde_json::json!({
            "runbook": run.runbook_name,
            "version": run.version,
            "approvals": run.approvals.len(),
            "required": context.runbook.approvals.count(),
            "now_ready": run.state == RunState::Ready,
        })),
    );

    Ok(Json(run))
}

/// `POST /api/v1/runs/{id}/cancel`
///
/// Only before a runner has taken it. A run that is `running` has already sent something,
/// and "cancel" would be a promise this product cannot keep — the honest thing it can
/// offer at that point is the transcript and the declared rollback, which §2.6 says is
/// offered rather than performed.
pub async fn cancel(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<Json<RunView>> {
    caller.require(Role::Operator)?;

    let run = one_run(&state, &caller, id).await?;
    if run.state.touched_a_device() {
        return Err(uops_core::Error::Invalid(
            "this run has already started sending commands. It cannot be called back — \
             read its transcript and decide about the rollback it declared."
                .to_owned(),
        )
        .into());
    }
    if matches!(
        run.state,
        RunState::Succeeded | RunState::Failed | RunState::Refused | RunState::Cancelled
    ) {
        return Err(uops_core::Error::Invalid("this run has already finished".to_owned()).into());
    }

    state
        .store
        .set_run_state(
            caller.scope(),
            id,
            RunState::Cancelled,
            Some("cancelled before it started"),
        )
        .await?;

    caller.audit().wrote(
        "runs.cancel",
        format!("run:{id}"),
        Some(serde_json::json!({ "state": run.state })),
        None,
    );

    Ok(Json(one_run(&state, &caller, id).await?))
}
