//! Runbooks, runs and approvals in `PostgreSQL` — M10.
//!
//! # This layer stores and refuses; it does not decide
//!
//! Whether a run may proceed is `uops_runbook::decide`. Whether a runbook may be saved is
//! `uops_runbook::validate`. What is here is the writing down, plus the three refusals
//! the *schema* makes — a version that cannot be edited, one person who cannot approve
//! twice, and nobody approving their own run.
//!
//! That the rules exist in both places is not redundancy for its own sake. The code
//! produces a message somebody can act on; the schema is what holds when a row is written
//! by another route. Migration 0026 says the same thing from the other side.
//!
//! # Saving a runbook writes a version
//!
//! There is no update. `save` inserts version *n+1* and leaves *n* readable, because a run
//! names the version it executed and "what did this actually do in March" has to have an
//! answer that does not depend on nobody having edited it since.

use chrono::{DateTime, Utc};
use uops_core::{ActorId, ResourceId, Result, TenantId, TenantScope};
use uops_runbook::{Approvals, Runbook, Step};

use crate::error::map;
use crate::store::PgStore;

/// A runbook and the version that is current.
#[derive(Clone, Debug)]
pub struct RunbookRow {
    pub id: uuid::Uuid,
    pub version_id: uuid::Uuid,
    pub version: i32,
    pub retired: bool,
    pub created_at: DateTime<Utc>,
    /// The runbook itself, as `uops-runbook` understands it.
    pub runbook: Runbook,
}

/// What state a run is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(sqlx::Type)]
#[sqlx(type_name = "runbook_run_state", rename_all = "snake_case")]
pub enum RunState {
    AwaitingApproval,
    Ready,
    Running,
    Succeeded,
    /// A step failed. The run stopped there and the declared rollback is *offered*.
    Failed,
    /// Declined before anything was sent. Distinct from `Failed`, because one of them
    /// touched a device and the other did not — and that is the first thing somebody
    /// reading a run list wants to know.
    Refused,
    Cancelled,
}

impl RunState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingApproval => "awaiting_approval",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Refused => "refused",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether anything was sent to a device.
    ///
    /// The question an operator asks first, and the reason `Refused` is its own state.
    #[must_use]
    pub const fn touched_a_device(self) -> bool {
        matches!(self, Self::Running | Self::Succeeded | Self::Failed)
    }
}

/// A run, as it is listed.
#[derive(Clone, Debug)]
pub struct RunRow {
    pub id: uuid::Uuid,
    pub runbook_id: uuid::Uuid,
    pub runbook_name: String,
    pub version: i32,
    pub state: RunState,
    pub dry_run: bool,
    pub targets: serde_json::Value,
    pub targets_fingerprint: String,
    pub reason: String,
    pub started_by: ActorId,
    /// Ran without approval. Visible for as long as the run is, rather than only in an
    /// audit entry somebody has to go and find — M10 §2.5.
    pub break_glass: bool,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub failure: Option<String>,
    pub approvals: Vec<ApprovalRow>,
}

/// One person having said yes.
#[derive(Clone, Debug)]
pub struct ApprovalRow {
    pub approved_by: ActorId,
    pub at: DateTime<Utc>,
    pub targets_fingerprint: String,
}

impl PgStore {
    /// Create a runbook, or save a new version of one that exists.
    ///
    /// There is no update. See the module docs.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said. The caller has already run
    /// [`uops_runbook::validate`] — a runbook that would not validate must not reach
    /// here, and the schema's own CHECKs are the backstop rather than the message.
    pub async fn save_runbook(
        &self,
        scope: &TenantScope,
        runbook: &Runbook,
        by: Option<ActorId>,
    ) -> Result<RunbookRow> {
        let targets = serde_json::to_value(&runbook.targets)?;
        let steps = serde_json::to_value(&runbook.steps)?;
        let approvals = approvals_to_sql(runbook.approvals);

        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("runbook", runbook.name.clone(), e))?;

        // The runbook itself is idempotent on `(tenant_id, name)`: saving twice is a
        // second *version*, not a second runbook.
        let book = sqlx::query!(
            r#"
            INSERT INTO runbook (tenant_id, name, created_by)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, name) DO UPDATE
               SET retired_at = NULL
            RETURNING id, created_at
            "#,
            scope.tenant_id() as TenantId,
            runbook.name,
            by as Option<ActorId>,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("runbook", runbook.name.clone(), e))?;

        // The next version number, computed inside the transaction. Two saves racing
        // would otherwise both read *n* and both try to write *n+1*, which the UNIQUE
        // turns into a failure for one of them — correct, and a worse message than
        // whichever one commits second simply getting *n+2*.
        let next = sqlx::query_scalar!(
            r#"
            SELECT coalesce(max(version), 0) + 1 AS "next!"
              FROM runbook_version
             WHERE runbook_id = $1 AND tenant_id = $2
            "#,
            book.id,
            scope.tenant_id() as TenantId,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("runbook", runbook.name.clone(), e))?;

        let version = sqlx::query!(
            r#"
            INSERT INTO runbook_version
                (runbook_id, tenant_id, version, description, targets, steps,
                 max_targets, concurrency, approvals, maintenance_only, created_by)
            -- Bound as text and cast, rather than teaching sqlx four enum types for
            -- values that are already `&'static str`. The same shape `record_audit`
            -- uses for `inet`, and PostgreSQL still validates it: a name the enum does
            -- not have fails the cast rather than being stored.
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::runbook_approvals, $10, $11)
            RETURNING id
            "#,
            book.id,
            scope.tenant_id() as TenantId,
            next,
            runbook.description,
            targets,
            steps,
            i32::try_from(runbook.max_targets).unwrap_or(i32::MAX),
            i32::try_from(runbook.concurrency).unwrap_or(i32::MAX),
            approvals,
            runbook.maintenance_only,
            by as Option<ActorId>,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("runbook", runbook.name.clone(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("runbook", runbook.name.clone(), e))?;

        Ok(RunbookRow {
            id: book.id,
            version_id: version.id,
            version: next,
            retired: false,
            created_at: book.created_at,
            runbook: runbook.clone(),
        })
    }

    /// Every runbook in a tenant, at its current version.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said, and [`uops_core::Error::Serialization`] for a stored
    /// runbook this build cannot read — which is what a downgrade past an action kind
    /// looks like, and is worth failing on rather than skipping.
    pub async fn runbooks(&self, scope: &TenantScope) -> Result<Vec<RunbookRow>> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT ON (r.id)
                   r.id, r.created_at, (r.retired_at IS NOT NULL) AS "retired!",
                   v.id AS version_id, v.version, r.name, v.description,
                   v.targets, v.steps, v.max_targets, v.concurrency,
                   v.approvals::text AS "approvals!", v.maintenance_only
              FROM runbook r
              JOIN runbook_version v ON v.runbook_id = r.id AND v.tenant_id = r.tenant_id
             WHERE r.tenant_id = $1
             ORDER BY r.id, v.version DESC
            "#,
            scope.tenant_id() as TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("runbook", scope.tenant_id().to_string(), e))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(RunbookRow {
                id: r.id,
                version_id: r.version_id,
                version: r.version,
                retired: r.retired,
                created_at: r.created_at,
                runbook: Runbook {
                    name: r.name,
                    description: r.description,
                    targets: serde_json::from_value(r.targets)?,
                    steps: serde_json::from_value::<Vec<Step>>(r.steps)?,
                    max_targets: u32::try_from(r.max_targets).unwrap_or(0),
                    concurrency: u32::try_from(r.concurrency).unwrap_or(0),
                    approvals: approvals_from_sql(&r.approvals),
                    maintenance_only: r.maintenance_only,
                },
            });
        }
        Ok(out)
    }

    /// One version, by id — the one a run executed.
    ///
    /// Scoped by tenant as well as by id, like every other read here: the id arrives from
    /// a URL.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn runbook_version(
        &self,
        scope: &TenantScope,
        version_id: uuid::Uuid,
    ) -> Result<Option<(uuid::Uuid, Runbook)>> {
        let row = sqlx::query!(
            r#"
            SELECT v.runbook_id, r.name, v.description, v.targets, v.steps,
                   v.max_targets, v.concurrency, v.approvals::text AS "approvals!",
                   v.maintenance_only
              FROM runbook_version v
              JOIN runbook r ON r.id = v.runbook_id AND r.tenant_id = v.tenant_id
             WHERE v.id = $1 AND v.tenant_id = $2
            "#,
            version_id,
            scope.tenant_id() as TenantId,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("runbook version", version_id.to_string(), e))?;

        let Some(r) = row else { return Ok(None) };
        Ok(Some((
            r.runbook_id,
            Runbook {
                name: r.name,
                description: r.description,
                targets: serde_json::from_value(r.targets)?,
                steps: serde_json::from_value::<Vec<Step>>(r.steps)?,
                max_targets: u32::try_from(r.max_targets).unwrap_or(0),
                concurrency: u32::try_from(r.concurrency).unwrap_or(0),
                approvals: approvals_from_sql(&r.approvals),
                maintenance_only: r.maintenance_only,
            },
        )))
    }

    /// Retire a runbook. Its versions and its run history stay.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn retire_runbook(&self, scope: &TenantScope, id: uuid::Uuid) -> Result<bool> {
        let affected = sqlx::query!(
            r#"
            UPDATE runbook SET retired_at = now()
             WHERE id = $1 AND tenant_id = $2 AND retired_at IS NULL
            "#,
            id,
            scope.tenant_id() as TenantId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("runbook", id.to_string(), e))?
        .rows_affected();
        Ok(affected == 1)
    }

    // ---- runs -------------------------------------------------------------------

    /// Record a planned run.
    ///
    /// The targets are stored rather than re-resolved later, because the whole point of
    /// approving a run is that somebody looked at *this list* — M10 §2.5.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_run(
        &self,
        scope: &TenantScope,
        runbook_id: uuid::Uuid,
        version_id: uuid::Uuid,
        state: RunState,
        dry_run: bool,
        targets: &[(ResourceId, String)],
        fingerprint: &str,
        reason: &str,
        started_by: ActorId,
        break_glass: bool,
    ) -> Result<uuid::Uuid> {
        let targets = serde_json::to_value(
            targets
                .iter()
                .map(|(id, name)| serde_json::json!({ "id": id, "name": name }))
                .collect::<Vec<_>>(),
        )?;

        let row = sqlx::query!(
            r#"
            INSERT INTO runbook_run
                (tenant_id, runbook_id, version_id, state, dry_run, targets,
                 targets_fingerprint, reason, started_by, break_glass)
            VALUES ($1, $2, $3, $4::text::runbook_run_state, $5, $6, $7, $8, $9, $10)
            RETURNING id
            "#,
            scope.tenant_id() as TenantId,
            runbook_id,
            version_id,
            state.as_str(),
            dry_run,
            targets,
            fingerprint,
            reason,
            started_by as ActorId,
            break_glass,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("run", runbook_id.to_string(), e))?;
        Ok(row.id)
    }

    /// Record an approval.
    ///
    /// `started_by` is written from the run's own row rather than from the caller, and the
    /// composite key in migration 0026 is what makes that true rather than trusted: a
    /// value that is not the run's starter does not reference anything.
    ///
    /// # Errors
    ///
    /// [`uops_core::Error::Forbidden`] when the approver is the person who started it, or
    /// has approved already. Both are schema refusals underneath; this turns them into a
    /// sentence, because the schema's message names a constraint and an operator needs
    /// the rule.
    pub async fn approve_run(
        &self,
        scope: &TenantScope,
        run_id: uuid::Uuid,
        approved_by: ActorId,
    ) -> Result<()> {
        let run = sqlx::query!(
            r#"
            SELECT started_by AS "started_by: ActorId", targets_fingerprint,
                   state AS "state: RunState"
              FROM runbook_run
             WHERE id = $1 AND tenant_id = $2
            "#,
            run_id,
            scope.tenant_id() as TenantId,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("run", run_id.to_string(), e))?
        .ok_or(uops_core::Error::NotFound {
            kind: "run",
            id: run_id.to_string(),
        })?;

        // Checked here for the message, and unrepresentable in the schema regardless.
        if run.started_by == approved_by {
            return Err(uops_core::Error::Forbidden(
                "the person who started a run cannot approve it",
            ));
        }
        if run.state != RunState::AwaitingApproval {
            return Err(uops_core::Error::Forbidden(
                "this run is not waiting for approval",
            ));
        }

        let inserted = sqlx::query!(
            r#"
            INSERT INTO runbook_approval
                (run_id, tenant_id, approved_by, started_by, targets_fingerprint)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (run_id, approved_by) DO NOTHING
            "#,
            run_id,
            scope.tenant_id() as TenantId,
            approved_by as ActorId,
            run.started_by as ActorId,
            run.targets_fingerprint,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("approval", run_id.to_string(), e))?
        .rows_affected();

        if inserted == 0 {
            return Err(uops_core::Error::Forbidden(
                "you have already approved this run; two approvals from one person are \
                 one person agreeing twice",
            ));
        }
        Ok(())
    }

    /// Move a run to a new state.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn set_run_state(
        &self,
        scope: &TenantScope,
        run_id: uuid::Uuid,
        state: RunState,
        failure: Option<&str>,
    ) -> Result<bool> {
        let affected = sqlx::query!(
            r#"
            UPDATE runbook_run
               SET state       = $3::text::runbook_run_state,
                   failure     = COALESCE($4, failure),
                   started_at  = CASE WHEN $3 = 'running' THEN now() ELSE started_at END,
                   finished_at = CASE
                                   WHEN $3 IN ('succeeded','failed','refused','cancelled')
                                   THEN now() ELSE finished_at
                                 END
             WHERE id = $1 AND tenant_id = $2
            "#,
            run_id,
            scope.tenant_id() as TenantId,
            state.as_str(),
            failure,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("run", run_id.to_string(), e))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// The runs of a tenant, newest first, with their approvals.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn runs(&self, scope: &TenantScope, limit: i64) -> Result<Vec<RunRow>> {
        let rows = sqlx::query!(
            r#"
            SELECT run.id, run.runbook_id, r.name AS runbook_name, v.version,
                   run.state AS "state: RunState", run.dry_run, run.targets,
                   run.targets_fingerprint, run.reason,
                   run.started_by AS "started_by: ActorId", run.break_glass,
                   run.created_at, run.started_at, run.finished_at, run.failure
              FROM runbook_run run
              JOIN runbook r ON r.id = run.runbook_id AND r.tenant_id = run.tenant_id
              JOIN runbook_version v ON v.id = run.version_id AND v.tenant_id = run.tenant_id
             WHERE run.tenant_id = $1
             ORDER BY run.created_at DESC, run.id
             LIMIT $2
            "#,
            scope.tenant_id() as TenantId,
            limit.clamp(1, 500),
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("run", scope.tenant_id().to_string(), e))?;

        // One query for every approval on this page rather than one per run: twenty runs
        // would otherwise be twenty-one round trips to draw one screen.
        let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
        let approvals = sqlx::query!(
            r#"
            SELECT run_id, approved_by AS "approved_by: ActorId", at, targets_fingerprint
              FROM runbook_approval
             WHERE tenant_id = $1 AND run_id = ANY($2)
             ORDER BY at
            "#,
            scope.tenant_id() as TenantId,
            &ids,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("approval", scope.tenant_id().to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| RunRow {
                approvals: approvals
                    .iter()
                    .filter(|a| a.run_id == r.id)
                    .map(|a| ApprovalRow {
                        approved_by: a.approved_by,
                        at: a.at,
                        targets_fingerprint: a.targets_fingerprint.clone(),
                    })
                    .collect(),
                id: r.id,
                runbook_id: r.runbook_id,
                runbook_name: r.runbook_name,
                version: r.version,
                state: r.state,
                dry_run: r.dry_run,
                targets: r.targets,
                targets_fingerprint: r.targets_fingerprint,
                reason: r.reason,
                started_by: r.started_by,
                break_glass: r.break_glass,
                created_at: r.created_at,
                started_at: r.started_at,
                finished_at: r.finished_at,
                failure: r.failure,
            })
            .collect())
    }

    /// Record what a step did, redacted.
    ///
    /// The output is passed through [`uops_runbook::redact::output`] **here**, so there is
    /// no path that writes a raw transcript — a caller that forgot would otherwise be the
    /// whole of the protection.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_step(
        &self,
        scope: &TenantScope,
        run_id: uuid::Uuid,
        resource: ResourceId,
        index: i32,
        name: &str,
        rendered: &str,
        destructive: bool,
        state: &str,
        output: Option<&str>,
        exit_code: Option<i32>,
    ) -> Result<()> {
        let redacted = output.map(uops_runbook::redact::output);

        sqlx::query!(
            r#"
            INSERT INTO runbook_run_step
                (run_id, tenant_id, resource_id, step_index, name, rendered,
                 destructive, state, output, exit_code, finished_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::runbook_step_state, $9, $10, now())
            ON CONFLICT (run_id, resource_id, step_index) DO UPDATE
               SET state       = EXCLUDED.state,
                   output      = EXCLUDED.output,
                   exit_code   = EXCLUDED.exit_code,
                   finished_at = now()
            "#,
            run_id,
            scope.tenant_id() as TenantId,
            resource as ResourceId,
            index,
            name,
            rendered,
            destructive,
            state,
            redacted,
            exit_code,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("run step", run_id.to_string(), e))?;
        Ok(())
    }
}

fn approvals_to_sql(a: Approvals) -> &'static str {
    match a {
        Approvals::None => "none",
        Approvals::One => "one",
        Approvals::Two => "two",
    }
}

/// The enum back from text.
///
/// An unknown value maps to [`Approvals::Two`] rather than to `None`. It is unreachable —
/// the column is a PostgreSQL enum — and if it ever happens, the safe reading of an
/// approval setting nobody can parse is the strictest one, not the one that lets a
/// destructive run through unapproved.
fn approvals_from_sql(s: &str) -> Approvals {
    match s {
        "none" => Approvals::None,
        "one" => Approvals::One,
        _ => Approvals::Two,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_did_not_touch_a_device_and_failed_did() {
        // The first thing somebody reading a run list wants to know, and the reason
        // `Refused` is its own state rather than a kind of failure.
        assert!(!RunState::Refused.touched_a_device());
        assert!(!RunState::AwaitingApproval.touched_a_device());
        assert!(!RunState::Ready.touched_a_device());
        assert!(!RunState::Cancelled.touched_a_device());

        assert!(RunState::Running.touched_a_device());
        assert!(RunState::Succeeded.touched_a_device());
        assert!(RunState::Failed.touched_a_device());
    }

    #[test]
    fn the_approval_setting_round_trips() {
        for a in [Approvals::None, Approvals::One, Approvals::Two] {
            assert_eq!(approvals_from_sql(approvals_to_sql(a)), a);
        }
    }

    #[test]
    fn an_unreadable_approval_setting_reads_as_the_strictest() {
        // Unreachable through the enum column. If it ever happens, the safe reading is
        // not the one that lets a destructive run through unapproved.
        assert_eq!(approvals_from_sql("nonsense"), Approvals::Two);
        assert_eq!(approvals_from_sql(""), Approvals::Two);
    }

    #[test]
    fn every_state_has_a_name_the_database_knows() {
        // The `as_str` values are cast to `runbook_run_state` in SQL, so a typo here is a
        // runtime error rather than a compile one. Listed so the set is visible.
        let all = [
            RunState::AwaitingApproval,
            RunState::Ready,
            RunState::Running,
            RunState::Succeeded,
            RunState::Failed,
            RunState::Refused,
            RunState::Cancelled,
        ];
        let names: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), 7);
        for name in &names {
            assert!(name.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{name}");
        }
    }
}
