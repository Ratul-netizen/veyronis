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

/// One resource a claimed run acts on, as it was resolved at plan time.
///
/// Read back from the run's own row rather than re-resolved. The whole point of approving
/// a run is that somebody looked at *this list* — M10 §2.5 — and a selector re-evaluated
/// at execution time would mean approving one thing and running another.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QueuedTarget {
    pub id: ResourceId,
    /// What an operator calls it, carried so a transcript reads in names.
    pub name: String,
}

/// A run this process has taken, and everything needed to execute it.
///
/// Held by value rather than as ids to look up again: between the claim and the first step
/// there must be no second read that could see a different answer.
#[derive(Clone, Debug)]
pub struct Claimed {
    pub id: uuid::Uuid,
    pub tenant_id: TenantId,
    pub runbook_id: uuid::Uuid,
    pub runbook: Runbook,
    pub dry_run: bool,
    pub targets: Vec<QueuedTarget>,
    pub targets_fingerprint: String,
    pub started_by: ActorId,
    pub break_glass: bool,
    /// Every approval on the run, unfiltered.
    ///
    /// Whether they are enough, fresh, distinct, and not the starter's own is
    /// `uops_runbook::decide` — not this layer's business, and re-deciding here would be
    /// a second copy of the rule that could disagree with the first.
    pub approvals: Vec<uops_runbook::Approval>,
}

impl Claimed {
    /// The scope everything about this run must be done under.
    #[must_use]
    pub const fn scope(&self) -> TenantScope {
        TenantScope::system(self.tenant_id)
    }

    /// The approval question, as `uops_runbook` asks it.
    #[must_use]
    pub fn request(&self) -> uops_runbook::Request {
        uops_runbook::Request {
            started_by: self.started_by,
            required: self.runbook.approvals,
            targets_fingerprint: self.targets_fingerprint.clone(),
            break_glass: self.break_glass,
        }
    }
}

/// One step of a run, as the transcript screen reads it.
#[derive(Clone, Debug)]
pub struct RunStepRow {
    pub resource_id: ResourceId,
    pub step_index: i32,
    pub name: String,
    pub rendered: String,
    pub destructive: bool,
    /// `pending`, `skipped`, `running`, `ok`, `failed`.
    pub state: String,
    /// Already redacted — it was redacted on the way *in*, by `record_step`, so there is
    /// no path in this product that can serve a raw transcript.
    pub output: Option<String>,
    pub exit_code: Option<i32>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// Everything about a run that the approval decision needs.
#[derive(Clone, Debug)]
pub struct RunContext {
    /// The version that was recorded, not the runbook's current one. An approval is of
    /// *this* run, which executed *that* version.
    pub runbook: Runbook,
    pub targets_fingerprint: String,
    pub started_by: ActorId,
    pub break_glass: bool,
    pub approvals: Vec<uops_runbook::Approval>,
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

    /// Whether this account is its organization's break-glass account.
    ///
    /// **The same account M12 §2.2 created, used for a second thing**, which M10 §2.5 asks
    /// for in as many words: *"The same argument, and the same shape, as the break-glass
    /// account in M12 §2.2."*
    ///
    /// One flag, two powers — signing in with a password when the organization requires
    /// SSO, and starting a destructive run without an approval — and that is the point
    /// rather than a conflation. Both are the 3 a.m. case: an organization with a rule and
    /// one engineer awake will get around the rule, through a laptop and SSH, with no
    /// audit trail at all. What the product offers instead is the route it can observe,
    /// and it is the *same* route, held by the same single account per organization that
    /// migration 0024's unique index enforces. Two separate emergency accounts would be
    /// two things to hand out, two to review and two to forget.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said. A user that does not exist is **not** break-glass
    /// rather than an error: the caller is asking "may this person skip approval", and the
    /// answer for somebody who is not there is no.
    pub async fn is_break_glass(&self, user: ActorId) -> Result<bool> {
        // tenant-exempt: a user is an organization-level record, and break-glass is a
        // property of the organization's emergency account rather than of a tenant.
        let row = sqlx::query!(
            r#"
            SELECT break_glass FROM app_user
             WHERE id = $1 AND disabled_at IS NULL
            "#,
            user as ActorId,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("user", user.to_string(), e))?;

        Ok(row.is_some_and(|r| r.break_glass))
    }

    /// A run's transcript, in the order it was executed.
    ///
    /// Ordered by resource and then step, so a run across forty devices reads as forty
    /// sequences rather than as one interleaved list nobody can follow.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn run_steps(&self, scope: &TenantScope, run: uuid::Uuid) -> Result<Vec<RunStepRow>> {
        // tenant-exempt: the tenant is a bound parameter, from the scope.
        let rows = sqlx::query!(
            r#"
            SELECT resource_id AS "resource_id: ResourceId", step_index, name, rendered,
                   destructive, state::text AS "state!", output, exit_code, finished_at
              FROM runbook_run_step
             WHERE run_id = $1 AND tenant_id = $2
             ORDER BY resource_id, step_index
            "#,
            run,
            scope.tenant_id() as TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("run step", run.to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| RunStepRow {
                resource_id: r.resource_id,
                step_index: r.step_index,
                name: r.name,
                rendered: r.rendered,
                destructive: r.destructive,
                state: r.state,
                output: r.output,
                exit_code: r.exit_code,
                finished_at: r.finished_at,
            })
            .collect())
    }

    /// What deciding about a run needs, in one read.
    ///
    /// The alternative is three calls from the route and an opportunity for two of them to
    /// see different versions of the same run. The decision itself is **not** here — it is
    /// `uops_runbook::decide`, and a second copy of it in this layer could disagree with
    /// the one the runner uses, which is the disagreement that matters most in this
    /// milestone.
    ///
    /// # Errors
    ///
    /// [`uops_core::Error::NotFound`] for a run that is not this tenant's, which is the
    /// same answer as one that does not exist — confirming an id exists elsewhere is an
    /// inventory leak between customers.
    pub async fn run_context(&self, scope: &TenantScope, run: uuid::Uuid) -> Result<RunContext> {
        // tenant-exempt: the tenant is a bound parameter, from the scope.
        let row = sqlx::query!(
            r#"
            SELECT version_id, targets_fingerprint,
                   started_by AS "started_by: ActorId", break_glass
              FROM runbook_run
             WHERE id = $1 AND tenant_id = $2
            "#,
            run,
            scope.tenant_id() as TenantId,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("run", run.to_string(), e))?
        .ok_or(uops_core::Error::NotFound {
            kind: "run",
            id: run.to_string(),
        })?;

        let (_, runbook) = self
            .runbook_version(scope, row.version_id)
            .await?
            .ok_or(uops_core::Error::NotFound {
                kind: "runbook version",
                id: row.version_id.to_string(),
            })?;

        // tenant-exempt: the tenant is a bound parameter, from the scope.
        let approvals = sqlx::query!(
            r#"
            SELECT approved_by AS "approved_by: ActorId", at, targets_fingerprint
              FROM runbook_approval
             WHERE run_id = $1 AND tenant_id = $2
            "#,
            run,
            scope.tenant_id() as TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("approval", run.to_string(), e))?
        .into_iter()
        .map(|a| uops_runbook::Approval {
            by: a.approved_by,
            at: a.at,
            targets_fingerprint: a.targets_fingerprint,
        })
        .collect();

        Ok(RunContext {
            runbook,
            targets_fingerprint: row.targets_fingerprint,
            started_by: row.started_by,
            break_glass: row.break_glass,
            approvals,
        })
    }

    // ---- the queue the runner reads ---------------------------------------------

    /// Take the oldest queued run, or find there is none.
    ///
    /// **This is what makes "each queued run executes once" true**, and the lease in M12
    /// §2.1 is not. The lease bounds how many runners contend; a lease that lapsed a
    /// millisecond ago while its holder was mid-claim would leave two processes both
    /// believing they may work, and the thing that decides between them has to be a
    /// single statement the database serialises.
    ///
    /// So the state transition *is* the claim: `ready` to `running` inside one `UPDATE`,
    /// against a row picked with `FOR UPDATE SKIP LOCKED`. A second runner either sees no
    /// `ready` row or skips the locked one. This is the lesson the enrolment token taught
    /// in M12 §2.3 — a guard that a connection pool happens to serialise is not a guard
    /// anybody can point at.
    ///
    /// It is **cross-tenant on purpose**: a runner serves the deployment, not a tenant,
    /// the same way the sweeper and the alert engine do. Everything it hands back carries
    /// the tenant it came from, and nothing below acts without it.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said, and [`uops_core::Error::Serialization`] for a stored
    /// runbook this build cannot read — a downgrade past an action kind. That run is left
    /// in `running` and reported by the caller rather than silently skipped, because a run
    /// nobody can parse is a run somebody has to look at.
    pub async fn claim_next_run(&self) -> Result<Option<Claimed>> {
        // tenant-exempt: a runner serves the deployment. The tenant is read from the row
        // and returned with it.
        let row = sqlx::query!(
            r#"
            UPDATE runbook_run AS run
               SET state = 'running', started_at = now()
             WHERE run.id = (
                     SELECT id FROM runbook_run
                      WHERE state = 'ready'
                      ORDER BY created_at
                      LIMIT 1
                      FOR UPDATE SKIP LOCKED
                   )
            RETURNING run.id, run.tenant_id AS "tenant_id: TenantId", run.version_id,
                      run.dry_run, run.targets, run.targets_fingerprint,
                      run.started_by AS "started_by: ActorId", run.break_glass
            "#,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("run", "queue".to_owned(), e))?;

        let Some(row) = row else { return Ok(None) };
        let scope = TenantScope::system(row.tenant_id);

        // Read after the claim rather than joined into it. The `UPDATE` has to stay one
        // statement over one row to be the thing that decides; widening it into a join
        // over four tables to save a round trip would trade the property for a query plan.
        let Some((runbook_id, runbook)) = self.runbook_version(&scope, row.version_id).await?
        else {
            return Err(uops_core::Error::NotFound {
                kind: "runbook version",
                id: row.version_id.to_string(),
            });
        };

        let targets: Vec<QueuedTarget> = serde_json::from_value(row.targets)?;

        let approvals = sqlx::query!(
            r#"
            SELECT approved_by AS "approved_by: ActorId", at, targets_fingerprint
              FROM runbook_approval
             WHERE run_id = $1 AND tenant_id = $2
            "#,
            row.id,
            scope.tenant_id() as TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("approval", row.id.to_string(), e))?
        .into_iter()
        .map(|a| uops_runbook::Approval {
            by: a.approved_by,
            at: a.at,
            targets_fingerprint: a.targets_fingerprint,
        })
        .collect();

        Ok(Some(Claimed {
            id: row.id,
            tenant_id: row.tenant_id,
            runbook_id,
            runbook,
            dry_run: row.dry_run,
            targets,
            targets_fingerprint: row.targets_fingerprint,
            started_by: row.started_by,
            break_glass: row.break_glass,
            approvals,
        }))
    }

    /// Put a claimed run back where it was, with no failure recorded against it.
    ///
    /// For the one case that is not a failure: an approval that expired while the run sat
    /// in the queue. M10 §3 says such a run *stays pending rather than failing*, because
    /// what went wrong is that ten minutes passed, and the operator's next step is to ask
    /// somebody again rather than to read a transcript.
    ///
    /// `started_at` is cleared with it: a run that is waiting again has not started.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn return_run_to_queue(&self, scope: &TenantScope, run_id: uuid::Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE runbook_run
               SET state = 'awaiting_approval', started_at = NULL
             WHERE id = $1 AND tenant_id = $2 AND state = 'running'
            "#,
            run_id,
            scope.tenant_id() as TenantId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("run", run_id.to_string(), e))?;
        Ok(())
    }

    /// Close out the runs a crashed runner left mid-flight.
    ///
    /// Called at start-up, the way the sweeper reaps its own abandoned discovery runs. A
    /// run in `running` whose process is gone is the one state nothing else corrects: no
    /// runner will claim it again, because claiming only looks at `ready`.
    ///
    /// **It is marked `failed`, not requeued.** A run that was `running` may already have
    /// sent a destructive step, and the product does not know which. Re-running it would
    /// be the product deciding, by itself, to send `clear bgp neighbor` a second time —
    /// which is exactly what §2.6 refuses to do with a rollback, for the same reason.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn fail_abandoned_runs(&self, older_than: chrono::Duration) -> Result<u64> {
        #[expect(clippy::cast_precision_loss, reason = "a staleness bound in seconds")]
        let secs = older_than.num_seconds() as f64;

        // tenant-exempt: a crashed process abandoned whichever tenants' runs it held.
        let affected = sqlx::query!(
            r#"
            UPDATE runbook_run
               SET state = 'failed', finished_at = now(),
                   failure = 'the runner executing this run stopped. What it had already sent is in the transcript; what it had not is not. It was not restarted, because a step that changes something must not be re-sent by a process guessing.'
             WHERE state = 'running'
               AND started_at < now() - make_interval(secs => $1)
            "#,
            secs,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("run", "abandoned".to_owned(), e))?
        .rows_affected();
        Ok(affected)
    }

    /// Where to reach each of a run's targets, right now.
    ///
    /// **Resolved at execution time and not carried in the run record**, which looks like
    /// an inconsistency with M10 §2.5 and is not. What §2.5 freezes is *which resources*
    /// were approved — the identities somebody looked at. A management address is not an
    /// identity, it is how this process opens a socket to one, and a device that was
    /// re-addressed between approval and execution should be reached at its new address
    /// rather than at a stale one held in a JSON blob.
    ///
    /// A target with no `mgmt_ip` identifier is simply absent from the result. The caller
    /// records that step as failed against that resource and carries on with the others,
    /// because one un-addressed device out of forty is not a reason to abandon a run.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn resource_addresses(
        &self,
        scope: &TenantScope,
        ids: &[ResourceId],
    ) -> Result<std::collections::HashMap<ResourceId, String>> {
        let raw: Vec<uuid::Uuid> = ids.iter().map(|id| (*id).into()).collect();

        // tenant-exempt: the tenant is a bound parameter, from the scope.
        let rows = sqlx::query!(
            r#"
            SELECT i.resource_id AS "id: ResourceId", i.value
              FROM resource_identifier i
             WHERE i.tenant_id = $1 AND i.kind = 'mgmt_ip' AND i.resource_id = ANY($2)
            "#,
            scope.tenant_id() as TenantId,
            &raw,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("resource", scope.tenant_id().to_string(), e))?;

        Ok(rows.into_iter().map(|r| (r.id, r.value)).collect())
    }

    /// How many resources a runbook's selector reaches, and what they are called.
    ///
    /// # Why the count comes back separately from the names
    ///
    /// M10 §2.7 refuses a run whose selector exceeds the runbook's maximum **and says by
    /// how much**. Saying by how much needs the true number; drawing the plan needs the
    /// names. A single query that fetched names for a selector matching forty thousand
    /// resources would do forty thousand rows of work in order to be told the answer is
    /// "no" — so the ids come first, and the names are fetched only once the count has
    /// been accepted.
    ///
    /// That ordering is also what §2.2's dry run reports: *"a selector that was meant to
    /// match one switch and matches four hundred is the single most common way automation
    /// causes an outage"*, and the number is the thing to look at before anything else.
    ///
    /// `ResourceSelector::All` is materialised here rather than left as "the whole
    /// tenant". A query may leave it implicit — no `resource_id` predicate is the whole
    /// tenant — but a run cannot: somebody has to approve *this list*, and "everything,
    /// whatever that is at the time" is not a list.
    ///
    /// # Errors
    ///
    /// Whatever the catalog or `PostgreSQL` said.
    pub async fn runbook_target_ids(
        &self,
        scope: &TenantScope,
        selector: &uops_query::ast::ResourceSelector,
    ) -> Result<Vec<ResourceId>> {
        let resolved = uops_query::resolve(selector, scope, &crate::PgCatalog::new(self.clone()))
            .await
            .map_err(|e| uops_core::Error::Invalid(format!("resolving the targets: {e}")))?;

        if let Some(ids) = resolved.ids() {
            return Ok(ids.to_vec());
        }

        // `All`. Decommissioned resources are excluded: they are kept so a run record's
        // name keeps resolving, and sending a command to one is not something a selector
        // meaning "everything" should be read as asking for.
        //
        // tenant-exempt: the tenant is the only bound parameter, from the scope.
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id: ResourceId"
              FROM resource
             WHERE tenant_id = $1 AND status <> 'decommissioned'
             ORDER BY id
            "#,
            scope.tenant_id() as TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("resource", scope.tenant_id().to_string(), e))?;

        Ok(rows.into_iter().map(|r| r.id).collect())
    }

    /// The names of resources a run will act on, in the order a plan lists them.
    ///
    /// Sorted by name rather than by id: the list exists to be *read* by somebody deciding
    /// whether to approve it, and a page of UUIDs in insertion order is a page nobody
    /// checks — which is the failure §2.2 is about.
    ///
    /// A resource that has disappeared between resolution and this call is simply absent.
    /// The caller compares the counts; a plan quietly one shorter than the selector
    /// matched is not a plan anybody should approve.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn runbook_target_names(
        &self,
        scope: &TenantScope,
        ids: &[ResourceId],
    ) -> Result<Vec<(ResourceId, String)>> {
        let raw: Vec<uuid::Uuid> = ids.iter().map(|id| (*id).into()).collect();

        // tenant-exempt: the tenant is a bound parameter, from the scope.
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id: ResourceId", COALESCE(display_name, name) AS "name!"
              FROM resource
             WHERE tenant_id = $1 AND id = ANY($2)
             ORDER BY COALESCE(display_name, name), id
            "#,
            scope.tenant_id() as TenantId,
            &raw,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("resource", scope.tenant_id().to_string(), e))?;

        Ok(rows.into_iter().map(|r| (r.id, r.name)).collect())
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
