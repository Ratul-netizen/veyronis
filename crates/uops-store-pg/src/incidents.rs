//! Incidents — M9, `docs/M9-incident.md`.
//!
//! The I/O half of grouping. `uops_incident` decides; this reads what the decision needs
//! and writes what it produced, and holds no rules of its own.
//!
//! That split is the reason §2.2's parameters could be mutation-tested at all: every
//! case in the acceptance criteria is a unit test over pure data, and what is left here
//! is three queries and an insert.

use chrono::{DateTime, Utc};
use uops_core::{ActorId, Error, IncidentId, ResourceId, Result, TenantScope};
use uops_incident::{Member, Neighbourhood, OpenIncident, RADIUS};

use crate::error::map;
use crate::store::PgStore;

/// One incident as a screen reads it.
#[derive(Clone, Debug)]
pub struct IncidentRow {
    pub id: IncidentId,
    pub state: String,
    pub severity: String,
    pub candidate_resource_id: Option<ResourceId>,
    /// Why there is no candidate, when there is none — §2.5. Empty when there is one.
    pub candidate_absent_because: String,
    pub started_at: DateTime<Utc>,
    pub last_alert_at: DateTime<Utc>,
    pub quiet_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub acked_by: Option<ActorId>,
    pub acked_at: Option<DateTime<Utc>>,
    pub summary: String,
    /// How many alerts are in it, and how many of those were allowed to notify.
    pub alerts: i64,
    pub suppressed: i64,
}

impl PgStore {
    /// Every incident that is still open, with what grouping needs to decide.
    ///
    /// Open only: §2.1's `quiet` means every alert resolved and nobody has said it is
    /// understood, and a *new* alert on a quiet incident is a recurrence rather than a
    /// continuation. Joining it would make one incident that spans a gap nobody was
    /// watching, which is two stories in one row.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn open_incidents(&self, scope: &TenantScope) -> Result<Vec<OpenIncident>> {
        // tenant-exempt: the tenant is the only bound parameter, from the scope, and
        // every join carries it so a row cannot pick up another tenant's alerts.
        let rows = sqlx::query!(
            r#"
            SELECT
                i.id            AS "id: IncidentId",
                i.last_alert_at,
                -- The two sets the decision needs, aggregated in the database rather
                -- than by fetching one row per alert: an incident with forty alerts is
                -- one row here and forty round trips otherwise, on the path that runs
                -- every time anything fires.
                coalesce(array_agg(DISTINCT a.resource_id)
                         FILTER (WHERE a.resource_id IS NOT NULL), '{}')
                                AS "resources!: Vec<ResourceId>",
                coalesce(array_agg(DISTINCT a.rule_id)
                         FILTER (WHERE a.rule_id IS NOT NULL), '{}')
                                AS "rules!: Vec<uuid::Uuid>"
              FROM incident i
              LEFT JOIN incident_alert ia
                ON ia.incident_id = i.id AND ia.tenant_id = i.tenant_id
              LEFT JOIN alert_state a
                ON a.id = ia.alert_state_id AND a.tenant_id = i.tenant_id
             WHERE i.tenant_id = $1 AND i.state = 'open'
             GROUP BY i.id, i.last_alert_at
             ORDER BY i.last_alert_at DESC
            "#,
            scope.tenant_id() as uops_core::TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("incident", "open".to_owned(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| OpenIncident {
                id: r.id,
                last_alert_at: r.last_alert_at,
                resources: r.resources.into_iter().collect(),
                rules: r.rules.into_iter().collect(),
            })
            .collect())
    }

    /// What the topology says around one resource — the input to §2.2 and §2.4.
    ///
    /// Three walks, because they answer three different questions and the product needs
    /// all three:
    ///
    /// * **`resource_neighbourhood`** is undirected proximity, which is what §2.2 groups
    ///   on. Two hosts under one switch are the commonest pair in any cascade and are
    ///   reached only by going up and then down.
    /// * **`resource_dependencies`** is what this resource depends on, which is what
    ///   §2.4's suppression is directional about.
    /// * **`estate_has_topology`** is a different fact from an empty neighbourhood — a
    ///   resource with no links in an estate that has plenty, against an estate with no
    ///   links anywhere. §2.3 says the screen must tell them apart, so the engine has to
    ///   know which it is looking at.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn neighbourhood(
        &self,
        scope: &TenantScope,
        resource: ResourceId,
    ) -> Result<Neighbourhood> {
        let tenant = scope.tenant_id();

        // tenant-exempt: the tenant is the function's first argument and it filters every
        // step of the walk — see `migrations/0003_relationships.sql` on why that
        // signature differs from SPEC's sketch.
        let within = sqlx::query!(
            r#"
            SELECT resource_id AS "id!: ResourceId", depth AS "depth!"
              FROM resource_neighbourhood($1, $2, $3)
            "#,
            tenant as uops_core::TenantId,
            resource as ResourceId,
            i32::from(RADIUS),
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("resource_relationship", "neighbourhood".to_owned(), e))?;

        // The radius bounds this one too: an upstream dependency six hops away cannot
        // suppress anything, because it could never have been grouped in the first place.
        //
        // tenant-exempt: as above — the tenant is `resource_dependencies`' first argument
        // and the walk filters on it at every step. Repeated per statement rather than
        // shared with the query above, because the scanner reads the six lines before a
        // call and a marker that covers its neighbour by accident stops covering it the
        // moment somebody adds a sentence.
        let upstream = sqlx::query_scalar!(
            r#"
            SELECT resource_id AS "id!: ResourceId"
              FROM resource_dependencies($1, $2, $3)
             WHERE depth > 0
            "#,
            tenant as uops_core::TenantId,
            resource as ResourceId,
            i32::from(RADIUS),
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("resource_relationship", "dependencies".to_owned(), e))?;

        let estate_has_topology = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM resource_relationship WHERE tenant_id = $1)
               AS "any!""#,
            tenant as uops_core::TenantId,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("resource_relationship", "any".to_owned(), e))?;

        Ok(Neighbourhood {
            within: within
                .into_iter()
                .map(|r| (r.id, u8::try_from(r.depth).unwrap_or(u8::MAX)))
                .collect(),
            upstream: upstream.into_iter().collect(),
            estate_has_topology,
        })
    }

    /// Is `upper` upstream of `lower`, within the radius? The oracle
    /// `uops_incident::candidate` takes.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn is_upstream_of(
        &self,
        scope: &TenantScope,
        upper: ResourceId,
        lower: ResourceId,
    ) -> Result<bool> {
        // tenant-exempt: as `neighbourhood`.
        sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM resource_dependencies($1, $2, $3)
                 WHERE resource_id = $4 AND depth > 0
            ) AS "yes!"
            "#,
            scope.tenant_id() as uops_core::TenantId,
            lower as ResourceId,
            i32::from(RADIUS),
            upper as ResourceId,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("resource_relationship", "is_upstream".to_owned(), e))
    }

    /// The resources in an incident and when each first alerted — the input to §2.5.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn incident_members(
        &self,
        scope: &TenantScope,
        incident: IncidentId,
    ) -> Result<Vec<Member>> {
        // tenant-exempt: the tenant bounds both the incident and the alerts joined to it.
        let rows = sqlx::query!(
            r#"
            SELECT a.resource_id AS "resource_id: ResourceId", min(a.since) AS "since!"
              FROM incident_alert ia
              JOIN alert_state a
                ON a.id = ia.alert_state_id AND a.tenant_id = ia.tenant_id
             WHERE ia.tenant_id = $1 AND ia.incident_id = $2
             GROUP BY a.resource_id
            "#,
            scope.tenant_id() as uops_core::TenantId,
            incident as IncidentId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("incident_alert", "members".to_owned(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| Member {
                resource_id: r.resource_id,
                first_alert_at: r.since,
            })
            .collect())
    }

    /// Open a new incident around one alert.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said, including a unique violation if the alert is already
    /// in an incident — which is §2.1 refusing, in the schema, rather than here.
    pub async fn open_incident(
        &self,
        scope: &TenantScope,
        alert_state_id: uuid::Uuid,
        severity: &str,
        summary: &str,
        at: DateTime<Utc>,
        why_no_candidate: Option<&str>,
    ) -> Result<IncidentId> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("incident", "begin".to_owned(), e))?;

        // The alert's own resource is the candidate of an incident of one — there is no
        // ambiguity to refuse — unless the estate has no topology, in which case §2.5
        // says there is no likely origin and the reason is carried instead.
        let candidate: Option<ResourceId> = if why_no_candidate.is_some() {
            None
        } else {
            sqlx::query_scalar!(
                r#"SELECT resource_id AS "id: ResourceId" FROM alert_state
                   WHERE id = $1 AND tenant_id = $2"#,
                alert_state_id,
                scope.tenant_id() as uops_core::TenantId,
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| map("alert_state", alert_state_id.to_string(), e))?
        };

        let id: IncidentId = sqlx::query_scalar!(
            r#"
            INSERT INTO incident
                (tenant_id, state, severity, candidate_resource_id,
                 candidate_absent_because, started_at, last_alert_at, summary)
            VALUES ($1, 'open', $2, $3, $4, $5, $5, $6)
            RETURNING id AS "id: IncidentId"
            "#,
            scope.tenant_id() as uops_core::TenantId,
            severity,
            candidate as Option<ResourceId>,
            why_no_candidate.unwrap_or_default(),
            at,
            summary,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("incident", "insert".to_owned(), e))?;

        sqlx::query!(
            r#"
            INSERT INTO incident_alert
                (incident_id, tenant_id, alert_state_id, joined_at, notified,
                 hops_from_candidate)
            VALUES ($1, $2, $3, $4, true, 0)
            "#,
            id as IncidentId,
            scope.tenant_id() as uops_core::TenantId,
            alert_state_id,
            at,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("incident_alert", "insert".to_owned(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("incident", "commit".to_owned(), e))?;
        Ok(id)
    }

    /// Add an alert to an incident that already exists.
    ///
    /// `notified` is the decision `uops_incident::group` returned, not a fact about
    /// whether a notification was sent — the engine records what it *decided* and the
    /// notifier acts on it, so a delivery failure does not retroactively make an alert
    /// look suppressed.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said. A duplicate alert is a unique violation, which is
    /// §2.1's "at most one incident" being enforced by the schema.
    // Eight arguments, which is one past clippy's bar. Every one of them is a distinct
    // fact the row records and none is derivable from the others; a `Join { .. }` struct
    // would move the same eight fields to a call site that has to name them anyway.
    #[allow(clippy::too_many_arguments)]
    pub async fn join_incident(
        &self,
        scope: &TenantScope,
        incident: IncidentId,
        alert_state_id: uuid::Uuid,
        notified: bool,
        hops: Option<u8>,
        severity: &str,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("incident", "begin".to_owned(), e))?;

        sqlx::query!(
            r#"
            INSERT INTO incident_alert
                (incident_id, tenant_id, alert_state_id, joined_at, notified,
                 hops_from_candidate)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            incident as IncidentId,
            scope.tenant_id() as uops_core::TenantId,
            alert_state_id,
            at,
            notified,
            hops.map(i16::from),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("incident_alert", "join".to_owned(), e))?;

        // The window slides from here — §2.2 — and the severity only ever rises, because
        // an incident that contained a critical alert was a critical incident whatever
        // joined it afterwards. `quiet_at` is cleared: an incident that went quiet and
        // came back was never over.
        sqlx::query!(
            r#"
            UPDATE incident
               SET last_alert_at = greatest(last_alert_at, $3),
                   state         = 'open',
                   quiet_at      = NULL,
                   severity      = CASE
                       WHEN $4 = 'critical' THEN 'critical'
                       WHEN $4 = 'warning' AND severity = 'info' THEN 'warning'
                       ELSE severity
                   END
             WHERE id = $1 AND tenant_id = $2
            "#,
            incident as IncidentId,
            scope.tenant_id() as uops_core::TenantId,
            at,
            severity,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("incident", "touch".to_owned(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("incident", "commit".to_owned(), e))
    }

    /// Record the candidate §2.5 picked, or the reason there is none.
    ///
    /// Recomputed after each join rather than held in memory, because the answer depends
    /// on the whole membership and the membership is what just changed.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn set_candidate(
        &self,
        scope: &TenantScope,
        incident: IncidentId,
        candidate: Result<ResourceId, &str>,
    ) -> Result<()> {
        let (resource, because) = match candidate {
            Ok(r) => (Some(r), ""),
            Err(why) => (None, why),
        };
        sqlx::query!(
            r#"
            UPDATE incident
               SET candidate_resource_id = $3, candidate_absent_because = $4
             WHERE id = $1 AND tenant_id = $2
            "#,
            incident as IncidentId,
            scope.tenant_id() as uops_core::TenantId,
            resource as Option<ResourceId>,
            because,
        )
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(|e| map("incident", "candidate".to_owned(), e))
    }

    /// Whether this tenant lets topology suppression stop a notification — §2.4.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn suppression_enabled(&self, scope: &TenantScope) -> Result<bool> {
        sqlx::query_scalar!(
            r#"SELECT suppress_downstream_alerts AS "on!" FROM tenant WHERE id = $1"#,
            scope.tenant_id() as uops_core::TenantId,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("tenant", "suppression".to_owned(), e))
    }

    /// A tenant's incidents, newest first.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn incidents(&self, scope: &TenantScope, limit: i64) -> Result<Vec<IncidentRow>> {
        // tenant-exempt: the tenant is a bound parameter from the scope and the join
        // carries it.
        let rows = sqlx::query!(
            r#"
            SELECT
                i.id AS "id: IncidentId",
                i.state, i.severity,
                i.candidate_resource_id AS "candidate_resource_id: ResourceId",
                i.candidate_absent_because,
                i.started_at, i.last_alert_at, i.quiet_at, i.closed_at,
                i.acked_by AS "acked_by: ActorId",
                i.acked_at, i.summary,
                count(ia.alert_state_id)                          AS "alerts!",
                count(ia.alert_state_id) FILTER (WHERE NOT ia.notified) AS "suppressed!"
              FROM incident i
              LEFT JOIN incident_alert ia
                ON ia.incident_id = i.id AND ia.tenant_id = i.tenant_id
             WHERE i.tenant_id = $1
             GROUP BY i.id
             ORDER BY i.started_at DESC
             LIMIT $2
            "#,
            scope.tenant_id() as uops_core::TenantId,
            limit.clamp(1, 500),
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("incident", "list".to_owned(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| IncidentRow {
                id: r.id,
                state: r.state,
                severity: r.severity,
                candidate_resource_id: r.candidate_resource_id,
                candidate_absent_because: r.candidate_absent_because,
                started_at: r.started_at,
                last_alert_at: r.last_alert_at,
                quiet_at: r.quiet_at,
                closed_at: r.closed_at,
                acked_by: r.acked_by,
                acked_at: r.acked_at,
                summary: r.summary,
                alerts: r.alerts,
                suppressed: r.suppressed,
            })
            .collect())
    }

    /// Close an incident. §2.1: only a human does this, because closing is a claim.
    ///
    /// # Errors
    ///
    /// `NotFound` for another tenant's incident, one that does not exist, or one that is
    /// already closed — closing twice is not idempotent here, it is two people believing
    /// they were the one who understood it.
    pub async fn close_incident(
        &self,
        scope: &TenantScope,
        incident: IncidentId,
        by: ActorId,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let done = sqlx::query!(
            r#"
            UPDATE incident
               SET state = 'closed', closed_at = $3, closed_by = $4
             WHERE id = $1 AND tenant_id = $2 AND state <> 'closed'
            "#,
            incident as IncidentId,
            scope.tenant_id() as uops_core::TenantId,
            at,
            by as ActorId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("incident", incident.to_string(), e))?;

        if done.rows_affected() == 0 {
            return Err(Error::NotFound {
                kind: "incident",
                id: incident.to_string(),
            });
        }
        Ok(())
    }

    /// Move an incident to `quiet` when every alert in it has resolved — §2.1.
    ///
    /// **Never to `closed`.** The router stopping its flapping at 02:14 is not the same
    /// event as somebody deciding at 09:00 that it is understood, and a machine that
    /// closed incidents would be making a claim it is not in a position to make.
    ///
    /// Returns how many incidents went quiet.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn quiet_settled_incidents(
        &self,
        scope: &TenantScope,
        at: DateTime<Utc>,
    ) -> Result<u64> {
        sqlx::query!(
            r#"
            UPDATE incident i
               SET state = 'quiet', quiet_at = $2
             WHERE i.tenant_id = $1
               AND i.state = 'open'
               -- Every alert in it has resolved. `NOT EXISTS` rather than a count, so an
               -- incident whose alerts were deleted with their rule also settles instead
               -- of staying open forever with nothing in it.
               AND NOT EXISTS (
                   SELECT 1
                     FROM incident_alert ia
                     JOIN alert_state a
                       ON a.id = ia.alert_state_id AND a.tenant_id = ia.tenant_id
                    WHERE ia.incident_id = i.id
                      AND ia.tenant_id = i.tenant_id
                      AND a.state IN ('pending', 'firing')
               )
            "#,
            scope.tenant_id() as uops_core::TenantId,
            at,
        )
        .execute(self.pool())
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| map("incident", "quiet".to_owned(), e))
    }
}
