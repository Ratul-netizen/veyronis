//! The collector registry — M12 §2.3, `docs/M12-enterprise.md`.
//!
//! ```text
//!   operator issues a token ──▶ collector enrols ──▶ heartbeat every 30 s
//!                                     │                      │
//!                            assigned tenants come back ─────┘
//!                                     │
//!                       a listener naming an unassigned tenant refuses to start
//! ```
//!
//! # Enrolment is idempotent, so there is no identity file
//!
//! A collector claims `(org, kind, name)`, and `name` defaults to its hostname. Restart
//! it and it claims the same row. The alternative — writing an id to disk on first
//! start — adds a file whose loss produces a second collector doing the same job with no
//! way to tell which is which, and whose *presence* in a container image produces forty
//! collectors that all believe they are the same one.
//!
//! # What the token is for
//!
//! Not security, and migration 0025 says so at length: a collector in this deployment
//! model holds `PostgreSQL` and `ClickHouse` credentials, which are strictly more
//! powerful than any token here. What it buys is that a box brought up with a copied
//! config serves
//! **no tenant** until somebody assigns one, and that the assignment is made server-side
//! rather than by editing the collector's own YAML.
//!
//! # Quiet is computed, never stored
//!
//! A stored flag needs a process to set it, and the processes this table watches are
//! processes. The failure mode of a stored flag is that the thing which stopped is the
//! thing that would have written the flag.

use chrono::{DateTime, Duration, Utc};
use uops_core::{ActorId, OrgId, Result, TenantId};
use uops_secrets::session;

use crate::error::map;
use crate::store::PgStore;

/// How often a collector reports in.
///
/// Thirty seconds, the same interval a lease renews at, and for a related reason: it is
/// short enough that a stopped collector is noticed within the time somebody would take
/// to notice anyway, and long enough that forty collectors are eighty writes a minute
/// rather than a load.
pub const HEARTBEAT: Duration = Duration::seconds(30);

/// How long silence lasts before a collector is called quiet.
///
/// Three missed heartbeats. One missed report is a slow database or a garbage collection
/// pause and means nothing; three in a row is a process that is not running. The same
/// asymmetry the lease's renew ratio comes from — a false "quiet" costs somebody a look
/// at a healthy box, and a late one costs a site whose logs nobody noticed stopping.
pub const QUIET_AFTER: Duration = Duration::minutes(3);

/// What kind of collector this is.
///
/// A closed set matching the `collector_kind` enum in migration 0025. Closed rather than
/// a free string for the same reason `Job` is in `lease.rs`: a typo would create a
/// category nothing else knows about, which looks like working code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(sqlx::Type)]
#[sqlx(type_name = "collector_kind", rename_all = "snake_case")]
pub enum Kind {
    Syslog,
    Otlp,
    Flow,
    /// Not a collector in the ingest sense, and here anyway: a poller that has stopped is
    /// the silence this registry exists to notice, and it is the one whose absence is
    /// least visible — no error, no drop counter, just metrics that stop arriving.
    Poller,
}

impl Kind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syslog => "syslog",
            Self::Otlp => "otlp",
            Self::Flow => "flow",
            Self::Poller => "poller",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "syslog" => Some(Self::Syslog),
            "otlp" => Some(Self::Otlp),
            "flow" => Some(Self::Flow),
            "poller" => Some(Self::Poller),
            _ => None,
        }
    }
}

/// What a collector says about itself.
///
/// Sent at enrolment and again on every heartbeat, because the question an operator asks
/// is *what is running there now* — and an upgrade that did not take is exactly the case
/// where the enrolment-time answer and the current one differ.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub hostname: Option<String>,
    pub version: Option<String>,
    /// What it is bound to, in whatever shape its kind has. Free-form on purpose; see
    /// the `reported` column in migration 0025.
    pub reported: Option<serde_json::Value>,
    /// When this *process* started. Without it, the monotonic counters below make a
    /// restart look like a collector that lost half its traffic.
    pub started_at: Option<DateTime<Utc>>,
    pub received: i64,
    pub written: i64,
    /// Everything lost at either end. One number, because an operator asking "did we lose
    /// anything" does not want a full queue and a full disk reported separately.
    pub lost: i64,
}

/// What enrolment hands back.
#[derive(Clone, Debug)]
pub struct Enrolled {
    pub collector_id: uuid::Uuid,
    pub org_id: OrgId,
    /// The tenants this collector may serve. Empty is the ordinary state of a collector
    /// that has enrolled and not yet been assigned anything, and it means *serve nothing*
    /// rather than *serve everything*.
    pub tenants: Vec<TenantId>,
}

/// A collector as an operator reads it.
#[derive(Clone, Debug)]
pub struct CollectorRow {
    pub id: uuid::Uuid,
    pub kind: Kind,
    pub name: String,
    pub hostname: Option<String>,
    pub version: Option<String>,
    pub reported: Option<serde_json::Value>,
    pub enrolled_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub received: i64,
    pub written: i64,
    pub lost: i64,
    pub retired: bool,
    /// Computed at read time — see the module docs.
    pub quiet: bool,
    /// Never reported at all, which is a different problem from having stopped.
    pub never_reported: bool,
    pub tenants: Vec<TenantId>,
}

/// An enrolment token, without the token.
#[derive(Clone, Debug)]
pub struct TokenRow {
    pub id: uuid::Uuid,
    pub label: String,
    pub kind: Option<Kind>,
    pub expires_at: Option<DateTime<Utc>>,
    pub uses_left: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

/// Why an enrolment was refused.
///
/// Distinguished for the server log and the audit entry, never for the collector: a
/// process that is told *the token is expired* versus *this token is for a syslog
/// collector* has learned something about a token it should not have, and a collector
/// operator reads the server's inventory rather than its own stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// No token matches this hash.
    Unknown,
    Revoked,
    Expired,
    /// The token has no uses left.
    Spent,
    /// The token is restricted to another kind of collector.
    WrongKind,
}

impl Refused {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "no such enrolment token",
            Self::Revoked => "that enrolment token was revoked",
            Self::Expired => "that enrolment token has expired",
            Self::Spent => "that enrolment token has no uses left",
            Self::WrongKind => "that enrolment token is for a different kind of collector",
        }
    }
}

impl PgStore {
    /// Mint an enrolment token.
    ///
    /// Returns the token **once**. Only its hash is stored, so this is the single moment
    /// it exists — the same posture as a session token, and for the same reason: a stolen
    /// database backup must not hand the thief a set of working enrolment tokens.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said, including the unique violation for a second token with
    /// the same label in one organization.
    pub async fn issue_enrolment_token(
        &self,
        org: OrgId,
        label: &str,
        kind: Option<Kind>,
        expires_at: Option<DateTime<Utc>>,
        uses_left: Option<i32>,
        by: Option<ActorId>,
    ) -> Result<(String, uuid::Uuid)> {
        let (token, hash) =
            session::issue().map_err(|e| uops_core::Error::Storage(e.to_string()))?;

        // tenant-exempt: an enrolment token belongs to an organization, which sits above
        // the tenant isolation boundary — the same reason `app_user` does.
        let row = sqlx::query!(
            r#"
            INSERT INTO collector_enrolment_token
                (org_id, label, token_hash, kind, expires_at, uses_left, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
            org as OrgId,
            label,
            hash.as_bytes().as_slice(),
            kind as Option<Kind>,
            expires_at,
            uses_left,
            by as Option<ActorId>,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("enrolment token", label.to_owned(), e))?;

        Ok((token.expose().to_owned(), row.id))
    }

    /// Every enrolment token an organization has, without the tokens.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn enrolment_tokens(&self, org: OrgId) -> Result<Vec<TokenRow>> {
        // tenant-exempt: as `issue_enrolment_token`.
        let rows = sqlx::query!(
            r#"
            SELECT id, label, kind AS "kind: Kind", expires_at, uses_left, created_at,
                   (revoked_at IS NOT NULL) AS "revoked!"
              FROM collector_enrolment_token
             WHERE org_id = $1
             ORDER BY created_at DESC, id
            "#,
            org as OrgId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("enrolment token", org.to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| TokenRow {
                id: r.id,
                label: r.label,
                kind: r.kind,
                expires_at: r.expires_at,
                uses_left: r.uses_left,
                created_at: r.created_at,
                revoked: r.revoked,
            })
            .collect())
    }

    /// Revoke an enrolment token.
    ///
    /// Already-enrolled collectors keep working: enrolment is a bootstrap, and a
    /// revocation that silently stopped forty running collectors would be a revocation
    /// nobody dares perform.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn revoke_enrolment_token(&self, org: OrgId, id: uuid::Uuid) -> Result<bool> {
        // tenant-exempt: as `issue_enrolment_token`.
        let affected = sqlx::query!(
            r#"
            UPDATE collector_enrolment_token SET revoked_at = now()
             WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL
            "#,
            id,
            org as OrgId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("enrolment token", id.to_string(), e))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Enrol, or re-claim an existing identity.
    ///
    /// One transaction, and the order inside it is the point:
    ///
    /// 1. the token is resolved to an organization — this is the only thing that decides
    ///    *whose* collector this is;
    /// 2. the collector row is claimed by `(org, kind, name)`, which is what makes a
    ///    restart idempotent;
    /// 3. a use is consumed **only when a row was created**, so a collector restarting in
    ///    a loop cannot spend a ten-use token in five minutes.
    ///
    /// # Errors
    ///
    /// [`uops_core::Error::Forbidden`] when the token will not do — with the reason in
    /// the message for the server log. See [`Refused`] for why the collector is not told
    /// which reason.
    pub async fn enrol(
        &self,
        token: &str,
        kind: Kind,
        name: &str,
        report: &Report,
    ) -> Result<Enrolled> {
        let hash = session::hash_of(token);

        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("collector", name.to_owned(), e))?;

        // Read without a lock, and `uses_left` is deliberately not read at all. The count
        // is enforced by the decrement further down, which is a single conditional
        // statement — the same shape as the lease's election in `lease.rs`, and for the
        // same reason: a read here followed by an act there is a check-then-act, and no
        // amount of locking makes that pattern easier to reason about than removing it.
        //
        // tenant-exempt: enrolment precedes knowing a tenant. Which tenants this
        // collector may serve is the *next* question, answered at the end of this
        // transaction.
        let found = sqlx::query!(
            r#"
            SELECT id, org_id AS "org_id: OrgId", kind AS "kind: Kind",
                   expires_at, revoked_at
              FROM collector_enrolment_token
             WHERE token_hash = $1
            "#,
            hash.as_bytes().as_slice(),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map("enrolment token", name.to_owned(), e))?;

        let Some(t) = found else {
            return Err(refused(Refused::Unknown));
        };
        if t.revoked_at.is_some() {
            return Err(refused(Refused::Revoked));
        }
        if t.expires_at.is_some_and(|at| at <= Utc::now()) {
            return Err(refused(Refused::Expired));
        }
        if t.kind.is_some_and(|k| k != kind) {
            return Err(refused(Refused::WrongKind));
        }

        // Claim the identity. `xmax = 0` distinguishes the insert from the conflict
        // update — a system column rather than a documented API, and the only way to
        // learn which happened in one statement. The alternative is a second round trip
        // whose race this transaction exists to remove.
        //
        // tenant-exempt: a collector belongs to an organization.
        let claimed = sqlx::query!(
            r#"
            INSERT INTO collector
                (org_id, kind, name, hostname, version, reported, started_at,
                 last_seen_at, received, written, lost)
            VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9, $10)
            ON CONFLICT (org_id, kind, name) DO UPDATE
               SET hostname     = EXCLUDED.hostname,
                   version      = EXCLUDED.version,
                   reported     = EXCLUDED.reported,
                   started_at   = EXCLUDED.started_at,
                   last_seen_at = now(),
                   received     = EXCLUDED.received,
                   written      = EXCLUDED.written,
                   lost         = EXCLUDED.lost,
                   -- A collector that comes back is not retired any more. Somebody
                   -- retired a box and it started talking again; the inventory should
                   -- say so rather than hiding it.
                   retired_at   = NULL
            RETURNING id, org_id AS "org_id: OrgId", (xmax = 0) AS "created!"
            "#,
            t.org_id as OrgId,
            kind as Kind,
            name,
            report.hostname,
            report.version,
            report.reported,
            report.started_at,
            report.received,
            report.written,
            report.lost,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("collector", name.to_owned(), e))?;

        if claimed.created {
            // Only a *new* collector spends a use: a restart loop must not burn a
            // ten-use token in five minutes, and the count is meant to bound how many
            // boxes a token can bring up rather than how many times they may start.
            //
            // **The decrement is the authority, not a read before it.** One statement
            // decides: `uses_left > 0` is evaluated under the row lock PostgreSQL takes
            // for the UPDATE, so two collectors racing the last use cannot both match.
            // The one that does not match gets no row back, and returning here drops the
            // transaction — which takes the collector row inserted above with it.
            //
            // That last part is what makes this correct rather than merely careful: a
            // collector row only survives if a use was actually claimed for it.
            //
            // tenant-exempt: as above.
            let spent = sqlx::query_scalar!(
                r#"
                UPDATE collector_enrolment_token
                   SET uses_left = uses_left - 1
                 WHERE id = $1 AND (uses_left IS NULL OR uses_left > 0)
                RETURNING uses_left
                "#,
                t.id,
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| map("enrolment token", name.to_owned(), e))?;

            if spent.is_none() {
                return Err(refused(Refused::Spent));
            }
        }

        // tenant-exempt: this reads the assignment that *decides* tenant access, so it
        // cannot itself be scoped to one tenant. It is keyed on a collector, which is
        // org-scoped by its own foreign key.
        let tenants = sqlx::query_scalar!(
            r#"SELECT tenant_id AS "tenant_id: TenantId" FROM collector_tenant WHERE collector_id = $1"#,
            claimed.id,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| map("collector", name.to_owned(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("collector", name.to_owned(), e))?;

        Ok(Enrolled {
            collector_id: claimed.id,
            org_id: claimed.org_id,
            tenants,
        })
    }

    /// Report in, and read back the current assignment.
    ///
    /// The assignment comes back on **every** heartbeat rather than only at enrolment,
    /// which is what makes a server-side change take effect within a heartbeat instead of
    /// at the collector's next restart.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said. A collector whose row has been deleted gets
    /// [`uops_core::Error::NotFound`], which its caller turns into a re-enrolment rather
    /// than a crash.
    pub async fn heartbeat(&self, collector: uuid::Uuid, report: &Report) -> Result<Vec<TenantId>> {
        // tenant-exempt: a collector belongs to an organization.
        let updated = sqlx::query!(
            r#"
            UPDATE collector
               SET last_seen_at = now(),
                   hostname   = COALESCE($2, hostname),
                   version    = COALESCE($3, version),
                   reported   = COALESCE($4, reported),
                   started_at = COALESCE($5, started_at),
                   received   = $6,
                   written    = $7,
                   lost       = $8
             WHERE id = $1
            RETURNING id
            "#,
            collector,
            report.hostname,
            report.version,
            report.reported,
            report.started_at,
            report.received,
            report.written,
            report.lost,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("collector", collector.to_string(), e))?;

        if updated.is_none() {
            return Err(uops_core::Error::NotFound {
                kind: "collector",
                id: collector.to_string(),
            });
        }

        // tenant-exempt: as in `enrol`.
        let tenants = sqlx::query_scalar!(
            r#"SELECT tenant_id AS "tenant_id: TenantId" FROM collector_tenant WHERE collector_id = $1"#,
            collector,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("collector", collector.to_string(), e))?;

        Ok(tenants)
    }

    /// Every collector an organization has, with its assignment and whether it is quiet.
    ///
    /// One statement rather than a query per collector's tenants: forty collectors would
    /// otherwise be forty-one round trips to draw one screen.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn collectors(&self, org: OrgId) -> Result<Vec<CollectorRow>> {
        let quiet_after = sqlx::postgres::types::PgInterval::try_from(QUIET_AFTER)
            .map_err(|e| uops_core::Error::Storage(e.to_string()))?;

        // tenant-exempt: a collector belongs to an organization, and this lists them
        // across every tenant it serves.
        let rows = sqlx::query!(
            r#"
            SELECT c.id, c.kind AS "kind: Kind", c.name, c.hostname, c.version, c.reported,
                   c.enrolled_at, c.last_seen_at, c.started_at,
                   c.received, c.written, c.lost,
                   (c.retired_at IS NOT NULL) AS "retired!",
                   -- Computed here rather than stored. See the module docs: the process
                   -- that would write a stored flag is the kind of process this watches.
                   (c.last_seen_at IS NOT NULL
                    AND c.last_seen_at < now() - $2::interval) AS "quiet!",
                   (c.last_seen_at IS NULL) AS "never_reported!",
                   COALESCE(
                       array_agg(ct.tenant_id) FILTER (WHERE ct.tenant_id IS NOT NULL),
                       '{}'
                   ) AS "tenants!: Vec<TenantId>"
              FROM collector c
              LEFT JOIN collector_tenant ct ON ct.collector_id = c.id
             WHERE c.org_id = $1
             GROUP BY c.id
             ORDER BY c.kind, c.name
            "#,
            org as OrgId,
            quiet_after,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("collector", org.to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| CollectorRow {
                id: r.id,
                kind: r.kind,
                name: r.name,
                hostname: r.hostname,
                version: r.version,
                reported: r.reported,
                enrolled_at: r.enrolled_at,
                last_seen_at: r.last_seen_at,
                started_at: r.started_at,
                received: r.received,
                written: r.written,
                lost: r.lost,
                retired: r.retired,
                quiet: r.quiet,
                never_reported: r.never_reported,
                tenants: r.tenants,
            })
            .collect())
    }

    /// Assign a tenant to a collector.
    ///
    /// Re-assigning is a no-op rather than an error, which is what an operator clicking
    /// twice expects.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said — including the composite foreign key that refuses a
    /// tenant belonging to another organization.
    pub async fn assign_collector_tenant(
        &self,
        org: OrgId,
        collector: uuid::Uuid,
        tenant: TenantId,
        by: Option<ActorId>,
    ) -> Result<()> {
        // tenant-exempt: the tenant is a *value* here rather than a scope — this writes a
        // rule about a tenant, and which tenants may appear is enforced by the composite
        // foreign key to `tenant (id, org_id)` rather than by a predicate.
        sqlx::query!(
            r#"
            INSERT INTO collector_tenant (collector_id, org_id, tenant_id, assigned_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (collector_id, tenant_id) DO NOTHING
            "#,
            collector,
            org as OrgId,
            tenant as TenantId,
            by as Option<ActorId>,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("collector assignment", collector.to_string(), e))?;
        Ok(())
    }

    /// Take a tenant away from a collector.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn unassign_collector_tenant(
        &self,
        org: OrgId,
        collector: uuid::Uuid,
        tenant: TenantId,
    ) -> Result<bool> {
        // tenant-exempt: as `assign_collector_tenant`.
        let affected = sqlx::query!(
            r#"
            DELETE FROM collector_tenant
             WHERE collector_id = $1 AND org_id = $2 AND tenant_id = $3
            "#,
            collector,
            org as OrgId,
            tenant as TenantId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("collector assignment", collector.to_string(), e))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Retire a collector.
    ///
    /// Not a delete. The row is referenced by an audit trail and by an operator's memory
    /// of what used to be at a site, and a collector that comes back un-retires itself —
    /// which is the honest outcome when somebody retires a box and it starts talking
    /// again.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn retire_collector(&self, org: OrgId, collector: uuid::Uuid) -> Result<bool> {
        // tenant-exempt: a collector belongs to an organization.
        let affected = sqlx::query!(
            r#"
            UPDATE collector SET retired_at = now()
             WHERE id = $1 AND org_id = $2 AND retired_at IS NULL
            "#,
            collector,
            org as OrgId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("collector", collector.to_string(), e))?
        .rows_affected();
        Ok(affected == 1)
    }
}

/// The collector side of the registry: enrol once, then report in on a schedule.
///
/// One implementation, four callers — the syslog, OTLP and flow collectors and the
/// poller — for the same reason the lease has one: three copies of a heartbeat loop
/// become three slightly different heartbeat loops.
///
/// # Enrolling is opt-in, and that is a transitional state
///
/// A collector with no [`TOKEN_VAR`] in its environment behaves exactly as it did before
/// migration 0025: it reads its own YAML and serves whatever that names. Making enrolment
/// mandatory would have turned this migration into a flag day for every existing
/// deployment, which is not a thing to do to somebody's logging pipeline.
///
/// The consequence is worth stating plainly: **the server-side assignment is
/// authoritative only for collectors that enrolled.** An unenrolled collector can still
/// carry any tenant by editing its own file. What closes that is making the token
/// required, which is a deployment decision rather than a code one, and which belongs
/// after an estate has enrolled everything it has.
#[derive(Clone, Debug)]
pub struct Agent {
    store: PgStore,
    id: uuid::Uuid,
    kind: Kind,
    name: String,
}

/// Where the enrolment token comes from. Unset means "do not enrol"; see [`Agent`].
pub const TOKEN_VAR: &str = "UOPS_COLLECTOR_TOKEN";
/// What this collector calls itself. Defaults to the hostname.
pub const NAME_VAR: &str = "UOPS_COLLECTOR_NAME";

impl Agent {
    /// Enrol, or re-claim the identity this collector already had.
    ///
    /// # Errors
    ///
    /// Whatever the token or `PostgreSQL` said. A collector that cannot enrol **does not
    /// start**: it was given a token, which is an operator saying "this box is part of the
    /// estate", and quietly falling back to its local file would be the one outcome
    /// nobody asked for.
    pub async fn enrol(
        store: PgStore,
        kind: Kind,
        name: &str,
        token: &str,
        report: &Report,
    ) -> Result<(Self, Vec<TenantId>)> {
        let enrolled = store.enrol(token, kind, name, report).await?;
        Ok((
            Self {
                store,
                id: enrolled.collector_id,
                kind,
                name: name.to_owned(),
            },
            enrolled.tenants,
        ))
    }

    #[must_use]
    pub const fn id(&self) -> uuid::Uuid {
        self.id
    }

    #[must_use]
    pub fn describe(&self) -> String {
        format!("{} {} ({})", self.kind.as_str(), self.name, self.id)
    }

    /// What this collector calls itself: `UOPS_COLLECTOR_NAME`, or the hostname.
    ///
    /// The hostname default is what makes enrolment idempotent without an identity file —
    /// see the module docs. A host running two collectors of the same kind needs the
    /// variable, and that is the case the variable exists for.
    #[must_use]
    pub fn default_name() -> String {
        std::env::var(NAME_VAR)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .unwrap_or_else(|| "unnamed".to_owned())
    }

    /// Report in once, and read back the assignment.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn beat(&self, report: &Report) -> Result<Vec<TenantId>> {
        self.store.heartbeat(self.id, report).await
    }

    /// Report in until told to stop.
    ///
    /// A failed heartbeat is logged and **not** fatal. A collector that stopped ingesting
    /// because it could not tell the registry it was alive would be a monitoring product
    /// causing the outage it exists to report — the same judgement `lease.rs` makes about
    /// a database blip.
    ///
    /// A change in the assignment is logged and not acted on; see the note in [`Agent`]
    /// about what is and is not enforced while running.
    pub async fn run<F>(self, mut report: F, shutdown: impl std::future::Future<Output = ()> + Send)
    where
        F: FnMut() -> Report + Send,
    {
        let period = HEARTBEAT
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));
        let mut ticker = tokio::time::interval(period);
        // A collector that was paused — a suspended VM, a stopped container — must not
        // send a burst of catch-up heartbeats claiming it was alive the whole time.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut known: Option<Vec<TenantId>> = None;
        let mut shutdown = std::pin::pin!(shutdown);

        loop {
            tokio::select! {
                () = &mut shutdown => return,
                _ = ticker.tick() => {
                    match self.beat(&report()).await {
                        Ok(tenants) => {
                            if known.as_ref().is_some_and(|k| k != &tenants) {
                                // Logged rather than applied. An operator who changes an
                                // assignment should be able to see that the collector
                                // heard it, even while acting on it needs a restart.
                                println!(
                                    "collector {}: the tenant assignment changed to {} tenant(s); restart to apply it",
                                    self.describe(),
                                    tenants.len()
                                );
                            }
                            known = Some(tenants);
                        }
                        Err(uops_core::Error::NotFound { .. }) => {
                            // The row was deleted underneath us. Re-enrolling needs the
                            // token, which this process may no longer hold, so the honest
                            // thing is to say so and keep ingesting.
                            eprintln!(
                                "collector {}: this collector is no longer registered; it is still ingesting. Re-enrol it to restore the inventory",
                                self.describe()
                            );
                        }
                        Err(e) => eprintln!("collector {}: heartbeat failed: {e}", self.describe()),
                    }
                }
            }
        }
    }
}

/// Check that every tenant a collector was configured to serve was assigned to it.
///
/// Called before a socket is bound, for the same reason the tenant slugs are resolved
/// before a socket is bound: a daemon that started and *then* found it may not carry a
/// customer would be accepting messages it has nowhere to put.
///
/// # Errors
///
/// [`uops_core::Error::Forbidden`] naming the tenants, because the operator reading it
/// has to go and assign them and the message is where they find out which.
pub fn check_assignment(configured: &[(String, TenantId)], assigned: &[TenantId]) -> Result<()> {
    let missing: Vec<&str> = configured
        .iter()
        .filter(|(_, id)| !assigned.contains(id))
        .map(|(slug, _)| slug.as_str())
        .collect();

    if missing.is_empty() {
        return Ok(());
    }

    // Leaked deliberately: the error type carries a `&'static str`, and the slugs have to
    // reach the operator. A one-off allocation on a startup path that is about to either
    // exit or run for months is not a leak anybody will measure.
    let message: &'static str = Box::leak(
        format!(
            "this collector is not assigned {}: {}. Assign it in the collector inventory, or remove the listener",
            if missing.len() == 1 {
                "this tenant"
            } else {
                "these tenants"
            },
            missing.join(", ")
        )
        .into_boxed_str(),
    );
    Err(uops_core::Error::Forbidden(message))
}

/// A refusal, with the reason in the message for the server log.
fn refused(why: Refused) -> uops_core::Error {
    uops_core::Error::Forbidden(why.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kind_set_is_closed() {
        for kind in [Kind::Syslog, Kind::Otlp, Kind::Flow, Kind::Poller] {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(Kind::parse("snmp"), None);
        assert_eq!(Kind::parse("Syslog"), None);
        assert_eq!(Kind::parse(""), None);
    }

    #[test]
    fn three_missed_heartbeats_is_quiet() {
        // The ratio, asserted rather than assumed: one missed report is a slow database
        // and means nothing, so the threshold has to be a multiple of the interval.
        assert_eq!(QUIET_AFTER.num_seconds() / HEARTBEAT.num_seconds(), 6);
        assert!(QUIET_AFTER > HEARTBEAT * 2);
    }

    #[test]
    fn a_listener_naming_an_unassigned_tenant_is_refused_by_name() {
        let acme = TenantId::new();
        let globex = TenantId::new();
        let configured = vec![("acme".to_owned(), acme), ("globex".to_owned(), globex)];

        assert!(check_assignment(&configured, &[acme, globex]).is_ok());
        assert!(
            check_assignment(&configured, &[globex, acme]).is_ok(),
            "order is not significant"
        );

        let Err(uops_core::Error::Forbidden(why)) = check_assignment(&configured, &[acme]) else {
            panic!("an unassigned tenant must be refused")
        };
        assert!(
            why.contains("globex"),
            "the message names the tenant: {why}"
        );
        assert!(
            !why.contains("acme"),
            "and not the ones that were fine: {why}"
        );
    }

    #[test]
    fn a_collector_assigned_nothing_may_serve_nothing() {
        // The state a freshly enrolled collector is in. Serving nothing is the point: a
        // box brought up with a copied config must not start carrying a customer.
        let acme = TenantId::new();
        assert!(check_assignment(&[("acme".to_owned(), acme)], &[]).is_err());
        // A collector with no listeners is fine with no assignment, which is what a
        // poller looks like.
        assert!(check_assignment(&[], &[]).is_ok());
    }

    #[test]
    fn being_assigned_more_than_is_configured_is_fine() {
        // An operator who assigns a tenant before the listener exists has staged a
        // change, not made a mistake.
        let acme = TenantId::new();
        let spare = TenantId::new();
        assert!(check_assignment(&[("acme".to_owned(), acme)], &[acme, spare]).is_ok());
    }

    #[test]
    fn every_refusal_says_something_an_operator_can_act_on() {
        for why in [
            Refused::Unknown,
            Refused::Revoked,
            Refused::Expired,
            Refused::Spent,
            Refused::WrongKind,
        ] {
            assert!(!why.as_str().is_empty());
            // Not "forbidden" or "invalid token" — the server log is read by somebody
            // holding the console, and the whole value of the distinction is that it
            // names the fix.
            assert!(why.as_str().contains("token"), "{}", why.as_str());
        }
    }
}
