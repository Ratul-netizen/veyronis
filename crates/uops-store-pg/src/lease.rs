//! Exactly one owner for a background job — M12, `docs/M12-enterprise.md` §2.1.
//!
//! ```text
//!   acquire ──▶ hold ──renew every 10s──▶ hold ──▶ (crash or stop)
//!                 │                                     │
//!                 └── lost: another process took it ────┴──▶ lapses after 30s
//! ```
//!
//! # The whole mechanism is one UPDATE
//!
//! ```sql
//! UPDATE lease SET holder = $me, expires_at = now() + $period
//!  WHERE name = $job AND (expires_at < now() OR holder = $me)
//! ```
//!
//! Two processes starting together both run it. PostgreSQL takes a row lock, so the
//! second one waits, and by the time it runs the predicate the first has already moved
//! `expires_at` into the future — so it matches nothing and reports zero rows affected.
//! That is the election, and it needs no protocol beyond the one the database already
//! implements.
//!
//! `OR holder = $me` is what makes the same statement serve renewal. A holder renewing is
//! the same claim restated, and giving renewal its own statement would mean two places
//! that must agree about what holding means.
//!
//! # What this is not
//!
//! Not distributed consensus. It is correct for as long as there is one PostgreSQL, which
//! is the assumption every other write in this product already makes — and adding etcd to
//! improve on that would add a second thing that can be down and a second thing an
//! on-premise customer has to operate.
//!
//! **Clock skew between processes is not a factor**, which is the one property worth
//! being explicit about: every comparison is `now()` *inside the database*, so two hosts
//! disagreeing about the time cannot both believe they hold a lease. A process's own
//! clock is used for nothing here.

use chrono::{DateTime, Duration, Utc};
use uops_core::Result;

use crate::error::map;
use crate::store::PgStore;

/// How long a claim lasts before anyone may take it.
///
/// Thirty seconds, renewed every ten — see [`RENEW_EVERY`]. Long enough that a slow
/// database does not cause a handover, short enough that a crashed process's work resumes
/// before anybody notices it stopped.
pub const PERIOD: Duration = Duration::seconds(30);

/// How often a holder restates its claim.
///
/// Three renewals per [`PERIOD`], so **two consecutive failures do not lose the lease**.
/// The ratio comes from the asymmetry of the two outcomes: losing a lease costs one
/// skipped cycle that the next holder picks up, and two processes both believing they
/// hold one costs the double-poll this exists to prevent.
pub const RENEW_EVERY: Duration = Duration::seconds(10);

/// The jobs that must have exactly one owner.
///
/// A fixed set rather than a free string, matched by the `CHECK` on the table: a typo in
/// a job name would silently create a lease nobody else contends for, which looks like
/// working code and is the failure this whole module exists to prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    /// The poll scheduler — `uops-poller`.
    Poll,
    /// The alert evaluator — `uops-alert`.
    Alert,
    /// The discovery sweeper — `uops-sweeper`.
    Sweep,
    /// The runbook runner — `uops-runner`, M10 §2.9.
    ///
    /// The one job here whose double-execution is not a duplicated *reading* but a
    /// duplicated *change*: two runners picking up the same queued run would send
    /// `clear bgp neighbor` to a device twice. The lease bounds how many processes
    /// contend; what makes the claim atomic is the conditional `UPDATE` in
    /// [`crate::PgStore::claim_next_run`], for the reason the enrolment token taught in
    /// M12 §2.3 — a lock that a connection pool happens to serialise is not a guard you
    /// can point at.
    Run,
}

impl Job {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Poll => "poll",
            Self::Alert => "alert",
            Self::Sweep => "sweep",
            Self::Run => "run",
        }
    }
}

/// What a claim attempt concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// This process holds the lease until the given instant.
    Held { until: DateTime<Utc> },
    /// Somebody else holds it. Wait and ask again — do not work.
    Taken,
}

impl Claim {
    #[must_use]
    pub const fn is_held(self) -> bool {
        matches!(self, Self::Held { .. })
    }
}

/// Who a process says it is.
///
/// Hostname and pid, because the first question in a support conversation about a fleet
/// that stopped being polled is *which box holds the poll lease*. A hash would answer it
/// only for somebody with access to the same hash function.
///
/// New on every start: a restarted process must not inherit its predecessor's claim by
/// looking like it, which is exactly what a stable identity would allow while the old
/// lease still had time on it.
#[must_use]
pub fn identity() -> String {
    let host = hostname();
    format!("{host}:{}", std::process::id())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned())
}

impl PgStore {
    /// Take a lease, or renew one already held.
    ///
    /// One statement, and the row lock is the election — see the module docs.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said. A failure is **not** a lost lease: the caller keeps
    /// working until its claim actually lapses, because a database blip that stopped
    /// every scheduler would be a worse outage than the one this prevents.
    pub async fn claim(&self, job: Job, holder: &str) -> Result<Claim> {
        // `make_interval(secs => …)` takes a double. Thirty seconds is exactly
        // representable and the constant is not going to approach 2^53.
        #[expect(clippy::cast_precision_loss, reason = "a lease period in seconds")]
        let period = PERIOD.num_seconds() as f64;

        // tenant-exempt: a lease is an installation-wide election and belongs to no
        // tenant. Every scheduler it governs walks all of them in one pass, so a lease
        // per tenant would mean a thousand rows renewed every ten seconds to elect the
        // same process a thousand times.
        let row = sqlx::query!(
            r#"
            UPDATE lease
               SET holder      = $2,
                   expires_at  = now() + make_interval(secs => $3),
                   -- Only when it actually changes hands. A renewal must not move
                   -- `acquired_at`, or "how long has this process held it" becomes "how
                   -- long since the last renewal" and is always ten seconds.
                   acquired_at = CASE WHEN holder = $2 THEN acquired_at ELSE now() END,
                   takeovers   = CASE WHEN holder = $2 THEN takeovers ELSE takeovers + 1 END
             WHERE name = $1
               AND (expires_at < now() OR holder = $2)
            RETURNING expires_at
            "#,
            job.as_str(),
            holder,
            period,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("lease", job.as_str().to_owned(), e))?;

        Ok(match row {
            Some(r) => Claim::Held {
                until: r.expires_at,
            },
            None => Claim::Taken,
        })
    }

    /// Give up a lease this process holds.
    ///
    /// An optimisation for a clean shutdown, never the mechanism: a crashed process
    /// cannot call this, which is why the lease expires on its own. What it buys is a
    /// rolling restart where the replacement starts working immediately instead of
    /// waiting out a period nobody is using.
    ///
    /// Silent when this process is not the holder — releasing something somebody else
    /// took is not an error, it is a slow shutdown finishing after a handover.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn release(&self, job: Job, holder: &str) -> Result<()> {
        // tenant-exempt: as `claim`.
        sqlx::query!(
            r#"
            UPDATE lease SET expires_at = to_timestamp(0)
             WHERE name = $1 AND holder = $2
            "#,
            job.as_str(),
            holder,
        )
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(|e| map("lease", job.as_str().to_owned(), e))
    }

    /// Who holds a lease, for an operator asking.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn lease_holder(&self, job: Job) -> Result<LeaseRow> {
        // tenant-exempt: as `claim`.
        let r = sqlx::query!(
            r#"
            SELECT holder, expires_at, acquired_at, takeovers,
                   expires_at > now() AS "live!"
              FROM lease WHERE name = $1
            "#,
            job.as_str(),
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("lease", job.as_str().to_owned(), e))?;

        Ok(LeaseRow {
            job,
            holder: r.holder,
            expires_at: r.expires_at,
            acquired_at: r.acquired_at,
            takeovers: r.takeovers,
            live: r.live,
        })
    }
}

/// A lease as an operator reads it.
#[derive(Clone, Debug)]
pub struct LeaseRow {
    pub job: Job,
    pub holder: String,
    pub expires_at: DateTime<Utc>,
    pub acquired_at: DateTime<Utc>,
    /// How many times it has changed hands.
    ///
    /// A counter rather than a log, because the question it answers is *is this flapping*
    /// and the answer is a rate. A lease changing holder every period is a process that
    /// cannot renew — an overloaded database, a paused VM, a clock that jumped — and it
    /// looks identical to healthy operation unless somebody counts.
    pub takeovers: i64,
    /// Whether the claim is still in force *according to the database's clock*.
    pub live: bool,
}
