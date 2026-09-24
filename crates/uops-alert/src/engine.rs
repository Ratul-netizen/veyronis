//! Evaluating one rule, and then every rule.
//!
//! The decision itself is [`uops_core::alert::step`] and lives elsewhere, without a
//! database or a clock. What is here is everything around it: which query to run, which
//! resources were expected, which of them are inside a maintenance window, and how the
//! answer gets written down exactly once.
//!
//! # Four things that are decisions, not details
//!
//! **A suppressed series is not evaluated at all.** SPEC: *"suppress alerts means the
//! rule does not fire at all"*. So a resource inside an open maintenance window is
//! skipped before `step` sees it, and its stored phase is left exactly as it was — a
//! window that opens over a firing alert does not resolve it, and one that closes does
//! not re-fire it. Suppressing *notifications* is the softer request and does the obvious
//! thing: the phase moves, nobody is told.
//!
//! **A series that stops producing data does not resolve.** A threshold rule that was
//! firing for a device which has now gone silent stays firing. "No data" is what an
//! absence rule is for, and treating it as recovery is how a real outage gets marked as
//! resolved at the moment it gets worse.
//!
//! **An absent resource has to be expected before it can be missing.** An absence rule
//! resolves its selector against the control plane and treats every resource that
//! produced no row as absent. That is why a rule scoped to the whole tenant is refused
//! when it is written: "everything" includes resources that have never reported once,
//! and the rule would fire for all of them on its first evaluation.
//!
//! **One failure does not stop a cycle.** A tenant whose `ClickHouse` query fails is
//! recorded and the rest are evaluated, because the alternative is that one broken rule
//! silences every other rule in the installation.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::Mutex;
use uops_core::alert::{Phase, step};
use uops_core::{ResourceId, Suppression, TenantId, TenantScope};
use uops_incident::{Firing, GroupReason, NoCandidate, candidate, group};
use uops_query::{Query, ResolvedResources, resolve};
use uops_store_ch::{ChStore, TelemetryStore};
use uops_store_pg::{AlertRule, Evaluated, PgCatalog, PgStore};

use crate::plan::{self, Reading, Series};

/// What one series' evaluation concluded.
#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub rule_id: uuid::Uuid,
    pub resource: ResourceId,
    pub dedup_key: String,
    pub phase: Phase,
    /// When the alert entered this phase. Carried so a notification can say the problem
    /// started eleven minutes ago rather than claiming it started when the message got
    /// through a rate limit.
    pub since: DateTime<Utc>,
    /// Whether somebody is to be told. Exactly the two entries `firing` and `resolved`,
    /// and never while notifications are suppressed.
    pub notify: bool,
    pub value: Option<f64>,
    /// How many alerts this one's incident had already silenced when it was decided — M9
    /// §2.4.
    ///
    /// Zero on nearly everything, including on the alert that *causes* a cascade: when
    /// the switch fires, the forty hosts behind it have not gone quiet yet. See
    /// `group_into_incident` for why that is not a bug and why delaying the page to find
    /// out would be worse.
    pub suppressed: u32,
}

/// What one pass over one rule did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RuleOutcome {
    pub decisions: Vec<Decision>,
    /// Series skipped because a maintenance window covers them.
    pub suppressed: usize,
    /// True when the evaluation filled its series ceiling — see [`plan::MAX_SERIES`].
    pub truncated: bool,
    /// Things that went wrong *beside* the evaluation rather than in it.
    ///
    /// M9's grouping is the first of these: an alert that cannot be put into an incident
    /// is still an alert, and still notifies. Returning `Err` from the evaluation would
    /// throw away a decision the engine had already made and written — SPEC §M0.2 rule 1
    /// one level up, where the thing that matters is not lost for the thing that
    /// decorates it.
    pub failures: Vec<String>,
}

impl RuleOutcome {
    #[must_use]
    pub fn notifications(&self) -> usize {
        self.decisions.iter().filter(|d| d.notify).count()
    }
}

/// What one pass over everything did.
#[derive(Clone, Debug, Default)]
pub struct Cycle {
    pub rules: usize,
    pub series: usize,
    pub notifications: usize,
    pub suppressed: usize,
    /// One sentence per rule that could not be evaluated. Collected rather than logged
    /// inside the loop, so the caller decides how often to say so and the engine stays
    /// testable without capturing output.
    pub failures: Vec<String>,
}

/// How long a tenant's suppression map is reused for.
///
/// Working out which resources are inside an open maintenance window costs one query for
/// the windows and one per window for what it covers. Doing that per *rule* means an
/// installation with SPEC's 1 000 rules pays a thousand times a cycle for an answer that
/// changes at the boundaries of a window somebody scheduled last week — which is the
/// difference between a suppression check and a second workload.
///
/// Ten seconds is the staleness this buys it with: a window that opens is honoured within
/// ten seconds, and one that closes lets alerting resume within ten. Both are far inside
/// the minute an evaluation interval is measured in, and the failure mode of being late
/// is the safe one — alerts stay suppressed a moment longer than the window, never a
/// moment less.
const SUPPRESSION_TTL: Duration = Duration::seconds(10);

/// The evaluator.
#[derive(Clone, Debug)]
pub struct Engine {
    pg: PgStore,
    ch: ChStore,
    /// Per tenant: when it was read, and what it said. Shared across clones so the run
    /// loop's spawned evaluations reuse one another's work rather than each doing it.
    suppression: SuppressionCache,
}

/// One line describing an incident at the moment it was opened.
///
/// Not a title a human edits — M9 §5 keeps incident editing out of v0.1, because an
/// editable summary is the first half of a ticketing system. It names the rule, because
/// that is what an operator recognises, and the grouping reason, because §2.3 requires an
/// incident of one to say why it is one.
fn summary(rule: &AlertRule, reason: GroupReason) -> String {
    format!("{} — {}", rule.name, reason.explain())
}

/// Which resources are inside an open maintenance window, and what it suppresses.
pub type Suppressions = HashMap<ResourceId, Suppression>;

/// One tenant's [`Suppressions`] and when they were read, shared between evaluations.
type SuppressionCache = Arc<Mutex<HashMap<TenantId, (DateTime<Utc>, Arc<Suppressions>)>>>;

impl Engine {
    #[must_use]
    pub fn new(pg: PgStore, ch: ChStore) -> Self {
        Self {
            pg,
            ch,
            suppression: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Evaluate one rule and write down what it decided.
    ///
    /// # Errors
    ///
    /// When the query cannot be resolved or run. A rule whose evaluation fails keeps the
    /// phase it had: the engine does not know whether the condition holds, and inventing
    /// either answer is worse than saying nothing.
    pub async fn evaluate(
        &self,
        scope: &TenantScope,
        rule: &AlertRule,
        now: DateTime<Utc>,
    ) -> uops_core::Result<RuleOutcome> {
        let query = plan::evaluation_query(&rule.query, rule.condition, now);
        let resources = resolve(&query.resources, scope, &PgCatalog::new(self.pg.clone()))
            .await
            .map_err(|e| uops_core::Error::Storage(e.to_string()))?;

        let reading = self.read(scope, &query, rule, &resources, now).await?;

        let known: HashMap<String, (Phase, DateTime<Utc>)> = self
            .pg
            .rule_state(scope, rule.id)
            .await?
            .into_iter()
            .map(|row| (row.dedup_key, (row.phase, row.since)))
            .collect();
        let suppression = self.suppressions(scope, now).await?;

        let mut outcome = RuleOutcome {
            truncated: reading.truncated,
            ..RuleOutcome::default()
        };

        for series in reading.series {
            let key = uops_core::alert::dedup_key(
                rule.id,
                series.resource,
                series.labels.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            );

            let quiet = suppression.get(&series.resource).copied();
            if quiet.is_some_and(|s| s.alerts) {
                // Not evaluated at all, and the stored phase is left alone. A window that
                // opens over a firing alert does not resolve it.
                outcome.suppressed += 1;
                continue;
            }

            let was = known.get(&key).copied();
            let breaching = rule.condition.breached_by(series.value);
            let transition = step(was, breaching, rule.condition.hold(), now);

            // Write when something is wrong, or when something *was* wrong and has just
            // stopped being — and never otherwise.
            //
            // The `was.is_some()` this used to say looks equivalent and is not: a series
            // that recovered keeps an `ok` row, so every series that has ever alerted
            // would be rewritten on every cycle, for ever. On an estate where a few
            // hundred resources have alerted at some point in the past year, that is a
            // few hundred pointless writes a minute whose only symptom is a `PostgreSQL`
            // instance that is busier than anybody can explain.
            let recovering = was.is_some_and(|(phase, _)| phase.is_active());
            let written = if transition.phase.is_active() || recovering {
                Some(
                    self.pg
                        .record_evaluation(
                            scope,
                            &Evaluated {
                                rule_id: rule.id,
                                resource_id: series.resource,
                                dedup_key: key.clone(),
                                phase: transition.phase,
                                since: transition.since,
                                at: now,
                                value: Some(series.value),
                            },
                        )
                        .await?,
                )
            } else {
                None
            };

            // The softer half of a maintenance window: the phase moves, the history is
            // kept, nobody is woken up.
            let mut notify = transition.notify && !quiet.is_some_and(|s| s.notifications);
            let mut suppressed = 0u32;

            // M9 §2.2. An alert that has just *entered* firing is grouped into an
            // incident, and grouping may take its notification away — §2.4. Only on the
            // entering edge: `notify` is also true when an alert resolves, and a
            // resolution belongs to the incident its alert already joined.
            if notify
                && transition.phase == Phase::Firing
                && let Some(row) = &written
            {
                {
                    match self.group_into_incident(scope, rule, row, now).await {
                        Ok((permitted, count)) => {
                            notify = permitted;
                            suppressed = count;
                        }
                        // Grouping is not allowed to lose an alert. A failure here leaves
                        // the alert ungrouped and notifying, which is the same behaviour
                        // the product had before M9 — SPEC §M0.2 rule 1 applied one level
                        // up: never block the thing that matters for the thing that
                        // decorates it.
                        Err(e) => outcome
                            .failures
                            .push(format!("incident grouping for rule {}: {e}", rule.id)),
                    }
                }
            }

            outcome.decisions.push(Decision {
                rule_id: rule.id,
                resource: series.resource,
                dedup_key: key,
                phase: transition.phase,
                since: transition.since,
                notify,
                value: Some(series.value),
                suppressed,
            });
        }

        Ok(outcome)
    }

    /// Put a newly firing alert into an incident, and say whether it may still notify.
    ///
    /// M9 §2.2 and §2.4. Everything that decides is in `uops_incident`; everything here
    /// is the four reads and one write that decision needs, in the order it needs them.
    ///
    /// # Why the candidate is recomputed rather than carried
    ///
    /// §2.5 picks the resource with nothing above it, and the answer depends on the whole
    /// membership — which is what just changed. An incident that grew a new root has a new
    /// candidate, and holding the old one would mean the screen names a switch that turned
    /// out to be downstream of the thing that actually broke.
    /// # Why the cause's own page cannot name what it suppressed
    ///
    /// §2.4 asks the notification for a cause to say *"and 39 downstream resources"*. At
    /// the moment the switch's alert fires, the hosts behind it are still up: the
    /// suppressions happen over the following seconds, after the page has gone out.
    ///
    /// Waiting to find out would mean delaying the notification for the outage in order
    /// to describe it better, which trades the thing that matters for the thing that
    /// decorates it — the same rule §M0.2 holds one level down.
    ///
    /// So the count is read **at notify time** and is honest about that: it is what the
    /// incident had silenced when this alert was decided. The complete figure lives on
    /// the incident, where the screen and the API both show it.
    async fn group_into_incident(
        &self,
        scope: &TenantScope,
        rule: &AlertRule,
        alert: &uops_store_pg::AlertStateRow,
        now: DateTime<Utc>,
    ) -> uops_core::Result<(bool, u32)> {
        let firing = Firing {
            resource_id: alert.resource_id,
            rule_id: rule.id,
            at: now,
        };

        let open = self.pg.open_incidents(scope).await?;
        let topology = self.pg.neighbourhood(scope, alert.resource_id).await?;
        let suppression = self.pg.suppression_enabled(scope).await?;

        let decision = group(&firing, &open, &topology, suppression);
        let severity = rule.severity.as_str();

        let incident = if let Some(id) = decision.join {
            let hops = match decision.reason {
                GroupReason::Connected { hops } => Some(hops),
                _ => None,
            };
            self.pg
                .join_incident(scope, id, alert.id, decision.notify, hops, severity, now)
                .await?;
            id
        } else {
            {
                // §2.3: an incident of one on an estate with no topology carries the
                // reason it was not grouped, because it is indistinguishable from a bug
                // otherwise.
                let why = match decision.reason {
                    GroupReason::NoTopology => Some(NoCandidate::NoTopology.as_str()),
                    _ => None,
                };
                self.pg
                    .open_incident(
                        scope,
                        alert.id,
                        severity,
                        &summary(rule, decision.reason),
                        now,
                        why,
                    )
                    .await?
            }
        };

        // Recomputed over the membership as it now stands. The oracle is one query per
        // pair, which is bounded by the incident's size and runs only when an alert joins
        // — not on the evaluation path that every series takes every cycle.
        let members = self.pg.incident_members(scope, incident).await?;
        let mut upstream = std::collections::HashMap::new();
        for a in &members {
            for b in &members {
                if a.resource_id != b.resource_id {
                    let yes = self
                        .pg
                        .is_upstream_of(scope, a.resource_id, b.resource_id)
                        .await?;
                    upstream.insert((a.resource_id, b.resource_id), yes);
                }
            }
        }
        let picked = candidate(&members, topology.estate_has_topology, |upper, lower| {
            upstream.get(&(upper, lower)).copied().unwrap_or(false)
        });
        self.pg
            .set_candidate(scope, incident, picked.map_err(NoCandidate::as_str))
            .await?;

        let suppressed = self.pg.incident_suppressed(scope, incident).await?;
        Ok((
            decision.notify,
            u32::try_from(suppressed).unwrap_or(u32::MAX),
        ))
    }

    /// Run the evaluation query, and for an absence rule add the resources that produced
    /// nothing at all.
    async fn read(
        &self,
        scope: &TenantScope,
        query: &Query,
        rule: &AlertRule,
        resources: &ResolvedResources,
        now: DateTime<Utc>,
    ) -> uops_core::Result<Reading> {
        let result = self
            .ch
            .query(query, scope, resources)
            .await
            .map_err(|e| uops_core::Error::Storage(e.to_string()))?;

        Ok(match rule.condition {
            uops_core::alert::Condition::Threshold { .. } => plan::read_threshold(&result),
            uops_core::alert::Condition::Absence { after_seconds } => {
                let mut reading = plan::read_absence(&result, now);

                // The whole point of an absence rule: the resources that are *not* in the
                // result are the ones nothing has arrived from. They cannot come out of a
                // result set, so they come out of the selector.
                let seen: HashSet<ResourceId> = reading.series.iter().map(|s| s.resource).collect();
                let expected = resources.ids().unwrap_or(&[]);

                for resource in expected.iter().filter(|r| !seen.contains(r)) {
                    reading.series.push(Series {
                        resource: *resource,
                        labels: Vec::new(),
                        // Nothing in the whole window, so the age is at least the window.
                        // Reported as the window rather than as infinity because it is
                        // the true lower bound and it is what the UI shows.
                        value: f64::from(after_seconds).max(plan::MIN_WINDOW_SECONDS) + 1.0,
                    });
                }
                reading
            }
        })
    }

    /// Which of this tenant's resources should not alert right now, and why.
    ///
    /// Two sources, and they are different in kind. A **maintenance window** is scheduled
    /// work with a start and an end. A **status** is a state a resource sits in until
    /// somebody changes it — `Maintenance` and `Decommissioned`, which
    /// `ResourceStatus::alertable` has always named and which nothing consulted until
    /// 2026-09-25. See `PgStore::not_alertable` for what that cost.
    ///
    /// Cached for [`SUPPRESSION_TTL`] and shared between evaluations: read once per rule,
    /// this would be several queries a rule a cycle for an answer that changes at the
    /// edges of a window scheduled last week, or when somebody retires a device.
    async fn suppressions(
        &self,
        scope: &TenantScope,
        now: DateTime<Utc>,
    ) -> uops_core::Result<Arc<Suppressions>> {
        {
            let cache = self.suppression.lock().await;
            if let Some((read_at, map)) = cache.get(&scope.tenant_id())
                && now - *read_at < SUPPRESSION_TTL
                && now >= *read_at
            {
                return Ok(Arc::clone(map));
            }
        }

        let fresh = Arc::new(self.read_suppressions(scope, now).await?);
        self.suppression
            .lock()
            .await
            .insert(scope.tenant_id(), (now, Arc::clone(&fresh)));
        Ok(fresh)
    }

    async fn read_suppressions(
        &self,
        scope: &TenantScope,
        now: DateTime<Utc>,
    ) -> uops_core::Result<Suppressions> {
        let mut covered: Suppressions = HashMap::new();

        // Status first, so that an explicit window over the same resource can only ever
        // widen what is suppressed and never narrow it — the combine below is `|=`.
        //
        // `Suppression::default()` is both flags, which is the right hammer here and for the
        // reason `uops_core::maintenance` gives for it being the default: an alert that
        // fired for a device somebody retired is still in the history afterwards, and
        // somebody has to explain it.
        for resource in self.pg.not_alertable(scope).await? {
            covered.insert(resource, Suppression::default());
        }

        for window in self.pg.live_windows(scope, now).await? {
            if !window.schedule.is_open_at(now) {
                continue;
            }
            for resource in self.pg.covered_by(scope, window.target).await? {
                // Two windows over one resource combine to the stronger request. An
                // operator who scheduled work on a site and on one device in it means
                // both, not the second one.
                covered
                    .entry(resource)
                    .and_modify(|s| {
                        s.alerts |= window.suppression.alerts;
                        s.notifications |= window.suppression.notifications;
                    })
                    .or_insert(window.suppression);
            }
        }

        Ok(covered)
    }

    /// Evaluate every enabled rule in one tenant.
    pub async fn evaluate_tenant(&self, tenant: TenantId, now: DateTime<Utc>) -> Cycle {
        let scope = TenantScope::collector(tenant);
        let mut cycle = Cycle::default();

        let rules = match self.pg.alert_rules(&scope).await {
            Ok(rules) => rules,
            Err(e) => {
                cycle.failures.push(format!("tenant {tenant}: {e}"));
                return cycle;
            }
        };

        for rule in rules.iter().filter(|r| r.enabled) {
            cycle.rules += 1;
            match self.evaluate(&scope, rule, now).await {
                Ok(outcome) => {
                    cycle.series += outcome.decisions.len();
                    cycle.notifications += outcome.notifications();
                    cycle.suppressed += outcome.suppressed;
                    cycle.failures.extend(outcome.failures);
                    if outcome.truncated {
                        cycle.failures.push(format!(
                            "rule {} read the maximum of {} series and stopped; its grouping \
                             produces more alerts than one rule can hold",
                            rule.name,
                            plan::MAX_SERIES
                        ));
                    }
                }
                // One rule's failure is not a reason to stop evaluating the others: the
                // alternative is that a single broken rule silences the installation.
                Err(e) => cycle.failures.push(format!("rule {}: {e}", rule.name)),
            }
        }

        // M9 §2.1. An incident whose alerts have all resolved becomes *quiet* — never
        // closed, because closing is a claim that it is understood and a machine is not
        // in a position to make one.
        //
        // Once per tenant per cycle rather than per rule: it is one statement over the
        // tenant's open incidents, and running it per rule would repeat it a thousand
        // times for an answer that changes when an alert resolves.
        if let Err(e) = self.pg.quiet_settled_incidents(&scope, now).await {
            cycle.failures.push(format!("settling incidents: {e}"));
        }

        cycle
    }

    /// Evaluate every enabled rule in every tenant.
    ///
    /// Crosses tenants by iterating, the way the poller's fleet loader does: `TenantScope`
    /// has no "all tenants" constructor on purpose, so the crossing is a `for` loop
    /// somebody can see rather than a `WHERE` clause somebody eventually copies.
    ///
    /// # Errors
    ///
    /// Only when the tenant list itself cannot be read.
    pub async fn cycle(&self, now: DateTime<Utc>) -> uops_core::Result<Cycle> {
        let mut total = Cycle::default();

        for tenant in self.pg.all_tenant_ids().await? {
            let cycle = self.evaluate_tenant(tenant, now).await;
            total.rules += cycle.rules;
            total.series += cycle.series;
            total.notifications += cycle.notifications;
            total.suppressed += cycle.suppressed;
            total.failures.extend(cycle.failures);
        }

        Ok(total)
    }
}
