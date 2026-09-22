//! Grouping alerts into incidents — M9, `docs/M9-incident.md`.
//!
//! ```text
//!   alert fires ─▶ group() ─▶ join an open incident, or open a new one
//!                     │
//!                     └─ and decide whether this alert may notify
//! ```
//!
//! # Everything here is pure
//!
//! `group` takes what the caller has already read — the open incidents, the topology
//! around the alerting resource — and returns a decision. It reads nothing, writes
//! nothing and does not know what a database is.
//!
//! That is the same split `uops_alert`'s state machine has, and for the same reason: the
//! rules in §2.2 are the part of this milestone most likely to be wrong, and a rule that
//! can only be exercised through PostgreSQL is a rule nobody will exercise at the edges.
//! Every case in §4's acceptance criteria is a unit test in this crate before it is an
//! integration test anywhere else.
//!
//! # What is deliberately *not* here
//!
//! The candidate's *recomputation* when an incident grows. §2.5 picks the candidate from
//! the incident's resources, and that set changes as alerts join — so the caller recomputes
//! it with [`candidate`] after each join rather than this module holding state across
//! calls. Pure functions, called again, beats a struct that remembers.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use uops_core::{IncidentId, ResourceId};

/// How long after an incident's most recent alert another one may still join it.
///
/// §2.2. Five minutes, measured from the incident's *last* alert rather than its first,
/// which is what makes the window slide: a cascade of twenty devices taking three minutes
/// to propagate stays one incident, while a fresh failure five minutes after the last one
/// is a fresh failure.
pub const JOIN_WINDOW: Duration = Duration::minutes(5);

/// How far through the topology two resources may be and still be one incident.
///
/// §2.2. Two hops reaches an access switch, its distribution switch, and the hosts
/// hanging off it. Three, on a typical campus, reaches most of the estate — at which
/// point grouping by topology means grouping by "is in the building".
pub const RADIUS: u8 = 2;

/// What the caller knows about one open incident when it decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenIncident {
    pub id: IncidentId,
    /// When the most recent alert joined. [`JOIN_WINDOW`] measures from here.
    pub last_alert_at: DateTime<Utc>,
    /// Every resource that already has an alert in this incident.
    pub resources: BTreeSet<ResourceId>,
    /// The rules that already have an alert in this incident — §2.2's third row.
    pub rules: BTreeSet<uuid::Uuid>,
}

/// The alert that just fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Firing {
    pub resource_id: ResourceId,
    pub rule_id: uuid::Uuid,
    pub at: DateTime<Utc>,
}

/// What the topology says about the neighbourhood of the alerting resource.
///
/// Passed in rather than looked up, so the decision is a pure function of its inputs. The
/// caller builds it from `resource_dependents()` — the cycle-guarded walk M0 wrote once
/// so that *"M6 and M9 don't each write it"*.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Neighbourhood {
    /// Every resource within [`RADIUS`] hops, and how many hops away it is. Includes the
    /// alerting resource itself at zero.
    pub within: BTreeMap<ResourceId, u8>,
    /// Resources that are *upstream* of the alerting one — it depends on them.
    ///
    /// Directed, and separate from `within` because §2.4's suppression is directional:
    /// upstream suppresses downstream and never the reverse.
    pub upstream: BTreeSet<ResourceId>,
    /// Whether this tenant has **any** topology at all.
    ///
    /// Not derivable from an empty `within`: a resource with no links in an estate that
    /// has plenty is a different fact from an estate with no links anywhere, and §2.3
    /// says the screen must be able to tell them apart.
    pub estate_has_topology: bool,
}

/// Why an alert was grouped the way it was.
///
/// §2.3 requires this to reach the screen. An incident of one on an estate with no
/// topology is correct and looks identical to a bug unless it can say so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupReason {
    /// Joined: the resource is within [`RADIUS`] hops of one already in the incident.
    Connected { hops: u8 },
    /// Joined: the same rule already has an alert in it.
    ///
    /// A threshold rule matching five thousand resources is one condition, not five
    /// thousand incidents — the same reading M4's rate limiter takes.
    SameRule,
    /// A new incident: nothing open was still inside the join window.
    NothingRecent,
    /// A new incident: something was recent, and none of it was connected to this.
    NotConnected,
    /// A new incident: this tenant has no topology, so nothing can be connected to
    /// anything. §2.3 — and the reason grouping by time alone is refused.
    NoTopology,
}

impl GroupReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected { .. } => "connected",
            Self::SameRule => "same_rule",
            Self::NothingRecent => "nothing_recent",
            Self::NotConnected => "not_connected",
            Self::NoTopology => "no_topology",
        }
    }

    /// A sentence for the screen. §2.3's "carries the reason it was not grouped".
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Connected { .. } => "connected to this incident through the topology",
            Self::SameRule => "the same rule is already firing in this incident",
            Self::NothingRecent => "no incident had an alert in the last five minutes",
            Self::NotConnected => "no recent incident is within two hops of this resource",
            Self::NoTopology => {
                "nothing links this estate yet, so no alert can be grouped with another"
            }
        }
    }
}

/// What to do with an alert that has just fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The incident to join, or `None` to open a new one.
    pub join: Option<IncidentId>,
    /// Whether this alert may send a notification — §2.4.
    pub notify: bool,
    pub reason: GroupReason,
}

/// Where this alert belongs, and whether it may notify.
///
/// # The order of the rules is the decision
///
/// 1. **Only incidents still inside the join window are candidates.** Time is checked
///    first because it is the cheap test and because an old incident is not a candidate
///    however well connected it is — two failures on one switch a week apart are two
///    failures.
/// 2. **The same rule wins over topology.** A rule matching five thousand resources
///    fires five thousand times; those are one condition. Checking this before the radius
///    also means it works on an estate with no topology at all, which is most of the
///    value for a customer who has not run discovery.
/// 3. **Then the radius**, nearest first — so an alert connected to two open incidents
///    joins the closer one. Ties break on the more recent incident, which keeps the
///    decision deterministic and puts the alert with the activity it most likely belongs
///    to.
/// 4. **Otherwise a new incident**, carrying the reason it was not grouped.
#[must_use]
pub fn group(
    firing: &Firing,
    open: &[OpenIncident],
    topology: &Neighbourhood,
    suppression_enabled: bool,
) -> Decision {
    let recent: Vec<&OpenIncident> = open
        .iter()
        .filter(|i| firing.at.signed_duration_since(i.last_alert_at) <= JOIN_WINDOW)
        // An incident whose last alert is in the *future* relative to this one is a
        // clock going backwards, not a grouping question. Treated as recent, because the
        // alternative is that a device with a fast clock never groups with anything.
        .collect();

    if recent.is_empty() {
        return Decision {
            join: None,
            notify: true,
            reason: if topology.estate_has_topology {
                GroupReason::NothingRecent
            } else {
                GroupReason::NoTopology
            },
        };
    }

    // Rule 2: the same rule, whatever the topology says.
    if let Some(same) = recent
        .iter()
        .filter(|i| i.rules.contains(&firing.rule_id))
        .max_by_key(|i| i.last_alert_at)
    {
        return Decision {
            join: Some(same.id),
            // A rule firing on a second resource is a second symptom of the same
            // condition, and notifying per resource is the storm M4's rate limiter exists
            // to stop. Suppressed regardless of the topology setting, because this is not
            // topology suppression — it is one condition, once.
            notify: false,
            reason: GroupReason::SameRule,
        };
    }

    // Rule 3: nearest by hops, then most recent.
    let nearest = recent
        .iter()
        .filter_map(|i| {
            i.resources
                .iter()
                .filter_map(|r| topology.within.get(r).copied())
                .min()
                .map(|hops| (hops, *i))
        })
        .min_by(|(a_hops, a), (b_hops, b)| {
            a_hops
                .cmp(b_hops)
                .then(b.last_alert_at.cmp(&a.last_alert_at))
        });

    if let Some((hops, incident)) = nearest {
        // §2.4, and the whole of it: an alert is silenced only when something the
        // incident already knows about is *upstream* of this resource. Downstream never
        // suppresses upstream — if the hosts fail first and the switch a minute later,
        // the switch's alert is new information and notifies.
        let downstream_of_a_known_cause = incident
            .resources
            .iter()
            .any(|r| topology.upstream.contains(r));
        return Decision {
            join: Some(incident.id),
            notify: !(suppression_enabled && downstream_of_a_known_cause),
            reason: GroupReason::Connected { hops },
        };
    }

    Decision {
        join: None,
        notify: true,
        reason: if topology.estate_has_topology {
            GroupReason::NotConnected
        } else {
            GroupReason::NoTopology
        },
    }
}

/// What an incident's resources look like to [`candidate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub resource_id: ResourceId,
    /// When this resource's first alert in the incident fired. The tie-break.
    pub first_alert_at: DateTime<Utc>,
}

/// Why an incident has no candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoCandidate {
    /// The estate has no topology, so nothing is upstream of anything.
    NoTopology,
    /// More than one resource has nothing upstream of it, and they alerted at the same
    /// instant. Two roots is two stories, and the product does not pick one.
    Disconnected,
}

impl NoCandidate {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoTopology => "no_topology",
            Self::Disconnected => "disconnected",
        }
    }
}

/// The incident's **candidate** — §2.5, and never its cause.
///
/// The resource with no other incident resource upstream of it, breaking ties by whichever
/// alerted first. No scoring and no confidence: a number like "87% confident" invites
/// trust that nothing here has earned, which is the same reason the identity resolver
/// raises a review instead of auto-merging on weak evidence.
///
/// `upstream_of(a, b)` answers *is `a` upstream of `b`* — the caller supplies it from the
/// same topology walk `group` was given.
///
/// # Errors
///
/// [`NoCandidate`] when the tie cannot be broken, which is information rather than a
/// failure: the screen says there is no likely origin, and why.
pub fn candidate<F>(
    members: &[Member],
    estate_has_topology: bool,
    upstream_of: F,
) -> Result<ResourceId, NoCandidate>
where
    F: Fn(ResourceId, ResourceId) -> bool,
{
    if !estate_has_topology {
        return Err(NoCandidate::NoTopology);
    }

    // An incident of one has exactly one answer, whatever the topology looks like.
    if let [only] = members {
        return Ok(only.resource_id);
    }

    let roots: Vec<&Member> = members
        .iter()
        .filter(|m| {
            !members.iter().any(|other| {
                other.resource_id != m.resource_id && upstream_of(other.resource_id, m.resource_id)
            })
        })
        .collect();

    // Every member is downstream of some other member, which a discovered graph really
    // can produce — `resource_dependents()` carries a cycle guard for exactly that
    // reason. No root means no origin to name.
    let Some(earliest) = roots.iter().min_by_key(|m| m.first_alert_at) else {
        return Err(NoCandidate::Disconnected);
    };

    // Two roots that alerted at the same instant are two stories, and the product does
    // not pick one. Ordering by id would be arbitrary dressed up as a finding.
    let tied = roots
        .iter()
        .filter(|m| m.first_alert_at == earliest.first_alert_at)
        .count();
    if tied > 1 {
        Err(NoCandidate::Disconnected)
    } else {
        Ok(earliest.resource_id)
    }
}
