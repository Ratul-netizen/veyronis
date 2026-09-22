//! §2.2, §2.3, §2.4 and §2.5, one test per rule.
//!
//! These are `docs/M9-incident.md`'s acceptance criteria before they are integration
//! tests: the grouping rules are the part of this milestone most likely to be wrong, and
//! a rule that can only be exercised through PostgreSQL is a rule nobody exercises at the
//! edges.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use uops_core::{IncidentId, ResourceId};
use uops_incident::{
    Decision, Firing, GroupReason, Member, Neighbourhood, NoCandidate, OpenIncident, RADIUS,
    candidate, group,
};

fn at(minutes: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + minutes * 60, 0)
        .single()
        .expect("an instant")
}

fn rule() -> uuid::Uuid {
    uuid::Uuid::now_v7()
}

fn incident(
    last_alert: DateTime<Utc>,
    resources: &[ResourceId],
    rules: &[uuid::Uuid],
) -> OpenIncident {
    OpenIncident {
        id: IncidentId::new(),
        last_alert_at: last_alert,
        resources: resources.iter().copied().collect(),
        rules: rules.iter().copied().collect(),
    }
}

/// A topology in which `near` is one hop away and `upstream` is above the alerting
/// resource.
fn topology(of: ResourceId, near: &[(ResourceId, u8)], upstream: &[ResourceId]) -> Neighbourhood {
    let mut within = BTreeMap::new();
    within.insert(of, 0);
    for (r, hops) in near {
        within.insert(*r, *hops);
    }
    Neighbourhood {
        within,
        upstream: upstream.iter().copied().collect(),
        estate_has_topology: true,
    }
}

/// An estate where nothing links to anything — a legitimate deployment, §2.3.
fn no_topology(of: ResourceId) -> Neighbourhood {
    Neighbourhood {
        within: [(of, 0)].into_iter().collect(),
        upstream: BTreeSet::new(),
        estate_has_topology: false,
    }
}

// --- §2.2  time and topology ---------------------------------------------------------

#[test]
fn a_cascade_joins_one_incident() {
    // The switch alerted; a host two hops away alerts thirty seconds later. One incident,
    // not two — this is the criterion the whole milestone is for.
    let switch = ResourceId::new();
    let host = ResourceId::new();
    let open = vec![incident(at(0), &[switch], &[rule()])];

    let decision = group(
        &Firing {
            resource_id: host,
            rule_id: rule(),
            at: at(0) + Duration::seconds(30),
        },
        &open,
        &topology(host, &[(switch, 2)], &[switch]),
        false,
    );

    assert_eq!(decision.join, Some(open[0].id));
    assert_eq!(decision.reason, GroupReason::Connected { hops: 2 });
}

#[test]
fn two_unrelated_failures_in_the_same_minute_are_two_incidents() {
    // Time alone is not enough. A busy estate has unrelated failures in the same minute,
    // and grouping by time produces one enormous incident that is really a clock.
    let theirs = ResourceId::new();
    let mine = ResourceId::new();
    let open = vec![incident(at(0), &[theirs], &[rule()])];

    // `mine` has a neighbourhood, and `theirs` is not in it.
    let decision = group(
        &Firing {
            resource_id: mine,
            rule_id: rule(),
            at: at(0) + Duration::seconds(20),
        },
        &open,
        &topology(mine, &[(ResourceId::new(), 1)], &[]),
        false,
    );

    assert_eq!(decision.join, None);
    assert_eq!(decision.reason, GroupReason::NotConnected);
    assert!(decision.notify, "a new incident always notifies");
}

#[test]
fn two_failures_on_one_resource_a_week_apart_are_two_incidents() {
    // Topology alone is not enough either, and this is the case that shows it: the
    // resource is not merely connected to the open incident, it *is* the open incident.
    let switch = ResourceId::new();
    let open = vec![incident(at(0), &[switch], &[rule()])];

    let decision = group(
        &Firing {
            resource_id: switch,
            rule_id: rule(),
            at: at(7 * 24 * 60),
        },
        &open,
        &topology(switch, &[], &[]),
        false,
    );

    assert_eq!(decision.join, None);
    assert_eq!(decision.reason, GroupReason::NothingRecent);
}

#[test]
fn the_join_window_slides_so_a_slow_cascade_stays_one_incident() {
    // Measured from the incident's *last* alert, not its first. Twenty devices failing
    // over twelve minutes is one cascade; a fixed window from the start would cut it in
    // half and produce two incidents for one event.
    let first = ResourceId::new();
    let second = ResourceId::new();
    let open = vec![incident(at(4), &[first], &[rule()])];

    let decision = group(
        &Firing {
            resource_id: second,
            rule_id: rule(),
            // Nine minutes after the incident started, four after its last alert.
            at: at(8),
        },
        &open,
        &topology(second, &[(first, 1)], &[]),
        false,
    );

    assert_eq!(
        decision.join,
        Some(open[0].id),
        "four minutes is inside the window"
    );
}

#[test]
fn one_rule_over_many_resources_is_one_incident() {
    // A threshold rule matching five thousand resources fires five thousand times, and
    // that is one condition rather than five thousand incidents — the same reading M4's
    // rate limiter takes. It holds with no topology at all, which is most of the value
    // for a customer who has not run discovery.
    let shared = rule();
    let open = vec![incident(at(0), &[ResourceId::new()], &[shared])];
    let alerting = ResourceId::new();

    let decision = group(
        &Firing {
            resource_id: alerting,
            rule_id: shared,
            at: at(1),
        },
        &open,
        &no_topology(alerting),
        false,
    );

    assert_eq!(decision.join, Some(open[0].id));
    assert_eq!(decision.reason, GroupReason::SameRule);
    assert!(
        !decision.notify,
        "one condition notifies once, whatever the topology setting says"
    );
}

#[test]
fn an_alert_connected_to_two_incidents_joins_the_nearer_one() {
    // And the tie, if the hops are equal, goes to the more recent incident — so the
    // decision is deterministic and the alert lands with the activity it most likely
    // belongs to.
    let near = ResourceId::new();
    let far = ResourceId::new();
    let alerting = ResourceId::new();
    let open = vec![
        incident(at(1), &[far], &[rule()]),
        incident(at(0), &[near], &[rule()]),
    ];

    let decision = group(
        &Firing {
            resource_id: alerting,
            rule_id: rule(),
            at: at(2),
        },
        &open,
        &topology(alerting, &[(near, 1), (far, 2)], &[]),
        false,
    );

    assert_eq!(decision.join, Some(open[1].id), "one hop beats two");
    assert_eq!(decision.reason, GroupReason::Connected { hops: 1 });
}

#[test]
fn a_resource_past_the_radius_is_not_connected() {
    // Two hops reaches an access switch, its distribution switch and the hosts under it.
    // Three, on a campus, reaches most of the estate — at which point grouping by
    // topology means grouping by "is in the building".
    let alerting = ResourceId::new();
    let distant = ResourceId::new();
    let open = vec![incident(at(0), &[distant], &[rule()])];

    // The caller's walk is bounded by RADIUS, so a resource beyond it is simply absent
    // from `within` — which is the shape this asserts.
    let mut topo = topology(alerting, &[], &[]);
    topo.within.remove(&distant);
    const { assert!(RADIUS >= 2, "the radius is the documented two") };

    let decision = group(
        &Firing {
            resource_id: alerting,
            rule_id: rule(),
            at: at(1),
        },
        &open,
        &topo,
        false,
    );
    assert_eq!(decision.join, None);
}

// --- §2.3  no topology ---------------------------------------------------------------

#[test]
fn with_no_topology_every_alert_is_its_own_incident_and_says_why() {
    // An estate with no discovered links is legitimate: SNMP refused, LLDP off, forty
    // cloud hosts with no L2 between them. Every alert becomes an incident of one, and
    // the reason is carried rather than left to look like a bug.
    //
    // What must *not* happen is a fallback to grouping by time, which would produce
    // confident nonsense exactly where there is least information.
    let alerting = ResourceId::new();
    let open = vec![incident(at(0), &[ResourceId::new()], &[rule()])];

    let decision = group(
        &Firing {
            resource_id: alerting,
            rule_id: rule(),
            at: at(1),
        },
        &open,
        &no_topology(alerting),
        false,
    );

    assert_eq!(decision.join, None);
    assert_eq!(decision.reason, GroupReason::NoTopology);
    assert!(
        decision
            .reason
            .explain()
            .contains("nothing links this estate")
    );
}

// --- §2.4  suppression ---------------------------------------------------------------

#[test]
fn suppression_silences_a_downstream_alert_and_nothing_else() {
    let switch = ResourceId::new();
    let host = ResourceId::new();
    let open = vec![incident(at(0), &[switch], &[rule()])];
    let firing = Firing {
        resource_id: host,
        rule_id: rule(),
        at: at(1),
    };
    // The switch is upstream of the host.
    let topo = topology(host, &[(switch, 1)], &[switch]);

    let on = group(&firing, &open, &topo, true);
    assert_eq!(on.join, Some(open[0].id));
    assert!(!on.notify, "the cause already notified");

    // The alert is still in the incident either way. Suppression is about the page at
    // 4am, never about the record — an operator looking at the incident sees all forty.
    let off = group(&firing, &open, &topo, false);
    assert_eq!(off.join, on.join);
    assert!(off.notify, "off by default, and off means notify");
}

#[test]
fn suppression_is_directional() {
    // The hosts fail first and the switch a minute later. The switch's alert is new
    // information and must notify — an upstream failure is never a symptom of a
    // downstream one.
    let switch = ResourceId::new();
    let host = ResourceId::new();
    let open = vec![incident(at(0), &[host], &[rule()])];

    // Nothing in the incident is upstream of the switch; the switch is upstream of them.
    let topo = topology(switch, &[(host, 1)], &[]);

    let decision = group(
        &Firing {
            resource_id: switch,
            rule_id: rule(),
            at: at(1),
        },
        &open,
        &topo,
        true,
    );

    assert_eq!(decision.join, Some(open[0].id), "still one incident");
    assert!(
        decision.notify,
        "the cause arriving second is still the cause"
    );
}

// --- §2.5  the candidate -------------------------------------------------------------

fn member(resource: ResourceId, minutes: i64) -> Member {
    Member {
        resource_id: resource,
        first_alert_at: at(minutes),
    }
}

#[test]
fn the_candidate_is_the_resource_with_nothing_above_it() {
    let switch = ResourceId::new();
    let host_a = ResourceId::new();
    let host_b = ResourceId::new();
    let members = [member(host_a, 1), member(switch, 0), member(host_b, 2)];

    let found = candidate(&members, true, |upper, lower| {
        upper == switch && (lower == host_a || lower == host_b)
    });

    assert_eq!(found, Ok(switch));
}

#[test]
fn the_earlier_alert_breaks_a_tie_between_two_roots() {
    // Two resources with nothing above either. The one that failed first is the better
    // story, and it is a *fact* rather than a score.
    let first = ResourceId::new();
    let second = ResourceId::new();
    let members = [member(second, 5), member(first, 1)];

    assert_eq!(candidate(&members, true, |_, _| false), Ok(first));
}

#[test]
fn two_roots_at_the_same_instant_have_no_candidate() {
    // Two stories, and the product does not pick one. Ordering by id would be arbitrary
    // dressed up as a finding.
    let a = ResourceId::new();
    let b = ResourceId::new();
    let members = [member(a, 3), member(b, 3)];

    assert_eq!(
        candidate(&members, true, |_, _| false),
        Err(NoCandidate::Disconnected)
    );
}

#[test]
fn an_incident_of_one_has_a_candidate_even_with_no_topology() {
    // The order of the two checks in `candidate`, asserted. One alert on one device has
    // an unambiguous origin whether or not anything in the estate is linked — and an
    // integration test found this the wrong way round, reporting "no likely origin" for
    // the single device the incident was about.
    let only = ResourceId::new();
    assert_eq!(candidate(&[member(only, 0)], false, |_, _| false), Ok(only));
}

#[test]
fn an_estate_with_no_topology_has_no_candidate() {
    // Nothing is upstream of anything, so nothing is a likely origin. The screen says
    // there is none and why — an empty field is information.
    let members = [member(ResourceId::new(), 0), member(ResourceId::new(), 1)];

    assert_eq!(
        candidate(&members, false, |_, _| true),
        Err(NoCandidate::NoTopology)
    );
}

#[test]
fn an_incident_of_one_is_its_own_candidate() {
    // Whatever the topology looks like. One alert, one resource, no ambiguity to refuse.
    let only = ResourceId::new();
    assert_eq!(candidate(&[member(only, 0)], true, |_, _| true), Ok(only));
}

#[test]
fn a_cycle_in_the_topology_does_not_produce_a_candidate() {
    // Two resources each upstream of the other — which a discovered graph really can
    // contain, which is why `resource_dependents()` carries a cycle guard. Neither is a
    // root, so there is no candidate, and saying so beats picking one.
    let a = ResourceId::new();
    let b = ResourceId::new();
    let members = [member(a, 0), member(b, 1)];

    assert_eq!(
        candidate(&members, true, |_, _| true),
        Err(NoCandidate::Disconnected)
    );
}

// --- the shape of a decision ---------------------------------------------------------

#[test]
fn a_new_incident_always_notifies() {
    // Nothing has told anybody about this yet. Suppression can only ever silence an alert
    // that joined something already reported — that is what makes it safe enough to ship
    // at all, and it holds for every path that returns `join: None`.
    let alerting = ResourceId::new();
    for (open, topo) in [
        (vec![], topology(alerting, &[], &[])),
        (
            vec![incident(at(0), &[ResourceId::new()], &[rule()])],
            no_topology(alerting),
        ),
    ] {
        let decision: Decision = group(
            &Firing {
                resource_id: alerting,
                rule_id: rule(),
                at: at(1),
            },
            &open,
            &topo,
            true,
        );
        assert_eq!(decision.join, None);
        assert!(decision.notify, "{:?} must notify", decision.reason);
    }
}
