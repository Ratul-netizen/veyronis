//! Every signal for a set of resources in one window — PLAN §6, and what M0's sort key
//! was chosen for.
//!
//! ```text
//!   metrics ─┐
//!   logs    ─┤
//!   events  ─┼─▶ one axis, ordered by time
//!   states  ─┤
//!   flows   ─┤
//!   spans   ─┘
//! ```
//!
//! # The whole point of the sort key, finally spent
//!
//! PLAN §6 named the Investigation Workspace as a product concept at M0 *because it
//! constrained M0's decisions*:
//!
//! > every store must answer "all signals for resource R in window W" cheaply — that
//! > dictates `ORDER BY (tenant_id, resource_id, observed_at)` on every telemetry table,
//! > a decision that is nearly free now and a full re-ingest later.
//!
//! Six milestones later, every telemetry table has that sort key. So this is **N ordinary
//! queries**, one per signal, each already a contiguous range read — not a join, not a
//! new table, and not a new access pattern. W1 measured the shape at **9 ms over 100M
//! logs**.
//!
//! # Why there is no stored timeline
//!
//! M9 §2.6. An incident's window moves while it is open, the retention of the signals is
//! not the retention of the incident, and a stored copy is a second truth to reconcile
//! with the first — which is the same reason M8 refused to store the service map.
//!
//! The consequence is accepted rather than hidden: **an incident older than the telemetry
//! it is about has holes**, and [`Coverage`] is how the screen says which signals expired
//! instead of drawing a gap that looks like silence.

use chrono::{DateTime, Duration, Utc};

use crate::ast::{Query, ResourceSelector, SignalType, Sort, SortKey, TimeRange};
use crate::error::{Error, Result};

/// How long each signal's *raw* rows are kept, from `ch-migrations/`.
///
/// Raw, not rolled up: a timeline wants the events that happened, and
/// `metrics_5m`/`service_5m` hold aggregates of them. A caller who wants the long window
/// asks for a chart, which is a different screen and a different question.
///
/// These mirror the `TTL … DELETE` clauses and have to be kept in step with them. A
/// number that drifts low makes the screen claim a signal expired when it is there; one
/// that drifts high draws an empty row and calls it silence.
#[must_use]
pub const fn retention(signal: SignalType) -> Duration {
    match signal {
        // 0004_metrics.sql — the shortest of the raw tables after flows and spans.
        SignalType::Metric => Duration::days(30),
        // 0001_logs.sql, 0006_events_states.sql.
        SignalType::Log | SignalType::Event => Duration::days(365),
        // 0006_events_states.sql — states are kept longest, because a status transition is
        // small and its history is what an availability report reads.
        SignalType::State => Duration::days(1095),
        // 0007_flows.sql, 0008_spans.sql. Both are investigation data and therefore recent.
        SignalType::Flow | SignalType::Trace => Duration::days(7),
    }
}

/// Every signal a timeline draws, in the order it draws them.
///
/// States first and traces last, which is the order an operator reads a failure in: what
/// changed, what was said about it, what the traffic did, what a request experienced.
pub const SIGNALS: [SignalType; 6] = [
    SignalType::State,
    SignalType::Event,
    SignalType::Log,
    SignalType::Metric,
    SignalType::Flow,
    SignalType::Trace,
];

/// Whether a signal can still answer for this window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// The whole window is inside retention.
    Whole,
    /// The window starts before this signal's retention does. The rows that survive are
    /// returned, and the screen says the rest expired rather than drawing silence.
    Partial { from: DateTime<Utc> },
    /// The window ends before retention begins. There is nothing left at all.
    Expired,
}

/// One signal's part of a timeline.
#[derive(Clone, Debug)]
pub struct Track {
    pub signal: SignalType,
    pub coverage: Coverage,
    /// `None` when the signal is [`Coverage::Expired`] — there is nothing to ask for, and
    /// issuing the query anyway would spend a scan to return zero rows and tell the
    /// screen nothing it does not already know.
    pub query: Option<Query>,
}

/// How many rows one signal contributes.
///
/// A timeline is read by eye and merged in memory, so this is a ceiling per track rather
/// than a page. Six signals at this limit is the most a screen can draw before it stops
/// being a timeline and becomes a log viewer.
pub const PER_SIGNAL: u32 = 500;

/// The queries that draw a timeline, one per signal.
///
/// # Errors
///
/// An empty or backwards window, or no resources — each of which is a caller's mistake
/// rather than a timeline with nothing in it, and the two must not look the same.
pub fn timeline(
    resources: &[uops_core::ResourceId],
    within: TimeRange,
    now: DateTime<Utc>,
) -> Result<Vec<Track>> {
    if within.end <= within.start {
        return Err(Error::Invalid(
            "time range must be non-empty and forward: start < end".into(),
        ));
    }
    if resources.is_empty() {
        return Err(Error::Invalid(
            "a timeline is about at least one resource; an empty set is not a window with \
             nothing in it"
                .into(),
        ));
    }

    Ok(SIGNALS
        .iter()
        .map(|&signal| {
            let horizon = now - retention(signal);
            let coverage = if within.end <= horizon {
                Coverage::Expired
            } else if within.start < horizon {
                Coverage::Partial { from: horizon }
            } else {
                Coverage::Whole
            };

            let query = match coverage {
                Coverage::Expired => None,
                // The window is clamped to what survives. Asking for the part that does
                // not exist costs a scan of partitions that were already dropped, and
                // returns the same rows.
                Coverage::Partial { from } => {
                    Some(one(signal, resources, TimeRange::new(from, within.end)))
                }
                Coverage::Whole => Some(one(signal, resources, within)),
            };

            Track {
                signal,
                coverage,
                query,
            }
        })
        .collect())
}

/// One signal's query: this window, these resources, oldest first.
///
/// Oldest first because a timeline is read forwards — the point is what happened *before*
/// the thing that broke, and a newest-first list puts the cause at the bottom.
fn one(signal: SignalType, resources: &[uops_core::ResourceId], within: TimeRange) -> Query {
    Query::new(signal, within)
        .with_resources(ResourceSelector::Ids {
            ids: resources.to_vec(),
        })
        .with_limit(PER_SIGNAL)
        .ordered(crate::ast::Field::ObservedAt)
}

impl Query {
    /// Oldest first on one column, replacing whatever order was there.
    #[must_use]
    fn ordered(mut self, field: crate::ast::Field) -> Self {
        self.order_by = vec![Sort {
            key: SortKey::Field { field },
            desc: false,
        }];
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use uops_core::ResourceId;

    fn at(days_ago: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000, 0)
            .single()
            .expect("an instant")
            - Duration::days(days_ago)
    }

    fn now() -> DateTime<Utc> {
        at(0)
    }

    fn resources() -> Vec<ResourceId> {
        vec![ResourceId::new()]
    }

    fn tracks(window: TimeRange) -> Vec<Track> {
        timeline(&resources(), window, now()).expect("a timeline")
    }

    fn track(tracks: &[Track], signal: SignalType) -> &Track {
        tracks
            .iter()
            .find(|t| t.signal == signal)
            .expect("every signal has a track")
    }

    #[test]
    fn a_recent_window_covers_every_signal() {
        let tracks = tracks(TimeRange::new(now() - Duration::hours(1), now()));
        assert_eq!(tracks.len(), SIGNALS.len());
        for t in &tracks {
            assert_eq!(t.coverage, Coverage::Whole, "{:?}", t.signal);
            assert!(t.query.is_some());
        }
    }

    #[test]
    fn an_old_incident_says_which_signals_expired() {
        // M9 §2.6's accepted consequence, and the reason it is accepted rather than
        // hidden: an incident from three weeks ago has its logs and its states, and the
        // flows and spans it was about are gone.
        let tracks = tracks(TimeRange::new(at(21) - Duration::hours(1), at(21)));

        assert_eq!(track(&tracks, SignalType::Log).coverage, Coverage::Whole);
        assert_eq!(track(&tracks, SignalType::Metric).coverage, Coverage::Whole);
        assert_eq!(track(&tracks, SignalType::Flow).coverage, Coverage::Expired);
        assert_eq!(
            track(&tracks, SignalType::Trace).coverage,
            Coverage::Expired
        );
    }

    #[test]
    fn an_expired_signal_is_not_queried_at_all() {
        // There is nothing to ask for. Issuing the query anyway spends a scan to return
        // zero rows and tells the screen nothing it does not already know.
        let tracks = tracks(TimeRange::new(at(30) - Duration::hours(1), at(30)));
        assert!(track(&tracks, SignalType::Flow).query.is_none());
        assert!(track(&tracks, SignalType::Log).query.is_some());
    }

    #[test]
    fn a_window_that_straddles_the_horizon_is_clamped_rather_than_refused() {
        // A ten-day incident's flows exist for the last seven. Returning them and saying
        // where they start beats returning nothing, and beats asking for partitions that
        // were dropped.
        let tracks = tracks(TimeRange::new(at(10), now()));
        let flows = track(&tracks, SignalType::Flow);

        match flows.coverage {
            Coverage::Partial { from } => {
                assert_eq!(from, now() - Duration::days(7));
                assert_eq!(
                    flows.query.as_ref().expect("a query").time.start,
                    from,
                    "the query asks only for what survives"
                );
            }
            other => panic!("expected partial coverage, got {other:?}"),
        }
    }

    #[test]
    fn every_query_is_scoped_to_the_incidents_resources() {
        // A timeline about two devices must not read the tenant. The selector is what
        // makes each of these a contiguous range read rather than a scan.
        let ids = vec![ResourceId::new(), ResourceId::new()];
        let tracks = timeline(
            &ids,
            TimeRange::new(now() - Duration::hours(1), now()),
            now(),
        )
        .expect("a timeline");

        for t in &tracks {
            let q = t.query.as_ref().expect("a query");
            assert_eq!(q.resources, ResourceSelector::Ids { ids: ids.clone() });
        }
    }

    #[test]
    fn a_timeline_is_read_forwards() {
        // The point is what happened *before* the thing that broke. Newest-first puts the
        // cause at the bottom of the screen.
        for t in tracks(TimeRange::new(now() - Duration::hours(1), now())) {
            let q = t.query.expect("a query");
            assert_eq!(q.order_by.len(), 1);
            assert!(!q.order_by[0].desc, "{:?}", t.signal);
        }
    }

    #[test]
    fn a_backwards_window_is_the_callers_mistake() {
        // Rather than a timeline with nothing in it, which is what a quiet hour looks
        // like — and the two must not be indistinguishable.
        assert!(matches!(
            timeline(
                &resources(),
                TimeRange::new(now(), now() - Duration::hours(1)),
                now()
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            timeline(&resources(), TimeRange::new(now(), now()), now()),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn a_timeline_about_nothing_is_refused() {
        assert!(matches!(
            timeline(
                &[],
                TimeRange::new(now() - Duration::hours(1), now()),
                now()
            ),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn the_retentions_match_the_migrations() {
        // These mirror `TTL … DELETE` clauses in `ch-migrations/`. A number that drifts
        // low makes the screen claim a signal expired when it is there; one that drifts
        // high draws an empty row and calls it silence.
        assert_eq!(retention(SignalType::Metric), Duration::days(30));
        assert_eq!(retention(SignalType::Log), Duration::days(365));
        assert_eq!(retention(SignalType::Event), Duration::days(365));
        assert_eq!(retention(SignalType::State), Duration::days(1095));
        assert_eq!(retention(SignalType::Flow), Duration::days(7));
        assert_eq!(retention(SignalType::Trace), Duration::days(7));
    }

    #[test]
    fn the_signals_are_ordered_the_way_a_failure_is_read() {
        // What changed, what was said about it, what the traffic did, what a request
        // experienced.
        assert_eq!(SIGNALS[0], SignalType::State);
        assert_eq!(SIGNALS[SIGNALS.len() - 1], SignalType::Trace);
    }
}
