//! What the observer already said, so it does not say it again.
//!
//! Each of the three facts in `docs/self-monitoring.md` §4 is read from a table on every
//! tick, but an event is a *statement that something happened* — emitting one per tick
//! would turn a single stopped collector into two events a minute for as long as it stays
//! stopped. This type holds the "already said that" memory and nothing else, so the rules
//! can be tested without `PostgreSQL` or `ClickHouse`.
//!
//! # Why the three facts remember differently
//!
//! A collector that is quiet *right now* is a true statement about the present, so a fresh
//! observer reports it. A lease holder read at startup is not a handover — nothing changed,
//! the observer simply arrived late — so the first observation of each job is recorded
//! silently. A failed run is an event in the past that is worth announcing exactly once.
//!
//! That asymmetry is deliberate. The cost is that restarting the server re-announces
//! currently-quiet collectors and failures from the last few minutes: the memory is in the
//! process, not in `ClickHouse`. Deduplicating across restarts would mean reading back the
//! events already written, which is a larger change than the seam it closes.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use uops_store_pg::Job;

/// The observer's memory of what it has already emitted.
#[derive(Debug, Default)]
pub struct Seen {
    /// Collector id to the `last_seen_at` that was reported as having gone quiet. Keyed on
    /// the timestamp rather than a flag so a collector that recovers and stops again is
    /// reported the second time too.
    quiet: HashMap<uuid::Uuid, DateTime<Utc>>,
    leases: HashMap<Job, String>,
    failed_runs: HashSet<uuid::Uuid>,
}

impl Seen {
    /// Whether this collector going quiet is news. Records it as reported.
    ///
    /// Call [`Self::collector_not_reported`] if the write then fails, so the next tick
    /// retries rather than silently swallowing the event.
    pub fn collector_quiet(&mut self, id: uuid::Uuid, last_seen: DateTime<Utc>) -> bool {
        self.quiet.insert(id, last_seen) != Some(last_seen)
    }

    /// Undo [`Self::collector_quiet`] after a failed write.
    pub fn collector_not_reported(&mut self, id: uuid::Uuid) {
        self.quiet.remove(&id);
    }

    /// Forget every collector that is no longer quiet, so a later stop is reported again
    /// and the map does not grow with collectors that have been retired.
    ///
    /// Takes the quiet collectors across *every* organization at once. Doing this per
    /// organization would have each one's set delete the others' entries, and the symptom —
    /// the same event every tick, forever, on any installation with two organizations — is
    /// invisible on the single-organization case that gets tested by hand.
    pub fn only_still_quiet(&mut self, quiet: &HashSet<uuid::Uuid>) {
        self.quiet.retain(|id, _| quiet.contains(id));
    }

    /// The holder this job was last seen with, if it has changed hands since. `None` on the
    /// first observation of a job: arriving mid-tenure is not a handover.
    pub fn lease_moved(&mut self, job: Job, holder: &str) -> Option<String> {
        let previous = self.leases.insert(job, holder.to_owned())?;
        (previous != holder).then_some(previous)
    }

    /// Whether this failed run is news. Records it as reported.
    pub fn run_failed(&mut self, id: uuid::Uuid) -> bool {
        self.failed_runs.insert(id)
    }

    /// Undo [`Self::run_failed`] after a failed write.
    pub fn run_not_reported(&mut self, id: uuid::Uuid) {
        self.failed_runs.remove(&id);
    }

    /// Forget runs that have fallen out of the query window. Without this the set holds
    /// every run that has ever failed, for the lifetime of the process, to deduplicate
    /// against rows that can no longer be returned.
    pub fn only_recent_runs(&mut self, recent: &HashSet<uuid::Uuid>) {
        self.failed_runs.retain(|id| recent.contains(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed rather than random: a failing assertion should name the same value twice.
    fn id(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    fn at(minute: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-09-24T10:{minute:02}:00Z"))
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn a_stopped_collector_is_reported_once_not_every_tick() {
        let mut seen = Seen::default();
        let id = id(1);
        assert!(seen.collector_quiet(id, at(10)));
        for _ in 0..20 {
            assert!(
                !seen.collector_quiet(id, at(10)),
                "still quiet for the same reason is not a second event"
            );
        }
    }

    #[test]
    fn a_collector_that_recovers_and_stops_again_is_reported_again() {
        let mut seen = Seen::default();
        let id = id(2);
        assert!(seen.collector_quiet(id, at(10)));
        // It came back, heartbeat at 10:20, then went quiet again. Same collector, new
        // `last_seen_at` — a second outage, and an operator needs to hear about it.
        assert!(seen.collector_quiet(id, at(20)));
    }

    #[test]
    fn a_failed_write_is_retried_on_the_next_tick() {
        let mut seen = Seen::default();
        let id = id(3);
        assert!(seen.collector_quiet(id, at(10)));
        seen.collector_not_reported(id);
        assert!(
            seen.collector_quiet(id, at(10)),
            "ClickHouse being down must not lose the event"
        );
    }

    /// The defect this module was extracted to fix. Two organizations, one quiet collector
    /// each: pruning with one organization's set at a time deletes the other's memory, and
    /// both are re-reported every 30 seconds for as long as they stay quiet.
    #[test]
    fn two_organizations_do_not_delete_each_others_memory() {
        let mut seen = Seen::default();
        let (a, b) = (id(4), id(5));
        assert!(seen.collector_quiet(a, at(10)));
        assert!(seen.collector_quiet(b, at(10)));

        seen.only_still_quiet(&HashSet::from([a, b]));

        assert!(!seen.collector_quiet(a, at(10)));
        assert!(!seen.collector_quiet(b, at(10)));
    }

    /// The same mistake, made the way it was actually made: pruning once per organization
    /// rather than once per tick. Kept as a test because the correct code and the broken
    /// code behave identically on a single-organization installation, which is the case
    /// anyone checks by hand.
    #[test]
    fn pruning_per_organization_would_re_report_every_tick() {
        let mut seen = Seen::default();
        let (a, b) = (id(11), id(12));
        for _ in 0..2 {
            // Organization A, then organization B, each pruning with only its own set.
            seen.collector_quiet(a, at(10));
            seen.only_still_quiet(&HashSet::from([a]));
            seen.collector_quiet(b, at(10));
            seen.only_still_quiet(&HashSet::from([b]));
        }
        assert!(
            seen.collector_quiet(a, at(10)),
            "A was forgotten by B's prune, so nothing stops it being reported forever"
        );
    }

    #[test]
    fn a_recovered_collector_is_forgotten() {
        let mut seen = Seen::default();
        let id = id(6);
        assert!(seen.collector_quiet(id, at(10)));
        seen.only_still_quiet(&HashSet::new());
        // Forgotten, so the map does not grow. Re-reporting on the same `last_seen_at`
        // cannot follow from this: recovering moves `last_seen_at` forward.
        assert!(seen.collector_quiet(id, at(10)));
    }

    #[test]
    fn arriving_mid_tenure_is_not_a_handover() {
        let mut seen = Seen::default();
        assert_eq!(
            seen.lease_moved(Job::Poll, "poller-1"),
            None,
            "a fresh observer must not report a handover that did not happen"
        );
        assert_eq!(seen.lease_moved(Job::Poll, "poller-1"), None);
    }

    #[test]
    fn a_handover_names_the_previous_holder() {
        let mut seen = Seen::default();
        assert_eq!(seen.lease_moved(Job::Poll, "poller-1"), None);
        assert_eq!(
            seen.lease_moved(Job::Poll, "poller-2"),
            Some("poller-1".to_owned())
        );
        assert_eq!(seen.lease_moved(Job::Poll, "poller-2"), None);
    }

    #[test]
    fn each_job_is_tracked_separately() {
        let mut seen = Seen::default();
        for job in [Job::Poll, Job::Alert, Job::Sweep, Job::Run] {
            assert_eq!(seen.lease_moved(job, "one"), None);
        }
        // A handover of the poll lease says nothing about the alert lease.
        assert_eq!(seen.lease_moved(Job::Poll, "two"), Some("one".to_owned()));
        for job in [Job::Alert, Job::Sweep, Job::Run] {
            assert_eq!(seen.lease_moved(job, "one"), None);
        }
    }

    #[test]
    fn a_holder_that_comes_back_is_a_second_handover() {
        let mut seen = Seen::default();
        assert_eq!(seen.lease_moved(Job::Sweep, "a"), None);
        assert_eq!(seen.lease_moved(Job::Sweep, "b"), Some("a".to_owned()));
        assert_eq!(seen.lease_moved(Job::Sweep, "a"), Some("b".to_owned()));
    }

    #[test]
    fn a_failed_run_is_reported_once() {
        let mut seen = Seen::default();
        let id = id(7);
        assert!(seen.run_failed(id));
        assert!(!seen.run_failed(id));
    }

    #[test]
    fn a_failed_run_whose_write_failed_is_retried() {
        let mut seen = Seen::default();
        let id = id(8);
        assert!(seen.run_failed(id));
        seen.run_not_reported(id);
        assert!(seen.run_failed(id));
    }

    #[test]
    fn runs_outside_the_window_are_forgotten() {
        let mut seen = Seen::default();
        let (old, recent) = (id(9), id(10));
        assert!(seen.run_failed(old));
        assert!(seen.run_failed(recent));

        seen.only_recent_runs(&HashSet::from([recent]));

        assert_eq!(seen.failed_runs.len(), 1, "the set must not grow forever");
        assert!(
            !seen.run_failed(recent),
            "and the recent one is still deduplicated"
        );
    }
}
