//! Who may let a run proceed — M10 §2.5.
//!
//! PLAN §0b: *destructive automation in defence contexts → two-person integrity on
//! runbooks — note for M10, do not build now.* It is M10 now.
//!
//! # An approval is of a *run*, not of a runbook
//!
//! The runbook was reviewed when it was written. What is being approved here is this
//! execution: this version, against **this resolved target list**, now. The dangerous
//! variable is the target list — a selector that matched one switch last week and four
//! hundred today is the same runbook and a different act.
//!
//! So an approval carries the resolved targets, and a run whose targets changed after it
//! was approved is not approved any more.
//!
//! # And an approval expires
//!
//! Ten minutes, the same order as the sign-in window in M12 §2.2. An approval that sat
//! overnight was given against an estate that may not be the one in front of it now.
//!
//! # Break-glass, because the alternative is worse
//!
//! An organisation that requires approval and has an outage at 3 a.m. with one engineer
//! awake will get around the rule — through a laptop and SSH, with no audit trail at all.
//! The product therefore offers the route it can *observe*: a named role may run without
//! approval, and the run record says so for as long as it exists. The same argument, and
//! the same shape, as the break-glass account in M12 §2.2.

use chrono::{DateTime, Duration, Utc};
use uops_core::ActorId;

/// How long an approval is good for.
///
/// Ten minutes: long enough for a second engineer to read the target list and agree,
/// short enough that it cannot be given at the end of one shift and used in the next.
pub const APPROVAL_WINDOW: Duration = Duration::minutes(10);

/// One person saying yes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub by: ActorId,
    pub at: DateTime<Utc>,
    /// What they were looking at. A run whose targets changed is not this run any more.
    pub targets_fingerprint: String,
}

/// What a run needs before it may proceed.
#[derive(Clone, Debug)]
pub struct Request {
    /// Who pressed the button.
    pub started_by: ActorId,
    /// How many approvals this runbook requires.
    pub required: crate::model::Approvals,
    /// The target list as it stands now.
    pub targets_fingerprint: String,
    /// Whether the person starting it holds the break-glass role.
    pub break_glass: bool,
}

/// Whether a run may proceed, and if not, why not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Go ahead.
    Approved,
    /// Go ahead, unapproved, and the run record will say so for ever.
    BreakGlass,
    /// Wait. The message is shown to the person who started it.
    Pending(Pending),
}

/// Why a run is not going yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pending {
    /// Not enough people have said yes.
    NeedMore { have: usize, need: usize },
    /// Somebody approved, and the target list has changed since.
    TargetsChanged,
    /// Every approval is older than the window.
    Expired,
}

impl Pending {
    /// What the person who started the run is told.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::NeedMore { have, need } => {
                if *have == 0 {
                    format!(
                        "this run needs {need} approval(s) from somebody other than you, \
                         and has none"
                    )
                } else {
                    format!("this run has {have} of {need} approvals")
                }
            }
            Self::TargetsChanged => "the resources this run would act on have changed \
                                     since it was approved; it needs approving again"
                .to_owned(),
            Self::Expired => format!(
                "every approval is older than {} minutes; an approval given against an \
                 estate that may have moved on is not one this will act on",
                APPROVAL_WINDOW.num_minutes()
            ),
        }
    }
}

/// Decide whether a run proceeds.
///
/// `now` is passed rather than read so every boundary of the window is testable without
/// waiting for it.
#[must_use]
pub fn decide(request: &Request, approvals: &[Approval], now: DateTime<Utc>) -> Decision {
    let need = request.required.count();

    // Nothing to approve. A read-only runbook is the ordinary case for this branch, and
    // `validate` is what guarantees a destructive one cannot reach it.
    if need == 0 {
        return Decision::Approved;
    }

    // **The person who starts a run cannot approve it**, and this is the whole of
    // two-person integrity. Enforced here rather than trusted to a process document,
    // because a process document is not a thing the product can check.
    //
    // Filtered rather than refused, so that a self-approval is simply not counted: an
    // operator who approved their own run and then found a colleague should not have to
    // start over.
    let usable: Vec<&Approval> = approvals
        .iter()
        .filter(|a| a.by != request.started_by)
        .collect();

    // Distinct people. Two approvals from one person are one person agreeing twice, which
    // is the exact thing two-person integrity exists to refuse.
    let mut distinct = std::collections::BTreeSet::new();
    let fresh: Vec<&&Approval> = usable
        .iter()
        .filter(|a| now.signed_duration_since(a.at) <= APPROVAL_WINDOW)
        .filter(|a| distinct.insert(a.by))
        .collect();

    // Checked before the count, because "your approval is stale" and "somebody changed
    // the targets" are different things to tell somebody, and the second is the alarming
    // one.
    if fresh
        .iter()
        .any(|a| a.targets_fingerprint != request.targets_fingerprint)
    {
        return Decision::Pending(Pending::TargetsChanged);
    }

    if fresh.len() >= need {
        return Decision::Approved;
    }

    // Break-glass is checked **last**, so that a run which is properly approved is
    // recorded as approved even when the person holding the role started it. A
    // break-glass record is a thing somebody has to explain, and handing one out where an
    // ordinary approval existed would teach everybody to ignore them.
    if request.break_glass {
        return Decision::BreakGlass;
    }

    if !usable.is_empty() && fresh.is_empty() {
        return Decision::Pending(Pending::Expired);
    }

    Decision::Pending(Pending::NeedMore {
        have: fresh.len(),
        need,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Approvals;

    fn actor() -> ActorId {
        ActorId::new()
    }

    fn request(started_by: ActorId, required: Approvals) -> Request {
        Request {
            started_by,
            required,
            targets_fingerprint: "sha:abc".to_owned(),
            break_glass: false,
        }
    }

    fn approval(by: ActorId, at: DateTime<Utc>) -> Approval {
        Approval {
            by,
            at,
            targets_fingerprint: "sha:abc".to_owned(),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::UNIX_EPOCH + Duration::days(20_000)
    }

    #[test]
    fn a_read_only_run_needs_nobody() {
        let r = request(actor(), Approvals::None);
        assert_eq!(decide(&r, &[], now()), Decision::Approved);
    }

    #[test]
    fn one_approval_from_somebody_else_is_enough() {
        let me = actor();
        let r = request(me, Approvals::One);
        assert_eq!(
            decide(&r, &[approval(actor(), now())], now()),
            Decision::Approved
        );
    }

    #[test]
    fn approving_your_own_run_does_not_count() {
        // The whole of two-person integrity, and the one rule a process document cannot
        // enforce.
        let me = actor();
        let r = request(me, Approvals::One);
        let decision = decide(&r, &[approval(me, now())], now());
        assert_eq!(
            decision,
            Decision::Pending(Pending::NeedMore { have: 0, need: 1 })
        );
    }

    #[test]
    fn two_approvals_from_one_person_are_one_person_agreeing_twice() {
        let me = actor();
        let colleague = actor();
        let r = request(me, Approvals::Two);
        let decision = decide(
            &r,
            &[approval(colleague, now()), approval(colleague, now())],
            now(),
        );
        assert_eq!(
            decision,
            Decision::Pending(Pending::NeedMore { have: 1, need: 2 })
        );
    }

    #[test]
    fn two_distinct_people_are_two() {
        let me = actor();
        let r = request(me, Approvals::Two);
        assert_eq!(
            decide(&r, &[approval(actor(), now()), approval(actor(), now())], now()),
            Decision::Approved
        );
    }

    #[test]
    fn an_approval_expires() {
        let me = actor();
        let r = request(me, Approvals::One);
        let stale = approval(actor(), now() - APPROVAL_WINDOW - Duration::seconds(1));
        assert_eq!(decide(&r, &[stale], now()), Decision::Pending(Pending::Expired));

        // And the boundary holds the other way, so a colleague who approved exactly at
        // the limit is not told to start over.
        let just_in_time = approval(actor(), now() - APPROVAL_WINDOW);
        assert_eq!(decide(&r, &[just_in_time], now()), Decision::Approved);
    }

    #[test]
    fn changing_the_targets_invalidates_an_approval() {
        // The dangerous variable. A selector that matched one switch last week and four
        // hundred today is the same runbook and a different act.
        let me = actor();
        let mut r = request(me, Approvals::One);
        let given = approval(actor(), now());
        r.targets_fingerprint = "sha:four-hundred-switches".to_owned();

        assert_eq!(
            decide(&r, &[given], now()),
            Decision::Pending(Pending::TargetsChanged)
        );
    }

    #[test]
    fn a_stale_approval_on_changed_targets_reports_the_expiry() {
        // Ordering: an expired approval is filtered before the fingerprint is compared,
        // so somebody is told the boring thing rather than the alarming one when the
        // alarming one is not actually true of any live approval.
        let me = actor();
        let mut r = request(me, Approvals::One);
        r.targets_fingerprint = "sha:different".to_owned();
        let stale = approval(actor(), now() - Duration::hours(2));
        assert_eq!(decide(&r, &[stale], now()), Decision::Pending(Pending::Expired));
    }

    #[test]
    fn break_glass_runs_without_approval_and_is_recorded_as_such() {
        let me = actor();
        let mut r = request(me, Approvals::Two);
        r.break_glass = true;
        assert_eq!(decide(&r, &[], now()), Decision::BreakGlass);
    }

    #[test]
    fn a_properly_approved_run_is_approved_even_when_break_glass_is_available() {
        // Handing out a break-glass record where an ordinary approval existed would teach
        // everybody to ignore them, and a break-glass record that means nothing is worse
        // than none.
        let me = actor();
        let mut r = request(me, Approvals::One);
        r.break_glass = true;
        assert_eq!(
            decide(&r, &[approval(actor(), now())], now()),
            Decision::Approved
        );
    }

    #[test]
    fn every_pending_reason_says_what_to_do_about_it() {
        let reasons = [
            Pending::NeedMore { have: 0, need: 2 },
            Pending::NeedMore { have: 1, need: 2 },
            Pending::TargetsChanged,
            Pending::Expired,
        ];
        for reason in &reasons {
            let text = reason.describe();
            assert!(text.len() > 25, "{text}");
            // Not "denied" or "forbidden": every one of these is a state somebody can
            // move out of, and the message is where they find out how.
            assert!(!text.to_lowercase().contains("denied"), "{text}");
        }
        assert!(reasons[0].describe().contains("other than you"));
        assert!(reasons[1].describe().contains("1 of 2"));
    }
}
