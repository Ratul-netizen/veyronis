//! What an alert says when it reaches a person.
//!
//! Rendered once and handed to every channel, rather than each transport building its
//! own. Two channels describing the same alert differently is how an operator ends up
//! believing there are two problems.
//!
//! # Why the resource's name is fetched
//!
//! An alert about `018f0000-0000-7000-8000-0000000000aa` is an alert nobody can act on.
//! The name costs one indexed lookup per notification, and notifications are rare by
//! construction — the rate limit sees to that. A dedup key carries the id for the machine
//! reading the webhook; the sentence carries the name for the person reading the page.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uops_core::ResourceId;
use uops_core::alert::{AlertSeverity, Phase};

/// One alert, ready to be delivered.
#[derive(Clone, Debug, Serialize)]
pub struct Notification {
    /// `firing` or `resolved`. The only two phases anybody is told about.
    pub phase: Phase,
    pub severity: AlertSeverity,
    pub rule: String,
    pub rule_id: uuid::Uuid,
    pub resource_id: ResourceId,
    /// What a person calls the device. Falls back to the id when the resource has been
    /// deleted between the evaluation and the delivery, which is rare and is still better
    /// than an empty string where a hostname should be.
    pub resource: String,
    pub dedup_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// When the alert entered its current phase — not when this was sent. An operator
    /// arriving at a screen needs to know the problem started eleven minutes ago, and a
    /// notification that was delayed by a rate limit would otherwise claim it started
    /// just now.
    pub since: DateTime<Utc>,
    pub at: DateTime<Utc>,

    /// How many *other* alerts this one's incident silenced — M9 §2.4.
    ///
    /// Zero on almost everything, and the field exists for the case where it is not.
    /// When a switch fails and forty hosts go quiet behind it, exactly one notification
    /// is sent and this says how much it stands for. Without it the page reads as one
    /// device having a problem, which is the wrong size of event to wake up to.
    ///
    /// §2.4 is explicit that a suppression nobody can see is indistinguishable from a
    /// bug, and the page at 4am is the one place it is hardest to see.
    #[serde(skip_serializing_if = "is_zero")]
    pub suppressed: u32,
}

/// Serde's `skip_serializing_if` needs a predicate by name.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde requires a reference"
)]
const fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl Notification {
    /// The one-line summary. A subject line, a chat message, the first thing read.
    ///
    /// Severity leads because it is what decides whether to get out of bed, and the
    /// resource comes before the rule because an operator recognises their own devices
    /// faster than the names somebody gave the rules.
    #[must_use]
    pub fn summary(&self) -> String {
        let verb = match self.phase {
            Phase::Resolved => "resolved",
            _ => "firing",
        };
        let head = match self.value {
            Some(v) => format!(
                "[{}] {} — {} {} ({:.3})",
                self.severity.as_str(),
                self.resource,
                self.rule,
                verb,
                v
            ),
            None => format!(
                "[{}] {} — {} {}",
                self.severity.as_str(),
                self.resource,
                self.rule,
                verb
            ),
        };
        // M9 §2.4, on the subject line rather than buried in the body: the difference
        // between one device and forty is the difference between finishing dinner and
        // getting in the car, and it has to survive being read on a lock screen.
        match self.suppressed {
            0 => head,
            1 => format!("{head} + 1 more downstream"),
            n => format!("{head} + {n} more downstream"),
        }
    }

    /// The body a person reads, in plain text.
    ///
    /// Deliberately not HTML and deliberately short. This is read on a phone at 4am, and
    /// the four facts that matter are what, where, since when, and how bad.
    #[must_use]
    pub fn text(&self) -> String {
        let mut lines = vec![
            self.summary(),
            String::new(),
            format!("Rule:     {}", self.rule),
            format!("Resource: {} ({})", self.resource, self.resource_id),
            format!("State:    {}", self.phase.as_str()),
            format!("Since:    {}", self.since.format("%Y-%m-%d %H:%M:%S UTC")),
        ];
        if let Some(value) = self.value {
            lines.push(format!("Value:    {value:.3}"));
        }
        if self.suppressed > 0 {
            // Named, not just counted. An operator who cannot tell *why* forty pages did
            // not arrive has to assume the notifier is broken, which is worse than forty
            // pages.
            lines.push(format!(
                "Also:     {} downstream alert(s) grouped into this incident and not sent \
                 separately",
                self.suppressed
            ));
        }
        lines.push(format!("Alert:    {}", self.dedup_key));
        lines.join("\n")
    }

    /// What a webhook receives.
    ///
    /// The struct itself, plus the rendered sentence — because the thing on the other end
    /// is as likely to be a chat bridge that wants a line of text as a system that wants
    /// the fields.
    #[must_use]
    pub fn payload(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(object) = value.as_object_mut() {
            object.insert("summary".to_owned(), serde_json::json!(self.summary()));
            object.insert("text".to_owned(), serde_json::json!(self.text()));
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notification(phase: Phase, value: Option<f64>) -> Notification {
        Notification {
            phase,
            severity: AlertSeverity::Critical,
            rule: "CPU hot".to_owned(),
            rule_id: uuid::Uuid::nil(),
            resource_id: ResourceId::nil(),
            resource: "rtr-01".to_owned(),
            dedup_key: "rule/rtr-01".to_owned(),
            value,
            since: DateTime::from_timestamp(1_700_000_000, 0).expect("an instant"),
            at: DateTime::from_timestamp(1_700_000_600, 0).expect("an instant"),
            suppressed: 0,
        }
    }

    #[test]
    fn the_summary_leads_with_what_decides_whether_to_get_up() {
        let firing = notification(Phase::Firing, Some(94.5));
        assert_eq!(
            firing.summary(),
            "[critical] rtr-01 — CPU hot firing (94.500)"
        );

        // The same alert ending says so in the same shape, so a person reading a list of
        // them can pair the two up at a glance.
        let resolved = notification(Phase::Resolved, Some(11.0));
        assert!(
            resolved.summary().contains("resolved"),
            "{}",
            resolved.summary()
        );
    }

    #[test]
    fn the_body_says_when_the_problem_started_not_when_this_was_sent() {
        // A notification delayed by a rate limit would otherwise claim the problem began
        // at the moment it happened to get through.
        let text = notification(Phase::Firing, Some(94.5)).text();
        assert!(text.contains("2023-11-14"), "{text}");
        assert!(text.contains("rtr-01"), "{text}");
        assert!(text.contains("Value:    94.500"), "{text}");
    }

    #[test]
    fn an_absence_alert_has_no_value_and_does_not_print_one() {
        let text = notification(Phase::Firing, None).text();
        assert!(!text.contains("Value:"), "{text}");
        assert!(!notification(Phase::Firing, None).summary().contains('('));
    }

    #[test]
    fn the_payload_carries_both_the_fields_and_the_sentence() {
        // The thing on the other end is as likely to be a chat bridge that wants a line
        // of text as a system that wants the fields.
        let payload = notification(Phase::Firing, Some(94.5)).payload();
        assert_eq!(payload["rule"], "CPU hot");
        assert_eq!(payload["phase"], "firing");
        assert_eq!(payload["severity"], "critical");
        assert!(
            payload["summary"]
                .as_str()
                .unwrap_or_default()
                .contains("rtr-01")
        );
        assert!(
            payload["text"]
                .as_str()
                .unwrap_or_default()
                .contains("Since:")
        );
    }

    #[test]
    fn a_page_for_a_cascade_says_how_much_it_stands_for() {
        // M9 §2.4. One notification for forty devices must not read like one device
        // having a problem — that is the wrong size of event to wake up to, and the
        // difference between finishing dinner and getting in the car.
        let mut n = notification(Phase::Firing, None);
        n.suppressed = 39;

        assert!(
            n.summary().ends_with("+ 39 more downstream"),
            "on the subject line, so it survives a lock screen: {}",
            n.summary()
        );
        assert!(
            n.text()
                .contains("39 downstream alert(s) grouped into this incident"),
            "and named in the body, because a count with no explanation reads as a bug: {}",
            n.text()
        );
    }

    #[test]
    fn one_suppressed_alert_is_not_pluralised_wrongly() {
        let mut n = notification(Phase::Firing, None);
        n.suppressed = 1;
        assert!(
            n.summary().ends_with("+ 1 more downstream"),
            "{}",
            n.summary()
        );
    }

    #[test]
    fn an_ordinary_alert_says_nothing_about_suppression() {
        // Zero on nearly everything. A field that appears on every page is a field
        // nobody reads, and the point is that a cascade stands out.
        let n = notification(Phase::Firing, None);
        assert!(!n.summary().contains("downstream"), "{}", n.summary());
        assert!(!n.text().contains("downstream"), "{}", n.text());
        assert!(
            !n.payload().to_string().contains("suppressed"),
            "and it is absent from the webhook body rather than sent as a zero"
        );
    }
}
