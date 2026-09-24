//! Security events — M11, `docs/M11-security.md`.
//!
//! A log line in, an event or nothing out. That is the whole crate.
//!
//! ```text
//!   body ──▶ shape ──▶ ECS fields ──▶ classify ──▶ Some(event)
//!              │                          │
//!         no grammar                 no evidence
//!           matched                   of a kind
//!              │                          │
//!              └──────────┬───────────────┘
//!                         ▼
//!                       None
//!                 the log line stands
//! ```
//!
//! # What this is not
//!
//! Not a SIEM. M11 §1 draws the line and it is worth repeating where somebody will read it
//! before adding a parser: a SIEM is a content business — a thousand vendor parsers, a
//! detection library with a release cadence, a threat-intelligence feed, a rules team. A
//! solo developer who starts down that road ships a parser library that is out of date on
//! the day it ships.
//!
//! What this product has instead is a resolved resource identity and a topology. A firewall
//! deny is a row in anybody's log aggregator. A firewall deny *on the interface facing the
//! branch whose link flapped four minutes ago, from a host this product already knows is a
//! printer* is something only this product can say — and it needs the event to carry a
//! `resource_id`, not a better regex.
//!
//! # Producing nothing is a correct answer, and the common one
//!
//! Most log lines are not security events. [`read`] returns `None` for all of them, the
//! line is still stored and searchable, and nothing is logged about the fact. A product
//! that warned about every unclassified line would be warning about almost every line.
//!
//! # Example
//!
//! ```
//! use std::collections::BTreeMap;
//! use uops_security::{read, Category, Kind};
//!
//! let event = read(
//!     "src=10.0.0.5 dst=203.0.113.9 dpt=445 proto=TCP act=deny",
//!     &BTreeMap::new(),
//!     "",
//! )
//! .expect("a firewall decision");
//!
//! assert_eq!(event.category, Category::Network);
//! assert_eq!(event.kind, Kind::Denied);
//! assert_eq!(event.attributes["source.ip"], "10.0.0.5");
//! assert_eq!(event.attributes["destination.port"], "445");
//!
//! // Prose is not an event, and that is not a failure.
//! assert!(read("interface Gi0/1 changed state to down", &BTreeMap::new(), "").is_none());
//! ```

pub mod classify;
pub mod field;
pub mod shape;

pub use classify::{Category, Classification, Kind};
pub use field::ecs_field;
pub use shape::{SHAPES, Shape};

use std::collections::BTreeMap;

/// What one message turned out to be.
///
/// Deliberately not a `uops_store_ch::EventRow`: this crate knows nothing about tenants,
/// resources or clocks, and it should stay that way — the identity of the thing that
/// emitted a message is the ingest pipeline's business, resolved the same way it is for
/// every other signal. This is the part that is a pure function of the text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityEvent {
    pub category: Category,
    pub kind: Kind,
    /// Which grammar read it. Kept because "why did this message not produce an event"
    /// is the question this crate will be asked most often, and the answer is usually
    /// "no grammar matched" rather than anything about the content.
    pub shape: Shape,
    /// A sentence, for the `summary` column.
    pub summary: String,
    /// ECS-keyed. Unrecognised vendor keys are kept under `vendor.*` — see [`field`].
    pub attributes: BTreeMap<String, String>,
    /// The vendor the *message* stated, which only CEF does in a standard position.
    ///
    /// `None` everywhere else, and the caller should prefer the vendor it knows from the
    /// resource: a vendor taken from a message is a claim the message made about itself.
    pub vendor: Option<String>,
}

/// Read one message.
///
/// `structured` is RFC 5424 structured data, already flattened by `uops-syslog`.
/// `context` is anything else known about the message — the syslog app name, say — and is
/// used **only** to tell a tunnel message from a plain sign-in. It can never cause an event
/// to exist that would not otherwise.
#[must_use]
pub fn read(
    body: &str,
    structured: &BTreeMap<String, String>,
    context: &str,
) -> Option<SecurityEvent> {
    let parsed = shape::parse(body, structured)?;
    let attributes = field::to_ecs(&parsed.fields);

    // The CEF event name is part of the context a tunnel message is recognised by: a
    // device that says `SSL VPN Login` in its event name and nothing in its extension is
    // the ordinary case.
    let context = match &parsed.name {
        Some(name) => format!("{context} {name}"),
        None => context.to_owned(),
    };

    let it = classify::classify(&attributes, &context)?;

    Some(SecurityEvent {
        category: it.category,
        kind: it.kind,
        shape: parsed.shape,
        summary: summarise(it, &attributes, parsed.name.as_deref()),
        attributes,
        vendor: parsed.vendor,
    })
}

/// One sentence about what happened.
///
/// The device's own event name when it gave one — it wrote a better sentence than this
/// function will — and otherwise the fields, in the order somebody reads them.
///
/// **Never a judgement.** "Denied 10.0.0.5 → 203.0.113.9:445" is what happened; "suspicious
/// connection blocked" is an opinion, and M11 §2.8's argument about severity applies to
/// prose just as much.
fn summarise(
    it: Classification,
    attributes: &BTreeMap<String, String>,
    name: Option<&str>,
) -> String {
    if let Some(name) = name.map(str::trim).filter(|n| !n.is_empty()) {
        return name.to_owned();
    }

    let at = |key: &str| attributes.get(key).map(String::as_str);
    match it.category {
        Category::Network => {
            let src = at("source.ip").unwrap_or("?");
            let dst = at("destination.ip").unwrap_or("?");
            match at("destination.port") {
                Some(port) => format!("{} {src} → {dst}:{port}", verb(it.kind)),
                None => format!("{} {src} → {dst}", verb(it.kind)),
            }
        }
        Category::Authentication | Category::Vpn => {
            let user = at("user.name").unwrap_or("?");
            match at("source.ip") {
                Some(src) => format!("{} for {user} from {src}", verb(it.kind)),
                None => format!("{} for {user}", verb(it.kind)),
            }
        }
        Category::Dns => {
            let question = at("dns.question.name").unwrap_or("?");
            match at("dns.response_code") {
                Some(code) => format!("Resolved {question} — {code}"),
                None => format!("Resolved {question}"),
            }
        }
    }
}

const fn verb(kind: Kind) -> &'static str {
    match kind {
        Kind::Allowed => "Allowed",
        Kind::Denied => "Denied",
        Kind::Success => "Succeeded",
        Kind::Failure => "Failed",
        Kind::Start => "Started",
        Kind::End => "Ended",
        Kind::Query => "Queried",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn a_firewall_deny_end_to_end() {
        let it = read(
            "src=10.0.0.5 dst=203.0.113.9 dpt=445 proto=TCP act=deny",
            &none(),
            "",
        )
        .expect("an event");

        assert_eq!(it.category, Category::Network);
        assert_eq!(it.kind, Kind::Denied);
        assert_eq!(it.shape, Shape::KeyValue);
        assert_eq!(it.attributes["source.ip"], "10.0.0.5");
        assert_eq!(it.attributes["destination.port"], "445");
        assert_eq!(it.attributes["network.transport"], "TCP");
        assert_eq!(it.summary, "Denied 10.0.0.5 → 203.0.113.9:445");
    }

    #[test]
    fn the_summary_says_what_happened_and_never_what_it_means() {
        // §2.8, applied to prose: "suspicious connection blocked" is an opinion, and once
        // it is on the row every screen repeats it.
        let it = read("src=1.1.1.1 dst=2.2.2.2 dpt=22 act=drop", &none(), "").unwrap();
        for opinion in ["suspicious", "attack", "malicious", "threat", "critical"] {
            assert!(
                !it.summary.to_lowercase().contains(opinion),
                "{}",
                it.summary
            );
        }
    }

    #[test]
    fn a_cef_event_keeps_the_devices_own_sentence() {
        // The device wrote a better one than `summarise` will.
        let it = read(
            "CEF:0|Palo Alto Networks|PAN-OS|10.2|threat|Traffic Denied|5|src=10.0.0.5 \
             dst=203.0.113.9 dpt=445 act=deny",
            &none(),
            "",
        )
        .expect("an event");
        assert_eq!(it.summary, "Traffic Denied");
        assert_eq!(it.vendor.as_deref(), Some("Palo Alto Networks"));
    }

    #[test]
    fn a_failed_sign_in_carries_the_user_and_the_source() {
        let it = read(
            r#"{"user":"alice","src_ip":"198.51.100.7","result":"failure"}"#,
            &none(),
            "sshd",
        )
        .expect("an event");
        assert_eq!(it.category, Category::Authentication);
        assert_eq!(it.kind, Kind::Failure);
        assert_eq!(it.attributes["user.name"], "alice");
        assert_eq!(it.summary, "Failed for alice from 198.51.100.7");
    }

    #[test]
    fn a_cef_event_name_can_be_what_makes_it_a_tunnel() {
        // A device whose extension says only user and outcome, and whose event name says
        // what kind of login it was. The common case, and the reason the name joins the
        // context rather than only becoming the summary.
        let it = read(
            "CEF:0|Cisco|ASA|9.1|113039|SSL VPN Login|5|user=carol act=connected src=1.1.1.1",
            &none(),
            "",
        )
        .expect("an event");
        assert_eq!(it.category, Category::Vpn);
        assert_eq!(it.kind, Kind::Start);
    }

    #[test]
    fn a_resolver_log_is_a_query_with_its_response_code() {
        let it = read(
            "query=lookup.example.invalid rcode=NXDOMAIN client_ip=10.0.0.5",
            &none(),
            "named",
        )
        .expect("an event");
        assert_eq!(it.category, Category::Dns);
        assert_eq!(it.attributes["dns.question.name"], "lookup.example.invalid");
        assert_eq!(it.summary, "Resolved lookup.example.invalid — NXDOMAIN");
    }

    #[test]
    fn most_log_lines_are_not_events_and_that_is_not_a_failure() {
        for ordinary in [
            "interface Gi0/1 changed state to down",
            "%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Up",
            "Started Session 42 of user root.",
            "kernel: usb 1-1: new high-speed USB device",
            "",
        ] {
            assert!(read(ordinary, &none(), "").is_none(), "{ordinary}");
        }
    }

    #[test]
    fn a_structured_message_with_no_evidence_of_a_kind_is_still_nothing() {
        // Three fields, a grammar matched, and nothing that says what happened. This is
        // the case that separates "parsed" from "understood", and producing an event here
        // is how a count of denials acquires rows that are not denials.
        assert!(read("cpu=42 mem=1024 disk=88", &none(), "").is_none());
    }

    #[test]
    fn an_unrecognised_field_survives_into_the_event() {
        let it = read("src=1.1.1.1 dst=2.2.2.2 act=deny wombat=17", &none(), "").expect("an event");
        assert_eq!(it.attributes["vendor.wombat"], "17");
    }
}
