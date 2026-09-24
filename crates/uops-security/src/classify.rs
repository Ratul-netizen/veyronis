//! Fields into a category and a type, or nothing — M11 §2.1, §2.8.
//!
//! # This is where the product decides what it will not claim
//!
//! [`shape`](crate::shape) answers *"what did the message say"*. This answers *"what kind
//! of thing was it"*, and the interesting half is the refusals. A message with a source
//! address and nothing else is not a firewall decision; a message with the word `failed`
//! in it is not an authentication failure. Both would produce an event that something
//! downstream counts, and a count of things that are not what they claim to be is worse
//! than no count.
//!
//! So a classification requires **evidence of the kind**, not a keyword:
//!
//! | category | needs |
//! |---|---|
//! | `network` | two addresses *and* an action word |
//! | `authentication` | a user *and* an outcome word |
//! | `dns` | a question name |
//! | `vpn` | a user *and* a tunnel word *and* an outcome |
//!
//! Anything else is `None`, the log line stands on its own, and that is the correct
//! outcome.
//!
//! # No severity of this product's own invention
//!
//! §2.8. A firewall says `deny`; this records `denied` and the device's own severity. It
//! does not decide the event is *high*. Once a number is on the row every screen sorts by
//! it and nobody reads the event again.

use std::collections::BTreeMap;

/// What kind of thing happened — ECS's `event.category`, restricted to what this product
/// can actually establish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Authentication,
    Network,
    Dns,
    Vpn,
}

impl Category {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Network => "network",
            Self::Dns => "dns",
            Self::Vpn => "vpn",
        }
    }
}

/// ECS's `event.type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Allowed,
    Denied,
    Success,
    Failure,
    Start,
    End,
    Query,
}

impl Kind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Start => "start",
            Self::End => "end",
            Self::Query => "query",
        }
    }
}

/// A classification, and nothing more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Classification {
    pub category: Category,
    pub kind: Kind,
}

/// Words that mean a packet was let through.
///
/// Whole-value matches, not substrings: `denied` contains no allow word, but a substring
/// rule on `pass` would match `bypassed` and a substring rule on `ok` matches almost
/// everything. The same argument `uops_runbook::validate` makes about its deny-list.
const ALLOW: &[&str] = &[
    "allow",
    "allowed",
    "accept",
    "accepted",
    "pass",
    "permit",
    "permitted",
];

/// Words that mean it was not.
const DENY: &[&str] = &[
    "deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "discard",
];

/// Words that mean an attempt worked.
const SUCCEEDED: &[&str] = &[
    "success",
    "succeeded",
    "accept",
    "accepted",
    "ok",
    "pass",
    "passed",
];

/// Words that mean it did not.
const FAILED: &[&str] = &[
    "fail", "failed", "failure", "invalid", "denied", "reject", "rejected",
];

/// Words that mean a session opened.
const OPENED: &[&str] = &[
    "start",
    "started",
    "connect",
    "connected",
    "login",
    "logon",
    "up",
];

/// Words that mean it closed.
const CLOSED: &[&str] = &[
    "stop",
    "stopped",
    "disconnect",
    "disconnected",
    "logout",
    "logoff",
    "down",
];

/// Words that say a message is about a tunnel.
const TUNNEL: &[&str] = &[
    "vpn",
    "ipsec",
    "ssl-vpn",
    "sslvpn",
    "anyconnect",
    "wireguard",
    "tunnel",
];

/// Whether a value is one of these words, case-insensitively.
fn is(value: &str, words: &[&str]) -> bool {
    let value = value.trim().to_ascii_lowercase();
    words.contains(&value.as_str())
}

/// Whether any of these words appears as a *whole word* in the text.
fn mentions(text: &str, words: &[&str]) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .any(|token| words.contains(&token))
}

fn get<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    fields
        .get(key)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
}

/// Classify ECS-mapped fields, or decline.
///
/// `context` is the rest of what is known about the message — the CEF event name, the
/// syslog app name — used only to decide whether a message is about a tunnel. It is never
/// used to *invent* a field: a message with the word `vpn` in it and no user is still not
/// a VPN event.
#[must_use]
pub fn classify(fields: &BTreeMap<String, String>, context: &str) -> Option<Classification> {
    // DNS first: a resolver log has a question name and usually nothing else this would
    // recognise, and checking it later would let a resolver that logs client and server
    // addresses be classified as network traffic instead.
    if get(fields, "dns.question.name").is_some() {
        return Some(Classification {
            category: Category::Dns,
            kind: Kind::Query,
        });
    }

    let action = get(fields, "event.action");
    let outcome = get(fields, "event.outcome");
    let user = get(fields, "user.name");

    // VPN before authentication: a tunnel message usually has a user and an outcome too,
    // and classifying it as a plain sign-in would lose the thing that makes it interesting.
    if user.is_some()
        && mentions(context, TUNNEL)
        && let Some(kind) = session_kind(action, outcome)
    {
        return Some(Classification {
            category: Category::Vpn,
            kind,
        });
    }

    // Network: two addresses **and** an action word. One address is a mention; two
    // addresses with no verdict is a flow record, which M7 already stores better.
    let both_ends = get(fields, "source.ip").is_some() && get(fields, "destination.ip").is_some();
    if both_ends && let Some(kind) = verdict(action, outcome) {
        return Some(Classification {
            category: Category::Network,
            kind,
        });
    }

    // Authentication: a user **and** an outcome. A user with no outcome is a message that
    // happens to name somebody.
    if user.is_some()
        && let Some(kind) = auth_outcome(action, outcome)
    {
        return Some(Classification {
            category: Category::Authentication,
            kind,
        });
    }

    None
}

/// Allowed or denied, from whichever field carried the word.
fn verdict(action: Option<&str>, outcome: Option<&str>) -> Option<Kind> {
    for value in [action, outcome].into_iter().flatten() {
        if is(value, DENY) {
            return Some(Kind::Denied);
        }
        if is(value, ALLOW) {
            return Some(Kind::Allowed);
        }
    }
    None
}

/// Succeeded or failed.
///
/// `FAILED` is checked first, and that ordering is the decision: `denied` is in both lists
/// — an accepted connection that was then denied by policy is a failure, and a product that
/// reported it as a success would be wrong in the direction that matters.
fn auth_outcome(action: Option<&str>, outcome: Option<&str>) -> Option<Kind> {
    for value in [outcome, action].into_iter().flatten() {
        if is(value, FAILED) {
            return Some(Kind::Failure);
        }
        if is(value, SUCCEEDED) {
            return Some(Kind::Success);
        }
    }
    None
}

/// Started or ended, falling back to succeeded or failed.
fn session_kind(action: Option<&str>, outcome: Option<&str>) -> Option<Kind> {
    for value in [action, outcome].into_iter().flatten() {
        if is(value, OPENED) {
            return Some(Kind::Start);
        }
        if is(value, CLOSED) {
            return Some(Kind::End);
        }
    }
    auth_outcome(action, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn a_firewall_decision_needs_two_addresses_and_a_verdict() {
        let denied = classify(
            &fields(&[
                ("source.ip", "10.0.0.5"),
                ("destination.ip", "203.0.113.9"),
                ("event.action", "deny"),
            ]),
            "",
        )
        .expect("a network event");
        assert_eq!(denied.category, Category::Network);
        assert_eq!(denied.kind, Kind::Denied);

        let allowed = classify(
            &fields(&[
                ("source.ip", "10.0.0.5"),
                ("destination.ip", "8.8.8.8"),
                ("event.action", "accept"),
            ]),
            "",
        )
        .expect("a network event");
        assert_eq!(allowed.kind, Kind::Allowed);
    }

    #[test]
    fn two_addresses_with_no_verdict_is_not_a_security_event() {
        // It is a flow record, and M7 already stores those better — §2.6. Producing a
        // network event with no outcome would put a row in `events` that says nothing.
        assert!(
            classify(
                &fields(&[("source.ip", "10.0.0.5"), ("destination.ip", "8.8.8.8")]),
                "",
            )
            .is_none()
        );
    }

    #[test]
    fn one_address_is_a_mention_rather_than_a_decision() {
        assert!(
            classify(
                &fields(&[("source.ip", "10.0.0.5"), ("event.action", "deny")]),
                ""
            )
            .is_none()
        );
    }

    #[test]
    fn an_authentication_needs_a_user_and_an_outcome() {
        let failed = classify(
            &fields(&[("user.name", "alice"), ("event.outcome", "failure")]),
            "sshd",
        )
        .expect("an authentication event");
        assert_eq!(failed.category, Category::Authentication);
        assert_eq!(failed.kind, Kind::Failure);

        // A user and nothing else is a message that happens to name somebody.
        assert!(classify(&fields(&[("user.name", "alice")]), "sshd").is_none());
    }

    #[test]
    fn denied_reads_as_a_failure_rather_than_a_success() {
        // `denied` is in both word lists: an attempt that was accepted and then denied by
        // policy is a failure, and reporting it as a success would be wrong in the one
        // direction that matters.
        let it = classify(
            &fields(&[("user.name", "bob"), ("event.outcome", "denied")]),
            "vpn",
        )
        .expect("classified");
        assert_eq!(it.kind, Kind::Failure);
    }

    #[test]
    fn a_resolver_log_is_a_dns_query() {
        let it = classify(
            &fields(&[
                ("dns.question.name", "example.invalid"),
                ("source.ip", "10.0.0.5"),
            ]),
            "",
        )
        .expect("a dns event");
        assert_eq!(it.category, Category::Dns);
        assert_eq!(it.kind, Kind::Query);
    }

    #[test]
    fn a_resolver_that_logs_both_ends_is_still_dns() {
        // Checked before network for exactly this: a resolver logging client and server
        // addresses with an action would otherwise be classified as firewall traffic.
        let it = classify(
            &fields(&[
                ("dns.question.name", "example.invalid"),
                ("source.ip", "10.0.0.5"),
                ("destination.ip", "10.0.0.1"),
                ("event.action", "allow"),
            ]),
            "",
        )
        .expect("classified");
        assert_eq!(it.category, Category::Dns);
    }

    #[test]
    fn a_tunnel_message_is_vpn_rather_than_a_plain_sign_in() {
        // Checked before authentication: a VPN login has a user and an outcome too, and
        // calling it a sign-in would lose the thing that makes it worth looking at.
        let it = classify(
            &fields(&[("user.name", "carol"), ("event.action", "connected")]),
            "sslvpn",
        )
        .expect("a vpn event");
        assert_eq!(it.category, Category::Vpn);
        assert_eq!(it.kind, Kind::Start);

        let out = classify(
            &fields(&[("user.name", "carol"), ("event.action", "disconnected")]),
            "AnyConnect session",
        )
        .expect("classified");
        assert_eq!(out.kind, Kind::End);
    }

    #[test]
    fn the_word_vpn_alone_does_not_make_a_vpn_event() {
        // Context decides *which* category, never whether there is one. A message with the
        // word in it and no user is still not a tunnel event.
        assert!(classify(&fields(&[("source.ip", "10.0.0.5")]), "vpn gateway").is_none());
    }

    #[test]
    fn nothing_recognisable_classifies_as_nothing() {
        assert!(classify(&BTreeMap::new(), "").is_none());
        assert!(classify(&fields(&[("vendor.thing", "42")]), "some prose").is_none());
    }

    #[test]
    fn word_matching_is_whole_words() {
        // `pass` must not match `bypassed`, and `up` must not match `upgrade`. The same
        // argument the runbook deny-list makes, and the reason these are values rather
        // than substrings.
        assert!(!is("bypassed", ALLOW));
        assert!(!is("upgrade", OPENED));
        assert!(is("Pass", ALLOW), "matching is case-insensitive");
        assert!(!mentions("the upgrade completed", TUNNEL));
        assert!(mentions("ssl-vpn session opened", TUNNEL));
    }

    #[test]
    fn every_category_and_kind_has_an_ecs_name() {
        for c in [
            Category::Authentication,
            Category::Network,
            Category::Dns,
            Category::Vpn,
        ] {
            assert!(!c.as_str().is_empty());
        }
        for k in [
            Kind::Allowed,
            Kind::Denied,
            Kind::Success,
            Kind::Failure,
            Kind::Start,
            Kind::End,
            Kind::Query,
        ] {
            assert!(!k.as_str().is_empty());
        }
    }
}
