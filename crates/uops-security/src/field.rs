//! Vendor field names, mapped to ECS — M11 §2.1.
//!
//! # Why an alias table and not a parser per vendor
//!
//! Every firewall in the world calls a source address something slightly different:
//! `src`, `srcip`, `src_ip`, `saddr`, `source-address`, `SourceIP`. The names differ; the
//! *field* does not. A table of aliases is a hundred lines that somebody can read and
//! extend in one place, and it degrades gracefully — an unrecognised key is kept under its
//! own name rather than dropped, so a customer can still search for it even when this
//! product does not know what it means.
//!
//! The alternative — a parser per vendor — is the thing M11 §2.2 exists to refuse.
//!
//! # Unrecognised keys are kept, not discarded
//!
//! A key this table has never heard of goes into the attributes under its own name, lightly
//! namespaced. Dropping it would mean the event carries less than the log line it came
//! from, which would make the event strictly worse than the thing it summarises.

use std::collections::BTreeMap;

/// Where a key this table does not recognise ends up.
///
/// Namespaced so it cannot be mistaken for a semantic convention that exists. The same
/// reasoning `uops_syslog::normalize` uses for its `syslog.` prefix.
pub const UNKNOWN_PREFIX: &str = "vendor.";

/// `(alias, ECS field)`, alias lower-cased.
///
/// Sorted by ECS field so that reading it answers "what does this product understand about
/// a firewall log" rather than "what does `spt` mean". Aliases are matched case-insensitively
/// and with `-`/`_` treated alike — see [`normalise_key`].
const ALIASES: &[(&str, &str)] = &[
    // --- addresses and ports ---
    ("src", "source.ip"),
    ("srcip", "source.ip"),
    ("src_ip", "source.ip"),
    ("saddr", "source.ip"),
    ("sourceip", "source.ip"),
    ("source_address", "source.ip"),
    ("client_ip", "source.ip"),
    ("dst", "destination.ip"),
    ("dstip", "destination.ip"),
    ("dst_ip", "destination.ip"),
    ("daddr", "destination.ip"),
    ("destinationip", "destination.ip"),
    ("destination_address", "destination.ip"),
    ("spt", "source.port"),
    ("sport", "source.port"),
    ("src_port", "source.port"),
    ("srcport", "source.port"),
    ("sourceport", "source.port"),
    ("dpt", "destination.port"),
    ("dport", "destination.port"),
    ("dst_port", "destination.port"),
    ("dstport", "destination.port"),
    ("destinationport", "destination.port"),
    // --- transport ---
    ("proto", "network.transport"),
    ("protocol", "network.transport"),
    ("ipproto", "network.transport"),
    ("transport", "network.transport"),
    // --- who ---
    ("user", "user.name"),
    ("usr", "user.name"),
    ("username", "user.name"),
    ("user_name", "user.name"),
    ("suser", "user.name"),
    ("duser", "user.name"),
    ("account", "user.name"),
    ("login", "user.name"),
    // --- what happened ---
    ("act", "event.action"),
    ("action", "event.action"),
    ("disposition", "event.action"),
    ("verdict", "event.action"),
    ("outcome", "event.outcome"),
    ("result", "event.outcome"),
    ("status", "event.outcome"),
    // --- dns ---
    ("query", "dns.question.name"),
    ("qname", "dns.question.name"),
    ("question", "dns.question.name"),
    ("domain", "dns.question.name"),
    ("rcode", "dns.response_code"),
    ("response_code", "dns.response_code"),
    ("qtype", "dns.question.type"),
    // --- context a firewall gives for free ---
    ("rule", "rule.name"),
    ("rulename", "rule.name"),
    ("policyid", "rule.id"),
    ("policy_id", "rule.id"),
    ("srcintf", "observer.ingress.interface.name"),
    ("dstintf", "observer.egress.interface.name"),
    ("devname", "observer.name"),
    ("hostname", "host.name"),
];

/// Lower-case, and `-` treated as `_`.
///
/// One normalisation rather than three aliases per name: `src-ip`, `src_ip` and `SRC_IP`
/// are one key spelled by three vendors, and putting all three in the table would make it
/// three times as long without saying anything more.
#[must_use]
pub fn normalise_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('-', "_")
}

/// The ECS field for a vendor key, if this product knows one.
#[must_use]
pub fn ecs_field(key: &str) -> Option<&'static str> {
    let key = normalise_key(key);
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == key)
        .map(|(_, field)| *field)
}

/// Map a bag of vendor key-values onto ECS names.
///
/// Later duplicates lose. A message with `src=1.1.1.1 src=2.2.2.2` is malformed and the
/// choice between them is arbitrary; taking the first is at least deterministic, which
/// matters more than which one it is.
#[must_use]
pub fn to_ecs(raw: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, value) in raw {
        if value.trim().is_empty() {
            // An empty value carries nothing and would make `has("source.ip")` true for a
            // message that named the field and gave no address.
            continue;
        }
        let name = ecs_field(key).map_or_else(
            || format!("{UNKNOWN_PREFIX}{}", normalise_key(key)),
            ToOwned::to_owned,
        );
        out.entry(name).or_insert_with(|| value.trim().to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn the_same_field_under_every_name_a_vendor_gives_it() {
        // The whole reason this table exists: one field, six spellings, and a product that
        // can group by it only if they all land on one name.
        for alias in ["src", "srcip", "src_ip", "saddr", "sourceip", "client_ip"] {
            assert_eq!(ecs_field(alias), Some("source.ip"), "{alias}");
        }
        for alias in ["dpt", "dport", "dst_port", "dstport"] {
            assert_eq!(ecs_field(alias), Some("destination.port"), "{alias}");
        }
    }

    #[test]
    fn case_and_the_dash_underscore_split_are_one_key() {
        // Three spellings of one name, normalised rather than listed three times.
        assert_eq!(ecs_field("SRC_IP"), Some("source.ip"));
        assert_eq!(ecs_field("src-ip"), Some("source.ip"));
        assert_eq!(ecs_field("  Src_Ip  "), Some("source.ip"));
    }

    #[test]
    fn a_key_nobody_knows_is_kept_rather_than_dropped() {
        // An event that carried less than the log line it summarises would be strictly
        // worse than the line. The namespace is so it cannot be mistaken for a convention.
        let mapped = to_ecs(&raw(&[("weird_vendor_thing", "42")]));
        assert_eq!(
            mapped.get("vendor.weird_vendor_thing").map(String::as_str),
            Some("42")
        );
        assert!(ecs_field("weird_vendor_thing").is_none());
    }

    #[test]
    fn an_empty_value_is_not_a_field() {
        // `src=` names the field and gives no address. Keeping it would make "this event
        // has a source address" true for a message that has none, which is the kind of
        // thing a detection then counts.
        let mapped = to_ecs(&raw(&[("src", "  "), ("dst", "10.0.0.1")]));
        assert!(!mapped.contains_key("source.ip"));
        assert_eq!(
            mapped.get("destination.ip").map(String::as_str),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn values_are_trimmed_but_not_otherwise_touched() {
        // Not lower-cased: `user.name` is a credential-shaped value and `Administrator`
        // is not `administrator` on every system that matters.
        let mapped = to_ecs(&raw(&[("user", " Administrator ")]));
        assert_eq!(
            mapped.get("user.name").map(String::as_str),
            Some("Administrator")
        );
    }

    #[test]
    fn every_alias_is_lower_case_and_normalised_in_the_table_itself() {
        // The lookup normalises the *input*; an alias written `Src-IP` in the table would
        // therefore never match anything. Asserted rather than trusted to review.
        for (alias, field) in ALIASES {
            assert_eq!(
                *alias,
                normalise_key(alias),
                "alias {alias} is not normalised"
            );
            assert!(field.contains('.'), "{field} is not an ECS-shaped name");
        }
    }

    #[test]
    fn no_alias_maps_to_two_fields() {
        // A duplicate with a different target would make the mapping depend on table
        // order, which is exactly the kind of thing that changes when somebody sorts it.
        for (alias, field) in ALIASES {
            let all: Vec<_> = ALIASES
                .iter()
                .filter(|(a, _)| a == alias)
                .map(|(_, f)| *f)
                .collect();
            assert!(all.iter().all(|f| f == field), "{alias} maps to {all:?}");
        }
    }
}
