//! Reading what `tracert` and `traceroute` printed — `docs/traceroute.md` §3.
//!
//! This is the liability in the whole feature and it is where the tests are. Parsing
//! another program's prose is fragile by nature: the wording changes with version and
//! locale, and the failure mode is silent — a misparsed line becomes a hop, and a hop
//! invented from a misparsed line puts an address on a path it was never on.
//!
//! So: **a line that is not understood is skipped, never guessed at**, and the raw output
//! travels back with the result so a reader can always check what was really said.
//!
//! # The cases that are not obvious
//!
//! All three were visible within five minutes of running the real command:
//!
//! ```text
//!   1     3 ms     3 ms     3 ms  192.168.1.1          ordinary
//!   1    <1 ms    <1 ms    <1 ms  192.168.1.116        sub-millisecond: "<1 ms", not a number
//!   1     *        *     192.168.1.171  reports: Destination host unreachable.
//! ```
//!
//! The third is the dangerous one. It is **not a hop** — it is the local machine saying the
//! target cannot be reached — and a reader that takes "the last address on the line" would
//! record `192.168.1.171` as hop 1 of a path to somewhere it never forwarded to.

use crate::{Hop, scope::scope_of};

/// Windows `tracert`.
///
/// Shape: hop number, then one field per probe (`3 ms`, `<1 ms` or `*`), then the address.
#[must_use]
pub fn parse_windows(output: &str) -> Vec<Hop> {
    let mut hops = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // A line the local stack emitted about the *trace*, not a hop on it. Dropped
        // whole: see the module docs for why taking its address would be actively wrong.
        if line.contains("reports:") {
            continue;
        }

        let mut fields = line.split_whitespace();
        let Some(number) = fields.next().and_then(|n| n.parse::<u8>().ok()) else {
            // Headers, blank lines, "Trace complete." — anything not starting with a hop
            // number is not a hop.
            continue;
        };

        let mut rtt_ms = Vec::new();
        let mut address = None;
        let rest: Vec<&str> = fields.collect();
        let mut i = 0;
        while i < rest.len() {
            let token = rest[i];
            if token == "*" {
                rtt_ms.push(None);
                i += 1;
            } else if let Some(ms) = windows_rtt(token, rest.get(i + 1).copied()) {
                rtt_ms.push(Some(ms));
                // `3 ms` is two tokens; `<1` and `ms` likewise. Either way the unit is
                // consumed with the number.
                i += if rest.get(i + 1) == Some(&"ms") { 2 } else { 1 };
            } else {
                // Not a timing. It is the address *only if it is one*: a fully-timed-out
                // hop ends with "Request timed out." and taking the first word of that as
                // an address is how "Request" ends up on a path. The probe always passes
                // `-d`/`-n`, so a real hop is always a literal address.
                let candidate = token.trim_matches(['[', ']']);
                if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
                    address = Some(candidate.to_owned());
                }
                break;
            }
        }

        // A hop with neither a timing nor an address is not a hop; it is a line that
        // happened to start with a number.
        if rtt_ms.is_empty() && address.is_none() {
            continue;
        }

        let scope = address.as_deref().map_or(crate::Scope::Unknown, scope_of);
        hops.push(Hop {
            number,
            address,
            rtt_ms,
            scope,
        });
    }

    hops
}

/// One Windows timing field. `3`+`ms`, or `<1`+`ms`.
///
/// `<1 ms` means "under a millisecond", and the honest number for it is not 1 — that would
/// read as a whole millisecond on a chart. Half is the midpoint of what it can mean and is
/// the convention every other tool uses.
fn windows_rtt(token: &str, next: Option<&str>) -> Option<f64> {
    if next != Some("ms") {
        return None;
    }
    if let Some(under) = token.strip_prefix('<') {
        return under.parse::<f64>().ok().map(|v| v / 2.0);
    }
    token.parse::<f64>().ok()
}

/// Unix `traceroute`.
///
/// Shape: hop number, then the address once, then timings that may be interleaved with
/// further addresses when a hop answers from more than one router — which is ordinary on a
/// load-balanced path and is why the first address is kept rather than the last.
#[must_use]
pub fn parse_unix(output: &str) -> Vec<Hop> {
    let mut hops = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("traceroute to") {
            continue;
        }

        let mut fields = line.split_whitespace().peekable();
        let Some(number) = fields.next().and_then(|n| n.parse::<u8>().ok()) else {
            continue;
        };

        let mut rtt_ms = Vec::new();
        let mut address: Option<String> = None;
        let mut pending: Option<f64> = None;

        for token in fields {
            if token == "*" {
                rtt_ms.push(None);
            } else if token == "ms" {
                // The unit closes the number before it.
                if let Some(value) = pending.take() {
                    rtt_ms.push(Some(value));
                }
            } else if let Ok(value) = token.parse::<f64>() {
                pending = Some(value);
            } else if address.is_none() {
                // The first token that *is an address* is the address. Anything else on
                // the line — a name in parentheses, an ICMP annotation like `!H` — is not,
                // and guessing would put it on the path.
                let candidate = token.trim_matches(['(', ')']);
                if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
                    address = Some(candidate.to_owned());
                }
            }
        }

        if rtt_ms.is_empty() && address.is_none() {
            continue;
        }

        let scope = address.as_deref().map_or(crate::Scope::Unknown, scope_of);
        hops.push(Hop {
            number,
            address,
            rtt_ms,
            scope,
        });
    }

    hops
}
