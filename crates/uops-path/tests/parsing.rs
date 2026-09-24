//! Reading what a traceroute actually printed.
//!
//! Every fixture here is **real output captured from the machine this was built on**, not
//! output invented to match the parser. That distinction is the point: a parser tested
//! against its author's idea of the format passes forever and fails on first contact.
//!
//! The failure this guards is silent. A misparsed line becomes a hop, and a hop invented
//! from a misparsed line puts an address on a path it was never on — which an operator
//! would then chase.

use uops_path::{Scope, parse_unix, parse_windows, probe::is_usable_target, scope_of};

/// Captured from `tracert -d -h 6 -w 1000 1.1.1.1` on 2026-09-24.
const REAL_WINDOWS: &str = "\
Tracing route to 1.1.1.1 over a maximum of 6 hops

  1     3 ms     3 ms     3 ms  192.168.1.1
  2     7 ms     3 ms     3 ms  10.153.77.1
  3     6 ms     3 ms     4 ms  10.20.251.97
  4     3 ms     4 ms     3 ms  100.64.170.170
  5     5 ms     3 ms     3 ms  100.64.170.33
  6     6 ms     3 ms     3 ms  100.64.170.21

Trace complete.
";

/// Captured from `tracert -d -h 3 -w 800 192.168.1.116` — a sub-millisecond single hop.
const REAL_SUBMILLISECOND: &str = "\
Tracing route to 192.168.1.116 over a maximum of 3 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.116

Trace complete.
";

/// Captured from `tracert -d -h 8 -w 800 192.168.1.250` while the router was stopped.
///
/// **The dangerous one.** The address on this line is the *local machine* reporting that
/// the target is unreachable. It is not a hop, and a reader that takes the last address on
/// a line would record it as one.
const REAL_UNREACHABLE: &str = "\
Tracing route to 192.168.1.250 over a maximum of 8 hops

  1     *        *     192.168.1.171  reports: Destination host unreachable.

Trace complete.
";

#[test]
fn a_real_windows_trace_reads_as_six_hops() {
    let hops = parse_windows(REAL_WINDOWS);
    assert_eq!(hops.len(), 6, "{hops:#?}");
    assert_eq!(hops[0].number, 1);
    assert_eq!(hops[0].address.as_deref(), Some("192.168.1.1"));
    assert_eq!(hops[0].rtt_ms, vec![Some(3.0), Some(3.0), Some(3.0)]);
    assert_eq!(hops[1].rtt_ms, vec![Some(7.0), Some(3.0), Some(3.0)]);
    assert_eq!(hops[5].address.as_deref(), Some("100.64.170.21"));
}

#[test]
fn the_headers_and_the_footer_are_not_hops() {
    // "Tracing route to..." and "Trace complete." both contain numbers and neither is a
    // hop. Anything that does not begin with a hop number is dropped.
    let hops = parse_windows(REAL_WINDOWS);
    assert!(hops.iter().all(|h| h.number >= 1 && h.number <= 6));
}

#[test]
fn a_report_line_is_not_a_hop() {
    // The whole reason this case is handled: 192.168.1.171 is this machine saying the
    // target is unreachable. Recording it as hop 1 would put the local address on a path
    // it never forwarded to, and an operator would chase it.
    let hops = parse_windows(REAL_UNREACHABLE);
    assert!(
        hops.is_empty(),
        "a 'reports:' line is the local stack talking, not a hop: {hops:#?}"
    );
}

#[test]
fn sub_millisecond_timings_are_not_read_as_a_whole_millisecond() {
    // "<1 ms" means under a millisecond. Reading it as 1.0 would put a whole millisecond
    // on a chart for a hop that took less, which is the only place these numbers are used.
    let hops = parse_windows(REAL_SUBMILLISECOND);
    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].address.as_deref(), Some("192.168.1.116"));
    for rtt in &hops[0].rtt_ms {
        let value = rtt.expect("the probe answered");
        assert!(value > 0.0 && value < 1.0, "got {value}");
    }
}

#[test]
fn a_silent_hop_is_recorded_as_a_gap_rather_than_dropped() {
    // A router that does not answer ttl-exceeded is silent by policy and the path
    // continues past it. Dropping the row would renumber everything after it.
    let output = "\
  1     1 ms     1 ms     1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3     9 ms     8 ms     9 ms  10.0.0.1
";
    let hops = parse_windows(output);
    assert_eq!(hops.len(), 3, "{hops:#?}");
    assert_eq!(hops[1].number, 2);
    assert!(!hops[1].answered());
    assert_eq!(hops[1].rtt_ms, vec![None, None, None]);
    assert_eq!(hops[1].loss(), Some(1.0));
    assert_eq!(hops[2].address.as_deref(), Some("10.0.0.1"));
}

#[test]
fn partial_loss_is_visible_rather_than_averaged_away() {
    // One slow probe out of three is a different finding from three evenly slow ones.
    let hops = parse_windows("  7     2 ms     *       40 ms  10.1.2.3\n");
    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].rtt_ms, vec![Some(2.0), None, Some(40.0)]);
    assert!((hops[0].loss().expect("sent") - 1.0 / 3.0).abs() < 1e-9);
    assert_eq!(hops[0].best_ms(), Some(2.0));
}

#[test]
fn a_unix_trace_reads_the_same_way() {
    let output = "\
traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets
 1  192.168.1.1  0.401 ms  0.372 ms  0.366 ms
 2  * * *
 3  100.64.0.1  8.201 ms  8.170 ms  8.140 ms
";
    let hops = parse_unix(output);
    assert_eq!(hops.len(), 3, "{hops:#?}");
    assert_eq!(hops[0].address.as_deref(), Some("192.168.1.1"));
    assert_eq!(hops[0].rtt_ms.len(), 3);
    assert!(!hops[1].answered());
    assert_eq!(hops[2].scope, Scope::CarrierGrade);
}

#[test]
fn nothing_parseable_yields_nothing_rather_than_a_guess() {
    for junk in [
        "",
        "permission denied",
        "Unable to resolve target system name.",
    ] {
        assert!(parse_windows(junk).is_empty(), "{junk}");
        assert!(parse_unix(junk).is_empty(), "{junk}");
    }
}

// ---------------------------------------------------------------------------

#[test]
fn carrier_grade_space_is_not_called_public() {
    // The distinction that earned its place on the first real trace: 100.64.170.170 is the
    // ISP's own space, not the internet. Calling it "outside" implies the operator's
    // responsibility ended one hop earlier than it did.
    assert_eq!(scope_of("100.64.170.170"), Scope::CarrierGrade);
    assert_eq!(scope_of("100.127.255.255"), Scope::CarrierGrade);
    // The range is 100.64.0.0/10 — the second octet runs 64..=127, and the easy mistake is
    // to match only `100.64`, which misses three quarters of it.
    assert_eq!(scope_of("100.100.1.1"), Scope::CarrierGrade);
    // Just outside, both ends.
    assert_eq!(scope_of("100.63.0.1"), Scope::Public);
    assert_eq!(scope_of("100.128.0.1"), Scope::Public);
}

#[test]
fn the_private_ranges_are_the_whole_of_rfc1918() {
    assert_eq!(scope_of("10.255.255.255"), Scope::Private);
    assert_eq!(scope_of("192.168.1.1"), Scope::Private);
    assert_eq!(scope_of("172.16.0.1"), Scope::Private);
    assert_eq!(scope_of("172.31.255.255"), Scope::Private);
    // 172.15 and 172.32 are public, which is the boundary people get wrong.
    assert_eq!(scope_of("172.15.0.1"), Scope::Public);
    assert_eq!(scope_of("172.32.0.1"), Scope::Public);
}

#[test]
fn only_public_hops_could_ever_be_placed_on_a_map() {
    // Geolocation is not built. The rule is written down now so it is the product's
    // already when it is — there is no place called 10.0.0.1.
    assert!(Scope::Public.is_locatable());
    for scope in [
        Scope::Private,
        Scope::CarrierGrade,
        Scope::LinkLocal,
        Scope::Loopback,
        Scope::Unknown,
    ] {
        assert!(!scope.is_locatable(), "{scope:?} has no geographic place");
    }
}

#[test]
fn private_means_not_publicly_routable_and_not_that_it_is_yours() {
    // Found in real output: the first public trace crossed 10.153.77.1 and 10.20.251.97 —
    // both RFC 1918, and both the ISP's rather than the estate's. An earlier version of
    // this called them "inside the estate's own responsibility", which would have pointed
    // an operator at two routers they cannot touch.
    assert!(Scope::Private.is_not_public());
    assert!(Scope::LinkLocal.is_not_public());
    assert!(Scope::Loopback.is_not_public());
    assert!(!Scope::CarrierGrade.is_not_public());
    assert!(!Scope::Public.is_not_public());
}

// ---------------------------------------------------------------------------

#[test]
fn a_target_that_is_not_an_address_or_a_hostname_is_refused_before_anything_is_spawned() {
    assert!(is_usable_target("192.168.1.1"));
    assert!(is_usable_target("core-sw-01.example.invalid"));

    for bad in [
        "",
        "   ",
        "8.8.8.8; rm -rf /",
        "$(whoami)",
        "`id`",
        "a b",
        "-h",
        ".leading.dot",
        "trailing.dash-",
        "host|name",
        "host\nname",
    ] {
        assert!(!is_usable_target(bad), "{bad:?} must be refused");
    }
}

#[test]
fn prose_on_a_timed_out_line_never_becomes_an_address() {
    // Caught by a test rather than by review: the parser took the first non-timing token
    // as the address, so "  2  *  *  *  Request timed out." recorded a hop at "Request".
    // The probe always passes -d/-n, so a real hop is a literal address and nothing else
    // qualifies.
    let hops = parse_windows("  2     *        *        *     Request timed out.\n");
    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].address, None, "{:?}", hops[0].address);

    // The Unix equivalent, plus an ICMP annotation that is not an address either.
    let unix = parse_unix(" 5  * * *\n 6  10.0.0.1  1.2 ms !H\n");
    assert_eq!(unix[0].address, None);
    assert_eq!(unix[1].address.as_deref(), Some("10.0.0.1"));
}
