//! What the product is allowed to say about a device that will not identify itself.
//!
//! Most of these are about **refusing**. A classifier that always has an answer is a
//! classifier nobody can trust on the day it matters, and the failure is silent: a wrong
//! label on an address looks exactly like a right one. So the tests that matter here are
//! the ones asserting it says *unknown*, keeps its confidence low, and shows its working.

use uops_guess::{Confidence, Evidence, Role, guess, initial_ttl};

/// Zebra Technologies — a vendor whose whole business is printing.
const ZEBRA: &str = "00:07:4d:11:22:33";
/// Cisco — a vendor that makes routers, switches, firewalls, phones and access points.
const CISCO: &str = "00:00:0c:aa:bb:cc";

#[test]
fn nothing_known_is_unknown_rather_than_a_plausible_label() {
    let it = guess(&Evidence::default());
    assert_eq!(it.role, Role::Unknown);
    assert_eq!(it.confidence, Confidence::Unknown);
    assert!(it.because.is_empty());
    assert!(!it.worth_showing());
}

#[test]
fn a_hostname_on_its_own_never_gets_past_possible() {
    // `ap-lobby` is a decent hint and is also what somebody calls the laptop they carry
    // to the lobby. One naming convention is not evidence.
    let it = guess(&Evidence {
        hostname: Some("ap-lobby"),
        ..Evidence::default()
    });
    assert_eq!(it.role, Role::AccessPoint);
    assert_eq!(it.confidence, Confidence::Possible);
}

#[test]
fn two_weak_signals_that_agree_are_worth_more_than_either() {
    let it = guess(&Evidence {
        mac: Some(ZEBRA),
        hostname: Some("print-lobby-2"),
        ..Evidence::default()
    });
    assert_eq!(it.role, Role::Printer);
    assert_eq!(it.confidence, Confidence::Likely);
    assert_eq!(it.because.len(), 2, "both signals are shown: {:?}", it.because);
}

#[test]
fn when_the_vendor_and_the_hostname_disagree_it_says_so_and_stays_a_hunch() {
    // A Zebra printer called "sw-03" is either mislabelled or replugged, and the product
    // does not know which. It must not sound certain, and it must show both readings.
    let it = guess(&Evidence {
        mac: Some(ZEBRA),
        hostname: Some("sw-03"),
        ..Evidence::default()
    });
    assert_eq!(it.confidence, Confidence::Possible);
    assert_eq!(it.because.len(), 2);
    let text: String = it.because.iter().map(|r| r.saying.clone()).collect();
    assert!(text.contains("Zebra"), "{text}");
    assert!(text.contains("sw-"), "{text}");
}

#[test]
fn a_device_that_describes_itself_beats_every_other_signal() {
    // sysDescr is the device's own account of itself. A Cisco MAC and a hostname of
    // "rtr-core" both point at a router; the description says it is a firewall, and it is
    // the one that actually knows.
    let it = guess(&Evidence {
        mac: Some(CISCO),
        hostname: Some("rtr-core-1"),
        sys_descr: Some("Cisco Adaptive Security Appliance Version 9.16"),
        ..Evidence::default()
    });
    assert_eq!(it.role, Role::Firewall);
    assert_eq!(it.confidence, Confidence::Likely);
}

#[test]
fn a_vendor_that_makes_everything_contributes_nothing_to_the_role() {
    // The table is deliberately short — `docs/what-is-this-thing.md` §3.5. Cisco makes
    // routers, switches, firewalls, phones and access points, so its OUI says nothing
    // about which. The vendor is still reported, because "Cisco" beats nothing.
    let it = guess(&Evidence {
        mac: Some(CISCO),
        ..Evidence::default()
    });
    assert_eq!(it.role, Role::Unknown);
    assert!(it.vendor.is_some(), "the manufacturer is still worth showing");
    assert!(it.worth_showing());
    assert_eq!(it.because.len(), 1);
}

#[test]
fn an_unknown_mac_is_not_an_error() {
    // Locally administered and unregistered addresses are ordinary, especially on
    // virtualised estates.
    let it = guess(&Evidence {
        mac: Some("02:00:00:00:00:01"),
        ..Evidence::default()
    });
    assert_eq!(it.role, Role::Unknown);
    assert!(it.vendor.is_none());
}

#[test]
fn malformed_input_is_survived_rather_than_rejected() {
    // The caller is a screen listing addresses. A panic here is a blank page; a wrong
    // guess is a line somebody dismisses.
    for mac in ["", "not a mac", "00:07", "zz:zz:zz:zz:zz:zz"] {
        let it = guess(&Evidence {
            mac: Some(mac),
            ..Evidence::default()
        });
        assert_eq!(it.role, Role::Unknown);
    }
}

#[test]
fn the_reasons_name_which_input_spoke() {
    let it = guess(&Evidence {
        mac: Some(ZEBRA),
        hostname: Some("printer-4"),
        ..Evidence::default()
    });
    let froms: Vec<&str> = it.because.iter().map(|r| r.from).collect();
    assert!(froms.contains(&"mac"), "{froms:?}");
    assert!(froms.contains(&"hostname"), "{froms:?}");
}

#[test]
fn ttl_recovers_the_family_and_the_hop_count() {
    // 64 on Linux and most embedded stacks, 128 on Windows, 255 on network gear.
    assert_eq!(initial_ttl(64), Some((64, 0)));
    assert_eq!(initial_ttl(57), Some((64, 7)));
    assert_eq!(initial_ttl(128), Some((128, 0)));
    assert_eq!(initial_ttl(120), Some((128, 8)));
    assert_eq!(initial_ttl(250), Some((255, 5)));
}

#[test]
fn ttl_is_reported_but_does_not_decide_a_role_on_its_own() {
    // An OS family is not a role: "something running Linux" covers a switch, a camera and
    // a server. It is context for a reader, not a classification.
    let it = guess(&Evidence {
        ttl: Some(57),
        ..Evidence::default()
    });
    assert_eq!(it.role, Role::Unknown);
    assert_eq!(it.because.len(), 1, "it still says what it saw");
    assert_eq!(it.because[0].from, "ttl");
}

#[test]
fn every_role_has_a_label_fit_for_a_screen() {
    for role in [
        Role::Router,
        Role::Switch,
        Role::AccessPoint,
        Role::Firewall,
        Role::Printer,
        Role::Camera,
        Role::Phone,
        Role::Hypervisor,
        Role::Storage,
        Role::Workstation,
        Role::Server,
        Role::Unknown,
    ] {
        let label = role.label();
        assert!(!label.is_empty());
        assert_eq!(label, label.to_lowercase(), "labels are sentence-cased by the UI");
    }
}
