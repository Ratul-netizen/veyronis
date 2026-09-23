//! What a thing probably is, when nothing will say what it is — `docs/what-is-this-thing.md`.
//!
//! # This is not identity resolution and must never be mistaken for it
//!
//! [`uops_identity`](https://docs.rs) decides *which resource* something is, on identifiers
//! that are unique by specification, and sends anything ambiguous to a review queue. It is
//! the highest-leverage component in the system and everything downstream is worthless if
//! it is wrong.
//!
//! This is the opposite kind of thing. It looks at a device that answered a ping and said
//! nothing useful, and offers an opinion about what it might be. The two are kept apart by
//! the type system rather than by care: a [`Guess`] is not a `ResourceKind`, so it cannot
//! be assigned to one by accident, and the only way a guess becomes a fact is a person
//! agreeing with it.
//!
//! # Every guess carries its evidence
//!
//! A bare *"73% printer"* is unarguable — a reader cannot tell whether to believe it. Every
//! [`Guess`] carries the [`Reason`]s that produced it, so an operator can dismiss a wrong
//! one in a second. That is what makes it safe to put on a screen at all, and it is the
//! same rule M11 §2.8 applies to severity: the product may show what it knows and may not
//! invent.
//!
//! ```
//! use uops_guess::{Evidence, Role, guess};
//!
//! let it = guess(&Evidence {
//!     mac: Some("00:07:4d:11:22:33"),   // Zebra Technologies
//!     hostname: Some("print-lobby-2"),
//!     ..Evidence::default()
//! });
//! assert_eq!(it.role, Role::Printer);
//! // Two independent signals agreed, so it is more than a hunch — and it says why.
//! assert!(it.because.len() >= 2);
//! ```

use serde::{Deserialize, Serialize};

/// What is known about a thing that has not identified itself.
///
/// Every field is optional because the case this exists for is the one where most of them
/// are missing. All of these except `ttl` are already stored on `discovery_candidate`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Evidence<'a> {
    /// From the ARP table. Resolved to a vendor through `uops_oui`.
    pub mac: Option<&'a str>,
    /// From rDNS. Weak and conventional, and never enough on its own — see [`Confidence`].
    pub hostname: Option<&'a str>,
    /// `sysDescr`, when the device answered SNMP at all but told us nothing structured.
    /// The strongest of these when present: it usually names the OS and often the model.
    pub sys_descr: Option<&'a str>,
    /// Observed ICMP TTL.
    ///
    /// **Nothing populates this yet** — `docs/what-is-this-thing.md` §5. The product does
    /// not capture TTL, and adding it means changing a check that cannot run on the
    /// development host at all. The field is here, and used when present, so the door is
    /// open without anything untested being shipped behind it.
    pub ttl: Option<u8>,
}

/// What a thing appears to be *for*.
///
/// A role, deliberately not a `ResourceKind`. `ResourceKind` is the schema's vocabulary —
/// `Device`, `Host`, `Service` — it answers a different question, and discovery already
/// sets it correctly. What an operator wants to know about an unaccounted address is
/// nearer to "printer".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Router,
    Switch,
    AccessPoint,
    Firewall,
    Printer,
    Camera,
    Phone,
    Hypervisor,
    Storage,
    Workstation,
    Server,
    /// Something is there and nothing about it suggests what. **The honest answer**, and
    /// the one this returns rather than reaching for the nearest plausible label.
    Unknown,
}

impl Role {
    /// What to call it on a screen.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::Switch => "switch",
            Self::AccessPoint => "access point",
            Self::Firewall => "firewall",
            Self::Printer => "printer",
            Self::Camera => "camera",
            Self::Phone => "phone",
            Self::Hypervisor => "hypervisor",
            Self::Storage => "storage",
            Self::Workstation => "workstation",
            Self::Server => "server",
            Self::Unknown => "unknown",
        }
    }
}

/// How much it would take for this to be wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Nothing suggested anything.
    Unknown,
    /// One weak signal. A hostname alone never gets past here: `ap-lobby` is a decent hint
    /// and is also what somebody calls the laptop they carry to the lobby.
    Possible,
    /// A strong signal, or two independent weak ones that agree.
    Likely,
}

/// One thing that pointed at the answer, in words an operator can argue with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    /// `mac`, `hostname`, `sys_descr` or `ttl` — which input spoke.
    pub from: &'static str,
    /// What it said, quoted back so the reader can check it.
    pub saying: String,
}

/// An opinion, with its evidence attached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Guess {
    pub role: Role,
    pub confidence: Confidence,
    /// Empty only when the role is [`Role::Unknown`].
    pub because: Vec<Reason>,
    /// The manufacturer, when the MAC gave one. Worth showing even when the role is
    /// unknown — an inventory that says "Cisco" beats one that says nothing.
    pub vendor: Option<&'static str>,
}

impl Guess {
    /// Nothing is known.
    #[must_use]
    pub fn nothing() -> Self {
        Self {
            role: Role::Unknown,
            confidence: Confidence::Unknown,
            because: Vec::new(),
            vendor: None,
        }
    }

    /// Whether this is worth showing to somebody.
    #[must_use]
    pub fn worth_showing(&self) -> bool {
        self.role != Role::Unknown || self.vendor.is_some()
    }
}

/// Vendors whose whole business is one kind of device.
///
/// `docs/what-is-this-thing.md` §3.5: deliberately short, and deliberately not exhaustive.
/// A vendor that makes five kinds of thing tells you nothing about which one this is, and
/// listing it anyway is how a guess becomes noise. Matched case-insensitively on a prefix
/// of the IEEE organisation name, because IEEE records them with suffixes like ", Inc."
/// that vary by registration.
const VENDOR_ROLES: &[(&str, Role)] = &[
    ("zebra", Role::Printer),
    ("lexmark", Role::Printer),
    ("kyocera", Role::Printer),
    ("ricoh", Role::Printer),
    ("brother", Role::Printer),
    ("axis communications", Role::Camera),
    ("hikvision", Role::Camera),
    ("dahua", Role::Camera),
    ("mobotix", Role::Camera),
    ("polycom", Role::Phone),
    ("yealink", Role::Phone),
    ("grandstream", Role::Phone),
    ("snom", Role::Phone),
    ("ubiquiti", Role::AccessPoint),
    ("aruba", Role::AccessPoint),
    ("ruckus", Role::AccessPoint),
    ("mist systems", Role::AccessPoint),
    ("fortinet", Role::Firewall),
    ("palo alto", Role::Firewall),
    ("sonicwall", Role::Firewall),
    ("watchguard", Role::Firewall),
    ("mikrotik", Role::Router),
    ("netgate", Role::Firewall),
    ("synology", Role::Storage),
    ("qnap", Role::Storage),
    ("netapp", Role::Storage),
];

/// Hostname fragments that conventionally mean something.
///
/// Weak by construction — these are naming habits, not facts — so a match here alone never
/// exceeds [`Confidence::Possible`].
const HOSTNAME_HINTS: &[(&str, Role)] = &[
    ("printer", Role::Printer),
    ("print", Role::Printer),
    ("mfp", Role::Printer),
    ("cam", Role::Camera),
    ("nvr", Role::Camera),
    ("phone", Role::Phone),
    ("voip", Role::Phone),
    ("sip", Role::Phone),
    ("ap-", Role::AccessPoint),
    ("wap", Role::AccessPoint),
    ("wifi", Role::AccessPoint),
    ("fw-", Role::Firewall),
    ("fw0", Role::Firewall),
    ("asa", Role::Firewall),
    ("rtr", Role::Router),
    ("router", Role::Router),
    ("gw-", Role::Router),
    ("sw-", Role::Switch),
    ("switch", Role::Switch),
    ("esx", Role::Hypervisor),
    ("vmware", Role::Hypervisor),
    ("proxmox", Role::Hypervisor),
    ("hyperv", Role::Hypervisor),
    ("nas", Role::Storage),
    ("san", Role::Storage),
];

/// What a `sysDescr` says about itself.
///
/// The strongest signal available here, because a device that bothers to answer `sysDescr`
/// usually names its own software. Ordered most specific first: "adaptive security
/// appliance" must win before "cisco ios" would.
const DESCR_HINTS: &[(&str, Role)] = &[
    ("adaptive security appliance", Role::Firewall),
    ("fortigate", Role::Firewall),
    ("pan-os", Role::Firewall),
    ("pfsense", Role::Firewall),
    ("opnsense", Role::Firewall),
    ("access point", Role::AccessPoint),
    ("wireless lan controller", Role::AccessPoint),
    ("jetdirect", Role::Printer),
    ("laserjet", Role::Printer),
    ("printer", Role::Printer),
    ("network camera", Role::Camera),
    ("ip camera", Role::Camera),
    ("vmware esxi", Role::Hypervisor),
    ("proxmox", Role::Hypervisor),
    ("ios-xe", Role::Router),
    ("ios xr", Role::Router),
    ("junos", Role::Router),
    ("routeros", Role::Router),
    ("switch", Role::Switch),
    ("windows", Role::Workstation),
    ("linux", Role::Server),
];

/// The TTL a packet started with, inferred from what arrived.
///
/// Initial TTL is 64 on Linux and most embedded stacks, 128 on Windows, 255 on a lot of
/// network equipment. The observed value is that minus the hops it crossed, so rounding up
/// to the next of those three recovers the family — and the difference is the hop count.
///
/// Returns `None` above 255 or at zero, neither of which a real packet produces.
#[must_use]
pub fn initial_ttl(observed: u8) -> Option<(u8, u8)> {
    for start in [64u8, 128, 255] {
        if observed <= start {
            return Some((start, start - observed));
        }
    }
    None
}

fn vendor_role(vendor: &str) -> Option<Role> {
    let lower = vendor.to_ascii_lowercase();
    VENDOR_ROLES
        .iter()
        .find(|(name, _)| lower.starts_with(name))
        .map(|(_, role)| *role)
}

fn hostname_role(hostname: &str) -> Option<(Role, &'static str)> {
    let lower = hostname.to_ascii_lowercase();
    HOSTNAME_HINTS
        .iter()
        .find(|(frag, _)| lower.contains(frag))
        .map(|(frag, role)| (*role, *frag))
}

fn descr_role(descr: &str) -> Option<(Role, &'static str)> {
    let lower = descr.to_ascii_lowercase();
    DESCR_HINTS
        .iter()
        .find(|(frag, _)| lower.contains(frag))
        .map(|(frag, role)| (*role, *frag))
}

/// What this probably is.
///
/// Never errors and never panics: every input is optional and every unknown is
/// [`Role::Unknown`], because the caller is a screen listing addresses and a failure there
/// would be a blank cell with no explanation.
#[must_use]
pub fn guess(evidence: &Evidence<'_>) -> Guess {
    let mut because = Vec::new();
    let vendor = evidence.mac.and_then(uops_oui::vendor_of);

    // Strong: the device described itself.
    let from_descr = evidence.sys_descr.and_then(descr_role);
    // Good: the manufacturer only makes one kind of thing.
    let from_vendor = vendor.and_then(vendor_role);
    // Weak: somebody's naming convention.
    let from_hostname = evidence.hostname.and_then(hostname_role);

    if let Some((_, matched)) = from_descr {
        because.push(Reason {
            from: "sys_descr",
            saying: format!("it describes itself as {matched}"),
        });
    }
    if let (Some(name), Some(_)) = (vendor, from_vendor) {
        because.push(Reason {
            from: "mac",
            saying: format!("the MAC is assigned to {name}"),
        });
    }
    if let Some((_, matched)) = from_hostname {
        because.push(Reason {
            from: "hostname",
            saying: format!("the hostname contains \"{matched}\""),
        });
    }
    if let Some((start, hops)) = evidence.ttl.and_then(initial_ttl) {
        because.push(Reason {
            from: "ttl",
            saying: format!("it replied with a TTL {hops} below {start}"),
        });
    }

    // A description beats everything, because it is the device's own account of itself.
    // Otherwise vendor and hostname vote, and agreement is what raises confidence.
    let (role, confidence) = match (from_descr, from_vendor, from_hostname) {
        (Some((role, _)), _, _) => (role, Confidence::Likely),
        (None, Some(v), Some((h, _))) if v == h => (v, Confidence::Likely),
        // They disagree. The vendor is the harder fact — a MAC block is assigned, a
        // hostname is typed — so it wins, but only as a hunch, and both reasons are
        // already attached for the reader to judge.
        (None, Some(v), Some(_)) => (v, Confidence::Possible),
        (None, Some(v), None) => (v, Confidence::Likely),
        (None, None, Some((h, _))) => (h, Confidence::Possible),
        (None, None, None) => (Role::Unknown, Confidence::Unknown),
    };

    // A vendor with no role still earns its line: "Cisco" is worth more than nothing.
    if role == Role::Unknown && because.is_empty() && let Some(name) = vendor {
        because.push(Reason {
            from: "mac",
            saying: format!("the MAC is assigned to {name}"),
        });
    }

    Guess {
        role,
        confidence,
        because,
        vendor,
    }
}
