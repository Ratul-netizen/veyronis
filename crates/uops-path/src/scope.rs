//! Where a hop sits, in four kinds — `docs/traceroute.md` §4.
//!
//! # Why four and not two
//!
//! The obvious split is inside/outside, and it is wrong in a way that matters. The first
//! real trace taken while building this crossed `10.153.77.1` and then `100.64.170.170`.
//! A two-way split calls the second one "outside" and implies it is on the internet. It is
//! not — `100.64.0.0/10` is RFC 6598 carrier-grade NAT, the *ISP's* own space.
//!
//! An operator chasing a path needs to know where their responsibility ends, and that
//! boundary is exactly where CGNAT begins: the last hop they can do anything about is the
//! one before it.
//!
//! # And why a private hop never gets a location
//!
//! There is no geographic place called `10.0.0.1`. Geolocation is not built here at all,
//! and this rule is written down now so that when it is built the rule is already the
//! product's rather than something remembered late.

use serde::{Deserialize, Serialize};

/// What kind of address a hop is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// RFC 1918. Inside the estate.
    Private,
    /// RFC 6598 `100.64.0.0/10`. The carrier's own space — outside the estate and **not**
    /// the public internet.
    CarrierGrade,
    /// RFC 3927 `169.254.0.0/16`. A link nobody assigned an address on.
    LinkLocal,
    /// `127.0.0.0/8`.
    Loopback,
    /// Everything else.
    Public,
    /// Nothing answered, so there is no address to place.
    Unknown,
}

impl Scope {
    /// Whether a hop of this kind could ever have a geographic location.
    ///
    /// The guard for a map that does not exist yet. `docs/traceroute.md` §4.
    #[must_use]
    pub const fn is_locatable(self) -> bool {
        matches!(self, Self::Public)
    }

    /// Whether this address is outside the globally routable internet.
    ///
    /// **Not the same as "yours", and the difference was found in real output.** The first
    /// public trace from this machine crossed `10.153.77.1` and `10.20.251.97` before
    /// reaching carrier-grade space — both RFC 1918, and both the *ISP's*, not the
    /// estate's. An earlier version of this method was called `is_inside` and documented
    /// as "inside the estate's own responsibility", which would have labelled two of the
    /// provider's routers as the operator's to fix.
    ///
    /// The product cannot tell whose a private address is, so it does not claim to. What
    /// it can say is that the address is not on the public internet, and that is all this
    /// says.
    #[must_use]
    pub const fn is_not_public(self) -> bool {
        matches!(self, Self::Private | Self::Loopback | Self::LinkLocal)
    }

    /// What to call it on a screen.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::CarrierGrade => "carrier",
            Self::LinkLocal => "link-local",
            Self::Loopback => "loopback",
            Self::Public => "public",
            Self::Unknown => "no reply",
        }
    }
}

/// Which scope an address falls in.
///
/// Anything unparseable is [`Scope::Unknown`] rather than an error: the caller is
/// classifying whatever a traceroute printed, and a line that is not an address is a line
/// the parser should already have dropped.
#[must_use]
pub fn scope_of(address: &str) -> Scope {
    let Ok(parsed) = address.trim().parse::<std::net::Ipv4Addr>() else {
        return Scope::Unknown;
    };
    let [a, b, ..] = parsed.octets();
    match (a, b) {
        (127, _) => Scope::Loopback,
        // The three RFC 1918 blocks, written as one arm because they mean one thing. The
        // 172 range is 16..=31 and the mistake people make is 172.16 alone; the 192.168
        // one needs both octets.
        (10, _) | (172, 16..=31) | (192, 168) => Scope::Private,
        (169, 254) => Scope::LinkLocal,
        // RFC 6598: 100.64.0.0/10 — the second octet runs 64 to 127, which is the half of
        // this rule that is easy to write as `100.64` and get wrong for three quarters of
        // the range.
        (100, 64..=127) => Scope::CarrierGrade,
        _ => Scope::Public,
    }
}
