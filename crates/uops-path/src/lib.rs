//! Where the traffic goes, and where it stops going — `docs/traceroute.md`.
//!
//! The product knows *adjacency* — `connected_to` edges from LLDP — and not *path*. When
//! an operator asks why they cannot reach something, adjacency has no answer.
//!
//! # The probe is the operating system's own traceroute
//!
//! `docs/traceroute.md` §2, and it is M10 §2.10's decision about `ssh(1)` applied to the
//! same shape of problem. Raw sockets are the correct way and need privileges this product
//! deliberately does not take; the crates that wrap them need the same. `tracert` and
//! `traceroute` are present, unprivileged, and already trusted by everyone who has debugged
//! a path.
//!
//! What that costs is parsing another program's prose, which changes with version and
//! locale. So the parser is pure, it is tested against real captured output, and **a line
//! it does not understand is skipped rather than guessed at** — a hop invented from a
//! misparsed line puts an address on a path it was never on, which is worse than a gap.
//! The raw output is returned alongside, so a reader can always check what was really said.

pub mod parse;
pub mod probe;
pub mod scope;

pub use parse::{parse_unix, parse_windows};
pub use probe::{MAX_HOPS, Trace, trace};
pub use scope::{Scope, scope_of};

use serde::{Deserialize, Serialize};

/// One step along the path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    /// Distance from here, starting at 1.
    pub number: u8,
    /// Who answered, when anything did.
    ///
    /// `None` is an ordinary result, not an error: a router that does not answer
    /// `ttl-exceeded` is silent by policy, and the path continues past it.
    pub address: Option<String>,
    /// Round trips in milliseconds, one per probe, `None` for each that timed out.
    ///
    /// Kept as a list rather than averaged: one slow probe out of three is a different
    /// finding from three evenly slow ones, and an average hides which it was.
    pub rtt_ms: Vec<Option<f64>>,
    /// Where this hop sits — see [`Scope`].
    pub scope: Scope,
}

impl Hop {
    /// Whether anything answered at this distance.
    #[must_use]
    pub fn answered(&self) -> bool {
        self.address.is_some()
    }

    /// The probes that came back, as a fraction. `None` when nothing was sent.
    #[must_use]
    pub fn loss(&self) -> Option<f64> {
        if self.rtt_ms.is_empty() {
            return None;
        }
        let lost = self.rtt_ms.iter().filter(|r| r.is_none()).count();
        #[allow(clippy::cast_precision_loss, reason = "three probes, not three billion")]
        Some(lost as f64 / self.rtt_ms.len() as f64)
    }

    /// The best round trip seen, which is the one least polluted by queueing.
    #[must_use]
    pub fn best_ms(&self) -> Option<f64> {
        self.rtt_ms
            .iter()
            .flatten()
            .copied()
            .fold(None, |best: Option<f64>, rtt| {
                Some(best.map_or(rtt, |b| b.min(rtt)))
            })
    }
}
