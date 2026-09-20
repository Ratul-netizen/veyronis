//! Flow decoding — M7, specified in `docs/M7-flow.md`.
//!
//! Four wire formats, one [`Flow`]:
//!
//! ```text
//!   NetFlow v5   fixed 48-byte records, no templates          v5
//!   NetFlow v9   templates (RFC 3954)                         - next
//!   IPFIX        templates, variable-length fields (RFC 7011) - next
//!   sFlow v5     sampled packet headers                       - next
//! ```
//!
//! # No I/O, on purpose
//!
//! Bytes in, [`Flow`]s out. There is no socket in this crate, no store, and no tenant —
//! those belong to `uops-collector-flow`, the same way `uops-syslog` parses and
//! `uops-collector-syslog` listens.
//!
//! That split is not tidiness. This is four binary parsers reading attacker-reachable
//! input off an unauthenticated UDP port, and every one of them takes a length from the
//! packet and uses it to slice a buffer. A parser that needs a socket to run is a parser
//! nobody fuzzes and nobody tests exhaustively; this one is exercised from a byte array.
//!
//! # A malformed packet is one lost packet
//!
//! Every entry point returns [`Result`], and the receive loop above is expected to count
//! the error and carry on. A panic here would be a denial of service against a port
//! anything on the network can reach — so nothing in this crate indexes a slice without
//! checking, and the workspace forbids `unsafe`, so the failure mode of a length this
//! code got wrong is a caught error rather than a read out of bounds.

pub mod v5;

use std::net::IpAddr;

use chrono::{DateTime, Utc};

/// One flow record, as the wire described it.
///
/// Protocol-independent: a v5 record, a v9 data record and an sFlow sample all arrive
/// here, so everything above this crate is written once. Fields a given protocol does
/// not carry are `None` rather than zero — `0` is a legitimate AS number and a
/// legitimate `ifIndex`, and a product that cannot tell "not reported" from "reported as
/// zero" will eventually draw a graph of the difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    /// When the flow *ended*, absolute.
    ///
    /// The end rather than the start, because that is the instant the exporter decided
    /// the flow was over and is the one every other signal in this product is aligned
    /// to — `observed_at` means "when the thing being described happened", not "when we
    /// heard about it". See [`v5::when`] for how it is recovered from device uptime.
    pub observed_at: DateTime<Utc>,
    /// When the flow started, absolute. `observed_at - started_at` is its duration.
    pub started_at: DateTime<Utc>,

    pub src_address: IpAddr,
    pub dst_address: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// IANA protocol number. 6 is TCP, 17 UDP, 1 ICMP.
    pub protocol: u8,

    /// Bytes and packets **as observed**, never scaled by [`Flow::sampling_rate`].
    ///
    /// §2.4 of the spec, and the reason is worth repeating where the field is: scaling
    /// here cannot be undone, so the count of packets actually seen — the thing that
    /// says how much to trust the estimate — would be gone. It also turns an
    /// extrapolation into something indistinguishable from a measurement, and every
    /// screen downstream would present it as one.
    pub bytes: u64,
    pub packets: u64,

    /// One in how many packets was sampled. `1` means no sampling.
    ///
    /// Never zero: a rate of zero would make the obvious query — `bytes * sampling_rate`
    /// — silently return nothing at all rather than fail, which is the worst way for a
    /// bad exporter to be wrong.
    pub sampling_rate: u32,

    /// Union of the TCP flags seen across the flow. Meaningless unless `protocol == 6`.
    pub tcp_flags: u8,
    /// IP type of service.
    pub tos: u8,

    /// `ifIndex` of the interface the traffic arrived on and left by, as the exporter
    /// numbers them — which is the same numbering SNMP uses, so these join to interfaces
    /// this product already discovered.
    pub input_if: Option<u32>,
    pub output_if: Option<u32>,

    /// Autonomous system numbers, when the exporter has a BGP table to know them.
    pub src_as: Option<u32>,
    pub dst_as: Option<u32>,
}

/// Why a packet could not be decoded.
///
/// Every variant names what was expected and what was there, because these are read off
/// a counter by somebody asking why one exporter's flow is missing — and "malformed
/// packet" on its own has never helped anybody.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("a flow packet is at least {need} bytes; this one is {got}")]
    TooShort { need: usize, got: usize },

    #[error("version {got} is not one this collector decodes")]
    UnknownVersion { got: u16 },

    /// The header's record count does not match the bytes present.
    ///
    /// Its own variant rather than a `TooShort`, because this is the shape a hostile
    /// packet takes: a small datagram claiming to hold thousands of records, hoping the
    /// reader allocates or indexes on the claim rather than on what arrived.
    #[error("the header claims {claimed} records, which needs {need} bytes; {got} arrived")]
    CountExceedsPacket {
        claimed: usize,
        need: usize,
        got: usize,
    },

    #[error("{what} is not a value this decoder can use: {why}")]
    Invalid {
        what: &'static str,
        why: &'static str,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Read a big-endian `u16` at `at`, or say the packet was too short.
///
/// Flow protocols are big-endian throughout. These three helpers exist so that no parser
/// in this crate ever writes `buf[at]` directly — which is the line that becomes a panic
/// on a packet somebody sent on purpose.
pub(crate) fn be16(buf: &[u8], at: usize) -> Result<u16> {
    let end = at.checked_add(2).ok_or(Error::TooShort {
        need: usize::MAX,
        got: buf.len(),
    })?;
    let slice = buf.get(at..end).ok_or(Error::TooShort {
        need: end,
        got: buf.len(),
    })?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

pub(crate) fn be32(buf: &[u8], at: usize) -> Result<u32> {
    let end = at.checked_add(4).ok_or(Error::TooShort {
        need: usize::MAX,
        got: buf.len(),
    })?;
    let slice = buf.get(at..end).ok_or(Error::TooShort {
        need: end,
        got: buf.len(),
    })?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub(crate) fn u8_at(buf: &[u8], at: usize) -> Result<u8> {
    buf.get(at).copied().ok_or(Error::TooShort {
        need: at + 1,
        got: buf.len(),
    })
}
