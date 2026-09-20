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

pub mod ipfix;
pub mod templates;
pub mod v5;
pub mod v9;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// Recover an absolute instant from a device uptime.
///
/// `NetFlow` v5 and v9 both date a flow by *uptime*: milliseconds since the exporter
/// booted. The header carries the wall clock and the uptime at the moment of export, so
/// the flow ended at `exported_at - (header_uptime - uptime)`.
///
/// # The wrap is real
///
/// Uptime is milliseconds in a `u32`, which runs out after **49.7 days** and wraps to
/// zero. A device up for longer reports a record uptime *greater* than the header's for
/// any flow that began before the wrap, and a signed subtraction lands that flow weeks in
/// the future. The row is then outside every query window, so the symptom is not a wrong
/// timestamp on a screen — it is traffic that silently vanishes.
///
/// `wrapping_sub` is the fix and it is not a trick: the two values are samples of the
/// same wrapping counter, so their difference in the ring is the elapsed time whenever
/// that is under 49.7 days — which it always is, because a flow does not last seven
/// weeks. It is the same reasoning `uops-poll` applies to a decreasing SNMP counter.
#[must_use]
pub fn absolute(
    exported_at: DateTime<Utc>,
    header_uptime_ms: u32,
    uptime_ms: u32,
) -> DateTime<Utc> {
    let ago = header_uptime_ms.wrapping_sub(uptime_ms);
    exported_at - chrono::Duration::milliseconds(i64::from(ago))
}

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

/// A numeric field of whatever width the template declared.
///
/// Shared by `v9` and `ipfix`, which both let the exporter choose a field's width.
///
/// RFC 3954 lets an exporter choose the width of a numeric field — `IN_BYTES` is
/// commonly 4 bytes and legitimately 8 — so nothing here may assume a size. Widths above
/// 8 take the low-order 8 bytes, which is what a big-endian value zero-padded on the left
/// means; a field wider than that carrying a number this decoder understands does not
/// occur, and guessing is better than refusing the whole record over it.
pub(crate) fn truncating(slice: &[u8]) -> u64 {
    let take = slice.len().min(8);
    let start = slice.len() - take;
    let mut value = 0u64;
    for &b in &slice[start..] {
        value = (value << 8) | u64::from(b);
    }
    value
}

/// The same value, narrowed to the width the field actually means.
///
/// A template may declare a port four bytes wide, and some do; the value in it is still a
/// port. Keeping the low-order bits is what a big-endian number zero-padded on the left
/// means, so this is the reading rather than a lossy shortcut — and it is named, because
/// a bare `as` at each of these call sites says nothing about which of the two it is.
pub(crate) fn narrow32(slice: &[u8]) -> u32 {
    u32::try_from(truncating(slice) & u64::from(u32::MAX)).unwrap_or(u32::MAX)
}

pub(crate) fn narrow16(slice: &[u8]) -> u16 {
    u16::try_from(truncating(slice) & u64::from(u16::MAX)).unwrap_or(u16::MAX)
}

pub(crate) fn narrow8(slice: &[u8]) -> u8 {
    u8::try_from(truncating(slice) & u64::from(u8::MAX)).unwrap_or(u8::MAX)
}

pub(crate) fn ipv4(slice: &[u8]) -> Option<IpAddr> {
    let octets: [u8; 4] = slice.try_into().ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(octets)))
}

pub(crate) fn ipv6(slice: &[u8]) -> Option<IpAddr> {
    let octets: [u8; 16] = slice.try_into().ok()?;
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}
