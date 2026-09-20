//! `NetFlow` v5 — fixed records, no templates.
//!
//! ```text
//!   ┌── header, 24 bytes ──────────────────────────────────────────┐
//!   │ version=5 │ count │ sys_uptime │ unix_secs │ unix_nsecs │ …  │
//!   └──────────────────────────────────────────────────────────────┘
//!   ┌── record, 48 bytes ──┐ ┌── record ──┐ …  up to 30 of them
//!   │ src │ dst │ bytes │… │ │            │
//!   └──────────────────────┘ └────────────┘
//! ```
//!
//! Cisco's original, from 1996, and still what a great deal of installed equipment
//! emits. IPv4 only, no templates, everything at a fixed offset — which is why it is
//! first: it exercises the whole path through the collector with none of v9's template
//! machinery, so when a v9 flow comes out wrong, v5 passing is what says the fault is in
//! the templates rather than everywhere else.
//!
//! # The timestamps are the hard part, and they are the only hard part
//!
//! A record does not carry a time. It carries two *uptimes* — milliseconds since the
//! exporter booted, at the moment the flow started and ended. The header carries the
//! wall clock and the uptime at the moment of export, and the absolute time is recovered
//! by subtraction. [`when`] does that, and its documentation is where the wrap is dealt
//! with.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, TimeZone, Utc};

use crate::{Error, Flow, Result, be16, be32, u8_at};

/// Bytes before the first record.
const HEADER: usize = 24;

/// Bytes per record. Fixed, which is the whole point of v5.
const RECORD: usize = 48;

/// The most records one v5 datagram may describe.
///
/// The protocol's own limit: 30 records is 1464 bytes of payload, which with headers is
/// the largest thing that fits in a 1500-byte Ethernet MTU without fragmenting. An
/// exporter claiming more is either broken or lying, and both are refused — but the
/// refusal that matters is the one against the *bytes present*, in [`decode`], because a
/// count within this limit can still exceed a short datagram.
const MAX_RECORDS: usize = 30;

/// What the header said, beyond the records.
///
/// Kept because the collector needs it: `sequence` is how a gap is detected — flow lost
/// between the exporter and here is invisible otherwise, since a missing flow looks
/// exactly like an idle network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub count: usize,
    pub sequence: u32,
    /// `engine_type` and `engine_id`, which together identify the forwarding engine
    /// within one chassis. Two engines on one exporter have independent sequences.
    pub engine: (u8, u8),
    pub sampling_rate: u32,
    pub exported_at: DateTime<Utc>,
    pub uptime_ms: u32,
}

/// Decode one datagram.
///
/// # Errors
///
/// When the packet is shorter than a header, is not version 5, or claims more records
/// than arrived. A record that is present is always decodable — every field is fixed
/// width — so there is no partial success to report.
pub fn decode(packet: &[u8]) -> Result<(Header, Vec<Flow>)> {
    if packet.len() < HEADER {
        return Err(Error::TooShort {
            need: HEADER,
            got: packet.len(),
        });
    }

    let version = be16(packet, 0)?;
    if version != 5 {
        return Err(Error::UnknownVersion { got: version });
    }

    let count = be16(packet, 2)? as usize;
    if count > MAX_RECORDS {
        return Err(Error::Invalid {
            what: "the record count",
            why: "a v5 datagram carries at most 30 records",
        });
    }

    // Against the bytes that arrived, not against the protocol's limit. This is the
    // check that matters: a 24-byte datagram claiming 30 records passes every sanity
    // rule about v5 and would, without this, have the reader walk 1440 bytes past the
    // end of the buffer.
    let need = HEADER + count * RECORD;
    if packet.len() < need {
        return Err(Error::CountExceedsPacket {
            claimed: count,
            need,
            got: packet.len(),
        });
    }

    let uptime_ms = be32(packet, 4)?;
    let secs = be32(packet, 8)?;
    let nanos = be32(packet, 12)?;
    let sequence = be32(packet, 16)?;
    let engine = (u8_at(packet, 20)?, u8_at(packet, 21)?);
    let sampling_rate = sampling(be16(packet, 22)?);

    let exported_at = Utc
        .timestamp_opt(i64::from(secs), nanos)
        .single()
        .ok_or(Error::Invalid {
            what: "the export timestamp",
            why: "it is not a representable instant",
        })?;

    let header = Header {
        count,
        sequence,
        engine,
        sampling_rate,
        exported_at,
        uptime_ms,
    };

    let mut flows = Vec::with_capacity(count);
    for n in 0..count {
        let at = HEADER + n * RECORD;
        flows.push(record(packet, at, &header)?);
    }

    Ok((header, flows))
}

/// One 48-byte record.
fn record(packet: &[u8], at: usize, header: &Header) -> Result<Flow> {
    let first_uptime = be32(packet, at + 24)?;
    let last_uptime = be32(packet, at + 28)?;

    Ok(Flow {
        observed_at: when(header, last_uptime),
        started_at: when(header, first_uptime),

        src_address: IpAddr::V4(Ipv4Addr::from(be32(packet, at)?)),
        dst_address: IpAddr::V4(Ipv4Addr::from(be32(packet, at + 4)?)),
        src_port: be16(packet, at + 32)?,
        dst_port: be16(packet, at + 34)?,
        protocol: u8_at(packet, at + 38)?,

        // u32 on the wire, u64 in the record: a v9 or IPFIX exporter reports 64-bit
        // counters, and one type above this crate beats two.
        packets: u64::from(be32(packet, at + 16)?),
        bytes: u64::from(be32(packet, at + 20)?),

        // Per datagram in v5, not per record. It is copied onto every flow anyway,
        // because a consumer must never have to go and find it: a byte count whose
        // sampling rate lives somewhere else is a byte count somebody will use without
        // it.
        sampling_rate: header.sampling_rate,

        // Offset 36 is a pad byte. Reading it as a flag is a classic v5 mistake and
        // produces tcp_flags that are always zero.
        tcp_flags: u8_at(packet, at + 37)?,
        tos: u8_at(packet, at + 39)?,

        input_if: Some(u32::from(be16(packet, at + 12)?)),
        output_if: Some(u32::from(be16(packet, at + 14)?)),

        src_as: Some(u32::from(be16(packet, at + 40)?)),
        dst_as: Some(u32::from(be16(packet, at + 42)?)),
    })
}

/// The sampling rate a v5 header describes.
///
/// The field is two things in sixteen bits: the top two are the mode, the low fourteen
/// the interval. Mode 0 is "not sampling", and in that mode the interval is not
/// meaningful — some exporters leave rubbish there, so reading the whole field as a rate
/// scales a fully-observed flow by whatever happened to be in those bits.
///
/// Returns 1 rather than 0 for "no sampling", and clamps a claimed interval of 0 up to
/// 1, because every consumer multiplies by this: a zero would silently turn every byte
/// count into nothing.
fn sampling(field: u16) -> u32 {
    let mode = field >> 14;
    if mode == 0 {
        return 1;
    }
    u32::from(field & 0x3fff).max(1)
}

/// Recover an absolute instant from this datagram's uptime base.
///
/// A record says "this flow ended 4 261 003 ms after the device booted"; the header says
/// what the clock read at export and how long the device had been up. The arithmetic,
/// and the 49.7-day wrap it has to survive, is [`crate::absolute`].
#[must_use]
pub fn when(header: &Header, uptime_ms: u32) -> DateTime<Utc> {
    crate::absolute(header.exported_at, header.uptime_ms, uptime_ms)
}
