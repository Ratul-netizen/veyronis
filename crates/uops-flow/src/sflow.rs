//! sFlow v5 — sampled packets, not summarised flows.
//!
//! ```text
//!   ┌── datagram header ─────────────────────────────────────────────┐
//!   │ version=5 │ agent address │ sub-agent │ sequence │ uptime │ n  │
//!   └────────────────────────────────────────────────────────────────┘
//!   ┌── sample ────────────────────────────────────────────────────┐
//!   │ format │ length │ … │ sampling_rate │ … │ records…           │
//!   └──────────────────────────────────────────────────────────────┘
//!                                            ┌── raw packet header ─┐
//!                                            │ proto │ frame_length │
//!                                            │ stripped │ header_len│
//!                                            │ the first N bytes of │
//!                                            │ an actual frame      │
//!                                            └──────────────────────┘
//!
//!   Ethernet ─▸ [VLAN…] ─▸ IPv4/IPv6 ─▸ TCP/UDP
//! ```
//!
//! `NetFlow` and IPFIX send a router's *summary* of a conversation. sFlow sends the first
//! hundred-odd bytes of one packet in every N, and leaves the reading to the collector —
//! so this module is a packet parser where the other two are record parsers, and it is
//! the only one that has to know what Ethernet looks like.
//!
//! There are no templates, so nothing is remembered between datagrams and
//! [`crate::templates::Learned`] is not involved.
//!
//! # Sampling is structural here, and §2.4 finally has an easy case
//!
//! Every flow sample carries its own `sampling_rate` in a fixed position. There is no
//! options record to miss and no exporter that forgets to mention it, so an sFlow flow's
//! rate is never assumed — which is the opposite of v9, where it is the hard part.
//!
//! # `bytes` is the frame's real length, not the captured length
//!
//! The record carries both: `frame_length` is how big the packet actually was, and
//! `header_length` is how much of it was copied into the datagram — typically 128 bytes.
//! Reporting the captured length would under-report a full-size packet by a factor of
//! ten, on top of the sampling factor, and both errors point the same way. `packets` is
//! 1, because one packet is what was seen; multiplying by the rate is the reader's job,
//! exactly as in §2.4.
//!
//! # There is no clock in an sFlow datagram
//!
//! Not a wall clock anywhere — the header's `uptime` is the agent's, with no epoch to
//! anchor it. So the caller supplies `received_at` and every flow is dated at it. That is
//! honest rather than convenient: the sample describes a packet seen a few milliseconds
//! before it was sent, and the receipt time is the best statement available.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};

use crate::{Error, Flow, Result, be16, be32};

/// Bytes before the agent address.
const MIN_HEADER: usize = 8;

/// Sample formats, from the standard's enterprise 0.
const FLOW_SAMPLE: u32 = 1;
const COUNTER_SAMPLE: u32 = 2;
const FLOW_SAMPLE_EXPANDED: u32 = 3;
const COUNTER_SAMPLE_EXPANDED: u32 = 4;

/// Flow record formats.
const RAW_PACKET_HEADER: u32 = 1;

/// `header_protocol` 1 is Ethernet. The others — token ring, FDDI — are not parsed.
const HEADER_PROTO_ETHERNET: u32 = 1;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// How deep a stack of VLAN tags will be followed.
///
/// Q-in-Q is two; three is seen in carrier networks. A bound is needed at all because the
/// tags are in attacker-controlled bytes and each one says "another header follows".
const MAX_VLAN_TAGS: usize = 3;

/// The most samples one datagram may claim.
///
/// The count is a `u32` the sender chose, and `Vec::with_capacity` on it would allocate
/// four gigabytes on request. Nothing is allocated from the claim — the loop stops when
/// the bytes run out — but the claim is also refused outright well before that, because
/// an sFlow datagram holding more than this is not a real one.
const MAX_SAMPLES: u32 = 256;

/// The most flow records one sample may claim, for the same reason.
const MAX_RECORDS: u32 = 64;

/// What the datagram header said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The agent's own address, which is not necessarily the address it sent from.
    ///
    /// Kept because it is the better identity: a switch with several interfaces answers
    /// from whichever one routing chose, and the agent address is the stable one.
    pub agent: IpAddr,
    pub sub_agent: u32,
    pub sequence: u32,
    /// Milliseconds since the agent booted. No epoch, so it dates nothing.
    pub uptime_ms: u32,
    pub samples: u32,
}

/// One datagram's worth of results.
#[derive(Clone, Debug, Default)]
pub struct Decoded {
    pub flows: Vec<Flow>,
    /// Counter samples, which describe interfaces rather than traffic. Skipped here;
    /// they are what an SNMP poll already provides in this product.
    pub counter_samples: usize,
    /// Flow samples whose record this decoder cannot read — a non-Ethernet header
    /// protocol, or a frame that is not IP.
    pub unreadable: usize,
    /// Samples whose declared length did not fit the datagram.
    pub truncated: usize,
}

/// Decode one datagram.
///
/// `received_at` dates every flow in it, because an sFlow datagram carries no clock. See
/// the module documentation.
///
/// # Errors
///
/// When the datagram is too short, is not version 5, has an agent address type this
/// decoder does not know, or claims an implausible number of samples. A sample that
/// cannot be read is counted rather than fatal — one bad sample must not discard the
/// others beside it.
pub fn decode(packet: &[u8], received_at: DateTime<Utc>) -> Result<(Header, Decoded)> {
    if packet.len() < MIN_HEADER {
        return Err(Error::TooShort {
            need: MIN_HEADER,
            got: packet.len(),
        });
    }

    let version = be32(packet, 0)?;
    if version != 5 {
        return Err(Error::UnknownVersion {
            got: u16::try_from(version).unwrap_or(u16::MAX),
        });
    }

    // The address type decides the header's width, so it has to be read before anything
    // after it can be located.
    let (agent, mut at) = match be32(packet, 4)? {
        1 => (IpAddr::V4(Ipv4Addr::from(be32(packet, 8)?)), 12),
        2 => {
            let octets: [u8; 16] = packet
                .get(8..24)
                .ok_or(Error::TooShort {
                    need: 24,
                    got: packet.len(),
                })?
                .try_into()
                .map_err(|_| Error::Invalid {
                    what: "the agent address",
                    why: "it is not sixteen bytes",
                })?;
            (IpAddr::V6(Ipv6Addr::from(octets)), 24)
        }
        _ => {
            return Err(Error::Invalid {
                what: "the agent address type",
                why: "only IPv4 (1) and IPv6 (2) are defined",
            });
        }
    };

    let sub_agent = be32(packet, at)?;
    let sequence = be32(packet, at + 4)?;
    let uptime_ms = be32(packet, at + 8)?;
    let samples = be32(packet, at + 12)?;
    at += 16;

    if samples > MAX_SAMPLES {
        return Err(Error::Invalid {
            what: "the sample count",
            why: "an sFlow datagram does not carry this many samples",
        });
    }

    let header = Header {
        agent,
        sub_agent,
        sequence,
        uptime_ms,
        samples,
    };

    let mut out = Decoded::default();

    for _ in 0..samples {
        // Every sample says its own length, so a sample this decoder cannot read is
        // stepped over rather than ending the datagram.
        let Ok(format) = be32(packet, at) else { break };
        let Ok(length) = be32(packet, at + 4) else {
            break;
        };
        let Ok(length) = usize::try_from(length) else {
            break;
        };

        let body_at = at + 8;
        let Some(end) = body_at.checked_add(length) else {
            break;
        };
        if end > packet.len() {
            out.truncated += 1;
            break;
        }
        let body = &packet[body_at..end];

        // The low twelve bits are the format; the high twenty are an enterprise number,
        // and anything but 0 is a vendor extension this decoder does not know.
        let enterprise = format >> 12;
        match (enterprise, format & 0xfff) {
            (0, FLOW_SAMPLE) => read_flow_sample(body, false, received_at, &mut out),
            (0, FLOW_SAMPLE_EXPANDED) => read_flow_sample(body, true, received_at, &mut out),
            (0, COUNTER_SAMPLE | COUNTER_SAMPLE_EXPANDED) => out.counter_samples += 1,
            _ => out.unreadable += 1,
        }

        at = end;
    }

    Ok((header, out))
}

/// A flow sample, in either the compact or the expanded layout.
///
/// They differ only in that the expanded form splits two packed fields into two words
/// each — which moves everything after them by eight bytes. Reading one as the other puts
/// the sampling rate in the wrong place, and a plausible-looking wrong rate is the worst
/// kind: it scales every byte count in the sample.
fn read_flow_sample(body: &[u8], expanded: bool, received_at: DateTime<Utc>, out: &mut Decoded) {
    //                        compact                 expanded
    //   sequence             0                       0
    //   source id            4  (packed)             4, 8  (type, index)
    //   sampling rate        8                       12
    //   sample pool          12                      16
    //   drops                16                      20
    //   input                20 (packed)             24, 28
    //   output               24 (packed)             32, 36
    //   record count         28                      40
    let (rate_at, count_at, in_at, out_at) = if expanded {
        (12, 40, 24, 32)
    } else {
        (8, 28, 20, 24)
    };

    let (Ok(sampling_rate), Ok(records)) = (be32(body, rate_at), be32(body, count_at)) else {
        out.truncated += 1;
        return;
    };

    let input_if = interface(body, in_at, expanded);
    let output_if = interface(body, out_at, expanded);

    if records > MAX_RECORDS {
        out.unreadable += 1;
        return;
    }

    let mut at = count_at + 4;
    for _ in 0..records {
        let (Ok(format), Ok(length)) = (be32(body, at), be32(body, at + 4)) else {
            return;
        };
        let Ok(length) = usize::try_from(length) else {
            return;
        };

        let data_at = at + 8;
        let Some(end) = data_at.checked_add(length) else {
            return;
        };
        let Some(data) = body.get(data_at..end) else {
            out.truncated += 1;
            return;
        };

        if format >> 12 == 0 && format & 0xfff == RAW_PACKET_HEADER {
            let sample = Sample {
                sampling_rate: sampling_rate.max(1),
                input_if,
                output_if,
                received_at,
            };
            match raw_packet(data, &sample) {
                Some(flow) => out.flows.push(flow),
                None => out.unreadable += 1,
            }
        }

        at = end;
    }
}

/// The interface index at `at`, in whichever of the two layouts this sample uses.
///
/// The compact form packs a format into the top byte and the index into the low
/// twenty-four bits of one word; the expanded form gives each its own word. Reading the
/// compact form without masking yields an ifIndex in the millions, which joins to no
/// interface this product has ever discovered.
fn interface(body: &[u8], at: usize, expanded: bool) -> Option<u32> {
    if expanded {
        be32(body, at + 4).ok()
    } else {
        be32(body, at).ok().map(|v| v & 0x00ff_ffff)
    }
}

/// What the sample around a record already established.
struct Sample {
    sampling_rate: u32,
    input_if: Option<u32>,
    output_if: Option<u32>,
    received_at: DateTime<Utc>,
}

/// A raw packet header record: some of an actual frame, and how big it really was.
fn raw_packet(data: &[u8], sample: &Sample) -> Option<Flow> {
    let protocol = be32(data, 0).ok()?;
    let frame_length = be32(data, 4).ok()?;
    // `stripped` is how many bytes the agent removed — usually the FCS. Read so the
    // layout is right; nothing downstream needs it.
    let _stripped = be32(data, 8).ok()?;
    let header_length = be32(data, 12).ok()?;

    if protocol != HEADER_PROTO_ETHERNET {
        return None;
    }

    let header_length = usize::try_from(header_length).ok()?;
    // The declared header length is checked against what arrived, not trusted: this is
    // the same attacker-controlled length IPFIX's variable fields are, in a different
    // protocol.
    let frame = data.get(16..16 + header_length)?;

    let (src_address, dst_address, ip_protocol, tos, rest) = ethernet(frame)?;
    let (src_port, dst_port, tcp_flags) = ports(ip_protocol, rest);

    Some(Flow {
        observed_at: sample.received_at,
        started_at: sample.received_at,
        src_address,
        dst_address,
        src_port,
        dst_port,
        protocol: ip_protocol,
        // The frame's real length, not the captured slice — see the module docs. One
        // packet, because one packet is what was seen.
        bytes: u64::from(frame_length),
        packets: 1,
        sampling_rate: sample.sampling_rate,
        tcp_flags,
        tos,
        input_if: sample.input_if,
        output_if: sample.output_if,
        // sFlow carries no BGP table. A null here is "not reported", which is what the
        // Option on the field is for.
        src_as: None,
        dst_as: None,
    })
}

/// Ethernet, through any VLAN tags, to the IP header.
///
/// Returns the addresses, the IP protocol, the type of service and whatever follows the
/// IP header.
fn ethernet(frame: &[u8]) -> Option<(IpAddr, IpAddr, u8, u8, &[u8])> {
    // Two addresses and a type.
    let mut at = 12usize;
    let mut ethertype = be16(frame, at).ok()?;
    at += 2;

    // 802.1Q and Q-in-Q: four bytes each, the last two being the real type.
    for _ in 0..MAX_VLAN_TAGS {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        ethertype = be16(frame, at + 2).ok()?;
        at += 4;
    }

    match ethertype {
        ETHERTYPE_IPV4 => ipv4_header(frame.get(at..)?),
        ETHERTYPE_IPV6 => ipv6_header(frame.get(at..)?),
        _ => None,
    }
}

fn ipv4_header(buf: &[u8]) -> Option<(IpAddr, IpAddr, u8, u8, &[u8])> {
    let first = *buf.first()?;
    if first >> 4 != 4 {
        return None;
    }
    // The low nibble counts 32-bit words, and a header is at least five of them. A
    // smaller claim would have the reader step backwards into the header it just read.
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < 20 {
        return None;
    }

    let tos = *buf.get(1)?;
    let protocol = *buf.get(9)?;
    let src: [u8; 4] = buf.get(12..16)?.try_into().ok()?;
    let dst: [u8; 4] = buf.get(16..20)?.try_into().ok()?;

    // A truncated capture often ends inside the IP header, so the payload may be absent
    // without the frame being malformed.
    let rest = buf.get(header_len..).unwrap_or(&[]);
    Some((
        IpAddr::V4(Ipv4Addr::from(src)),
        IpAddr::V4(Ipv4Addr::from(dst)),
        protocol,
        tos,
        rest,
    ))
}

fn ipv6_header(buf: &[u8]) -> Option<(IpAddr, IpAddr, u8, u8, &[u8])> {
    let first = *buf.first()?;
    if first >> 4 != 6 {
        return None;
    }

    // Traffic class spans the low nibble of byte 0 and the high nibble of byte 1.
    let tos = (first << 4) | (*buf.get(1)? >> 4);
    let next_header = *buf.get(6)?;
    let src: [u8; 16] = buf.get(8..24)?.try_into().ok()?;
    let dst: [u8; 16] = buf.get(24..40)?.try_into().ok()?;

    // Extension headers are not walked. A packet carrying them reports its first next
    // header, which is what it is — and the ports are then not read rather than read from
    // the wrong offset, which is the failure that would matter.
    let rest = buf.get(40..).unwrap_or(&[]);
    Some((
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
        next_header,
        tos,
        rest,
    ))
}

/// Source port, destination port and TCP flags, when the protocol has them.
///
/// Zeroes when it does not, or when the capture ended before them — which is common, and
/// is why this returns values rather than an `Option`: a sampled ICMP packet is a real
/// flow with no ports, and so is a TCP packet whose header was cut off.
fn ports(protocol: u8, rest: &[u8]) -> (u16, u16, u8) {
    match protocol {
        IPPROTO_TCP => {
            let src = be16(rest, 0).unwrap_or(0);
            let dst = be16(rest, 2).unwrap_or(0);
            // Byte 13 holds the flags; the top two bits of byte 12 are reserved and the
            // data offset is its high nibble.
            let flags = rest.get(13).copied().unwrap_or(0);
            (src, dst, flags)
        }
        IPPROTO_UDP => (be16(rest, 0).unwrap_or(0), be16(rest, 2).unwrap_or(0), 0),
        _ => (0, 0, 0),
    }
}
