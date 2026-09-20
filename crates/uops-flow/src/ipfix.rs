//! IPFIX — RFC 7011, the standard `NetFlow` v9 became.
//!
//! ```text
//!   ┌── message header, 16 bytes ────────────────────────────────────┐
//!   │ version=10 │ length │ export_time │ sequence │ observation dom │
//!   └────────────────────────────────────────────────────────────────┘
//!   ┌── Set ───────────────┐ ┌── Set ───────────────┐ …
//!   │ id │ length │ body   │ │ id │ length │ body   │
//!   └──────────────────────┘ └──────────────────────┘
//!
//!     id = 2    templates
//!     id = 3    options templates
//!     id ≥ 256  data, laid out by the template with that id
//! ```
//!
//! The model is v9's and the template cache is literally the same one — see
//! [`crate::templates`], and §2.2 for the rules it enforces. Three things differ, and all
//! three are places to get it wrong.
//!
//! # Variable-length fields
//!
//! A template may declare a field's length as 65 535, meaning *the record says*. The
//! record then begins that field with a one-byte length, or — when that byte is 255 —
//! with three bytes, the last two being the real length. §7 of the RFC.
//!
//! This is the first place in the product where an attacker-controlled length drives the
//! parse, which is why M7's spec made fuzzing a topic. [`crate::templates::Template::walk`]
//! is where it is read and where it is checked, and a record whose declared length runs
//! past the set is a short record rather than a panic.
//!
//! It also changes how a data set is read: records of a fixed template can be counted by
//! division, but a variable one's have to be walked one at a time, because only the
//! record says where the next one starts.
//!
//! # Time is absolute
//!
//! v9 dates a flow by device uptime, and the header carries the uptime to subtract from.
//! **IPFIX has no uptime in its header at all.** Instead it has absolute elements —
//! `flowStartMilliseconds` and friends — which are better in every way: no 49.7-day wrap,
//! no dependence on a reboot the collector did not see.
//!
//! An exporter that sends only the v9-style `flowStartSysUpTime` is therefore asking to
//! be dated against something this message does not contain. Those flows are dated at the
//! export time and counted in [`Decoded::time_assumed`] — the export instant is the one
//! honest answer available, since it is when the exporter said the flow existed.
//!
//! # Enterprise fields
//!
//! The top bit of a field identifier means "vendor-specific", and the specifier then
//! carries four more bytes naming the vendor. Read and skipped: the width still has to be
//! right or every field after it shifts, which is the whole reason this is handled rather
//! than ignored.

use std::net::IpAddr;

use chrono::{DateTime, TimeZone, Utc};

use crate::templates::{Field, Kind, Learned, Protocol, Samplers, Source, Template};
use crate::{Error, Flow, Result, be16, be32, ipv4, ipv6, narrow8, narrow16, narrow32, truncating};

/// Bytes before the first Set.
const HEADER: usize = 16;

/// A Set's own header: id and length.
const SET_HEADER: usize = 4;

const TEMPLATE_SET: u16 = 2;
const OPTIONS_TEMPLATE_SET: u16 = 3;
const FIRST_DATA_ID: u16 = 256;

/// A field length of 65 535 means the record carries the real one. RFC 7011 §7.
const VARIABLE: u16 = 0xffff;

/// The top bit of an information element identifier.
const ENTERPRISE_BIT: u16 = 0x8000;

// IANA IPFIX information elements. The identifiers v9 shares are deliberately the same
// numbers — IPFIX adopted them — so these agree with `v9`'s list where they overlap.
const OCTET_DELTA_COUNT: u16 = 1;
const PACKET_DELTA_COUNT: u16 = 2;
const PROTOCOL_IDENTIFIER: u16 = 4;
const IP_CLASS_OF_SERVICE: u16 = 5;
const TCP_CONTROL_BITS: u16 = 6;
const SOURCE_TRANSPORT_PORT: u16 = 7;
const SOURCE_IPV4_ADDRESS: u16 = 8;
const INGRESS_INTERFACE: u16 = 10;
const DESTINATION_TRANSPORT_PORT: u16 = 11;
const DESTINATION_IPV4_ADDRESS: u16 = 12;
const EGRESS_INTERFACE: u16 = 14;
const BGP_SOURCE_AS: u16 = 16;
const BGP_DESTINATION_AS: u16 = 17;
const FLOW_END_SYS_UP_TIME: u16 = 21;
const FLOW_START_SYS_UP_TIME: u16 = 22;
const POST_OCTET_DELTA_COUNT: u16 = 23;
const POST_PACKET_DELTA_COUNT: u16 = 24;
const SOURCE_IPV6_ADDRESS: u16 = 27;
const DESTINATION_IPV6_ADDRESS: u16 = 28;
const SAMPLING_INTERVAL: u16 = 34;
const SAMPLER_ID: u16 = 48;
const SAMPLER_RANDOM_INTERVAL: u16 = 50;
const FLOW_START_SECONDS: u16 = 150;
const FLOW_END_SECONDS: u16 = 151;
const FLOW_START_MILLISECONDS: u16 = 152;
const FLOW_END_MILLISECONDS: u16 = 153;
/// The modern spelling of a sampling rate: one packet in this many.
const SAMPLING_PACKET_INTERVAL: u16 = 305;
const SELECTOR_ID: u16 = 302;

/// What the message header said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The message's own declared length, which is checked against what arrived.
    pub length: usize,
    pub sequence: u32,
    pub domain: u32,
    pub exported_at: DateTime<Utc>,
}

/// One message's worth of results.
#[derive(Clone, Debug, Default)]
pub struct Decoded {
    pub flows: Vec<Flow>,
    pub templates_learned: usize,
    pub templates_refused: usize,
    /// Data sets dropped because their template has not arrived. §2.2.
    pub awaiting_template: usize,
    /// Records skipped because their template describes no addresses.
    pub not_a_flow: usize,
    pub options_learned: usize,
    pub options_applied: usize,
    /// Flows whose sampling rate could not be established — see `v9`'s note on the same
    /// counter. Non-zero exactly when a rate of 1 is an assumption rather than a
    /// statement.
    pub sampling_unknown: usize,
    /// Flows dated at the export time because the record carried no absolute timestamp.
    pub time_assumed: usize,
}

/// Decode one message, learning templates as they appear.
///
/// # Errors
///
/// When the message is shorter than a header, is not version 10, or contains a Set whose
/// declared length runs past the end of it. Anything recoverable is counted in
/// [`Decoded`], because one unusable Set must not discard the ones beside it.
pub fn decode(packet: &[u8], exporter: IpAddr, learned: &mut Learned) -> Result<(Header, Decoded)> {
    if packet.len() < HEADER {
        return Err(Error::TooShort {
            need: HEADER,
            got: packet.len(),
        });
    }

    let version = be16(packet, 0)?;
    if version != 10 {
        return Err(Error::UnknownVersion { got: version });
    }

    let length = be16(packet, 2)? as usize;
    let secs = be32(packet, 4)?;
    let sequence = be32(packet, 8)?;
    let domain = be32(packet, 12)?;

    // Unlike v9, the header says how long the message is. A claim longer than the
    // datagram is refused rather than trusted: it is the same shape of lie v5's record
    // count takes, and believing it walks off the end of the buffer.
    if length > packet.len() {
        return Err(Error::CountExceedsPacket {
            claimed: length,
            need: length,
            got: packet.len(),
        });
    }
    // A shorter claim is honoured — trailing bytes are not ours to read — but it must at
    // least cover the header it is part of.
    let limit = if length < HEADER {
        packet.len()
    } else {
        length
    };

    let exported_at = Utc
        .timestamp_opt(i64::from(secs), 0)
        .single()
        .ok_or(Error::Invalid {
            what: "the export timestamp",
            why: "it is not a representable instant",
        })?;

    let header = Header {
        length,
        sequence,
        domain,
        exported_at,
    };
    let source = Source {
        exporter,
        protocol: Protocol::Ipfix,
        domain,
    };

    let mut out = Decoded::default();
    let mut at = HEADER;

    while at + SET_HEADER <= limit {
        let set_id = be16(packet, at)?;
        let set_len = be16(packet, at + 2)? as usize;

        // A length that does not cover its own header would not advance `at`, and the
        // loop would spin on the same bytes forever.
        if set_len < SET_HEADER {
            return Err(Error::Invalid {
                what: "a Set length",
                why: "it is shorter than the Set header it includes",
            });
        }
        let end = at.checked_add(set_len).ok_or(Error::Invalid {
            what: "a Set length",
            why: "it overflows the message offset",
        })?;
        if end > limit {
            return Err(Error::CountExceedsPacket {
                claimed: usize::from(set_id),
                need: end,
                got: limit,
            });
        }

        let body = &packet[at + SET_HEADER..end];
        match set_id {
            TEMPLATE_SET => read_templates(body, source, learned, &mut out, false),
            OPTIONS_TEMPLATE_SET => read_templates(body, source, learned, &mut out, true),
            // 0, 1 and 4..=255 have no defined meaning here. Skipped by their length,
            // which is the forward-compatible reading.
            0..FIRST_DATA_ID => {}
            id => match learned.get(source, id).map(|t| t.kind) {
                None => out.awaiting_template += 1,
                Some(Kind::Data) => read_data(body, id, source, learned, &header, &mut out),
                Some(Kind::Options) => {
                    if let Some(template) = learned.get(source, id).cloned() {
                        read_options(body, &template, source, learned, &mut out);
                    }
                }
            },
        }

        at = end;
    }

    Ok((header, out))
}

/// A template Set, or an options template Set — they differ by one field.
///
/// ```text
///   template          id │ field_count │ specifiers…
///   options template  id │ field_count │ scope_count │ specifiers…
/// ```
///
/// Both count *fields*, where v9's options template counts bytes. The scope count is read
/// and discarded: scope says which entity an options record is about, and this decoder
/// only wants the sampling values, which are ordinary fields either way.
fn read_templates(
    body: &[u8],
    source: Source,
    learned: &mut Learned,
    out: &mut Decoded,
    options: bool,
) {
    let head = if options { 6 } else { 4 };
    let mut at = 0;

    while at + head <= body.len() {
        let Ok(id) = be16(body, at) else { return };
        let Ok(field_count) = be16(body, at + 2) else {
            return;
        };

        // A withdrawal: field count zero means "forget this template". Nothing to learn,
        // and nothing to resynchronise around either, so the Set ends here.
        if field_count == 0 {
            return;
        }

        let Some((template, consumed)) =
            parse_fields(body, at + head, field_count as usize, options)
        else {
            // A declaration running past the Set, or one that cannot be used. There is no
            // way to continue: the next template's offset depended on this one's width.
            return;
        };

        at += head + consumed;

        if learned.learn(source, id, template) {
            if options {
                out.options_learned += 1;
            } else {
                out.templates_learned += 1;
            }
        } else {
            out.templates_refused += 1;
        }
    }
}

/// `field_count` specifiers starting at `at`, returning the template and its byte width.
///
/// A specifier is four bytes, or eight when the enterprise bit is set — which is why this
/// returns how much it consumed rather than letting the caller multiply.
fn parse_fields(
    body: &[u8],
    at: usize,
    field_count: usize,
    options: bool,
) -> Option<(Template, usize)> {
    let mut fields = Vec::with_capacity(field_count);
    let mut cursor = at;

    for _ in 0..field_count {
        let raw = be16(body, cursor).ok()?;
        let len = be16(body, cursor + 2).ok()?;
        cursor += 4;

        if raw & ENTERPRISE_BIT != 0 {
            // The vendor's number. Not kept — nothing here interprets a private element —
            // but its four bytes are read, because getting the specifier's width wrong
            // shifts every field after it.
            be32(body, cursor).ok()?;
            cursor += 4;
        }

        fields.push(Field {
            kind: raw & !ENTERPRISE_BIT,
            len: usize::from(len),
            variable: len == VARIABLE,
            enterprise: raw & ENTERPRISE_BIT != 0,
        });
    }

    let kind = if options { Kind::Options } else { Kind::Data };
    Some((Template::new(fields, kind)?, cursor - at))
}

/// A data Set: records back to back, laid out by `id`'s template.
fn read_data(
    body: &[u8],
    id: u16,
    source: Source,
    learned: &Learned,
    header: &Header,
    out: &mut Decoded,
) {
    let Some(template) = learned.get(source, id) else {
        out.awaiting_template += 1;
        return;
    };
    let samplers = learned.samplers(source);

    let mut at = 0;
    loop {
        // A fixed template stops on padding; a variable one stops when a record will not
        // fit, which `walk` reports by returning None.
        if let Some(width) = template.fixed_len {
            if at + width > body.len() {
                return;
            }
        } else if at >= body.len() {
            return;
        }

        let Some(read) = record(&body[at..], template, header, samplers) else {
            return;
        };
        at += read.consumed;

        match read.flow {
            Some(flow) => {
                if read.sampling_assumed {
                    out.sampling_unknown += 1;
                }
                if read.time_assumed {
                    out.time_assumed += 1;
                }
                out.flows.push(flow);
            }
            None => out.not_a_flow += 1,
        }

        if read.consumed == 0 {
            return;
        }
    }
}

/// An options record: what the exporter says about its own sampling.
fn read_options(
    body: &[u8],
    template: &Template,
    source: Source,
    learned: &mut Learned,
    out: &mut Decoded,
) {
    let mut at = 0;
    while at < body.len() {
        let mut sampler = None;
        let mut interval = None;

        let Some(consumed) = template.walk(&body[at..], |field, slice| {
            if field.enterprise {
                return;
            }
            match field.kind {
                SAMPLER_ID | SELECTOR_ID => sampler = Some(narrow32(slice)),
                SAMPLING_INTERVAL | SAMPLER_RANDOM_INTERVAL | SAMPLING_PACKET_INTERVAL => {
                    interval = Some(narrow32(slice));
                }
                _ => {}
            }
        }) else {
            return;
        };

        if consumed == 0 {
            return;
        }
        at += consumed;

        if let Some(interval) = interval.filter(|i| *i > 1) {
            learned.learn_sampler(source, sampler, interval);
            out.options_applied += 1;
        }
    }
}

/// One record, and what had to be assumed about it.
struct Read {
    flow: Option<Flow>,
    consumed: usize,
    sampling_assumed: bool,
    time_assumed: bool,
}

fn record(
    buf: &[u8],
    template: &Template,
    header: &Header,
    samplers: Option<&Samplers>,
) -> Option<Read> {
    let mut src_address = None;
    let mut dst_address = None;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut protocol = 0u8;
    let mut bytes = 0u64;
    let mut packets = 0u64;
    let mut tcp_flags = 0u8;
    let mut tos = 0u8;
    let mut input_if = None;
    let mut output_if = None;
    let mut src_as = None;
    let mut dst_as = None;
    let mut in_record_rate = None;
    let mut sampler_id = None;
    let mut start = None;
    let mut end = None;
    let mut saw_uptime_only = false;

    let consumed = template.walk(buf, |field, slice| {
        // A vendor's element numbers mean nothing here, and the identifier spaces overlap
        // completely — enterprise 9's element 8 is not sourceIPv4Address. Stepped over
        // for its width and otherwise ignored.
        if field.enterprise {
            return;
        }
        match field.kind {
            SOURCE_IPV4_ADDRESS => src_address = ipv4(slice),
            DESTINATION_IPV4_ADDRESS => dst_address = ipv4(slice),
            SOURCE_IPV6_ADDRESS => src_address = ipv6(slice),
            DESTINATION_IPV6_ADDRESS => dst_address = ipv6(slice),

            SOURCE_TRANSPORT_PORT => src_port = narrow16(slice),
            DESTINATION_TRANSPORT_PORT => dst_port = narrow16(slice),
            PROTOCOL_IDENTIFIER => protocol = narrow8(slice),
            TCP_CONTROL_BITS => tcp_flags = narrow8(slice),
            IP_CLASS_OF_SERVICE => tos = narrow8(slice),

            OCTET_DELTA_COUNT | POST_OCTET_DELTA_COUNT => bytes += truncating(slice),
            PACKET_DELTA_COUNT | POST_PACKET_DELTA_COUNT => packets += truncating(slice),

            INGRESS_INTERFACE => input_if = Some(narrow32(slice)),
            EGRESS_INTERFACE => output_if = Some(narrow32(slice)),
            BGP_SOURCE_AS => src_as = Some(narrow32(slice)),
            BGP_DESTINATION_AS => dst_as = Some(narrow32(slice)),

            // Absolute, and preferred: no wrap, and no dependence on a reboot the collector
            // did not see.
            FLOW_START_MILLISECONDS => start = millis(truncating(slice)),
            FLOW_END_MILLISECONDS => end = millis(truncating(slice)),
            FLOW_START_SECONDS => start = seconds(truncating(slice)),
            FLOW_END_SECONDS => end = seconds(truncating(slice)),

            // The v9 spelling. IPFIX carries no uptime in its header, so there is nothing to
            // subtract these from — recorded only so the flow can say its time was assumed.
            FLOW_START_SYS_UP_TIME | FLOW_END_SYS_UP_TIME => saw_uptime_only = true,

            SAMPLING_INTERVAL | SAMPLER_RANDOM_INTERVAL | SAMPLING_PACKET_INTERVAL => {
                in_record_rate = Some(narrow32(slice));
            }
            SAMPLER_ID | SELECTOR_ID => sampler_id = Some(narrow32(slice)),

            _ => {}
        }
    })?;

    let Some(src_address) = src_address else {
        return Some(Read {
            flow: None,
            consumed,
            sampling_assumed: false,
            time_assumed: false,
        });
    };
    let Some(dst_address) = dst_address else {
        return Some(Read {
            flow: None,
            consumed,
            sampling_assumed: false,
            time_assumed: false,
        });
    };

    let established = in_record_rate.or_else(|| samplers.and_then(|s| s.rate(sampler_id)));
    let sampling_rate = established.unwrap_or(1).max(1);

    let observed_at = end.or(start).unwrap_or(header.exported_at);
    let started_at = start.unwrap_or(observed_at);

    Some(Read {
        flow: Some(Flow {
            observed_at,
            started_at,
            src_address,
            dst_address,
            src_port,
            dst_port,
            protocol,
            bytes,
            packets,
            sampling_rate,
            tcp_flags,
            tos,
            input_if,
            output_if,
            src_as,
            dst_as,
        }),
        consumed,
        sampling_assumed: established.is_none(),
        // Either the record carried no time at all, or it carried only the uptime form
        // this message cannot resolve. Both mean the export instant was used.
        time_assumed: end.is_none() && start.is_none() || saw_uptime_only && end.is_none(),
    })
}

/// Milliseconds since the epoch, as `flowStartMilliseconds` counts them.
fn millis(value: u64) -> Option<DateTime<Utc>> {
    let ms = i64::try_from(value).ok()?;
    Utc.timestamp_millis_opt(ms).single()
}

fn seconds(value: u64) -> Option<DateTime<Utc>> {
    let secs = i64::try_from(value).ok()?;
    Utc.timestamp_opt(secs, 0).single()
}
