//! `NetFlow` v9 — RFC 3954, where the layout arrives separately from the data.
//!
//! ```text
//!   ┌── header, 20 bytes ─────────────────────────────────────────────┐
//!   │ version=9 │ count │ sys_uptime │ unix_secs │ sequence │ source  │
//!   └─────────────────────────────────────────────────────────────────┘
//!   ┌── FlowSet ───────────┐ ┌── FlowSet ───────────┐ …
//!   │ id │ length │ body   │ │ id │ length │ body   │
//!   └──────────────────────┘ └──────────────────────┘
//!
//!     id = 0    templates: how to read everything that follows
//!     id = 1    options templates — parsed and skipped, see below
//!     id ≥ 256  data, laid out by the template with that id
//! ```
//!
//! # The template is the whole problem
//!
//! A data record is a bag of bytes with no field names and no field boundaries. The
//! template that gives it both arrives in a different packet, periodically, and
//! [`Templates`] is where it is kept. `docs/M7-flow.md` §2.2 sets the rules this module
//! implements; the two that show up as code are the cache key and the refusal to buffer.
//!
//! **The key is `(exporter, observation domain, template ID)`.** Template IDs start at
//! 256 on every exporter, so two routers pointed at one collector will both use 256 for
//! different layouts. A cache keyed on the ID alone decodes one as the other — and not
//! loudly: the fields are the right *width*, so it yields plausible addresses and byte
//! counts that are wrong.
//!
//! **A record whose template has not arrived is counted and dropped.** Not buffered.
//! Buffering is the obvious alternative and it is memory exhaustion with a public UDP
//! port in front of it.
//!
//! # What this does not do yet
//!
//! **Options templates (`FlowSet` 1) are skipped, and counted.** They are how some
//! exporters report their sampling rate, so an exporter that samples 1-in-1000 and
//! announces it only that way is currently read as unsampled — which §2.4 is explicit is
//! the error worth a factor of a thousand. [`Decoded::options_skipped`] is non-zero
//! exactly when that is possible, so it is visible rather than silent. A sampling rate
//! carried as a *field in the data record* is read, which covers the exporters that do
//! it that way.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, TimeZone, Utc};

use crate::{Error, Flow, Result, be16, be32};

/// Bytes before the first `FlowSet`.
const HEADER: usize = 20;

/// A `FlowSet`'s own header: id and length.
const FLOWSET_HEADER: usize = 4;

/// Below this, a `FlowSet` id is not a template id.
const FIRST_DATA_ID: u16 = 256;

// The field types this decoder understands. RFC 3954 §8. Anything else is skipped by its
// declared length, which is what makes a vendor's private fields harmless rather than
// fatal.
const IN_BYTES: u16 = 1;
const IN_PKTS: u16 = 2;
const PROTOCOL: u16 = 4;
const SRC_TOS: u16 = 5;
const TCP_FLAGS: u16 = 6;
const L4_SRC_PORT: u16 = 7;
const IPV4_SRC_ADDR: u16 = 8;
const INPUT_SNMP: u16 = 10;
const L4_DST_PORT: u16 = 11;
const IPV4_DST_ADDR: u16 = 12;
const OUTPUT_SNMP: u16 = 14;
const SRC_AS: u16 = 16;
const DST_AS: u16 = 17;
const LAST_SWITCHED: u16 = 21;
const FIRST_SWITCHED: u16 = 22;
const OUT_BYTES: u16 = 23;
const OUT_PKTS: u16 = 24;
const IPV6_SRC_ADDR: u16 = 27;
const IPV6_DST_ADDR: u16 = 28;
const SAMPLING_INTERVAL: u16 = 34;
const FLOW_SAMPLER_RANDOM_INTERVAL: u16 = 50;

/// How much template state one collector will hold.
///
/// Bounded because the input is unauthenticated UDP: without a limit, anything that can
/// reach the port can make this process allocate by inventing exporters or template ids.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Distinct `(exporter, observation domain)` pairs.
    ///
    /// A pair rather than an exporter, because one chassis can export several
    /// observation domains and each numbers its templates independently.
    pub max_sources: usize,
    /// Templates held for any one source.
    pub max_templates_per_source: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // Room for a large estate — a thousand exporters, each with a handful of
        // templates and headroom for re-registration — and still a bound a hostile
        // sender cannot walk past.
        Self {
            max_sources: 1024,
            max_templates_per_source: 64,
        }
    }
}

/// One field, as a template declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Field {
    kind: u16,
    len: usize,
}

/// A layout for data records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    fields: Vec<Field>,
    /// Sum of the field lengths. Every record laid out by this template is this long.
    record_len: usize,
}

impl Template {
    /// How long one record is. Never zero — see [`parse_template`].
    #[must_use]
    pub fn record_len(&self) -> usize {
        self.record_len
    }
}

/// The template cache.
///
/// Keyed as §2.2 requires. Held by the collector across datagrams and across exporters,
/// and deliberately *not* persisted: the gap after a restart is inherent to the protocol
/// and is reported rather than papered over.
#[derive(Debug)]
pub struct Templates {
    by_source: HashMap<(IpAddr, u32), HashMap<u16, Template>>,
    limits: Limits,
}

impl Default for Templates {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Templates {
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            by_source: HashMap::new(),
            limits,
        }
    }

    /// How many templates are held, across every source.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_source.values().map(HashMap::len).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, source: (IpAddr, u32), id: u16) -> Option<&Template> {
        self.by_source.get(&source)?.get(&id)
    }

    /// Learn a template. `false` when a limit refused it.
    ///
    /// A template that is already held is *replaced*, and replacing never counts against
    /// the limit — an exporter re-registering the same id is the normal case, not
    /// growth. A redefinition is accepted because the protocol offers no way to reject
    /// one; §2.2 records why the data records racing it cannot be rescued.
    fn learn(&mut self, source: (IpAddr, u32), id: u16, template: Template) -> bool {
        let known = self.by_source.contains_key(&source);
        if !known && self.by_source.len() >= self.limits.max_sources {
            return false;
        }

        let slot = self.by_source.entry(source).or_default();
        if !slot.contains_key(&id) && slot.len() >= self.limits.max_templates_per_source {
            // Refused rather than evicted. Evicting to make room means dropping whichever
            // exporter is quietest, which is the one nobody notices has gone missing.
            return false;
        }

        slot.insert(id, template);
        true
    }
}

/// What the header said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Records the exporter claims the datagram holds, templates included.
    ///
    /// Advisory: RFC 3954 is ambiguous about whether it counts records or `FlowSet`s, and
    /// implementations differ. The `FlowSet` lengths are what this decoder walks, because
    /// they are what the bytes actually say.
    pub count: u16,
    pub sequence: u32,
    /// The observation domain. Part of the cache key.
    pub source_id: u32,
    pub exported_at: DateTime<Utc>,
    pub uptime_ms: u32,
}

/// One datagram's worth of results.
#[derive(Clone, Debug, Default)]
pub struct Decoded {
    pub flows: Vec<Flow>,
    /// Templates learned or replaced.
    pub templates_learned: usize,
    /// Templates a limit refused. Non-zero means flow is being lost — see [`Limits`].
    pub templates_refused: usize,
    /// Data records dropped because their template has not arrived. §2.2.
    pub awaiting_template: usize,
    /// Data records skipped because their template describes no addresses.
    ///
    /// A template with no address fields is not describing an IP conversation, and
    /// inventing `0.0.0.0` for it would put rows in the table that mean nothing. Counted
    /// rather than silently ignored, because a template this decoder cannot use is
    /// something an operator may need to hear about.
    pub not_a_flow: usize,
    /// Options template `FlowSet`s skipped. See the module documentation.
    pub options_skipped: usize,
}

/// Decode one datagram, learning templates as they appear.
///
/// `exporter` is the address the packet came from. It is the cache key's first component
/// and the crate takes it as an argument rather than reading a socket, so this stays
/// testable from a byte array.
///
/// # Errors
///
/// When the datagram is shorter than a header, is not version 9, or contains a `FlowSet`
/// whose declared length runs past the end of the packet. Anything recoverable — a
/// missing template, a template that cannot be used — is counted in [`Decoded`] instead,
/// because one unusable `FlowSet` must not discard the ones beside it.
pub fn decode(
    packet: &[u8],
    exporter: IpAddr,
    templates: &mut Templates,
) -> Result<(Header, Decoded)> {
    if packet.len() < HEADER {
        return Err(Error::TooShort {
            need: HEADER,
            got: packet.len(),
        });
    }

    let version = be16(packet, 0)?;
    if version != 9 {
        return Err(Error::UnknownVersion { got: version });
    }

    let count = be16(packet, 2)?;
    let uptime_ms = be32(packet, 4)?;
    let secs = be32(packet, 8)?;
    let sequence = be32(packet, 12)?;
    let source_id = be32(packet, 16)?;

    let exported_at = Utc
        .timestamp_opt(i64::from(secs), 0)
        .single()
        .ok_or(Error::Invalid {
            what: "the export timestamp",
            why: "it is not a representable instant",
        })?;

    let header = Header {
        count,
        sequence,
        source_id,
        exported_at,
        uptime_ms,
    };
    let source = (exporter, source_id);

    let mut out = Decoded::default();
    let mut at = HEADER;

    while at + FLOWSET_HEADER <= packet.len() {
        let set_id = be16(packet, at)?;
        let set_len = be16(packet, at + 4 - 2)? as usize;

        // A length that does not cover its own header would not advance `at`, and the
        // loop would spin on the same bytes forever. This is the packet that hangs a
        // collector, so it is refused rather than skipped.
        if set_len < FLOWSET_HEADER {
            return Err(Error::Invalid {
                what: "a FlowSet length",
                why: "it is shorter than the FlowSet header it includes",
            });
        }
        let end = at.checked_add(set_len).ok_or(Error::Invalid {
            what: "a FlowSet length",
            why: "it overflows the packet offset",
        })?;
        if end > packet.len() {
            return Err(Error::CountExceedsPacket {
                claimed: usize::from(set_id),
                need: end,
                got: packet.len(),
            });
        }

        let body = &packet[at + FLOWSET_HEADER..end];
        match set_id {
            0 => read_templates(body, source, templates, &mut out),
            1 => out.options_skipped += 1,
            // 2..=255 are reserved and have no defined meaning. Skipped by their length,
            // which is the forward-compatible reading.
            2..FIRST_DATA_ID => {}
            id => read_data(body, id, source, templates, &header, &mut out),
        }

        at = end;
    }

    Ok((header, out))
}

/// A template `FlowSet` holds one or more templates, back to back.
fn read_templates(
    body: &[u8],
    source: (IpAddr, u32),
    templates: &mut Templates,
    out: &mut Decoded,
) {
    let mut at = 0;
    // Four bytes is the smallest possible template header; anything left below that is
    // the FlowSet's alignment padding.
    while at + 4 <= body.len() {
        let Ok(id) = be16(body, at) else { return };
        let Ok(field_count) = be16(body, at + 2) else {
            return;
        };

        let Some(template) = parse_template(body, at + 4, field_count as usize) else {
            // A template this decoder cannot represent — no fields, or zero total width,
            // or a declaration running past the FlowSet. There is no way to resynchronise
            // within the set, because the next template's offset depended on this one.
            return;
        };

        at += 4 + field_count as usize * 4;

        if templates.learn(source, id, template) {
            out.templates_learned += 1;
        } else {
            out.templates_refused += 1;
        }
    }
}

/// `field_count` pairs of `(type, length)`, starting at `at`.
///
/// `None` when the declaration is unusable. A zero `record_len` is the one that matters:
/// the data reader divides by it, and a template of "one field, zero bytes wide" would
/// otherwise mean a data `FlowSet` holds infinitely many records.
fn parse_template(body: &[u8], at: usize, field_count: usize) -> Option<Template> {
    if field_count == 0 {
        return None;
    }

    let mut fields = Vec::with_capacity(field_count);
    let mut record_len = 0usize;

    for n in 0..field_count {
        let base = at.checked_add(n.checked_mul(4)?)?;
        let kind = be16(body, base).ok()?;
        let len = be16(body, base + 2).ok()? as usize;
        record_len = record_len.checked_add(len)?;
        fields.push(Field { kind, len });
    }

    if record_len == 0 {
        return None;
    }

    Some(Template { fields, record_len })
}

/// A data `FlowSet`: records packed back to back, laid out by `id`'s template.
fn read_data(
    body: &[u8],
    id: u16,
    source: (IpAddr, u32),
    templates: &Templates,
    header: &Header,
    out: &mut Decoded,
) {
    let Some(template) = templates.get(source, id) else {
        // §2.2: counted and dropped, never buffered. How many records were lost is not
        // knowable without the template — the record width is exactly what is missing —
        // so this counts the FlowSet.
        out.awaiting_template += 1;
        return;
    };

    // Trailing bytes shorter than one record are the FlowSet's padding to a 4-byte
    // boundary, and are not a short record.
    let mut at = 0;
    while at + template.record_len <= body.len() {
        match record(&body[at..at + template.record_len], template, header) {
            Some(flow) => out.flows.push(flow),
            None => out.not_a_flow += 1,
        }
        at += template.record_len;
    }
}

/// One record, walked field by field in the order the template declared.
fn record(buf: &[u8], template: &Template, header: &Header) -> Option<Flow> {
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
    let mut sampling_rate = 1u32;
    let mut first_ms = None;
    let mut last_ms = None;

    let mut at = 0usize;
    for field in &template.fields {
        let slice = buf.get(at..at + field.len)?;
        at += field.len;

        match field.kind {
            IPV4_SRC_ADDR => src_address = ipv4(slice),
            IPV4_DST_ADDR => dst_address = ipv4(slice),
            IPV6_SRC_ADDR => src_address = ipv6(slice),
            IPV6_DST_ADDR => dst_address = ipv6(slice),

            L4_SRC_PORT => src_port = narrow16(slice),
            L4_DST_PORT => dst_port = narrow16(slice),
            PROTOCOL => protocol = narrow8(slice),
            TCP_FLAGS => tcp_flags = narrow8(slice),
            SRC_TOS => tos = narrow8(slice),

            // A record reports either ingress or egress counters depending on how the
            // exporter is configured, and some send both. Added rather than overwritten:
            // a template carrying IN_BYTES and OUT_BYTES describes one conversation, and
            // taking whichever came last would report half of it.
            IN_BYTES | OUT_BYTES => bytes += truncating(slice),
            IN_PKTS | OUT_PKTS => packets += truncating(slice),

            INPUT_SNMP => input_if = Some(narrow32(slice)),
            OUTPUT_SNMP => output_if = Some(narrow32(slice)),
            SRC_AS => src_as = Some(narrow32(slice)),
            DST_AS => dst_as = Some(narrow32(slice)),

            FIRST_SWITCHED => first_ms = Some(narrow32(slice)),
            LAST_SWITCHED => last_ms = Some(narrow32(slice)),

            // §2.4. Clamped up to 1 for the same reason v5 clamps: every consumer
            // multiplies by this, and a zero turns every byte count into nothing.
            SAMPLING_INTERVAL | FLOW_SAMPLER_RANDOM_INTERVAL => {
                sampling_rate = narrow32(slice).max(1);
            }

            // Everything else is skipped by its declared length. A vendor's private
            // field is then harmless rather than fatal, which is the whole reason the
            // template carries lengths.
            _ => {}
        }
    }

    // No addresses means this template is not describing an IP conversation. Returning
    // None puts it on a counter; inventing 0.0.0.0 would put a meaningless row in the
    // table and no screen downstream could tell it from a real one.
    let (src_address, dst_address) = (src_address?, dst_address?);

    // An exporter that sends neither switched time dates the flow at the export instant,
    // which is the only honest answer available: it is when we know the flow existed.
    let observed_at = last_ms.map_or(header.exported_at, |ms| {
        crate::absolute(header.exported_at, header.uptime_ms, ms)
    });
    let started_at = first_ms.map_or(observed_at, |ms| {
        crate::absolute(header.exported_at, header.uptime_ms, ms)
    });

    Some(Flow {
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
    })
}

/// A numeric field of whatever width the template declared.
///
/// RFC 3954 lets an exporter choose the width of a numeric field — `IN_BYTES` is
/// commonly 4 bytes and legitimately 8 — so nothing here may assume a size. Widths above
/// 8 take the low-order 8 bytes, which is what a big-endian value zero-padded on the left
/// means; a field wider than that carrying a number this decoder understands does not
/// occur, and guessing is better than refusing the whole record over it.
fn truncating(slice: &[u8]) -> u64 {
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
fn narrow32(slice: &[u8]) -> u32 {
    u32::try_from(truncating(slice) & u64::from(u32::MAX)).unwrap_or(u32::MAX)
}

fn narrow16(slice: &[u8]) -> u16 {
    u16::try_from(truncating(slice) & u64::from(u16::MAX)).unwrap_or(u16::MAX)
}

fn narrow8(slice: &[u8]) -> u8 {
    u8::try_from(truncating(slice) & u64::from(u8::MAX)).unwrap_or(u8::MAX)
}

fn ipv4(slice: &[u8]) -> Option<IpAddr> {
    let octets: [u8; 4] = slice.try_into().ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(octets)))
}

fn ipv6(slice: &[u8]) -> Option<IpAddr> {
    let octets: [u8; 16] = slice.try_into().ok()?;
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}
