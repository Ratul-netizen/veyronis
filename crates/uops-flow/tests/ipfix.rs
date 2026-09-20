//! IPFIX — `docs/M7-flow.md` §2.2 and §2.4, and the fourth acceptance criterion:
//! "an IPFIX export with a variable-length field decodes, and one whose declared length
//! runs past the end of the packet is one dropped packet rather than a panic".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{TimeZone, Utc};
use uops_flow::ipfix;
use uops_flow::templates::{Learned, Limits};
use uops_flow::{Error, v9};

const EXPORT_SECS: u32 = 1_789_000_000;
const ONE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const TWO: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

const OCTET_DELTA_COUNT: u16 = 1;
const PACKET_DELTA_COUNT: u16 = 2;
const PROTOCOL_IDENTIFIER: u16 = 4;
const SOURCE_TRANSPORT_PORT: u16 = 7;
const SOURCE_IPV4_ADDRESS: u16 = 8;
const DESTINATION_TRANSPORT_PORT: u16 = 11;
const DESTINATION_IPV4_ADDRESS: u16 = 12;
const FLOW_END_SYS_UP_TIME: u16 = 21;
const FLOW_START_SYS_UP_TIME: u16 = 22;
const SOURCE_IPV6_ADDRESS: u16 = 27;
const DESTINATION_IPV6_ADDRESS: u16 = 28;
const SAMPLER_ID: u16 = 48;
const FLOW_START_MILLISECONDS: u16 = 152;
const FLOW_END_MILLISECONDS: u16 = 153;
const SAMPLING_PACKET_INTERVAL: u16 = 305;
/// An arbitrary variable-length element. `applicationName` is 96 and is a string.
const APPLICATION_NAME: u16 = 96;
const VARIABLE: u16 = 0xffff;

/// A message, with its declared length filled in afterwards.
fn message(sets: &[Vec<u8>]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&10u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes()); // length, patched below
    p.extend_from_slice(&EXPORT_SECS.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes()); // sequence
    p.extend_from_slice(&9u32.to_be_bytes()); // observation domain
    for set in sets {
        p.extend_from_slice(set);
    }
    let len = u16::try_from(p.len()).unwrap();
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p
}

fn set(id: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A template set. A field of `(kind, len, Some(enterprise))` is a vendor element.
fn template(id: u16, fields: &[(u16, u16, Option<u32>)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(&u16::try_from(fields.len()).unwrap().to_be_bytes());
    for (kind, len, enterprise) in fields {
        let raw = if enterprise.is_some() {
            kind | 0x8000
        } else {
            *kind
        };
        body.extend_from_slice(&raw.to_be_bytes());
        body.extend_from_slice(&len.to_be_bytes());
        if let Some(e) = enterprise {
            body.extend_from_slice(&e.to_be_bytes());
        }
    }
    set(2, &body)
}

fn options_template(id: u16, scope: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(&u16::try_from(fields.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&scope.to_be_bytes());
    for (kind, len) in fields {
        body.extend_from_slice(&kind.to_be_bytes());
        body.extend_from_slice(&len.to_be_bytes());
    }
    set(3, &body)
}

fn plain_fields() -> Vec<(u16, u16, Option<u32>)> {
    vec![
        (SOURCE_IPV4_ADDRESS, 4, None),
        (DESTINATION_IPV4_ADDRESS, 4, None),
        (SOURCE_TRANSPORT_PORT, 2, None),
        (DESTINATION_TRANSPORT_PORT, 2, None),
        (PROTOCOL_IDENTIFIER, 1, None),
        (OCTET_DELTA_COUNT, 8, None),
        (PACKET_DELTA_COUNT, 8, None),
        (FLOW_START_MILLISECONDS, 8, None),
        (FLOW_END_MILLISECONDS, 8, None),
    ]
}

fn plain_record(start_ms: i64, end_ms: i64) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&[10, 0, 0, 7]);
    r.extend_from_slice(&[8, 8, 8, 8]);
    r.extend_from_slice(&51_000u16.to_be_bytes());
    r.extend_from_slice(&443u16.to_be_bytes());
    r.push(6);
    r.extend_from_slice(&6000u64.to_be_bytes());
    r.extend_from_slice(&42u64.to_be_bytes());
    r.extend_from_slice(&start_ms.to_be_bytes());
    r.extend_from_slice(&end_ms.to_be_bytes());
    r
}

const START_MS: i64 = 1_789_000_000_000 - 5_000;
const END_MS: i64 = 1_789_000_000_000 - 1_000;

#[test]
fn a_template_then_data_decodes_with_absolute_timestamps() {
    let p = message(&[
        template(256, &plain_fields()),
        set(256, &plain_record(START_MS, END_MS)),
    ]);

    let mut cache = Learned::default();
    let (header, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(header.length, p.len());
    assert_eq!(header.domain, 9);
    assert_eq!(out.templates_learned, 1);
    assert_eq!(out.flows.len(), 1);

    let f = out.flows[0];
    assert_eq!(f.src_address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
    assert_eq!(f.dst_address, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(f.src_port, 51_000);
    assert_eq!(f.dst_port, 443);
    assert_eq!(f.protocol, 6);
    assert_eq!(f.bytes, 6000);
    assert_eq!(f.packets, 42);

    // Absolute, so no uptime arithmetic and no wrap to survive.
    assert_eq!(f.observed_at, Utc.timestamp_millis_opt(END_MS).unwrap());
    assert_eq!(f.started_at, Utc.timestamp_millis_opt(START_MS).unwrap());
    assert_eq!(out.time_assumed, 0);
}

#[test]
fn a_short_variable_length_field_decodes_and_does_not_shift_what_follows() {
    // The acceptance criterion's first half. The one-byte form: a length under 255.
    let mut fields = plain_fields();
    fields.insert(2, (APPLICATION_NAME, VARIABLE, None));

    let name = b"https";
    let mut record = Vec::new();
    record.extend_from_slice(&[10, 0, 0, 7]);
    record.extend_from_slice(&[8, 8, 8, 8]);
    record.push(u8::try_from(name.len()).unwrap());
    record.extend_from_slice(name);
    record.extend_from_slice(&51_000u16.to_be_bytes());
    record.extend_from_slice(&443u16.to_be_bytes());
    record.push(6);
    record.extend_from_slice(&6000u64.to_be_bytes());
    record.extend_from_slice(&42u64.to_be_bytes());
    record.extend_from_slice(&START_MS.to_be_bytes());
    record.extend_from_slice(&END_MS.to_be_bytes());

    let p = message(&[template(256, &fields), set(256, &record)]);
    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(
        out.flows[0].src_port, 51_000,
        "the variable-length field shifted everything after it"
    );
    assert_eq!(out.flows[0].bytes, 6000);
}

#[test]
fn the_three_byte_length_form_is_read() {
    // RFC 7011 §7: a first byte of 255 means the real length is the next two bytes.
    let mut fields = plain_fields();
    fields.insert(0, (APPLICATION_NAME, VARIABLE, None));

    let long = vec![b'x'; 300];
    let mut record = Vec::new();
    record.push(255);
    record.extend_from_slice(&u16::try_from(long.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&long);
    record.extend_from_slice(&plain_record(START_MS, END_MS));

    let p = message(&[template(256, &fields), set(256, &record)]);
    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(out.flows[0].src_port, 51_000);
}

#[test]
fn a_variable_length_running_past_the_set_is_a_short_record_rather_than_a_panic() {
    // The acceptance criterion's second half, and the first place in the product where a
    // length the attacker chose drives the parse.
    let mut fields = plain_fields();
    fields.insert(0, (APPLICATION_NAME, VARIABLE, None));

    // Claims 200 bytes of name in a record that holds four.
    let mut record = vec![200u8];
    record.extend_from_slice(b"abcd");

    let p = message(&[template(256, &fields), set(256, &record)]);
    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert!(
        out.flows.is_empty(),
        "a record that cannot fit produced a flow"
    );
}

#[test]
fn several_variable_length_records_in_one_set_all_decode() {
    // A fixed template's records can be counted by division; these cannot, because only
    // the record says where the next one starts.
    let mut fields = plain_fields();
    fields.insert(0, (APPLICATION_NAME, VARIABLE, None));

    let mut body = Vec::new();
    for name in [&b"a"[..], &b"bb"[..], &b"ccc"[..]] {
        body.push(u8::try_from(name.len()).unwrap());
        body.extend_from_slice(name);
        body.extend_from_slice(&plain_record(START_MS, END_MS));
    }

    let p = message(&[template(256, &fields), set(256, &body)]);
    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.flows.len(), 3);
}

#[test]
fn an_enterprise_field_is_skipped_by_its_width_and_costs_four_extra_header_bytes() {
    // The specifier is eight bytes rather than four when the enterprise bit is set. Read
    // it as four and every field after it shifts.
    let mut fields = plain_fields();
    fields.insert(2, (1234, 6, Some(9))); // enterprise 9 = Cisco

    let mut record = Vec::new();
    record.extend_from_slice(&[10, 0, 0, 7]);
    record.extend_from_slice(&[8, 8, 8, 8]);
    record.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]);
    record.extend_from_slice(&51_000u16.to_be_bytes());
    record.extend_from_slice(&443u16.to_be_bytes());
    record.push(6);
    record.extend_from_slice(&6000u64.to_be_bytes());
    record.extend_from_slice(&42u64.to_be_bytes());
    record.extend_from_slice(&START_MS.to_be_bytes());
    record.extend_from_slice(&END_MS.to_be_bytes());

    let p = message(&[template(256, &fields), set(256, &record)]);
    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(out.flows[0].src_port, 51_000);
    assert_eq!(out.flows[0].bytes, 6000);
}

#[test]
fn an_enterprise_element_does_not_collide_with_the_iana_element_of_the_same_number() {
    // Enterprise 9's element 8 is not sourceIPv4Address. Reading it as one would put a
    // vendor's private value in the address column.
    let fields = vec![
        (SOURCE_IPV4_ADDRESS, 4, None),
        (DESTINATION_IPV4_ADDRESS, 4, None),
        (8, 4, Some(9)),
    ];

    let mut record = Vec::new();
    record.extend_from_slice(&[10, 0, 0, 7]);
    record.extend_from_slice(&[8, 8, 8, 8]);
    record.extend_from_slice(&[1, 2, 3, 4]);

    let p = message(&[template(256, &fields), set(256, &record)]);
    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(
        out.flows[0].src_address,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        "an enterprise element overwrote the IANA one with the same id"
    );
}

#[test]
fn ipv6_decodes() {
    let fields = vec![
        (SOURCE_IPV6_ADDRESS, 16, None),
        (DESTINATION_IPV6_ADDRESS, 16, None),
        (OCTET_DELTA_COUNT, 8, None),
    ];
    let mut record = Vec::new();
    record.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    record.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
    record.extend_from_slice(&123u64.to_be_bytes());

    let p = message(&[template(256, &fields), set(256, &record)]);
    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(
        out.flows[0].src_address,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!(out.flows[0].bytes, 123);
}

#[test]
fn a_record_carrying_only_sys_up_time_is_dated_at_the_export_and_says_so() {
    // IPFIX has no uptime in its header, so there is nothing to subtract these from.
    // Dating the flow at the export instant is the one honest answer; the counter is what
    // stops that looking like a measurement.
    let fields = vec![
        (SOURCE_IPV4_ADDRESS, 4, None),
        (DESTINATION_IPV4_ADDRESS, 4, None),
        (FLOW_START_SYS_UP_TIME, 4, None),
        (FLOW_END_SYS_UP_TIME, 4, None),
    ];
    let mut record = Vec::new();
    record.extend_from_slice(&[10, 0, 0, 7]);
    record.extend_from_slice(&[8, 8, 8, 8]);
    record.extend_from_slice(&1_000u32.to_be_bytes());
    record.extend_from_slice(&2_000u32.to_be_bytes());

    let p = message(&[template(256, &fields), set(256, &record)]);
    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(
        out.flows[0].observed_at,
        Utc.timestamp_opt(i64::from(EXPORT_SECS), 0).unwrap()
    );
    assert_eq!(out.time_assumed, 1);
}

#[test]
fn data_before_its_template_is_counted_and_dropped() {
    let mut cache = Learned::default();

    let early = message(&[set(256, &plain_record(START_MS, END_MS))]);
    let (_, out) = ipfix::decode(&early, ONE, &mut cache).unwrap();
    assert_eq!(out.awaiting_template, 1);
    assert!(out.flows.is_empty());

    let later = message(&[
        template(256, &plain_fields()),
        set(256, &plain_record(START_MS, END_MS)),
    ]);
    let (_, out) = ipfix::decode(&later, ONE, &mut cache).unwrap();
    assert_eq!(out.flows.len(), 1);
}

#[test]
fn an_ipfix_template_does_not_collide_with_a_v9_template_of_the_same_id() {
    // Both protocols number templates from 256, and an exporter mid-migration sends both
    // from the same domain. Without the protocol in the cache key one overwrites the
    // other — and the symptom is the quiet one: fields of the right width, wrong values.
    let mut cache = Learned::default();

    // v9 first: domain 9, template 256, an IPv4 layout.
    let mut v9_packet = Vec::new();
    v9_packet.extend_from_slice(&9u16.to_be_bytes());
    v9_packet.extend_from_slice(&0u16.to_be_bytes());
    v9_packet.extend_from_slice(&10_000u32.to_be_bytes());
    v9_packet.extend_from_slice(&EXPORT_SECS.to_be_bytes());
    v9_packet.extend_from_slice(&1u32.to_be_bytes());
    v9_packet.extend_from_slice(&9u32.to_be_bytes());
    let mut tmpl = Vec::new();
    tmpl.extend_from_slice(&256u16.to_be_bytes());
    tmpl.extend_from_slice(&2u16.to_be_bytes());
    for (k, l) in [(SOURCE_IPV4_ADDRESS, 4u16), (DESTINATION_IPV4_ADDRESS, 4)] {
        tmpl.extend_from_slice(&k.to_be_bytes());
        tmpl.extend_from_slice(&l.to_be_bytes());
    }
    v9_packet.extend_from_slice(&0u16.to_be_bytes());
    v9_packet.extend_from_slice(&u16::try_from(tmpl.len() + 4).unwrap().to_be_bytes());
    v9_packet.extend_from_slice(&tmpl);
    v9::decode(&v9_packet, ONE, &mut cache).unwrap();

    // IPFIX next: same exporter, same domain, same template id, a different layout.
    let p = message(&[
        template(256, &plain_fields()),
        set(256, &plain_record(START_MS, END_MS)),
    ]);
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(out.flows[0].bytes, 6000, "the v9 template was used instead");
    assert_eq!(cache.len(), 2, "one template overwrote the other");
}

#[test]
fn a_sampler_from_an_options_record_reaches_the_flows_that_name_it() {
    let mut cache = Learned::default();

    let announce = message(&[
        options_template(300, 1, &[(SAMPLER_ID, 4), (SAMPLING_PACKET_INTERVAL, 4)]),
        set(300, &{
            let mut r = Vec::new();
            r.extend_from_slice(&7u32.to_be_bytes());
            r.extend_from_slice(&1000u32.to_be_bytes());
            r
        }),
    ]);
    let (_, out) = ipfix::decode(&announce, ONE, &mut cache).unwrap();
    assert_eq!(out.options_learned, 1);
    assert_eq!(out.options_applied, 1);
    assert!(out.flows.is_empty());

    let mut fields = plain_fields();
    fields.push((SAMPLER_ID, 4, None));
    let mut record = plain_record(START_MS, END_MS);
    record.extend_from_slice(&7u32.to_be_bytes());

    let traffic = message(&[template(256, &fields), set(256, &record)]);
    let (_, out) = ipfix::decode(&traffic, ONE, &mut cache).unwrap();

    assert_eq!(out.flows[0].sampling_rate, 1000);
    assert_eq!(out.sampling_unknown, 0);
    assert_eq!(out.flows[0].bytes, 6000, "counts are stored as observed");
}

#[test]
fn one_exporters_templates_are_not_anothers() {
    let mut cache = Learned::default();

    let p = message(&[
        template(256, &plain_fields()),
        set(256, &plain_record(START_MS, END_MS)),
    ]);
    ipfix::decode(&p, ONE, &mut cache).unwrap();

    let data_only = message(&[set(256, &plain_record(START_MS, END_MS))]);
    let (_, out) = ipfix::decode(&data_only, TWO, &mut cache).unwrap();
    assert_eq!(out.awaiting_template, 1);
}

#[test]
fn a_message_claiming_to_be_longer_than_the_datagram_is_refused() {
    let mut p = message(&[template(256, &plain_fields())]);
    p[2..4].copy_from_slice(&9000u16.to_be_bytes());

    let mut cache = Learned::default();
    assert!(matches!(
        ipfix::decode(&p, ONE, &mut cache),
        Err(Error::CountExceedsPacket { .. })
    ));
}

#[test]
fn trailing_bytes_beyond_the_declared_length_are_not_read() {
    // The header says how long the message is. Bytes after that are not ours — they are
    // padding, or a second message the caller has not split off.
    let mut p = message(&[
        template(256, &plain_fields()),
        set(256, &plain_record(START_MS, END_MS)),
    ]);
    let real = p.len();
    p.extend_from_slice(&[0xff; 32]);
    p[2..4].copy_from_slice(&u16::try_from(real).unwrap().to_be_bytes());

    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();
    assert_eq!(out.flows.len(), 1);
}

#[test]
fn a_set_length_that_does_not_cover_its_own_header_is_refused_and_does_not_spin() {
    let mut p = Vec::new();
    p.extend_from_slice(&10u16.to_be_bytes());
    p.extend_from_slice(&20u16.to_be_bytes());
    p.extend_from_slice(&EXPORT_SECS.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&9u32.to_be_bytes());
    p.extend_from_slice(&256u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());

    let mut cache = Learned::default();
    assert!(matches!(
        ipfix::decode(&p, ONE, &mut cache),
        Err(Error::Invalid { .. })
    ));
}

#[test]
fn a_template_withdrawal_is_not_read_as_a_template() {
    // Field count zero means "forget this one". Parsing it as a template would produce a
    // zero-width layout, which is the shape that makes a data set look infinite.
    let mut body = Vec::new();
    body.extend_from_slice(&256u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());

    let p = message(&[set(2, &body)]);
    let mut cache = Learned::default();
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.templates_learned, 0);
    assert!(cache.is_empty());
}

#[test]
fn the_template_cache_is_bounded() {
    let mut cache = Learned::new(Limits {
        max_templates_per_source: 2,
        ..Limits::default()
    });

    let sets: Vec<Vec<u8>> = (256..262u16)
        .map(|id| template(id, &plain_fields()))
        .collect();
    let p = message(&sets);
    let (_, out) = ipfix::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.templates_learned, 2);
    assert_eq!(out.templates_refused, 4);
}

#[test]
fn every_truncation_of_a_valid_message_is_an_error_or_a_count_and_never_a_panic() {
    let full = message(&[
        template(256, &plain_fields()),
        set(256, &plain_record(START_MS, END_MS)),
    ]);

    for cut in 0..full.len() {
        let mut cache = Learned::default();
        let _ = ipfix::decode(&full[..cut], ONE, &mut cache);
    }
    let mut cache = Learned::default();
    assert!(ipfix::decode(&full, ONE, &mut cache).is_ok());
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut seed = 0x1234_5678_9abc_def1u64;
    for len in 0..300usize {
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = u8::try_from((seed >> 24) & 0xff).expect("masked to a byte");
        }
        if len >= 4 {
            buf[0..2].copy_from_slice(&10u16.to_be_bytes());
            let l = u16::try_from(len).unwrap();
            buf[2..4].copy_from_slice(&l.to_be_bytes());
        }
        let mut cache = Learned::default();
        let _ = ipfix::decode(&buf, ONE, &mut cache);
    }
}
