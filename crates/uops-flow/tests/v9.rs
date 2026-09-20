//! `NetFlow` v9 — `docs/M7-flow.md` §2.2, and acceptance criteria two and three.
//!
//! The template cache is the hard part of M7, so most of these are about what happens
//! when it does not have what the data needs — which on a real network is most of the
//! first minute after anything restarts.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{TimeZone, Utc};
use uops_flow::Error;
use uops_flow::v9::{self, Limits, Templates};

const EXPORT_SECS: u32 = 1_789_000_000;
const UPTIME_MS: u32 = 10_000_000;

const ONE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const TWO: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

// Field types, as RFC 3954 numbers them.
const IN_BYTES: u16 = 1;
const IN_PKTS: u16 = 2;
const PROTOCOL: u16 = 4;
const L4_SRC_PORT: u16 = 7;
const IPV4_SRC_ADDR: u16 = 8;
const L4_DST_PORT: u16 = 11;
const IPV4_DST_ADDR: u16 = 12;
const LAST_SWITCHED: u16 = 21;
const FIRST_SWITCHED: u16 = 22;
const IPV6_SRC_ADDR: u16 = 27;
const IPV6_DST_ADDR: u16 = 28;
const SAMPLING_INTERVAL: u16 = 34;

fn header(source_id: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&9u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes()); // count, advisory
    p.extend_from_slice(&UPTIME_MS.to_be_bytes());
    p.extend_from_slice(&EXPORT_SECS.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes()); // sequence
    p.extend_from_slice(&source_id.to_be_bytes());
    p
}

/// A template `FlowSet` defining one template.
fn template_set(id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(&u16::try_from(fields.len()).unwrap().to_be_bytes());
    for (kind, len) in fields {
        body.extend_from_slice(&kind.to_be_bytes());
        body.extend_from_slice(&len.to_be_bytes());
    }
    flowset(0, &body)
}

/// Wrap a body in a `FlowSet` header.
fn flowset(id: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// The layout most exporters send, in the order they send it.
fn standard_fields() -> Vec<(u16, u16)> {
    vec![
        (IPV4_SRC_ADDR, 4),
        (IPV4_DST_ADDR, 4),
        (L4_SRC_PORT, 2),
        (L4_DST_PORT, 2),
        (PROTOCOL, 1),
        (IN_BYTES, 4),
        (IN_PKTS, 4),
        (FIRST_SWITCHED, 4),
        (LAST_SWITCHED, 4),
    ]
}

#[allow(clippy::too_many_arguments)]
fn standard_record(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    proto: u8,
    bytes: u32,
    packets: u32,
    first_ms: u32,
    last_ms: u32,
) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&src);
    r.extend_from_slice(&dst);
    r.extend_from_slice(&sport.to_be_bytes());
    r.extend_from_slice(&dport.to_be_bytes());
    r.push(proto);
    r.extend_from_slice(&bytes.to_be_bytes());
    r.extend_from_slice(&packets.to_be_bytes());
    r.extend_from_slice(&first_ms.to_be_bytes());
    r.extend_from_slice(&last_ms.to_be_bytes());
    r
}

fn one_record() -> Vec<u8> {
    standard_record(
        [10, 0, 0, 7],
        [8, 8, 8, 8],
        51_000,
        443,
        6,
        6000,
        42,
        UPTIME_MS - 5_000,
        UPTIME_MS - 1_000,
    )
}

#[test]
fn a_template_then_data_in_one_datagram_decodes() {
    let mut p = header(1);
    p.extend_from_slice(&template_set(256, &standard_fields()));
    p.extend_from_slice(&flowset(256, &one_record()));

    let mut cache = Templates::default();
    let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.templates_learned, 1);
    assert_eq!(out.flows.len(), 1);
    assert_eq!(out.awaiting_template, 0);

    let f = out.flows[0];
    assert_eq!(f.src_address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
    assert_eq!(f.dst_address, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(f.src_port, 51_000);
    assert_eq!(f.dst_port, 443);
    assert_eq!(f.protocol, 6);
    assert_eq!(f.bytes, 6000);
    assert_eq!(f.packets, 42);

    let exported = Utc.timestamp_opt(i64::from(EXPORT_SECS), 0).unwrap();
    assert_eq!(f.observed_at, exported - chrono::Duration::seconds(1));
    assert_eq!(f.started_at, exported - chrono::Duration::seconds(5));
}

#[test]
fn data_before_its_template_is_counted_and_dropped_and_the_next_datagram_decodes() {
    // The second acceptance criterion, and the normal state of affairs for the first
    // thirty seconds after anything restarts.
    let mut cache = Templates::default();

    let mut early = header(1);
    early.extend_from_slice(&flowset(256, &one_record()));
    let (_, out) = v9::decode(&early, ONE, &mut cache).unwrap();
    assert_eq!(out.awaiting_template, 1, "the drop must be counted");
    assert!(out.flows.is_empty());

    let mut later = header(1);
    later.extend_from_slice(&template_set(256, &standard_fields()));
    later.extend_from_slice(&flowset(256, &one_record()));
    let (_, out) = v9::decode(&later, ONE, &mut cache).unwrap();
    assert_eq!(out.awaiting_template, 0);
    assert_eq!(out.flows.len(), 1);
}

#[test]
fn the_cache_survives_between_datagrams() {
    let mut cache = Templates::default();

    let mut first = header(1);
    first.extend_from_slice(&template_set(256, &standard_fields()));
    v9::decode(&first, ONE, &mut cache).unwrap();

    // A later datagram with data alone — which is what an exporter sends the other 99%
    // of the time.
    let mut second = header(1);
    second.extend_from_slice(&flowset(256, &one_record()));
    let (_, out) = v9::decode(&second, ONE, &mut cache).unwrap();
    assert_eq!(out.flows.len(), 1);
}

#[test]
fn two_exporters_both_using_template_256_do_not_decode_each_others_data() {
    // The third acceptance criterion, and §2.2's cache-key decision stated as a test.
    //
    // Template IDs start at 256 on every exporter, so this collision is the normal case
    // rather than a contrived one. Keyed on the id alone, the second exporter's records
    // would be read with the first's layout — and the failure is quiet, because the
    // fields are the right width and produce plausible addresses that are wrong.
    let mut cache = Templates::default();

    // Exporter ONE: the standard layout.
    let mut a = header(1);
    a.extend_from_slice(&template_set(256, &standard_fields()));
    a.extend_from_slice(&flowset(256, &one_record()));
    let (_, out) = v9::decode(&a, ONE, &mut cache).unwrap();
    assert_eq!(out.flows.len(), 1);

    // Exporter TWO: also template 256, but IPv6 and a different field order.
    let v6_fields = vec![
        (IPV6_SRC_ADDR, 16),
        (IPV6_DST_ADDR, 16),
        (IN_BYTES, 8),
        (PROTOCOL, 1),
    ];
    let mut record = Vec::new();
    record.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    record.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
    record.extend_from_slice(&999u64.to_be_bytes());
    record.push(17);

    let mut b = header(1);
    b.extend_from_slice(&template_set(256, &v6_fields));
    b.extend_from_slice(&flowset(256, &record));
    let (_, out) = v9::decode(&b, TWO, &mut cache).unwrap();

    assert_eq!(out.flows.len(), 1);
    let f = out.flows[0];
    assert_eq!(
        f.src_address,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        "exporter TWO's record was decoded with exporter ONE's template"
    );
    assert_eq!(f.bytes, 999);
    assert_eq!(f.protocol, 17);
    assert_eq!(
        cache.len(),
        2,
        "both templates are held, not one overwritten"
    );
}

#[test]
fn one_exporters_two_observation_domains_are_separate() {
    // Same reasoning one level down: a chassis can export several domains, and each
    // numbers its templates from 256 independently.
    let mut cache = Templates::default();

    let mut a = header(1);
    a.extend_from_slice(&template_set(256, &standard_fields()));
    v9::decode(&a, ONE, &mut cache).unwrap();

    // Domain 2, same exporter, same template id, data only — the template belongs to
    // domain 1 and must not be reachable from here.
    let mut b = header(2);
    b.extend_from_slice(&flowset(256, &one_record()));
    let (_, out) = v9::decode(&b, ONE, &mut cache).unwrap();

    assert_eq!(out.awaiting_template, 1);
    assert!(out.flows.is_empty());
}

#[test]
fn a_redefined_template_replaces_the_old_one_without_counting_against_the_limit() {
    let mut cache = Templates::new(Limits {
        max_sources: 4,
        max_templates_per_source: 2,
    });

    for _ in 0..10 {
        let mut p = header(1);
        p.extend_from_slice(&template_set(256, &standard_fields()));
        let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();
        assert_eq!(out.templates_refused, 0, "re-registering is not growth");
    }
    assert_eq!(cache.len(), 1);
}

#[test]
fn the_template_cache_is_bounded_and_says_when_it_refuses() {
    // Unauthenticated UDP: without this, anything that can reach the port can make the
    // process allocate by inventing template ids.
    let mut cache = Templates::new(Limits {
        max_sources: 4,
        max_templates_per_source: 2,
    });

    let mut p = header(1);
    for id in 256..262u16 {
        p.extend_from_slice(&template_set(id, &standard_fields()));
    }
    let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.templates_learned, 2);
    assert_eq!(out.templates_refused, 4, "the refusal has to be visible");
    assert_eq!(cache.len(), 2);
}

#[test]
fn the_source_limit_bounds_exporters_as_well_as_templates() {
    let mut cache = Templates::new(Limits {
        max_sources: 2,
        max_templates_per_source: 8,
    });

    for n in 0..5u8 {
        let mut p = header(1);
        p.extend_from_slice(&template_set(256, &standard_fields()));
        let from = IpAddr::V4(Ipv4Addr::new(198, 51, 100, n));
        v9::decode(&p, from, &mut cache).unwrap();
    }
    assert_eq!(cache.len(), 2);
}

#[test]
fn a_sampling_interval_in_the_record_reaches_the_flow() {
    // §2.4. The exporters that carry the rate this way are covered; the ones that only
    // announce it in an options template are the documented gap, below.
    let mut fields = standard_fields();
    fields.push((SAMPLING_INTERVAL, 4));

    let mut record = one_record();
    record.extend_from_slice(&1000u32.to_be_bytes());

    let mut p = header(1);
    p.extend_from_slice(&template_set(256, &fields));
    p.extend_from_slice(&flowset(256, &record));

    let mut cache = Templates::default();
    let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.flows[0].sampling_rate, 1000);
    // As observed, never scaled — the multiplication belongs to the reader.
    assert_eq!(out.flows[0].bytes, 6000);
}

#[test]
fn an_options_template_is_skipped_and_counted_rather_than_silently_ignored() {
    // The known gap, made visible. An exporter that announces its sampling rate only
    // this way is currently read as unsampled, and this counter is what says so.
    let mut p = header(1);
    p.extend_from_slice(&flowset(1, &[0u8; 12]));

    let mut cache = Templates::default();
    let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();
    assert_eq!(out.options_skipped, 1);
}

#[test]
fn a_template_with_no_addresses_produces_a_count_rather_than_a_row_of_zeroes() {
    // Inventing 0.0.0.0 would put rows in the table that mean nothing, and no screen
    // downstream could tell them from real ones.
    let fields = vec![(IN_BYTES, 4), (IN_PKTS, 4)];
    let mut record = Vec::new();
    record.extend_from_slice(&100u32.to_be_bytes());
    record.extend_from_slice(&5u32.to_be_bytes());

    let mut p = header(1);
    p.extend_from_slice(&template_set(256, &fields));
    p.extend_from_slice(&flowset(256, &record));

    let mut cache = Templates::default();
    let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();

    assert!(out.flows.is_empty());
    assert_eq!(out.not_a_flow, 1);
}

#[test]
fn a_vendors_unknown_field_is_skipped_by_its_length_and_the_rest_still_decodes() {
    // The reason a template carries lengths at all. A private field must be harmless,
    // not fatal — and it must not shift every field after it.
    let mut fields = standard_fields();
    fields.insert(2, (34_000, 6)); // an enterprise field nobody here knows

    let mut record = Vec::new();
    record.extend_from_slice(&[10, 0, 0, 7]);
    record.extend_from_slice(&[8, 8, 8, 8]);
    record.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]);
    record.extend_from_slice(&51_000u16.to_be_bytes());
    record.extend_from_slice(&443u16.to_be_bytes());
    record.push(6);
    record.extend_from_slice(&6000u32.to_be_bytes());
    record.extend_from_slice(&42u32.to_be_bytes());
    record.extend_from_slice(&(UPTIME_MS - 5_000).to_be_bytes());
    record.extend_from_slice(&(UPTIME_MS - 1_000).to_be_bytes());

    let mut p = header(1);
    p.extend_from_slice(&template_set(256, &fields));
    p.extend_from_slice(&flowset(256, &record));

    let mut cache = Templates::default();
    let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(
        out.flows[0].src_port, 51_000,
        "the unknown field shifted the rest"
    );
    assert_eq!(out.flows[0].bytes, 6000);
}

#[test]
fn several_records_in_one_data_flowset_all_decode_and_padding_is_not_a_short_record() {
    let mut body = Vec::new();
    for _ in 0..3 {
        body.extend_from_slice(&one_record());
    }
    body.extend_from_slice(&[0, 0, 0]); // alignment padding

    let mut p = header(1);
    p.extend_from_slice(&template_set(256, &standard_fields()));
    p.extend_from_slice(&flowset(256, &body));

    let mut cache = Templates::default();
    let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();
    assert_eq!(out.flows.len(), 3);
    assert_eq!(out.not_a_flow, 0, "padding was read as a record");
}

#[test]
fn a_template_whose_fields_are_all_zero_width_is_refused_rather_than_looped_on() {
    // record_len would be zero, and the data reader divides by it: without the guard a
    // data FlowSet holds infinitely many records and the collector never returns.
    let mut p = header(1);
    p.extend_from_slice(&template_set(256, &[(IN_BYTES, 0), (IN_PKTS, 0)]));
    p.extend_from_slice(&flowset(256, &[0u8; 8]));

    let mut cache = Templates::default();
    let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();

    assert_eq!(out.templates_learned, 0);
    assert_eq!(
        out.awaiting_template, 1,
        "no template, so the data is dropped"
    );
    assert!(cache.is_empty());
}

#[test]
fn a_flowset_length_that_does_not_cover_its_own_header_is_refused_and_does_not_spin() {
    // A length of 0 leaves the cursor where it was. This is the packet that hangs a
    // collector rather than crashing it, which is worse: nothing looks wrong.
    let mut p = header(1);
    p.extend_from_slice(&256u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());

    let mut cache = Templates::default();
    assert!(matches!(
        v9::decode(&p, ONE, &mut cache),
        Err(Error::Invalid { .. })
    ));
}

#[test]
fn a_flowset_running_past_the_packet_is_refused() {
    let mut p = header(1);
    p.extend_from_slice(&256u16.to_be_bytes());
    p.extend_from_slice(&4000u16.to_be_bytes());
    p.extend_from_slice(&[0u8; 8]);

    let mut cache = Templates::default();
    assert!(matches!(
        v9::decode(&p, ONE, &mut cache),
        Err(Error::CountExceedsPacket { .. })
    ));
}

#[test]
fn a_flow_that_began_before_the_uptime_wrap_is_not_dated_in_the_future() {
    // The same wrap v5 has, through the same shared conversion.
    let record = standard_record(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1,
        2,
        17,
        100,
        1,
        u32::MAX - 4_000,
        u32::MAX - 1_000,
    );

    let mut p = header(1);
    p[4..8].copy_from_slice(&2_000u32.to_be_bytes()); // wrapped 2 s ago
    p.extend_from_slice(&template_set(256, &standard_fields()));
    p.extend_from_slice(&flowset(256, &record));

    let mut cache = Templates::default();
    let (_, out) = v9::decode(&p, ONE, &mut cache).unwrap();

    let exported = Utc.timestamp_opt(i64::from(EXPORT_SECS), 0).unwrap();
    assert_eq!(
        out.flows[0].observed_at,
        exported - chrono::Duration::milliseconds(3_001)
    );
}

#[test]
fn every_truncation_of_a_valid_packet_is_an_error_or_a_count_and_never_a_panic() {
    let mut full = header(1);
    full.extend_from_slice(&template_set(256, &standard_fields()));
    full.extend_from_slice(&flowset(256, &one_record()));

    for cut in 0..full.len() {
        let mut cache = Templates::default();
        // Either outcome is acceptable; a panic is not. A truncated template FlowSet is
        // recoverable — the templates before it were learned — so unlike v5 this is not
        // required to be an error.
        let _ = v9::decode(&full[..cut], ONE, &mut cache);
    }
    let mut cache = Templates::default();
    assert!(v9::decode(&full, ONE, &mut cache).is_ok());
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut seed = 0x853c_49e6_748f_ea9bu64;
    for len in 0..300usize {
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = u8::try_from((seed >> 24) & 0xff).expect("masked to a byte");
        }
        if len >= 2 {
            buf[0..2].copy_from_slice(&9u16.to_be_bytes());
        }
        let mut cache = Templates::default();
        let _ = v9::decode(&buf, ONE, &mut cache);
    }
}
