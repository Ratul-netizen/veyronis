//! sFlow v5 — `docs/M7-flow.md` §2.4's fifth acceptance criterion: "an sFlow v5 sample
//! carries its sampling rate into the row, and a query that sums bytes multiplies by it".
//!
//! This decoder parses real frames, so the fixtures build real frames: Ethernet, VLAN
//! tags, IPv4 and IPv6 headers, TCP and UDP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{TimeZone, Utc};
use uops_flow::{Error, sflow};

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_789_000_000, 0).unwrap()
}

const AGENT: [u8; 4] = [192, 0, 2, 1];

/// An sFlow datagram carrying `samples`, each already `(format, body)`.
fn datagram(samples: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&5u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes()); // agent address type: IPv4
    p.extend_from_slice(&AGENT);
    p.extend_from_slice(&0u32.to_be_bytes()); // sub-agent
    p.extend_from_slice(&11u32.to_be_bytes()); // sequence
    p.extend_from_slice(&50_000u32.to_be_bytes()); // uptime
    p.extend_from_slice(&u32::try_from(samples.len()).unwrap().to_be_bytes());
    for (format, body) in samples {
        p.extend_from_slice(&format.to_be_bytes());
        p.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        p.extend_from_slice(body);
    }
    p
}

/// A compact flow sample wrapping one raw-packet-header record.
fn flow_sample(rate: u32, records: &[Vec<u8>]) -> (u32, Vec<u8>) {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_be_bytes()); // sequence
    b.extend_from_slice(&0x0100_000bu32.to_be_bytes()); // source id: type 1, index 11
    b.extend_from_slice(&rate.to_be_bytes());
    b.extend_from_slice(&100_000u32.to_be_bytes()); // sample pool
    b.extend_from_slice(&0u32.to_be_bytes()); // drops
    b.extend_from_slice(&0x0000_000bu32.to_be_bytes()); // input ifIndex 11
    b.extend_from_slice(&0x0000_0016u32.to_be_bytes()); // output ifIndex 22
    b.extend_from_slice(&u32::try_from(records.len()).unwrap().to_be_bytes());
    for r in records {
        b.extend_from_slice(r);
    }
    (1, b)
}

/// The expanded layout, which splits the packed fields and moves everything after them.
fn flow_sample_expanded(rate: u32, records: &[Vec<u8>]) -> (u32, Vec<u8>) {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_be_bytes()); // sequence
    b.extend_from_slice(&1u32.to_be_bytes()); // source id type
    b.extend_from_slice(&11u32.to_be_bytes()); // source id index
    b.extend_from_slice(&rate.to_be_bytes());
    b.extend_from_slice(&100_000u32.to_be_bytes()); // sample pool
    b.extend_from_slice(&0u32.to_be_bytes()); // drops
    b.extend_from_slice(&0u32.to_be_bytes()); // input format
    b.extend_from_slice(&11u32.to_be_bytes()); // input value
    b.extend_from_slice(&0u32.to_be_bytes()); // output format
    b.extend_from_slice(&22u32.to_be_bytes()); // output value
    b.extend_from_slice(&u32::try_from(records.len()).unwrap().to_be_bytes());
    for r in records {
        b.extend_from_slice(r);
    }
    (3, b)
}

/// A raw packet header record around `frame`, claiming the frame was `frame_length` long.
fn raw_header(frame: &[u8], frame_length: u32) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&1u32.to_be_bytes()); // record format: raw packet header
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes()); // header protocol: Ethernet
    body.extend_from_slice(&frame_length.to_be_bytes());
    body.extend_from_slice(&4u32.to_be_bytes()); // stripped (FCS)
    body.extend_from_slice(&u32::try_from(frame.len()).unwrap().to_be_bytes());
    body.extend_from_slice(frame);
    r.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    r.extend_from_slice(&body);
    r
}

/// Ethernet header, with an optional stack of VLAN tags.
fn ethernet(ethertype: u16, vlans: &[u16]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    f.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src
    for vid in vlans {
        f.extend_from_slice(&0x8100u16.to_be_bytes());
        f.extend_from_slice(&vid.to_be_bytes());
    }
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

/// An IPv4 header, then whatever follows it.
fn ipv4(protocol: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    h.push(0x45); // version 4, 5 words of header
    h.push(0x10); // tos
    h.extend_from_slice(&(20u16 + u16::try_from(payload.len()).unwrap()).to_be_bytes());
    h.extend_from_slice(&0u16.to_be_bytes()); // id
    h.extend_from_slice(&0u16.to_be_bytes()); // flags, fragment
    h.push(64); // ttl
    h.push(protocol);
    h.extend_from_slice(&0u16.to_be_bytes()); // checksum
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h.extend_from_slice(payload);
    h
}

fn tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&src_port.to_be_bytes());
    t.extend_from_slice(&dst_port.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes()); // seq
    t.extend_from_slice(&0u32.to_be_bytes()); // ack
    t.push(0x50); // data offset
    t.push(flags);
    t.extend_from_slice(&0u16.to_be_bytes()); // window
    t.extend_from_slice(&0u16.to_be_bytes()); // checksum
    t.extend_from_slice(&0u16.to_be_bytes()); // urgent
    t
}

fn udp(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&src_port.to_be_bytes());
    u.extend_from_slice(&dst_port.to_be_bytes());
    u.extend_from_slice(&8u16.to_be_bytes()); // length
    u.extend_from_slice(&0u16.to_be_bytes()); // checksum
    u
}

/// The ordinary case: one sampled TCP packet.
fn tcp_frame() -> Vec<u8> {
    let mut f = ethernet(0x0800, &[]);
    f.extend_from_slice(&ipv4(
        6,
        [10, 0, 0, 7],
        [8, 8, 8, 8],
        &tcp(51_000, 443, 0x18),
    ));
    f
}

#[test]
fn a_sampled_tcp_packet_becomes_a_flow() {
    let p = datagram(&[flow_sample(1000, &[raw_header(&tcp_frame(), 1514)])]);
    let (header, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(header.agent, IpAddr::V4(Ipv4Addr::from(AGENT)));
    assert_eq!(header.sequence, 11);
    assert_eq!(out.flows.len(), 1);

    let f = out.flows[0];
    assert_eq!(f.src_address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
    assert_eq!(f.dst_address, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(f.src_port, 51_000);
    assert_eq!(f.dst_port, 443);
    assert_eq!(f.protocol, 6);
    assert_eq!(f.tcp_flags, 0x18);
    assert_eq!(f.tos, 0x10);
    assert_eq!(f.input_if, Some(11));
    assert_eq!(f.output_if, Some(22));
    assert_eq!(f.observed_at, now(), "sFlow carries no clock of its own");
}

#[test]
fn bytes_is_the_frames_real_length_and_not_the_captured_slice() {
    // The capture is a 54-byte header; the packet was 1514 bytes. Reporting the capture
    // under-reports by a factor of thirty, on top of the sampling factor — and both
    // errors point the same way, so they compound.
    let frame = tcp_frame();
    assert!(frame.len() < 100, "the fixture must be a partial capture");

    let p = datagram(&[flow_sample(1000, &[raw_header(&frame, 1514)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(out.flows[0].bytes, 1514);
    assert_eq!(out.flows[0].packets, 1, "one sampled packet is one packet");
}

#[test]
fn the_sampling_rate_is_carried_and_the_counts_are_left_as_observed() {
    // §2.4's fifth criterion. sFlow is the easy case: the rate is in a fixed position in
    // every flow sample, so it is never assumed.
    let p = datagram(&[flow_sample(1000, &[raw_header(&tcp_frame(), 1514)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    let f = out.flows[0];
    assert_eq!(f.sampling_rate, 1000);
    assert_eq!(f.bytes, 1514, "the decoder must not pre-multiply");
    // What a query does, and the number the operator is shown.
    assert_eq!(f.bytes * u64::from(f.sampling_rate), 1_514_000);
}

#[test]
fn a_rate_of_zero_becomes_one_rather_than_erasing_the_traffic() {
    let p = datagram(&[flow_sample(0, &[raw_header(&tcp_frame(), 1514)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();
    assert_eq!(out.flows[0].sampling_rate, 1);
}

#[test]
fn the_expanded_layout_reads_its_rate_from_the_right_place() {
    // The two layouts differ by eight bytes. Reading one as the other puts the sample
    // pool where the rate should be — 100 000 here — which is a plausible-looking rate
    // that would scale every byte count in the sample by a hundred thousand.
    let p = datagram(&[flow_sample_expanded(512, &[raw_header(&tcp_frame(), 1514)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(out.flows[0].sampling_rate, 512);
    assert_eq!(out.flows[0].input_if, Some(11));
    assert_eq!(out.flows[0].output_if, Some(22));
}

#[test]
fn a_vlan_tagged_frame_decodes_through_the_tag() {
    let mut frame = ethernet(0x0800, &[100]);
    frame.extend_from_slice(&ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], &udp(53, 40_000)));

    let p = datagram(&[flow_sample(1, &[raw_header(&frame, 300)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(out.flows[0].protocol, 17);
    assert_eq!(out.flows[0].src_port, 53);
    assert_eq!(out.flows[0].dst_port, 40_000);
}

#[test]
fn a_q_in_q_frame_decodes_through_both_tags() {
    let mut frame = ethernet(0x0800, &[100, 200]);
    frame.extend_from_slice(&ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &tcp(1, 2, 0)));

    let p = datagram(&[flow_sample(1, &[raw_header(&frame, 300)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(out.flows.len(), 1, "the second VLAN tag was not followed");
    assert_eq!(
        out.flows[0].src_address,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );
}

#[test]
fn an_ipv6_frame_decodes() {
    let mut frame = ethernet(0x86dd, &[]);
    let mut h = Vec::new();
    h.push(0x60); // version 6
    h.push(0x00);
    h.extend_from_slice(&0u16.to_be_bytes()); // flow label
    h.extend_from_slice(&20u16.to_be_bytes()); // payload length
    h.push(6); // next header: TCP
    h.push(64); // hop limit
    h.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    h.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
    h.extend_from_slice(&tcp(4000, 80, 0x02));
    frame.extend_from_slice(&h);

    let p = datagram(&[flow_sample(1, &[raw_header(&frame, 300)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(
        out.flows[0].src_address,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!(out.flows[0].protocol, 6);
    assert_eq!(out.flows[0].src_port, 4000);
    assert_eq!(out.flows[0].dst_port, 80);
}

#[test]
fn a_capture_that_stops_inside_the_ip_header_yields_no_flow_rather_than_a_wrong_one() {
    let mut frame = ethernet(0x0800, &[]);
    frame.extend_from_slice(&[0x45, 0x10, 0x00]); // three bytes of IPv4 header

    let p = datagram(&[flow_sample(1, &[raw_header(&frame, 1514)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert!(out.flows.is_empty());
    assert_eq!(out.unreadable, 1);
}

#[test]
fn a_capture_that_stops_after_the_ip_header_is_a_flow_with_no_ports() {
    // Common with a short capture length, and it is still a real conversation. Ports of
    // zero are what "the header was cut off" looks like; dropping the flow would lose
    // traffic that was genuinely observed.
    let mut frame = ethernet(0x0800, &[]);
    frame.extend_from_slice(&ipv4(6, [10, 0, 0, 7], [8, 8, 8, 8], &[]));

    let p = datagram(&[flow_sample(1, &[raw_header(&frame, 1514)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(out.flows[0].src_port, 0);
    assert_eq!(out.flows[0].dst_port, 0);
    assert_eq!(out.flows[0].bytes, 1514);
}

#[test]
fn an_icmp_packet_is_a_flow_with_no_ports() {
    let mut frame = ethernet(0x0800, &[]);
    frame.extend_from_slice(&ipv4(1, [10, 0, 0, 7], [8, 8, 8, 8], &[8, 0, 0, 0]));

    let p = datagram(&[flow_sample(1, &[raw_header(&frame, 98)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(out.flows[0].protocol, 1);
    assert_eq!(out.flows[0].src_port, 0);
}

#[test]
fn a_non_ip_frame_is_counted_rather_than_guessed_at() {
    // ARP. A real frame, not a flow this product can describe.
    let frame = ethernet(0x0806, &[]);
    let p = datagram(&[flow_sample(1, &[raw_header(&frame, 60)])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert!(out.flows.is_empty());
    assert_eq!(out.unreadable, 1);
}

#[test]
fn a_counter_sample_is_counted_and_skipped() {
    // Interface counters, which this product already gets by polling SNMP.
    let p = datagram(&[(2, vec![0u8; 32])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert!(out.flows.is_empty());
    assert_eq!(out.counter_samples, 1);
}

#[test]
fn a_datagram_mixing_counter_and_flow_samples_still_yields_the_flow() {
    let p = datagram(&[
        (2, vec![0u8; 32]),
        flow_sample(1000, &[raw_header(&tcp_frame(), 1514)]),
        (2, vec![0u8; 16]),
    ]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(out.flows.len(), 1);
    assert_eq!(out.counter_samples, 2);
}

#[test]
fn several_flow_samples_all_decode() {
    let p = datagram(&[
        flow_sample(1000, &[raw_header(&tcp_frame(), 1514)]),
        flow_sample(1000, &[raw_header(&tcp_frame(), 590)]),
    ]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert_eq!(out.flows.len(), 2);
    assert_eq!(out.flows[1].bytes, 590);
}

#[test]
fn an_ipv6_agent_address_shifts_the_header_and_is_read() {
    let mut p = Vec::new();
    p.extend_from_slice(&5u32.to_be_bytes());
    p.extend_from_slice(&2u32.to_be_bytes()); // agent address type: IPv6
    p.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9).octets());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&11u32.to_be_bytes());
    p.extend_from_slice(&50_000u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    let (format, body) = flow_sample(1000, &[raw_header(&tcp_frame(), 1514)]);
    p.extend_from_slice(&format.to_be_bytes());
    p.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    p.extend_from_slice(&body);

    let (header, out) = sflow::decode(&p, now()).unwrap();
    assert_eq!(
        header.agent,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9))
    );
    assert_eq!(out.flows.len(), 1);
}

#[test]
fn an_unknown_agent_address_type_is_refused() {
    let mut p = datagram(&[]);
    p[4..8].copy_from_slice(&7u32.to_be_bytes());
    assert!(matches!(
        sflow::decode(&p, now()),
        Err(Error::Invalid { .. })
    ));
}

#[test]
fn another_version_is_named() {
    let mut p = datagram(&[]);
    p[0..4].copy_from_slice(&4u32.to_be_bytes());
    assert!(matches!(
        sflow::decode(&p, now()),
        Err(Error::UnknownVersion { got: 4 })
    ));
}

#[test]
fn an_implausible_sample_count_is_refused_rather_than_looped_on() {
    // The count is the last word of the header: version, address type, a four-byte
    // agent address, sub-agent, sequence, uptime, then this.
    let mut p = datagram(&[]);
    p[24..28].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        sflow::decode(&p, now()),
        Err(Error::Invalid { .. })
    ));
}

#[test]
fn a_sample_claiming_more_bytes_than_arrived_is_counted_rather_than_read_past() {
    let (format, body) = flow_sample(1000, &[raw_header(&tcp_frame(), 1514)]);
    let mut p = Vec::new();
    p.extend_from_slice(&5u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&AGENT);
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&11u32.to_be_bytes());
    p.extend_from_slice(&50_000u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&format.to_be_bytes());
    p.extend_from_slice(&9000u32.to_be_bytes()); // claims far more than follows
    p.extend_from_slice(&body);

    let (_, out) = sflow::decode(&p, now()).unwrap();
    assert!(out.flows.is_empty());
    assert_eq!(out.truncated, 1);
}

#[test]
fn a_header_length_longer_than_the_record_yields_no_flow() {
    // The declared capture length is attacker-controlled, the same as IPFIX's variable
    // field lengths in a different protocol.
    let frame = tcp_frame();
    let mut record = Vec::new();
    record.extend_from_slice(&1u32.to_be_bytes());
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&1514u32.to_be_bytes());
    body.extend_from_slice(&4u32.to_be_bytes());
    body.extend_from_slice(&9000u32.to_be_bytes()); // claims 9000 bytes of frame
    body.extend_from_slice(&frame);
    record.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&body);

    let p = datagram(&[flow_sample(1000, &[record])]);
    let (_, out) = sflow::decode(&p, now()).unwrap();

    assert!(out.flows.is_empty());
    assert_eq!(out.unreadable, 1);
}

#[test]
fn every_truncation_of_a_valid_datagram_is_an_error_or_a_count_and_never_a_panic() {
    let full = datagram(&[flow_sample(1000, &[raw_header(&tcp_frame(), 1514)])]);
    for cut in 0..full.len() {
        let _ = sflow::decode(&full[..cut], now());
    }
    assert!(sflow::decode(&full, now()).is_ok());
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for len in 0..400usize {
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = u8::try_from((seed >> 24) & 0xff).expect("masked to a byte");
        }
        if len >= 8 {
            buf[0..4].copy_from_slice(&5u32.to_be_bytes());
            buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        }
        let _ = sflow::decode(&buf, now());
    }
}
