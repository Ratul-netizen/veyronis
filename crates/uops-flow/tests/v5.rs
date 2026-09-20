//! `NetFlow` v5 decoding — `docs/M7-flow.md` §2.1, §2.4 and the fourth acceptance
//! criterion's "one dropped packet rather than a panic".
//!
//! Every case here is a byte array. That is the point of the crate having no I/O: a
//! parser reading attacker-reachable input off an unauthenticated port has to be
//! exercisable exhaustively without a network.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{TimeZone, Utc};
use uops_flow::{Error, v5};

/// Wall clock at export, and the device uptime at that moment.
const EXPORT_SECS: u32 = 1_789_000_000;
const UPTIME_MS: u32 = 10_000_000;

/// Build a v5 datagram. `sampling` is the raw header field, mode bits and all.
fn packet(records: &[[u8; 48]], sampling: u16) -> Vec<u8> {
    let count = u16::try_from(records.len()).expect("fixtures never exceed u16");
    let mut p = Vec::new();
    p.extend_from_slice(&5u16.to_be_bytes());
    p.extend_from_slice(&count.to_be_bytes());
    p.extend_from_slice(&UPTIME_MS.to_be_bytes());
    p.extend_from_slice(&EXPORT_SECS.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes()); // unix_nsecs
    p.extend_from_slice(&7u32.to_be_bytes()); // flow_sequence
    p.push(1); // engine_type
    p.push(2); // engine_id
    p.extend_from_slice(&sampling.to_be_bytes());
    for r in records {
        p.extend_from_slice(r);
    }
    p
}

/// One record with everything at its documented offset.
#[allow(clippy::too_many_arguments)]
fn record(
    src: [u8; 4],
    dst: [u8; 4],
    packets: u32,
    octets: u32,
    first_ms: u32,
    last_ms: u32,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    protocol: u8,
) -> [u8; 48] {
    let mut r = [0u8; 48];
    r[0..4].copy_from_slice(&src);
    r[4..8].copy_from_slice(&dst);
    r[8..12].copy_from_slice(&[0, 0, 0, 0]); // nexthop
    r[12..14].copy_from_slice(&11u16.to_be_bytes()); // input ifIndex
    r[14..16].copy_from_slice(&22u16.to_be_bytes()); // output ifIndex
    r[16..20].copy_from_slice(&packets.to_be_bytes());
    r[20..24].copy_from_slice(&octets.to_be_bytes());
    r[24..28].copy_from_slice(&first_ms.to_be_bytes());
    r[28..32].copy_from_slice(&last_ms.to_be_bytes());
    r[32..34].copy_from_slice(&src_port.to_be_bytes());
    r[34..36].copy_from_slice(&dst_port.to_be_bytes());
    r[36] = 0xff; // pad1 — deliberately not zero, see the tcp_flags test
    r[37] = tcp_flags;
    r[38] = protocol;
    r[39] = 0x10; // tos
    r[40..42].copy_from_slice(&64500u16.to_be_bytes()); // src_as
    r[42..44].copy_from_slice(&15169u16.to_be_bytes()); // dst_as
    r
}

fn one() -> [u8; 48] {
    record(
        [10, 0, 0, 7],
        [8, 8, 8, 8],
        42,
        6000,
        UPTIME_MS - 5_000,
        UPTIME_MS - 1_000,
        51_000,
        443,
        0x1b,
        6,
    )
}

#[test]
fn a_record_decodes_every_field_from_its_documented_offset() {
    let (header, flows) = v5::decode(&packet(&[one()], 0)).unwrap();

    assert_eq!(header.count, 1);
    assert_eq!(header.sequence, 7);
    assert_eq!(header.engine, (1, 2));

    let f = flows[0];
    assert_eq!(f.src_address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
    assert_eq!(f.dst_address, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(f.src_port, 51_000);
    assert_eq!(f.dst_port, 443);
    assert_eq!(f.protocol, 6);
    assert_eq!(f.packets, 42);
    assert_eq!(f.bytes, 6000);
    assert_eq!(f.tos, 0x10);
    assert_eq!(f.input_if, Some(11));
    assert_eq!(f.output_if, Some(22));
    assert_eq!(f.src_as, Some(64500));
    assert_eq!(f.dst_as, Some(15169));
}

#[test]
fn tcp_flags_come_from_offset_37_and_not_from_the_pad_byte_before_it() {
    // Offset 36 is padding and 37 is the flags. Reading 36 is a classic v5 mistake; the
    // fixture puts 0xff in the pad so that getting it wrong is loud rather than a
    // plausible-looking flag set.
    let f = v5::decode(&packet(&[one()], 0)).unwrap().1[0];
    assert_eq!(f.tcp_flags, 0x1b);
}

#[test]
fn the_absolute_time_is_recovered_from_the_device_uptime() {
    // The record says the flow ended 1 000 ms before the export uptime, so it ended one
    // second before the export wall clock — and began five seconds before it.
    let f = v5::decode(&packet(&[one()], 0)).unwrap().1[0];
    let exported = Utc.timestamp_opt(i64::from(EXPORT_SECS), 0).unwrap();

    assert_eq!(f.observed_at, exported - chrono::Duration::seconds(1));
    assert_eq!(f.started_at, exported - chrono::Duration::seconds(5));
    assert_eq!(f.observed_at - f.started_at, chrono::Duration::seconds(4));
}

#[test]
fn a_flow_that_began_before_the_uptime_counter_wrapped_is_not_dated_in_the_future() {
    // sys_uptime is milliseconds in a u32 and wraps after 49.7 days. A device just past
    // the wrap reports a small header uptime and a record uptime near u32::MAX for any
    // flow that started before it.
    //
    // Signed arithmetic here puts the flow about seven weeks in the future, which is the
    // bug this test exists for: the row would be outside every query window, so the
    // symptom is not a wrong timestamp on a screen but traffic that silently vanishes.
    let mut p = packet(
        &[record(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1,
            100,
            u32::MAX - 4_000,
            u32::MAX - 1_000,
            1,
            2,
            0,
            17,
        )],
        0,
    );
    // Header uptime 2 000 ms — the counter wrapped 2 seconds ago.
    p[4..8].copy_from_slice(&2_000u32.to_be_bytes());

    let f = v5::decode(&p).unwrap().1[0];
    let exported = Utc.timestamp_opt(i64::from(EXPORT_SECS), 0).unwrap();

    // u32::MAX - 1_000 is 1 001 ms before the wrap, and the header is 2 000 ms after it:
    // 3 001 ms of elapsed time, not seven weeks.
    assert_eq!(
        f.observed_at,
        exported - chrono::Duration::milliseconds(3_001)
    );
    assert!(f.observed_at < exported, "dated after its own export");
    assert!(f.started_at < f.observed_at);
}

#[test]
fn an_unsampled_export_has_a_rate_of_one_whatever_is_in_the_interval_bits() {
    // Mode 0 means "not sampling", and the interval bits are then not meaningful — some
    // exporters leave rubbish in them. Reading the field whole would scale a fully
    // observed flow by that rubbish.
    let (header, flows) = v5::decode(&packet(&[one()], 0x3fff)).unwrap();
    assert_eq!(header.sampling_rate, 1);
    assert_eq!(flows[0].sampling_rate, 1);
}

#[test]
fn a_sampled_export_carries_its_rate_onto_every_flow() {
    // Mode 1, interval 1000: one packet in a thousand was seen.
    let field = (1u16 << 14) | 0x03e8; // mode 1, interval 1000
    let (header, flows) = v5::decode(&packet(&[one(), one()], field)).unwrap();

    assert_eq!(header.sampling_rate, 1000);
    for f in &flows {
        assert_eq!(
            f.sampling_rate, 1000,
            "the rate is on the flow, not just the header"
        );
        // §2.4: what is stored is what was observed. The multiplication is the reader's.
        assert_eq!(f.bytes, 6000);
    }
}

#[test]
fn a_claimed_sampling_interval_of_zero_becomes_one() {
    // Every consumer multiplies by this. A zero would turn every byte count into nothing
    // — silently, and only for the exporter that is misconfigured.
    let field = 1u16 << 14; // sampling mode, interval 0
    assert_eq!(
        v5::decode(&packet(&[one()], field))
            .unwrap()
            .0
            .sampling_rate,
        1
    );
}

#[test]
fn thirty_records_is_the_protocol_limit_and_all_of_them_decode() {
    let records = vec![one(); 30];
    let (header, flows) = v5::decode(&packet(&records, 0)).unwrap();
    assert_eq!(header.count, 30);
    assert_eq!(flows.len(), 30);
}

#[test]
fn a_header_claiming_more_records_than_arrived_is_refused_rather_than_read_past() {
    // The shape a hostile packet takes: a small datagram claiming a full complement of
    // records, hoping the reader walks 1 440 bytes off the end of the buffer.
    let mut p = packet(&[one()], 0);
    p[2..4].copy_from_slice(&30u16.to_be_bytes());

    match v5::decode(&p) {
        Err(Error::CountExceedsPacket { claimed, got, .. }) => {
            assert_eq!(claimed, 30);
            assert_eq!(got, p.len());
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_count_beyond_the_protocol_limit_is_refused() {
    let mut p = packet(&[one()], 0);
    p[2..4].copy_from_slice(&31u16.to_be_bytes());
    assert!(matches!(v5::decode(&p), Err(Error::Invalid { .. })));
}

#[test]
fn a_datagram_with_no_records_is_valid_and_empty() {
    // Exporters send these as a keepalive. Not an error: the sequence number in the
    // header is still how a gap is detected.
    let (header, flows) = v5::decode(&packet(&[], 0)).unwrap();
    assert_eq!(header.count, 0);
    assert!(flows.is_empty());
    assert_eq!(header.sequence, 7);
}

#[test]
fn another_version_is_named_rather_than_guessed_at() {
    let mut p = packet(&[one()], 0);
    p[0..2].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(v5::decode(&p), Err(Error::UnknownVersion { got: 9 }));
}

#[test]
fn every_truncation_of_a_valid_packet_is_an_error_and_never_a_panic() {
    // The acceptance criterion, as an exhaustive case rather than a sampled one: a
    // datagram cut at any point must produce a caught error. A panic here is a denial of
    // service against a port anything on the network can reach.
    let full = packet(&[one(), one()], 0);
    for cut in 0..full.len() {
        let result = v5::decode(&full[..cut]);
        assert!(
            result.is_err(),
            "a packet truncated to {cut} bytes decoded as if it were whole"
        );
    }
    assert!(
        v5::decode(&full).is_ok(),
        "the untruncated packet must decode"
    );
}

#[test]
fn a_packet_of_arbitrary_bytes_never_panics() {
    // Not a fuzzer — it is deterministic and it is cheap enough to keep in the suite.
    // The real one is a separate piece of work; this stops the obvious regression.
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for len in 0..200usize {
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            // Truncation is the point: one byte out of a 64-bit state.
            *b = u8::try_from((seed >> 24) & 0xff).expect("masked to a byte");
        }
        // Force the version through often enough to reach the record loop.
        if len >= 2 {
            buf[0..2].copy_from_slice(&5u16.to_be_bytes());
        }
        let _ = v5::decode(&buf);
    }
}
