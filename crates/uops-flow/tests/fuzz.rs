//! Structure-aware fuzzing — M7's tenth acceptance criterion.
//!
//! Every decoder here already has an `arbitrary_bytes_never_panic` test, and those are
//! nearly worthless on their own: a random buffer fails the version check in the first
//! two bytes and never reaches a template, a variable-length field or a nested set. The
//! code that would actually break is the code random bytes cannot get to.
//!
//! So this builds *plausible* packets — correct version, coherent lengths, real template
//! shapes — and then breaks them: flips bytes, truncates, rewrites length fields, repeats
//! sections. That reaches the parsers' interesting paths and then lies to them there.
//!
//! # Why this is not `cargo fuzz`
//!
//! Coverage-guided fuzzing is stronger and this is not a substitute for it. libFuzzer
//! needs a nightly toolchain and a clang with sanitizer support, and the machine this was
//! written on has a stable MSVC toolchain and neither — see `docs/dev-environment.md` for
//! why that machine is what it is. `cargo fuzz` over these same decoders on a Linux host
//! is the stronger form and is recorded in `docs/M7-flow.md` as outstanding rather than
//! quietly claimed.
//!
//! What this does give, and libFuzzer does not, is a deterministic run in the ordinary
//! test suite: the same seed produces the same packets on every machine, so a failure
//! found in CI reproduces on a laptop.
//!
//! # A failure has to be reproducible or it is not a finding
//!
//! A panic is caught, and the seed, the iteration and the packet's bytes are printed
//! before it is re-raised. Without that, a fuzzer that finds something once has found
//! nothing anybody can fix.

use std::net::{IpAddr, Ipv4Addr};
use std::panic::{AssertUnwindSafe, catch_unwind};

use chrono::{TimeZone, Utc};
use uops_flow::templates::Learned;
use uops_flow::{ipfix, sflow, v5, v9};

/// Iterations per decoder.
///
/// Small enough that the suite stays fast, and overridable so that a longer soak is one
/// environment variable rather than a code change: `UOPS_FUZZ_ITERS=2000000 cargo test`.
fn iterations() -> u32 {
    std::env::var("UOPS_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

/// The seed. Fixed, so the run is the same everywhere; overridable, so a soak explores.
fn seed() -> u64 {
    std::env::var("UOPS_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5eed_1234_abcd_0001)
}

/// xorshift64*. Deterministic, seedable and fast enough not to dominate the run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A number below `n`. Modulo bias is irrelevant here: this picks which mutation to
    /// apply, not a cryptographic value.
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        usize::try_from(self.next() % n as u64).unwrap_or(0)
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next() & 0xff).expect("masked to a byte")
    }

    fn chance(&mut self, one_in: u64) -> bool {
        self.next().is_multiple_of(one_in)
    }
}

// --- builders: plausible packets, so the mutations land somewhere interesting ---------

fn v5_packet(rng: &mut Rng) -> Vec<u8> {
    let count = rng.below(31);
    let uptime: u32 = 10_000_000;
    let mut p = Vec::new();
    p.extend_from_slice(&5u16.to_be_bytes());
    p.extend_from_slice(&u16::try_from(count).unwrap().to_be_bytes());
    p.extend_from_slice(&uptime.to_be_bytes());
    p.extend_from_slice(&1_789_000_000u32.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&7u32.to_be_bytes());
    p.push(rng.byte());
    p.push(rng.byte());
    // Sometimes a sampling mode, sometimes not.
    p.extend_from_slice(&u16::try_from(rng.below(0xffff)).unwrap().to_be_bytes());

    for _ in 0..count {
        let mut r = [0u8; 48];
        for b in &mut r {
            *b = rng.byte();
        }
        p.extend_from_slice(&r);
    }
    p
}

/// A field specifier list that looks like something an exporter would send.
fn field_specs(rng: &mut Rng, ipfix_style: bool) -> (Vec<u8>, usize, usize) {
    // Real element ids, so the decoders take their interesting branches rather than
    // skipping everything as unknown.
    const KINDS: [u16; 12] = [1, 2, 4, 6, 7, 8, 11, 12, 21, 22, 34, 48];
    let n = 1 + rng.below(8);
    let mut out = Vec::new();
    let mut width = 0usize;

    for _ in 0..n {
        let kind = KINDS[rng.below(KINDS.len())];
        // Widths the elements actually use, plus the IPFIX variable marker.
        let len: u16 = if ipfix_style && rng.chance(6) {
            0xffff
        } else {
            match kind {
                8 | 12 => 4,
                7 | 11 => 2,
                4 | 6 => 1,
                _ => [1u16, 2, 4, 8][rng.below(4)],
            }
        };
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        if len != 0xffff {
            width += usize::from(len);
        }
    }
    (out, n, width)
}

fn v9_packet(rng: &mut Rng) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&9u16.to_be_bytes());
    p.extend_from_slice(&2u16.to_be_bytes());
    p.extend_from_slice(&10_000_000u32.to_be_bytes());
    p.extend_from_slice(&1_789_000_000u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&u32::try_from(rng.below(3)).unwrap().to_be_bytes());

    let id = 256 + u16::try_from(rng.below(4)).unwrap();
    let (specs, count, width) = field_specs(rng, false);

    // A template FlowSet, an options template FlowSet, or a data FlowSet — often several.
    for _ in 0..=rng.below(2) {
        match rng.below(3) {
            0 => {
                let mut body = Vec::new();
                body.extend_from_slice(&id.to_be_bytes());
                body.extend_from_slice(&u16::try_from(count).unwrap().to_be_bytes());
                body.extend_from_slice(&specs);
                flowset(&mut p, 0, &body);
            }
            1 => {
                let mut body = Vec::new();
                body.extend_from_slice(&id.to_be_bytes());
                body.extend_from_slice(&4u16.to_be_bytes()); // scope length
                body.extend_from_slice(&u16::try_from(specs.len()).unwrap().to_be_bytes());
                body.extend_from_slice(&[0, 1, 0, 4]); // one scope field
                body.extend_from_slice(&specs);
                flowset(&mut p, 1, &body);
            }
            _ => {
                let records = 1 + rng.below(4);
                let mut body = vec![0u8; records * width.max(1)];
                for b in &mut body {
                    *b = rng.byte();
                }
                flowset(&mut p, id, &body);
            }
        }
    }
    p
}

fn flowset(p: &mut Vec<u8>, id: u16, body: &[u8]) {
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    p.extend_from_slice(body);
}

fn ipfix_packet(rng: &mut Rng) -> Vec<u8> {
    let mut sets = Vec::new();
    let id = 256 + u16::try_from(rng.below(4)).unwrap();
    let (specs, count, width) = field_specs(rng, true);

    for _ in 0..=rng.below(2) {
        match rng.below(3) {
            0 => {
                let mut body = Vec::new();
                body.extend_from_slice(&id.to_be_bytes());
                body.extend_from_slice(&u16::try_from(count).unwrap().to_be_bytes());
                body.extend_from_slice(&specs);
                flowset(&mut sets, 2, &body);
            }
            1 => {
                let mut body = Vec::new();
                body.extend_from_slice(&id.to_be_bytes());
                body.extend_from_slice(&u16::try_from(count).unwrap().to_be_bytes());
                body.extend_from_slice(&1u16.to_be_bytes()); // scope count
                body.extend_from_slice(&specs);
                flowset(&mut sets, 3, &body);
            }
            _ => {
                // Variable-length fields make the width a guess, which is the point.
                let mut body = vec![0u8; (1 + rng.below(3)) * width.max(1) + rng.below(8)];
                for b in &mut body {
                    *b = rng.byte();
                }
                flowset(&mut sets, id, &body);
            }
        }
    }

    let mut p = Vec::new();
    p.extend_from_slice(&10u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes()); // length, patched below
    p.extend_from_slice(&1_789_000_000u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&u32::try_from(rng.below(3)).unwrap().to_be_bytes());
    p.extend_from_slice(&sets);

    let len = u16::try_from(p.len()).unwrap_or(u16::MAX);
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p
}

fn sflow_packet(rng: &mut Rng) -> Vec<u8> {
    let samples = rng.below(4);
    let mut p = Vec::new();
    p.extend_from_slice(&5u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&[192, 0, 2, 1]);
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&11u32.to_be_bytes());
    p.extend_from_slice(&50_000u32.to_be_bytes());
    p.extend_from_slice(&u32::try_from(samples).unwrap().to_be_bytes());

    for _ in 0..samples {
        // An Ethernet/IPv4/TCP frame, then a raw-packet-header record around it.
        let mut frame = vec![0u8; 14];
        for b in &mut frame {
            *b = rng.byte();
        }
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0u8; 20 + 20];
        for b in &mut ip {
            *b = rng.byte();
        }
        ip[0] = 0x45;
        ip[9] = [6u8, 17, 1][rng.below(3)];
        frame.extend_from_slice(&ip);

        let mut record = Vec::new();
        record.extend_from_slice(&1u32.to_be_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&1514u32.to_be_bytes());
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&u32::try_from(frame.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&frame);
        record.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&body);

        let mut sample = Vec::new();
        sample.extend_from_slice(&1u32.to_be_bytes());
        sample.extend_from_slice(&0x0100_000bu32.to_be_bytes());
        sample.extend_from_slice(&u32::try_from(1 + rng.below(2000)).unwrap().to_be_bytes());
        sample.extend_from_slice(&100_000u32.to_be_bytes());
        sample.extend_from_slice(&0u32.to_be_bytes());
        sample.extend_from_slice(&11u32.to_be_bytes());
        sample.extend_from_slice(&22u32.to_be_bytes());
        sample.extend_from_slice(&1u32.to_be_bytes());
        sample.extend_from_slice(&record);

        let format = if rng.chance(4) { 3u32 } else { 1u32 };
        p.extend_from_slice(&format.to_be_bytes());
        p.extend_from_slice(&u32::try_from(sample.len()).unwrap().to_be_bytes());
        p.extend_from_slice(&sample);
    }
    p
}

/// Break a well-formed packet in one of the ways a hostile or broken sender would.
///
/// Length fields get their own case because they are what every one of these parsers
/// trusts to walk the buffer, and they are the field an attacker actually controls.
fn mutate(packet: &mut Vec<u8>, rng: &mut Rng) {
    for _ in 0..=rng.below(3) {
        if packet.is_empty() {
            return;
        }
        match rng.below(6) {
            // Flip a byte anywhere.
            0 => {
                let at = rng.below(packet.len());
                packet[at] ^= 1 << rng.below(8);
            }
            // Replace a byte outright.
            1 => {
                let at = rng.below(packet.len());
                packet[at] = rng.byte();
            }
            // Cut it short — the commonest real corruption, and the one every `get` has
            // to survive.
            2 => {
                let keep = rng.below(packet.len());
                packet.truncate(keep);
            }
            // Rewrite a 16-bit field as something enormous. Lengths live at even offsets
            // in all four formats, so this lands on one often.
            3 => {
                if packet.len() >= 2 {
                    let at = rng.below(packet.len() - 1) & !1;
                    let value = [0xffffu16, 0x7fff, 0, 1, 0xfffe][rng.below(5)];
                    packet[at..at + 2].copy_from_slice(&value.to_be_bytes());
                }
            }
            // And as a 32-bit one, for sFlow's counts and lengths.
            4 => {
                if packet.len() >= 4 {
                    let at = rng.below(packet.len() - 3) & !3;
                    let value = [u32::MAX, 0, 1, 0x7fff_ffff][rng.below(4)];
                    packet[at..at + 4].copy_from_slice(&value.to_be_bytes());
                }
            }
            // Repeat a slice, which pushes offsets out of step without shortening it.
            _ => {
                let at = rng.below(packet.len());
                let run = packet[at..].to_vec();
                packet.extend_from_slice(&run[..run.len().min(64)]);
            }
        }
    }
}

/// Run one decoder over `iterations` generated-and-broken packets.
///
/// `decode` returns nothing: the assertion is that it returns at all.
fn soak(name: &str, mut build: impl FnMut(&mut Rng) -> Vec<u8>, mut decode: impl FnMut(&[u8])) {
    let seed = seed();
    let mut rng = Rng(seed);
    let iterations = iterations();

    for i in 0..iterations {
        let mut packet = build(&mut rng);
        mutate(&mut packet, &mut rng);

        let outcome = catch_unwind(AssertUnwindSafe(|| decode(&packet)));
        assert!(
            outcome.is_ok(),
            "{name} panicked on iteration {i} of seed {seed:#x}\n\
             reproduce with UOPS_FUZZ_SEED={seed} UOPS_FUZZ_ITERS={}\n\
             packet ({} bytes): {}",
            i + 1,
            packet.len(),
            hex(&packet),
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

#[test]
fn netflow_v5_survives_a_soak() {
    soak("v5", v5_packet, |p| {
        let _ = v5::decode(p);
    });
}

#[test]
fn netflow_v9_survives_a_soak() {
    // One cache across the whole run, on purpose: a template learned from a mutated
    // packet is then used to read the next one, which is the state-carrying path and the
    // only way to reach a decode against a layout nothing sane produced.
    let mut learned = Learned::default();
    soak("v9", v9_packet, |p| {
        let _ = v9::decode(p, EXPORTER, &mut learned);
    });
}

#[test]
fn ipfix_survives_a_soak() {
    let mut learned = Learned::default();
    soak("ipfix", ipfix_packet, |p| {
        let _ = ipfix::decode(p, EXPORTER, &mut learned);
    });
}

#[test]
fn sflow_survives_a_soak() {
    let now = Utc.timestamp_opt(1_789_000_000, 0).unwrap();
    soak("sflow", sflow_packet, |p| {
        let _ = sflow::decode(p, now);
    });
}

#[test]
fn the_generators_produce_packets_the_decoders_actually_accept() {
    // The guard on the whole file. A generator that drifted into producing garbage would
    // make every soak above pass while testing nothing but the version check — which is
    // exactly the failure mode the random-bytes tests already have.
    let mut rng = Rng(seed());
    let mut learned = Learned::default();
    let (mut v5_ok, mut v9_ok, mut ipfix_ok, mut sflow_ok) = (0, 0, 0, 0);

    for _ in 0..500 {
        if v5::decode(&v5_packet(&mut rng)).is_ok() {
            v5_ok += 1;
        }
        if v9::decode(&v9_packet(&mut rng), EXPORTER, &mut learned).is_ok() {
            v9_ok += 1;
        }
        if ipfix::decode(&ipfix_packet(&mut rng), EXPORTER, &mut learned).is_ok() {
            ipfix_ok += 1;
        }
        let now = Utc.timestamp_opt(1_789_000_000, 0).unwrap();
        if sflow::decode(&sflow_packet(&mut rng), now).is_ok() {
            sflow_ok += 1;
        }
    }

    // Unmutated, these should almost all decode. A low number means the builder is
    // wrong, not that the decoder is strict.
    assert!(
        v5_ok > 400,
        "v5 generator produced {v5_ok}/500 valid packets"
    );
    assert!(
        v9_ok > 400,
        "v9 generator produced {v9_ok}/500 valid packets"
    );
    assert!(ipfix_ok > 400, "ipfix generator produced {ipfix_ok}/500");
    assert!(sflow_ok > 400, "sflow generator produced {sflow_ok}/500");
}

#[test]
fn a_mutation_actually_changes_the_packet() {
    // Cheap, and it catches the version of this file where `mutate` silently did nothing
    // — which would make four passing soaks mean four passing round trips.
    let mut rng = Rng(99);
    let mut changed = 0;
    for _ in 0..200 {
        let original = v9_packet(&mut rng);
        let mut copy = original.clone();
        mutate(&mut copy, &mut rng);
        if copy != original {
            changed += 1;
        }
    }
    assert!(changed > 190, "only {changed}/200 packets were mutated");
}
