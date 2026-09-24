//! base64url, strictly, without padding — RFC 7515 §2.
//!
//! Hand-written rather than imported, and the reason is the word *strictly*. A general
//! base64 crate is lenient by default: it will accept `+` and `/`, accept padding, and
//! in some configurations ignore trailing bits. Every one of those leniencies means two
//! different encodings decode to the same bytes, and a JWS is verified over the encoded
//! form while its claims are read from the decoded one. That gap is where signature
//! confusion lives.
//!
//! So this decoder rejects anything that is not exactly what RFC 7515 says to produce:
//! the URL alphabet, no padding, and a final quantum whose unused bits are zero.

/// Decode base64url with no padding.
///
/// Returns `None` for any input that is not a canonical encoding — including one that
/// a lenient decoder would happily accept.
#[must_use]
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();

    // 1 mod 4 cannot arise: six bits is not enough for a byte, so an encoder never
    // produces it and only a corrupt or crafted token contains it.
    if bytes.len() % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &b in bytes {
        let six = sextet(b)?;
        acc = (acc << 6) | u32::from(six);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Masked to eight bits, so the conversion is exact by construction.
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or_default());
        }
    }

    // The leftover bits of a short final quantum are padding and an encoder writes them
    // as zero. Anything else is a second encoding of the same bytes, which is exactly
    // the ambiguity this decoder exists to refuse.
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }

    Some(out)
}

/// Encode base64url with no padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = |i: usize| chunk.get(i).map_or(0u32, |v| u32::from(*v));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        // 3 bytes → 4 characters, 2 → 3, 1 → 2. The dropped characters encode only the
        // zero bits `b` supplied, which is what "no padding" means.
        let take = chunk.len() + 1;
        for i in 0..take {
            let shift = 18 - 6 * i;
            out.push(ALPHABET[((n >> shift) & 0x3f) as usize] as char);
        }
    }
    out
}

/// Encode *standard* base64, with padding — RFC 4648 §4.
///
/// One caller: the `Authorization: Basic` header of the token request, which RFC 7617
/// defines over standard base64 and not the URL alphabet. Kept beside its sibling
/// rather than in the HTTP module so that the two alphabets are visible together and
/// nobody reaches for the wrong one.
#[must_use]
pub fn encode_standard(bytes: &[u8]) -> String {
    let mut out = encode(bytes).replace('-', "+").replace('_', "/");
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

/// One character to its six bits. `None` for anything outside the URL alphabet —
/// including `+`, `/` and `=`, which belong to standard base64 and not to this one.
const fn sextet(b: u8) -> Option<u8> {
    Some(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_length_of_tail() {
        for n in 0..32 {
            let bytes: Vec<u8> = (0..n)
                .map(|i: u8| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            let encoded = encode(&bytes);
            assert!(!encoded.contains('='), "padding was emitted: {encoded}");
            assert_eq!(
                decode(&encoded).as_deref(),
                Some(&bytes[..]),
                "at length {n}"
            );
        }
    }

    #[test]
    fn agrees_with_the_example_in_rfc_7515() {
        // Appendix A.1, the JWS Protected Header, byte for byte — CRLF and all. Its
        // encoding is printed in the RFC, which makes this a vector rather than a
        // restatement of this file’s own arithmetic.
        //
        // The CR is written as a byte rather than an escape: a literal CRLF inside a
        // string does not survive every checkout on this platform, and a vector that
        // changes with a line-ending setting is not a vector.
        let mut header = br#"{"typ":"JWT","#.to_vec();
        header.extend_from_slice(&[0x0d, 0x0a]);
        header.extend_from_slice(br#" "alg":"HS256"}"#);
        let expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
        assert_eq!(encode(&header), expected);
        assert_eq!(decode(expected).as_deref(), Some(&header[..]));
    }

    #[test]
    fn the_standard_alphabet_is_available_separately_and_padded() {
        // RFC 4648 §10's own vectors. `Authorization: Basic` is defined over this
        // alphabet, and using the URL one there produces a header the server rejects
        // for a reason nobody can see.
        assert_eq!(encode_standard(b""), "");
        assert_eq!(encode_standard(b"f"), "Zg==");
        assert_eq!(encode_standard(b"fo"), "Zm8=");
        assert_eq!(encode_standard(b"foo"), "Zm9v");
        assert_eq!(encode_standard(b"foobar"), "Zm9vYmFy");
        // The two alphabets differ on exactly these two sextets.
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(encode_standard(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn refuses_the_standard_alphabet() {
        // `+` and `/` are base64, not base64url. A decoder that accepted both would
        // give two encodings of the same bytes, and a JWS is signed over the encoding.
        assert_eq!(decode("ab+d"), None);
        assert_eq!(decode("ab/d"), None);
    }

    #[test]
    fn refuses_padding() {
        assert_eq!(decode("Zg=="), None);
        assert_eq!(decode("Zm8="), None);
    }

    #[test]
    fn refuses_a_length_that_no_encoder_produces() {
        // One character is six bits: not enough for a byte, so nothing ever emits it.
        assert_eq!(decode("A"), None);
        assert_eq!(decode("ZZZZZ"), None);
    }

    #[test]
    fn refuses_a_non_canonical_final_quantum() {
        // "Zh" and "Zg" both decode to `f` under a lenient decoder: the trailing four
        // bits are unused, and only `Zg` sets them to zero. Accepting both is how one
        // token gets two encodings, which is one more than a signature covers.
        assert_eq!(decode("Zg").as_deref(), Some(&b"f"[..]));
        assert_eq!(decode("Zh"), None);
    }

    #[test]
    fn refuses_whitespace_and_unicode() {
        assert_eq!(decode("Zg Zg"), None);
        assert_eq!(decode("Zg\n"), None);
        assert_eq!(decode("Zgé"), None);
    }
}
