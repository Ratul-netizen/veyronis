//! Splitting a JWS and checking its signature — RFC 7515.
//!
//! # The algorithm comes from the key, not from the token
//!
//! This is the whole of it. A JWS header names an algorithm, and a verifier that reads
//! that name and does what it says has handed the choice of algorithm to whoever wrote
//! the token. Two attacks follow directly: `alg: none`, where the verifier is told not
//! to check anything; and `alg: HS256` against a verifier holding an RSA *public* key,
//! which is a published value — the attacker signs with it and the verifier, obligingly
//! symmetric, agrees.
//!
//! So the header's `alg` is treated as a **filter over the provider's keys**, never as
//! an instruction. [`crate::jwk::Alg`] cannot represent `none` or an HMAC, so a token
//! naming one selects no key and fails before any signature is examined.
//!
//! # And the signature covers the encoded form
//!
//! `header.payload` as it arrived, byte for byte — not a re-encoding of the parsed
//! claims. Re-encoding would mean verifying one document and reading another, and every
//! difference between the two is somewhere to hide a claim.

use rsa::signature::Verifier as _;
use sha2::{Digest as _, Sha256};

use crate::b64;
use crate::error::{Error, Result};
use crate::jwk::{Alg, Jwk, Jwks, Material};

/// A compact JWS, split but not yet trusted.
#[derive(Clone, Debug)]
pub struct Jws {
    /// `header.payload`, exactly as it arrived. What the signature covers.
    signed: String,
    /// The decoded header.
    pub alg: Alg,
    pub kid: Option<String>,
    /// The decoded payload, still untrusted.
    pub payload: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

impl Jws {
    /// Split a compact serialization into its parts.
    ///
    /// Nothing here is trusted afterwards. The payload is decoded so that the *caller*
    /// can verify first and read second, which is the order [`Jws::verify`] enforces by
    /// consuming `self`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for anything that is not three base64url segments, and
    /// [`Error::Algorithm`] for a header naming an algorithm this product will not use.
    pub fn parse(token: &str) -> Result<Self> {
        // A JWE is five segments and is not a JWS. Counting first gives that case an
        // honest message rather than "malformed".
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() == 5 {
            return Err(Error::Malformed(
                "this is an encrypted token (JWE); this product accepts signed tokens",
            ));
        }
        let [header_b64, payload_b64, signature_b64] = parts.as_slice() else {
            return Err(Error::Malformed("a JWS is three dot-separated segments"));
        };

        let header_bytes =
            b64::decode(header_b64).ok_or(Error::Malformed("the header is not base64url"))?;
        let header: Header = serde_json::from_slice(&header_bytes)
            .map_err(|_| Error::Malformed("the header is not JSON"))?;

        let alg = Alg::parse(&header.alg).ok_or_else(|| Error::Algorithm(header.alg.clone()))?;

        let payload =
            b64::decode(payload_b64).ok_or(Error::Malformed("the payload is not base64url"))?;
        let signature =
            b64::decode(signature_b64).ok_or(Error::Malformed("the signature is not base64url"))?;

        Ok(Self {
            // Not `format!("{header_b64}.{payload_b64}")` for elegance — for accuracy.
            // These are the bytes the provider signed, and reconstructing them from
            // anything else would be verifying a document nobody produced.
            signed: format!("{header_b64}.{payload_b64}"),
            alg,
            kid: header.kid,
            payload,
            signature,
        })
    }

    /// Check the signature against the provider's key set, and hand back the payload.
    ///
    /// Consuming `self` is the point: there is no way to read the claims of a token
    /// whose signature has not been checked, because reading them is what this returns.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] when no key verified it — which covers both "the provider
    /// publishes no key that could have signed this" and "one could have and did not".
    /// They are one fact to anybody who can act on it.
    pub fn verify(self, keys: &Jwks) -> Result<Vec<u8>> {
        let candidates = keys.candidates(self.kid.as_deref(), self.alg);

        // Every candidate is tried rather than only the first. During a rotation a
        // provider publishes two keys and signs with one, and which one is not
        // something this end can know.
        for key in candidates {
            if verify_with(key, self.signed.as_bytes(), &self.signature) {
                return Ok(self.payload);
            }
        }
        Err(Error::Signature)
    }
}

/// One key against one signature. `false` for every failure, including a malformed key.
fn verify_with(key: &Jwk, signed: &[u8], signature: &[u8]) -> bool {
    match &key.material {
        Material::Rsa { n, e } => {
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use rsa::{BigUint, RsaPublicKey};

            let Ok(public) = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
            else {
                return false;
            };
            let Ok(sig) = Signature::try_from(signature) else {
                return false;
            };
            VerifyingKey::<Sha256>::new(public).verify(signed, &sig).is_ok()
        }
        Material::P256 { x, y } => {
            use p256::ecdsa::{Signature, VerifyingKey};
            use p256::elliptic_curve::sec1::FromEncodedPoint as _;
            use p256::{AffinePoint, EncodedPoint};

            let point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
            let maybe: Option<AffinePoint> = AffinePoint::from_encoded_point(&point).into();
            let Some(affine) = maybe else {
                return false;
            };
            let Ok(public) = VerifyingKey::from_affine(affine) else {
                return false;
            };
            // Fixed-width r‖s, 64 bytes. `from_slice` also accepts nothing else, which
            // is worth having: an ASN.1-wrapped signature is a different encoding of the
            // same numbers, and JWS specifies exactly one of them.
            let Ok(sig) = Signature::from_slice(signature) else {
                return false;
            };
            public.verify(signed, &sig).is_ok()
        }
    }
}

/// SHA-256, for the PKCE challenge and the `at_hash`/`c_hash` claims.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_two_segment_token_is_malformed() {
        assert!(matches!(
            Jws::parse("aGVhZGVy.cGF5bG9hZA").unwrap_err(),
            Error::Malformed(_)
        ));
    }

    #[test]
    fn an_encrypted_token_says_so() {
        let err = Jws::parse("a.b.c.d.e").unwrap_err();
        let Error::Malformed(why) = err else {
            panic!("expected Malformed, got {err:?}")
        };
        assert!(why.contains("JWE"), "{why}");
    }

    #[test]
    fn alg_none_is_refused_before_anything_else_happens() {
        // The canonical JWT attack: a header saying not to check, and a verifier that
        // obliges. It must fail at parse, not at verification — there is no key set
        // here to verify against and it still fails.
        let header = b64::encode(br#"{"alg":"none"}"#);
        let payload = b64::encode(br#"{"sub":"admin"}"#);
        let token = format!("{header}.{payload}.");
        assert!(matches!(
            Jws::parse(&token).unwrap_err(),
            Error::Algorithm(a) if a == "none"
        ));
    }

    #[test]
    fn hmac_is_refused_for_the_same_reason() {
        // The other half: HS256 verified with the provider's *published* RSA modulus as
        // the shared secret. The defence is not to implement HMAC at all.
        let header = b64::encode(br#"{"alg":"HS256","kid":"k1"}"#);
        let payload = b64::encode(br#"{"sub":"admin"}"#);
        let token = format!("{header}.{payload}.c2ln");
        assert!(matches!(
            Jws::parse(&token).unwrap_err(),
            Error::Algorithm(a) if a == "HS256"
        ));
    }

    #[test]
    fn the_signed_bytes_are_the_ones_that_arrived() {
        // Not a re-encoding of the parsed header and claims. The payload below has a
        // space in it that a re-encoding would drop, and the signature covers the
        // version with the space.
        let header = b64::encode(br#"{"alg":"RS256"}"#);
        let payload = b64::encode(br#"{"sub": "one"}"#);
        let jws = Jws::parse(&format!("{header}.{payload}.c2ln")).unwrap();
        assert_eq!(jws.signed, format!("{header}.{payload}"));
        assert_eq!(jws.payload, br#"{"sub": "one"}"#);
    }
}
