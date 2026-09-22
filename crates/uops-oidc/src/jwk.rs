//! The provider's public keys, as it publishes them — RFC 7517.
//!
//! # Only what is needed to verify a signature
//!
//! A JWKS in the wild carries keys for algorithms this product does not accept, keys
//! marked for encryption rather than signing, and — from at least one large provider —
//! keys with fields that are not in any RFC. A parser that refused the whole document
//! over an unknown member would stop working the day a provider added one.
//!
//! So an unrecognised key is **skipped**, not an error, and the set is whatever remains.
//! An empty set after filtering is an error, because that is the case where nothing can
//! be verified and continuing would mean accepting tokens unverified.

use serde::Deserialize;

use crate::b64;
use crate::error::{Error, Result};

/// A signing algorithm this product accepts.
///
/// A closed set, and deliberately a small one. `none` is not here and never will be —
/// the single most-exploited JWT flaw is a verifier that reads the algorithm out of the
/// token and obliges. HMAC algorithms are not here either: `HS256` with the provider's
/// *public* key as the secret is the other half of that same attack, and the only
/// defence that holds is a verifier that cannot be talked into a symmetric algorithm at
/// all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    /// RSASSA-PKCS1-v1_5 with SHA-256. Entra ID, Okta, Keycloak.
    Rs256,
    /// ECDSA P-256 with SHA-256. Google, and anything modern.
    Es256,
}

impl Alg {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "RS256" => Some(Self::Rs256),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }
}

/// One usable verification key.
#[derive(Clone, Debug)]
pub struct Jwk {
    /// The key id, matched against the token header's `kid`.
    ///
    /// Optional because a provider publishing exactly one key may omit it, and several
    /// do. Absent `kid` on both sides means "try the keys there are", which is correct
    /// and is what [`Jwks::candidates`] implements.
    pub kid: Option<String>,
    pub alg: Alg,
    pub material: Material,
}

/// The key itself, in the only two shapes this product verifies.
#[derive(Clone, Debug)]
pub enum Material {
    /// RSA modulus and exponent, big-endian.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// A P-256 point: the two affine coordinates, 32 bytes each.
    P256 { x: [u8; 32], y: [u8; 32] },
}

/// Every key a provider publishes that this product could verify with.
#[derive(Clone, Debug, Default)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    /// Parse a JWKS document.
    ///
    /// # Errors
    ///
    /// [`Error::Jwks`] when the document is not JSON in the shape RFC 7517 describes, or
    /// when nothing in it is a key this product can verify with.
    pub fn parse(body: &str) -> Result<Self> {
        let raw: RawSet = serde_json::from_str(body).map_err(|e| Error::Jwks(e.to_string()))?;

        let keys: Vec<Jwk> = raw.keys.iter().filter_map(convert).collect();

        if keys.is_empty() {
            return Err(Error::Jwks(
                "the provider published no key this product can verify with".to_owned(),
            ));
        }
        Ok(Self { keys })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The keys worth trying for a token with this header.
    ///
    /// When the token names a `kid`, that is the answer and there is at most one. When
    /// it does not, every key of the right algorithm is a candidate — which is what a
    /// provider that publishes one unnamed key requires, and what a *rotation* makes
    /// temporarily true for everyone else.
    ///
    /// Matching on `kid` alone would be a mistake: a provider is free to reuse a `kid`
    /// across algorithms, and a key whose algorithm disagrees with the header cannot
    /// verify the signature anyway.
    #[must_use]
    pub fn candidates(&self, kid: Option<&str>, alg: Alg) -> Vec<&Jwk> {
        self.keys
            .iter()
            .filter(|k| k.alg == alg)
            .filter(|k| match kid {
                // A token naming a key the provider does not publish under that name is
                // not a candidate for the provider's *other* keys. That would turn a
                // rotation mistake into a silent acceptance.
                Some(want) => k.kid.as_deref() == Some(want),
                None => true,
            })
            .collect()
    }
}

/// The JSON as the RFC defines it, before anything is decided about it.
#[derive(Debug, Deserialize)]
struct RawSet {
    keys: Vec<RawKey>,
}

#[derive(Debug, Deserialize)]
struct RawKey {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    // RSA
    n: Option<String>,
    e: Option<String>,
    // EC
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

/// One raw key to a usable one, or `None` to skip it.
fn convert(raw: &RawKey) -> Option<Jwk> {
    // `use: enc` is a key for encrypting to the provider, not for verifying its
    // signatures. Absent means unrestricted, which RFC 7517 §4.2 is explicit about.
    if raw.use_.as_deref().is_some_and(|u| u != "sig") {
        return None;
    }

    let material = match raw.kty.as_str() {
        "RSA" => {
            let n = b64::decode(raw.n.as_deref()?)?;
            let e = b64::decode(raw.e.as_deref()?)?;
            // A 1024-bit modulus is factorable by people with a budget, and no identity
            // provider has issued one this decade. Refusing it here means a
            // misconfigured or downgraded provider fails to verify rather than
            // verifying weakly, which is the direction to fail in.
            if n.len() < 256 || e.is_empty() {
                return None;
            }
            Material::Rsa { n, e }
        }
        "EC" => {
            if raw.crv.as_deref() != Some("P-256") {
                return None;
            }
            let x: [u8; 32] = b64::decode(raw.x.as_deref()?)?.try_into().ok()?;
            let y: [u8; 32] = b64::decode(raw.y.as_deref()?)?.try_into().ok()?;
            Material::P256 { x, y }
        }
        _ => return None,
    };

    // `alg` is optional in a JWKS. When it is absent the key type decides, which is
    // unambiguous for exactly the two this product accepts. When it is present and says
    // something else — an RSA key marked `RS512`, say — the key is skipped rather than
    // silently verified under an algorithm its owner did not nominate.
    let implied = match material {
        Material::Rsa { .. } => Alg::Rs256,
        Material::P256 { .. } => Alg::Es256,
    };
    let alg = match raw.alg.as_deref() {
        None => implied,
        Some(named) => {
            let parsed = Alg::parse(named)?;
            if parsed != implied {
                return None;
            }
            parsed
        }
    };

    Some(Jwk {
        kid: raw.kid.clone(),
        alg,
        material,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2048-bit modulus, as base64url. The value does not have to be a real key for
    /// parsing tests — only the right length.
    fn modulus() -> String {
        b64::encode(&[0x0b; 256])
    }

    fn rsa_key(kid: &str) -> String {
        format!(
            r#"{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{}","e":"AQAB"}}"#,
            modulus()
        )
    }

    #[test]
    fn parses_an_rsa_set() {
        let set = Jwks::parse(&format!(r#"{{"keys":[{}]}}"#, rsa_key("k1"))).unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set.candidates(Some("k1"), Alg::Rs256).len(), 1);
    }

    #[test]
    fn skips_a_key_it_cannot_use_rather_than_refusing_the_document() {
        // An Ed25519 key beside an RSA one. A provider adding an algorithm must not
        // break every login until this product is upgraded.
        let body = format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},{}]}}"#,
            rsa_key("k1")
        );
        let set = Jwks::parse(&body).unwrap();
        assert_eq!(set.len(), 1, "the unusable key should be skipped, not fatal");
    }

    #[test]
    fn a_set_with_nothing_usable_is_an_error() {
        // The distinction that matters: skipping every key leaves nothing to verify
        // with, and continuing from there would mean accepting a token unverified.
        let err = Jwks::parse(r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}]}"#).unwrap_err();
        assert!(matches!(err, Error::Jwks(_)), "{err}");
    }

    #[test]
    fn skips_an_encryption_key() {
        let body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"enc","use":"enc","n":"{}","e":"AQAB"}},{}]}}"#,
            modulus(),
            rsa_key("sig")
        );
        let set = Jwks::parse(&body).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.candidates(Some("enc"), Alg::Rs256).is_empty());
    }

    #[test]
    fn skips_a_short_modulus() {
        let body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"weak","n":"{}","e":"AQAB"}},{}]}}"#,
            b64::encode(&[0x0b; 128]),
            rsa_key("ok")
        );
        let set = Jwks::parse(&body).unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set.candidates(Some("ok"), Alg::Rs256).len(), 1);
    }

    #[test]
    fn skips_a_key_whose_named_algorithm_disagrees_with_its_type() {
        let body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"odd","alg":"ES256","n":"{}","e":"AQAB"}},{}]}}"#,
            modulus(),
            rsa_key("ok")
        );
        let set = Jwks::parse(&body).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn a_named_key_is_not_a_candidate_for_the_others() {
        // A token naming a `kid` the provider does not publish must fail, not fall back
        // to whatever else is in the set — that would turn a rotation mistake into a
        // silent acceptance.
        let body = format!(r#"{{"keys":[{},{}]}}"#, rsa_key("k1"), rsa_key("k2"));
        let set = Jwks::parse(&body).unwrap();
        assert!(set.candidates(Some("k3"), Alg::Rs256).is_empty());
    }

    #[test]
    fn a_token_without_a_kid_may_try_every_key_of_its_algorithm() {
        // Which is what a provider publishing one unnamed key requires, and what a
        // rotation makes briefly true for everyone else.
        let body = format!(r#"{{"keys":[{},{}]}}"#, rsa_key("k1"), rsa_key("k2"));
        let set = Jwks::parse(&body).unwrap();
        assert_eq!(set.candidates(None, Alg::Rs256).len(), 2);
    }

    #[test]
    fn the_algorithm_set_is_closed() {
        assert_eq!(Alg::parse("none"), None);
        assert_eq!(Alg::parse("HS256"), None);
        assert_eq!(Alg::parse("RS256"), Some(Alg::Rs256));
        assert_eq!(Alg::parse("ES256"), Some(Alg::Es256));
    }
}
