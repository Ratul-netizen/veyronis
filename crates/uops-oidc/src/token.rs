//! The ID token's claims, and what has to be true of them — OIDC Core §3.1.3.7.
//!
//! # A verified signature is not an accepted token
//!
//! It means the provider minted this, not that it minted it *for this product*. Every
//! check below closes a gap that a correct signature leaves open:
//!
//! | check | what it stops |
//! |---|---|
//! | `iss` exactly matches | a token from a different provider, correctly signed by that one |
//! | `aud` contains the client id | a token the same provider minted for another application, replayed here |
//! | `nonce` matches the login | a token captured from an earlier sign-in and replayed |
//! | `exp` / `iat` | a token that was legitimate last month |
//! | `sub` present and stable | an account keyed on something the provider may reassign |
//!
//! The audience one is the one people leave out, and it is the one that matters most in
//! a large organisation: every application behind the same Entra ID tenant is signed by
//! the same key. Without an `aud` check, a token issued for the cafeteria booking system
//! is a valid login here.

use chrono::{DateTime, TimeZone as _, Utc};
use serde::Deserialize;

use crate::error::{Error, Result};

/// Tolerance for the two clocks disagreeing.
///
/// Sixty seconds, which is the conventional value and is what providers themselves
/// assume. It is applied to both ends: a token from a provider one minute fast must not
/// be rejected as "not yet valid", and one that expired within the last minute is not
/// worth a failed login.
///
/// Larger would be a real extension of every token's life. NTP exists, and a deployment
/// whose clock is out by more than a minute has a problem this constant should not hide.
pub const LEEWAY: chrono::Duration = chrono::Duration::seconds(60);

/// The longest `sub` this product will store.
///
/// Providers issue short opaque strings; 255 is far past anything real. The bound exists
/// so an oversized claim fails validation rather than being truncated into a collision
/// with another account's identifier.
pub const MAX_SUBJECT: usize = 255;

/// What the caller already knows, and requires the token to agree with.
#[derive(Clone, Debug)]
pub struct Expected<'a> {
    /// The provider's issuer identifier, compared **exactly**.
    ///
    /// Not normalised, not case-folded, no trailing slash forgiven. OIDC Discovery
    /// requires the `iss` in a token to equal the issuer in the discovery document
    /// character for character, and a verifier that relaxes that is a verifier that can
    /// be pointed at `https://provider.example.com.attacker.net`.
    pub issuer: &'a str,
    /// This product's client id at that provider.
    pub client_id: &'a str,
    /// The nonce this server put into the authorization request.
    pub nonce: &'a str,
    /// Which claim carries group membership, per [`crate::mapping`].
    pub groups_claim: &'a str,
}

/// An ID token whose signature verified and whose claims were checked.
///
/// Constructed only by [`IdToken::validate`], so holding one is evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdToken {
    /// The provider's identifier for this person. The account key.
    ///
    /// Stable per provider and opaque. Deliberately *not* the email address: an address
    /// can be reassigned to a new hire when someone leaves, and an account keyed on one
    /// would hand the leaver's access to their replacement.
    pub subject: String,
    pub issuer: String,
    /// The address, if the provider released one.
    ///
    /// Used for display and for matching an invited user, never as the identity.
    pub email: Option<String>,
    /// Whether the provider asserts it verified that address.
    pub email_verified: bool,
    /// A human name, if there is one.
    pub name: Option<String>,
    /// The values of the configured groups claim.
    pub groups: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// The claims as JSON, before anything has been decided about them.
#[derive(Debug, Deserialize)]
struct Claims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audience>,
    /// Authorized party. Required when `aud` has more than one value.
    azp: Option<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    nbf: Option<i64>,
    nonce: Option<String>,
    email: Option<String>,
    /// Some providers send this as a JSON string rather than a boolean. Both are seen
    /// in production and refusing one would be refusing a real provider.
    email_verified: Option<Flexible>,
    name: Option<String>,
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

/// `aud` is a string or an array of strings. RFC 7519 §4.1.3 allows both.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn values(&self) -> &[String] {
        match self {
            Self::One(s) => std::slice::from_ref(s),
            Self::Many(v) => v,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Flexible {
    Bool(bool),
    Text(String),
}

impl Flexible {
    fn truth(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Text(s) => s == "true",
        }
    }
}

impl IdToken {
    /// Check a verified payload's claims.
    ///
    /// `now` is passed rather than read so that every boundary in the validity window is
    /// testable without waiting for it.
    ///
    /// # Errors
    ///
    /// [`Error::Claim`] for a claim that is absent or wrong, and [`Error::Expired`] for
    /// one that is merely out of date — see [`Error::Expired`] for why those are apart.
    pub fn validate(payload: &[u8], expected: &Expected<'_>, now: DateTime<Utc>) -> Result<Self> {
        let claims: Claims = serde_json::from_slice(payload).map_err(|e| Error::Claim {
            claim: "payload",
            because: e.to_string(),
        })?;

        let issuer = required(claims.iss.as_deref(), "iss")?;
        if issuer != expected.issuer {
            // Not a comparison that tolerates a trailing slash or a case difference.
            // See `Expected::issuer`.
            return Err(Error::Claim {
                claim: "iss",
                because: format!(
                    "the token says {issuer}, this provider is {}",
                    expected.issuer
                ),
            });
        }

        let subject = required(claims.sub.as_deref(), "sub")?;
        if subject.len() > MAX_SUBJECT {
            return Err(Error::Claim {
                claim: "sub",
                because: format!("{} characters, longer than {MAX_SUBJECT}", subject.len()),
            });
        }

        let audience = claims.aud.as_ref().ok_or(Error::Claim {
            claim: "aud",
            because: "absent".to_owned(),
        })?;
        let values = audience.values();
        if !values.iter().any(|a| a == expected.client_id) {
            return Err(Error::Claim {
                claim: "aud",
                because: "names another application".to_owned(),
            });
        }
        // OIDC Core §3.1.3.7 rule 4: more than one audience means `azp` must be present
        // and must be this client. Without it, a token minted for this product *and*
        // another one is presentable at either — which is the point of `azp` and the
        // reason the rule is not optional.
        if values.len() > 1 {
            let azp = required(claims.azp.as_deref(), "azp")?;
            if azp != expected.client_id {
                return Err(Error::Claim {
                    claim: "azp",
                    because: "the token was authorized for another application".to_owned(),
                });
            }
        }

        let nonce = required(claims.nonce.as_deref(), "nonce")?;
        // Constant-time is not needed: the nonce is this server's own value, held in the
        // caller's cookie, and an attacker comparing against it already has it.
        if nonce != expected.nonce {
            return Err(Error::Claim {
                claim: "nonce",
                because: "this token belongs to a different sign-in".to_owned(),
            });
        }

        let expires_at = instant(claims.exp, "exp")?;
        let issued_at = instant(claims.iat, "iat")?;

        if expires_at + LEEWAY <= now {
            return Err(Error::Expired("exp has passed"));
        }
        if issued_at - LEEWAY > now {
            return Err(Error::Expired("iat is in the future"));
        }
        if let Some(nbf) = claims.nbf {
            let not_before = instant(Some(nbf), "nbf")?;
            if not_before - LEEWAY > now {
                return Err(Error::Expired("nbf has not arrived"));
            }
        }

        Ok(Self {
            subject: subject.to_owned(),
            issuer: issuer.to_owned(),
            email: claims.email.clone(),
            email_verified: claims.email_verified.as_ref().is_some_and(Flexible::truth),
            name: claims.name.clone(),
            groups: groups(&claims, expected.groups_claim),
            issued_at,
            expires_at,
        })
    }

    /// How this account is keyed, for a log line an operator reads.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.email {
            Some(email) => format!("{} <{email}> at {}", self.subject, self.issuer),
            None => format!("{} at {}", self.subject, self.issuer),
        }
    }
}

/// The configured groups claim, as a list.
///
/// Absent is an empty list rather than an error, and that is a decision: a provider that
/// releases no groups should produce a user with no role — which the mapping then
/// refuses — rather than a failed login that looks like a broken provider. The two are
/// distinguishable in the log and only one of them is the operator's to fix.
fn groups(claims: &Claims, claim: &str) -> Vec<String> {
    let Some(value) = claims.rest.get(claim) else {
        return Vec::new();
    };
    match value {
        // Some providers send a space-separated string. Splitting on whitespace handles
        // that and leaves a single value intact.
        serde_json::Value::String(s) => s.split_whitespace().map(ToOwned::to_owned).collect(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

fn required<'a>(value: Option<&'a str>, claim: &'static str) -> Result<&'a str> {
    match value {
        Some(s) if !s.is_empty() => Ok(s),
        Some(_) => Err(Error::Claim {
            claim,
            because: "empty".to_owned(),
        }),
        None => Err(Error::Claim {
            claim,
            because: "absent".to_owned(),
        }),
    }
}

fn instant(seconds: Option<i64>, claim: &'static str) -> Result<DateTime<Utc>> {
    let value = seconds.ok_or(Error::Claim {
        claim,
        because: "absent".to_owned(),
    })?;
    Utc.timestamp_opt(value, 0).single().ok_or(Error::Claim {
        claim,
        because: format!("{value} is not a representable instant"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0).unwrap()
    }

    fn expected() -> Expected<'static> {
        Expected {
            issuer: "https://idp.example.com",
            client_id: "uops",
            nonce: "n-0S6_WzA2Mj",
            groups_claim: "groups",
        }
    }

    /// A payload with every required claim right, and whatever else the test overrides.
    fn payload(extra: &str) -> Vec<u8> {
        let base = format!(
            r#""iss":"https://idp.example.com","sub":"00u1","aud":"uops",
               "nonce":"n-0S6_WzA2Mj","exp":{},"iat":{}"#,
            now().timestamp() + 300,
            now().timestamp() - 10,
        );
        if extra.is_empty() {
            format!("{{{base}}}").into_bytes()
        } else {
            format!("{{{base},{extra}}}").into_bytes()
        }
    }

    #[test]
    fn a_correct_token_validates() {
        let token = IdToken::validate(&payload(""), &expected(), now()).unwrap();
        assert_eq!(token.subject, "00u1");
        assert!(token.groups.is_empty());
    }

    #[test]
    fn a_token_for_another_application_is_refused() {
        // The check people leave out, and the one that matters most: every application
        // behind the same Entra ID tenant is signed by the same key, so without this a
        // token for the cafeteria booking system is a valid login here.
        let other = payload("").clone();
        let swapped = String::from_utf8(other)
            .unwrap()
            .replace(r#""aud":"uops""#, r#""aud":"cafeteria""#);
        let err = IdToken::validate(swapped.as_bytes(), &expected(), now()).unwrap_err();
        assert!(matches!(err, Error::Claim { claim: "aud", .. }), "{err:?}");
    }

    #[test]
    fn a_multi_audience_token_needs_azp() {
        let body = String::from_utf8(payload("").clone())
            .unwrap()
            .replace(r#""aud":"uops""#, r#""aud":["uops","other"]"#);
        let err = IdToken::validate(body.as_bytes(), &expected(), now()).unwrap_err();
        assert!(matches!(err, Error::Claim { claim: "azp", .. }), "{err:?}");

        let with_azp = body.replace(r#""sub":"00u1""#, r#""sub":"00u1","azp":"uops""#);
        assert!(IdToken::validate(with_azp.as_bytes(), &expected(), now()).is_ok());
    }

    #[test]
    fn azp_naming_another_application_is_refused() {
        let body = String::from_utf8(payload("").clone())
            .unwrap()
            .replace(r#""aud":"uops""#, r#""aud":["uops","other"],"azp":"other""#);
        let err = IdToken::validate(body.as_bytes(), &expected(), now()).unwrap_err();
        assert!(matches!(err, Error::Claim { claim: "azp", .. }), "{err:?}");
    }

    #[test]
    fn an_issuer_that_merely_looks_right_is_refused() {
        for impostor in [
            "https://idp.example.com/",
            "https://idp.example.com.attacker.net",
            "https://IDP.example.com",
            "http://idp.example.com",
        ] {
            let body = String::from_utf8(payload("").clone())
                .unwrap()
                .replace("https://idp.example.com\"", &format!("{impostor}\""));
            let err = IdToken::validate(body.as_bytes(), &expected(), now()).unwrap_err();
            assert!(
                matches!(err, Error::Claim { claim: "iss", .. }),
                "{impostor} was accepted"
            );
        }
    }

    #[test]
    fn a_replayed_token_from_another_sign_in_is_refused() {
        let mut other = expected();
        other.nonce = "a different login";
        let err = IdToken::validate(&payload(""), &other, now()).unwrap_err();
        assert!(
            matches!(err, Error::Claim { claim: "nonce", .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_token_with_no_nonce_is_refused() {
        // Absent is not "no check". A provider that omits it has not proved the token
        // belongs to the sign-in in progress, which is the whole purpose of the claim.
        let body = String::from_utf8(payload("").clone())
            .unwrap()
            .replace(r#""nonce":"n-0S6_WzA2Mj","#, "");
        let err = IdToken::validate(body.as_bytes(), &expected(), now()).unwrap_err();
        assert!(
            matches!(err, Error::Claim { claim: "nonce", .. }),
            "{err:?}"
        );
    }

    #[test]
    fn the_validity_window_holds_at_both_ends() {
        let just_expired = now() + LEEWAY + chrono::Duration::seconds(301);
        assert!(matches!(
            IdToken::validate(&payload(""), &expected(), just_expired).unwrap_err(),
            Error::Expired(_)
        ));

        // Inside the leeway, so a provider a minute out of step still works.
        let barely = now() + chrono::Duration::seconds(300 + 59);
        assert!(IdToken::validate(&payload(""), &expected(), barely).is_ok());
    }

    #[test]
    fn a_token_issued_in_the_future_is_refused() {
        let long_ago = now() - chrono::Duration::hours(1);
        assert!(matches!(
            IdToken::validate(&payload(""), &expected(), long_ago).unwrap_err(),
            Error::Expired(_)
        ));
    }

    #[test]
    fn nbf_is_honoured_when_present() {
        let body = payload(&format!(r#""nbf":{}"#, now().timestamp() + 600));
        assert!(matches!(
            IdToken::validate(&body, &expected(), now()).unwrap_err(),
            Error::Expired(_)
        ));
    }

    #[test]
    fn an_empty_subject_is_not_a_subject() {
        let body = String::from_utf8(payload("").clone())
            .unwrap()
            .replace(r#""sub":"00u1""#, r#""sub":"""#);
        let err = IdToken::validate(body.as_bytes(), &expected(), now()).unwrap_err();
        assert!(matches!(err, Error::Claim { claim: "sub", .. }), "{err:?}");
    }

    #[test]
    fn an_oversized_subject_is_refused_rather_than_truncated() {
        let long = "x".repeat(MAX_SUBJECT + 1);
        let body = String::from_utf8(payload("").clone())
            .unwrap()
            .replace(r#""sub":"00u1""#, &format!(r#""sub":"{long}""#));
        let err = IdToken::validate(body.as_bytes(), &expected(), now()).unwrap_err();
        assert!(matches!(err, Error::Claim { claim: "sub", .. }), "{err:?}");
    }

    #[test]
    fn groups_arrive_as_an_array_or_a_space_separated_string() {
        let array = IdToken::validate(&payload(r#""groups":["net","sec"]"#), &expected(), now())
            .unwrap()
            .groups;
        assert_eq!(array, ["net", "sec"]);

        let text = IdToken::validate(&payload(r#""groups":"net sec""#), &expected(), now())
            .unwrap()
            .groups;
        assert_eq!(text, ["net", "sec"]);
    }

    #[test]
    fn the_groups_claim_is_whichever_one_was_configured() {
        let mut roles = expected();
        roles.groups_claim = "roles";
        let token = IdToken::validate(
            &payload(r#""roles":["admin"],"groups":["ignored"]"#),
            &roles,
            now(),
        )
        .unwrap();
        assert_eq!(token.groups, ["admin"]);
    }

    #[test]
    fn email_verified_may_be_a_string() {
        // Seen in production from more than one provider. Refusing it would be refusing
        // a real identity provider over a JSON type.
        let token =
            IdToken::validate(&payload(r#""email_verified":"true""#), &expected(), now()).unwrap();
        assert!(token.email_verified);

        let token =
            IdToken::validate(&payload(r#""email_verified":true"#), &expected(), now()).unwrap();
        assert!(token.email_verified);

        let token = IdToken::validate(&payload(""), &expected(), now()).unwrap();
        assert!(!token.email_verified, "absent must not mean verified");
    }
}
