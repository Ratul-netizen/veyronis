//! The provider's self-description — `OpenID` Connect Discovery 1.0.
//!
//! # The issuer in the document is checked against the URL it came from
//!
//! Discovery §4.3 requires it, and the reason is the whole security of the flow: every
//! later check in [`crate::token`] compares the token's `iss` against this value, so a
//! document that is allowed to name any issuer it likes can nominate the one whose
//! tokens it wants accepted. Fetching from `https://idp.example.com` and believing a
//! document that says `iss: https://accounts.google.com` would make this product verify
//! Google's tokens with Google's keys and then hand out the attacker's roles.

use serde::Deserialize;

use crate::error::{Error, Result};

/// Where a document was fetched from, to the endpoints it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// Optional, and only used for the sign-out link when the provider offers one.
    pub end_session_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Document {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
}

/// The well-known path, appended to an issuer.
///
/// Appended rather than joined: an issuer with a path component — which Keycloak always
/// has, `https://host/realms/acme` — keeps it, and a URL join would throw it away and
/// fetch the wrong document.
#[must_use]
pub fn well_known(issuer: &str) -> String {
    format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))
}

impl Discovered {
    /// Parse a discovery document fetched from `issuer`.
    ///
    /// # Errors
    ///
    /// [`Error::Discovery`] when the document is not JSON in the required shape, when
    /// it names an issuer other than the one it was fetched for, or when any endpoint
    /// it names is not `https`.
    pub fn parse(issuer: &str, body: &str) -> Result<Self> {
        let doc: Document =
            serde_json::from_str(body).map_err(|e| Error::Discovery(e.to_string()))?;

        // Discovery §4.3, and see the module docs for what it prevents.
        if doc.issuer != issuer {
            return Err(Error::Discovery(format!(
                "fetched for {issuer} but the document claims to be {}",
                doc.issuer
            )));
        }

        for (name, url) in [
            ("authorization_endpoint", &doc.authorization_endpoint),
            ("token_endpoint", &doc.token_endpoint),
            ("jwks_uri", &doc.jwks_uri),
        ] {
            // The client secret is posted to the token endpoint and the keys come back
            // from the jwks_uri. Either over plain HTTP is a credential on the wire and
            // a key an on-path attacker chooses.
            if !url.starts_with("https://") {
                return Err(Error::Discovery(format!("{name} is not https: {url}")));
            }
        }

        Ok(Self {
            issuer: doc.issuer,
            authorization_endpoint: doc.authorization_endpoint,
            token_endpoint: doc.token_endpoint,
            jwks_uri: doc.jwks_uri,
            end_session_endpoint: doc.end_session_endpoint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://idp.example.com";

    fn document(issuer: &str) -> String {
        format!(
            r#"{{"issuer":"{issuer}",
                "authorization_endpoint":"https://idp.example.com/authorize",
                "token_endpoint":"https://idp.example.com/token",
                "jwks_uri":"https://idp.example.com/keys",
                "subject_types_supported":["public"],
                "response_types_supported":["code"]}}"#
        )
    }

    #[test]
    fn parses_a_provider_document() {
        let d = Discovered::parse(ISSUER, &document(ISSUER)).unwrap();
        assert_eq!(d.jwks_uri, "https://idp.example.com/keys");
        assert_eq!(d.end_session_endpoint, None);
    }

    #[test]
    fn a_document_cannot_nominate_a_different_issuer() {
        // Discovery §4.3. Without this check, a document fetched from a host the
        // operator typed can hand this product Google's issuer and keys.
        let err = Discovered::parse(ISSUER, &document("https://accounts.google.com")).unwrap_err();
        assert!(matches!(err, Error::Discovery(_)), "{err:?}");
    }

    #[test]
    fn a_plain_http_endpoint_is_refused() {
        let body = document(ISSUER).replace("https://idp.example.com/token", "http://idp.example.com/token");
        let err = Discovered::parse(ISSUER, &body).unwrap_err();
        let Error::Discovery(why) = err else { panic!() };
        assert!(why.contains("token_endpoint"), "{why}");
    }

    #[test]
    fn a_missing_endpoint_is_an_error_rather_than_a_default() {
        let body = document(ISSUER).replace(r#""jwks_uri":"https://idp.example.com/keys","#, "");
        assert!(Discovered::parse(ISSUER, &body).is_err());
    }

    #[test]
    fn the_well_known_path_keeps_the_issuers_own_path() {
        // Keycloak always has one. A URL join would drop `/realms/acme` and fetch a
        // document that describes a different realm, or nothing at all.
        assert_eq!(
            well_known("https://sso.example.com/realms/acme"),
            "https://sso.example.com/realms/acme/.well-known/openid-configuration"
        );
        assert_eq!(
            well_known("https://idp.example.com/"),
            "https://idp.example.com/.well-known/openid-configuration"
        );
    }
}
