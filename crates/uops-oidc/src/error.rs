//! What can go wrong, and how much of it a caller may repeat.
//!
//! # The variants are deliberately coarse where the user can see them
//!
//! Every failure below reaches a browser as the same sentence: *sign-in failed*. The
//! distinctions exist for the operator reading the server log, who is the only person
//! who can act on them — an expired token, a wrong audience and a bad signature call for
//! three different fixes, and none of those fixes is the user's.
//!
//! Telling the browser which one occurred would be an oracle. "Wrong audience" confirms
//! that a token was well-formed and correctly signed, which is a useful thing to learn
//! while working out what to forge next.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// The token is not three base64url segments carrying the JSON they must carry.
    #[error("malformed token: {0}")]
    Malformed(&'static str),

    /// The header names an algorithm this product does not accept — including `none`
    /// and any HMAC variant. See [`crate::jwk::Alg`] for why the set is closed.
    #[error("unacceptable algorithm: {0}")]
    Algorithm(String),

    /// No key in the provider's set could be tried, or none of them verified.
    ///
    /// One variant for both, because they are one fact to a caller: this token was not
    /// signed by this provider as far as anything here can tell.
    #[error("signature did not verify")]
    Signature,

    /// A claim was absent, empty, or not what it had to be.
    ///
    /// The string names the claim and says what was expected. It goes to the server log.
    #[error("claim {claim}: {because}")]
    Claim {
        claim: &'static str,
        because: String,
    },

    /// The token is outside its validity window, in either direction.
    ///
    /// Separate from [`Error::Claim`] because it is the one failure that is *routine* —
    /// a user leaving a login tab open produces it, and an operator scanning a log needs
    /// to be able to tell it apart from the ones that mean something.
    #[error("token is not valid at this time: {0}")]
    Expired(&'static str),

    /// The provider's key set could not be used.
    #[error("key set: {0}")]
    Jwks(String),

    /// The provider's discovery document could not be used.
    #[error("discovery: {0}")]
    Discovery(String),

    /// The login this response belongs to is not one this server started, or has been
    /// used already.
    #[error("login state: {0}")]
    State(&'static str),

    /// The provider returned an error at the authorization or token endpoint.
    #[error("the provider refused: {0}")]
    Provider(String),

    /// The provider could not be reached, or did not answer in the shape it must.
    #[error("transport: {0}")]
    Transport(String),
}

impl Error {
    /// What the browser is told. Always the same sentence — see the module docs.
    #[must_use]
    pub const fn public_message(&self) -> &'static str {
        "sign-in failed"
    }

    /// Whether the operator should look at their provider configuration rather than at
    /// this product.
    ///
    /// Not a nicety: the commonest SSO failure by a wide margin is a redirect URI or an
    /// audience that does not match, and the log line that says so saves an afternoon.
    #[must_use]
    pub const fn is_configuration(&self) -> bool {
        matches!(
            self,
            Self::Discovery(_) | Self::Jwks(_) | Self::Provider(_) | Self::Algorithm(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_looks_identical_from_outside() {
        let failures = [
            Error::Malformed("two segments"),
            Error::Signature,
            Error::Expired("exp"),
            Error::Claim {
                claim: "aud",
                because: "names another client".to_owned(),
            },
        ];
        for e in &failures {
            assert_eq!(e.public_message(), "sign-in failed");
        }
    }

    #[test]
    fn a_wrong_audience_is_not_reported_as_configuration() {
        // It is far more likely to be a token minted for another application — which is
        // an attack shape, not a typo — and telling an operator to go and edit their
        // configuration is the wrong instruction in that case.
        assert!(
            !Error::Claim {
                claim: "aud",
                because: "names another client".to_owned()
            }
            .is_configuration()
        );
        assert!(Error::Discovery("404".to_owned()).is_configuration());
    }
}
