//! `OpenID` Connect — M12 §2.2, `docs/M12-enterprise.md`.
//!
//! A product that asks a 2 000-person company to keep a second password list is a
//! product their identity team will refuse. This is the authorization-code flow with
//! PKCE, the ID token checks that make it mean anything, and the mapping from the
//! provider's groups to this product's roles.
//!
//! ```text
//!   browser ──▶ /auth/oidc/start ──▶ provider ──▶ /auth/oidc/callback ──▶ session
//!                     │                                    │
//!               state, nonce, verifier             code + state
//!               into an HttpOnly cookie          code ⇄ id_token, verified
//! ```
//!
//! # What lives here and what does not
//!
//! | here | elsewhere |
//! |---|---|
//! | verifying a token ([`token`], [`jws`], [`jwk`]) | fetching the keys ([`fetch`]) |
//! | starting and recognising a sign-in ([`flow`]) | the cookies it travels in (`uops-api`) |
//! | groups to roles ([`mapping`]) | who the provider is (`uops-store-pg`) |
//!
//! The split is deliberate: everything above the line is pure, decides something, and is
//! tested exhaustively without a provider, a network or a database. That is where the
//! security lives, so that is where it can be argued about.
//!
//! # Why not an OIDC crate
//!
//! The mature ones bring a TLS stack and an HTTP client with them, which this workspace
//! has spent M0 through M9 deliberately not having (see the licence notes in the root
//! `Cargo.toml`). More to the point, the parts worth importing are the parts worth
//! owning: the algorithm allow-list, the audience check, the issuer comparison. Every
//! published OIDC vulnerability of the last decade has been one of those three being
//! generous. They are about three hundred lines, and reading them here is the point.
//!
//! # Example
//!
//! ```
//! use uops_oidc::{Expected, IdToken, Jwks, Jws, Pending};
//!
//! // Start a sign-in. Three unrelated random values, one per job — see `flow`.
//! let pending = Pending::start(Some("/incidents")).unwrap();
//! let url = pending.authorization_url(
//!     "https://idp.example.com/authorize",
//!     "uops",
//!     "https://uops.example.com/api/v1/auth/oidc/callback",
//!     "openid email profile",
//! );
//! assert!(url.contains("code_challenge_method=S256"));
//!
//! // The verifier never leaves this server; only its hash is sent.
//! assert!(!url.contains(&pending.verifier));
//! ```

pub mod b64;
pub mod discovery;
pub mod error;
pub mod fetch;
pub mod flow;
pub mod jwk;
pub mod jws;
pub mod mapping;
pub mod token;

pub use discovery::{Discovered, well_known};
pub use error::{Error, Result};
pub use fetch::{Fetch, Http, TokenResponse, redeem};
pub use flow::{Pending, safe_return_to};
pub use jwk::{Alg, Jwk, Jwks, Material};
pub use jws::Jws;
pub use mapping::{Entitlement, Grant, Mapping};
pub use token::{Expected, IdToken};

/// The scopes this product asks for.
///
/// `openid` is required. `email` and `profile` are what make a provisioned user
/// something other than a UUID in a list — and nothing more is asked for, because a
/// consent screen listing scopes a monitoring product has no business with is a consent
/// screen an identity team declines.
///
/// Group membership is deliberately not a scope here: providers disagree about how to
/// release it — a scope for Okta, an optional claim for Entra ID, a client mapper for
/// Keycloak — and the one thing they agree on is that it is configured at the provider.
/// Asking for a scope one of them does not define is a sign-in that fails with a message
/// about the scope rather than about the configuration.
pub const SCOPES: &str = "openid email profile";
