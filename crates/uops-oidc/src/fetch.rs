//! Talking to the provider: discovery, the key set, and redeeming a code.
//!
//! # The network is a trait
//!
//! Everything in this crate that *decides* something is pure and tested without a
//! provider. This module is the seam where that stops. It is a trait so the exchange
//! above it — which provider, which credential, what to do with a refusal — is tested
//! against a scripted provider that answers the way a real one would, including the ways
//! a real one misbehaves.
//!
//! # Synchronous, and called from a blocking pool
//!
//! Three requests happen per sign-in, at most, and the key set is cached across them. An
//! async HTTP client to save microseconds on a path that already waits for a human to
//! type a password would be a second HTTP stack in this workspace for no gain. The same
//! judgement `PgSealedStore` made, written down in the same terms.
//!
//! # And it is the one place with TLS
//!
//! Every other client in this workspace has TLS deliberately switched off, because every
//! other thing it talks to is on a private network behind a reverse proxy. An identity
//! provider is not: it is `https://login.microsoftonline.com`, on the internet, and its
//! signing keys are fetched over that link. The trust store is the operating system's,
//! which is the property that matters for on-premise — a customer's internal Keycloak is
//! signed by a certificate authority that is in their machine's store and in nobody's
//! bundled root list.

use std::sync::Mutex;

use serde::Deserialize;

use crate::b64;
use crate::discovery::{Discovered, well_known};
use crate::error::{Error, Result};
use crate::jwk::Jwks;

/// How long a fetched key set is used before it is fetched again.
///
/// Providers rotate keys on the order of weeks and publish the new one well before they
/// sign with it, so an hour is comfortable. The refresh that actually matters is the
/// unscheduled one in [`Keys::for_token`]: a token naming a `kid` this cache has never
/// seen triggers a fetch immediately, which is what makes an *early* rotation a pause
/// rather than an outage.
pub const KEYS_TTL: chrono::Duration = chrono::Duration::hours(1);

/// The shortest interval between two unscheduled key fetches.
///
/// Without it, a stream of tokens bearing invented `kid`s is a request amplifier pointed
/// at the identity provider — from an unauthenticated endpoint, which is the worst kind.
/// One fetch a minute is plenty for a real rotation and useless as a lever.
pub const REFRESH_FLOOR: chrono::Duration = chrono::Duration::minutes(1);

/// The HTTP this crate needs, and nothing else.
pub trait Fetch: Send + Sync + std::fmt::Debug {
    /// `GET`, returning the body as text.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] for anything that is not a 2xx with a body.
    fn get(&self, url: &str) -> Result<String>;

    /// `POST` a form, optionally with HTTP Basic credentials.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] for a failure to reach the provider, and [`Error::Provider`]
    /// for a refusal the provider described — those are different conversations and the
    /// error type keeps them apart.
    fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<String>;
}

/// A cached key set for one provider.
///
/// Behind a `Mutex` rather than an `RwLock`: the guarded work is a clone of a handful of
/// public keys, contention is one login at a time, and a read-write lock here would be
/// ceremony around a cheap copy.
#[derive(Debug)]
pub struct Keys {
    inner: Mutex<Cached>,
}

#[derive(Debug, Default)]
struct Cached {
    jwks: Option<Jwks>,
    fetched_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for Keys {
    fn default() -> Self {
        Self::new()
    }
}

impl Keys {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Cached::default()),
        }
    }

    /// The key set to verify a token bearing this `kid`.
    ///
    /// Fetches when the cache is empty, when it has aged past [`KEYS_TTL`], or when the
    /// token names a key the cached set does not contain — the last being a rotation the
    /// provider performed early, and the case an interval-only cache turns into an hour
    /// of failed logins.
    ///
    /// # Errors
    ///
    /// Whatever the fetch or the parse said. A stale-but-usable cache is **kept** when a
    /// refresh fails: a provider that is briefly unreachable must not invalidate keys
    /// that were good a minute ago.
    pub fn for_token(
        &self,
        http: &dyn Fetch,
        jwks_uri: &str,
        kid: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Jwks> {
        {
            let cached = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let (Some(jwks), Some(at)) = (cached.jwks.as_ref(), cached.fetched_at) {
                let fresh = now - at < KEYS_TTL;
                let known = kid.is_none_or(|k| {
                    !jwks.candidates(Some(k), crate::Alg::Rs256).is_empty()
                        || !jwks.candidates(Some(k), crate::Alg::Es256).is_empty()
                });
                if fresh && known {
                    return Ok(jwks.clone());
                }
                // An unknown kid on a set that is still fresh: refresh, but not more
                // often than the floor. See `REFRESH_FLOOR`.
                if !known && fresh && now - at < REFRESH_FLOOR {
                    return Ok(jwks.clone());
                }
            }
        }

        let fetched = http.get(jwks_uri).and_then(|body| Jwks::parse(&body));

        let mut cached = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match fetched {
            Ok(jwks) => {
                cached.jwks = Some(jwks.clone());
                cached.fetched_at = Some(now);
                Ok(jwks)
            }
            // A provider that is briefly unreachable must not invalidate keys that were
            // good a minute ago. The stale set still verifies every token signed with a
            // key it holds, which during an outage is all of them.
            Err(e) => cached.jwks.clone().ok_or(e),
        }
    }

    /// Drop the cache. For an operator who has just changed the provider.
    pub fn forget(&self) {
        let mut cached = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *cached = Cached::default();
    }
}

/// Fetch and check a provider's discovery document.
///
/// # Errors
///
/// [`Error::Transport`] if it cannot be fetched, [`Error::Discovery`] if it is not what
/// it must be — including naming an issuer other than the one it was fetched for.
pub fn discover(http: &dyn Fetch, issuer: &str) -> Result<Discovered> {
    let body = http.get(&well_known(issuer))?;
    Discovered::parse(issuer, &body)
}

/// What the token endpoint returns.
#[derive(Clone, Debug, Deserialize)]
pub struct TokenResponse {
    /// The only field this product uses. An access token for the provider's own APIs is
    /// not something a monitoring product has any business holding.
    pub id_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ProviderError {
    error: String,
    error_description: Option<String>,
}

/// Exchange an authorization code for an ID token.
///
/// # Errors
///
/// [`Error::Provider`] when the provider refuses — the commonest causes being a redirect
/// URI that does not match the one registered, and an expired code — and
/// [`Error::Transport`] when it cannot be reached or answers with something that is not
/// a token response.
pub fn redeem(
    http: &dyn Fetch,
    provider: &Discovered,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<TokenResponse> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        // RFC 7636 §4.5. The provider hashes this and compares it to the challenge sent
        // at the start, which is what ties the redemption to the browser that asked.
        ("code_verifier", verifier),
    ];

    // `client_secret_basic` is the spec's default and what every provider accepts;
    // `client_secret_post` is the fallback for the ones that do not. A public client —
    // no secret at all — is legitimate here precisely because PKCE is always on.
    let basic = if let Some(secret) = client_secret {
        Some((client_id, secret))
    } else {
        form.push(("client_id", client_id));
        None
    };

    let body = http.post_form(&provider.token_endpoint, &form, basic)?;

    // A provider's refusal is JSON with an `error` member — RFC 6749 §5.2 — and it is
    // the difference between "your configuration is wrong" and "the network is down".
    // Parsing the token response first would report a real refusal as a parse failure.
    if let Ok(refusal) = serde_json::from_str::<ProviderError>(&body) {
        return Err(Error::Provider(match refusal.error_description {
            Some(description) => format!("{}: {description}", refusal.error),
            None => refusal.error,
        }));
    }

    serde_json::from_str(&body)
        .map_err(|e| Error::Transport(format!("the token endpoint answered with {e}")))
}

/// HTTP over TLS, using the operating system's trust store.
///
/// See the module docs for why this is the one client in the workspace that speaks TLS,
/// and why the trust store is the machine's rather than a bundled list.
#[derive(Debug)]
pub struct Http {
    agent: ureq::Agent,
}

impl Default for Http {
    fn default() -> Self {
        Self::new()
    }
}

impl Http {
    #[must_use]
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            // A provider that does not answer promptly is a failed login, not a held
            // worker. Both halves are bounded: a connect that hangs and a body that
            // trickles are different failures and an unbounded read is the one that
            // ties up a thread indefinitely.
            .timeout_connect(Some(std::time::Duration::from_secs(5)))
            .timeout_global(Some(std::time::Duration::from_secs(15)))
            // A discovery document or key set larger than this is not one; the cap is
            // what stops a hostile or broken endpoint from being a memory exhaustion.
            .max_response_header_size(16 * 1024)
            // Redirects off. Every URL here comes from a document this code checked, and
            // following a redirect would mean fetching keys from a host the check never
            // saw. The provider has no legitimate reason to bounce these.
            .max_redirects(0)
            .build();
        Self {
            agent: config.into(),
        }
    }
}

/// The largest body this client will read.
///
/// Discovery documents run to a few kilobytes and key sets to a few more. A megabyte is
/// two orders of magnitude of headroom and still a bound.
const MAX_BODY: u64 = 1024 * 1024;

impl Fetch for Http {
    fn get(&self, url: &str) -> Result<String> {
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|e| Error::Transport(format!("GET {url}: {e}")))?;
        response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_string()
            .map_err(|e| Error::Transport(format!("reading {url}: {e}")))
    }

    fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<String> {
        let mut request = self.agent.post(url).header("Accept", "application/json");
        if let Some((user, password)) = basic {
            // RFC 7617, over *standard* base64. The components are percent-encoded
            // first, per OAuth 2.0 §2.3.1 — a client secret containing a colon would
            // otherwise be read as part of the username.
            let credentials = format!(
                "{}:{}",
                crate::flow::encode_component(user),
                crate::flow::encode_component(password)
            );
            let encoded = b64::encode_standard(credentials.as_bytes());
            request = request.header("Authorization", &format!("Basic {encoded}"));
        }

        let mut response = request
            .send_form(form.iter().copied())
            // A 4xx here is a refusal with a body worth reading, not a transport
            // failure — the body is where the provider says *which* thing is wrong.
            .map_err(|e| match e {
                ureq::Error::StatusCode(_) => Error::Provider(format!("POST {url}: {e}")),
                other => Error::Transport(format!("POST {url}: {other}")),
            })?;

        response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_string()
            .map_err(|e| Error::Transport(format!("reading {url}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A provider that answers from a script, and counts.
    #[derive(Debug)]
    struct Scripted {
        body: Mutex<String>,
        gets: AtomicUsize,
        fail: Mutex<bool>,
    }

    impl Scripted {
        fn new(body: &str) -> Self {
            Self {
                body: Mutex::new(body.to_owned()),
                gets: AtomicUsize::new(0),
                fail: Mutex::new(false),
            }
        }
        fn serve(&self, body: &str) {
            *self.body.lock().unwrap() = body.to_owned();
        }
        fn go_down(&self) {
            *self.fail.lock().unwrap() = true;
        }
    }

    impl Fetch for Scripted {
        fn get(&self, _url: &str) -> Result<String> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            if *self.fail.lock().unwrap() {
                return Err(Error::Transport("the provider is unreachable".to_owned()));
            }
            Ok(self.body.lock().unwrap().clone())
        }
        fn post_form(
            &self,
            _: &str,
            _: &[(&str, &str)],
            _: Option<(&str, &str)>,
        ) -> Result<String> {
            Ok(self.body.lock().unwrap().clone())
        }
    }

    fn jwks(kid: &str) -> String {
        format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","alg":"RS256","n":"{}","e":"AQAB"}}]}}"#,
            b64::encode(&[0x0b; 256])
        )
    }

    fn at(minutes: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::UNIX_EPOCH + chrono::Duration::minutes(minutes)
    }

    #[test]
    fn a_key_set_is_fetched_once_and_then_cached() {
        let http = Scripted::new(&jwks("k1"));
        let keys = Keys::new();
        for _ in 0..5 {
            keys.for_token(&http, "https://idp/keys", Some("k1"), at(0))
                .unwrap();
        }
        assert_eq!(http.gets.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_unknown_kid_triggers_a_refresh() {
        // An early rotation. An interval-only cache turns this into an hour of failed
        // logins for everybody.
        let http = Scripted::new(&jwks("k1"));
        let keys = Keys::new();
        keys.for_token(&http, "https://idp/keys", Some("k1"), at(0))
            .unwrap();

        http.serve(&jwks("k2"));
        let set = keys
            .for_token(&http, "https://idp/keys", Some("k2"), at(2))
            .unwrap();
        assert_eq!(set.candidates(Some("k2"), crate::Alg::Rs256).len(), 1);
        assert_eq!(http.gets.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn invented_kids_cannot_be_used_to_hammer_the_provider() {
        // The endpoint that reaches this is unauthenticated, so without a floor a
        // stream of made-up `kid`s is a request amplifier pointed at the customer's
        // identity provider.
        let http = Scripted::new(&jwks("k1"));
        let keys = Keys::new();
        keys.for_token(&http, "https://idp/keys", Some("k1"), at(0))
            .unwrap();
        for i in 0..50 {
            let _ = keys.for_token(
                &http,
                "https://idp/keys",
                Some(&format!("made-up-{i}")),
                at(0),
            );
        }
        assert_eq!(
            http.gets.load(Ordering::SeqCst),
            1,
            "fifty invented kids inside the floor bought fifty requests to the provider"
        );
    }

    #[test]
    fn the_cache_expires_on_its_own() {
        let http = Scripted::new(&jwks("k1"));
        let keys = Keys::new();
        keys.for_token(&http, "https://idp/keys", Some("k1"), at(0))
            .unwrap();
        keys.for_token(&http, "https://idp/keys", Some("k1"), at(61))
            .unwrap();
        assert_eq!(http.gets.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_provider_that_goes_down_does_not_invalidate_good_keys() {
        // During an outage every token in flight is signed with a key the cache already
        // holds, so dropping the cache would turn a provider blip into a total sign-in
        // failure that outlasts it.
        let http = Scripted::new(&jwks("k1"));
        let keys = Keys::new();
        keys.for_token(&http, "https://idp/keys", Some("k1"), at(0))
            .unwrap();

        http.go_down();
        let set = keys
            .for_token(&http, "https://idp/keys", Some("k1"), at(120))
            .unwrap();
        assert_eq!(set.candidates(Some("k1"), crate::Alg::Rs256).len(), 1);
    }

    #[test]
    fn an_unreachable_provider_with_no_cache_is_an_error() {
        let http = Scripted::new("");
        http.go_down();
        let keys = Keys::new();
        assert!(
            keys.for_token(&http, "https://idp/keys", None, at(0))
                .is_err()
        );
    }

    #[test]
    fn forgetting_the_cache_makes_the_next_call_fetch() {
        let http = Scripted::new(&jwks("k1"));
        let keys = Keys::new();
        keys.for_token(&http, "https://idp/keys", Some("k1"), at(0))
            .unwrap();
        keys.forget();
        keys.for_token(&http, "https://idp/keys", Some("k1"), at(0))
            .unwrap();
        assert_eq!(http.gets.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_refusal_is_reported_as_a_refusal_and_not_as_a_parse_failure() {
        // The commonest SSO failure in the world is a redirect URI that does not match
        // the registered one, and the provider says exactly that in this body. Reporting
        // it as "could not parse the token response" costs an afternoon.
        let http = Scripted::new(
            r#"{"error":"invalid_grant","error_description":"redirect_uri does not match"}"#,
        );
        let provider = Discovered {
            issuer: "https://idp.example.com".to_owned(),
            authorization_endpoint: "https://idp.example.com/authorize".to_owned(),
            token_endpoint: "https://idp.example.com/token".to_owned(),
            jwks_uri: "https://idp.example.com/keys".to_owned(),
            end_session_endpoint: None,
        };
        let err = redeem(
            &http,
            &provider,
            "uops",
            Some("s"),
            "https://uops/cb",
            "c",
            "v",
        )
        .unwrap_err();
        let Error::Provider(why) = err else {
            panic!("{err:?}")
        };
        assert!(why.contains("invalid_grant"), "{why}");
        assert!(why.contains("redirect_uri"), "{why}");
    }

    #[test]
    fn a_token_response_parses() {
        let http = Scripted::new(r#"{"id_token":"a.b.c","token_type":"Bearer","expires_in":3600}"#);
        let provider = Discovered {
            issuer: "https://idp.example.com".to_owned(),
            authorization_endpoint: "https://idp.example.com/authorize".to_owned(),
            token_endpoint: "https://idp.example.com/token".to_owned(),
            jwks_uri: "https://idp.example.com/keys".to_owned(),
            end_session_endpoint: None,
        };
        let response = redeem(
            &http,
            &provider,
            "uops",
            Some("s"),
            "https://uops/cb",
            "c",
            "v",
        )
        .unwrap();
        assert_eq!(response.id_token, "a.b.c");
    }

    #[test]
    fn discovery_goes_through_the_issuer_check() {
        let http = Scripted::new(
            r#"{"issuer":"https://elsewhere.example.com",
                "authorization_endpoint":"https://x/a","token_endpoint":"https://x/t",
                "jwks_uri":"https://x/k"}"#,
        );
        let err = discover(&http, "https://idp.example.com").unwrap_err();
        assert!(matches!(err, Error::Discovery(_)), "{err:?}");
    }
}
