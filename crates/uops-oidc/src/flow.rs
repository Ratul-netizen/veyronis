//! Starting a sign-in, and recognising the answer — RFC 6749 §4.1, RFC 7636.
//!
//! # Three random values, three different jobs
//!
//! They are easy to confuse, and a deployment that conflates any two of them has a hole:
//!
//! | value | held by | answers |
//! |---|---|---|
//! | `state` | this server, in a cookie | *did this browser start this sign-in?* |
//! | `nonce` | this server, in a cookie | *was this token minted for this sign-in?* |
//! | PKCE verifier | this server, in a cookie | *is the party redeeming this code the one that asked for it?* |
//!
//! `state` stops a cross-site request forgery on the callback — without it, an attacker
//! completes a sign-in *as themselves* in the victim's browser, and everything the
//! victim then does happens in the attacker's account.
//!
//! `nonce` stops the replay of a token captured elsewhere. It is checked in
//! [`crate::token`], not here, because it is a property of the token.
//!
//! PKCE stops an intercepted authorization code being redeemed by whoever intercepted
//! it. For a confidential client holding a secret it is belt and braces — and it is
//! still here, because the code appears in a URL, URLs appear in proxy logs and browser
//! history, and a client secret that has leaked is exactly the situation where the
//! second layer is the only one left.
//!
//! # Why the state lives in a cookie rather than a table
//!
//! It is per-browser, short-lived, and only ever read back by the same browser that was
//! given it — which is precisely a cookie's shape. A table would need a sweeper, would
//! grow under a crawler hitting the login endpoint, and would let one browser's
//! in-flight sign-in be completed by another. The cookie is `HttpOnly` and `SameSite=Lax`
//! so that it survives the provider's redirect back and is unreadable to script.

use crate::b64;
use crate::error::{Error, Result};
use crate::jws::sha256;

/// Bytes of randomness in each of `state`, `nonce` and the PKCE verifier.
///
/// 256 bits. RFC 7636 asks for at least 32 characters of verifier and allows 128; this
/// produces 43, which is the minimum length and 256 bits of entropy because the encoding
/// is dense rather than a hex string pretending to be one.
pub const ENTROPY: usize = 32;

/// How long a started sign-in stays completable.
///
/// Ten minutes. Long enough for a password, a push notification and a fumbled phone;
/// short enough that a `state` cookie left on a shared machine is not a standing
/// invitation. It is the cookie's `Max-Age`, so expiry is the browser's to enforce and
/// needs nothing swept here.
pub const WINDOW: chrono::Duration = chrono::Duration::minutes(10);

/// The three secrets for one sign-in, generated together.
///
/// Together, because generating them in three places is how two of them end up equal —
/// and a `state` that equals the `nonce` means a captured redirect URL carries both.
#[derive(Clone, Debug)]
pub struct Pending {
    /// Sent to the provider and returned in the callback; also stored in the cookie.
    pub state: String,
    /// Sent to the provider, which puts it in the token. Never appears in the callback.
    pub nonce: String,
    /// Kept here. Only its hash is sent.
    pub verifier: String,
    /// Where to send the browser afterwards, within this application.
    ///
    /// A path, always — [`safe_return_to`] is what makes that true, and why it is not
    /// simply whatever the login page put in the query string.
    pub return_to: String,
}

impl Pending {
    /// Start a sign-in.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if the operating system's randomness is unavailable, which
    /// is not a condition to paper over with a fallback.
    pub fn start(return_to: Option<&str>) -> Result<Self> {
        Ok(Self {
            state: random()?,
            nonce: random()?,
            verifier: random()?,
            return_to: safe_return_to(return_to),
        })
    }

    /// The `code_challenge` to send: base64url of SHA-256 over the verifier.
    ///
    /// `S256` only. RFC 7636 also defines `plain`, which sends the verifier itself and
    /// therefore protects against nothing — it exists for devices that cannot hash, and
    /// there are none here.
    #[must_use]
    pub fn challenge(&self) -> String {
        b64::encode(&sha256(self.verifier.as_bytes()))
    }

    /// The URL to send the browser to.
    ///
    /// `prompt` and `login_hint` are deliberately absent: the first is a policy the
    /// identity provider owns, and the second would leak whichever address the user
    /// typed into a URL that ends up in their history.
    #[must_use]
    pub fn authorization_url(
        &self,
        authorization_endpoint: &str,
        client_id: &str,
        redirect_uri: &str,
        scopes: &str,
    ) -> String {
        // A discovery document's endpoint may already carry a query — Entra ID's does
        // not, some Keycloak deployments behind a rewriting proxy do. Appending with the
        // wrong separator produces a URL that fails in a way nobody can read.
        let separator = if authorization_endpoint.contains('?') { '&' } else { '?' };
        let mut url = format!("{authorization_endpoint}{separator}response_type=code");
        for (key, value) in [
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("scope", scopes),
            ("state", self.state.as_str()),
            ("nonce", self.nonce.as_str()),
            ("code_challenge", &self.challenge()),
            ("code_challenge_method", "S256"),
        ] {
            url.push('&');
            url.push_str(key);
            url.push('=');
            url.push_str(&encode_component(value));
        }
        url
    }

    /// Check a callback's `state` against this sign-in's.
    ///
    /// # Errors
    ///
    /// [`Error::State`] when they differ — which means this callback belongs to a
    /// sign-in this browser did not start.
    pub fn accept(&self, returned_state: &str) -> Result<()> {
        // Not constant-time, and that is correct rather than an omission: `state` is not
        // a secret being guessed. It is this browser's own value, and the party who
        // could time this comparison is the party holding the cookie it is compared to.
        if returned_state != self.state {
            return Err(Error::State(
                "this callback does not belong to a sign-in this browser started",
            ));
        }
        Ok(())
    }
}

/// `ENTROPY` bytes from the OS, base64url.
fn random() -> Result<String> {
    let mut bytes = [0u8; ENTROPY];
    getrandom::fill(&mut bytes)
        .map_err(|e| Error::Transport(format!("the system random source failed: {e}")))?;
    Ok(b64::encode(&bytes))
}

/// Where a completed sign-in may send the browser.
///
/// An open redirect on the login flow is worth more to a phisher than most bugs in this
/// product: the link genuinely is the customer's domain, the sign-in genuinely succeeds,
/// and the user lands wherever the link said. So this refuses everything except a path
/// within this application, and refusing means `/`, not an error — a bad `return_to` is
/// a redirect to the home page, never a failed login.
///
/// `//evil.example.com` is the case an obvious check misses: it begins with `/`, and a
/// browser reads it as a protocol-relative URL to another host.
#[must_use]
pub fn safe_return_to(candidate: Option<&str>) -> String {
    const HOME: &str = "/";

    let Some(path) = candidate else {
        return HOME.to_owned();
    };
    if path.len() > 512 || !path.starts_with('/') || path.starts_with("//") {
        return HOME.to_owned();
    }
    // `/\evil.example.com` is read as protocol-relative by more than one browser, and
    // a control character can split a header further down.
    if path.contains('\\') || path.chars().any(char::is_control) {
        return HOME.to_owned();
    }
    path.to_owned()
}

/// Percent-encode a value for a query string or a form body.
///
/// Written out rather than imported for the same reason as [`crate::b64`]: what must be
/// escaped is exactly RFC 3986's unreserved set, and a crate that is lenient about one
/// character of it puts an `&` into a URL this code assembled.
///
/// Shared with [`crate::fetch`], which needs the same escaping for the two halves of a
/// Basic credential — OAuth 2.0 §2.3.1 specifies it there, and a client secret
/// containing a colon is read as part of the username without it.
pub(crate) fn encode_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            other => {
                out.push('%');
                out.push(HEX[usize::from(other >> 4)] as char);
                out.push(HEX[usize::from(other & 0x0f)] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_values_are_three_values() {
        let pending = Pending::start(None).unwrap();
        assert_ne!(pending.state, pending.nonce);
        assert_ne!(pending.state, pending.verifier);
        assert_ne!(pending.nonce, pending.verifier);
    }

    #[test]
    fn the_verifier_is_long_enough_for_rfc_7636() {
        let pending = Pending::start(None).unwrap();
        assert!(
            (43..=128).contains(&pending.verifier.len()),
            "{} characters",
            pending.verifier.len()
        );
    }

    #[test]
    fn two_sign_ins_share_nothing() {
        let a = Pending::start(None).unwrap();
        let b = Pending::start(None).unwrap();
        assert_ne!(a.state, b.state);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.verifier, b.verifier);
    }

    #[test]
    fn the_challenge_is_the_hash_and_not_the_verifier() {
        // `plain` sends the verifier itself and therefore protects against nothing.
        let pending = Pending::start(None).unwrap();
        assert_ne!(pending.challenge(), pending.verifier);
        assert_eq!(pending.challenge(), b64::encode(&sha256(pending.verifier.as_bytes())));
    }

    #[test]
    fn the_challenge_matches_the_vector_in_rfc_7636() {
        // Appendix B. A hand-written encoder and a hand-written hash wrapper agreeing
        // with the RFC's own numbers is worth more than either agreeing with itself.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            b64::encode(&sha256(verifier.as_bytes())),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_authorization_url_carries_everything_the_provider_needs() {
        let pending = Pending::start(None).unwrap();
        let url = pending.authorization_url(
            "https://idp.example.com/authorize",
            "uops",
            "https://uops.example.com/api/v1/auth/oidc/callback",
            "openid email profile",
        );
        assert!(url.starts_with("https://idp.example.com/authorize?response_type=code&"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(&format!("state={}", encode_component(&pending.state))));
        assert!(url.contains(&format!("nonce={}", encode_component(&pending.nonce))));
        // The verifier is the one value that must never travel.
        assert!(!url.contains(&pending.verifier), "the verifier was sent to the provider");
    }

    #[test]
    fn an_endpoint_that_already_has_a_query_is_appended_to_correctly() {
        let pending = Pending::start(None).unwrap();
        let url = pending.authorization_url(
            "https://idp.example.com/authorize?tenant=acme",
            "uops",
            "https://uops.example.com/cb",
            "openid",
        );
        assert!(url.contains("?tenant=acme&response_type=code"), "{url}");
    }

    #[test]
    fn values_are_escaped_into_the_url() {
        let pending = Pending::start(None).unwrap();
        let url = pending.authorization_url(
            "https://idp.example.com/authorize",
            "uops",
            "https://uops.example.com/cb",
            "openid email profile",
        );
        assert!(url.contains("scope=openid%20email%20profile"), "{url}");
        assert!(url.contains("redirect_uri=https%3A%2F%2Fuops.example.com%2Fcb"), "{url}");
    }

    #[test]
    fn a_callback_for_another_sign_in_is_refused() {
        let pending = Pending::start(None).unwrap();
        let other = Pending::start(None).unwrap();
        assert!(pending.accept(&pending.state).is_ok());
        assert!(matches!(pending.accept(&other.state), Err(Error::State(_))));
        assert!(matches!(pending.accept(""), Err(Error::State(_))));
    }

    #[test]
    fn the_return_path_cannot_leave_this_application() {
        // An open redirect here is worth more to a phisher than most bugs in this
        // product: the domain is genuinely the customer's and the sign-in genuinely
        // works.
        for hostile in [
            "https://evil.example.com",
            "//evil.example.com",
            "/\\evil.example.com",
            "javascript:alert(1)",
            "http://evil.example.com/path",
            "/ok\r\nSet-Cookie: session=stolen",
        ] {
            assert_eq!(
                safe_return_to(Some(hostile)),
                "/",
                "{hostile} survived as a redirect target"
            );
        }
    }

    #[test]
    fn an_ordinary_path_survives() {
        assert_eq!(safe_return_to(Some("/incidents")), "/incidents");
        assert_eq!(safe_return_to(Some("/r/abc?tab=timeline")), "/r/abc?tab=timeline");
        assert_eq!(safe_return_to(None), "/");
    }

    #[test]
    fn an_absurdly_long_path_is_dropped() {
        let long = format!("/{}", "a".repeat(600));
        assert_eq!(safe_return_to(Some(&long)), "/");
    }
}
