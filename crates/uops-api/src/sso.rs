//! What a sign-in through an identity provider needs while the server is running.
//!
//! Three things, and they are here rather than in `AppState` because two of them are
//! caches and the third holds key material:
//!
//! * an **HTTP client** that speaks TLS — the one in this workspace that does;
//! * a **key set per provider**, so that a sign-in is one round trip to the provider
//!   rather than three;
//! * an **envelope**, to open the client secret, which needs the KEK.
//!
//! # The envelope is optional and the rest is not
//!
//! The same asymmetry `AppState::vault` has, for the same reason. A deployment with no
//! KEK can still use a *public* client — PKCE alone, which is a legitimate and common
//! configuration — and refusing to start would mean a KEK in every developer's
//! environment for a feature they are not using. A confidential client without a KEK is
//! reported by the route, in a sentence naming what to set.

use std::collections::HashMap;
use std::sync::Mutex;

use uops_core::Secret;
use uops_oidc::fetch::{Fetch, Http, Keys};
use uops_secrets::{Envelope, RustCryptoAead, SealedValue};

/// The AAD a provider's client secret is sealed under.
///
/// The row it belongs to, so the ciphertext refuses to open anywhere else — see
/// `uops_secrets::envelope`. Written once, here, because the sealing and the opening
/// happen in different handlers and a context that differs between them is a client
/// secret that stops working at the next sign-in rather than at the write.
#[must_use]
pub fn secret_context(provider: uuid::Uuid) -> String {
    format!("identity_provider:{provider}")
}

/// Everything a sign-in needs that outlives one request.
pub struct Sso {
    http: Box<dyn Fetch>,
    /// One key cache per provider. Created on first use and never evicted — the bound is
    /// the number of identity providers an organization has configured, which is small
    /// enough that an eviction policy would be more code than the thing it bounds.
    keys: Mutex<HashMap<uuid::Uuid, std::sync::Arc<Keys>>>,
    envelope: Option<Envelope<RustCryptoAead>>,
}

impl std::fmt::Debug for Sso {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written because the envelope holds a key ring, and a derived impl would
        // make keeping that out of a log somebody else's job. Same reasoning as
        // `AppState`'s.
        f.debug_struct("Sso")
            .field("can_open_client_secrets", &self.envelope.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for Sso {
    fn default() -> Self {
        Self::new()
    }
}

impl Sso {
    /// A runtime that can complete a public-client sign-in and nothing more.
    #[must_use]
    pub fn new() -> Self {
        Self {
            http: Box::new(Http::new()),
            keys: Mutex::new(HashMap::new()),
            envelope: None,
        }
    }

    /// Give it the key material to open stored client secrets.
    #[must_use]
    pub fn with_envelope(mut self, envelope: Envelope<RustCryptoAead>) -> Self {
        self.envelope = Some(envelope);
        self
    }

    /// Replace the HTTP client. For tests, which script a provider rather than reach one.
    #[must_use]
    pub fn with_http(mut self, http: Box<dyn Fetch>) -> Self {
        self.http = http;
        self
    }

    #[must_use]
    pub fn http(&self) -> &dyn Fetch {
        self.http.as_ref()
    }

    /// This provider's key cache, created on first use.
    #[must_use]
    pub fn keys(&self, provider: uuid::Uuid) -> std::sync::Arc<Keys> {
        let mut cache = self
            .keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.entry(provider).or_default().clone()
    }

    /// Forget a provider's keys. For an operator who has just changed it.
    pub fn forget(&self, provider: uuid::Uuid) {
        let mut cache = self
            .keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.remove(&provider);
    }

    /// Whether this deployment can hold a confidential client's secret.
    #[must_use]
    pub const fn can_seal(&self) -> bool {
        self.envelope.is_some()
    }

    /// Seal a client secret for storage.
    ///
    /// # Errors
    ///
    /// `None` when no KEK is configured. The caller turns that into a 503 naming the
    /// variable to set, rather than a 500 — it is a deployment that has not been
    /// finished, not a server that is broken.
    #[must_use]
    pub fn seal(&self, provider: uuid::Uuid, secret: Secret<String>) -> Option<SealedValue> {
        self.envelope
            .as_ref()?
            .seal(&secret_context(provider), secret)
            .ok()
    }

    /// Open a stored client secret.
    #[must_use]
    pub fn open(&self, provider: uuid::Uuid, sealed: &SealedValue) -> Option<Secret<String>> {
        self.envelope
            .as_ref()?
            .open(&secret_context(provider), sealed)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_provider_gets_the_same_key_cache() {
        // A new cache per request would make the cache pointless: every sign-in would
        // fetch the provider's keys again, which is the round trip it exists to remove.
        let sso = Sso::new();
        let id = uuid::Uuid::now_v7();
        assert!(std::sync::Arc::ptr_eq(&sso.keys(id), &sso.keys(id)));
        assert!(!std::sync::Arc::ptr_eq(
            &sso.keys(id),
            &sso.keys(uuid::Uuid::now_v7())
        ));
    }

    #[test]
    fn forgetting_one_provider_leaves_the_others() {
        let sso = Sso::new();
        let a = uuid::Uuid::now_v7();
        let b = uuid::Uuid::now_v7();
        let kept = sso.keys(b);
        let dropped = sso.keys(a);
        sso.forget(a);
        assert!(std::sync::Arc::ptr_eq(&sso.keys(b), &kept));
        assert!(!std::sync::Arc::ptr_eq(&sso.keys(a), &dropped));
    }

    #[test]
    fn without_a_kek_a_client_secret_cannot_be_stored() {
        // Not a panic and not a silent plaintext write: `None`, which the route turns
        // into a sentence naming the variable to set.
        let sso = Sso::new();
        assert!(!sso.can_seal());
        assert!(
            sso.seal(uuid::Uuid::now_v7(), Secret::new("s".to_owned()))
                .is_none()
        );
    }

    #[test]
    fn the_sealing_context_is_the_row_it_belongs_to() {
        let id = uuid::Uuid::now_v7();
        assert_eq!(secret_context(id), format!("identity_provider:{id}"));
        assert_ne!(secret_context(id), secret_context(uuid::Uuid::now_v7()));
    }
}
