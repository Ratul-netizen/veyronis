//! What every handler is given.

use std::sync::Arc;

use uops_secrets::{LocalVault, MemoryAccessLog, RustCryptoAead};
use uops_store_ch::ChStore;
use uops_store_pg::{PgSealedStore, PgStore};

use crate::cookie::Secure;

/// The vault this API seals credentials with.
///
/// The same type `uops-poller` opens them with, over the same table and the same key
/// ring — which is the point: a credential the API wrote that the poller cannot read is
/// a device that silently never gets polled.
pub type Vault = LocalVault<RustCryptoAead, PgSealedStore, MemoryAccessLog>;

/// Shared application state.
///
/// Cheap to clone — `PgStore` wraps a pool that is already an `Arc` — which is what
/// axum requires of state and what lets a handler hold it without ceremony.
#[derive(Clone)]
pub struct AppState {
    /// The control plane: resources, identity, users, both audit logs.
    pub store: PgStore,
    /// Telemetry. Required rather than optional: an API that cannot answer a query is
    /// not a degraded version of this product, it is a different one — and an `Option`
    /// here would put a "telemetry is not configured" branch in every handler that
    /// touches it.
    pub telemetry: ChStore,
    /// Whether cookies carry `Secure`. On, except for a developer on plain HTTP
    /// against localhost, where the browser would silently discard them and the app
    /// would appear broken for a reason nothing logs.
    pub secure_cookies: Secure,
    /// Where device credentials are sealed. `None` when the deployment has configured no
    /// key-encryption key.
    ///
    /// Optional, unlike the stores, and the asymmetry is deliberate. An API with no
    /// telemetry is a different product; an API with no KEK is this product with one
    /// feature switched off — everything except storing a device credential works
    /// exactly as before. Making it required would mean a deployment that only wants the
    /// inventory could not start, and would put a KEK in every developer's environment
    /// for a feature they are not using.
    ///
    /// The route says so plainly rather than 500-ing: see `routes::credentials`.
    pub vault: Option<Arc<Vault>>,
    /// What a sign-in through an identity provider needs while the server runs — see
    /// [`crate::sso`]. Always present, unlike the vault: a *public* client works without
    /// any key material, and a deployment with no identity provider configured simply
    /// never reaches it.
    pub sso: Arc<crate::sso::Sso>,
    /// The redirect URI registered at the identity provider.
    ///
    /// Configured rather than derived from the request, and that is the decision worth
    /// recording: deriving it from `Host` would let whoever controls that header point a
    /// sign-in's authorization code at a host of their choosing, and the provider —
    /// which is comparing against its own registered list — would be the only thing
    /// standing in the way. A constant string cannot be influenced.
    pub oidc_redirect_uri: String,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written because the vault holds a key ring. `LocalVault`'s own `Debug`
        // prints only its backend and active key id, but a derived impl here would mean
        // that staying true is somebody else's job.
        f.debug_struct("AppState")
            .field("secure_cookies", &self.secure_cookies)
            .field("vault", &self.vault.is_some())
            .field("sso", &self.sso)
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Production defaults, with no vault. See [`AppState::with_vault`].
    #[must_use]
    pub fn new(store: PgStore, telemetry: ChStore) -> Self {
        Self {
            store,
            telemetry,
            secure_cookies: Secure::Yes,
            vault: None,
            sso: Arc::new(crate::sso::Sso::new()),
            // Overwritten by `with_public_url`. The default is what a single-host
            // deployment on localhost needs, and a provider's registered list is what
            // refuses it anywhere else.
            oidc_redirect_uri: "http://localhost:8080/api/v1/auth/oidc/callback".to_owned(),
        }
    }

    /// Where this deployment is reachable from a browser.
    ///
    /// The redirect URI is built from it once, at boot, rather than per request. See
    /// [`AppState::oidc_redirect_uri`].
    #[must_use]
    pub fn with_public_url(mut self, base: &str) -> Self {
        self.oidc_redirect_uri =
            format!("{}/api/v1/auth/oidc/callback", base.trim_end_matches('/'));
        self
    }

    /// Give this API what it needs to complete a sign-in.
    #[must_use]
    pub fn with_sso(mut self, sso: crate::sso::Sso) -> Self {
        self.sso = Arc::new(sso);
        self
    }

    /// Give this API somewhere to seal device credentials.
    #[must_use]
    pub fn with_vault(mut self, vault: Vault) -> Self {
        self.vault = Some(Arc::new(vault));
        self
    }

    /// Drop the `Secure` cookie attribute. For `http://localhost` only — and named so
    /// that it is visible in a diff if it ever reaches a deployment.
    #[must_use]
    pub const fn allowing_insecure_cookies(mut self) -> Self {
        self.secure_cookies = Secure::No;
        self
    }
}
