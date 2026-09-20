//! The sweep the server actually runs.
//!
//! [`Live`] is the production half of the [`Sweep`](crate::Sweep) seam: it opens the
//! credentials a job names, probes the job's ranges with them, and hands the findings to
//! the store. Nothing here decides *when* — that is [`turn`](crate::turn) — and nothing
//! here decides *how to probe*, which is `uops_discover::run_with` and has been tested
//! since M5's first acceptance criterion.
//!
//! # Why the transports are cached per credential
//!
//! The same argument `uops-poller`'s `Transports` makes, for the same reason:
//! [`UdpTransport`] holds one credential and a pool of sessions keyed by address, so a
//! transport per credential re-derives `SNMPv3`'s localised keys once per credential
//! rather than once per address. A /24 against four credentials is a thousand probes; it
//! is not a thousand key derivations.
//!
//! Across sweeps as well as within one, because a nightly job opens the same four
//! credentials every night and a vault access log written at sweep rate is a log nobody
//! can find an anomaly in.
//!
//! # Why a missing credential fails the whole run
//!
//! A job names what it may try and there is no fallback — `uops-discover`'s first rule.
//! If one of the four cannot be opened, the sweep that runs is not the sweep the operator
//! configured: it would probe the estate with three credentials and record everything the
//! fourth would have answered as `unreachable`, which is worse than not sweeping, because
//! it looks like an answer. So the run fails with a sentence naming the credential, and
//! the estate is left as it was.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use uops_core::{CredentialRef, TenantScope};
use uops_discover::{Sweep as Addresses, run_with};
use uops_identity::Resolver;
use uops_secrets::{LocalVault, MemoryAccessLog, RustCryptoAead};
use uops_snmp::{Transport, UdpTransport};
use uops_store_pg::discovery_jobs::{DiscoveryJob, RunCounts};
use uops_store_pg::sweep_ingest::SweepContext;
use uops_store_pg::{PgSealedStore, PgStore};

/// The vault this crate reads credentials through.
///
/// The same shape the server and the poller build, so a credential stored through the API
/// is openable here without a second key path to keep in step.
pub type Vault = LocalVault<RustCryptoAead, PgSealedStore, MemoryAccessLog>;

/// A sweep that talks to the network.
pub struct Live {
    vault: Vault,
    resolver: Resolver<PgStore>,
    store: PgStore,
    open: Mutex<HashMap<(uops_core::TenantId, CredentialRef), Arc<UdpTransport>>>,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A count. Everything inside the map is derived from a credential.
        f.debug_struct("Live")
            .field("open", &self.open().len())
            .finish_non_exhaustive()
    }
}

impl Live {
    #[must_use]
    pub fn new(store: PgStore, vault: Vault) -> Self {
        Self {
            vault,
            resolver: Resolver::new(store.clone()),
            store,
            open: Mutex::new(HashMap::new()),
        }
    }

    /// A poisoned lock means a panic while holding it, which cannot happen here — the
    /// critical sections are a hash lookup and an insert. Recovering the guard beats
    /// turning somebody else's panic into a failed sweep.
    fn open(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<(uops_core::TenantId, CredentialRef), Arc<UdpTransport>>>
    {
        self.open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The transport for one of a job's credentials, opening it the first time.
    fn transport(
        &self,
        tenant: uops_core::TenantId,
        credential: CredentialRef,
    ) -> Result<Arc<UdpTransport>, String> {
        let key = (tenant, credential);
        if let Some(open) = self.open().get(&key) {
            return Ok(Arc::clone(open));
        }

        let ctx = uops_snmp::credential::discovery_context();
        let opened = self
            .vault
            .get(tenant, credential, &ctx)
            .map_err(|e| format!("credential {credential} could not be opened: {e}"))?;

        // The Secret, not the material: the plaintext is never owned outside one, and is
        // zeroized when the last transport holding it is dropped.
        let transport =
            Arc::new(UdpTransport::new(opened).with_timeout(uops_discover::PROBE_TIMEOUT));
        self.open().insert(key, Arc::clone(&transport));
        Ok(transport)
    }
}

impl crate::Sweep for Live {
    async fn sweep(
        &self,
        scope: &TenantScope,
        job: &DiscoveryJob,
        run_id: uuid::Uuid,
    ) -> Result<RunCounts, String> {
        // Before anything is opened or sent. `Sweep::new` is the bounds check — §2.3 —
        // and a job that cannot be expanded is a configuration error the operator reads
        // off the run rather than a sweep that half-happens.
        let addresses = Addresses::new(&job.ranges).map_err(|e| e.to_string())?;

        if job.credential_refs.is_empty() {
            return Err(
                "this job names no credentials, so there is nothing to probe with".to_owned(),
            );
        }

        // In the order the job names them, because that order is what a sighting's
        // credential index refers to when the store turns it back into a reference.
        let mut transports = Vec::with_capacity(job.credential_refs.len());
        for credential in &job.credential_refs {
            transports.push(self.transport(job.tenant_id, *credential)?);
        }
        let borrowed: Vec<&dyn Transport> =
            transports.iter().map(|t| &**t as &dyn Transport).collect();

        let findings = run_with(&borrowed, &addresses, job.snmp_port).await;

        self.store
            .record_sweep(
                scope,
                &self.resolver,
                &findings,
                SweepContext {
                    run_id: Some(run_id),
                    site_id: job.site_id,
                    credentials: &job.credential_refs,
                },
            )
            .await
            .map_err(|e| format!("the sweep finished but its findings could not be recorded: {e}"))
    }
}
