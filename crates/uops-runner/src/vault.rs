//! Opening the credentials a step names — M10 §2.4.
//!
//! # The runbook never sees one
//!
//! A step says *which* credential by reference. This is the only place in the runner that
//! turns a reference into material, and what it hands back goes straight into the
//! transport that uses it. There is no binding for a credential in
//! `uops_runbook::render`, so a template cannot substitute one into a command, and
//! nothing here returns a `String`.
//!
//! # Why the access log says which resource
//!
//! The context string names the resource the credential is being used *against*, so the
//! vault's log answers "which devices did this key open" rather than only "how often was
//! it read". For a credential that changes an estate, the first question is the one worth
//! being able to answer.

use uops_secrets::{KekRing, LocalVault, MemoryAccessLog, RustCryptoAead};
use uops_store_pg::{PgSealedStore, PgStore};

use crate::config::{Config, KekSource};

/// The vault this binary uses: `RustCrypto` over `PostgreSQL`, logging to memory.
///
/// The same three parts the poller's is made of, and the same gap: the access log is in
/// memory because there is nowhere durable to put it yet. Named here rather than hidden
/// behind a type alias that reads as if it were resolved.
pub type Vault = LocalVault<RustCryptoAead, PgSealedStore, MemoryAccessLog>;

/// Build the vault from the configured key ring.
///
/// # Errors
///
/// When the KEK cannot be read, is not 64 hex characters, or — on Unix — is in a file
/// other local accounts can read.
pub fn open(store: PgStore, config: &Config) -> Result<Vault, uops_secrets::Error> {
    let ring = match &config.kek {
        KekSource::File(path) => KekRing::from_file(path, config.kek_id.clone())?,
        KekSource::Env(name) => KekRing::from_env(name, config.kek_id.clone())?,
    };
    Ok(LocalVault::new(
        RustCryptoAead,
        PgSealedStore::new(store),
        MemoryAccessLog::new(),
        ring,
    ))
}

/// What the vault's access log is told an SSH step's read is for.
///
/// `&'static str` by the type's own design — the vocabulary lives in the code rather than
/// in a runtime string — and `uops_secrets::AccessContext` already names this one in its
/// own documentation.
pub const SSH_STEP: &str = "ssh-runbook";

/// The same, for an `http.request` step.
///
/// A separate purpose rather than one "runbook": the two reach a device over different
/// protocols with different credential kinds, and a log that cannot tell them apart cannot
/// answer "was this API token ever used over SSH", which is the question a mis-assigned
/// credential raises.
pub const HTTP_STEP: &str = "http-runbook";

/// What the vault's access log is told this read is for.
///
/// The resource is named, so the log answers "which devices did this key open" rather than
/// only "how often was it read". For a credential that changes an estate, that is the
/// first question worth being able to answer.
#[must_use]
pub fn step_context(
    resource: uops_core::ResourceId,
    purpose: &'static str,
) -> uops_secrets::AccessContext {
    uops_secrets::AccessContext::new(uops_core::scope::Actor::System, purpose)
        .for_resource(resource)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_context_names_the_resource_a_credential_was_used_against() {
        let id = uops_core::ResourceId::new();
        let ctx = step_context(id, SSH_STEP);
        assert_eq!(ctx.resource_id, Some(id));
        assert_eq!(ctx.purpose, SSH_STEP);
    }

    #[test]
    fn the_two_step_kinds_are_distinguishable_in_the_log() {
        // A log that cannot tell them apart cannot answer "was this API token ever used
        // over SSH", which is the question a mis-assigned credential raises.
        assert_ne!(SSH_STEP, HTTP_STEP);
    }
}
