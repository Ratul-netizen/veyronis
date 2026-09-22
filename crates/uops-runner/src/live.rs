//! The transport a deployment actually uses: SSH over OpenSSH, HTTP over hyper.
//!
//! One type implementing [`crate::transport::Transport`] by dispatching to the two that do
//! the work. Neither of them implements the trait itself, on purpose: a transport that
//! answered *"this does not make HTTP requests"* to half the trait would be a type whose
//! shape lies about what it is for, and the executor would have to know which one to hand
//! each step to — which is exactly the knowledge this type exists to hold.

use std::path::Path;
use std::sync::Arc;

use uops_core::CredentialRef;
use uops_runbook::HttpMethod;

use crate::http::Http;
use crate::ssh::Ssh;
use crate::transport::{Endpoint, Outcome, Transport};
use crate::vault::Vault;

/// SSH and HTTP, chosen by the step.
#[derive(Debug)]
pub struct Live {
    ssh: Ssh,
    http: Http,
}

impl Live {
    /// `state_dir` is where `known_hosts` lives and where a key file exists for the
    /// duration of a step. One directory the product owns — see [`crate::ssh`].
    #[must_use]
    pub fn new(vault: Arc<Vault>, state_dir: &Path) -> Self {
        Self {
            ssh: Ssh::new(Arc::clone(&vault), state_dir),
            http: Http::new(vault),
        }
    }
}

#[async_trait::async_trait]
impl Transport for Live {
    async fn ssh(&self, to: &Endpoint, command: &str, credential: CredentialRef) -> Outcome {
        self.ssh.command(to, command, credential).await
    }

    async fn http(
        &self,
        to: &Endpoint,
        method: HttpMethod,
        url: &str,
        body: Option<&str>,
        credential: Option<CredentialRef>,
    ) -> Outcome {
        self.http.request(to, method, url, body, credential).await
    }
}
