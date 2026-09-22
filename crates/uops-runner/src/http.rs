//! The HTTP transport for `http.request` steps.
//!
//! A device API rather than a general HTTP client, and the difference shows up in what it
//! refuses. The URL comes from a runbook an operator wrote and a reviewer approved, but
//! part of it is *rendered* — `{{ resource.address }}` — so the check is here rather than
//! trusted to the review.
//!
//! # What it will not fetch
//!
//! **Only `http://`.** Not `file:`, not `gopher:`, not a scheme this client would hand to
//! something else. `https` is absent for the reason every other client in this workspace
//! has no TLS: the licence allow-list, and a reverse proxy that every on-premise
//! deployment already runs.
//!
//! # The credential is a bearer token and nothing else
//!
//! An `ApiToken` becomes an `Authorization` header. It is never put in the URL — a token
//! in a query string is a token in the device's own access log, and this product writes
//! the URL into a transcript an auditor reads.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt as _;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use uops_core::{CredentialMaterial, CredentialRef};
use uops_runbook::HttpMethod;

use crate::transport::{Endpoint, Outcome};
use crate::vault::Vault;

/// How long one request gets.
///
/// Shorter than an SSH step's budget: a device API that has not answered in thirty
/// seconds is not going to.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The most body read back, before redaction. Matches the SSH transport's cap.
pub const MAX_READ: usize = crate::ssh::MAX_READ;

/// The HTTP transport.
pub struct Http {
    vault: Arc<Vault>,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, String>,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http").finish_non_exhaustive()
    }
}

impl Http {
    #[must_use]
    pub fn new(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            client: Client::builder(TokioExecutor::new()).build_http(),
        }
    }

    /// Make one request.
    pub async fn request(
        &self,
        to: &Endpoint,
        method: HttpMethod,
        url: &str,
        body: Option<&str>,
        credential: Option<CredentialRef>,
    ) -> Outcome {
        if let Err(why) = check_url(url) {
            return Outcome::failed(why);
        }

        let token = match credential {
            None => None,
            Some(reference) => {
                let context = crate::vault::step_context(to.resource, crate::vault::HTTP_STEP);
                match self.vault.get(to.tenant, reference, &context) {
                    Err(e) => {
                        return Outcome::failed(format!("the credential could not be opened: {e}"));
                    }
                    Ok(opened) => match opened.expose() {
                        CredentialMaterial::ApiToken(token) => Some(token.clone()),
                        other => {
                            return Outcome::failed(format!(
                                "an http.request step needs an API token credential, and \
                                 this one is {other:?}"
                            ));
                        }
                    },
                }
            }
        };

        let mut request = hyper::Request::builder()
            .method(method.as_str())
            .uri(url)
            .header(hyper::header::USER_AGENT, "uops-runner");
        if let Some(token) = token {
            request = request.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if body.is_some() {
            request = request.header(hyper::header::CONTENT_TYPE, "application/json");
        }

        let request = match request.body(body.unwrap_or_default().to_owned()) {
            Ok(request) => request,
            Err(e) => return Outcome::failed(format!("the request could not be built: {e}")),
        };

        let sent = tokio::time::timeout(REQUEST_TIMEOUT, self.client.request(request)).await;
        let response = match sent {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => return Outcome::failed(format!("{url} could not be reached: {e}")),
            Err(_) => {
                return Outcome::failed(format!(
                    "{url} did not answer within {}s",
                    REQUEST_TIMEOUT.as_secs()
                ));
            }
        };

        let status = response.status();
        let collected = match response.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => return Outcome::failed(format!("the response body could not be read: {e}")),
        };

        let mut text = String::from_utf8_lossy(&collected).into_owned();
        crate::ssh::truncate_on_boundary(&mut text, MAX_READ);

        Outcome::answered(status.as_u16(), text)
    }
}

/// What this client will fetch.
///
/// # Errors
///
/// A scheme other than `http`, or a URL this client cannot parse. Both name the URL,
/// because the operator's next action is to look at the runbook's template.
fn check_url(url: &str) -> Result<(), String> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(format!("`{url}` is not a URL this step can request"));
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(format!(
            "`{scheme}` is not a scheme a runbook step may request. Only http is, and \
             https is terminated at the reverse proxy this deployment already runs — see \
             the note in this module."
        ));
    }
    if rest.is_empty() {
        return Err(format!("`{url}` has no host"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_http_is_requestable() {
        assert!(check_url("http://10.0.0.1/api/v1/reload").is_ok());
        assert!(check_url("HTTP://10.0.0.1/x").is_ok());

        // The ones that matter: a rendered URL that changed scheme is how a device API
        // call becomes a local file read.
        for bad in [
            "file:///etc/shadow",
            "gopher://10.0.0.1/",
            "ftp://10.0.0.1/",
            "https://10.0.0.1/",
            "10.0.0.1/api",
            "http://",
        ] {
            assert!(check_url(bad).is_err(), "{bad} was allowed");
        }
    }

    #[test]
    fn the_refusal_says_which_scheme_and_why_https_is_absent() {
        // The operator's next action is to look at the runbook's template, and "invalid
        // URL" would send them to look at the device instead.
        let why = check_url("https://10.0.0.1/").unwrap_err();
        assert!(why.contains("https"), "{why}");
        assert!(why.contains("reverse proxy"), "{why}");
    }

    #[test]
    fn a_request_timeout_is_shorter_than_an_ssh_step() {
        // A device API that has not answered in thirty seconds is not going to, and the
        // operator is watching.
        assert!(REQUEST_TIMEOUT < crate::ssh::STEP_BUDGET);
    }
}
