//! What a step is sent over, and what comes back — M10 §2.10.
//!
//! # Why this is a trait
//!
//! Not for mocking. It is a trait because the interesting tests in this crate are about
//! what the *runner* does with an outcome — stops at the first failure, skips the
//! destructive steps in a dry run, records a transcript with the credential absent from
//! it — and those are properties of the orchestration, not of SSH. A scripted transport
//! makes each of them one assertion instead of an SSH server and a fixture.
//!
//! The real transports are tested against a real device the same way the poller's are:
//! by a `live` test that is skipped when the fixture is not there.
//!
//! # Every failure is an [`Outcome`], not an `Err`
//!
//! A device that refused the connection, a command that exited 1, a step that timed out —
//! all of them are things the *run* has to record against a resource and then decide
//! about. Returning `Result` would let a caller use `?` and abandon the run halfway
//! through a fleet with no transcript of what had already been sent, which is the one
//! outcome M10 §2.6 exists to prevent.

use uops_core::{CredentialRef, ResourceId, TenantId};
use uops_runbook::HttpMethod;

/// Where one step is going.
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub tenant: TenantId,
    pub resource: ResourceId,
    /// What an operator calls it. Carried so a failure reads in names.
    pub name: String,
    /// The management address, resolved at execution time — see
    /// `PgStore::resource_addresses` for why that is not a contradiction of §2.5.
    pub address: String,
}

/// What a step did.
///
/// `output` is raw here and redacted where it is stored, not before: redaction belongs at
/// the one place that writes, so there is no path that forgets — `PgStore::record_step`.
///
/// # `ok` is its own field, and that is deliberate
///
/// The obvious design derives success from `exit_code == Some(0)`, and it is wrong the
/// moment there is a second transport: an HTTP 200 is a success and is not zero, and 204
/// and 201 are successes too. Deriving it would mean either rewriting the status to 0 —
/// throwing away the number a transcript needs — or teaching this type which transport it
/// came from.
///
/// So the transport that knows what it asked says whether it got what it asked for, and
/// `exit_code` stays whatever the far end actually said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Whether the far end did what it was asked. Set by the transport.
    pub ok: bool,
    /// The remote command's status, or the HTTP status. `None` when nothing ran.
    pub exit_code: Option<i32>,
    pub output: String,
    /// Why the transport itself failed: no route, refused, a changed host key, a
    /// credential of a kind this transport will not use.
    ///
    /// Distinct from a non-zero `exit_code`, and the distinction matters: one of them
    /// means the device answered and said no, and the other means it was never asked.
    pub error: Option<String>,
}

impl Outcome {
    /// A transport that never reached the device.
    #[must_use]
    pub fn failed(why: impl Into<String>) -> Self {
        Self {
            ok: false,
            exit_code: None,
            output: String::new(),
            error: Some(why.into()),
        }
    }

    /// A process that ran and exited.
    #[must_use]
    pub fn exited(code: i32, output: String) -> Self {
        Self {
            ok: code == 0,
            exit_code: Some(code),
            output,
            error: None,
        }
    }

    /// A device API that answered.
    ///
    /// The status is kept as it was — a run record that says only "ok" cannot answer "did
    /// it 200 or 204", which is the first question when a device API changed behaviour
    /// between firmware versions.
    #[must_use]
    pub fn answered(status: u16, output: String) -> Self {
        let ok = (200..300).contains(&status);
        Self {
            ok,
            exit_code: Some(i32::from(status)),
            output,
            error: if ok {
                None
            } else {
                Some(format!("the device answered {status}"))
            },
        }
    }

    /// Whether the step did what it was asked.
    ///
    /// Both halves, because a transport that set `ok` and then failed to clean up after
    /// itself has produced a contradiction, and the safe reading of a contradiction is the
    /// pessimistic one.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.ok && self.error.is_none()
    }

    /// One line for the run's `failure` column.
    #[must_use]
    pub fn why(&self) -> String {
        match (&self.error, self.exit_code) {
            (Some(e), _) => e.clone(),
            (None, Some(code)) => format!("the step exited {code}"),
            (None, None) => "the step produced no result".to_owned(),
        }
    }
}

/// How a step reaches a device.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Run one command over SSH.
    ///
    /// `command` arrives already rendered — every placeholder substituted and every value
    /// checked against `uops_runbook::render`'s allow-list. An implementation must pass it
    /// as a single argument and must not interpolate it into anything a shell will read.
    async fn ssh(&self, to: &Endpoint, command: &str, credential: CredentialRef) -> Outcome;

    /// Make one HTTP request against a device's own API.
    async fn http(
        &self,
        to: &Endpoint,
        method: HttpMethod,
        url: &str,
        body: Option<&str>,
        credential: Option<CredentialRef>,
    ) -> Outcome;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_step_that_produced_nothing_is_not_a_success() {
        // The shape an outcome would have if a transport forgot to set anything. Reading
        // it as success is how a run reports green having sent nothing.
        let nothing = Outcome {
            ok: false,
            exit_code: None,
            output: String::new(),
            error: None,
        };
        assert!(!nothing.succeeded());
        assert_eq!(nothing.why(), "the step produced no result");
    }

    #[test]
    fn a_device_that_answered_no_reads_differently_from_one_never_asked() {
        let refused = Outcome::failed("connection refused");
        let exited = Outcome::exited(1, "% Invalid input".to_owned());
        assert_eq!(refused.why(), "connection refused");
        assert_eq!(exited.why(), "the step exited 1");
        assert!(!refused.succeeded() && !exited.succeeded());
    }

    #[test]
    fn an_http_success_is_not_zero_and_keeps_its_status() {
        // The whole reason `ok` is a field. Deriving success from `exit_code == 0` would
        // mean rewriting 204 to 0 and throwing away the number the transcript needs.
        let created = Outcome::answered(201, "{}".to_owned());
        assert!(created.succeeded());
        assert_eq!(created.exit_code, Some(201));

        let not_found = Outcome::answered(404, String::new());
        assert!(!not_found.succeeded());
        assert_eq!(not_found.why(), "the device answered 404");
        assert_eq!(not_found.exit_code, Some(404));
    }

    #[test]
    fn an_error_alongside_a_good_result_is_still_a_failure() {
        // The shape of a transport that ran the step and then could not remove the key
        // file it wrote. A green run would hide a private key left on a disk.
        let mut messy = Outcome::exited(0, "up".to_owned());
        assert!(messy.succeeded());
        messy.error = Some("the key file could not be removed".to_owned());
        assert!(!messy.succeeded());
    }
}
