//! What a runbook is — M10 §2.1.
//!
//! # Typed actions, not a shell
//!
//! A step is one of a small number of action kinds with a schema, not a string somebody
//! pastes a command into. That costs expressiveness and buys the one property that makes
//! the rest of this milestone possible: **what a runbook can do is enumerable by reading
//! it** — by a person reviewing it, and by the product validating it.
//!
//! A free-text step could only be reviewed *after* it ran, by reading what happened. This
//! is reviewable before it ever runs, which is where a mistake should be caught.
//!
//! # Every destructive step declares its rollback, and "none" is an answer
//!
//! Clearing a BGP session cannot be un-cleared; a reboot cannot be un-rebooted. What is
//! not an answer is [`Rollback::Unknown`], which fails validation — a step whose author
//! has not decided is a step nobody has thought about.

use serde::{Deserialize, Serialize};
use uops_query::ast::ResourceSelector;

/// One thing a step does.
///
/// A closed set. Adding a kind is a deliberate act that touches validation, the deny-list
/// and the runner — which is the point: a product that can grow an action kind by
/// accident is one whose blast radius nobody can state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// A command over SSH, using a credential the step names by reference.
    ///
    /// The credential is a [`uops_core::CredentialRef`] and never appears in `command` —
    /// see [`crate::render`], which has no binding that could substitute one.
    SshCommand {
        command: String,
        /// Which credential opens the connection. Resolved by the runner through the same
        /// vault the poller uses.
        credential: uops_core::CredentialRef,
    },
    /// An HTTP request against a device's own API.
    HttpRequest {
        method: HttpMethod,
        url: String,
        #[serde(default)]
        body: Option<String>,
        /// Optional: a device API that needs no credential is a device API on a trusted
        /// segment, which is somebody's decision to make.
        #[serde(default)]
        credential: Option<uops_core::CredentialRef>,
    },
    /// Do nothing for a while.
    ///
    /// The step that makes a runbook readable: *clear the session, wait 30 seconds, check
    /// it came back*. Without it every author writes `sleep 30` as a shell command and the
    /// product loses the ability to say that step changes nothing.
    Wait { seconds: u32 },
}

/// The HTTP methods a step may use.
///
/// `GET` and `HEAD` are the read-only ones and the product knows it — see
/// [`Action::is_inherently_read_only`]. `DELETE` is always destructive whatever a step
/// claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    /// Whether this method can be expected not to change anything.
    ///
    /// "Expected" is doing real work in that sentence: a `GET` against an endpoint whose
    /// author made it change state is still destructive, and no product can know that.
    /// What this encodes is the convention, which is what an author's *claim* is checked
    /// against rather than what the world guarantees.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::Get | Self::Head)
    }
}

impl Action {
    /// The kind, for a message an operator reads.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::SshCommand { .. } => "ssh.command",
            Self::HttpRequest { .. } => "http.request",
            Self::Wait { .. } => "wait",
        }
    }

    /// Whether this action cannot change anything, whatever it is marked.
    ///
    /// A runbook that marks every step destructive to look careful trains everybody to
    /// click through the warning, so the product refuses the claim rather than accepting
    /// it — see [`crate::validate`].
    #[must_use]
    pub const fn is_inherently_read_only(&self) -> bool {
        match self {
            Self::Wait { .. } => true,
            Self::HttpRequest { method, .. } => method.is_read_only(),
            Self::SshCommand { .. } => false,
        }
    }

    /// The text a deny-list should be applied to, if any.
    #[must_use]
    pub fn command_text(&self) -> Option<&str> {
        match self {
            Self::SshCommand { command, .. } => Some(command),
            Self::HttpRequest { .. } | Self::Wait { .. } => None,
        }
    }

    /// Every template this action contains, for validation and rendering.
    #[must_use]
    pub fn templates(&self) -> Vec<&str> {
        match self {
            Self::SshCommand { command, .. } => vec![command.as_str()],
            Self::HttpRequest { url, body, .. } => match body {
                Some(body) => vec![url.as_str(), body.as_str()],
                None => vec![url.as_str()],
            },
            Self::Wait { .. } => Vec::new(),
        }
    }
}

/// What undoes a destructive step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Rollback {
    /// An action that reverses it.
    ///
    /// Offered to an operator, never performed automatically — M10 §2.6. A step that
    /// failed halfway left the device in a state the product does not know, and running
    /// more commands into an unknown state is how a small outage becomes a large one.
    Action { action: Box<Action> },
    /// There is no way back, and here is why.
    ///
    /// A first-class answer rather than a gap. `because` is required because "none" with
    /// no reason is indistinguishable from nobody having thought about it, which is the
    /// next variant.
    None { because: String },
    /// Nobody has decided. **Fails validation.**
    Unknown,
}

/// What a step expects to see, for a precondition.
///
/// Deliberately tiny: `contains` and `not_contains` against the captured output. A
/// matching language here would be a matching language somebody debugs at 3 a.m., and the
/// preconditions operators actually write are *did this string appear*.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expect {
    Contains {
        text: String,
    },
    NotContains {
        text: String,
    },
    /// The process exited zero, or the HTTP status was 2xx.
    Success,
}

/// One step of a runbook.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// What this step is for, in the author's words. Shown in the dry run and in the run
    /// record, which is where somebody reads it.
    pub name: String,
    pub action: Action,
    /// Declared by the author, verified by the product — M10 §2.3.
    #[serde(default)]
    pub destructive: bool,
    /// Required when `destructive`; refused otherwise, because a rollback for a step that
    /// changes nothing is a rollback nobody will maintain.
    #[serde(default)]
    pub rollback: Option<Rollback>,
    #[serde(default)]
    pub expect: Option<Expect>,
    /// Carry on when this step fails.
    ///
    /// For read-only preconditions. Refused on a destructive step: continuing past a
    /// change that failed is exactly the unknown state §2.6 refuses to act into.
    #[serde(default)]
    pub continue_on_error: bool,
}

impl Step {
    /// Whether the dry run executes this step.
    ///
    /// M10 §2.2: a dry run really runs the read-only steps, against the real devices,
    /// right now — so the preconditions are genuinely checked rather than assumed.
    ///
    /// # This was `&& is_inherently_read_only()` and that was wrong
    ///
    /// The stricter version reads as the cautious choice and is the opposite. An
    /// `ssh.command` is never *inherently* read-only, so under it a dry run of the runbook
    /// §2.1 uses as its own example — `show bgp summary`, then `clear bgp neighbor` — ran
    /// nothing at all. It reported "would run 2 steps on 4 resources" having touched
    /// nothing, which is precisely the simulation §2.2 opens by saying a dry run is not.
    ///
    /// A safety feature that quietly does nothing is worse than none, because somebody
    /// trusts it. So the author's declaration is what decides, and what makes that
    /// trustworthy is [`crate::validate`]: a step marked non-destructive whose command
    /// matches the deny-list does not save. §2.3 exists so that `destructive: false` can
    /// be relied on here — that is the whole of what it is for.
    #[must_use]
    pub const fn runs_in_dry_run(&self) -> bool {
        !self.destructive
    }
}

/// How many approvals a run of this runbook needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approvals {
    /// No approval. Only legitimate for a runbook with no destructive step — validation
    /// enforces that, so "nobody has to approve this" cannot be set on something that
    /// reboots a switch.
    None,
    One,
    /// Two-person integrity — PLAN §0b, for the destructive-in-defence case.
    ///
    /// Per-runbook rather than global on purpose: requiring two approvals to restart an
    /// interface is how an organisation ends up with a standing exception, and a standing
    /// exception is worse than no rule.
    Two,
}

impl Approvals {
    #[must_use]
    pub const fn count(self) -> usize {
        match self {
            Self::None => 0,
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

/// The largest number of resources a runbook may ever touch, unless it says otherwise.
///
/// Small on purpose. A selector meant to match one switch and matching four hundred is the
/// single most common way automation causes an outage, and the number nobody checks is the
/// count. Raising it is an edit to a reviewed object rather than a checkbox at run time.
pub const DEFAULT_MAX_TARGETS: u32 = 10;

/// How many resources a run may act on at once, unless the runbook says otherwise.
///
/// A runbook that SSHs into four hundred devices simultaneously is a denial of service
/// against the customer's own authentication server, which is a failure this product would
/// be causing rather than reporting.
pub const DEFAULT_CONCURRENCY: u32 = 4;

/// A runbook, as it is written and reviewed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runbook {
    pub name: String,
    pub description: String,
    /// The same selector an alert rule and a maintenance window use — so *restart the
    /// device this alert fired on* is a copy of one field rather than a translation.
    pub targets: ResourceSelector,
    pub steps: Vec<Step>,
    /// M10 §2.7.
    pub max_targets: u32,
    pub concurrency: u32,
    pub approvals: Approvals,
    /// Whether this runbook may only run inside a maintenance window.
    ///
    /// The opposite of how a window works for alerting, and deliberately: an alert is
    /// *suppressed* during a window, and a change arguably should be *only* allowed during
    /// one. Per-runbook, because "restart this stuck agent" and "upgrade this firmware"
    /// are not the same risk.
    #[serde(default)]
    pub maintenance_only: bool,
}

impl Runbook {
    /// Whether any step changes anything.
    #[must_use]
    pub fn is_destructive(&self) -> bool {
        self.steps.iter().any(|s| s.destructive)
    }

    /// The steps a dry run would actually execute.
    pub fn dry_run_steps(&self) -> impl Iterator<Item = &Step> {
        self.steps.iter().filter(|s| s.runs_in_dry_run())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_and_a_get_cannot_change_anything() {
        assert!(Action::Wait { seconds: 5 }.is_inherently_read_only());
        for method in [HttpMethod::Get, HttpMethod::Head] {
            assert!(
                Action::HttpRequest {
                    method,
                    url: "https://device/api".to_owned(),
                    body: None,
                    credential: None,
                }
                .is_inherently_read_only(),
                "{method:?}"
            );
        }
    }

    #[test]
    fn an_ssh_command_is_never_assumed_read_only() {
        // The product cannot parse every network vendor's CLI, so it does not pretend to.
        // `show` and `reload` are both `ssh.command`, and what separates them is the
        // author's declaration plus the deny-list in `validate`.
        assert!(
            !Action::SshCommand {
                command: "show version".to_owned(),
                credential: uops_core::CredentialRef::new(),
            }
            .is_inherently_read_only()
        );
    }

    #[test]
    fn a_post_is_not_read_only() {
        for method in [
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Patch,
            HttpMethod::Delete,
        ] {
            assert!(!method.is_read_only(), "{method:?}");
        }
    }

    #[test]
    fn a_dry_run_executes_only_what_cannot_change_anything() {
        let read_only = Step {
            name: "check".to_owned(),
            action: Action::Wait { seconds: 1 },
            destructive: false,
            rollback: None,
            expect: None,
            continue_on_error: false,
        };
        assert!(read_only.runs_in_dry_run());

        // Marked destructive wins over the action being harmless. An author who marked a
        // wait destructive has said something odd, and the safe reading is theirs.
        let marked = Step {
            destructive: true,
            ..read_only.clone()
        };
        assert!(!marked.runs_in_dry_run());

        // A `show` command. It really runs, which is the whole of what makes a dry run
        // more than a simulation — the precondition is checked against the device rather
        // than assumed. What makes that safe is `validate`: this step would not have saved
        // if its command matched the deny-list.
        let ssh = Step {
            action: Action::SshCommand {
                command: "show bgp summary".to_owned(),
                credential: uops_core::CredentialRef::new(),
            },
            ..read_only
        };
        assert!(
            ssh.runs_in_dry_run(),
            "a dry run that runs no ssh.command step runs nothing at all — see the note              on runs_in_dry_run"
        );

        // And the one that must not: the author said it changes something.
        let clear = Step {
            destructive: true,
            ..ssh
        };
        assert!(!clear.runs_in_dry_run());
    }

    #[test]
    fn the_approval_counts_are_what_they_say() {
        assert_eq!(Approvals::None.count(), 0);
        assert_eq!(Approvals::One.count(), 1);
        assert_eq!(Approvals::Two.count(), 2);
        assert!(Approvals::Two > Approvals::One);
    }

    #[test]
    fn the_default_blast_radius_is_small() {
        // Not an arbitrary number: the point is that it is *low enough to be wrong*, so a
        // selector that matched an estate fails rather than proceeding.
        //
        // `const` blocks, so raising the default past this fails to **compile** rather
        // than failing a test somebody can mark ignored. It is a tripwire on a number
        // that will be tempting to raise.
        const { assert!(DEFAULT_MAX_TARGETS <= 25) };
        const { assert!(DEFAULT_CONCURRENCY <= DEFAULT_MAX_TARGETS) };
    }
}
