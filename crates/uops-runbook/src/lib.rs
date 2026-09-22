//! Runbooks — M10, `docs/M10-automation.md`.
//!
//! Every milestone up to here reads. This one writes.
//!
//! M0 through M12 observe an estate, and the worst a defect in any of them can do is
//! report something untrue. This logs into somebody's core switch and runs a command, and
//! the worst a defect here can do is take down a hospital's network at 3 a.m. because an
//! alert misfired. Every decision in this crate is about what stops that, which is why
//! the interesting code is in the refusals rather than the execution.
//!
//! ```text
//!   write ──▶ validate ──▶ plan (dry run) ──▶ approve ──▶ run
//!               │            │                  │
//!          refuses a      names every       two people,
//!          claim, not     resource and      and not the
//!          a command      every command     one who asked
//! ```
//!
//! # What is here and what is not
//!
//! | here | elsewhere |
//! |---|---|
//! | what a runbook may be ([`model`]) | storing one (`uops-store-pg`) |
//! | what is refused ([`validate`]) | the screens that show the refusal (`web`) |
//! | substitution ([`render`]) | opening an SSH connection (`uops-runner`) |
//! | who may approve ([`approval`]) | the routes that record it (`uops-api`) |
//! | what a run would do ([`plan`]) | doing it (`uops-runner`) |
//!
//! Everything above the line is pure, decides something, and is tested exhaustively
//! without a device, a network or a database. That is where the safety lives, so that is
//! where it can be argued about.
//!
//! # Example
//!
//! ```
//! use uops_runbook::{validate, Approvals, Action, Rollback, Runbook, Step};
//! use uops_query::ast::ResourceSelector;
//!
//! // A step that reloads a device and claims to be read-only does not save.
//! let runbook = Runbook {
//!     name: "innocent".to_owned(),
//!     description: String::new(),
//!     targets: ResourceSelector::All,
//!     steps: vec![Step {
//!         name: "just looking".to_owned(),
//!         action: Action::SshCommand {
//!             command: "reload in 5".to_owned(),
//!             credential: uops_core::CredentialRef::new(),
//!         },
//!         destructive: false,
//!         rollback: None,
//!         expect: None,
//!         continue_on_error: false,
//!     }],
//!     max_targets: 10,
//!     concurrency: 2,
//!     approvals: Approvals::None,
//!     maintenance_only: false,
//! };
//!
//! let problems = validate(&runbook);
//! assert!(problems.iter().any(|p| p.because.contains("\"reload\"")));
//! ```

pub mod approval;
pub mod error;
pub mod model;
pub mod plan;
pub mod render;
pub mod validate;

pub use approval::{APPROVAL_WINDOW, Approval, Decision, Pending, Request, decide};
pub use error::{Error, Result};
pub use model::{
    Action, Approvals, DEFAULT_CONCURRENCY, DEFAULT_MAX_TARGETS, Expect, HttpMethod, Rollback,
    Runbook, Step,
};
pub use plan::{Plan, PlannedStep, Target, plan};
pub use render::{Context, render};
pub use validate::{DESTRUCTIVE_WORDS, Problem, validate};
