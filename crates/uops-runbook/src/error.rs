//! What can go wrong before a command is ever sent.
//!
//! Every variant here is a **refusal**, not a failure: the product declining to do
//! something rather than trying and not managing it. That distinction is worth keeping in
//! the type, because the two need opposite responses — a refusal is fixed by editing the
//! runbook, and a failure is investigated on the device.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// A template names something the run's context does not have.
    ///
    /// Never an empty substitution — see [`crate::render`]. `rm -rf /{{ path }}` with
    /// `path` unset is the reason this is an error.
    #[error("the template needs a value for {0:?}, and the run has none")]
    UnknownPlaceholder(String),

    /// A value could end the command it is going into.
    #[error("the value for {name:?} cannot be used: {because}")]
    UnsafeValue { name: String, because: String },

    #[error("the template is malformed: {0}")]
    MalformedTemplate(String),

    /// The selector resolved to more resources than the runbook allows.
    ///
    /// The single most common way automation causes an outage, and the number nobody
    /// checks — so it is in the type rather than a log line.
    #[error(
        "this run would act on {found} resources and the runbook allows {allowed}. \
         Narrow the targets, or raise max_targets on the runbook — which is an edit \
         somebody reviews"
    )]
    TooManyTargets { found: usize, allowed: u32 },

    /// The selector resolved to nothing.
    #[error("this run would act on no resources; the targets match nothing right now")]
    NoTargets,
}

impl Error {
    /// Whether this is something the runbook's author fixes, rather than the operator.
    ///
    /// Used to point a message at the right person: an unsafe value is a run-time input
    /// and a malformed template is a saved mistake.
    #[must_use]
    pub const fn is_authoring_mistake(&self) -> bool {
        matches!(self, Self::MalformedTemplate(_) | Self::UnknownPlaceholder(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_cap_message_says_both_numbers_and_what_to_do() {
        let e = Error::TooManyTargets {
            found: 400,
            allowed: 10,
        };
        let text = e.to_string();
        assert!(text.contains("400"), "{text}");
        assert!(text.contains("10"), "{text}");
        assert!(text.contains("max_targets"), "{text}");
    }

    #[test]
    fn an_authoring_mistake_is_told_apart_from_a_run_time_one() {
        assert!(Error::MalformedTemplate("x".to_owned()).is_authoring_mistake());
        assert!(Error::UnknownPlaceholder("peer".to_owned()).is_authoring_mistake());
        assert!(
            !Error::UnsafeValue {
                name: "peer".to_owned(),
                because: "x".to_owned()
            }
            .is_authoring_mistake()
        );
        assert!(
            !Error::TooManyTargets {
                found: 1,
                allowed: 0
            }
            .is_authoring_mistake()
        );
    }
}
