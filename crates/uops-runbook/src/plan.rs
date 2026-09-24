//! What a run would do, before it does any of it — M10 §2.2.
//!
//! **Every run is a dry run unless somebody says otherwise.** This module is what a dry
//! run produces: the resolved targets by name, every command as it would literally be
//! sent, and a mark against each step saying whether the dry run will execute it.
//!
//! # A plan is not a prediction
//!
//! It says what *would run*. It does not say what would happen, and it must never look as
//! though it does. A dry run that claimed to know the effect of `clear bgp neighbor` would
//! be lying, and a safety feature that lies is worse than no safety feature — somebody
//! trusts it once.
//!
//! So [`Plan::describe`] says *"would run 3 steps on 4 resources"* and there is no
//! variant of it that says *"would succeed"*.

use uops_core::ResourceId;

use crate::error::{Error, Result};
use crate::model::{Runbook, Step};
use crate::render::{self, Context};

/// One resource a run would act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub id: ResourceId,
    /// What an operator calls it. A plan listing UUIDs is a plan nobody reads, and the
    /// whole point of the count is that somebody looks at it.
    pub name: String,
}

/// One step, as it would be sent to one resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedStep {
    pub name: String,
    pub kind: &'static str,
    /// The literal text, with substitution applied. This is what a reviewer reads, so it
    /// is the rendered form rather than the template.
    pub rendered: Vec<String>,
    pub destructive: bool,
    /// Whether a dry run executes it — M10 §2.2. The read-only steps really do run,
    /// against the real devices, so the preconditions are checked rather than assumed.
    pub runs_in_dry_run: bool,
    /// What the author said undoes it, in words, for the reviewer.
    pub rollback: Option<String>,
}

/// Everything a run would do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub runbook: String,
    pub targets: Vec<Target>,
    /// Per target, because a template may render differently for each one.
    pub steps: Vec<(ResourceId, Vec<PlannedStep>)>,
}

impl Plan {
    /// How many steps would actually be sent, across every target.
    #[must_use]
    pub fn total_steps(&self) -> usize {
        self.steps.iter().map(|(_, steps)| steps.len()).sum()
    }

    #[must_use]
    pub fn destructive_steps(&self) -> usize {
        self.steps
            .iter()
            .flat_map(|(_, steps)| steps)
            .filter(|s| s.destructive)
            .count()
    }

    /// One sentence, for the confirmation somebody clicks through.
    ///
    /// Says what *would run* and never what would happen — see the module docs. The
    /// resource count comes first because it is the number that matters and the number
    /// nobody checks.
    #[must_use]
    pub fn describe(&self) -> String {
        let resources = self.targets.len();
        let destructive = self.destructive_steps();
        let plural = if resources == 1 { "" } else { "s" };

        if destructive == 0 {
            format!(
                "would run {} step(s) on {resources} resource{plural}, none of which \
                 change anything",
                self.total_steps()
            )
        } else {
            format!(
                "would run {} step(s) on {resources} resource{plural}, {destructive} of \
                 which change something",
                self.total_steps()
            )
        }
    }
}

/// Build a plan, or refuse.
///
/// `context_for` supplies the per-resource values a template substitutes. It is a closure
/// rather than a map so the caller decides what a run knows about a resource without this
/// crate depending on the store.
///
/// # Errors
///
/// [`Error::NoTargets`] and [`Error::TooManyTargets`] before any rendering, because the
/// count is the thing to refuse on and there is no point rendering four hundred commands
/// to then decline. Then whatever [`render`] said, which names the step.
pub fn plan<F>(runbook: &Runbook, targets: &[Target], context_for: F) -> Result<Plan>
where
    F: Fn(&Target) -> Context,
{
    if targets.is_empty() {
        return Err(Error::NoTargets);
    }
    if targets.len() > runbook.max_targets as usize {
        return Err(Error::TooManyTargets {
            found: targets.len(),
            allowed: runbook.max_targets,
        });
    }

    let mut steps = Vec::with_capacity(targets.len());
    for target in targets {
        let context = context_for(target);
        let mut planned = Vec::with_capacity(runbook.steps.len());
        for step in &runbook.steps {
            planned.push(plan_step(step, &context)?);
        }
        steps.push((target.id, planned));
    }

    Ok(Plan {
        runbook: runbook.name.clone(),
        targets: targets.to_vec(),
        steps,
    })
}

fn plan_step(step: &Step, context: &Context) -> Result<PlannedStep> {
    let mut rendered = Vec::new();
    for template in step.action.templates() {
        rendered.push(render::render(template, context)?);
    }

    Ok(PlannedStep {
        name: step.name.clone(),
        kind: step.action.kind(),
        rendered,
        destructive: step.destructive,
        runs_in_dry_run: step.runs_in_dry_run(),
        rollback: step.rollback.as_ref().map(describe_rollback),
    })
}

/// A rollback in words, for somebody deciding whether to approve.
fn describe_rollback(rollback: &crate::model::Rollback) -> String {
    match rollback {
        crate::model::Rollback::Action { action } => {
            format!("{} would be offered to undo it", action.kind())
        }
        // The reason, verbatim, because the author wrote it for exactly this moment.
        crate::model::Rollback::None { because } => format!("no way back: {because}"),
        crate::model::Rollback::Unknown => {
            // Unreachable through a validated runbook; stated rather than unwrapped
            // because a plan is read by somebody about to change a network.
            "the rollback was never declared — this runbook should not have saved".to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, Approvals, Rollback};
    use uops_query::ast::ResourceSelector;

    fn target(name: &str) -> Target {
        Target {
            id: ResourceId::new(),
            name: name.to_owned(),
        }
    }

    fn context_with_peer(_t: &Target) -> Context {
        [("peer".to_owned(), "10.0.0.1".to_owned())]
            .into_iter()
            .collect()
    }

    fn runbook(steps: Vec<Step>, max_targets: u32) -> Runbook {
        Runbook {
            name: "restart-bgp".to_owned(),
            description: String::new(),
            targets: ResourceSelector::All,
            steps,
            max_targets,
            concurrency: 2,
            approvals: Approvals::One,
            maintenance_only: false,
        }
    }

    fn check() -> Step {
        Step {
            name: "check".to_owned(),
            action: Action::Wait { seconds: 1 },
            destructive: false,
            rollback: None,
            expect: None,
            continue_on_error: false,
        }
    }

    fn clear() -> Step {
        Step {
            name: "clear it".to_owned(),
            action: Action::SshCommand {
                command: "clear bgp neighbor {{ peer }}".to_owned(),
                credential: uops_core::CredentialRef::new(),
            },
            destructive: true,
            rollback: Some(Rollback::None {
                because: "a cleared session cannot be un-cleared".to_owned(),
            }),
            expect: None,
            continue_on_error: false,
        }
    }

    #[test]
    fn a_plan_renders_the_literal_command() {
        // What a reviewer reads has to be what would be sent, not the template. A
        // template is what the mistake hides in.
        let book = runbook(vec![clear()], 10);
        let plan = plan(&book, &[target("core-sw-01")], context_with_peer).unwrap();

        let (_, steps) = &plan.steps[0];
        assert_eq!(steps[0].rendered, vec!["clear bgp neighbor 10.0.0.1"]);
        assert!(steps[0].destructive);
        assert!(!steps[0].runs_in_dry_run);
    }

    #[test]
    fn a_plan_names_every_resource() {
        // A plan listing UUIDs is a plan nobody reads, and the whole point of the count
        // is that somebody looks at it.
        let book = runbook(vec![check()], 10);
        let targets = vec![target("core-sw-01"), target("core-sw-02")];
        let plan = plan(&book, &targets, context_with_peer).unwrap();
        let names: Vec<&str> = plan.targets.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["core-sw-01", "core-sw-02"]);
    }

    #[test]
    fn too_many_targets_is_refused_before_anything_is_rendered() {
        let book = runbook(vec![clear()], 2);
        let targets = vec![target("a"), target("b"), target("c")];
        let err = plan(&book, &targets, context_with_peer).unwrap_err();
        assert_eq!(
            err,
            Error::TooManyTargets {
                found: 3,
                allowed: 2
            }
        );
    }

    #[test]
    fn no_targets_is_its_own_refusal() {
        // Different from too many, and different advice: a selector matching nothing is
        // usually a selector written against an estate that changed.
        let book = runbook(vec![check()], 10);
        assert_eq!(
            plan(&book, &[], context_with_peer).unwrap_err(),
            Error::NoTargets
        );
    }

    #[test]
    fn a_missing_value_refuses_the_whole_plan() {
        // Not "render what we can". A partially rendered plan is a plan somebody approves
        // and a run that then fails halfway through a device.
        let book = runbook(vec![clear()], 10);
        let err = plan(&book, &[target("core-sw-01")], |_| Context::new()).unwrap_err();
        assert!(matches!(err, Error::UnknownPlaceholder(n) if n == "peer"));
    }

    #[test]
    fn the_description_never_predicts_success() {
        // A dry run that claimed to know the effect of `clear bgp neighbor` would be
        // lying, and somebody trusts a safety feature once.
        let book = runbook(vec![check(), clear()], 10);
        let plan = plan(&book, &[target("core-sw-01")], context_with_peer).unwrap();
        let text = plan.describe();

        assert!(text.contains("would run"), "{text}");
        assert!(text.contains("1 resource"), "{text}");
        assert!(text.contains("1 of which change something"), "{text}");
        for forbidden in ["succeed", "success", "safe", "no impact", "without"] {
            assert!(!text.to_lowercase().contains(forbidden), "{text}");
        }
    }

    #[test]
    fn a_read_only_plan_says_nothing_changes() {
        let book = runbook(vec![check()], 10);
        let plan = plan(&book, &[target("a")], context_with_peer).unwrap();
        assert!(plan.describe().contains("none of which change anything"));
        assert_eq!(plan.destructive_steps(), 0);
    }

    #[test]
    fn the_rollback_reaches_the_reviewer_in_the_authors_words() {
        // They wrote it for exactly this moment — somebody deciding whether to approve.
        let book = runbook(vec![clear()], 10);
        let plan = plan(&book, &[target("a")], context_with_peer).unwrap();
        let (_, steps) = &plan.steps[0];
        assert_eq!(
            steps[0].rollback.as_deref(),
            Some("no way back: a cleared session cannot be un-cleared")
        );
    }

    #[test]
    fn a_plan_counts_every_target_not_just_the_first() {
        let book = runbook(vec![check(), clear()], 10);
        let targets = vec![target("a"), target("b"), target("c")];
        let plan = plan(&book, &targets, context_with_peer).unwrap();
        assert_eq!(plan.total_steps(), 6);
        assert_eq!(plan.destructive_steps(), 3);
        assert!(
            plan.describe().contains("3 resources"),
            "{}",
            plan.describe()
        );
    }
}
