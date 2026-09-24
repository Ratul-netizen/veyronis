//! What the product refuses to save — M10 §2.3.
//!
//! Validation runs when a runbook is written, not when it is run. That is the whole
//! value: a mistake caught here is caught by the person who made it, at a desk, with time
//! to think. The same mistake caught at run time is caught at 3 a.m. by somebody else.
//!
//! # The deny-list is not a security control
//!
//! It catches a step somebody marked read-only **by accident**. It does not defend against
//! an author being deliberately clever, and it is not trying to: an author who can write a
//! runbook can already run these commands by hand, and what stands between them and an
//! estate is the approval in §2.5, not a regex.
//!
//! Saying that plainly matters, because a deny-list that is believed to be a security
//! boundary is one somebody will lean on. This one exists so that
//! `destructive: false` on a `reload` fails to save.
//!
//! # Every problem names its step
//!
//! An operator reading *"step 3 is invalid"* has to go and count. Every message below
//! names the step, and where it matched a word, the word.

use crate::model::{Action, Approvals, Rollback, Runbook, Step};

/// Commands that change something, whatever a step claims.
///
/// Short, boring, and matched as whole words against the command text. It will never be
/// complete and is not trying to be — see the module docs.
///
/// Sorted, and kept that way, because the next person to add one should be able to see
/// whether it is already here.
pub const DESTRUCTIVE_WORDS: &[&str] = &[
    "delete", "erase", "format", "halt", "mkfs", "poweroff", "reboot", "reload", "rm", "shutdown",
    "wipe", "wr",
];

/// The longest a captured command may be.
///
/// Not a security bound — a bound on the thing a person has to read in a review. A
/// four-kilobyte command pasted into a step is a script, and a script is what §2.1 refuses
/// to be.
pub const MAX_COMMAND_LEN: usize = 512;

/// The most steps a runbook may have.
///
/// Same argument. Past this it is a program, and a program wants a debugger rather than an
/// approval workflow.
pub const MAX_STEPS: usize = 50;

/// Something that stops a runbook being saved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The step it is about, by name. `None` for a problem with the runbook itself.
    pub step: Option<String>,
    pub because: String,
}

impl Problem {
    fn runbook(because: impl Into<String>) -> Self {
        Self {
            step: None,
            because: because.into(),
        }
    }

    fn step(step: &Step, because: impl Into<String>) -> Self {
        Self {
            step: Some(step.name.clone()),
            because: because.into(),
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.step {
            Some(name) => write!(f, "step {name:?}: {}", self.because),
            None => write!(f, "{}", self.because),
        }
    }
}

/// Check a runbook. An empty result means it may be saved.
///
/// Returns **every** problem rather than the first. An author fixing one thing, saving,
/// and being told about the next is how a five-step runbook takes five round trips.
#[must_use]
pub fn validate(runbook: &Runbook) -> Vec<Problem> {
    let mut problems = Vec::new();

    if runbook.name.trim().is_empty() {
        problems.push(Problem::runbook("a runbook needs a name"));
    }
    if runbook.steps.is_empty() {
        problems.push(Problem::runbook(
            "a runbook with no steps does nothing; delete it rather than saving it",
        ));
    }
    if runbook.steps.len() > MAX_STEPS {
        problems.push(Problem::runbook(format!(
            "{} steps is past the {MAX_STEPS} a runbook may have — past this it is a \
             program, and a program wants a debugger rather than an approval",
            runbook.steps.len()
        )));
    }
    if runbook.max_targets == 0 {
        problems.push(Problem::runbook(
            "max_targets is 0, so this runbook could never act on anything",
        ));
    }
    if runbook.concurrency == 0 {
        problems.push(Problem::runbook(
            "concurrency is 0, so a run would never start",
        ));
    }
    if runbook.concurrency > runbook.max_targets {
        problems.push(Problem::runbook(format!(
            "concurrency {} is higher than max_targets {} — it would never be reached, \
             and reading it as the real bound is how somebody raises the wrong number",
            runbook.concurrency, runbook.max_targets
        )));
    }

    let mut seen = std::collections::BTreeSet::new();
    for step in &runbook.steps {
        if step.name.trim().is_empty() {
            problems.push(Problem::runbook(
                "a step has no name; the dry run and the run record are read by name",
            ));
        } else if !seen.insert(step.name.trim().to_lowercase()) {
            // Two steps called "check" make a run record nobody can read, and a rollback
            // that names a step ambiguous.
            problems.push(Problem::step(step, "two steps share this name"));
        }

        problems.extend(check_step(step));
    }

    // A runbook that changes something and needs no approval is the configuration this
    // whole milestone exists to make impossible to set by accident.
    if runbook.is_destructive() && runbook.approvals == Approvals::None {
        problems.push(Problem::runbook(
            "this runbook has a destructive step and requires no approval; \
             set approvals to one or two, or mark the step read-only if it is",
        ));
    }

    problems
}

// Long, and deliberately one function: it is the list of everything a step can be wrong
// about, in one place, which is what makes "what does the product refuse" answerable by
// reading rather than by following calls. Splitting it per rule would turn a checklist
// into a call graph.
#[allow(clippy::too_many_lines)]
fn check_step(step: &Step) -> Vec<Problem> {
    let mut problems = Vec::new();

    // ---- what the action itself says ------------------------------------------------

    if step.destructive && step.action.is_inherently_read_only() {
        problems.push(Problem::step(
            step,
            format!(
                "marked destructive, but {} cannot change anything. A runbook that marks \
                 every step destructive to look careful trains everybody to click through \
                 the warning",
                step.action.kind()
            ),
        ));
    }

    // ---- the deny-list ---------------------------------------------------------------

    if let Some(command) = step.action.command_text() {
        if command.trim().is_empty() {
            problems.push(Problem::step(step, "the command is empty"));
        }
        if command.len() > MAX_COMMAND_LEN {
            problems.push(Problem::step(
                step,
                format!(
                    "the command is {} characters, past the {MAX_COMMAND_LEN} a step may \
                     have — a command this long is a script, and a script is not reviewable \
                     as a step",
                    command.len()
                ),
            ));
        }
        // A newline is how one command becomes two, and it is the one character that
        // turns a reviewed step into an unreviewed one.
        if command.contains('\n') || command.contains('\r') {
            problems.push(Problem::step(
                step,
                "the command contains a newline, which makes it two commands; \
                 write two steps",
            ));
        }

        if !step.destructive
            && let Some(word) = matched_destructive_word(command)
        {
            problems.push(Problem::step(
                step,
                format!(
                    "marked read-only, but the command contains {word:?}. Mark it \
                     destructive, or change the command"
                ),
            ));
        }
    }

    if let Action::HttpRequest { method, url, .. } = &step.action {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            problems.push(Problem::step(
                step,
                format!("the URL {url:?} is not http or https"),
            ));
        }
        if !step.destructive && !method.is_read_only() {
            problems.push(Problem::step(
                step,
                format!(
                    "marked read-only, but {} changes state by convention",
                    method.as_str()
                ),
            ));
        }
    }

    // ---- rollback ---------------------------------------------------------------------

    match (&step.rollback, step.destructive) {
        (Some(Rollback::Unknown) | None, true) => {
            problems.push(Problem::step(
                step,
                "a destructive step must declare a rollback: an action that undoes it, or \
                 `none` with a reason. A step whose author has not decided is a step \
                 nobody has thought about",
            ));
        }
        (Some(Rollback::None { because }), true) if because.trim().is_empty() => {
            problems.push(Problem::step(
                step,
                "`rollback: none` needs a reason — without one it is indistinguishable \
                 from nobody having thought about it",
            ));
        }
        // Not a gap: a rollback for a step that changes nothing is a rollback nobody will
        // maintain and everybody will assume is correct. `Unknown` on a read-only step is
        // left alone — it means nothing there, and reporting it would send an author
        // looking for a rollback they must not write.
        (Some(Rollback::Action { .. } | Rollback::None { .. }), false) => {
            problems.push(Problem::step(
                step,
                "this step is not destructive, so a rollback has nothing to undo",
            ));
        }
        _ => {}
    }

    // A rollback that is itself destructive is fine and expected — undoing a change is a
    // change. A rollback that is *another read-only step* is a mistake worth naming.
    if let Some(Rollback::Action { action }) = &step.rollback
        && action.is_inherently_read_only()
    {
        problems.push(Problem::step(
            step,
            format!(
                "the rollback is {}, which cannot undo anything",
                action.kind()
            ),
        ));
    }

    // ---- continue_on_error --------------------------------------------------------------

    if step.continue_on_error && step.destructive {
        problems.push(Problem::step(
            step,
            "a destructive step cannot continue on error: carrying on past a change that \
             failed is exactly the unknown state a rollback refuses to act into",
        ));
    }

    problems
}

/// The first deny-listed word in a command, if any.
///
/// Whole words, case-insensitively. Substring matching would flag `show interfaces
/// description` for containing `rm`, which is the kind of false positive that gets a guard
/// switched off.
#[must_use]
pub fn matched_destructive_word(command: &str) -> Option<&'static str> {
    let lowered = command.to_lowercase();
    lowered
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .find_map(|word| {
            DESTRUCTIVE_WORDS
                .iter()
                .find(|listed| **listed == word)
                .copied()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, Expect, HttpMethod};
    use uops_query::ast::ResourceSelector;

    fn credential() -> uops_core::CredentialRef {
        uops_core::CredentialRef::new()
    }

    fn ssh(command: &str) -> Action {
        Action::SshCommand {
            command: command.to_owned(),
            credential: credential(),
        }
    }

    fn step(name: &str, action: Action) -> Step {
        Step {
            name: name.to_owned(),
            action,
            destructive: false,
            rollback: None,
            expect: None,
            continue_on_error: false,
        }
    }

    fn runbook(steps: Vec<Step>) -> Runbook {
        let destructive = steps.iter().any(|s| s.destructive);
        Runbook {
            name: "restart-bgp".to_owned(),
            description: String::new(),
            targets: ResourceSelector::All,
            steps,
            max_targets: crate::model::DEFAULT_MAX_TARGETS,
            concurrency: crate::model::DEFAULT_CONCURRENCY,
            approvals: if destructive {
                Approvals::One
            } else {
                Approvals::None
            },
            maintenance_only: false,
        }
    }

    fn destructive(name: &str, command: &str) -> Step {
        Step {
            destructive: true,
            rollback: Some(Rollback::None {
                because: "a cleared session cannot be un-cleared".to_owned(),
            }),
            ..step(name, ssh(command))
        }
    }

    #[test]
    fn a_reasonable_runbook_validates() {
        let book = runbook(vec![
            Step {
                expect: Some(Expect::Contains {
                    text: "Idle".to_owned(),
                }),
                ..step("check the session is down", ssh("show bgp summary"))
            },
            destructive("clear it", "clear bgp neighbor 10.0.0.1"),
        ]);
        assert_eq!(validate(&book), Vec::new());
    }

    // ---- the deny-list ------------------------------------------------------------

    #[test]
    fn a_step_marked_read_only_that_reloads_is_refused_by_name() {
        let book = runbook(vec![step("innocent", ssh("reload in 5"))]);
        let problems = validate(&book);
        let about = problems
            .iter()
            .find(|p| p.step.as_deref() == Some("innocent"))
            .expect("a problem about that step");
        assert!(about.because.contains("\"reload\""), "{}", about.because);
    }

    #[test]
    fn the_same_command_marked_destructive_is_fine() {
        // The deny-list refuses a *claim*, not a command. This is the whole distinction.
        let book = runbook(vec![destructive("reboot it", "reload in 5")]);
        assert_eq!(validate(&book), Vec::new());
    }

    #[test]
    fn the_deny_list_matches_whole_words() {
        // `show interfaces description` contains "rm" as a substring and must not match,
        // because a guard with false positives is a guard somebody switches off.
        assert_eq!(
            matched_destructive_word("show interfaces description"),
            None
        );
        assert_eq!(matched_destructive_word("show running-config"), None);
        assert_eq!(matched_destructive_word("show platform"), None);
        assert_eq!(matched_destructive_word("show formatting"), None);

        assert_eq!(matched_destructive_word("rm -rf /var/log"), Some("rm"));
        assert_eq!(matched_destructive_word("RELOAD"), Some("reload"));
        assert_eq!(
            matched_destructive_word("interface gi0/1 ; shutdown"),
            Some("shutdown")
        );
    }

    #[test]
    fn the_deny_list_is_sorted_and_has_no_duplicates() {
        // So the next person to add one can see whether it is already there.
        let mut sorted = DESTRUCTIVE_WORDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.as_slice(), DESTRUCTIVE_WORDS);
    }

    // ---- claims the product refuses ------------------------------------------------

    #[test]
    fn a_wait_cannot_be_destructive() {
        let mut s = step("pause", Action::Wait { seconds: 30 });
        s.destructive = true;
        s.rollback = Some(Rollback::None {
            because: "time passes".to_owned(),
        });
        let problems = validate(&runbook(vec![s]));
        assert!(
            problems
                .iter()
                .any(|p| p.because.contains("cannot change anything")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_delete_cannot_be_read_only() {
        let s = step(
            "clean up",
            Action::HttpRequest {
                method: HttpMethod::Delete,
                url: "https://device/api/session/1".to_owned(),
                body: None,
                credential: None,
            },
        );
        let problems = validate(&runbook(vec![s]));
        assert!(
            problems.iter().any(|p| p.because.contains("DELETE")),
            "{problems:?}"
        );
    }

    // ---- rollback --------------------------------------------------------------------

    #[test]
    fn a_destructive_step_with_no_rollback_is_refused() {
        let mut s = step("clear it", ssh("clear bgp neighbor 10.0.0.1"));
        s.destructive = true;
        let problems = validate(&runbook(vec![s]));
        assert!(
            problems
                .iter()
                .any(|p| p.because.contains("must declare a rollback")),
            "{problems:?}"
        );
    }

    #[test]
    fn rollback_unknown_is_refused_and_rollback_none_with_a_reason_is_not() {
        let mut s = step("clear it", ssh("clear bgp neighbor 10.0.0.1"));
        s.destructive = true;
        s.rollback = Some(Rollback::Unknown);
        assert!(!validate(&runbook(vec![s.clone()])).is_empty());

        s.rollback = Some(Rollback::None {
            because: String::new(),
        });
        let problems = validate(&runbook(vec![s.clone()]));
        assert!(
            problems
                .iter()
                .any(|p| p.because.contains("needs a reason")),
            "{problems:?}"
        );

        s.rollback = Some(Rollback::None {
            because: "a cleared session cannot be un-cleared".to_owned(),
        });
        assert_eq!(validate(&runbook(vec![s])), Vec::new());
    }

    #[test]
    fn a_rollback_that_cannot_undo_anything_is_refused() {
        let mut s = step("shut it", ssh("interface gi0/1 shutdown"));
        s.destructive = true;
        s.rollback = Some(Rollback::Action {
            action: Box::new(Action::Wait { seconds: 5 }),
        });
        let problems = validate(&runbook(vec![s]));
        assert!(
            problems
                .iter()
                .any(|p| p.because.contains("cannot undo anything")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_read_only_step_may_not_carry_a_rollback() {
        let mut s = step("check", ssh("show bgp summary"));
        s.rollback = Some(Rollback::None {
            because: "nothing to undo".to_owned(),
        });
        let problems = validate(&runbook(vec![s]));
        assert!(
            problems
                .iter()
                .any(|p| p.because.contains("nothing to undo")),
            "{problems:?}"
        );
    }

    // ---- the runbook itself ------------------------------------------------------------

    #[test]
    fn a_destructive_runbook_needing_no_approval_is_refused() {
        // The configuration this milestone exists to make impossible to set by accident.
        let mut book = runbook(vec![destructive("clear it", "clear bgp neighbor 10.0.0.1")]);
        book.approvals = Approvals::None;
        let problems = validate(&book);
        assert!(
            problems
                .iter()
                .any(|p| p.because.contains("requires no approval")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_read_only_runbook_may_need_no_approval() {
        let mut book = runbook(vec![step("check", ssh("show bgp summary"))]);
        book.approvals = Approvals::None;
        assert_eq!(validate(&book), Vec::new());
    }

    #[test]
    fn a_newline_in_a_command_is_two_commands() {
        let book = runbook(vec![step("sneaky", ssh("show version\nreload"))]);
        let problems = validate(&book);
        assert!(
            problems.iter().any(|p| p.because.contains("newline")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_destructive_step_cannot_continue_on_error() {
        let mut s = destructive("clear it", "clear bgp neighbor 10.0.0.1");
        s.continue_on_error = true;
        let problems = validate(&runbook(vec![s]));
        assert!(
            problems.iter().any(|p| p.because.contains("unknown state")),
            "{problems:?}"
        );
    }

    #[test]
    fn two_steps_cannot_share_a_name() {
        let book = runbook(vec![
            step("check", ssh("show bgp summary")),
            step("Check", ssh("show ip route")),
        ]);
        let problems = validate(&book);
        assert!(
            problems
                .iter()
                .any(|p| p.because.contains("share this name")),
            "{problems:?}"
        );
    }

    #[test]
    fn concurrency_above_the_target_cap_is_refused() {
        let mut book = runbook(vec![step("check", ssh("show version"))]);
        book.max_targets = 4;
        book.concurrency = 40;
        let problems = validate(&book);
        assert!(
            problems
                .iter()
                .any(|p| p.because.contains("higher than max_targets")),
            "{problems:?}"
        );
    }

    #[test]
    fn every_problem_reads_as_a_sentence_naming_its_step() {
        let mut s = step("clear it", ssh("reload"));
        s.destructive = false;
        let problems = validate(&runbook(vec![s]));
        assert!(!problems.is_empty());
        for p in &problems {
            let rendered = p.to_string();
            // An operator reading "step 3 is invalid" has to go and count.
            if p.step.is_some() {
                assert!(rendered.contains("clear it"), "{rendered}");
            }
            assert!(rendered.len() > 20, "{rendered}");
        }
    }

    #[test]
    fn every_problem_is_reported_rather_than_only_the_first() {
        // An author fixing one thing, saving, and being told about the next is how a
        // five-step runbook takes five round trips.
        let mut s = step("bad", ssh("reload"));
        s.continue_on_error = true;
        s.rollback = Some(Rollback::None {
            because: String::new(),
        });
        let mut book = runbook(vec![s]);
        book.name = String::new();
        book.concurrency = 0;

        let problems = validate(&book);
        assert!(problems.len() >= 3, "{problems:#?}");
    }
}
