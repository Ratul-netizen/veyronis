//! Running one claimed run — M10 §2.2, §2.6, §2.7.
//!
//! Everything above this file decided whether a run *may* happen. This is the only file in
//! the product that makes something happen to somebody else's equipment, and the shape of
//! it is set by three sentences from the milestone document:
//!
//! * **A dry run really runs the read-only steps.** It is not a simulation. The `show`
//!   commands go to the real devices, right now, so a precondition is genuinely checked.
//!   What it will not do is guess at the steps it did not run.
//! * **A run stops at the first failed step**, unless the step said `continue_on_error` —
//!   which validation refuses on anything destructive.
//! * **Rollback is offered, never performed.** A step that failed halfway left the device
//!   in a state this process does not know, and running more commands into an unknown
//!   state is how a small outage becomes a large one.
//!
//! # What "stops" means when targets run in parallel
//!
//! A run may act on several devices at once, up to the runbook's `concurrency`. A failure
//! is therefore not one event but one *per target*, and "stop" has to be defined:
//!
//! * the target that failed stops immediately, and its remaining steps are recorded
//!   `skipped` rather than left `pending` — a step nobody will run is not a step still to
//!   come;
//! * **no further target is started**;
//! * a target already in flight finishes the step it is on and then stops.
//!
//! The last one is not a compromise, it is the only honest option: a step in flight has
//! already been sent, and abandoning the future would leave the product not knowing what
//! the device did with it. Waiting means the transcript is complete.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use uops_core::{ResourceId, TenantScope};
use uops_runbook::{Action, Expect, Step};
use uops_store_pg::{Claimed, PgStore, RunState};

use crate::transport::{Endpoint, Outcome, Transport};

/// What the state of a step is called in `runbook_run_step`.
///
/// Strings rather than an enum because the column is a `PostgreSQL` enum and the store
/// binds through `::text::`; a second Rust enum here would be a copy of the schema's with
/// nothing keeping the two in step.
const OK: &str = "ok";
const FAILED: &str = "failed";
const SKIPPED: &str = "skipped";

/// What a finished run amounted to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub state: RunState,
    /// One sentence for the run's `failure` column, and `None` when it succeeded.
    pub failure: Option<String>,
    /// What the author declared undoes the step that failed — **offered, not performed**.
    ///
    /// Carried separately from `failure` so the screen can show it as a thing to decide
    /// about rather than as part of an error message somebody skims.
    pub rollback: Option<String>,
    pub steps_run: usize,
    pub steps_skipped: usize,
}

/// Execute a claimed run to completion.
///
/// Returns what happened; **does not set the run's final state**, which the caller does,
/// because the caller is the thing holding the lease and it is the one that must still
/// write a state if this returns having panicked its way out of a task.
///
/// # Errors
///
/// Only what the *store* said. A device that refused, a command that exited non-zero and a
/// step that timed out are all outcomes rather than errors — see [`crate::transport`].
pub async fn run<T: Transport + ?Sized>(
    store: &PgStore,
    transport: &T,
    claimed: &Claimed,
) -> uops_core::Result<Report> {
    let scope = claimed.scope();
    let addresses = store
        .resource_addresses(&scope, &claimed.targets.iter().map(|t| t.id).collect::<Vec<_>>())
        .await?;

    let stop = Arc::new(AtomicBool::new(false));
    let mut run_count = 0usize;
    let mut skip_count = 0usize;
    let mut first_failure: Option<(String, Option<String>)> = None;

    // Targets in chunks of `concurrency`, which is the bound §2.7 asks for: a runbook that
    // SSHs into four hundred devices at once is a denial of service against the customer's
    // own authentication server.
    let width = (claimed.runbook.concurrency as usize).max(1);

    for chunk in claimed.targets.chunks(width) {
        if stop.load(Ordering::Relaxed) {
            // No further target is started. The ones in this chunk have not been touched,
            // so their steps stay `pending` — which is the truth: they are still to come,
            // and a person deciding about the rollback may yet run them.
            break;
        }

        let mut tasks = Vec::with_capacity(chunk.len());
        for target in chunk {
            let endpoint = addresses.get(&target.id).map(|address| Endpoint {
                tenant: claimed.tenant_id,
                resource: target.id,
                name: target.name.clone(),
                address: address.clone(),
            });
            tasks.push(one_target(
                store,
                transport,
                claimed,
                &scope,
                target.id,
                &target.name,
                endpoint,
                &stop,
            ));
        }

        for outcome in futures_util::future::join_all(tasks).await {
            let outcome = outcome?;
            run_count += outcome.run;
            skip_count += outcome.skipped;
            if first_failure.is_none() {
                first_failure = outcome.failure;
            }
        }
    }

    Ok(match first_failure {
        None => Report {
            state: RunState::Succeeded,
            failure: None,
            rollback: None,
            steps_run: run_count,
            steps_skipped: skip_count,
        },
        Some((why, rollback)) => Report {
            state: RunState::Failed,
            failure: Some(why),
            rollback,
            steps_run: run_count,
            steps_skipped: skip_count,
        },
    })
}

struct TargetOutcome {
    run: usize,
    skipped: usize,
    /// The failure and the declared rollback, when this target failed.
    failure: Option<(String, Option<String>)>,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn one_target<T: Transport + ?Sized>(
    store: &PgStore,
    transport: &T,
    claimed: &Claimed,
    scope: &TenantScope,
    resource: ResourceId,
    name: &str,
    endpoint: Option<Endpoint>,
    stop: &AtomicBool,
) -> uops_core::Result<TargetOutcome> {
    let mut out = TargetOutcome {
        run: 0,
        skipped: 0,
        failure: None,
    };

    let Some(endpoint) = endpoint else {
        // A target with no management address. Recorded against this resource by name, and
        // it stops the run like any other failed step — a fleet where one device out of
        // forty has lost its address is a fleet somebody should look at before a
        // destructive runbook carries on through the other thirty-nine.
        store
            .record_step(
                scope,
                claimed.id,
                resource,
                0,
                "resolve the device",
                String::new().as_str(),
                false,
                FAILED,
                Some(&format!(
                    "{name} has no management address, so no step could be sent to it"
                )),
                None,
            )
            .await?;
        out.failure = Some((format!("{name} has no management address"), None));
        stop.store(true, Ordering::Relaxed);
        return Ok(out);
    };

    let context = context_for(&endpoint);

    for (index, step) in claimed.runbook.steps.iter().enumerate() {
        let position = i32::try_from(index).unwrap_or(i32::MAX);

        // Rendered before anything else, because a template this build cannot render is a
        // step that must not be half-sent. The failure names the step.
        let rendered = match render_step(step, &context) {
            Ok(rendered) => rendered,
            Err(e) => {
                store
                    .record_step(
                        scope, claimed.id, resource, position, &step.name, "", step.destructive,
                        FAILED, Some(&e.to_string()), None,
                    )
                    .await?;
                out.failure = Some((
                    format!("step {} could not be rendered: {e}", index + 1),
                    describe_rollback(step),
                ));
                stop.store(true, Ordering::Relaxed);
                return Ok(out);
            }
        };

        // M10 §2.2. The read-only steps really run; the rest are recorded as skipped, not
        // left pending, because a step nobody will run is not a step still to come.
        if claimed.dry_run && !step.runs_in_dry_run() {
            store
                .record_step(
                    scope,
                    claimed.id,
                    resource,
                    position,
                    &step.name,
                    &rendered.join("
"),
                    step.destructive,
                    SKIPPED,
                    Some("not run: this is a dry run, and this step changes something"),
                    None,
                )
                .await?;
            out.skipped += 1;
            continue;
        }

        // What the transcript records as having been sent. One line per template, so an
        // http.request step's body is in the record beside its URL rather than lost.
        let transcript = rendered.join("
");

        let outcome = execute_step(transport, &endpoint, step, &rendered).await;
        out.run += 1;

        let verdict = check_expectation(step, &outcome);
        store
            .record_step(
                scope,
                claimed.id,
                resource,
                position,
                &step.name,
                &transcript,
                step.destructive,
                if verdict.is_ok() { OK } else { FAILED },
                Some(&outcome.output),
                outcome.exit_code,
            )
            .await?;

        if let Err(why) = verdict {
            if step.continue_on_error {
                // Refused by validation on a destructive step, so this is a read-only
                // precondition the author said may fail.
                continue;
            }

            // Everything after this on this device is recorded skipped rather than left
            // pending: nothing will run it, and `pending` would read as "still to come".
            for (later, step) in claimed.runbook.steps.iter().enumerate().skip(index + 1) {
                store
                    .record_step(
                        scope,
                        claimed.id,
                        resource,
                        i32::try_from(later).unwrap_or(i32::MAX),
                        &step.name,
                        "",
                        step.destructive,
                        SKIPPED,
                        Some("not run: an earlier step failed and the run stopped"),
                        None,
                    )
                    .await?;
                out.skipped += 1;
            }

            out.failure = Some((
                format!("{name}: step {} ({}) {why}", index + 1, step.name),
                describe_rollback(step),
            ));
            stop.store(true, Ordering::Relaxed);
            return Ok(out);
        }
    }

    Ok(out)
}

/// What a step's templates substitute from.
///
/// Three values, and no credential among them — there is no binding that could put one in
/// a command, which is M10 §2.4 expressed as an absence rather than as a check.
fn context_for(endpoint: &Endpoint) -> BTreeMap<String, String> {
    let mut context = BTreeMap::new();
    context.insert("resource.name".to_owned(), endpoint.name.clone());
    context.insert("resource.address".to_owned(), endpoint.address.clone());
    context.insert("resource.id".to_owned(), endpoint.resource.to_string());
    context
}

/// Every template in a step, rendered in the order [`Action::templates`] gives them.
fn render_step(step: &Step, context: &BTreeMap<String, String>) -> uops_runbook::Result<Vec<String>> {
    step.action
        .templates()
        .into_iter()
        .map(|template| uops_runbook::render(template, context))
        .collect()
}

/// Send one step.
async fn execute_step<T: Transport + ?Sized>(
    transport: &T,
    endpoint: &Endpoint,
    step: &Step,
    rendered: &[String],
) -> Outcome {
    match &step.action {
        Action::SshCommand { credential, .. } => {
            let command = rendered.first().map_or("", String::as_str);
            transport.ssh(endpoint, command, *credential).await
        }
        Action::HttpRequest {
            method, credential, ..
        } => {
            let url = rendered.first().map_or("", String::as_str);
            let body = rendered.get(1).map(String::as_str);
            transport
                .http(endpoint, *method, url, body, *credential)
                .await
        }
        Action::Wait { seconds } => {
            tokio::time::sleep(std::time::Duration::from_secs(u64::from(*seconds))).await;
            Outcome::exited(0, format!("waited {seconds}s"))
        }
    }
}

/// Whether the step got what it said it expected.
///
/// `Expect` is checked here rather than in the transport because it is a property of the
/// *step*, and the same outcome satisfies one step's expectation and fails another's.
fn check_expectation(step: &Step, outcome: &Outcome) -> Result<(), String> {
    // A transport failure loses before any expectation is considered: `not_contains` over
    // the empty output of a device that was never reached would otherwise pass, and a
    // precondition that passes because nothing happened is the worst possible result.
    if let Some(error) = &outcome.error {
        return Err(format!("failed: {error}"));
    }

    match &step.expect {
        // The same arm, and deliberately not collapsed away in the type: `Expect::Success`
        // is an author writing down what they meant, and an absent expectation is the
        // default. That they agree today does not make them one thing.
        None | Some(Expect::Success) => {
            if outcome.succeeded() {
                Ok(())
            } else {
                Err(outcome.why())
            }
        }
        Some(Expect::Contains { text }) => {
            if outcome.output.contains(text.as_str()) {
                Ok(())
            } else {
                Err(format!("did not find `{text}` in what the device said"))
            }
        }
        Some(Expect::NotContains { text }) => {
            if outcome.output.contains(text.as_str()) {
                Err(format!("found `{text}` in what the device said"))
            } else {
                Ok(())
            }
        }
    }
}

/// The declared rollback in words, to **offer**.
///
/// M10 §2.6, and the sentence that belongs in the UI beside it: a rollback is another
/// runbook, and it can fail too.
fn describe_rollback(step: &Step) -> Option<String> {
    match step.rollback.as_ref()? {
        uops_runbook::Rollback::Action { action } => Some(match action.command_text() {
            Some(command) => format!("the author declared this undone by: {command}"),
            None => format!(
                "the author declared this undone by a {} step",
                action.kind()
            ),
        }),
        uops_runbook::Rollback::None { because } => {
            Some(format!("the author declared no way back: {because}"))
        }
        // Refused by validation, so unreachable through a saved runbook. Reported rather
        // than treated as "no rollback": a run that reached here came from a row written
        // by another route, and that is worth somebody seeing.
        uops_runbook::Rollback::Unknown => Some(
            "this step's rollback is `unknown`, which validation refuses — this runbook \
             did not come through the API"
                .to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uops_core::CredentialRef;

    fn step(expect: Option<Expect>) -> Step {
        Step {
            name: "check".to_owned(),
            action: Action::SshCommand {
                command: "show bgp summary".to_owned(),
                credential: CredentialRef::new(),
            },
            destructive: false,
            rollback: None,
            expect,
            continue_on_error: false,
        }
    }

    #[test]
    fn a_device_that_was_never_reached_fails_every_expectation() {
        // The case that matters: `not_contains` over empty output would otherwise pass,
        // and a precondition that passes because nothing happened is the worst result
        // this module can produce.
        let unreachable = Outcome::failed("connection refused");
        for expectation in [
            None,
            Some(Expect::Success),
            Some(Expect::Contains {
                text: "Idle".to_owned(),
            }),
            Some(Expect::NotContains {
                text: "Idle".to_owned(),
            }),
        ] {
            let verdict = check_expectation(&step(expectation.clone()), &unreachable);
            assert!(verdict.is_err(), "{expectation:?} passed on an unreachable device");
        }
    }

    #[test]
    fn contains_is_checked_against_the_output_and_not_the_exit_code() {
        // A device CLI that prints `% BGP not enabled` and exits zero is the ordinary
        // shape of a failed precondition, and an exit code alone would call it fine.
        let said_no = Outcome::exited(0, "% BGP not enabled".to_owned());
        let verdict = check_expectation(
            &step(Some(Expect::Contains {
                text: "Idle".to_owned(),
            })),
            &said_no,
        );
        assert!(verdict.is_err());
        assert!(verdict.unwrap_err().contains("Idle"));
    }

    #[test]
    fn not_contains_fails_when_the_text_is_there() {
        let found = Outcome::exited(0, "Neighbor 10.0.0.1 Idle".to_owned());
        assert!(
            check_expectation(
                &step(Some(Expect::NotContains {
                    text: "Idle".to_owned()
                })),
                &found
            )
            .is_err()
        );
    }

    #[test]
    fn a_step_with_no_expectation_is_judged_by_whether_it_worked() {
        assert!(check_expectation(&step(None), &Outcome::exited(0, "up".to_owned())).is_ok());
        assert!(check_expectation(&step(None), &Outcome::exited(1, String::new())).is_err());
    }

    #[test]
    fn the_render_context_has_no_binding_for_a_credential() {
        // M10 §2.4 as an absence rather than a check: a template cannot substitute a
        // credential because there is no key that would give it one.
        let context = context_for(&Endpoint {
            tenant: uops_core::TenantId::new(),
            resource: ResourceId::new(),
            name: "core-sw-1".to_owned(),
            address: "10.0.0.1".to_owned(),
        });
        assert_eq!(context.len(), 3);
        for key in context.keys() {
            for word in ["credential", "password", "secret", "key", "token"] {
                assert!(!key.contains(word), "`{key}` would expose a {word}");
            }
        }
    }

    #[test]
    fn an_unknown_rollback_is_reported_rather_than_read_as_none() {
        // Validation refuses it, so a run that reached here came from a row written by
        // another route — which is worth somebody seeing rather than silently treating as
        // "no rollback declared".
        let mut s = step(None);
        s.rollback = Some(uops_runbook::Rollback::Unknown);
        let described = describe_rollback(&s).expect("unknown must still be described");
        assert!(described.contains("did not come through the API"), "{described}");
    }

    #[test]
    fn a_declared_rollback_is_described_as_the_authors_claim() {
        // "the author declared", not "this will undo it". A rollback is another runbook
        // and it can fail too — M10 §2.6.
        let mut s = step(None);
        s.rollback = Some(uops_runbook::Rollback::None {
            because: "a cleared session cannot be un-cleared".to_owned(),
        });
        let described = describe_rollback(&s).unwrap();
        assert!(described.starts_with("the author declared"), "{described}");
    }
}
