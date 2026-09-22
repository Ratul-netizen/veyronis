# Runbooks

Running something against the estate, and everything that stands between deciding to and
it happening.

`docs/M10-automation.md` records *why* it is built this way; this file is for somebody
about to run one.

---

## The shape of it

```text
write ──▶ save ──▶ dry run ──▶ approve ──▶ a runner picks it up
           │         │            │
      refuses a   names every   somebody who is
      claim, not  resource and  not you, within
      a command   every command ten minutes
```

Five stages, and **four of them happen before anything reaches a device**. That is the
whole design: the mistakes this product is afraid of are the ones nobody looked at, so
every stage exists to put a number or a sentence in front of somebody.

---

## Writing one

Runbooks → *New version*. A runbook is JSON: a name, a selector, and a small list of typed
steps.

```json
{
  "name": "restart-bgp-session",
  "description": "Check a BGP session is down, then clear it",
  "targets": { "type": "all" },
  "steps": [
    {
      "name": "check the session is actually down",
      "action": {
        "kind": "ssh_command",
        "command": "show bgp summary",
        "credential": "<credential id>"
      },
      "destructive": false,
      "expect": { "kind": "contains", "text": "Idle" }
    },
    {
      "name": "clear it",
      "action": {
        "kind": "ssh_command",
        "command": "clear bgp neighbor {{ resource.name }}",
        "credential": "<credential id>"
      },
      "destructive": true,
      "rollback": { "kind": "none", "because": "a cleared session cannot be un-cleared" }
    }
  ],
  "max_targets": 10,
  "concurrency": 2,
  "approvals": "one",
  "maintenance_only": false
}
```

**There are three action kinds and no shell.** `ssh_command`, `http_request`, `wait`. A
step that does not match one of them does not save. That costs expressiveness and buys the
property the rest of this depends on: what a runbook can do is enumerable by reading it.

**Substitution, not evaluation.** `{{ resource.name }}`, `{{ resource.address }}`,
`{{ resource.id }}` — and nothing else, including no way to name a credential. A value
containing anything but letters, digits and `. : - _ / @` is refused at render time,
naming the character. It is not stripped: a value quietly stripped of a semicolon is a
command reviewed in one form and run in another.

**An unset placeholder is an error.** `rm -rf /{{ path }}` with `path` unset renders as
`rm -rf /` under every templating library that treats a missing key as blank. This one
refuses.

**Editing writes a new version.** Post a runbook whose name already exists and it becomes
version *n+1*; version *n* stays readable, and every run names the version it executed.
There is no edit, and the database refuses one even if something tried.

### What the validator refuses

Every problem at once, not the first — an author fixing them one at a time saves six
times.

| refusal | why |
|---|---|
| a step marked read-only whose command matches the deny-list | `reload`, `erase`, `delete`, `format`, `shutdown`, `halt`, `rm -rf`, HTTP `DELETE`. The message names the word it matched |
| a destructive step with no `rollback` | undeclared is undecided |
| `"rollback": { "kind": "unknown" }` | a step whose author has not decided is a step nobody has thought about |
| a rollback on a step that changes nothing | a rollback nobody will maintain |
| `continue_on_error` on a destructive step | continuing past a change that failed is the unknown state the product refuses to act into |
| a destructive runbook with `"approvals": "none"` | see below |
| a `wait` or an HTTP `GET` marked destructive | a runbook that marks everything destructive to look careful trains everybody to click through the warning |

The deny-list will never be complete and is not trying to be. It catches the step somebody
marked read-only by accident. The defence against an author being deliberately clever is
the approval, not a regex.

---

## Dry running

Runbooks → *Dry run*. This is the screen the milestone is about.

It does three things and is honest about the third:

1. **Resolves the targets and names them.** The count is at the top. It is the number
   nobody checks and everybody should — a selector meant to match one switch and matching
   four hundred is the single most common way automation causes an outage.
2. **Renders every command.** What you read is the literal text that would be sent, with
   substitution applied. A template is what the mistake hides in.
3. **Executes only the steps that change nothing.** Really executes them, against the real
   devices, now. So a precondition is genuinely checked rather than assumed.

**What it cannot do is predict the effect of the steps it did not run.** The screen says
*"would run 3 steps on 4 resources"* and there is no version of it that says *"would
succeed"*.

A selector resolving to more than `max_targets` **does not run**, and the refusal says by
how much. Raising the limit is an edit to the runbook, which is a reviewed object — not a
checkbox at run time.

---

## Starting a real one

The dry run is the primary button. A real run is behind a checkbox and a confirmation that
repeats the count, and that friction is deliberate.

**Every destructive run needs an approval, and it cannot be yours.** The product enforces
that rather than trusting a process document: the approve button is not offered to the
person who started the run, the API refuses it, and the database has no row that could
express it. A runbook may require two — a per-runbook setting, because requiring two
approvals for restarting an interface is how an organisation ends up with a standing
exception, and a standing exception is worse than no rule.

**An approval expires after ten minutes.** One given against a target list that may no
longer be the same estate is not one this will act on. A run whose approval went stale
while it queued goes **back to waiting**, not to failed: what went wrong is that ten
minutes passed, and the next step is to ask somebody again.

**A dry run needs no approval, whatever the runbook requires.** It sends only the steps
marked as changing nothing, so there is nothing for an approval to be about — and
requiring one would teach everybody to approve dry runs without reading them.

### Break-glass

An organisation with a rule, a production outage at 3 a.m. and one engineer awake will get
around the rule — through a laptop and SSH, with no audit trail at all. So the product
offers the route it can observe.

The organisation's single **break-glass account** — the same one that may sign in with a
password when SSO is required — may start a destructive run without an approval. Every
such run:

* is audited as `runbooks.run.break_glass`, a different action from an ordinary start, so
  an investigation can filter for them rather than read every run;
* carries `unapproved` on its record **for as long as the record exists**.

It is not a way to avoid asking. It is a way for asking to have been skipped *visibly*.

### Maintenance windows

A runbook with `"maintenance_only": true` runs only while **every one of its targets** is
inside an open maintenance window. Not any of them: a change that reaches one device
nobody scheduled work on is a change outside the window.

This cuts the opposite way from alerting, and deliberately. An alert is *suppressed* during
a window; an automated change is *only permitted* during one.

---

## While it runs

`POST` returns as soon as the run is recorded. Nothing has been sent — `uops-runner` picks
it up, because an SSH handshake does not belong on the API's runtime, and a run that says
`Queued` is waiting for a runner rather than promising a time.

Runs → a run → the transcript. Per device, per step, with the command that was sent and
what came back.

**A step that fails stops the run.** Everything after it on that device is recorded as
*not run*, no further device is started, and a device already in flight finishes the step
it is on — abandoning it would leave the product not knowing what the device did.

**The rollback is offered, never performed.** What the author declared undoes the step is
shown, with the sentence that it has not been run. A step that failed halfway left the
device in a state this product does not know, and running more commands into an unknown
state is how a small outage becomes a large one — and *a rollback is another runbook, and
it can fail too*.

### Cancelling

Only before a runner takes it. Once a run has sent something, *cancel* would be a promise
the product cannot keep; what it offers instead is the transcript and the declared
rollback.

### If the runner stops

A run left mid-flight by a stopped runner is marked **failed** at the next runner
start-up, not requeued. It may already have sent a destructive step and the product does
not know which; re-running it would be the product deciding by itself to send
`clear bgp neighbor` a second time.

---

## Credentials

A step names a credential **by reference**. The transport opens the connection; the
credential never enters the runbook's context, never appears in a rendered command, and
cannot be substituted into one because the template engine has no binding for it.

**SSH steps authenticate with a key.** A password credential, or a key with a passphrase,
is refused at execution with a message saying which. `ssh(1)` cannot take either without a
helper program whose job is to print a secret, and a runbook that changes an estate should
be using a key. See M10 §2.10 for why the transport is OpenSSH at all.

`http_request` steps take an API token, which becomes an `Authorization` header — never a
query parameter, because a token in a URL is a token in the device's own access log and in
this product's transcript.

---

## Running the runner

```bash
UOPS_KEK_FILE=/etc/uops/kek            # or UOPS_KEK_HEX. No default: a runner that
                                       # cannot open a credential has nothing to do
UOPS_RUNNER_STATE_DIR=/var/lib/uops    # no default either — see below
DATABASE_URL=postgres://…
uops-runner
```

**`UOPS_RUNNER_STATE_DIR` has no default on purpose.** It holds `known_hosts` — the record
of which devices this deployment has decided to trust. A default under `/tmp` would mean a
container restart silently discarding every host key it had learned, which turns
`StrictHostKeyChecking=accept-new` back into trust-on-every-use. Give it a path that
persists, and back it up with the rest of the deployment's state.

**OpenSSH must be installed** where the runner runs. The error says so if it is not.

Two runners against one database are safe: they take a lease, and the claim itself is a
single `UPDATE` the database serialises, so a queued run executes once.

---

## What the transcript is not

It is redacted on the way in — known secret shapes are replaced, whole-word matched — and
capped at 4 KiB per step, so a `show running-config` is truncated rather than stored.

That redaction is a **net, not a boundary**. A regex over arbitrary device output cannot be
complete; vendors invent syntax. What actually keeps a transcript from becoming a
credential store is three things together, of which the regex is the weakest: the cap, the
fact that this is not where configuration backup lives, and then the regex.

A deployment that treats the redaction as a guarantee has misread it. A deployment that
keeps its transcripts under the same access control as its credentials has not.

---

## What this does not do

**Nothing triggers a runbook except a person.** Not an alert, not a schedule. The
product's alerting has a false-positive rate nobody has measured, and wiring an unmeasured
false-positive rate to an action that restarts a device is how a monitoring product causes
the outage it was bought to prevent. M10 §2.8 names the precondition: a measured rate.

A run already records *why* it was started, and that field is shaped for a non-human
reason — so the connection, when it is made, is a decision rather than a migration.
