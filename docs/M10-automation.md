# M10 — Automation

PLAN §10: *runbooks · SSH · APIs · approval · rollback · audit*.

Written before anything is built, the way every milestone since M5 has been. This one
differs from all of them in a way that has to come first:

> **Every milestone up to here reads. This one writes.**

M0 through M12 observe a customer's estate. They poll it, receive from it, correlate it
and draw it, and the worst thing a defect in any of them can do is report something untrue.
M10 logs into somebody's core switch and runs a command. The worst thing a defect here can
do is take down a hospital's network at 3 a.m. because an alert misfired.

That asymmetry is not a reason to refuse the milestone — an NMS that cannot act is half a
product, and the operators who want this want it badly. It is a reason for every decision
below to be about what stops it, and for the interesting engineering to be in the
refusals rather than in the execution.

---

## 1. What "automation" means here, and what it does not

**A runbook is a named, versioned, reviewed sequence of steps.** It is written once,
reviewed like code, and run many times. It is *not* a box an operator pastes a command
into — that is a remote shell with an audit log, which is a worse remote shell than the
one they already have.

The distinction is the whole design. A runbook can be reviewed before it is ever run,
which is where a mistake should be caught. A free-text command can only be reviewed
*after*, by reading what happened.

**Every run is initiated by a person.** M10 has no trigger from an alert, no schedule, no
self-healing. That is §2.8 and it is the decision most likely to be argued with, so it is
argued for there rather than asserted here.

**The product does not become a configuration manager.** Ansible, Salt and NetBox+NAPALM
exist and are better at that than a monitoring product will be. What this does is the
thing those cannot: act on the resource identity, topology and telemetry this product
already holds — *restart the BGP session on the device whose flow just collapsed*, with the
device identified by the same `resource_id` the alert fired on.

### What this milestone deliberately does not chase

**A workflow engine.** Branching, loops, parallel fan-out with join semantics, and a
visual designer. Every automation product grows one and every one of them becomes a
programming language with a worse debugger. A runbook here is a sequence with a
precondition per step, which covers the cases an operator actually writes and stops well
short of Turing-completeness.

**Arbitrary code execution as a feature.** No embedded Python, no Lua, no `eval`. A step
is one of a small number of typed action kinds. This costs expressiveness and buys the
one property that matters: *what a runbook can do is enumerable by reading it*, by a human
and by the product.

**Credential passthrough.** A runbook never receives a credential and never renders one
into a command. §2.4.

---

## 2. Decisions

### 2.1 A runbook is data, not a script.

```
runbook: restart-bgp-session
  description: ...
  targets:    a resource selector — the same one alert rules and saved searches use
  steps:
    - name: check the session is actually down
      action: ssh.command { command: "show bgp summary" }
      expect: stdout contains "Idle"
    - name: clear it
      action: ssh.command { command: "clear bgp neighbor {{ peer }}" }
      destructive: true
      rollback: none — clearing a session cannot be un-cleared
```

**Typed actions, not a shell.** The first three kinds are `ssh.command`, `http.request`
and `wait`. Each has a schema; a step that does not match one is a runbook that fails
validation at save time rather than at 3 a.m.

**Templating is substitution, not evaluation.** `{{ resource.name }}`, `{{ peer }}` — a
named value from the run's context. There is no expression language, because an expression
language is where injection lives and where "the runbook did something nobody predicted"
starts.

> **Amended while building it.** This paragraph said a value would be *"escaped for the
> transport it is going into"*, and writing `render.rs` is what showed that to be wrong.
> `ssh.command` does not run in a POSIX shell. It runs in a Cisco IOS CLI, or a JunOS CLI,
> or a busybox on a PDU, and their quoting rules differ from each other and from `sh` — a
> product that shell-quoted `10.0.0.1` into `'10.0.0.1'` would break on the majority of the
> devices this is for.
>
> So a value must **be** safe rather than be made safe: letters, digits, and `. : - _ / @`,
> which covers every hostname, address, interface name and peer identifier that actually
> appears. Anything else is refused at render time, naming the character. Not stripped — a
> value quietly stripped of a semicolon is a command an operator reviewed in one form and
> ran in another.
>
> **And an unknown placeholder is an error, not an empty string.** `rm -rf /{{ path }}`
> with `path` unset renders as `rm -rf /` under every templating library that treats a
> missing key as blank. So does an empty *value* under a key that exists, which is refused
> too.

**Stored in PostgreSQL, versioned, and immutable once run.** Editing a runbook creates a
new version. A run records the version it executed, so "what did this actually do in
March" has an answer that does not depend on nobody having edited it since. The same
argument migrations make about being immutable after they are applied.

### 2.2 Dry run is the default, and it is not a simulation.

**Every run is a dry run unless somebody says otherwise**, and the API's default is the
safe one — not a flag that defaults to `false` and can be omitted.

A dry run does three things and is honest about the third:

1. **Resolves the targets** and reports exactly which resources would be acted on, by
   name. The count is the number nobody checks and everybody should: a selector that was
   meant to match one switch and matches four hundred is the single most common way
   automation causes an outage.
2. **Renders every step**, with substitution applied, so an operator reads the literal
   command that would run.
3. **Executes only the steps marked read-only** — the `show` commands, the `GET`s. The
   preconditions are therefore really checked, against the real devices, right now.

**What it cannot do is predict the effect of the steps it did not run.** A dry run that
claimed to know what `clear bgp neighbor` would do would be lying, and a safety feature
that lies is worse than none. The UI says *"would run 3 steps on 4 resources"* and never
*"would succeed"*.

### 2.3 Destructive is declared by the author and verified by the product.

An action is destructive if it changes state. The runbook's author marks each step, and
the product does not take their word for it:

* **A step whose action kind is inherently read-only** — `wait`, an HTTP `GET` — cannot be
  marked destructive, because a runbook that marks everything destructive to look careful
  trains everybody to click through the warning.
* **A step whose command matches the deny-list is destructive whatever it claims.** A
  small, boring list — `reload`, `erase`, `write erase`, `delete`, `format`, `shutdown`,
  `halt`, `rm -rf`, an HTTP `DELETE` — and a mis-marked step fails validation with the
  word it matched on.

That list will never be complete and is not trying to be. It exists to catch the case
where somebody marked a step read-only by accident, not to defend against an author who
is being deliberately clever — an author who can write a runbook can already do this by
hand, and the defence against them is the approval in §2.5, not a regex.

### 2.4 The runbook never sees a credential.

The step says *which credential reference* to use — the same `CredentialRef` the poller
uses, resolved through the same vault. The transport opens the connection; the credential
never enters the runbook's context, never appears in a rendered command, and cannot be
substituted into one because the template engine has no binding for it.

**And output is redacted before it is stored.** A `show running-config` prints a hashed
password; a `curl -v` prints an `Authorization` header. The audit trail of a runbook run
is one of the most sensitive tables this product will have, and the failure mode is that
it quietly becomes a credential store. So: the known shapes are stripped, output has a
size cap, and — the part that matters more than the regex — the audit record of a
destructive step is not the place anybody should be reading configuration from anyway.

`uops-secrets` already has a CI guard that keeps crypto primitives in one crate. This
needs the equivalent: a guard that a rendered command and a captured output cannot reach a
logging macro.

### 2.5 Approval is per-run, and two-person integrity is per-runbook.

PLAN §0b: *destructive automation in defence contexts → two-person integrity on runbooks —
note for M10, do not build now.* It is M10 now, so:

**Every destructive run requires an approval.** The operator who starts it is not the
operator who approves it, and the product enforces that rather than trusting a process
document. The approval names the run, the resolved target list and the runbook version —
approving *a run*, not a runbook, because the dangerous variable is which resources it
resolved to.

**An approval expires.** Ten minutes, the same order as the OIDC sign-in window. An
approval that sat overnight is an approval given against a target list that may no longer
be the same estate.

**A runbook may require two.** A per-runbook setting rather than a global one: requiring
two approvals for restarting an interface is how an organisation ends up with a standing
exception, and a standing exception is worse than no rule.

**And there is a break-glass.** An organisation that requires approval and has a
production outage at 3 a.m. with one engineer awake will get around the rule — through a
laptop and SSH, with no audit trail at all. So the product offers the route it can
observe: a single named role may run without approval, every such run is an audit event of
its own kind, and the run record says it was unapproved for as long as it exists. The same
argument, and the same shape, as the break-glass account in M12 §2.2.

### 2.6 Rollback is a declaration, not a promise.

Every destructive step declares one of three things, and the third is a first-class
answer:

* **`rollback: <step>`** — an action that undoes it.
* **`rollback: none`**, with a reason. Clearing a BGP session cannot be un-cleared. A
  reboot cannot be un-rebooted.
* **`rollback: unknown`** — fails validation. A step whose author has not decided is a
  step nobody has thought about.

**Rollback is offered, never automatic.** A step that fails halfway leaves the device in a
state the product does not know, and running more commands into an unknown state is how a
small outage becomes a large one. What the product does is *stop*, show what ran, what its
output was, and what the declared rollback would be — and let a person decide.

The honest sentence, which belongs in the UI and not only here: **a rollback is another
runbook, and it can fail too.**

### 2.7 Blast radius is bounded before it is approved.

A selector that resolves to more resources than the runbook's declared maximum **does not
run**. The maximum is per-runbook, defaults to a small number, and raising it is an edit
to a reviewed object rather than a checkbox at run time.

Three further bounds, because the interesting failures are about scale rather than
correctness:

* **Concurrency** is capped per run and per tenant — a runbook that SSHs into four hundred
  devices at once is a denial of service against the customer's own authentication server.
* **Maintenance windows are honoured**, and this one cuts the opposite way from alerting:
  an alert is *suppressed* during a window, and an automated change should arguably be
  *only* allowed during one. The setting is per-runbook and the default is the
  conservative one.
* **A run stops at the first failed step** unless the step is marked `continue_on_error`,
  which is for the read-only preconditions and refused on destructive steps.

### 2.8 Nothing triggers a runbook except a person. Not in M10.

This is the decision most likely to be argued with, because auto-remediation is what sells
an automation module. The argument for deferring it:

**The product's alerting has a false-positive rate that nobody has measured yet.** M4 does
`ok → pending → firing`, which stops flapping, and a flapping signal producing zero
notifications is a *measured* property. Nothing has measured how often `firing` is wrong.
Wiring an unmeasured false-positive rate to an action that restarts a device is how a
monitoring product causes the outage it was bought to prevent.

**And the blast radius of a bad trigger is different in kind.** A false page wakes
somebody. A false remediation, fired across a selector, changes an estate at machine
speed, and the second alert it causes fires the runbook again.

So M10 builds the thing auto-remediation would need — a runbook that is reviewed, bounded,
approved and audited — and does not connect it. The connection is a later decision made
with data this product does not have yet, and the data it needs is a false-positive rate
somebody has measured. That is a concrete precondition rather than a vague "when we are
ready".

**What M10 *does* build toward it:** a run records why it was started, and the field is
already shaped for a non-human reason.

### 2.9 It runs where the poller runs, under a lease.

Not in `uops-server`. A runbook step is a long, blocking, network-bound operation with an
SSH handshake in it, and putting those on the API's runtime is how a web request queues
behind a device that is not answering.

`uops-runner` is a binary of its own, taking the `run` lease from M12 §2.1 — one owner, so
a run cannot be started twice by two replicas. It reads the queue from PostgreSQL, which
is the same pattern the sweeper uses, and needs the vault for the same reason the poller
does.

### 2.10 The SSH transport is OpenSSH, because there is no library this product may link.

This decision was made while building the runner, and it was not the intended one.

**What was looked for and not found.** An SSH client for this workspace has to be pure
Rust and carry a licence on the allow-list, because every other transport decision in this
product has been made that way: `snmp2` over `async-snmp` to avoid `aws-lc-rs`, `ureq`
without default features, `sqlx` and `axum` and the ClickHouse client all without TLS. The
one maintained async SSH client in the ecosystem, `russh`, offers exactly two crypto
backends — `aws-lc-rs` and `ring` — and both carry the OpenSSL licence term in their
expression. Neither is on the allow-list.

Adding one would make this the first OpenSSL-licensed code in an AGPL product, which is a
distribution question for a lawyer and not a dependency choice for an afternoon. The
alternative, writing an SSH client, is not a serious proposal: the transport that logs into
a customer's core switch is the last place in this product to hand-roll cryptography.

**So the transport is `ssh(1)`, invoked as a child process with an argument vector.**

The cost is real and worth stating: the product now depends on OpenSSH being installed,
and on its exit-code contract — 255 for the client's own failures, the remote command's
status otherwise. That contract has been stable for twenty years and is better understood
than anything this repository could write.

Three things fall out of it that are better than the library would have been:

* **There is no shell on this side.** `std::process::Command` takes an argv, not a command
  line, so nothing between this process and `ssh` interprets the rendered text. The far end
  still interprets it — that is what a device CLI *is* — which is precisely why §2.1's
  amendment refuses to shell-quote and demands that a value simply *be* safe. Removing the
  local shell removes the layer that could have been argued about; the remote one was never
  ours to quote for.
* **The credential never becomes a string in this process's memory on the way to the
  device.** It is written to a private file, the path is passed as `-i`, and the file is
  removed when the step ends.
* **Host keys are checked.** `BatchMode=yes`, and `StrictHostKeyChecking=accept-new`
  against a `known_hosts` file the product owns. Trust on first use, which is weak, and
  `no` — which is what every hurried integration picks — is not weak, it is nothing. Once a
  device's key is recorded, a changed key stops the run, which is the case worth catching.

**Key authentication only, and this is a security position rather than a shortcut.**
`ssh(1)` cannot take a password without a helper, and the helper would be a program whose
job is to print a secret. A runbook that changes an estate should be authenticating with a
key, so `CredentialMaterial::SshPassword` is refused at execution with a message that says
so, and a passphrase-protected key is refused the same way. If a deployment genuinely needs
either, the route is `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force`, and it is a decision
somebody should make deliberately rather than inherit.

**`http.request` needs none of this.** It is the HTTP client already in the tree.

---

## 3. Acceptance criteria

- [x] A runbook is created, validated, versioned, and a second edit produces a second
      version while the first stays readable
- [x] A step whose action does not match a known kind, or whose rollback is `unknown`,
      fails validation at save time with a message naming the step
- [x] A step marked read-only whose command matches the deny-list fails validation, naming
      the word it matched
- [x] A dry run resolves the targets, names every resource, renders every command, and
      executes only the read-only steps — verified against a real SSH server, not a mock
      > **It was partly met, and this is what the rest took.** The resolving, naming and
      > rendering were tested by `uops-api/tests/runbooks.rs` and the executing by
      > `uops-runner/tests/runner.rs`; what was missing was a *completed session*, because
      > no SSH server was reachable from the machine this was built on. What had been
      > verified against a real `ssh(1)` was the client invocation and the refused-
      > connection contract (`ssh::tests::a_refused_connection_is_reported_as_never_having_asked`),
      > which is the failure path rather than the working one.
      >
      > **Closed 2026-09-24 by `uops-runner/tests/live_ssh.rs`**, against a real `sshd`.
      > Nothing is stubbed between the run queue and the remote shell: the key is sealed in
      > the vault, opened through `PgSealedStore`, written to a private file for the
      > duration of the step and removed after it.
      >
      > The read-only step's proof is output no mock could produce — a per-run marker
      > concatenated with `$(uname -s)`, which only a real remote shell expands. The
      > destructive step's proof is **not** its transcript: the test asks the device
      > directly, over a separate `ssh`, whether the file that step would create exists. A
      > scripted transport cannot make that assertion, because it is about the far end's
      > disk rather than about what the runner recorded.
      >
      > `a_real_run_does_send_the_destructive_step_to_the_device` is the paired positive
      > case, without which the first test proves only that *nothing* was sent —
      > `uops-store-pg/tests/restore.rs` makes the same argument about its own negative
      > assertion.
      >
      > **Skipped, loudly, when `UOPS_SSH_HOST` and friends are unset**, so a developer
      > without the fixture does not get a red suite for a server they did not ask for —
      > the pattern `uops-poller/tests/live.rs` established.
      >
      > Building it found a defect worth recording: `runs_in_dry_run` was
      > `!destructive && is_inherently_read_only()`, which meant a dry run of this
      > milestone's own example runbook executed *nothing* and reported "would run 2 steps"
      > having touched no device — exactly the simulation §2.2 opens by saying a dry run is
      > not. The author's `destructive` flag is what decides, and §2.3's deny-list is what
      > makes that flag trustworthy. That is what §2.3 is for.
- [x] A run whose selector exceeds the runbook's maximum does not run, and says by how much
      > And the count is checked *before* the names are fetched, so a selector matching
      > forty thousand resources costs one index scan to be told no rather than forty
      > thousand rows of work.
- [x] A destructive run started and approved by the same person is **refused**
- [x] An approval older than its window is refused, and the run stays pending rather than
      failing
- [x] A break-glass run without approval succeeds, is audited as its own kind of event, and
      the run record says it was unapproved
      > `runbooks.run.break_glass` is a separate action from `runbooks.run.start`, not one
      > action with a flag: an investigation looking for these should filter on the action
      > rather than read every run's detail. The account is the organization's single
      > emergency account — the same one M12 §2.2 created, which §2.5 asks for by name.
- [x] A step that fails stops the run, and the product offers the declared rollback rather
      than performing it
- [x] A rendered command and a captured output never reach a log line — by the same kind of
      CI grep that keeps crypto in `uops-secrets`
- [x] A credential used by a run never appears in the run record, the rendered command, or
      the output
- [x] Two runners against one database execute each queued run **once** — by the same
      lease M12 §2.1 built
      > And not by it, which is the part worth reading. The lease bounds how many runners
      > contend; what makes the claim atomic is one `UPDATE … FOR UPDATE SKIP LOCKED` that
      > the database serialises. The test runs **with no lease at all**, so it tests the
      > claim rather than the lease — M12 §2.3's enrolment token is where that distinction
      > was learned.
- [x] Cross-tenant isolation holds for every new surface, by the same adversarial test
      every milestone since M7 has used
      > Ten routes, each with both attacks. The second one matters more here than anywhere
      > else in the product: a leak on these routes is not one customer *reading* another's
      > inventory, it is one customer **starting a run against** it.
      >
      > The two store surfaces that are deliberately cross-tenant — `claim_next_run` and
      > `fail_abandoned_runs`, because a runner serves a deployment rather than a tenant —
      > carry the `tenant-exempt` marker the CI guard reads, and everything they hand back
      > carries the tenant it came from.

---

## 3b. What the screens are, and the one that is the product

`RunbooksPage` lists what exists. `RunPage` says what happened. **`PlanPage` is where
somebody decides**, and every decision §2.2 argues for is on it: the resolved targets by
name, the count in front of the reader, the literal command that would be sent to each
device, and a mark against every step saying whether a dry run executes it.

It prints the server's own sentence rather than composing one. There is no client-side
summary, because there is no client-side version of *"would run 3 steps on 4 resources,
none of which change anything"* that could not drift into *"would succeed"*.

**Starting a real run is two clicks and the second is not the easy path.** A dry run is the
primary button; a real run is behind a checkbox that says what it means and a confirmation
that repeats the count. Deliberate friction on the only action in this product that
changes somebody else's equipment.

**There is no runbook editor.** A runbook is written as JSON in a textarea and posted, and
the refusal comes back in full with every problem at once. A typed step-tree editor is a
screen of its own and is not what §3 asks for — what §3 asks for is that a runbook is
created, validated and versioned, and that the refusal names the step.

### A test-infrastructure note that is really a design note

The queue is deployment-wide: `claim_next_run` takes the oldest `ready` run in the whole
database, because a runner serves a deployment rather than a tenant. That is correct, and
it means **two test binaries against one database are two runners contending for one
queue** — `uops-api`'s tests create `ready` runs and `uops-runner`'s claims them, then
asserts about a runbook it never wrote.

An in-process mutex cannot fix that; a `PostgreSQL` session advisory lock can, because the
contention is in the database and so is the lock. Both suites take it, held by a connection
of its own so that a panicking test still releases it.

The same work turned up a second thing worth knowing: a development database accumulates
abandoned `ready` rows, and oldest-first means a fresh test claims one of them. The runner
fixture drains the queue under the lock. Both are the shape of the real system showing
through the tests rather than test bugs, which is why they are recorded here.


## 4. What M10 does not do

**Auto-remediation.** §2.8, with the precondition named.

**Scheduled runs.** A cron that changes a network unattended is auto-remediation with a
clock instead of an alert, and it has the same unmeasured precondition.

**Configuration backup and diff.** It is the single most-requested NMS feature after
alerting and it is a milestone of its own, not a side effect of having SSH. Doing it badly
here — a `show running-config` stashed in a runbook's output — would be worse than not
doing it, because the output table is redacted, capped and not built to be read as
configuration.

**Netconf, RESTCONF, gNMI.** SSH and HTTP first, because they reach everything. The
structured protocols are better and are worth adding once there is one customer whose
devices all speak one of them.

**A runbook marketplace.** Shipping a library of vendor runbooks means shipping commands
that run on somebody's core switch, maintained by people who have not seen their estate.
An organisation's runbooks are its own, reviewed by the people who own the consequences.
