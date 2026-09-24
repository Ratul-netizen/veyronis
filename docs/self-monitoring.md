# Self-monitoring, and the detection path that does not exist

**Status:** a decision document, not a milestone. **§2.3 and §4 are built** — migration
0027, `uops_store_pg::platform`, the sign-in path, and `uops-platform-events` for the
collector, lease and runbook events. §2.1, §2.2 and §2.4 were costed and not taken; they are kept because the reasoning is what makes the choice reviewable, and because
§3 names the thing that would overturn it.

M11 §2.4 said the product's own sign-ins should be *"the first source"* of authentication
events — *"a security-analytics milestone whose first detection cannot see attacks on the
monitoring platform itself is one that missed the target closest to it."* Building it showed
the shape was wrong, the criterion went `[~]`, and the amendment named a precondition:

> A detection cannot fire on these. The alert engine evaluates a `Query` against
> `ClickHouse` under a tenant scope, and these are `PostgreSQL` rows with no tenant.
> Detecting on them needs an organization-scoped evaluation path, which does not exist.

This document is what that precondition turns out to involve, because "add an
organization-scoped evaluation path" sounds like one change and is three.

---

## 1. Why it is three changes

A detection over product sign-ins has to cross every axis the alerting engine is built on.

| | an ordinary alert rule | a sign-in detection |
|---|---|---|
| **scope** | `TenantScope`, and `alert_rule.tenant_id` is `NOT NULL` | an organization — authentication precedes knowing a tenant |
| **store** | `ClickHouse` | `PostgreSQL`: `audit_log` is a control-plane table |
| **language** | the `Query` AST, over six telemetry signals | none of those signals is `audit_log` |

Each of the three is load-bearing somewhere else:

* **`TenantScope` is the isolation guarantee**, and SPEC §M0.8 is explicit that it is
  *"enforced by the type system, not by review"*. A repository takes `&TenantScope` and a
  missing tenant filter is a compile error. An `OrgScope` alongside it is a second thing
  that has to be equally hard to get wrong, and the first version of anything is not.
* **The Query AST is the single path to SQL** — PLAN's frozen decision, *"never a parallel
  code path"*. It compiles to `ClickHouse` because that is where telemetry lives.
* **`audit_log` is deliberately not telemetry.** It is the control plane's own record, it
  is written in the same transaction as the thing it records, and it is read by an
  auditor rather than by a dashboard.

**A change that touches all three at once is not a feature, it is a second alerting
engine.** That is the thing to avoid, and it is why this is a document rather than a
branch.

---

## 2. The options, and what each one costs

### 2.1 Emit sign-ins into `events` under every tenant in the organization

Write one `EventRow` per tenant the organization owns. Everything downstream works
unchanged — detections, incidents, timeline, suppression — because the row is an ordinary
tenant-scoped event.

**What it costs.** An organization-level fact becomes N tenant-level rows, each of which is
an invitation for a tenant-scoped detection to count a sign-in that was not against that
tenant. For an MSP with two hundred tenants a failed-login burst of a thousand becomes two
hundred thousand rows, which `ClickHouse` will not notice and an operator reading a
per-tenant count will.

It is also **false in the way that matters**: a detection that says "twenty failed sign-ins
against this tenant" when the sign-ins were against the organization is the product
asserting something it knows to be untrue. Rejected.

### 2.2 Give `events` an `org_id` and the engine an organization scope

Add the column, add `OrgScope`, let a rule carry one or the other.

**What it costs.** Two isolation types, and every repository method that takes a scope has
to decide which it accepts. The property SPEC §M0.8 relies on — *a missing tenant filter is
a compile error* — becomes *a missing filter of the right kind is a compile error*, which
is weaker in a way that is hard to see and easy to get wrong. It also puts control-plane
facts in the telemetry plane, which is the boundary M0 drew deliberately.

Not obviously wrong, and by far the largest change. If the product ever needs
organization-level *telemetry* for a second reason, this becomes the right answer; with one
reason it is a lot of structure for one question.

### 2.3 The installation is a resource

The product monitors an estate. **The monitoring platform is part of an estate**, and this
product has a type for that: a resource. Sign-ins become `authentication` events on a
`self` resource, in a tenant the organization nominates, and *every existing mechanism works
with no change at all* — the Query AST, the alert engine, incidents, the timeline, topology
suppression, read auditing.

It is also the framing most monitoring products end up at: the NMS appears in its own
inventory.

**What it costs**, and this is the honest objection: **which tenant**. For a single-tenant
organization — every on-premise deployment, which is the defence and law-enforcement case
that motivated read auditing in the first place — there is exactly one answer and nothing to
choose. For a multi-tenant organization somebody must nominate one, and then only people
with a role on that tenant can see platform sign-ins. That is defensible isolation and it is
also not what every tenant administrator would expect.

**A second cost worth stating:** a `self` resource is a resource, so it appears in the
inventory, in topology, in resource counts and in anything that meters them. That is mostly
correct and is occasionally surprising.

### 2.4 Do nothing, and say so

Sign-ins stay in the organization audit log. They are recorded, attributable, readable, and
carry the address and the reason. What is missing is that nothing *fires* on them.

**What it costs.** The failure M11 §2.4 named stays open: an attack on the monitoring
platform itself is visible only to somebody who goes and looks. SPEC §M0.8's rate limit on
auth endpoints is the control that actually stops blind spraying, so the gap is narrower
than it sounds — but "narrower than it sounds" is not "closed".

---

## 3. What this document recommends, and what would change it

**§2.3, the installation as a resource, and only for organizations with one tenant to
start.** The reasoning:

1. It reuses everything. No new scope type, no new store, no second evaluation path, no
   schema change to `events`. The work is a resource, a writer, and a decision about which
   tenant — and for the deployment shape that matters most, that decision is automatic.
2. It is true. A sign-in to this installation *is* an event about this installation, and
   the installation is a thing the product can legitimately hold a resource for.
3. It degrades honestly. A multi-tenant organization that nominates no platform tenant gets
   exactly what it has today — audit rows and no detection — rather than something wrong.

**What would change the recommendation:** a second need for organization-level telemetry.
Collector health across an organization, entitlement counts, cross-tenant capacity — if any
of those arrives, §2.2 stops being a lot of structure for one question and becomes the
right shape, and building §2.3 first would be work to undo.

**What is explicitly not recommended** is §2.1. It is the cheapest to build and the only one
that makes the product state something false.

---

## 4. The decisions that came with it

Written down because they are the ones that otherwise get decided by accident.

**The `self` resource is created, not discovered.** Identity resolution exists to work out
what a thing is from what it says about itself; the installation does not need to be
guessed at. It is created at first run, beside the administrator — one more row in the
transaction that already creates the organization, the tenant and the first user.

**It is not pollable and not a runbook target.** It has no `mgmt_ip`, which is what makes a
resource pollable (`pollable_devices` joins on it) and what a runbook step needs to reach
one. That falls out of the existing schema rather than needing a rule, and it is the right
answer: a product that could be told to SSH into itself is a product with a new class of
mistake available to it.

**Sign-ins are not the only thing it would carry.** Once the resource exists, the obvious
next events are the ones the product already knows and does not surface: a collector that
stopped heartbeating (M12 §2.3 has the data and a screen, and no alert), a lease that
changed hands, a runbook run that failed. Each is a thing an operator currently finds by
looking. **That is the argument for doing this at all** — the sign-in detection is one
instance, and on its own it does not justify the work.

> **Built, and so are all three.** The resource carries sign-ins, and
> `uops-platform-events` observes the other three: a collector that stopped heartbeating, a
> lease that changed hands, a runbook run that failed. One elected observer per deployment,
> held by a PostgreSQL session advisory lock, on a thirty-second tick.
>
> The observer reads current state every tick and asks what of it is *news* —
> `crates/uops-platform-events/src/seen.rs` is where that question lives, and is the only
> part of this that can be tested without a database. The three facts remember differently on
> purpose: a collector that is quiet now is a true statement about the present, so a fresh
> observer reports it; a lease holder read at startup is not a handover, so the first
> observation of each job is recorded silently. The cost is that a restart re-announces
> currently-quiet collectors and failures from the last ten minutes, because the memory is
> in the process and not in ClickHouse.

**Three of these were worth writing down.** The first draft pruned its "already reported"
memory once per organization rather than once per tick, so on any installation with two
organizations each one's prune deleted the other's memory and both collectors were
re-reported every thirty seconds, forever. It is invisible on the single-organization case
anyone checks by hand. `seen.rs` keeps that as a test — the wrong order, asserted to
misbehave — because the right order and the wrong one are indistinguishable by reading.

The second was worse and is the more useful lesson. Both new readers aliased their columns
`AS "org: OrgId"`, which is an instruction to the `query!` *macro* and means nothing in an
unchecked `sqlx::query`: the column comes back named `org: OrgId` literally, and every
`try_get("org")` raised `ColumnNotFound`. So the observer logged *"could not read platform
targets"* once per tick and emitted nothing at all. The failure was handled, reported and
total, and no amount of reading the code would have shown it. It was found by writing the
first test that asked for a row back. Both readers are now `sqlx::query!`, which is what the
workspace uses everywhere else and what would have rejected the alias at compile time.

The third was found by the same test, from its clock rather than its assertion.
`emit_to_all` looped and inserted one row per organization, so the deployment-wide test took
**492 seconds** against a development database holding several thousand of them — which is
what a lease handover would have cost a real multi-tenant installation, in thousands of
single-row inserts into a column store whose worst case is exactly that. A deployment-wide
event is by definition the same statement about every organization, so it is now one insert:
0.60 seconds. Worth naming because nothing about the loop looked wrong, and no assertion
would ever have failed — the only symptom was a number in the test output.

**An organization created after first run gets none of this, and that is still open.**
`bootstrap` nominates the installation resource inline because it must be atomic with
creating the organization; migration 0027 backfilled the ones that already existed. Neither
covers an organization added later: it has no nominated resource, no route to acquire one,
and so receives no self-events while looking no different from any other.
`PgStore::nominate_platform_tenant` is the function that would serve it and has no caller
outside tests — found by `scripts/unreached.py`, which is the seventh instance of that shape.
It is recorded here rather than fixed with a route nobody asked for.

**The detections are not shipped.** M11 §1's line holds: a detection library is a content
business. The product ships a `self` resource and the *events*; an organization writes the
rule that says how many failures in how long matter to it. The test that proves a detection
can fire writes its own rule for that reason.

**The product does give its own events a severity**, which M11 §2.8 forbids for a message a
device sent — and the two are not in tension. §2.8 refuses to invent a severity for
somebody else's message; this is the product describing a thing it did itself, where it is
the authority. A failed sign-in is `warn` because it is ordinary. There is no level meaning
"alarming", because how alarming depends on how many, and that is a rule's business.

---

## 5. What this is not

**Not an APM of itself.** No self-instrumentation, no internal metrics pipeline, no
`uops_requests_total`. Those are a different and much larger thing, and a product that
spends its telemetry budget on itself has misplaced it.

**Not a milestone.** PLAN §10 has M13 as AI and calls M5 onward *direction, not
commitments*. This is smaller than a milestone and should stay that way; if it grows past a
resource, a writer and a nominated tenant, that growth is the signal that §2.2 was the right
answer after all.
