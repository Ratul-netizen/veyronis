# M9 — Incident

SPEC §M9, PLAN §10: *alert grouping · root cause · timeline · **Investigation Workspace***.

M8 answered *which service is slow*. M9 answers the question an operator actually has at
02:00: **what is broken, what else is broken because of it, and what happened just
before.**

Written before anything is built, the way [`M5-discovery.md`](./M5-discovery.md),
[`M7-flow.md`](./M7-flow.md) and [`M8-observability.md`](./M8-observability.md) were. Two
decisions here are the ones that would otherwise be made accidentally by whichever file
was written first — §2.2, what puts two alerts in one incident, and §2.5, whether this
product is allowed to use the words *root cause*.

---

## 1. What M9 is

```text
   alert fires ──▶ grouping ──▶ incident ──▶ investigation
                      │                          ├── timeline: every signal, one axis
                      │                          ├── blast radius: the topology walk
                      │                          └── the candidate, and why
                      └── topology suppression: notify about the cause, not the symptoms
```

**Almost all of it already exists and is doing nothing together.** That has been true of
every milestone since M5 and it is the point of the architecture:

* **Alerts have state, dedup keys and acknowledgement** — M4, `alert_state`, eight routes.
* **The topology is a real graph with a cycle-guarded walk** — M6, `resource_dependents()`,
  written once in M0 precisely so *"M6 and M9 don't each write it"* (SPEC §M0.1).
* **Every telemetry table answers "all signals for resource R in window W" as one
  contiguous range read** — the M0 sort key, chosen for this milestone and measured at
  every scale since. W1 recorded that query at **9 ms over 100M logs**.
* **Maintenance windows exist**, with the occurrence arithmetic and the DST cases tested.

So M9 is not "build correlation". It is: decide what an incident is, group alerts into
one, and finally *spend* the sort key that six milestones have been paying for.

---

## 2. Decisions

### 2.1 An incident is a human's unit of work. An alert is a machine's.

The distinction has to be stated first, because everything else follows from it and the
temptation is to make them the same thing with two names.

An **alert** is a rule's opinion about one resource: it fires and resolves on its own, it
has no memory, and nothing it does requires a person. An **incident** is what somebody is
*working on*. It has an owner, a start and an end that a human may set, and it survives
its alerts — the router stopped flapping at 02:14 and the incident is still open at 09:00
because nobody has decided whether it will come back.

Three consequences, each of which is a thing not to build:

* **Resolving every alert does not close an incident.** It marks it *quiet*. A human
  closes incidents, because closing one is a claim that it is understood.
* **An incident is never created by a human in v0.1.** There is no "raise incident"
  button. If it can be raised by hand it becomes a ticketing system, and this product is
  not a ticketing system — it integrates with one later.
* **An alert belongs to at most one incident.** Not zero — every firing alert lands
  somewhere, even if the somewhere is an incident of one. Not many, because an alert in
  two incidents means two people are working on the same failure without knowing.

### 2.2 Two alerts join one incident when they are **connected in time and in topology**.

This is the decision M9 exists to make, and the one with the most ways to be wrong.

**The rule: an alert joins an existing open incident when it starts within the join
window of that incident's most recent alert, and its resource is within N topology hops
of any resource already in it. Otherwise it opens a new incident of one.**

Time alone is not enough — a busy estate has unrelated failures in the same minute, and
grouping by time produces one enormous incident that is really a clock. Topology alone is
not enough either: two failures on the same switch a week apart are not one incident.

The parameters are deliberately conservative and are written down rather than tuned by
feel:

| | value | why |
|---|---|---|
| join window | **5 minutes** from the incident's last alert | a cascade propagates in seconds; a fresh failure five minutes later is a fresh failure. The window slides, so a genuine cascade of twenty devices stays one incident |
| topology radius | **2 hops** | one hop is the neighbour, two reaches the neighbour's neighbour — an access switch, its distribution switch, and the hosts hanging off it. Three hops on a typical campus reaches most of the estate |
| same rule, many resources | always joins | a threshold rule matching 5 000 resources is one condition, not 5 000 incidents. M4's rate limiter already treats it that way |

**Grouping is computed once, when an alert fires, and never revisited.** A late alert
joins the incident it was connected to at the time. Re-grouping retroactively would mean
an incident someone is reading changes shape underneath them, and merging two incidents a
person is already working on is worse than having two.

### 2.3 No topology, no grouping — and that is the honest default.

An estate with no discovered links is a legitimate deployment: SNMP may be refused, LLDP
may be off, the customer may monitor forty cloud hosts with no L2 between them.

With no edges, the radius rule matches nothing and **every alert becomes an incident of
one**. That is correct, it is what the product knows, and it must not be papered over by
falling back to "group by time" — which would produce confident nonsense exactly where
there is least information.

What the screen does instead is say so: an incident of one, on an estate with no
topology, carries the reason it was not grouped. That is the same posture as flow's `≈`
and M8's `sampled` counts.

### 2.4 Topology suppression notifies about the cause, not the symptoms — and it is the most dangerous thing in this milestone.

SPEC §M4 deferred it here: *"Rate, change, anomaly, correlation and topology suppression
are M9."* The distribution switch dies and forty hosts go silent; forty absence alerts
fire; nobody needs forty notifications.

The mechanism is the grouping rule, one step further: **when an incident already has an
alert on a resource that is upstream of a newly firing alert's resource, the new alert
joins the incident and does not notify.** The alert still fires, is still recorded, and is
still on the timeline. Only the *notification* is suppressed.

**Why this is dangerous, stated plainly.** Suppression is the one feature here that can
cause a missed outage. If the rule is wrong, a genuinely independent failure disappears
into somebody else's incident and nobody is told. So:

* **It suppresses notifications only.** Never the alert, never the record, never the
  screen. An operator looking at the incident sees all forty.
* **It is directional.** Upstream suppresses downstream and never the reverse. If the
  hosts fail first and the switch a minute later, the switch's alert notifies — it is new
  information.
* **It is off by default in v0.1**, per tenant. A feature that can hide an outage earns
  its way on after an operator has seen it group correctly on their own estate.
* **The notification for the cause says what it suppressed**: *"and 39 downstream
  resources"*. A suppression nobody can see is indistinguishable from a bug.

### 2.5 The product says **candidate**, and it says why.

"Root cause" is a claim about causation, and nothing here observes causation. What the
topology observes is *direction*, and what the incident observes is *order*.

So the field is `candidate_resource_id`, the screen says **likely origin**, and it always
shows the two facts it was derived from: this resource is upstream of the others, and its
alert fired first. An operator who disagrees can see exactly what the product thought.

The rule is the simplest one that is defensible: **the resource in the incident with no
other incident resource upstream of it, breaking ties by whichever alerted first.** No
scoring, no weights, no confidence percentage. A number like "87% confident" invites
trust that nothing here has earned — the same reason the identity resolver refuses to
auto-merge on weak evidence and raises a review instead.

When the tie cannot be broken — two disconnected roots, or no topology at all — there is
**no candidate**, and the screen says there is none. An empty field is information.

### 2.6 The timeline is a read, never a stored artifact.

Every signal for the incident's resources across its window, on one axis. This is PLAN §6
and it is the thing the M0 sort key was chosen for:

> every store must answer "all signals for resource R in window W" cheaply — that dictates
> `ORDER BY (tenant_id, resource_id, observed_at)` on every telemetry table, a decision
> that is nearly free now and a full re-ingest later.

It is **N queries through the existing AST**, one per signal, each already a contiguous
range read, merged by timestamp in the caller. Not a materialised "incident timeline"
table, for three reasons: the window moves while the incident is open; the retention of
the signals is not the retention of the incident; and a stored copy is a second truth to
reconcile with the first, which is the mistake §2.6 of M8 refused for the service map.

The consequence to accept: **an incident older than the telemetry it is about will have a
timeline with holes.** `spans` and `flows` keep 7 days; `metrics` 30. An incident from
last month shows its alerts and its logs and says the rest expired. That is honest, and a
stored timeline would only have moved the same problem to ingest time.

### 2.7 Incidents live in PostgreSQL.

They are entities a human owns, edits and acknowledges, with foreign keys to alerts and
resources and an audit trail — every property of the control plane and none of the
telemetry plane's. `ClickHouse` is for immutable observations; an incident is a mutable
opinion.

---

## 3. Schema

```sql
incident                -- the unit of work
incident_alert          -- which alerts are in it, and whether each was suppressed
```

Sketch, to be settled in the migration:

* `incident` — `id`, `tenant_id`, `state` (`open`|`quiet`|`closed`), `severity` (the max
  of its alerts'), `candidate_resource_id` (nullable — §2.5), `started_at`, `last_alert_at`,
  `closed_at`, `closed_by`, `acked_by`, `acked_at`, `summary`.
* `incident_alert` — `(incident_id, alert_state_id)`, `joined_at`, `notified` (false when
  §2.4 suppressed it), `hops_from_candidate`.

`UNIQUE (alert_state_id)` on `incident_alert` is what enforces §2.1's "at most one
incident", in the schema rather than in code.

---

## 4. Acceptance criteria

- [x] A cascade — one switch down, its downstream hosts going silent — produces **one**
      incident, not forty, and the incident names the switch as the candidate
- [x] Two unrelated failures in the same minute produce **two** incidents
- [x] Two failures on the same resource a week apart produce **two** incidents
- [x] An estate with no topology produces an incident per alert, and each says why it was
      not grouped — §2.3, carried from `GroupReason` through the API to the screen
- [~] Topology suppression silences the downstream notification and every suppressed
      alert is still visible on the incident — `suppressed` is on the list row and on the
      API response. **The notification does not yet name what it suppressed**: the count
      reaches the screen but not the notifier's message body
- [~] Suppression is off by default and is a per-tenant column — tested. The **audit
      entry** for switching it on is not written, because no route changes it yet: today
      it is a database update
- [x] A downstream failure followed by an upstream one notifies for the upstream — the
      direction rule, §2.4
- [x] Resolving every alert moves an incident to `quiet` and not to `closed`; only a
      human closes it — §2.1, and closing twice is refused rather than treated as
      idempotent
- [x] The timeline shows metrics, logs, events, states, flows and spans for the incident's
      resources on one axis, and says which signals expired rather than showing a gap —
      `uops_query::timeline`'s `Coverage`, through the API, onto the screen
- [~] The timeline for a one-hour incident over 100M rows is answered from the sort key —
      **measured**: 40 960 rows read against 3 735 552 without the resource predicate, a
      77× reduction across both loaded tracks.
      [`bench/results/m9-timeline-100000000rows.md`](../bench/results/m9-timeline-100000000rows.md).
      W1's 9 ms is **not** beaten: 24 ms per track, because this reads two resources with
      an ordering where W1's Q05 read one without. Same shape, more of it
- [x] Incidents from tenant A are unreachable from tenant B, by the same adversarial test
      every milestone since M7 has used — and the timeline's membership read *is* its
      tenant check, so the two cannot drift apart

---

## 5. What M9 does not do

**Anomaly detection.** SPEC lists rate, change and anomaly rule types alongside
correlation, and they are not this milestone. A grouping engine that is fed by better
rules is still the same grouping engine; building both at once means neither can be
debugged.

**Automated remediation.** M10. An incident that can run a runbook is a different risk
profile — that is the difference between a product that tells you and a product that acts.

**Machine-learned root cause.** §2.5 is deliberately a topology walk and a timestamp. PLAN
§10 puts AI at M13 *"only after the data model and correlation actually work"*, and this
milestone is the correlation it is waiting for.

**Ticketing.** No assignment, no SLA clock, no comment thread. Incidents integrate with
the system that already has those; competing with it is how a monitoring product acquires
a worse Jira.

**A stored timeline.** §2.6.
