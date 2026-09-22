# M11 — Security analytics

PLAN's one line for this milestone is *"security events · detections · auth/firewall/VPN/DNS
analytics"*, and PLAN §10 calls M5 onward **direction, not commitments**. So the first job
of this document is to decide what the direction actually means here, because the words
"security analytics" name a product category this one is not going to enter.

---

## 1. What this milestone is, and the thing it must not become

**It is not a SIEM.** A SIEM is a content business: a thousand vendor parsers, a detection
library with a release cadence, a threat-intelligence feed, a rules team. Splunk and Sentinel
employ more people on content than this product has on everything. A solo developer who
starts down that road ships a parser library that is out of date on the day it ships, and
the monitoring platform stops being maintained while it happens.

**What this product has that a SIEM does not** is the thing every milestone since M0 has
been arranging: a resolved resource identity, a topology, and one axis to put signals on.
A firewall deny is a row in somebody's log aggregator. A firewall deny *on the interface
that faces the branch office whose link flapped four minutes earlier, from a host this
product already knows is a printer*, is something only this product can say.

So M11 is:

> **The security signals this product already receives, made first-class — and correlated
> with the estate it already understands. Not a detection library.**

### The line, stated so it can be held

| In | Out |
|---|---|
| A typed `events` row with an ECS-shaped category and type | A vendor parser library |
| Normalizing the handful of message shapes the product already ingests | Regex packs per firmware version |
| Detections as *saved queries with a schedule*, reusing M4's rule engine | A detection-as-code DSL and a content release process |
| Auth, firewall, VPN and DNS analytics **over what a device already sends** | An agent that collects Windows Event Log (that is the OTel Collector's job — M3) |
| Correlating a security event with a resource, a site and an incident | Threat intelligence, IOC feeds, reputation scoring |
| Saying *"this is what the device reported"* | Saying *"this is an attack"* |

The last row is the whole posture. This product reports what it observed and what it is
connected to. An assertion that something is malicious is a claim that needs an analyst,
and the value here is in getting the analyst to the evidence in one step rather than in
guessing on their behalf.

### Why it is worth building at all, given that

Three reasons, in order of how much each is worth:

1. **The `events` table has existed since ClickHouse migration 0006 and nothing writes to
   it.** It is queryable, it is in the Query AST, `uops_query::plan` rewrites attributes
   onto its materialised columns, and the product has never put a row in it. That is a
   whole signal type the Investigation Workspace can already display and never shows. M11
   is its first producer.
2. **A firewall is already a monitored resource.** The estate sends syslog; the product
   stores the body as text and knows nothing about it. Extracting the four fields that
   matter — who, from where, to where, allowed or denied — turns a body nobody greps into a
   dimension somebody can group by.
3. **The correlation is free.** Identity resolution, topology and the incident timeline
   already exist. A security event that carries a `resource_id` lands on the same axis as
   the metrics and the traces, with no new machinery.

---

## 2. Decisions

### 2.1 A security event is an `events` row, not a new table.

The table is there, the AST knows it, the timeline reads it. Adding `security_events`
alongside it would mean a second sort key to tune, a second retention policy to explain,
and an Investigation Workspace that has to merge two things that are the same shape.

What M11 adds is a **vocabulary**, not a schema:

```text
event_category   authentication | network | dns | vpn | process | configuration
event_type       start | end | allowed | denied | failure | success | change | query
```

Both columns already exist and are `LowCardinality(String)`. The pairs are
[ECS](https://www.elastic.co/guide/en/ecs/current/ecs-category-field-values-reference.html)'s,
not invented here — a customer who already has ECS-shaped data should not have to learn a
second set of words, and a vendor who ships an ECS mapping should be able to point it here.

**The attribute keys are ECS too**: `source.ip`, `destination.ip`, `destination.port`,
`user.name`, `network.transport`, `dns.question.name`, `event.outcome`. They go in the
existing `attributes` map.

> **The one place this diverges from ECS**, and it matters: ECS has no `resource_id`. This
> product's whole argument is that a signal without a resolved resource is a log line, so
> a security event carries the same `resource_id`, `site_id` and `tenant_id` every other
> row does — resolved by the same identity layer, not by a field in the message.

### 2.2 Normalization is a small, named set of shapes — and the count is the control.

This is the decision the milestone lives or dies on.

The pressure is to write a parser per vendor per product per firmware version. That set is
unbounded, it is somebody else's release schedule, and every entry in it is a regex that
silently stops matching. **A monitoring product with three hundred parsers has three
hundred things that fail quietly.**

So:

* **A fixed, small number of *shapes*, not vendors.** A shape is a message grammar that
  several vendors happen to share — a key-value body (`src=1.2.3.4 dst=5.6.7.8 act=deny`),
  a CEF header, a structured-data RFC 5424 message, a JSON body. Four or five shapes cover
  most of what an enterprise firewall actually emits, and a shape is stable in a way a
  vendor's format is not.
* **A parse that fails leaves the log line alone.** It is still stored, still searchable,
  still on the timeline. Producing *no* event is the correct outcome for an unrecognised
  message, and it must never be a dropped log.
* **The count is a test.** A `const SHAPES` with an asserted length, the same mechanism
  `uops_profile::builtin::all` uses to keep the built-in profiles at five. Adding a sixth
  is a deliberate act with a failing test attached.

> **What this gives up, stated plainly.** A customer with a firewall whose format is not one
> of the shapes gets no security events from it. They get every log line, searchable, as
> they do today. The honest answer to "can you parse our X" is *"not unless it fits a shape
> we already have, and here is the list"* — which is a better answer than a parser written
> against one sample that breaks on their next upgrade.

### 2.3 A detection is a saved query with a schedule. There is no detection language.

M4 built an alert rule: a `Query` AST, a `Condition`, and a `Phase` machine that stops
flapping. A detection is the same thing pointed at `events` instead of `metrics`.

```text
alert rule      avg(value) > 90 for 5m          over metrics
detection       count() > 20 for 5m             over events where event_type = 'failure'
```

That is not a simplification to be undone later — it is the point. Every property M4 and
M9 already have comes with it: `ok → pending → firing` so a burst does not page twice,
maintenance-window suppression, notification budgets, incident grouping, the topology
suppression in M9 §2.4, and an investigation timeline that already knows how to show the
window.

**A detection-as-code DSL would be a second evaluation path**, and PLAN's frozen decision
about the Query AST — *"never a parallel code path"* — applies with full force. Sigma
support, if a customer ever asks for it, is a **translator onto this AST**, exactly as the
text query language is a parser onto it.

> **What a detection cannot express, and why that is acceptable for now.** Sequence — *"a
> failed login, then a success, then an outbound connection"* — is not a threshold over one
> window, and it is what real detections are made of. It is deferred, with the reason in
> §4, and the deferral is honest rather than hidden: M11 ships thresholds and says so.

### 2.4 Failed authentication is counted per *principal and source*, never per resource.

The obvious detection is "more than N failed logins in 5 minutes". Written over a resource
it is useless: a domain controller has hundreds of failures an hour from typos, and the
threshold that catches an attack on one user is far below the noise floor of the server.

So the grouping key is `(user.name, source.ip)` and the interesting shapes are:

* **many failures, one user, one source** — somebody mistyping, or a stuck service account;
* **many failures, many users, one source** — spraying, and the one worth waking up for;
* **many failures, one user, many sources** — a credential in a botnet, or a user whose
  phone is looping.

The product does not name these. It groups by the key and reports the counts, because
"password spraying" is an interpretation and the three shapes above are arithmetic.

**And the product's own sign-ins are the first source.** `audit_log` and the SSO work in
M12 §2.2 already record every authentication against this installation. A security-analytics
milestone whose first detection cannot see attacks on the monitoring platform itself is
one that missed the target closest to it.

> **Amended while building it.** This paragraph assumed a product sign-in could become an
> `events` row like any other. It cannot, and the reason is one this project has already
> met once: **authentication precedes knowing a tenant.** M12 §2.2 discovered it and made
> SSO an *organization* property; the same fact applies here, and `events` is partitioned
> by tenant.
>
> Writing one event row per tenant in the organization would put an organization-level fact
> into N tenant partitions, each copy inviting a tenant-scoped detection to count a sign-in
> that was not against it. So sign-in records go where break-glass sign-ins already go — the
> organization audit log, which is organization-scoped by construction — as
> `auth.sign_in.success` and `auth.sign_in.failure`, with the reason, the address and the
> first parseable forwarded hop.
>
> **The cost is that a detection cannot fire on them**, and that is named rather than
> hidden. The alert engine evaluates a `Query` against `ClickHouse` under a tenant scope,
> and these are `PostgreSQL` rows with no tenant. What is missing is an organization-scoped
> evaluation path, and that is a concrete precondition rather than a vague "later" — the
> same shape M10 §2.8 uses for auto-remediation. Until it exists these are evidence an
> investigator reads, not a trigger.
>
> **An address that resolves to no user is deliberately not recorded.** There is no
> organization to attribute it to, and showing it to *an* organization would tell them about
> an attempt that was not against them — in a hosted deployment, a leak between customers.
> Blind spraying at addresses that do not exist is what SPEC §M0.8's per-IP rate limit on
> auth endpoints is for. This records what can be attributed truthfully, which is less than
> everything.

### 2.5 DNS analytics is the two questions a resolver log can answer, and neither is "is this malicious".

A DNS log is the richest security signal on most networks and the one most often turned
into nonsense. Reputation lookups, DGA scoring and entropy heuristics all require either a
feed this product will not ship (§1) or a model whose false-positive rate nobody here has
measured — which is the argument M10 §2.8 makes about auto-remediation, applied to a
different machine.

The two things a resolver log answers on its own:

* **What resolved, from where, how often.** A frequency table over `dns.question.name`
  grouped by `resource_id`. Volume, not verdict.
* **What failed to resolve.** `NXDOMAIN` in volume from one host is one of the few DNS
  signals that means something without any external knowledge — it is what a piece of
  software looking for a command server that has been taken down does, and it is also what
  a misconfigured search domain does. The product reports the count and says both.

### 2.6 Flow already has the network side of this, and M11 must not rebuild it.

M7 stores flow records with GeoIP. "Which internal host talked to the most external
destinations", "what left the network on a port nobody uses", "which country" — all of
those are flow queries the product can already answer, and none of them needs a security
event.

**M11's contribution to the network side is a join, not a store.** A firewall `denied`
event and a flow record describing the same conversation are two observations of one thing,
and the product knows the resource both are attached to. What is worth building is the
screen that shows them together; what is not worth building is a second copy of flow
analytics with the word "security" on it.

### 2.7 Every read of a security event is already audited, and that is not an accident.

SPEC §M0.8 requires read auditing — *"defence and law-enforcement buyers audit who **saw**
what, not only who changed it"* — and it is Axum middleware over the query and resource
routes, in place since M1.

A security-events screen is exactly the surface that requirement was written for. It needs
no new work, and this section exists to say so: the cost was paid in M1 precisely so that
this milestone would not have to retrofit it. That is what PLAN §0b means by *build the
seams*.

### 2.8 There is no severity of this product's own invention.

A firewall says `deny`. This product records `event.outcome: denied` and the device's own
severity. It does not decide the event is `high`.

Severity on a security event is the single easiest place to manufacture confidence: once a
number is on the row, every screen sorts by it and everybody stops reading the event. A
detection has a severity — because somebody wrote the detection and chose it, and that is
a person's judgement rather than a product's guess — and an event does not.

---

## 3. Acceptance criteria

- [ ] A firewall syslog message in a recognised shape becomes an `events` row with
      `event_category = 'network'`, an `event_type` of `allowed` or `denied`, and
      `source.ip` / `destination.ip` / `destination.port` as attributes
- [ ] A message in **no** recognised shape produces no event, is still stored as a log, and
      is still searchable — verified by a test that asserts the log count is unchanged
- [ ] The number of normalization shapes is asserted by a test, so adding one is deliberate
- [ ] A security event appears on the Investigation Workspace timeline beside the metrics
      and logs for the same resource, on the same axis, with no new timeline code
- [ ] Failed authentications group by `(user.name, source.ip)` and the three shapes in
      §2.4 are distinguishable in the output
- [x] A detection is a saved query with a condition, evaluated by the **same** engine as an
      alert rule — verified by pointing an existing alert rule at `events` and getting a
      firing alert with no new evaluation path
      > `uops-alert/tests/evaluate.rs`. The detection is `cpu_rule` with `SignalType::Metric`
      > changed to `SignalType::Event` and `avg(value)` changed to `count()`. Nothing else
      > moved, and it produces the *identical* phase sequence — pending, firing at the dwell,
      > resolved, quiet — with two notifications over twenty minutes.
      >
      > A second test puts a hundred `allowed` events in the window and requires the rule to
      > stay quiet, because without it the first would pass against a rule with no filter at
      > all: seventy-five events a minute is over the threshold whether or not any of them
      > were denials, and a detection that counts everything is not a detection.
- [ ] A detection firing produces an incident through M9's existing grouping, and topology
      suppression applies to it exactly as it does to any other alert
- [~] Sign-ins against this product itself are a source of authentication events
      > **Recorded, not detectable.** They are `auth.sign_in.success` /
      > `auth.sign_in.failure` in the organization audit log, with the reason, the address
      > and the source hop — see the amendment in §2.4 for why they cannot be `events`
      > rows. A detection over them needs an organization-scoped evaluation path that does
      > not exist, and that is the named precondition.
- [ ] An `NXDOMAIN` frequency table is answerable through the Query AST with no new
      aggregate
- [ ] A firewall `denied` event and the flow record for the same conversation are shown
      together, joined on the resource rather than on a re-parsed address
- [ ] Reading a security event writes an `access_log` entry, by the middleware that has
      been there since M1 — verified, not assumed
- [ ] Cross-tenant isolation holds for every new surface, by the same adversarial test
      every milestone since M7 has used

---

## 4. What M11 does not do

**Sequence detections.** *"A failed login, then a success from the same source, then an
outbound connection"* is what a real detection looks like and it is not a threshold over a
window. Building it means a state machine per rule per entity, with memory bounded by the
number of entities — which is a real engine and deserves a milestone rather than a corner
of this one. §2.3 ships thresholds and says so on the screen.

**Threat intelligence.** No IOC feeds, no reputation, no enrichment from anything outside
the installation. PLAN §0b's air-gap requirement makes a phone-home impossible anyway, and
an offline feed is a subscription this product would be reselling.

**User and entity behaviour analytics.** A baseline per user with a deviation score is a
model whose false-positive rate nobody here has measured, and M10 §2.8's argument applies
unchanged: wiring an unmeasured false-positive rate to anything that wakes somebody up is
how a product teaches its users to ignore it.

**A vendor parser library.** §2.2. The shapes are the commitment; a vendor is not.

**Case management.** An incident is already the product's unit of "something is happening
and somebody owns it" — M9 §2.1, with acknowledgement, closing and a timeline. A separate
security case object would be the same thing with a different noun, and two lists nobody
keeps in step.

**Compliance reporting.** PCI, HIPAA and ISO report packs are a content business with an
audit cycle attached, and PLAN §0b is explicit that pursuing certification is not available
to a solo developer. The evidence generator M12 §2.5 built is what a buyer actually asks
for during evaluation.
