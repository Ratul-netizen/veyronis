# Product strategy — growing into a family, in validated stages

**Prepared:** 23 September 2026
**Status:** product-direction note. Supersedes §4 of
[`COMPETITIVE-POSITION.md`](./COMPETITIVE-POSITION.md), which framed the choice as
*narrow vs broad*. That framing was wrong and this document says why.
**Method:** repository ground truth read from code, tests and migrations on 23 September
2026. Competitor capability read from vendor documentation and review sources, accessed
23 September 2026; marketing claims labelled separately throughout.
**No product code or roadmap file was changed.** Findings that imply a change to
`STATUS.md` or a milestone document are listed in §10 as actions to take, not taken.

---

## 1. The correction that matters most

The earlier note recommended staying narrow and declining whole categories. **That was the
wrong axis.** Narrow-vs-broad is a question about the *destination*, and the destination
was never in doubt — a product family is a legitimate ambition. The real question is about
the *route*, and the route has a governing constraint that has nothing to do with breadth:

> **A module is cheap when it rides substrate that already exists, and ruinous when it
> needs substrate of its own.** Breadth built on shared substrate compounds. Breadth built
> as separate products multiplies cost forever.

That is not a theory. It is the single clearest finding of the competitor research, and it
comes from the company the ambition is modelled on.

### What ManageEngine actually teaches

ManageEngine is the broad-portfolio proof that breadth works commercially. It is *also* the
clearest available warning about how to get there. The consistent criticism in independent
reviews is not that the portfolio is too broad — it is that **each capability lives in a
separate product with its own console, its own licensing and its own learning curve**
([Xurrent](https://www.xurrent.com/blog/manageengine-alternatives),
[Siit](https://www.siit.io/tools/trending/manageengine-review), accessed 23 Sep 2026).

And ManageEngine is now *paying to undo that*. **OpManager Nexus** exists to bundle what
were separately-licensed add-ons — NCM, NetFlow Analyzer, IPAM, Firewall Analyzer and the
Applications Manager plugin — into one licence at a discount
([licensing page](https://www.manageengine.com/it-operations-management/opmanager-plus-licensing.html),
accessed 23 Sep 2026).

**The market is telling us something precise: the portfolio is worth money and the
fragmentation is the cost.** ManageEngine is retrofitting unity onto a family that grew
apart. Veyronis has the unity and does not yet have the family.

> **This is the strategy in one sentence: build the family ManageEngine has, on the
> substrate ManageEngine is paying to retrofit.**

### The fact that should change how you see the current position

Those five OpManager paid add-ons are a good definition of "a complete network operations
product". Against them, checked in this repository today:

| OpManager Nexus add-on | Veyronis |
|---|---|
| NetFlow Analyzer | **Already core** — `uops-collector-flow`, NetFlow/IPFIX/sFlow |
| Applications Manager (APM) | **Already core** — OTLP traces, service map, service aggregates |
| Firewall Analyzer | **Already core** — M11 security analytics, ECS, firewall deny events |
| **NCM** (config management) | **Absent** |
| **IPAM** | **Absent** |

**Three of the five are already in the core product, unbundled and unlicensed separately.**
Veyronis is two modules away from a feature-complete network operations product — and both
of those two turn out to be unusually cheap here (§4).

This is a much stronger position than either the earlier note or the outside assessment
described. It was missed because both read capability lists instead of substrate.

---

## 2. Repository ground truth

Read from code, tests and migrations on 23 September 2026. **Stronger evidence than
`STATUS.md`, which is stale** — it was last updated 2026-09-22 and still describes M10
automation and M11 security as unbuilt. Both have since closed. Correcting it is action 1
in §10; per instruction it has not been edited here.

| Capability | State | Evidence |
|---|---|---|
| SNMP polling, availability | **Implemented** | `uops-snmp`, `uops-poll`, `uops-poller` |
| Discovery (CIDR sweep, ARP, neighbour) | **Implemented** | `uops-discover`, migration 0017 |
| Topology + evidence semantics | **Implemented** | `uops-api/routes/topology.rs` |
| Flow: NetFlow/IPFIX/sFlow | **Implemented** | `uops-collector-flow` |
| Logs: syslog + OTLP, search, live tail | **Implemented** | `uops-collector-syslog`, `-otlp` |
| Metrics + alerting | **Implemented** | `uops-alert` |
| Incidents, topology suppression, timeline | **Implemented** | `uops-incident` |
| Traces, service map | **Implemented (backend)** | `uops-otlp`, `routes/servicemap.rs` |
| **Trace waterfall screen** | **Absent — UI only** | M8: "needs nothing new from the backend" |
| Security analytics (ECS, detections) | **Implemented** | `uops-security`, M11 12/12 |
| Runbook automation (typed, approved, dry-run) | **Implemented** | `uops-runbook`, `uops-runner`, M10 12/13 |
| Multi-tenancy | **Implemented, type-enforced** | `TenantScope`, 68 routes in `isolation.rs` |
| SSO/OIDC + break-glass | **Implemented** | `uops-oidc`, M12 |
| Leases/HA, rehearsed restore, read audit | **Implemented** | M12, `docs/restore-drill.md` |
| Self-monitoring | **Partial** | sign-ins done; collector/lease/run events open |
| **NCCM config backup/diff** | **Absent** — "out of scope" in M10 | — |
| **IPAM** | **Absent** | but see §4: substrate exists |
| **SLO framework** | **Absent** | no code, no doc |
| Cloud/hybrid (AWS/Azure/K8s) | **Absent as integrations** | OTLP gives generic visibility |
| RUM | **Absent** | — |
| ITSM / service desk | **Absent** | — |
| Endpoint / patch | **Absent** | — |
| AI | **Planned (M13)** | PLAN §10 |

**Scale, and the finding that matters for §7:** ~113 000 lines of Rust against
~17 000 lines of TypeScript. **The backend is roughly seven times the front end.** That
ratio is the single most important fact about where this product is weakest, and it is why
UI is treated in this document as product rather than as cleanup.

---

## 3. Buyers, and which one comes first

A product family serves several buyers. It does not serve them all at once, and the
sequencing of *buyers* matters more than the sequencing of features.

| Buyer | Problem | Veyronis fit today |
|---|---|---|
| **Network operations in regulated/disconnected estates** | Multi-vendor estate, no SaaS permitted, must prove what happened | **Strong.** Nearly everything they need exists; NCM is the notable hole |
| **MSP / shared-services** | Many estates, one console, per-client isolation and proof | **Good substrate, no packaging** — isolation exists, branded portal does not |
| **Mid-market general IT** | One tool for everything, cheap, easy | **Weak.** This is Motadata/ManageEngine's home ground; breadth is the entry ticket |
| **Cloud-native platform teams** | Kubernetes, ephemeral workloads, SLOs | **Weak, and a different product.** Datadog/Grafana own it |

**Initial segment: network operations in regulated and disconnected estates, and the MSPs
serving them.** Not because the others are bad, but because this is the one where the
product is already close to complete, where the existing architecture is a *moat* rather
than a detail, and where the incumbent is beatable (§6).

**Product promise for that buyer:**

> One console for the whole estate — discovery, topology, metrics, logs, flows, traces,
> security events, configuration and change — on one resource identity, deployable
> air-gapped, with the isolation, audit and restore evidence your assessor will ask for.

Note that this promise is *already broad*. It is a family promise, not a niche one. What
makes it credible is that every clause names something built or scheduled next, and the
clause that is not yet true — configuration and change — is Stage 1.

---

## 4. The staged family roadmap

Each stage has an **entry gate** (what evidence justifies starting) and names the **shared
substrate** it consumes. A module that would need substrate of its own is not cheap and is
scheduled accordingly — that is the rule from §1, applied.

### The sequencing rule

A candidate module is scored on three axes before it enters a stage:

1. **Evidence** — direct customer demand, not inferred from a competitor's feature list.
2. **Substrate reuse** — what fraction already exists. High reuse means weeks; low reuse
   means a second product.
3. **Marginal support burden** — new agent? new protocol surface? new buyer? new
   compliance obligation? This cost is *permanent* and is the one consistently
   underestimated.

### Stage 0 — now: make what exists buyer-ready

**Not a holding pattern. This is the stage that converts a strong backend into a sellable
product**, and on the 7:1 code ratio it is where the actual gap is.

| Work | Substrate | Cost |
|---|---|---|
| Correct `STATUS.md` | — | hours |
| **Trace waterfall screen** | none needed — M8 says so | small, UI only |
| Role-aware home dashboard (§8.1) | existing queries + `Role` | small–medium |
| Investigation spine (§8.2) | existing correlate/timeline | medium, UI-weighted |
| Close M10's real-SSH criterion | VM has `openssh-server` | small |
| Self-monitoring events (collector/lease/run) | `self` resource, shipped | small |

**Exit gate:** a stranger can be given the product and reach a root cause without a guided
tour, and the demo does not require an apology.

### Stage 1 — network operations completeness (the family's first two modules)

This is where Veyronis becomes a *complete network product* and reaches parity with
OpManager Nexus on its own add-on list.

**1a. NCCM — configuration backup, version history, diff, drift, compliance**

- **Substrate reuse: very high.** The M10 runner already performs approved, audited,
  credential-safe SSH with dry runs and transcripts that never contain the credential. A
  config fetch *is* a read-only runbook. New work is storage, versioning, diff, baseline
  and compliance checks — not device access, not credentials, not scheduling.
- **Evidence to require before building:** ≥5 of the Stage-0 interviews naming config or
  change management unprompted in their top three. Industry sources put 70–80% of network
  outages on manual config error, and ScienceLogic, ManageEngine and Infraon all lead with
  it — but that is *their* evidence, not yours.
- **Why it is strategically special:** it produces the one screen no point tool can draw —
  a config change correlated against the incident that followed it — because the point
  tools do not hold the telemetry. **This is a capability Motadata's separate-module
  architecture makes harder for them than for you.**
- **Note:** reverses `docs/M10-automation.md`'s "config backup and diff are out of scope".
  That line was correct when the runner did not exist. It needs an explicit written
  amendment in the project's usual style.

**1b. IPAM — address inventory, subnet utilisation, conflict and reclaim**

- **Substrate reuse: very high, and this was the surprise of the research.** Discovery
  already performs CIDR sweeps and stores ARP results (IP + MAC); migration 0017 already
  has `cidr[]` columns with `discovery_address_count` and `discovery_widest_prefix`
  functions; `identifier_kind` already types `mgmt_ip`. **The data is largely being
  collected already and thrown away as inventory rather than kept as address space.**
- **Cost:** likely the cheapest module on this entire list. Mostly schema, aggregation and
  a screen.
- **Evidence:** cheap enough that a lower bar is defensible — ≥3 interviews confirming they
  track addresses in a spreadsheet today (which is the common answer).

**Exit gate for Stage 1:** Veyronis answers every question OpManager Nexus answers, in one
console, on one identity, with one licence.

### Stage 2 — choose *one* expansion, on evidence

Do **not** take both. Each doubles a different dimension of cost, and the Stage-0/1
interviews should decide which.

| Option | Substrate | Opens | Cost/risk |
|---|---|---|---|
| **Hybrid/cloud monitoring** (AWS/Azure/K8s) | polling + query AST reuse; **new**: cloud auth, API pagination, cost model | Mid-market and hybrid enterprises | Contradicts the air-gapped buyer's reality; large ongoing API-churn maintenance |
| **SLO framework** | `uops-alert` + existing aggregates; little new | Service-owner buyer, procurement checkboxes | Modest; low differentiation on its own |
| **MSP packaging** (branded portal, per-client reporting) | isolation exists; **new**: cross-tenant aggregate reads, branding | The MSP buyer as primary | Cross-tenant reads must be designed as carefully as isolation itself |

**Recommendation if evidence is ambiguous: SLO first** (cheapest, no new buyer, no new
operational surface), then MSP packaging if MSP interviews are strong, and cloud only if
the segment choice in §3 is being revisited.

### Stage 3 — service management adjacency, integration before imitation

**Integrate first.** An outbound webhook to ServiceNow/Jira/ServiceDesk Plus is days of
work and removes most of the "you don't do ITSM" objection. Build a service desk only if
interviews show buyers would *replace* their ITSM — which is rare, because ITSM is
usually chosen above the network team's pay grade.

**Substrate needed if ever built:** ticketing, workflow engine, SLA timers, approvals
(partly exists in runbooks), a customer portal. **This is the first module on this list
that genuinely needs substrate of its own**, which is exactly why it sits at Stage 3.

### Stage 4 — endpoint and patch management

A different agent, a different risk profile, a different buyer, and a permanent support
burden (an agent on every endpoint is a support channel on every endpoint). Legitimate
long-term; last in sequence. **Not declined — sequenced.**

### AI — a property, not a stage

Motadata's AI claims are marketing-grade: "AI-driven anomaly detection", "predictive
analytics", no documented mechanism. **Do not compete with that by making the same kind of
claim.** Do the narrow, evidential version continuously: baseline-and-deviation on existing
aggregates, correlation ranking for incidents (topology already gives causality most
products must guess at), and natural-language query over the Query AST — which is unusually
well-suited because there is exactly one path to SQL. Ship each with the mechanism written
down. **Topology-backed causality is a better story than "AI RCA" and is defensible.**

### What is *not* recommended at any stage

**RUM.** Needs a browser agent, a JS SDK and CDN distribution, and in disconnected estates
there is frequently no public web app to instrument. Revisit only if the buyer segment
changes. This is a sequencing judgement, not a permanent prohibition.

---

## 5. On-prem and cloud, sustainably

Treat both as first-class deployment options of **one product**, never as two codebases.
The forking of an on-prem and a SaaS build is the most common way a small team's cost
doubles invisibly.

**The rule: one artifact set, configuration-driven; the hosted offering is the same
binaries operated by you.**

Where they genuinely differ, and where the cost actually sits:

| Concern | On-prem / air-gapped | Hosted |
|---|---|---|
| Updates | **Offline bundles**, signed, with checksums; no phone-home | Continuous deploy, your schedule |
| Licensing | Must work with **no callback** | Ordinary entitlement service |
| Secrets | Customer-held; `uops-secrets` envelope already fits | You hold them — larger breach blast radius |
| Identity | IdP may be unreachable → **local passwords must stay** (M12 already decided this) | SSO can be mandatory |
| Tenancy | Often single-tenant | Multi-tenant — noisy-neighbour and quota work is **new** |
| Backup/DR | Customer's; you supply the rehearsed procedure (`restore-drill.md`) | **Yours, contractually** — the biggest new obligation |
| Support access | Often none — diagnostics must be **exportable by the customer** | Direct access |
| Upgrades | Customer-chosen, so **N-2 version support** is a real cost | You control versions |

**Two things to build once and early**, because retrofitting them is expensive:
a **self-contained diagnostic bundle** the customer can export and send (air-gapped support
is impossible without it), and **signed offline update bundles**. Both also improve the
hosted product.

**Candid:** hosting adds an on-call obligation, a DR commitment and a security surface that
a solo team feels immediately. Sequence hosted *after* Stage 1 unless a paying customer
requires it.

---

## 6. Beating Motadata, the broad suites, and the assembled stacks

Three different opponents needing three different arguments. **The product wins on
different ground in each case, and the mistake is using one pitch for all three.**

### Against Motadata specifically

Motadata is the closest competitor: unified observability, five signals, on-prem capable,
plus modules Veyronis lacks. Beating it needs specifics, not a better adjective.

| Ground | The argument | Honest status |
|---|---|---|
| **One identity, one query path** | Motadata's APM, RUM, SLO, NCCM are documented as *modules*. Veyronis's signals share one resource identity and one query AST — correlation is structural, not an integration | **True today.** The strongest claim available |
| **Provable isolation** | Type-enforced tenant scope, adversarial test across all 68 routes | **True today.** Ask them to show theirs |
| **Automation you can put in a change window** | Expiring approvals, dry runs that execute only read-only steps, rollback *offered* with the honest caveat, credentials absent from transcripts | **True today.** "Auto-remediation" is usually a script runner — make the comparison concrete |
| **Evidence for assessors** | Rehearsed restore, read auditing, break-glass, self-monitoring | **True today.** Not established for Motadata |
| **AI** | Their claims lack documented mechanism | **Do not fight here.** Reframe to topology-backed causality |
| **Breadth** | They have RUM, SLO, NCCM, ITSM, MSP portals | **They win today.** Stage 1 closes the two that matter to the network buyer |

**Where Motadata is genuinely ahead: breadth and time in market.** The answer is Stage 1,
not a rebuttal. **Where they are structurally weak: modules integrate; substrate
correlates.** Every quarter they add a module, that gap widens in your favour — provided
you spend those quarters on substrate rather than chasing their list.

### Against broad suites (ManageEngine, ScienceLogic, SolarWinds)

Do not out-feature them. **Out-integrate them.** One console, one query language, one
identity, one install, one licence — against a portfolio the buyer must assemble, learn
and license separately. ManageEngine's own OpManager Nexus bundling concedes the point.
ScienceLogic's reviews concede a related one: complexity and tuning burden.

**The demo that wins:** alert → cause → affected services → the config change that caused
it → the runbook that fixes it, **without leaving the screen or re-entering an ID**. On a
portfolio product that path crosses two or three consoles.

### Against assembled stacks (Zabbix + Prometheus/Grafana/Loki)

**This is the real incumbent in disconnected estates** and the most common thing a Veyronis
deal displaces. It is also the opponent least addressed by feature comparisons.

They have collection, storage and dashboards. **What they do not have, and cannot assemble,
is a shared resource identity.** In that stack a switch is a Zabbix host, a set of
Prometheus labels and a Loki stream, and the joining happens in an engineer's head at 3am.

- **Do not pitch on features.** Pitch on the joins, on the assembly and upgrade cost of
  four projects, and on the evidence an assessor wants that the stack cannot produce
  (per-tenant isolation proof, read audit, rehearsed restore).
- **Respect the price of free.** Never claim they are cheap to run *and* expensive to
  license. The honest argument is total cost of ownership plus capability that is not
  assemblable.
- **Interoperate.** Speak OTLP and Prometheus formats; let them keep Grafana if they want.
  Displacing an entire stack on day one is a harder sale than becoming its correlation
  layer.

---

## 7. UI and dashboard direction — as product, not cleanup

**The 7:1 backend-to-frontend ratio is the finding.** The product's differentiator is
correlation, correlation is experienced entirely through the interface, and the interface
is the thinnest part of the system. **Stage 0 is therefore not a delay before the family —
it is the stage that makes the family sellable.**

**What is already good**, and should not be rebuilt: the navigation IA in
`web/src/layout.tsx` is principled and documented — grouped by the question each section
answers (Network / Observability / Operations), with an explicit rule that *only what
exists* appears. That rule is correct and should survive every stage below. The Context Bar
gives tenant/site/time scope. `UI-SPEC.md` already commits to 200% zoom and a 16px minimum.

**What is missing, in priority order:**

1. **A home.** There is a dashboard screen, but not a *landing* that answers "is anything
   wrong, what does it affect, what do I do".
2. **Role-specific views.** `Role` is `Viewer | Operator | Admin`, ordered and coarse. That
   is enough to vary a home dashboard and should be used before inventing personas.
3. **One investigation spine.** The pieces exist as separate screens; the path between them
   is not a designed flow.
4. **The trace waterfall.** The most visible hole, and pure UI work.
5. **A reserved place for change/configuration.** Stage 1 needs a home in the IA. It
   belongs under Network, as a sibling of Resources — but **not added until it exists**,
   per the file's own rule.
6. **Designed empty, loading, error and *partial* states.** "ClickHouse unreachable,
   control plane healthy" is a state this product can genuinely be in; saying so beats an
   empty chart and is the kind of honesty that sells to this buyer.

**IA as the family grows** — the current three groups scale without restructuring:

```text
Network        Resources · Topology · Discovery · Flow · Map · [Configuration]¹ · [Addresses]²
Observability  Explore · Services · [Traces]³ · [SLOs]⁴
Operations     Incidents · Security · Alerts · Rules · Channels · Collectors · Runbooks · Runs
Dashboards
                    ¹ Stage 1a  ² Stage 1b  ³ Stage 0  ⁴ Stage 2
```

Each stage adds items to existing groups. **No stage requires a new top-level concept,
which is itself evidence the substrate is right.**

---

## 8. Three screen concepts

### 8.1 Operator home — "is anything wrong, and what do I do"

**User need.** The first screen of the shift. Today an operator lands without a summary and
must go looking, which is the single biggest reason the product feels less finished than it
is.

**Content.** Estate health with trend and an explicit *data freshness* indicator (last
ingest per signal — this product can distinguish "nothing is wrong" from "nothing is
arriving", and most cannot). Active incidents **ranked by blast radius derived from
topology**, not by count or severity — this is a capability competitors approximate with
heuristics. Affected services and sites. Recent change: runbook runs, maintenance windows,
and after Stage 1a, config changes. Signal-volume sparklines. "Needs you" — items
actionable by *this* role.

**Interactions.** Every tile is a filter into the investigation spine, never a dead end.
Tenant/site scope from the Context Bar. Role-varied: Viewer sees health and incidents;
Operator adds acknowledge and run; Admin adds collector health, lease state and failed
sign-ins (already available from the self-monitoring work).

**Backend.** Mostly existing queries. **New:** a blast-radius ordering over the topology
graph (small), and a per-signal freshness endpoint (small). **Improvable now: ~80%.**

### 8.2 Investigation spine — alert → resource/service → topology → signals → incident → runbook

**User need.** The differentiator made literal. The correlation model is the product's
strongest asset and is currently experienced as a set of screens the operator navigates
between manually.

**Content.** A persistent **subject** (resource or service) that survives every pivot, so
context is never retyped. A signal switcher over metrics / logs / flows / traces / security
events **on one shared time axis** — the thing an assembled stack cannot do. Topology
context showing upstream cause and downstream suppressed symptoms *as evidence, with the
rule that produced it*. The incident timeline. Then the step that closes the loop:
**"act"** — propose a runbook, dry-run it, show the rendered commands, request approval,
all without leaving the spine.

**Interactions.** Pivots preserve subject and time range. Every suppression is explained,
never silent. A permalink reproduces the exact investigation state — which matters for this
buyer because it is how an incident writeup is evidenced.

**Backend.** Largely exists (`uops_query::correlate`, incident timeline, runbook plan API).
**New:** the incident→runbook handoff seam, and permalink state encoding. **Improvable now:
~70%**, and the remaining 30% is small.

### 8.3 Change and configuration — *requires Stage 1a*

**User need.** "What changed, who changed it, and is it still compliant." The question the
network buyer asks most and the one the product currently cannot answer at all.

**Content.** Per-device config version history. Side-by-side diff with attribution. Drift
against a baseline. Compliance check results (CIS-style rules). And the screen that
justifies building it here rather than buying a point tool: **a config change on one axis
and the incidents, alerts and metric shifts that followed it on the same axis.**

**Interactions.** Diff any two versions; restore proposed as a runbook with the existing
approval and dry-run path — **never a one-click push**, consistent with M10's safety model.
Filter by device, author, compliance state.

**Backend.** **Substantial and mostly new:** config storage and versioning, per-vendor fetch
runbooks, a diff engine (normalisation and secret-redaction are the hard parts), baselines,
a compliance rule model. The *access* path — approved, audited, dry-runnable SSH — already
exists, which is why this is a module rather than a product. **Improvable now: 0%; this is
Stage 1 work.**

---

## 9. Ninety-day validation plan

**Purpose: find out which parts of §4 are wrong while changing them is still cheap.**
Two tracks in parallel — build Stage 0, and gather the evidence that decides Stage 1.

### Days 1–30 — make it demoable, then listen

**Build:** `STATUS.md` correction (day 1); trace waterfall; close M10's SSH criterion;
first cut of the operator home (§8.1).
**Research:** 12–15 interviews — ≥8 regulated/disconnected network operators, ≥4 MSPs. Ask
what they run today, what they have replaced and why, what their last audit demanded, and
how they handle device configs. **Demo only in the last third of the call**; a demo shown
early converts an interview into a sales pitch and destroys the evidence.
**Competitors:** obtain Motadata ObserveOps and ManageEngine OpManager trials; record what
each does better, specifically.

**Gate 1 (day 30) — measurable:**
- ≥8 interviews completed
- ≥5 name config/change management unprompted in their top three → **Stage 1a proceeds**
- ≥3 confirm they track IP addresses in spreadsheets → **Stage 1b proceeds**
- ≥5 confirm SaaS is disqualifying → §3 segment confirmed
- **Stopping criterion:** if <3 confirm SaaS is disqualifying, **§3 is wrong** — reopen the
  segment choice and with it the cloud-integration decision in Stage 2. Written before the
  interviews, not after.

### Days 31–60 — prototype, and test against reality

**Build:** investigation spine (§8.2) to clickable quality; **non-functional** clickable
prototype of Change & Configuration (§8.3) — prototype before building, because the diff
and normalisation work is the expensive part and the layout is not.
**Test:** 6–8 of the same people, task-based, unaided.

**Gate 2 (day 60) — measurable:**
- ≥5 of 8 complete an alert→root-cause task unaided in <10 minutes
- ≥5 of 8 say the Change & Config prototype would change their tooling decision
- ≥2 volunteer for a pilot
- **Stopping criterion:** if <3 find the config prototype compelling, **Stage 1a is
  deprioritised below SLO and MSP packaging**, regardless of what competitors ship.

### Days 61–90 — pilot, then decide in writing

**Run:** 1–2 pilots on real estates, ≥2 weeks each.
**Build:** begin Stage 1a *only if Gate 2 passed*; otherwise Stage 1b (cheap regardless) and
Stage 0 polish.
**Write:** a dated decision document in the project's usual style — the module order, with
reasons, including the ones declined.

**Gate 3 (day 90) — measurable:**
- ≥1 pilot running ≥2 weeks on a real estate
- ≥1 buyer states a price they would pay, unprompted
- A written, dated module-order decision exists
- **Stopping criterion:** zero pilots converting to a stated willingness to pay means the
  *promise* in §3 is wrong, not the features. Revisit the promise before building more.

---

## 10. Candid risks

- **Capacity is the binding constraint, not ideas.** One founder plus an AI collaborator
  maintaining ~113k lines of Rust. Every module is permanent: docs, tests, upgrade paths,
  security surface, support questions, forever. Stage 1's two modules are chosen partly
  because they add almost no *new* operational surface.
- **The polish-versus-modules tension is real and the 7:1 ratio settles it.** Adding Stage 1
  before Stage 0 would produce a broader product that still demos badly. Stage 0 is short —
  weeks, not quarters — and must not be allowed to expand indefinitely either.
- **No customer demand here is proven.** The NCM and IPAM priorities are inferences from
  competitor structure and industry sources. §9's gates exist precisely because those
  inferences may be wrong; do not treat Gate 1 as a formality.
- **NCCM is underestimated by everyone, including this document.** Multi-vendor config
  parsing, normalisation and secret redaction in diffs is the classic swamp. The runner
  reduces it; it does not trivialise it. Budget conservatively.
- **Hosting is a second business.** On-call, DR commitments, a larger breach radius.
  Sequence after Stage 1 unless a paying customer requires it.
- **Certifications may gate the chosen segment** (Common Criteria, FIPS-validated crypto,
  ITAR handling). Slow and expensive, and not an engineering problem. This is the largest
  commercial risk in §3.
- **Licensing constraints persist.** The cargo-deny allow-list continues to shape
  dependency choices (it is why there is no Rust SSH crate); Stage 1 must respect it.
- **This document should not become a course change.** Project memory records that strategy
  documents have twice proposed one and the answer was twice "keep going". Stage 0 is
  existing work finished; Stage 1 is two modules on existing substrate; nothing here alters
  the architecture.

---

## 11. Next three actions

1. **Correct `STATUS.md`** to reflect M10, M11 and the self-monitoring work. It is
   currently misrepresenting the product to every outside reader, and it already has.
2. **Build the trace waterfall screen.** Pure UI, no backend work (M8 states this), closes
   the most visible capability hole, and makes the investigation demo complete.
3. **Start the Stage-0 operator home (§8.1) and book the first five interviews.** Build and
   evidence-gathering run in parallel; neither should wait for the other.

Then Gate 1 decides Stage 1.

---

## 12. Alignment message

To keep implementation work pointed at this strategy:

> Work to `docs/PRODUCT-STRATEGY.md`. We are building a product family in validated
> stages, not staying narrow — but a module only ships when it rides substrate that already
> exists and has direct customer evidence behind it, not because a competitor lists it.
>
> Right now that means Stage 0: finish and polish what exists so it demos without apology.
> The UI is product, not cleanup — the backend is seven times the size of the front end and
> that ratio is the problem to fix. Priorities are the trace waterfall (pure UI), a
> role-aware operator home, and the investigation spine from alert through topology and
> signals to a runbook.
>
> Do not start NCCM, IPAM, SLOs, cloud integrations or ITSM until the Gate 1 interviews in
> §9 say so — and if the evidence says a module is wanted, say which existing substrate it
> reuses before proposing how to build it. Keep the existing rules: decisions documented
> before building, honest amendments when a document turns out wrong, partial criteria
> marked `[~]` rather than ticked, and the sidebar showing only what exists.

---

## 13. Sources

Vendor documentation and marketing are the vendors' own claims; review sites are
third-party opinion. All accessed **23 September 2026**.

- [Motadata ObserveOps documentation](https://docs.motadata.com/motadata-aiops-docs/) — documented modules: metrics, logs, flows, agent, SNMP trap, APM, RUM, SLO, NCCM, topology, dashboards, runbooks
- [Motadata ObserveOps platform page](https://www.motadata.com/aiops-platform/) — AI/ML claims, marketing
- [Motadata MSP Edition](https://www.motadata.com/products/msp-edition) — multi-tenant, branded portals, per-client SLAs
- [Gartner Peer Insights — Motadata ObserveOps](https://www.gartner.com/reviews/product/motadata-observeops)
- [ManageEngine OpManager Nexus licensing](https://www.manageengine.com/it-operations-management/opmanager-plus-licensing.html) — bundles NCM, NetFlow Analyzer, IPAM, Firewall Analyzer, APM plugin
- [ManageEngine OpManager add-ons](https://www.manageengine.com/network-monitoring/opmanager-addons.html)
- [ManageEngine NCCM](https://www.manageengine.com/network-configuration-manager/network-configuration-and-change-management.html) — config-error outage statistics, compliance framing
- [ManageEngine corporate site](https://www.manageengine.com/) — portfolio breadth
- [Xurrent — ManageEngine alternatives](https://www.xurrent.com/blog/manageengine-alternatives) — separate consoles/licensing/learning curve criticism
- [Siit — ManageEngine review](https://www.siit.io/tools/trending/manageengine-review)
- [ScienceLogic Skylar Compliance (NCCM)](https://sciencelogic.com/platform/network-configuration-change-management)
- [PeerSpot — LogicMonitor vs ScienceLogic vs Zabbix](https://www.peerspot.com/products/comparisons/logicmonitor_vs_sciencelogic_vs_zabbix) — complexity and tuning criticism
- [Graylog — where SaaS-only SIEM fails](https://graylog.org/post/the-four-environments-where-saas-only-siem-fails/) — air-gap architectural constraint
- [F5 — air-gapped networks for government and defense](https://www.f5.com/industries/use-cases/air-gapped-network-for-government-and-defense)
- [rConfig — network device configuration management guide 2026](https://www.rconfig.com/blog/network-device-configuration-management-the-ultimate-guide-for-2026)

**Repository evidence (23 Sep 2026):** `web/src/layout.tsx` (navigation IA and its rules),
`crates/uops-core/src/scope.rs` (`Role`), `crates/uops-discover/src/sweep.rs` and
`migrations/0017_discovery_jobs.sql` (CIDR/ARP substrate for IPAM),
`docs/M8-observability.md` (waterfall needs no backend), `docs/M10-automation.md` (runner
shipped; config out of scope; one criterion open), `docs/M11-security.md` (12/12),
`docs/M12-enterprise.md`, `crates/uops-api/tests/isolation.rs` (68 routes); full workspace
run 1 648 passed / 0 failed; ~113k lines Rust vs ~17k lines TypeScript.
