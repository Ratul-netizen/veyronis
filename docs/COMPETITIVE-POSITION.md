# Competitive position against Motadata and comparable ITOM platforms

**Prepared:** 23 September 2026
**Status:** research and product-direction note. Not legal, procurement, or investment advice.
**Audience:** the founder, and whoever picks up the roadmap next.
**Method:** repository ground truth read from code and tests on 23 September 2026;
competitor capability read from vendor documentation and analyst listings, accessed
23 September 2026. Marketing claims are labelled separately from documented capability
throughout. Nothing here was validated with a customer — see §7, which is the part that
matters most and is the part not yet done.

> **Amended 23 September 2026 — §1.2, §4 and §5 are superseded by
> [`PRODUCT-STRATEGY.md`](./PRODUCT-STRATEGY.md).** This note framed the choice as *narrow
> versus broad* and recommended declining whole categories. That framing was wrong. The
> governing constraint is not breadth, it is **substrate reuse**: a module is cheap when it
> rides substrate that already exists and ruinous when it needs its own. Read on that axis,
> a product family is a legitimate ambition and most of the "decline" list becomes a
> *sequencing* question instead.
>
> The competitor mapping in §2, the ground-truth table in §3 and the risk list in §6 stand.
> The `STATUS.md` finding in §1.1 stands and is more urgent than this note implied. What
> changed is the recommendation, not the evidence — and the evidence that changed it was
> the ManageEngine research, which this note did not do.

> **This note does not propose an architectural change.** PLAN's sequence and the M-series
> discipline stand. Its recommendations are additions inside the existing architecture, and
> where a gap would require a second architecture the recommendation is to decline it.

---

## 1. Executive summary

**Five findings.**

1. **The assessment that prompted this understated the product, and the repository caused
   that.** `STATUS.md` was last updated 2026-09-22 and still describes M10 automation as
   unbuilt and M11 as "direction, not commitments". Both closed since. A reviewer reading
   the repo's own status file will conclude the runner, the runbook API and the runbook
   screens do not exist. They do, with 1 648 passing tests. **Fixing `STATUS.md` is the
   cheapest competitive action available and should happen before any outside party reads
   the repo again.**

2. **Veyronis cannot win on breadth and should stop measuring itself that way.** Motadata
   documents dedicated modules for APM, RUM, SLO, NCCM, ITSM, MSP portals and AIOps. A
   solo-founder product reaching feature parity across that surface would be shallow
   everywhere. The screenshot-matching instinct is the single largest scope risk on this
   project, and it is the same risk PLAN §10 and the milestone sequence were written to
   contain.

3. **The genuine differentiator is not a feature, it is deployability and provability.**
   One resource identity across five signals, one query AST, on-premise and air-gap as
   first-class rather than a downgrade, tenant isolation enforced by the type system, a
   restore somebody has actually rehearsed, read auditing — **which the product could not
   show anybody until 24 September 2026, see `PRODUCT-STRATEGY.md` §15** — and runbook
   automation that is
   typed, approved, dry-runnable and refuses to invent a rollback. For a regulated,
   air-gapped or sovereignty-constrained buyer that combination is rare; for a mid-market
   commercial buyer it is close to irrelevant. **The buyer choice is the strategy.**

4. **Three gaps are real and differ sharply in cost.** The trace waterfall needs *no
   backend work at all* (M8 §"A trace waterfall" says so explicitly). NCCM config backup and
   diff is currently "out of scope" — but the M10 runner shipped an approved, audited,
   dry-runnable SSH execution path, which is most of what NCCM needs, and NCCM is the single
   most-expected capability of the network buyer this product targets. SLO is a moderate
   build over an alerting engine that already exists. **RUM, ITSM and patch management are
   different products and should be declined, not deferred politely.**

5. **One criterion is open across M10/M11/M12** — the real-SSH dry run — and the Kali VM
   has `openssh-server` installed but inactive, so it is now closable. It is unrelated to
   positioning but it is the honest answer to "is the product finished to its own standard".

**Recommended position statement:**

> **Veyronis is unified network and infrastructure observability for estates that cannot
> send their telemetry to somebody else's cloud — and that have to prove what they did.**
> Five signals on one resource identity, deployable air-gapped, with isolation, auditing,
> restore and change-control evidence a procurement review can actually check.

This restates rather than replaces the conclusion `INTERNATIONAL-LAUNCH-RESEARCH.md`
reached on 22 September 2026. That is a point in its favour: two independent passes over
different evidence converged.

---

## 2. Competitor map

Access date for all rows: **23 September 2026.** "Documented" means the vendor publishes a
dedicated documentation section. "Marketing" means the claim appears in sales copy without
corresponding documentation that was checked. **Neither means the capability is good** —
depth, reliability and support quality cannot be established from documentation, and are
exactly what a buyer reference call is for.

### 2.1 Motadata (ObserveOps + ServiceOps), Mindarray Systems

| Aspect | Finding | Basis |
|---|---|---|
| Buyer | Mid-market to enterprise IT ops; separate MSP edition | Documented |
| Observability | Metrics, logs (Log Explorer, dynamic parsing), flows (NetFlow/sFlow/jFlow, Sankey), topology, SNMP trap, agent-based with 1s polling | Documented |
| APM / RUM | Both have dedicated documentation sections | Documented |
| SLO | Dedicated documentation section | Documented |
| NCCM | Dedicated documentation section | Documented |
| Automation | Runbooks, "auto-remediation" | Documented (depth unverified) |
| ITSM | Full ServiceOps suite: service desk, change, request; MSP edition with branded portals and per-client SLAs | Documented |
| AI/ML | Anomaly detection, alert correlation, RCA, predictive analytics | **Marketing** — mechanism not established from docs |
| Deployment | On-prem, private cloud, public cloud, hybrid | Documented |
| Pricing | Not public | — |

**Read:** Motadata is a genuinely broad suite and the breadth is real, not vapour. Its
weakest publicly-verifiable claim is AI — "AI-driven anomaly detection" and "predictive
analytics" are stated without documented mechanism, which is the industry norm and is not
an accusation. **Do not compete with the AI claim. Compete with the evidence standard.**

### 2.2 The rest of the field

| Vendor | Shape | Relevance to Veyronis |
|---|---|---|
| **LogicMonitor** | SaaS-first, AI-first, hybrid/agentless breadth, strong MSP story | **Structurally cannot serve air-gapped buyers.** The clearest contrast case. |
| **ScienceLogic (SL1 / Skylar)** | Service-operations, 400+ integrations, topology and business-service modelling, NCCM (Skylar Compliance) | Closest to the "prove the estate" buyer; reviews repeatedly cite complexity and tuning burden — an opening for a product that is simpler to stand up |
| **Zabbix** | Free, open-source, self-hosted, very large installed base | **The real incumbent in air-gapped estates.** Beating it needs correlation and investigation quality, not feature count; its documented weaknesses are UI, reporting and non-expert usability |
| **ManageEngine / rConfig / Infraon** | NCCM-centric point tools | Define the buyer's expectation of what config management means |
| **Datadog / Grafana stack** | Cloud-native observability; Prometheus+Grafana+Loki is the default air-gapped answer today | The incumbent Veyronis actually displaces in disconnected estates — and it is an *assembly*, not a product, which is the wedge |

**The most important competitive fact in this table is not about Motadata.** In air-gapped
and sovereignty-constrained estates the incumbent is Zabbix or a self-assembled
Prometheus/Grafana/Loki stack. Those are the things a Veyronis deal actually replaces.

---

## 3. Capability comparison, from repository ground truth

Read from code and tests on 23 September 2026, not from `STATUS.md`. **Shipped** means
implemented and covered by tests.

| Area | Veyronis | Motadata | Note |
|---|---|---|---|
| Network monitoring, SNMP, availability | **Shipped** | Yes | `uops-snmp`, `uops-poll`, `uops-poller` |
| Discovery | **Shipped** | Yes | `uops-discover`, scheduler |
| Topology | **Shipped** | Yes | plus evidence semantics and a 3D explorer (phases 0–2) |
| Flow (NetFlow/IPFIX/sFlow) | **Shipped** | Yes | `uops-collector-flow` |
| Logs (syslog, OTLP), search, live tail | **Shipped** | Yes | `uops-collector-syslog`, `uops-collector-otlp` |
| Metrics and alerting | **Shipped** | Yes | `uops-alert` |
| Incident grouping, suppression, timeline | **Shipped** | Partial | topology-aware suppression is a real strength |
| Traces, service map, service aggregates | **Shipped** | Yes | backend complete |
| **Trace waterfall screen** | **Absent (UI only)** | Yes | M8: "needs nothing new from the backend" |
| Security analytics (ECS, detections) | **Shipped** (M11, 12/12) | Partial | ships events and a grammar, **not** a detection library — deliberate |
| Runbook automation | **Shipped** (M10, 12/13) | Yes | typed, approved, dry-run, rollback *offered* not performed |
| **NCCM config backup / diff** | **Absent, "out of scope"** | **Documented** | ← largest true gap for the target buyer |
| **SLO framework** | **Absent** | **Documented** | ← second gap |
| **RUM** | **Absent** | **Documented** | ← decline |
| ITSM / service desk / change | **Absent** | **Documented (full suite)** | ← decline |
| Patch / endpoint management | **Absent** | Yes | ← decline |
| Cloud provider integrations (AWS/Azure/K8s) | **Absent as dedicated integrations** | Yes | OTLP gives generic visibility only |
| Multi-tenancy | **Shipped**, type-enforced | Yes, with branded MSP portals | Veyronis has isolation; Motadata has the *portal product* |
| SSO / OIDC | **Shipped** | Assumed | plus break-glass and `require SSO` |
| HA / leases / rehearsed restore | **Shipped** | Not established | genuine procurement asset |
| Read auditing | **Shipped** | Not established | genuine procurement asset |
| Self-monitoring | **Shipped** (sign-ins; collector/lease/run events open) | Assumed | |
| AI | **Absent** (M13) | Marketing | do not chase |

**Veyronis's strongest existing advantages**, in order of how hard they are to copy:

1. **One resource identity and one query AST across all five signals.** Competitors that
   grew by acquisition or module cannot retrofit this. It is the architectural bet and it
   held.
2. **Isolation as a type-system property**, not a review convention, with an adversarial
   cross-tenant test over all 68 routes.
3. **Automation with a safety model** — approvals that expire, dry runs that actually
   execute the read-only steps, a rollback that is offered with the honest caveat that it
   can also fail, and a credential path that never reaches a transcript.
4. **A rehearsed restore and buyer-facing evidence.**
5. **Air-gap viability**, including local passwords deliberately retained for estates with
   no reachable IdP.

---

## 4. Recommended position and prioritized roadmap

### Target buyer

**Primary:** operators of multi-vendor network estates that cannot use SaaS monitoring —
defence, government, law enforcement, critical national infrastructure, sovereignty-
constrained enterprises, and the regulated end of finance and healthcare. Secondary: MSPs
serving those customers, who inherit the same constraint.

**Why this buyer:** they are underserved by the SaaS-first field, they currently run Zabbix
or a self-assembled stack, they have budget, procurement rewards exactly the evidence this
product already produces — and they are reachable by a founder without a field sales
organisation.

**Differentiation statement (for a deck, not a website):**

> Everything a SaaS observability platform gives you, in a deployment that never phones
> home — with the isolation, audit, restore and change-control evidence your assessor is
> going to ask for, already built and already tested.

### Near-term (0–90 days) — depth on what is already true

| # | Item | Cost | Why |
|---|---|---|---|
| 1 | **Rewrite `STATUS.md`** to current reality | Hours | It is actively misrepresenting the product to reviewers. Highest ratio on this list. |
| 2 | **Trace waterfall screen** | Small, **UI only** | M8 states it needs nothing from the backend. It closes the most visible APM gap and unlocks the alert → trace → span → log investigation story end to end. |
| 3 | **Close M10's real-SSH criterion** | Small | The VM has `openssh-server`; last open criterion in M10–M12. |
| 4 | **Self-monitoring events** — collector stopped, lease changed hands, runbook run failed | Small–medium | `docs/self-monitoring.md` §4 already names these as the actual justification for the `self` resource. Also a live demo asset: the product noticing its own failure is persuasive. |
| 5 | **Investigation flow polish** (§5) | Medium, UI-weighted | The correlation model is the differentiator and the UI currently under-sells it. |

### Next (90–180 days) — the two gaps worth closing

| # | Item | Cost | Why |
|---|---|---|---|
| 6 | **NCCM: config backup, version history, diff, drift alert** | **Medium — and much cheaper than it looks** | The M10 runner already does approved, audited, credential-safe SSH with dry runs. A config fetch is a read-only runbook; the new work is storage, versioning, diff and a compliance check. Industry sources attribute **70–80% of network outages to manual configuration error**; ScienceLogic, ManageEngine and Infraon all lead with it. For this buyer it is close to table stakes, and it is the one "suite" capability that is a natural extension of what shipped rather than a second product. **This is the single highest-value capability decision on the list.** |
| 7 | **SLO framework** — objectives, error budgets, burn-rate alerts | Medium | Builds on `uops-alert` and existing aggregates; asked for by procurement and by anyone running a service. No new architecture. |

> **Both items change `docs/M10-automation.md`'s "config backup and diff are out of scope".**
> That line was correct when the runner did not exist. Reversing it should be an explicit,
> written amendment in the project's usual style — not a quiet change of mind.

### Defer deliberately (state the reason; do not drift into them)

| Item | Reason |
|---|---|
| **RUM** | Needs a browser agent, a JS SDK, CDN distribution and a different buyer. In air-gapped estates there often *is* no public web app to instrument. Highest dilution risk on the list. |
| **ITSM / service desk / change / request** | A second product with a second buyer and a mature, crowded field. Instead: **integrate** — outbound webhook to ServiceNow/Jira, which is days of work, not quarters. |
| **Patch / endpoint management** | Different product, different agent, different risk profile. |
| **Dedicated AWS/Azure/K8s integrations** | Directly contradicts the air-gapped buyer's reality. Revisit only if the commercial-hybrid buyer is chosen instead — that is a *strategy* change, not a backlog item. |
| **AI / AIOps claims** | M13. Competing on undocumented AI claims means making undocumented AI claims. The credible version is narrow and evidence-backed, and is not urgent. |
| **Branded MSP portal** | Isolation exists; the portal is a packaging project. Only worth it if MSP becomes primary. |

---

## 5. Screen concepts

Five, each marked for whether it needs backend work. This is where the correlation
advantage becomes visible — today the architecture is better than the interface.

### 5.1 Operator landing — "what is wrong and what do I do"
**Purpose:** answer, in one screen, whether anything is wrong, what it affects, and what to do next.
**Components:** estate health with trend; **active incidents ranked by blast radius** (derived from topology, not by count — this is something most competitors cannot do); affected services and sites; recent changes (runbook runs, config changes once §6 exists, maintenance windows); signal-volume sparklines with ingest-gap warnings; "next actions" tied to real permissions.
**Interactions:** every tile is a filter, not a link to a dead end; tenant and site scope pinned in the Context Bar.
**Backend:** mostly existing. Blast-radius ranking needs a topology-weighted ordering — small.

### 5.2 Investigation workspace — alert → resource → topology → signals → incident → runbook
**Purpose:** the differentiator, made literal. One spine, no dead ends, no copy-pasting an ID between screens.
**Components:** a persistent subject (resource or service); a signal switcher over metrics/logs/flows/traces/events **on one time axis**; topology context with upstream cause and downstream suppression shown as evidence; the incident timeline; and — the missing piece — **"act": propose a runbook, dry-run it, show the rendered commands, request approval**.
**Backend:** largely exists. The runbook-from-incident handoff is the new seam.

### 5.3 Trace waterfall — **do this first**
**Purpose:** answer "what was this one request waiting for".
**Components:** span tree with critical path highlighted; per-span attributes; **logs emitted during the span inline**, which `uops_query::correlate` already builds the query for; jump to the resource or service.
**Backend:** **none.** M8 states this explicitly.

### 5.4 Configuration and change — *requires §6*
**Purpose:** what changed, who changed it, and does it still comply.
**Components:** per-device config version history; side-by-side diff with attribution; drift against a baseline; compliance check results; correlation of a config change with the incident that followed it — **which is the screen no point tool can draw**, because they do not hold the telemetry.
**Backend:** the NCCM work in §4. The correlation view is the reason to build it here rather than buy a point tool.

### 5.5 Tenant/estate overview for MSP and multi-site
**Purpose:** one console, many estates, without leaking between them.
**Components:** per-tenant health matrix; cross-tenant incident queue honouring isolation; per-tenant ingest and entitlement counts; a visible scope indicator that makes the current tenant unmistakable.
**Backend:** isolation exists; the aggregate-across-tenants read is genuinely new and must be designed as carefully as the isolation it crosses — closer to `docs/self-monitoring.md`'s organization-scope problem than it first appears.

**Cross-cutting:** every screen needs designed empty, loading, error and *partial* states — "ClickHouse unreachable, control plane fine" is a real state this product can be in, and saying so beats an empty chart. Accessibility per `UI-SPEC.md` §381 (200% zoom, 16px minimum) applies throughout.

---

## 6. Risks and uncertainty, stated plainly

- **No customer has validated any of this.** The buyer segment, the NCCM priority and the
  willingness to pay are inferences from public sources. §7 exists because of that.
- **Competitor depth is unknown.** Documentation sections were checked; product quality was
  not. Motadata's RUM/SLO/NCCM modules may be excellent or thin, and this note cannot say.
- **NCCM is a real build**, not a weekend. The runner reduces it; it does not trivialise it.
  Config parsing across vendors is the classic underestimate.
- **The air-gapped buyer has a long sales cycle** and may demand certifications (Common
  Criteria, FIPS-validated crypto, ITAR handling) that are expensive and slow. This is the
  largest commercial risk in the recommended position and is not an engineering problem.
- **Scope risk is the standing one.** Project memory records that strategy documents have
  twice proposed course changes and the conclusion was twice "keep going". **This document
  should not become the third.** Items 6 and 7 are the only capability additions
  recommended, and both are extensions of shipped systems.
- **Licensing** was not re-reviewed here; the cargo-deny allow-list continues to constrain
  dependency choices (it is why there is no Rust SSH crate), and NCCM work must respect it.

---

## 7. 90-day validation plan

**The purpose is to find out whether §4 is wrong while it is still cheap.**

**Days 1–30 — evidence and interviews.**
Fix `STATUS.md` (day 1). Build the trace waterfall and close the M10 SSH criterion — both
small, both needed for a credible demo. Then **12–15 interviews**, at least 8 with
air-gapped or sovereignty-constrained operators, the rest MSPs. Ask what they run today,
what they have replaced and why, and what their last assessment demanded. **Do not demo in
the first half of the call.**
*Success:* ≥8 completed; ≥5 independently name config/change management as a top-three pain
without prompting; ≥5 confirm SaaS is disqualifying.

**Days 31–60 — prototype and competitive reality-check.**
Prototype the investigation flow (§5.2) and a **clickable, non-functional** NCCM concept
(§5.4). Test with 6–8 of the same people. In parallel, take trials or recorded demos of
Motadata ObserveOps, ScienceLogic SL1 and LogicMonitor, and write down what each does
better — specifically, not defensively.
*Success:* ≥5 of 8 complete an alert→cause investigation unaided; the NCCM concept either
draws strong pull or clearly does not, and either answer is worth the month.

**Days 61–90 — decide, in writing.**
Pilot with 1–2 organisations on real estates. Then write the decision document in the
project's usual style: **build NCCM, or decline it and say why.**
*Success:* ≥1 pilot running on a real estate for ≥2 weeks; a written, dated decision on
NCCM and SLO; explicit written confirmation or rejection of the target-buyer choice.

**Stopping rule, stated in advance:** if fewer than 3 of the air-gapped interviews confirm
SaaS is disqualifying, **the position in §4 is wrong** and the commercial-hybrid buyer
should be reconsidered — which would also reopen the cloud-integration decision. Write that
down before the interviews, not after.

**Explicitly not a reason to build anything:** that a competitor lists it. Every item in §4
is justified by a buyer need or by reuse of something already built, and the deferral list
is deferred for stated reasons rather than by omission.

---

## 8. Sources

Accessed 23 September 2026. Vendor documentation and marketing are the vendors' own claims.

- [Motadata ObserveOps documentation](https://docs.motadata.com/motadata-aiops-docs/) — modules: metrics, logs, flows, agent, SNMP trap, APM, RUM, SLO, NCCM, topology, dashboards, runbooks
- [Motadata ObserveOps platform page](https://www.motadata.com/aiops-platform/)
- [Motadata MSP Edition](https://www.motadata.com/products/msp-edition) — multi-tenant, branded portals, per-client SLAs
- [Motadata brochure (PDF)](https://www.motadata.com/collaterals/motadata-brochure.pdf)
- [Gartner Peer Insights — Motadata ObserveOps](https://www.gartner.com/reviews/product/motadata-observeops)
- [LogicMonitor vs ScienceLogic](https://www.logicmonitor.com/logicmonitor-vs-sciencelogic) — vendor comparison, read as marketing
- [ScienceLogic Skylar Compliance (NCCM)](https://sciencelogic.com/platform/network-configuration-change-management)
- [PeerSpot — LogicMonitor vs ScienceLogic vs Zabbix](https://www.peerspot.com/products/comparisons/logicmonitor_vs_sciencelogic_vs_zabbix)
- [Graylog — where SaaS-only SIEM fails](https://graylog.org/post/the-four-environments-where-saas-only-siem-fails/) — air-gapped architecture constraint
- [F5 — air-gapped networks for government and defense](https://www.f5.com/industries/use-cases/air-gapped-network-for-government-and-defense)
- [rConfig — network device configuration management guide 2026](https://www.rconfig.com/blog/network-device-configuration-management-the-ultimate-guide-for-2026)
- [ManageEngine NCCM](https://www.manageengine.com/network-configuration-manager/network-configuration-and-change-management.html) — config outage statistics, compliance framing

**Repository evidence:** `docs/M8-observability.md` (trace waterfall, backend complete),
`docs/M10-automation.md` (runner shipped; config backup out of scope; one open criterion),
`docs/M11-security.md` (12/12), `docs/M12-enterprise.md` (11 done, 1 standing partial),
`docs/self-monitoring.md` (§4 open items), `crates/uops-api/tests/isolation.rs` (68 routes),
full workspace run 2026-09-23: 1 648 passed, 0 failed.
