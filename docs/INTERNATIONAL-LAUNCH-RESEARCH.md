# International product launch research — working brief for Claude

**Prepared:** 22 September 2026  
**Status:** research and product-direction note; not legal, tax, accounting, trademark, or certification advice.  
**Audience:** Claude (product/engineering collaborator) and the founder.  
**Repository state used:** `STATUS.md` records M0–M8 complete. M9 Incident is in progress: commit `d732038` adds its schema, graph-walk rules, and store layer; the remaining M9 work is the alert-fire engine integration, cross-signal timeline, API/UI, and the full acceptance-test set.

## 1. The decision to make now

Veyronis should not launch as a general-purpose “all-in-one observability platform” or a self-serve Datadog alternative. A solo founder cannot credibly support that promise yet.

Launch it as a focused B2B operational product:

> **Unified network and infrastructure observability for organizations that need private, on-premise, or air-gapped deployment.**

The customer outcome is:

```text
Discover → understand topology → collect telemetry → detect → investigate → respond
```

The differentiator is not “we have dashboards.” It is that SNMP, syslog, OTLP, flows, traces, topology, alerts, and later incidents resolve to a common resource identity and can be investigated together. The current architecture is unusually well aligned with that statement.

Do **not** promise all of the following at launch: universal vendor support, global self-serve SaaS, automatic root-cause certainty, autonomous remediation, SIEM/SOAR replacement, or compliance certification. Those claims create support and procurement obligations before the product and company can sustain them.

## 2. Current maturity: what can be sold and what cannot

### Presently credible

The project already has the technical basis for a controlled pilot:

- Network collection: SNMP, ICMP, discovery, LLDP/CDP/ARP-informed topology, interface/counter monitoring.
- Telemetry: syslog, OTLP logs/metrics/traces, NetFlow v5/v9, IPFIX, and sFlow v5.
- Operations: alert rules, acknowledgements, webhook/SMTP notifications, dashboards, saved queries, maintenance windows, tenant isolation, audited secret access, and resource groups.
- Observability: metrics, logs, flows, traces, service map, and correlation through resource identity.
- Deployment direction: PostgreSQL control plane, ClickHouse telemetry plane, portable on-prem and hosted profiles, no compulsory Internet egress for an air-gapped customer.

The repository records meaningful performance evidence: the M8 trace lookup and service-map measurements at 100M spans, plus prior log/alert/dashboard measurements. Preserve this evidence; pilots and enterprise buyers value demonstrated limits more than broad feature lists.

### Not yet credible as a general commercial promise

- A complete M9 Incident / Investigation Workspace. The grouping foundations are implemented, but the alert-fire engine integration, cross-signal timeline, API/UI, and full end-to-end acceptance evidence remain.
- Mature HA, DR testing, distributed collector management, billing, support tooling, SSO/SAML, and formal customer-facing security evidence.
- Broad vendor integration coverage and a mature monitoring-profile ecosystem.
- A trademark-cleared public name. Keep `uops` as the internal implementation identity until clearance is completed.
- Any claim of ISO/IEC 27001 certification, SOC 2 attestation, or legal compliance without external evidence.

## 3. Competitive landscape: what customers already expect

The competitive lesson is not to reproduce every product. It is to identify the minimum product bar and the unoccupied angle.

### Network / infrastructure operations products

**PRTG** is a useful baseline for a practical NMS. Its current documentation presents SNMP interface counters, flow analysis, Cisco CBQoS, Cisco IP SLA, and a QoS Round Trip sensor for latency, jitter, loss, corruption, and duplication between probes. It also makes an operational constraint explicit: flow collection and active path tests require configuration or probes at the relevant points. Veyronis should be equally candid about measurement scope and sampling.  
Source: [PRTG network-performance documentation](https://www.paessler.com/monitoring/performance/network-performance-test-tool)

**ManageEngine OpManager / NetFlow Analyzer** represents the “integrated NMS plus traffic analysis” buyer expectation: device health, flows, top talkers, applications, IP SLA, QoS/CBQoS reporting, capacity planning, and vendor configuration templates. Its flow add-on supports NetFlow, sFlow, J-Flow, IPFIX, cflowd, rFlow, NetStream, and Cisco NBAR.  
Sources: [traffic analysis](https://www.manageengine.com/network-monitoring/network-traffic-analysis.html), [flow support](https://www.manageengine.com/network-monitoring/netflow-monitoring.html)

**LogicMonitor** demonstrates the current SaaS monitoring expectation for a flow layer: top talkers, endpoints, flows, ports, applications, and QoS across NetFlow, IPFIX, sFlow, JFlow, and NBAR2.  
Source: [LogicMonitor flow monitoring](https://www.logicmonitor.com/support/network-traffic-flow-monitoring-new-ui)

**Datadog Network Device Monitoring** demonstrates the cloud-observability expectation: NetFlow records enriched with device/interface metadata and analysis by device, interface, conversation, ASN, geography, ports, protocols, and flags.  
Source: [Datadog NetFlow monitoring](https://docs.datadoghq.com/network_monitoring/netflow/)

### Full-stack observability products

**Grafana** is a useful reference for the investigation model: metrics detect, logs provide context, traces show the request path, and profiles identify code-level cost. It explicitly presents correlation across signals as necessary for investigation. Veyronis should match the correlation principle, but should not attempt profiling or every Grafana data source before customer demand exists.  
Source: [Grafana telemetry and correlation](https://grafana.com/docs/enterprise-traces/latest/introduction/telemetry/)

**Dynatrace** is the long-term ceiling, not an initial direct competitor. Its differentiator is topology-rich context with causation claims and automation across cloud/application/security data. Veyronis should take the design lesson—topology and context first—but preserve the current, more honest language: *likely origin/candidate*, with stated evidence, rather than unearned automated “root cause.”  
Sources: [Dynatrace topology-aware correlation](https://docs.dynatrace.com/docs/analyze-explore-automate/explorer), [Dynatrace unified observability](https://www.dynatrace.com/news/blog/ai-driven-analytics-and-automation-for-unified-observability/)

### Positioning implication

The defensible near-term category is:

```text
Network + infrastructure visibility
  + flows + topology
  + logs/metrics/traces where available
  + evidence-backed incident investigation
  + private / air-gapped deployment option
```

This is narrower, clearer, and more sellable than “all observability.” It can later expand outward without undoing the architecture.

## 4. QoS: add it, but split monitoring from control

QoS is commercially relevant and fits Veyronis well. It must be implemented in two separately governed layers.

### 4.1 QoS visibility — recommended product scope

Build this first. It is observation, not a production network change:

**Roadmap decision required:** QoS is not in the current M0–M13 sequence. The proposal fits the product, but it must be added deliberately to `PLAN.md` as a new milestone or a bounded extension, rather than silently displacing M10–M13. The natural split is CBQoS/vendor profiles alongside the M2 collection model, DSCP attributes alongside M7 flow, then an explicitly named QoS visibility milestone once a design partner makes the need concrete.

- Interface utilization, errors, discards, and queue drops.
- Service policy / class-map / queue statistics where exposed by SNMP and vendor APIs.
- DSCP/traffic-class distribution from flow records when exporters provide it.
- Per-class bandwidth, top applications/endpoints/conversations, and capacity trend.
- Active path quality: round-trip latency, jitter, packet loss, and optionally MOS where a supported mechanism provides it.
- QoS/SLA alerting: congestion, class drops, jitter/loss thresholds, policy mismatch, and sustained saturation.
- Correlation: affected interfaces, flows, resources, services, and topology path in one investigation.

PRTG’s implementation is a practical benchmark: it separates passive SNMP/flow visibility from active QoS path tests and Cisco IP SLA. It also states that sFlow is sampled and therefore approximate. Veyronis already uses an approximation mark for flow; retain that semantic in all sampled QoS views.  
Source: [PRTG flow and QoS details](https://www.paessler.com/monitoring/performance/network-performance-test-tool)

### 4.2 QoS control — later, M10-class automation only

Never treat a QoS policy change as ordinary monitoring. A bad queue policy can degrade or isolate a customer’s production traffic.

Required control path:

```text
Proposed policy change
→ explicit customer authorization
→ RBAC and (later) two-person approval where required
→ maintenance/change window
→ provider-specific execution
→ read-back verification
→ immutable audit event
→ rollback path
```

Initial product language must say **“monitor QoS policy and service quality.”** Do not market “automatic QoS optimization” until the authorization, verification, audit, and rollback system is built and tested with real customer equipment.

### 4.3 Suggested engineering sequence

1. Cisco CBQoS / service-policy monitoring profile and normalized queue/class schema.
2. Generic interface discards/errors/utilization and clear evidence labels.
3. IP SLA / active-probe abstraction with source and target identity.
4. DSCP/class attributes in the existing flow model only when actually exported.
5. QoS dashboards and alert templates.
6. Cross-vendor profiles after real customer demand: Juniper, Fortinet, Aruba/HPE, MikroTik, Huawei, etc.
7. Only then: controlled configuration providers in M10.

## 5. Solo-founder launch model

### Phase A — design-partner pilot, not public self-serve

Secure 3–5 design partners before a broad public launch. Ideal early organizations have 50–1,000 monitored resources, multi-site networks, operational pain, and a person able to give weekly product feedback. Examples include MSPs, ISPs, manufacturers, universities, healthcare groups, financial institutions, and multi-site enterprises.

Each pilot needs a written scope:

- Monitored assets, sites, telemetry sources, and explicitly excluded systems.
- Deployment model: customer-controlled private deployment is preferable for sensitive early environments.
- Support hours, response targets, named customer administrators, and escalation contacts.
- Data residency, retention, backup responsibility, and exit/deletion process.
- Pilot duration, commercial fee or discount, and success criteria.
- Permission (or not) to produce an anonymized case study.

Do not offer free, unlimited “enterprise trials.” A pilot must produce either revenue, reference value, validated requirements, or all three.

### Phase B — a repeatable private deployment

Before public SaaS, make one deployment path repeatable:

```text
Customer environment
  ├─ Veyronis control/data plane OR approved private cloud account
  ├─ customer-local collector(s)
  └─ documented backup, update, recovery, and support procedure
```

The supportable unit is not a container image; it is a documented deployment plus an upgrade/rollback and recovery story. A solo founder should decline a deployment that requires an undocumented special case.

### Phase C — carefully bounded hosted service

Offer hosted SaaS only after repeatable onboarding, logs/metrics for the product itself, backup restores, tenant isolation tests, status communications, and a defined support process exist. Customer networks should use outbound authenticated TLS from a customer-local collector to an ingestion endpoint; do not require broad inbound access from Veyronis Cloud into customer networks.

### Pricing structure

Use simple, predictable annual pricing:

- base platform fee;
- monitored-resource band;
- included retention/telemetry allowance;
- onboarding or professional-services fee;
- later: premium support, long retention, HA/private/air-gapped deployment, and enterprise identity features.

Avoid early per-event pricing, complicated feature gates, and “unlimited” plans. Those are difficult to explain and dangerous for a product whose telemetry cost can vary widely.

## 6. International company, payments, and brand: required decisions

### Company and tax

Establish a legal entity and a business bank account before accepting substantial customer payments. Use a Bangladesh lawyer/accountant who understands exported software and SaaS revenue; this note is not a substitute for local advice. Bangladesh currently publishes IT/ITES export incentives, including a stated 6% export subsidy for software, ITES, and hardware for FY 2026–27, subject to applicable rules and eligibility.  
Source: [Invest Bangladesh IT/ITES sector page](https://investbangladesh.gov.bd/investment-sector/it-it-enabled-services)

Do not choose a tax, VAT, export-registration, or payment structure from generic Internet guidance. Confirm the facts for the actual entity, products, locations of customers, contract terms, and foreign-currency settlement.

### Payments

Do not design billing around Stripe as the only route: Bangladesh is not listed in Stripe’s current supported-country list. A lawful payment provider and settlement path needs to be chosen with local professional advice before promising card subscriptions.  
Source: [Stripe global availability](https://stripe.com/global)

For early enterprise customers, invoices and bank transfer are often simpler and more appropriate than self-serve card billing. This also allows annual contracts and implementation fees while pricing is being learned.

### Brand and trademark

Treat `Veyronis` as a temporary working name until professional clearance. The public name must be screened for confusingly similar marks and company/domain use in the actual intended markets, not merely searched once on the web. Bangladesh’s official DPDT search is one required part of that process; it is not global legal clearance.  
Source: [DPDT trademark search](https://dpdtbd.com/search)

Keep `uops` in code until the decision passes clearance, as the repository strategy already states. A premature repository-wide rename creates operational risk around databases, secrets, images, volumes, and published identifiers without increasing customer value.

## 7. International privacy and data-residency baseline

Veyronis will often process personal data even though it is an infrastructure product. Logs and telemetry can contain user names, email addresses, IP addresses, device identifiers, locations, URLs, authentication events, and application payloads. Treat the customer as the usual controller and Veyronis as processor only where the contractual and factual roles support that conclusion.

### Product requirements now

- Tenant isolation by construction and adversarial tests for cross-tenant access.
- Encryption in transit and at rest; secrets never written to ordinary logs or responses.
- RBAC, read access audit trails, administrative audit trails, and a support-access procedure.
- Configurable retention; documented deletion and export process.
- Region/deployment disclosure: exactly where telemetry, backups, support access, and subprocessors are located.
- Data minimization/redaction options for logs and telemetry.
- Incident response, breach escalation, backup restore, and vulnerability disclosure processes.
- No hidden analytics/telemetry or compulsory Internet egress in air-gapped mode.

### Contract package before pilot

- Pilot agreement / order form.
- Terms of Service or master SaaS agreement.
- Data Processing Agreement (DPA).
- Security addendum and shared-responsibility description.
- Service-level / support policy that only promises what can be staffed.
- Acceptable use policy.
- Subprocessor list and change-notice process.
- Privacy policy.
- On-prem/agent EULA if software is customer-installed.

The EU GDPR requires appropriate controller–processor arrangements; Article 28 addresses use of processors and their guarantees. The European Commission publishes standard contractual clauses for controller–processor relationships.  
Sources: [GDPR text, Article 28](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679), [European Commission Article 28 SCCs](https://commission.europa.eu/publications/standard-contractual-clauses-controllers-and-processors-eueea_en)

For the UK, the ICO states that controller–processor relationships require written contracts, and gives the expected clauses: instructions, confidentiality, security, subprocessor controls, data-subject rights assistance, end-of-contract deletion/return, and audit information. Cross-border access can itself count as an international transfer, even if data is not copied.  
Sources: [ICO processor contracts](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/guide-to-accountability-and-governance/contracts/), [ICO international transfers](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/a-brief-guide-to-international-transfers/)

**Rule:** do not say “GDPR compliant” or “data-residency compliant” as a blanket claim. State the actual technical facts and have counsel approve the contractual position for each target market.

## 8. ISO, SOC 2, and security maturity — the realistic path

### ISO/IEC 27001:2022

ISO/IEC 27001:2022 is an information-security management system (ISMS) standard. It is not a product-feature checklist and it is not obtained by writing a security policy. ISO describes it as requirements for establishing, implementing, maintaining, and continually improving an ISMS using risk management. An organization may implement it before pursuing certification.  
Source: [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)

For a solo founder, the correct sequence is:

```text
Build evidence and operating discipline
→ implement an ISO-aligned ISMS
→ run it long enough to create evidence
→ obtain an independent readiness assessment if commercially justified
→ pursue certification only when buyer demand/revenue supports it
```

Do not claim “ISO compliant,” “ISO certified,” or “ISO ready” casually. Until a defined ISMS exists, say only what is demonstrably true: for example, “we operate documented access control, encryption, audit logging, secure-development, and incident-response controls.”

### SOC 2

SOC 2 is an attestation engagement, not a generic security badge. The AICPA SOC 2 materials cover controls relevant to Security, Availability, Processing Integrity, Confidentiality, and Privacy. Start with Security; add other criteria only when the service and customer commitments justify them.  
Source: [AICPA SOC suite](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)

Avoid a SOC 2 audit until the company has stable policies, systems, staff responsibilities, and enough operating evidence. A Type I report assesses controls at a point in time; Type II evaluates operation over a period. An early audit before controls are real is expensive theater.

### Practical security baseline: NIST CSF 2.0

Use NIST CSF 2.0 as the operational organizing model while small. It is designed for organizations of all sizes and has six functions: **Govern, Identify, Protect, Detect, Respond, Recover**.  
Source: [NIST CSF 2.0 release](https://www.nist.gov/news-events/news/2024/02/nist-releases-version-20-landmark-cybersecurity-framework)

Build a small but real control set:

1. **Govern:** named security owner, risk register, policy inventory, vendor/subprocessor register, customer commitment register.
2. **Identify:** asset inventory, data-flow map, classification of customer telemetry, threat model, dependency inventory/SBOM.
3. **Protect:** MFA, least privilege, secrets management, secure defaults, encrypted backups, CI access control, signed releases.
4. **Detect:** application/administrative audit logging, alerting on suspicious access, vulnerability monitoring, customer notification workflow.
5. **Respond:** incident-response plan, severity model, contact list, tabletop exercise, post-incident review.
6. **Recover:** restore tests, RTO/RPO targets stated per deployment type, disaster-recovery runbook, customer communications.

CISA’s secure-by-design guidance is especially relevant because Veyronis holds powerful customer credentials and may later make authorized network changes. The guiding expectation is to make products secure by default and to put the security burden on the producer rather than on customers.  
Source: [CISA Secure by Demand guide](https://www.cisa.gov/sites/default/files/2024-08/SecureByDemandGuide_080624_508c.pdf)

## 9. Evidence that enterprise buyers will ask for

Create these progressively; do not invent them before the underlying practice exists:

- Security overview / architecture diagram.
- Data-flow and data-residency statement.
- Encryption and key-management statement.
- Authentication, RBAC, audit, and support-access policy.
- Secure-development lifecycle and dependency-management statement.
- SBOM and third-party notices per release.
- Vulnerability-disclosure policy and security contact.
- Incident-response and customer-notification policy.
- Backup, restore, retention, deletion, and disaster-recovery policy.
- Availability status page and historical incident record once SaaS exists.
- Subprocessor list.
- Penetration-test / independent assessment summary only after it has happened.

The repository’s existing secret handling, tenant typing, audit discipline, dependency-license work, and deployment-profile approach are strong foundations. Transform these into repeatable evidence—not marketing claims.

## 10. Engineering constraints Claude should preserve

1. **Resource identity and correlation remain the product core.** Do not add a new telemetry pathway that bypasses the envelope/identity/query-AST model.
2. **Topology evidence must stay explicit.** Never convert weak ARP or sampled flow evidence into a confident physical link without labeling it.
3. **Sampled data stays labeled.** sFlow and sampled traces must not appear equivalent to complete measurement.
4. **“Candidate/likely origin,” not “root cause,”** until the product can establish causation rather than correlation.
5. **No topology means no invented grouping.** M9 correctly makes unrelated alerts separate without graph evidence.
6. **Automation is separate from observation.** M10 actions require authorization, audit, verification, and rollback; no silent device configuration changes.
7. **Air-gapped is a real product profile.** No telemetry phone-home, hidden analytics, or mandatory remote dependency.
8. **Security boundaries are implementation requirements, not enterprise add-ons:** tenant scoping, secret confinement, audit, secure defaults, backups, and release integrity.
9. **Keep scope close to validated customers.** A proposed integration needs a design partner, a commercial reason, or an architecture necessity.

## 11. Recommended roadmap from today

### Next engineering work: complete M9 Incident

The schema, time-plus-topology grouping, suppression-default control, candidate explanation, and store layer are already committed in `d732038`. Complete `docs/M9-incident.md` without broadening it:

- Wire the grouping engine to the alert-fire path.
- Add the cross-signal timeline, queried from the existing stores rather than duplicated into a second truth.
- Add the API/UI and the remaining acceptance tests: cascade, unrelated failures, quiet versus closed, suppression semantics, and tenant isolation.
- Measure timeline performance honestly. The documented ClickHouse VM has 3.8 GB RAM and cannot currently support a trustworthy 100M-row timeline benchmark. Allocate sufficient memory, or measure at a smaller scale and label the result precisely; never report a 10M result as a 100M result.

### Immediately after M9

1. Build one repeatable pilot deployment guide and restore drill.
2. Create a customer-facing security overview based on actual facts.
3. Acquire two design partners; gather their vendor/device/integration requirements.
4. Implement the highest-demand first monitoring profile or QoS visibility slice.
5. Add carefully scoped incident integrations (ticket/webhook) only when a pilot needs them.
6. Begin M10 automation only with approval/audit/rollback foundations, not with “AI remediation.”

### 90-day outcome

The goal is not a worldwide public launch. The goal is:

```text
M9 complete
+ two design partners
+ one repeatable private deployment
+ one tested backup restore
+ one paid or tightly-scoped pilot
+ one anonymized case study or quantified reference outcome
```

That makes an international service product plausible. A public website or a large feature list without these outcomes does not.

## 12. Research sources

All sources below were consulted on 22 September 2026. Product pages describe vendor claims and should be rechecked before being used in public comparison material.

- [Datadog: NetFlow monitoring](https://docs.datadoghq.com/network_monitoring/netflow/)
- [Dynatrace: topology-aware correlation](https://docs.dynatrace.com/docs/analyze-explore-automate/explorer)
- [Grafana: traces and telemetry](https://grafana.com/docs/enterprise-traces/latest/introduction/telemetry/)
- [LogicMonitor: network traffic flow monitoring](https://www.logicmonitor.com/support/network-traffic-flow-monitoring-new-ui)
- [ManageEngine: network traffic analysis](https://www.manageengine.com/network-monitoring/network-traffic-analysis.html)
- [PRTG: network performance, QoS and flows](https://www.paessler.com/monitoring/performance/network-performance-test-tool)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [AICPA: SOC suite](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
- [CISA: Secure by Demand](https://www.cisa.gov/sites/default/files/2024-08/SecureByDemandGuide_080624_508c.pdf)
- [EU GDPR legal text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679)
- [European Commission: controller–processor SCCs](https://commission.europa.eu/publications/standard-contractual-clauses-controllers-and-processors-eueea_en)
- [UK ICO: controller–processor contracts](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/guide-to-accountability-and-governance/contracts/)
- [UK ICO: international-transfer guidance](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/a-brief-guide-to-international-transfers/)
- [Bangladesh DPDT trademark search](https://dpdtbd.com/search)
- [Invest Bangladesh: IT/ITES](https://investbangladesh.gov.bd/investment-sector/it-it-enabled-services)
- [Stripe: global availability](https://stripe.com/global)
