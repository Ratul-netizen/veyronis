# M12 — Enterprise

PLAN §10: *multi-tenancy features · SSO · distributed collectors · HA · MSP*.

Written before anything is built, the way every milestone since M5 has been. This one
differs from the others in a way worth stating first: **most of it is not a feature.**

M5 through M9 each added a capability the product did not have. M12 mostly makes
capabilities it *already has* survive contact with an organisation that has a change
board, an identity provider, a procurement team and an auditor. The work is less about
new screens than about the sentence *"and what happens when that machine dies"* having an
answer.

---

## 1. What "enterprise grade" actually means here

Four things, and only one of them is a feature list.

**It survives losing a process.** Today it does not. `uops-poller`, `uops-alert` and
`uops-sweeper` each assume they are the only instance, and two of any of them against one
database is not a degraded mode — it is double the SNMP load on a customer's fleet,
duplicate samples in `metrics`, and two notifications for one alert. That is §2.1, it is a
correctness bug rather than a missing feature, and it blocks everything else in this
milestone: distributed collectors, rolling upgrades and HA all presume you can run two of
something.

**It authenticates the way the organisation already does.** A product that asks a
2 000-person company to keep a second password list is a product their identity team will
refuse. §2.2.

**It can be operated by somebody who did not build it.** A documented deployment, a
*tested* restore, an upgrade with a rollback, and a way to see whether the product itself
is healthy. §2.4. The launch brief's phrasing is the one to keep: the supportable unit is
not a container image, it is a documented deployment plus an upgrade and recovery story.

**It can be bought.** Security overview, data-flow statement, subprocessor list, SBOM,
vulnerability disclosure. §2.5. None of that is code, all of it is a gate, and the repo
already has the substance — what it lacks is any of it in a form a procurement team can
read.

### What this milestone deliberately does not chase

**A number of nines.** An availability target is a promise about an operations team that
does not exist yet. The honest claim at the end of M12 is *"no component is a single point
of failure, and here is the measured recovery time"*, which is a fact rather than a
commitment.

**Active-active across regions.** A second region is a data-residency decision
(§2.3) before it is an engineering one, and PLAN's deployment model makes the customer's
own environment first-class — so the first HA story is two of everything in one place.

---

## 2. Decisions

### 2.1 Every background process takes a lease, and the lease lives in PostgreSQL.

The three schedulers — poll, alert evaluation, discovery sweep — each need exactly one
owner at a time. The mechanism is the same for all three because the problem is:

```sql
lease(name, holder, expires_at)   -- one row per job, taken by UPDATE … WHERE expired
```

**PostgreSQL rather than a consensus system.** The control plane is already a hard
dependency of every one of these processes — none of them can do useful work without it —
so a lease there adds no new failure mode. Adding etcd or Consul to get leader election
would mean a second thing that can be down, and a second thing an on-premise customer has
to operate, for a guarantee the database already provides through a row lock.

**Leases expire; they are not released.** A process that crashes cannot release anything,
and a lease that needs releasing turns a crash into a stuck estate. The holder renews
while it works and the lease lapses on its own if it stops — so the worst case is a gap of
one lease period rather than an outage that needs a human.

**The period is 30 seconds, renewed every 10.** Three renewals per period, so two
consecutive failures do not lose the lease. The cost of losing one is one skipped cycle,
which the next holder picks up; the cost of two processes believing they hold it is the
double-poll this exists to prevent, so the asymmetry decides the ratio.

**A lost lease stops work immediately.** A process that notices it no longer holds one
finishes nothing in flight and waits — it does not "finish the current cycle politely",
because the whole point is that somebody else is already doing that cycle.

### 2.2 SSO is OIDC, and local passwords stay.

**OIDC rather than SAML first.** Every identity provider an enterprise is likely to have —
Entra ID, Okta, Google Workspace, Keycloak — speaks it; the libraries are smaller; and the
protocol is JSON and HTTP rather than signed XML, which is a meaningful difference in
attack surface for a product that will be deployed on-premise and patched slowly. SAML is
the second one to add, for the organisations that only have that.

**Local passwords are not removed.** An air-gapped deployment may have no identity
provider at all, and an installation whose IdP is unreachable must still be enterable by
the person fixing it. The rule instead is that a tenant may *require* SSO, which disables
password login for everyone but a named break-glass account whose use is an audit event.

**Group-to-role mapping is configuration, not inference.** The product does not guess that
a group called `network-admins` means `Admin`. An operator maps claims to roles
explicitly, because the alternative is that renaming a group in the IdP silently grants or
removes access here.

**Provisioning is just-in-time, and SCIM is deferred.** A user who authenticates
successfully and maps to a role gets an account on first login. SCIM adds a second write
path into the user table for the benefit of *de*provisioning promptly, which matters and
is not the first thing.

### 2.3 A collector is registered, not configured.

Today every collector reads a YAML file naming its tenants. That is right for one
collector and wrong for forty across nine sites.

**A collector enrols with a token and is issued an identity.** Thereafter it reports what
it is, what it can reach and what it has sent, and the server can see which ones have gone
quiet — a collector that stops is exactly as important as a device that stops, and today
nothing notices.

**Configuration stays local; assignment comes from the server.** Which addresses to bind
and which interfaces to use are properties of where the collector sits, and a server that
pushed those would be a server that can break a collector it cannot reach. Which *tenant*
a collector serves is an assignment, and that comes down.

**No inbound connections to a collector, ever.** The collector dials out over
authenticated TLS. A product that needs a hole punched into a customer's monitoring
segment is a product their security team refuses, and this is also what makes the same
design work for a customer-hosted collector talking to a hosted control plane.

### 2.4 Backup and restore are a tested procedure, not a documented intention.

**The two planes back up differently and must be said separately.** PostgreSQL is small,
mutable and irreplaceable — it holds identity, credentials and every decision. ClickHouse
is large, append-only and *partially* regenerable: telemetry that has aged out is gone,
and telemetry that has not can often be re-sent. Treating them as one "backup story" is
how somebody restores a control plane and discovers the telemetry retention was the part
that mattered.

**A restore that has not been performed is not a backup.** The deliverable is a drill:
restore into a scratch environment, bring the product up against it, and record what was
lost and how long it took. The number that goes in the security overview is the one from
that drill.

**Credentials restore or they do not.** The KEK never enters the database — SPEC §M0.4 —
so a restored control plane without its key material holds sealed credentials nobody can
open. That is the correct behaviour and it has to be written down where an operator will
read it *before* the restore rather than during one.

### 2.5 The evidence a buyer asks for is generated, not written once.

An SBOM, a dependency licence report and a list of what the product talks to are facts
about a build. Anything regenerated per release stays true; anything typed into a document
is true on the day it is typed.

So: the SBOM and licence report come out of CI per release, and the documents that cannot
be generated — the security overview, the data-flow statement, the shared-responsibility
description — are short, dated, and say which release they describe.

**Nothing claims a certification.** ISO 27001 and SOC 2 are organisational, not technical,
and the launch brief is right that claiming either casually is worse than claiming
neither. The wording is what is demonstrably true: documented access control, encryption,
audit logging, tenant isolation enforced by the type system, and adversarial tests for it
in every milestone since M7.

---

## 3. Acceptance criteria

- [ ] Two pollers against one database poll each device **once** — measured by sample
      count, not by inspection
- [ ] Killing the process that holds a lease causes another to take over within one lease
      period, and the gap is one cycle rather than an outage
- [ ] A process that loses its lease stops work in flight rather than finishing its cycle
- [ ] The same lease mechanism is used by the poller, the alert engine and the sweeper —
      one implementation, three callers
- [ ] A user authenticates through an OIDC provider and is provisioned with the role their
      mapped claim grants
- [ ] A tenant that requires SSO refuses password login for everyone except a break-glass
      account, and that account's use is an audit event
- [ ] A collector enrols with a token, appears in an inventory, and is marked quiet when it
      stops reporting
- [ ] No inbound connection to a collector is required for any of it
- [ ] A restore drill is performed and recorded: what was lost, how long it took, and what
      a restored control plane cannot open without its KEK
- [ ] An SBOM and a licence report are produced by CI for a release
- [ ] A security overview exists, is dated, names the release it describes, and claims no
      certification
- [ ] Cross-tenant isolation holds for every new surface, by the same adversarial test
      every milestone since M7 has used

---

## 4. What M12 does not do

**Multi-region.** §1.

**Autoscaling.** The workloads here are scheduled rather than bursty, and a lease that
elects one owner is the opposite problem from horizontal scale-out. Sharding the poll
fleet across holders is a real question and it is the *next* one, not this one.

**A status page.** It belongs to a hosted service, and PLAN's phase ordering puts a
repeatable private deployment before one.

**Billing and metering.** Commercial machinery, not enterprise readiness. A design partner
paying by invoice needs none of it.
