# Security overview

**Release:** pre-1.0, development. **Describes commit:** see the footer.
**Last reviewed:** 2026-09-22.

This document describes what this product does today. It is dated and it names the
release it describes, because a security document that does neither is a document nobody
can tell is stale.

---

## What this does not claim

**No certification.** This product holds no ISO 27001 certificate and no SOC 2 report,
and the organisation behind it has not been audited for either.

That is a deliberate statement rather than an omission. Both are *organisational*
certifications — they attest to a company's processes, not to a codebase — and claiming
either casually is worse than claiming neither, because a buyer who discovers the claim is
loose stops believing the rest of the document.

**No penetration test.** No third party has been paid to attack this. The adversarial
testing described below is the authors' own and is in the repository where anybody can
read what it does and does not cover.

**No production deployment history.** This is pre-1.0. Nothing below describes how it has
behaved in somebody's estate, because it has not been in one.

What follows is what is demonstrably true and checkable by reading the code.

---

## Deployment models

Both are first-class, which is a design constraint rather than a marketing position:
buyers include government and defence, for whom on-premise is the only option.

**On-premise.** The customer runs everything: PostgreSQL, ClickHouse, the server and the
collectors. No data leaves their network. No component requires outbound internet access
**except** single sign-on, which by definition talks to their identity provider.

**Hosted.** Not offered yet. The parts of this document that describe a hosted service —
subprocessors, shared responsibility — say so where they apply.

---

## Tenant isolation

The product is multi-tenant, and an MSP running it holds several customers' data in one
database. Isolation is enforced in three places rather than one, because a single
mechanism is a single mistake away from failing:

**1. The type system.** A query against tenant data requires a `TenantScope`, which cannot
be constructed except from an authenticated session with a role on that tenant. There is
exactly one function that produces one — `TenantScope::from_authenticated` — and exactly
one caller, the request extractor. A handler cannot read a customer's data without a
scope, and cannot obtain a scope without having been authorised.

**2. The schema.** Intra-tenant references are composite foreign keys, `(row_id,
tenant_id)`, so a row in one tenant cannot reference a row in another *at the database
level*. `migrations/tests/invariants.sql` asserts this per table — it attempts the
cross-tenant write and requires PostgreSQL to refuse it.

**3. An adversarial test over every endpoint.** `crates/uops-api/tests/isolation.rs` reads
the route table out of the router's own source at compile time and requires every route to
have a declared isolation expectation. A route added without that decision fails the test
before any request is sent. For each one it attempts two attacks: naming another tenant,
and naming your own tenant with another tenant's object id. Both must be indistinguishable
from asking for something that never existed — a 404, never a 403, because a distinct
status confirms the object exists somewhere.

This test has run on every commit since M1 and is extended by every milestone.

---

## Authentication and access control

**Sessions are opaque server-side tokens**, not JWTs, so revocation is a row update rather
than a deny-list. 256 bits of CSPRNG output; only the SHA-256 hash is stored, so a stolen
database backup does not hand the thief live sessions. Two clocks: 12 hours idle, 7 days
absolute.

**Passwords** are hashed with **Argon2id, m=19456 KiB, t=2, p=1**. Parameters travel with
the hash, so the cost can be raised later without invalidating anyone's password, and a
hash written under weaker parameters is upgraded at the next successful login.

**Login is not an oracle.** An unknown address and a wrong password are indistinguishable
in the response *and in how long it takes to produce one*: the handler verifies against a
fixed decoy hash when no user matches, so "no such user" costs what "wrong password"
costs. There is a CI guard that fails the build if that path short-circuits.

**Single sign-on** is OpenID Connect — authorization code with PKCE, RS256/ES256. The
algorithm is a filter over the provider's published keys and never an instruction, so
`alg: none` and HMAC confusion select no key and fail before a signature is examined. The
issuer is compared exactly and the audience is checked, which is the one that matters in a
large organisation: every application behind the same identity provider is signed by the
same key. An organization may require SSO, which disables password login for everyone
except one named break-glass account whose every use is an audit event.

**Roles** are per `(user, tenant)`: viewer, operator, admin. One MSP engineer is admin on
one customer and viewer on another with a single account. Organization-wide settings —
identity providers, group mappings, collector assignment — require admin on *every* tenant
in the organization, because those decisions are about more than one customer.

> **Both halves of that became reachable on 2026-09-24, and this note records what changed.**
> Until then the role model was enforced everywhere it was read — it is what `TenantScope` and
> the isolation tests are built on — and none of it could be *administered*: nothing in the
> product granted or revoked a role, created or disabled a user, or created a second tenant.
> An organization using passwords had one user and every installation had one tenant, so the
> sentence above was true of the schema and false of the product. SSO organizations were
> unaffected, because group mappings did provision users and grant roles.
>
> `docs/user-administration.md` and `docs/tenant-lifecycle.md` record the decisions and what
> they cost. Kept here rather than deleted: a buyer who was told this before that date was told
> something the product did not do, and an overview that quietly starts being true is worth
> less than one that says when it began.

**Group-to-role mapping is configuration, not inference.** Nothing guesses that a group
called `network-admins` means admin. A user whose groups map to nothing authenticates
successfully and is refused, with an audit entry naming the groups they had.

---

## Encryption

**In transit.** The server speaks HTTP and expects TLS to be terminated at a reverse proxy
— which every deployment shape has for certificate management they already have processes
for. The one exception is the outbound OIDC client, which speaks TLS directly because an
identity provider is on the internet rather than behind that proxy; it uses the operating
system's trust store, so a customer's internal certificate authority works without
shipping them a bundle to edit.

Connections to PostgreSQL and ClickHouse do not use TLS. Both are expected to be on a
private network or a Unix socket. Enabling TLS there is a feature flag and a deployment
decision rather than a rewrite, and it is honest to say it is not on today.

**At rest.** Device credentials — SNMPv3 keys, SSH keys, API tokens — are sealed with
**envelope encryption**: a fresh AES-256-GCM data key per credential, wrapped under a
key-encryption key (KEK). The KEK **never enters the database**. Additional authenticated
data binds each ciphertext to its tenant, credential id and version, so a sealed row moved
to another tenant's row fails to decrypt rather than opening.

The consequence, stated plainly: **a database backup does not contain the key material,
and a control plane restored without its KEK holds credentials nobody can open.** The
rows, names and assignments are intact; nothing can be polled. That is the intended
behaviour and it is a test, not a claim — `crates/uops-store-pg/tests/restore.rs`.

Telemetry at rest is not encrypted by this product. It is stored in ClickHouse, and disk
encryption is the deployment's — as it is for PostgreSQL's own data files.

**A CI guard** fails the build if an AEAD or a key-derivation function is called anywhere
outside `uops-secrets`, so the crypto a deployment actually runs is auditable in one
directory.

---

## Audit logging

Two logs, and the second is the one most products leave out:

**`audit_log`** — every mutating call, with actor, action, target, before and after, and
the source address. Since M12 it also carries organization-level events that precede
choosing a tenant: signing in through an identity provider, being refused, changing SSO
configuration, and every use of the break-glass account.

**`access_log`** — every *read* of a credential, a resource detail, or a telemetry query.
Defence and law-enforcement buyers audit who **saw** what, not only who changed it. Query
parameters are not stored — a fingerprint of the query shape is — because the parameters
contain a customer's hostnames and addresses.

Neither log has a foreign key to what it describes, on purpose: deleting a resource, or a
user, must not delete the record of who read or changed it.

The hook is attached to the extractor that produces a `TenantScope`, not to a list of
routes. A handler cannot reach tenant data without being attributed first, so "did we log
that read" is answerable by reading one file rather than every route.

---

## What the product talks to

The complete outbound list. Nothing else is contacted.

| From | To | Why | Required |
|---|---|---|---|
| server | PostgreSQL | control plane | yes |
| server | ClickHouse | telemetry | yes |
| server | identity provider (HTTPS) | SSO discovery, token exchange, signing keys | only if SSO is configured |
| server | webhook URLs you configure | alert notifications | only if configured |
| server | an SMTP smarthost you configure | alert notifications | only if configured |
| poller | your network devices (SNMP, ICMP) | polling | yes, for polling |
| poller | PostgreSQL, ClickHouse | credentials, samples | yes |
| collectors | PostgreSQL, ClickHouse | identity resolution, writes | yes |
| sweeper | your network ranges (ICMP, SNMP) | discovery | only if discovery is on |

**Inbound**, the product listens on: the API/UI port, and whichever syslog, OTLP and flow
ports the collectors are configured to bind. **Nothing ever connects *into* a collector** —
collectors dial out.

**No telemetry is sent to the authors.** There is no phone-home, no usage analytics, no
crash reporting, and no licence check. The product does not contact any host that is not
in the table above.

**Bundled data.** The IEEE OUI registries are embedded in the binary so that MAC-address
vendor lookup needs no network call. They are redistributed widely — Wireshark, nmap and
Debian's `ieee-data` all ship them. IEEE attaches no SPDX identifier and `cargo deny`
checks crate licences rather than embedded data, so nothing in CI is looking at this; it
is a commercial-release item and it is named as one in `STATUS.md`.

---

## Data handling

**What is stored.** Device inventory and identity, network topology, the telemetry you
send (logs, metrics, events, state, flows, traces), user accounts and roles, sealed device
credentials, alert rules and history, dashboards, and the two audit logs.

**Personal data.** This is infrastructure monitoring, so the personal data is the
operators' own: name, email address, and audit entries naming them. Telemetry *may* contain
personal data if your log messages do — the product does not inspect or redact it, and that
is your decision to make at the source.

**Retention** is per signal, set in the ClickHouse schema:

| Signal | Kept for | Why |
|---|---|---|
| State | 1 095 days | a status transition is small and its history is what an availability report reads |
| Log, Event | 365 days | |
| Metric | 30 days raw | rolled up to 5-minute and 1-hour aggregates, which outlive the raw rows |
| Flow, Trace | 7 days | investigation data, and therefore recent |

The aggregates outliving their raw rows is deliberate and has a consequence worth knowing
for restores: rebuilding an aggregate from raw data loses everything older than the raw
retention.

**Deletion.** This paragraph said that deleting a tenant removes its control-plane rows by
cascade. **That was wrong in both halves and is corrected here as of 2026-09-24.** Of the
twenty-seven foreign keys referencing `tenant`, nineteen cascade and eight refuse — the
resource, identifier, relationship, credential, identity-decision, monitoring-profile and
site tables, plus the platform-resource nomination. So a `DELETE` already fails on any tenant
that has ever held a resource, which is every real one. That is deliberate: the cascading
tables hold state the product can derive again, and the refusing tables hold *identity*,
which the product's central claim is about not losing.

Removal is therefore **retirement**, not deletion. Retiring a tenant stops the product
scheduling against it — no polling, no sweeps, no alerting — and keeps everything that says
what the estate was. It is reversible. `docs/tenant-lifecycle.md` records why. Telemetry ages out by the table TTLs above
rather than on demand, and those are not one number: raw flows and spans at 7 days and raw
metrics at 30, but states and the hourly metric rollup at 1 095 — so **up to three years**,
with the aggregates outliving the raw rows they came from. A deletion request covering
telemetry is not a feature today. Saying all of that plainly is better than a sentence that
implied a cascade which does not run.

---

## Shared responsibility

**On-premise — yours:** the hosts, the operating systems, disk encryption, network
segmentation, TLS termination and certificates, database credentials, backups and the
rehearsal of them, the KEK and wherever it lives, patching this product when a release
comes out, and who you give accounts to.

**On-premise — ours:** the code, the schema, the migrations, the dependency licence and
advisory policy, the published SBOM, and telling you when a version has a vulnerability.

**Hosted:** not offered. When it is, this section will say what moves.

---

## Supply chain

Every push runs `cargo deny check advisories bans licenses sources`:

* **Advisories** — the RustSec database, failing on any known vulnerability. There is
  exactly one documented exception, `RUSTSEC-2023-0071` in the `rsa` crate, with the
  argument recorded in `deny.toml`: it is a timing side channel in RSA *private-key*
  operations, this product holds no RSA private key and performs none, and a CI job fails
  the build if a private-key type ever appears.
* **Licences** — an allow-list of permissive licences. Anything outside it fails.
* **Sources** — crates.io only. No git dependencies, no unknown registries.
* **Bans** — a `*` version on a crates.io dependency fails, because it is the opposite of
  a reproducible build.

**An SBOM** (CycloneDX, JSON) and a **dependency licence report** are produced by CI and
attached to every release. As of the commit in the footer: 300 third-party crates across
18 licence expressions, all permissive. The report is generated from `cargo metadata` by
`scripts/licence-report.py` rather than maintained by hand, because a list somebody
maintains is true on the day it is typed.

**The crates are not published.** Every `uops-*` crate is `publish = false` and they depend
on each other by path, so there is no crates.io package anybody could typosquat.

---

## Backup and recovery

Documented and **rehearsed**, not documented alone: `docs/restore-drill.md` records a
restore performed on real PostgreSQL and real ClickHouse, with what came back, what did
not, and how long it took.

The drill found a defect that a written procedure would not have — a restore that silently
doubled every aggregate table while every raw table was exactly right — which is the
argument for rehearsing rather than describing. It is now a CI guard, with a second guard
that requires the defect to reappear when the fix is removed.

The recovery time recorded there is for a developer-scale dataset and says so.

---

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md).

---

## Footer

This document describes the repository at the commit it was last reviewed against. To
check whether it is current:

```bash
git log -1 --format='%h %ci' -- docs/security-overview.md
```

If that commit is far behind `HEAD`, treat the specifics here as indicative and the code
as authoritative.
