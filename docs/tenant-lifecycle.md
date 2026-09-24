# Tenants, and the second one that cannot exist

**Status:** **built, 2026-09-24.** Migration 0031, `uops_store_pg::tenants`, five routes, and
the Customers screen. Fourteen store tests, nine route tests, fifteen web tests, five guards
mutation-verified. This began as a decision document — the sibling `docs/user-administration.md`
§3 promised — and the decisions below are kept because the reasoning is what makes the result
reviewable. Two of them were wrong and are amended in place rather than quietly corrected.

The only `INSERT INTO tenant` outside tests is `bootstrap.rs:152`, inside
`bootstrap_first_run`, whose whole decision is *"does any user exist"* — so it runs once and
declines forever after. There is no `create_tenant` function anywhere: not in the store, not
in a route, not in a binary, not in a migration or a script. A running installation has
**one** tenant, permanently.

That matters more than the count suggests. `TenantScope` is the isolation guarantee SPEC
§M0.8 says is *"enforced by the type system, not by review"*; every repository takes
`&TenantScope` and a missing filter is a compile error; `crates/uops-api/tests/isolation.rs`
asserts it across all 44 registered route paths; `docs/security-overview.md` sells it as
*"One MSP engineer is admin on one customer and viewer on another with a single account."*
All of that is real and none of it is reachable, because production can only ever have one
side of the boundary.

---

## 1. What is missing, and the large part that is not

**Missing:** a way to create a tenant, a way to stop using one, and the settings surface for
the two per-tenant knobs the table already carries.

**Not missing — and this is why the work is small:** the runtime was built for tenants
appearing at any moment. Every scheduling loop re-reads `PgStore::all_tenant_ids()` on each
turn rather than caching a list at startup — `uops-alert/src/scheduler.rs:157`,
`uops-poller/src/fleet.rs:63`, `uops-sweeper/src/lib.rs:252`, `uops-alert/src/run.rs:358`.
`uops-sweeper`'s own module docs say why:

> The caller supplies the tenants rather than this reading them … the loop asks
> `all_tenant_ids` every turn so a tenant created a minute ago is swept.

So a new tenant needs no restart, no cache invalidation and no fleet reload. Somebody
already thought about this; only the door is absent.

The second thing that is already decided is deletion — see §4.1, where the schema turns out
to have made the choice.

## 2. The lockout, which has to be decided before anything else

`is_org_admin` returns `row.total > 0 && row.held == row.total`: admin on **every** tenant in
the organization. It gates `OrgAdmin`, which gates identity providers, group mappings,
collector assignment — and would gate tenant creation.

**Creating a tenant increases `total`.** An admin who creates one and is not granted a role
on it holds admin on *n* of *n+1* tenants, so `is_org_admin` becomes false and they lose
`OrgAdmin` the instant the insert commits. Nobody else has it either, since nobody has a role
on the new tenant. And because creating a tenant requires `OrgAdmin`, the state cannot be
repaired from inside the product — the fix is a hand-written `INSERT` against production.

A feature whose first successful use locks the organization out of its own settings.

**Decision: the creating administrator is granted `admin` on the new tenant in the same
transaction as the insert, and it is not optional.** Not a checkbox, not a follow-up call —
one statement pair or neither. `granted_by` names them, which is true: they did grant it, to
themselves, by creating the tenant.

This is also the answer to *who administers a brand-new tenant*, which would otherwise need
its own rule.

> The related edge is already handled: `total > 0` means an organization with no tenants has
> no org-admin rather than every user being one. Worth stating because the guard looks
> redundant and is not.

## 3. Creating a tenant

### 3.1 It is an organization-level act, not a tenant-level one

`POST /api/v1/tenants`, behind `OrgAdmin`, with no `X-Tenant` header — there is no tenant for
the request to be *about* yet, and the extractor that demands the header would be the wrong
gate. Audited as `tenant.create` against a `NULL` `tenant_id`, which migration 0024 made
possible for exactly this class of act; `sso.rs`'s comment on it is the precedent:

> writing them against an arbitrary tenant would be a lie, and specifically the kind an
> auditor has to be told about afterwards — which is worse than a gap.

### 3.2 The slug gets a format rule; renaming is allowed

`tenant.slug` has `UNIQUE (org_id, slug)` from migration 0001 and **no format constraint
anywhere** — not in the schema, not in `FirstRunRequest`, not in any validator. First run
takes whatever configuration hands it.

**Decision: lowercase letters, digits and single inner hyphens, 2–63 characters, enforced by
a `CHECK` in the new migration rather than only in the route.** In the schema because the
route is not the only writer — `bootstrap` writes one too, and a rule that lives in one
caller is a rule the other caller breaks.

> **Amended while building it: 2–40 became 2–63.** This said 40, which was taste rather than
> reasoning. Measured against the development database before applying the migration: 15 177
> tenants, none malformed, and **6 818 longer than 40** — fixtures that append a UUID, the
> longest at 51. A migration that refuses rows already in the table is not a migration. 63 is
> the length of a DNS label, which is both comfortably above what is there and the honest
> bound for a string shaped like a hostname component: a slug is the kind of thing that ends
> up in a subdomain or a URL segment, and that is where a real limit comes from.
>
> The rule now exists in three places — `tenant_slug_is_a_label` in migration 0031,
> `check_slug` in the route, and `slugProblem` in the browser. The schema is the one that
> counts; the other two exist so somebody reads a sentence while typing rather than a
> constraint name after submitting.

**Renaming is permitted, for both name and slug.** It would be easy to declare the slug
immutable and call it rigour, but nothing durable references it: the `X-Tenant` header
carries a `TenantId` UUID, `audit_log` and `access_log` key on `tenant_id`, and the slug
reaches the interface only through `/api/v1/me`'s membership list for the tenant switcher.
Inventing immutability here would be the same mistake `user-administration.md` §4.5 refuses —
a rule that reads as a safeguard and protects nothing. The one real dependency is
`scripts/db.sh`, which resets everything whose `slug <> 'default'`; that is a development
script, and it is noted here so that renaming the first tenant does not quietly change what
a reset wipes.

### 3.3 A new tenant inherits nothing, and receives no telemetry until a collector is assigned

`tenant` carries two settings with schema defaults — `notification_budget_per_day` (1000,
`CHECK` 0–100000) and `suppress_downstream_alerts` (false). A new tenant takes those
defaults and copies nothing from any existing tenant. Copying would mean a tenant silently
inheriting another customer's alert budget, and the defaults are the considered values.

`bootstrap` creates no monitoring profile and no notification channel for the first tenant
either, so a bare tenant is a working tenant. **One thing is genuinely required and is not
obvious: a collector must be assigned to the new tenant** (`collector_tenant`, via the
existing `POST /api/v1/collectors/{id}/tenants`) or nothing will ever arrive in it. The
create response names this, and the screen says it in a sentence rather than leaving somebody
to discover an empty tenant an hour later.

**The platform resource is per organization, not per tenant, and stays that way.**
`docs/self-monitoring.md` §4 nominates one tenant per organization to carry the
installation's own events, and `organization.platform_tenant_id` is a single column. A new
tenant is not nominated and needs nothing; self-events continue to land where they already
do. This was listed as an open question when the sibling document deferred it; the answer is
that the existing schema already decided it and the decision is right — the installation is
one thing, so events about it belong in one place, not duplicated per customer.

## 4. Removing a tenant

### 4.1 Not deletion — the schema already refuses, deliberately

Twenty-seven foreign keys reference `tenant`. Nineteen are `ON DELETE CASCADE`: alert rules
and state, collector assignments, dashboards, the three discovery tables, identity-provider
grants, incidents and their alerts, maintenance windows, notification channels and the sent
log, resource groups, runbooks, saved searches, SLOs, subnets, and `user_tenant_role`.

**Eight are not**, and they are the interesting ones: `resource`, `resource_identifier`,
`resource_relationship`, `credential`, `identity_decision`, `monitoring_profile`, `site`, and
`organization.platform_tenant_id`.

So `DELETE FROM tenant` **already fails today** on any tenant that has ever had a resource.
That is not an oversight. The cascading tables hold operational state — things the product
derived and can derive again — and the refusing tables hold *identity*: what the resources
were, how they were recognised, which credentials reached them, where they sat, and every
identity decision a human reviewed. The product's central claim is one resource identity
across six signals, and the schema declines to make that disappear on request.

**Decision: removal is retirement, and the delete path is never offered.** No cascade is
added and none is removed.

### 4.2 `retired_at`, and the two queries that have to learn about it

Following the collector precedent — `collectors.rs` uses `retired_at IS NULL` in its reads
and exposes a `retired: bool` — the new migration adds `tenant.retired_at timestamptz`.

Two existing readers must change in the same commit, and they are the whole risk of this
feature:

* **`all_tenant_ids()`** currently selects every row with no filter. The four scheduling
  loops call it every turn, so a retired tenant would keep being polled, swept, evaluated and
  alerted on — a "removed" customer whose devices are still being reached over the network.
  This is the criterion to write first.
* **`is_org_admin()`** counts every tenant in the organization as `total`. A retired tenant
  that nobody holds admin on would permanently break `OrgAdmin` for everyone, which is §2's
  lockout arriving by the back door.

Both need `retired_at IS NULL`. Naming them here because each is a one-line change whose
omission is silent, and neither has a test today that would notice.

### 4.3 Telemetry is not deleted when a tenant is retired

There is no cross-store transaction, so a PostgreSQL commit and a ClickHouse mutation cannot
be made atomic; a purge that half-succeeded would be worse than one that never started.
Beyond that, the ClickHouse tables are `PARTITION BY toYYYYMMDD(observed_at)` — by **day**,
not by tenant — so removing one tenant's rows is `ALTER TABLE … DELETE WHERE tenant_id = …`
across every partition in the retention window: an asynchronous mutation rewriting parts that
belong overwhelmingly to other customers.

Two facts make leaving it correct rather than merely convenient:

1. `ORDER BY (tenant_id, resource_id, observed_at)` puts the tenant first in the sort key, so
   a live tenant's queries never read a retired one's granules. The data is inert, not slow.
2. Every table carries a `TTL … DELETE`, so it expires on its own within the retention the
   installation already agreed to. **How long that is deserves stating precisely, because it
   is not one number and the rollups outlive the raw rows:** raw flows and spans 7 days, raw
   metrics 30, raw logs and events 365, states 1095 — and the aggregates are 365 for the log
   and flow and span rollups and **1095 for the hourly metric rollup**. So the honest sentence
   is that a retired tenant's telemetry is gone within **three years**, not one, and its
   aggregates are the last thing to go.

**Decision: retiring a tenant stops ingest and hides it, and does not touch ClickHouse.** A
purge is a **separate, explicitly-requested, audited** operation — `tenant.purge` — which may
only be asked for on an already-retired tenant, is asynchronous, and reports progress rather
than blocking a request. It is not part of this document's scope beyond reserving the name
and the ordering, because a deletion tool that a customer's data-protection request depends
on deserves its own decisions about evidence of completion.

> The honest consequence, and it goes in `docs/security-overview.md` rather than only here:
> retiring a tenant does not erase its telemetry, and a buyer asking about erasure gets the
> TTLs above — up to three years for the hourly metric rollup — and a purge that is not built
> yet.
>
> **It also goes in the confirmation dialogue**, which is the only place somebody reads it at
> the moment it matters. `web/src/tenants.ts::retireConsequences` lists what stops, how many
> people lose access, that the estate is kept, and that the telemetry is not purged — with a
> test asserting the last of those, because a dialogue saying "removed" would be the single
> place this product lied to somebody who then repeated it to a regulator.

### 4.4 What cannot be retired

* **The organization's last tenant.** `is_org_admin` needs `total > 0`, and an organization
  with no tenants is an installation with nothing in it and no way back in.
* **The nominated platform tenant**, while it is nominated. The FK
  `organization_platform_tenant_is_its_own` already refuses, and the error should be a
  sentence saying to nominate another one first rather than a foreign-key violation.
* **A tenant the caller would lose `OrgAdmin` by keeping** — not a restriction, the opposite:
  retiring is one of the few ways `held == total` is *restored*, and §4.2 is what makes that
  work.

Both refusals are decided in the statement, not read-then-write, for the reason
`user-administration.md` §4.3 gives about concurrent requests.

## 5. The surface this implies

| Method and path | Authorisation | Audit action |
|---|---|---|
| `GET /api/v1/tenants` | `OrgAdmin` | `tenant.list` |
| `POST /api/v1/tenants` | `OrgAdmin` | `tenant.create` |
| `PATCH /api/v1/tenants/{id}` | `OrgAdmin` | `tenant.update` |
| `POST /api/v1/tenants/{id}/retire` | `OrgAdmin` | `tenant.retire` |
| `POST /api/v1/tenants/{id}/restore` | `OrgAdmin` | `tenant.restore` |

`GET /api/v1/tenants` is not the same as `/api/v1/me`'s membership list: this is every tenant
in the organization including retired ones and ones the caller holds no role on, which is
information only an org-admin should have. All five entries go in
`crates/uops-api/tests/isolation.rs`, per M12's `[~]` criterion.

Retirement is reversible (`restore`) for the same reason `user-administration.md` §4.4 makes
disabling reversible: an irreversible suspension forces a workaround that is worse than the
thing it works around — here, a second tenant holding the same customer's estate, with the
identity history split across both.

## 6. What this does not do

**Move resources between tenants.** The interesting request behind it is real — a device was
onboarded into the wrong customer — and it is a different problem: `resource` has composite
foreign keys `(id, tenant_id)` from migration 0002 specifically so that a resource cannot
drift across the boundary, and re-parenting one means rewriting every row that references the
pair, in both stores. It deserves its own document and probably a different answer, such as
re-onboarding.

**Per-tenant retention.** The `TTL` is one value per table for the whole installation.
Per-tenant retention means either partitioning by tenant, which trades away the day-partition
pruning every time-ranged query depends on, or a mutation per tenant per day. `W1` chose the
current layout on measurements; changing it needs measurements, not a decision document.

**Quotas and limits.** `notification_budget_per_day` exists because a runaway alert loop is a
notification bill; nothing else is capped, and capping ingest is a commercial decision that
`PLAN` puts after a repeatable deployment.

**Self-service tenant creation.** No signup flow, no billing, no trials.

**Cross-tenant dashboards or queries.** An MSP wanting one pane over forty customers is a
real ask and it is exactly the thing `TenantScope` is built to make impossible by accident.
It would need an explicit organization-scoped read path — the same one
`docs/self-monitoring.md` §1 costed at three changes and declined.

## 7. Acceptance criteria

- [x] An org-admin creates a second tenant and is granted `admin` on it **in the same
      transaction** — asserted twice: by `is_org_admin` immediately afterwards
      (`uops-store-pg/tests/tenants.rs::creating_a_tenant_does_not_lock_the_creator_out`) and
      over HTTP by `GET /api/v1/tenants` still answering `200` for the creator, which needs
      admin on every tenant and would `403` if the grant had not happened
- [x] A tenant created while the server is running is polled, swept and evaluated without a
      restart — asserted against `all_tenant_ids`, which is what all four scheduling loops
      read on every turn, and through the switcher (`/me`) and a scoped route
- [x] A slug that breaks the format is refused by the database, not only by the route —
      asserted by `create_tenant` erroring on six malformed slugs, which reaches the
      constraint rather than the route's own check
- [x] A duplicate slug within one organization is refused; the same slug in a different
      organization is accepted
- [x] A tenant can be renamed, and its `tenant_id`-keyed audit history is continuous across
      the rename — the id is asserted unchanged, which is what every audit row and every
      `X-Uops-Tenant` header names
- [x] Retiring a tenant removes it from `all_tenant_ids()`, so the loops stop reaching its
      devices. **Mutation-verified**: relaxing that one filter leaves a removed customer being
      polled and alerted on, and the test fails
- [x] Retiring a tenant does not change `is_org_admin` for an admin who held it everywhere
      else — the second one-line filter, also mutation-verified, because a retired tenant
      nobody administered would otherwise break organization-wide admin for everyone, forever
- [x] The organization's last tenant cannot be retired
- [x] The nominated platform tenant cannot be retired, and the refusal is a sentence naming
      what to do first rather than a foreign-key error — asserted on the response body
- [x] A retired tenant is restorable, and its resources, identifiers, credentials, sites and
      identity decisions are all still there afterwards — a test plants a site and a resource,
      retires the tenant, and counts them
- [~] A retired tenant's telemetry is still in `ClickHouse` and is not read by any other
      tenant's query. **The first half is true by construction and the second is untested
      here**: nothing deletes telemetry, and `tenant_id` is first in every sort key, but the
      isolation of a *retired* tenant's rows rests on the same scoping every other query uses
      rather than on anything this work added. Writing a test that retires a tenant, queries as
      another, and asserts the granules were never touched needs `ClickHouse` query
      introspection this repository does not have a harness for
- [x] `DELETE FROM tenant` is not reachable from any route, and the eight non-cascading
      foreign keys are unchanged by this work — no migration here alters a foreign key
- [x] Every route above appears in `crates/uops-api/tests/isolation.rs` — five cases, and
      `every_route_in_the_router_has_an_isolation_case` is what makes that not a promise
- [x] A second tenant with no collector assigned reports that plainly, rather than looking
      like a broken installation — the Customers screen says a new tenant starts with nobody
      but its creator, and `docs/collectors.md` already covers the assignment step

**Thirteen of fourteen.** The one `[~]` is a test this repository cannot currently write
rather than a behaviour in doubt, and it says which.

> **What this did not need.** The two predictions in §1 held: every scheduling loop already
> re-read `all_tenant_ids` each turn, so a new tenant needs no restart and no cache
> invalidation — nothing in `uops-poller`, `uops-sweeper` or `uops-alert` was touched. And
> deletion was already decided by the schema, so no foreign key changed. The work was a
> column, a constraint, a module, five routes, a screen, and two one-line filters whose
> omission would have been silent.
