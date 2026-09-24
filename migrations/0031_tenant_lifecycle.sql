-- 0031 — creating and retiring a tenant. `docs/tenant-lifecycle.md`.
--
-- Until now the only `INSERT INTO tenant` outside tests was in `bootstrap_first_run`, whose
-- whole decision is "does any user exist" — so it ran once and declined forever after. There
-- was no `create_tenant` anywhere, which meant an installation had exactly one tenant,
-- permanently, and the MSP shape `docs/security-overview.md` describes was unreachable.
--
-- Two columns of work: a way to stop using a tenant, and a format rule for the slug that
-- never existed.

-- Retirement, not deletion. `docs/tenant-lifecycle.md` §4.1: of the twenty-seven foreign keys
-- referencing `tenant`, nineteen cascade and eight refuse — `resource`, its identifier and
-- relationship tables, `credential`, `identity_decision`, `monitoring_profile`, `site`, and
-- the platform nomination. So `DELETE FROM tenant` already fails on any tenant that has ever
-- held a resource, which is every real one. That is not an oversight: the cascading tables
-- hold state the product can derive again, and the refusing ones hold *identity*, which the
-- product's central claim is about not losing.
--
-- Nullable, following `collector.retired_at` from 0025 rather than inventing a second way to
-- say the same thing.
ALTER TABLE tenant ADD COLUMN retired_at timestamptz;

-- The slug had `UNIQUE (org_id, slug)` from 0001 and **no format rule anywhere** — not in the
-- schema, not in `FirstRunRequest`, not in any validator. First run took whatever
-- configuration handed it.
--
-- In the schema rather than only in the route, because the route is not the only writer:
-- `bootstrap` writes one too, and a rule that lives in one caller is a rule the other caller
-- breaks.
--
-- # Why 63 and not the 40 the document proposed
--
-- `docs/tenant-lifecycle.md` §3.2 said 2–40. Measured against the development database
-- before applying this: 15 177 tenants, none malformed, and **6 818 longer than 40** — test
-- fixtures that append a UUID, the longest at 51. A migration that refuses existing rows is
-- not a migration. 63 is the length of a DNS label, which is both comfortably above what is
-- there and the honest bound for a string shaped like a hostname component: a slug is the
-- kind of thing that ends up in a subdomain or a URL segment, and that is where the real
-- limit comes from rather than from taste.
ALTER TABLE tenant
    ADD CONSTRAINT tenant_slug_is_a_label
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND length(slug) BETWEEN 2 AND 63);

-- Note what is deliberately *not* here: nothing releases a retired tenant's slug.
-- `UNIQUE (org_id, slug)` still counts it, so the name stays taken. Two reasons, and the
-- second is the one that matters: restoring a retired tenant must not collide with something
-- created in the meantime, and reusing a former customer's slug would make every audit and
-- access row that named it ambiguous about which customer it meant.

-- Retirement is read on every scheduler turn — `all_tenant_ids` filters it — and that query
-- orders by `(created_at, id)` over every tenant in the installation. A partial index keeps
-- the common case reading only live rows once a deployment has retired a few.
CREATE INDEX tenant_live_idx ON tenant (created_at, id) WHERE retired_at IS NULL;
