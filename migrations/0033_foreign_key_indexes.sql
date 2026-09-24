-- The five foreign keys added since 0010 without an index on the referencing side.
--
-- Migration 0010 fixed this class and left behind the audit query that finds it, and
-- `migrations/tests/invariants.sql` runs that query as an assertion — *"this is the guard
-- that stops the next foreign key being added without one."*
--
-- It did not stop them, and the reason is worth writing down rather than quietly fixing.
-- The invariant has been **failing** since migration 0027, so the `schemas · repositories ·
-- api` job has been red on every push since then, and three more migrations added a sixth,
-- seventh and eighth unindexed key while it was red. A guard that is already failing is not
-- a guard; it is scenery, and everybody learns to walk past it. Found 2026-09-25 by reading
-- a CI run instead of assuming it was green.
--
-- What each one costs, which is the same arithmetic 0010 sets out: PostgreSQL indexes the
-- referenced side automatically and the referencing side never, so every DELETE or key
-- UPDATE on the parent sequentially scans each child table once per row deleted. None of
-- these child tables is large today, and that is exactly when the cost is invisible.
--
--   subnet (site_id, tenant_id)          <- decommissioning a site
--   organization (platform_tenant_id)    <- retiring a tenant; `db.sh sweep` does it in a loop
--   organization (platform_resource_id)  <- deleting resources in bulk, which is 0010's story
--   user_invitation (created_by)         <- removing a person
--   ingest_token (created_by)            <- removing a person
--
-- The two on `organization` are the self-monitoring columns from 0027. Both are nullable, so
-- a partial index would be smaller; plain ones are used here because `organization` holds one
-- row per customer and a partial index buys nothing measurable while adding a predicate that
-- the invariant does not check and a reader has to reason about.
--
-- Coverage, not exact shape, is what the audit asks for: an index whose leading columns
-- contain the key's columns serves it, in any order, because the check is array containment.

-- 0028. The child of `site`.
CREATE INDEX subnet_site_idx
    ON subnet (site_id, tenant_id);

-- 0027. `organization.platform_tenant_id` points at the tenant that holds this
-- installation's own telemetry, so retiring a tenant checks this constraint.
CREATE INDEX organization_platform_tenant_idx
    ON organization (platform_tenant_id, id);

-- 0027. And `platform_resource_id` points at the resource that *is* the installation, so
-- every bulk resource delete checks it — the operation 0010 was written about.
CREATE INDEX organization_platform_resource_idx
    ON organization (platform_resource_id, platform_tenant_id);

-- 0030. Who sent the invitation. Deleting a user checks this, and the first-run recovery
-- path in `firstrun.rs` is "emptying app_user", which is precisely a bulk delete.
CREATE INDEX user_invitation_created_by_idx
    ON user_invitation (created_by);

-- 0032. Who minted the ingest token. Same parent, same reason.
CREATE INDEX ingest_token_created_by_idx
    ON ingest_token (created_by);
