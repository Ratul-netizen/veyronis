-- The installation, as a resource — docs/self-monitoring.md §2.3.
--
-- M11 §2.4 wanted the product's own sign-ins to be detectable and found they could not be:
-- `events` is partitioned by tenant and authentication precedes knowing one. The decision
-- document costs four ways out of that and recommends this one, on the grounds that it is
-- the only one which adds no new isolation scope, no second store behind the Query AST and
-- no second evaluation path.
--
-- The product monitors an estate. The monitoring platform is part of an estate, and this
-- product already has a type for that: a resource. A sign-in becomes an `authentication`
-- event on it, in a tenant the organization nominates, and every existing mechanism — the
-- Query AST, the alert engine, incidents, the timeline, topology suppression, read auditing
-- — works with no change at all.
--
-- # The two columns, and why they are on `organization`
--
-- Not on `tenant`: nominating is an organization's decision, and putting a flag on the
-- tenant would let two tenants in one organization both claim to be the platform. One
-- nullable pair on the organization makes "which tenant" a question with exactly one
-- answer, or none.
--
-- `resource` has no `UNIQUE (tenant_id, name)` — names are not unique and identity
-- resolution may rewrite them — so the reference is held by id rather than looked up by
-- name. A `self` resource found by name would be a `self` resource somebody could rename.

ALTER TABLE organization
    ADD COLUMN platform_tenant_id   uuid,
    ADD COLUMN platform_resource_id uuid;

-- The tenant must belong to *this* organization. The composite key is what makes that a
-- schema fact rather than a handler's good intentions — the same mechanism tenant isolation
-- has used since 0002, pointed at a different property.
ALTER TABLE organization
    ADD CONSTRAINT organization_platform_tenant_is_its_own
        FOREIGN KEY (platform_tenant_id, id) REFERENCES tenant (id, org_id);

-- And the resource must belong to that tenant.
ALTER TABLE organization
    ADD CONSTRAINT organization_platform_resource_is_in_that_tenant
        FOREIGN KEY (platform_resource_id, platform_tenant_id)
            REFERENCES resource (id, tenant_id);

-- Both or neither. A nominated tenant with no resource is a half-configured state nothing
-- would ever complete, and a resource with no tenant cannot be reached.
ALTER TABLE organization
    ADD CONSTRAINT organization_platform_is_whole
        CHECK ((platform_tenant_id IS NULL) = (platform_resource_id IS NULL));

-- ---------------------------------------------------------------------------
-- Backfill: every organization that has exactly one tenant.
--
-- One tenant is one answer, so nominating is unambiguous and nobody has to be asked. An
-- organization with several gets NULL and behaves exactly as it does today — audit rows and
-- no detectable events — which is what docs/self-monitoring.md §3 means by degrading
-- honestly. It is also, deliberately, the whole of the on-premise case: a single-tenant
-- installation is the defence and law-enforcement shape that motivated read auditing.
--
-- `service`, not `device`: the installation is a logical thing rather than a box, and it is
-- the kind the UI already draws as a capsule. It gets no `mgmt_ip` identifier, which is
-- what makes a resource pollable (`pollable_devices` joins on it) and what a runbook step
-- needs to reach one — so "the product cannot be told to SSH into itself" falls out of the
-- existing schema rather than needing a rule of its own.
--
-- The name is deliberately not a brand: it says what the row is.
WITH only_child AS (
    SELECT t.org_id, t.id AS tenant_id
      FROM tenant t
     WHERE (SELECT count(*) FROM tenant o WHERE o.org_id = t.org_id) = 1
),
created AS (
    INSERT INTO resource (id, tenant_id, kind, name, status, attributes)
    SELECT gen_random_uuid(), only_child.tenant_id, 'service', 'This installation', 'up',
           '{"service.name": "uops"}'::jsonb
      FROM only_child
    RETURNING id, tenant_id
)
UPDATE organization o
   SET platform_tenant_id   = created.tenant_id,
       platform_resource_id = created.id
  FROM created, only_child
 WHERE only_child.tenant_id = created.tenant_id
   AND o.id = only_child.org_id;

-- Reading "which organization is this tenant the platform for" is not a query anything
-- makes; reading "what is my organization's platform resource" is, on every sign-in.
-- The primary key covers it, so no index is added here — a partial index on a column read
-- by primary-key lookup would be storage nothing uses.
