-- 0026 — runbooks, runs and approvals. M10, `docs/M10-automation.md`.
--
-- Every table before this one records something that happened to a customer's estate.
-- These record something this product *did* to it, and the difference shows up in what
-- the schema refuses rather than in what it stores.
--
-- # Three things are unrepresentable here, not merely checked
--
--   1. **A version that changed.** A trigger refuses every UPDATE on `runbook_version`.
--      Editing a runbook writes a new version; a run names the version it executed, so
--      "what did this actually do in March" has an answer that does not depend on nobody
--      having edited it since.
--   2. **One person approving twice.** `PRIMARY KEY (run_id, approved_by)`. Two
--      approvals from one person are one person agreeing twice, which is the exact thing
--      two-person integrity exists to refuse.
--   3. **Approving your own run.** The composite key below, and it is the one worth
--      reading carefully — see `runbook_approval`.
--
-- `uops-runbook` enforces all three in code as well, and that is not redundancy for its
-- own sake: the code produces a message somebody can act on, and the schema is what holds
-- when somebody writes a row by another route.

CREATE TYPE runbook_approvals AS ENUM ('none', 'one', 'two');

CREATE TYPE runbook_run_state AS ENUM (
    -- Planned and waiting for somebody: the targets are resolved and the commands are
    -- rendered, and nothing has been sent.
    'awaiting_approval',
    -- Approved, or needed no approval. Waiting for a runner to pick it up.
    'ready',
    'running',
    'succeeded',
    -- A step failed. The run stopped there — M10 §2.6 — and the declared rollback is
    -- offered rather than performed.
    'failed',
    -- The product declined before anything was sent: too many targets, an unrenderable
    -- template, an approval that expired. Distinct from `failed`, because one of them
    -- touched a device and the other did not.
    'refused',
    'cancelled'
);

-- ----------------------------------------------------------------------------
-- The runbook, and its versions
-- ----------------------------------------------------------------------------

CREATE TABLE runbook (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid        NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,

    -- What an operator calls it: `restart-bgp-session`. Unique per tenant, because a run
    -- is discussed by name in an incident and two of them would make that ambiguous.
    name       text        NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid        REFERENCES app_user (id),

    -- Retired rather than deleted, like a collector and a user: a run record names the
    -- runbook it executed, and that name has to keep resolving.
    retired_at timestamptz,

    UNIQUE (tenant_id, name),
    UNIQUE (id, tenant_id)
);

CREATE INDEX runbook_tenant_idx ON runbook (tenant_id);
CREATE INDEX runbook_created_by_idx ON runbook (created_by);

CREATE TABLE runbook_version (
    id          uuid              PRIMARY KEY DEFAULT gen_random_uuid(),
    runbook_id  uuid              NOT NULL,
    tenant_id   uuid              NOT NULL,

    -- 1, 2, 3… A run names this in its record, and an operator says "version 4" out loud.
    version     integer           NOT NULL CHECK (version >= 1),

    description text              NOT NULL DEFAULT '',

    -- The `ResourceSelector` from `uops-query`, as the alert rules and maintenance windows
    -- store it. Reusing the shape is what makes "restart the device this alert fired on" a
    -- copy of one field rather than a translation.
    targets     jsonb             NOT NULL,

    -- `Vec<Step>`. Validated by `uops_runbook::validate` before it ever reaches here — a
    -- shape check in the database would be a second, weaker copy of rules that are
    -- already written down once.
    steps       jsonb             NOT NULL,

    -- M10 §2.7. Small by default; raising it is an edit to a reviewed object.
    max_targets integer           NOT NULL CHECK (max_targets >= 1),
    concurrency integer           NOT NULL CHECK (concurrency >= 1),
    CONSTRAINT runbook_version_concurrency_within_targets
        CHECK (concurrency <= max_targets),

    approvals   runbook_approvals NOT NULL,
    -- Whether this may only run inside a maintenance window. The opposite of how a window
    -- works for alerting, and deliberately: an alert is suppressed during one, and a
    -- change arguably should be only allowed during one.
    maintenance_only boolean      NOT NULL DEFAULT false,

    created_at  timestamptz       NOT NULL DEFAULT now(),
    created_by  uuid              REFERENCES app_user (id),

    UNIQUE (runbook_id, version),
    UNIQUE (id, tenant_id),

    FOREIGN KEY (runbook_id, tenant_id)
        REFERENCES runbook (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX runbook_version_runbook_idx ON runbook_version (runbook_id, tenant_id);
CREATE INDEX runbook_version_created_by_idx ON runbook_version (created_by);

-- A version never changes. See the header.
--
-- A trigger rather than a permission, because a permission is a deployment's to grant and
-- this is a property of the data model: the thing a run points at has to still be the
-- thing that ran. Without it, "this runbook only ever did X" is a claim resting on nobody
-- having run an UPDATE.
CREATE FUNCTION runbook_version_is_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        'a runbook version cannot be edited; save a new version instead (runbook %, version %)',
        OLD.runbook_id, OLD.version
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER runbook_version_no_update
    BEFORE UPDATE ON runbook_version
    FOR EACH ROW EXECUTE FUNCTION runbook_version_is_immutable();

-- ----------------------------------------------------------------------------
-- A run
-- ----------------------------------------------------------------------------

CREATE TABLE runbook_run (
    id            uuid              PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid              NOT NULL,
    runbook_id    uuid              NOT NULL,
    -- The exact version executed, not the runbook's current one.
    version_id    uuid              NOT NULL,

    state         runbook_run_state NOT NULL DEFAULT 'awaiting_approval',

    -- M10 §2.2: every run is a dry run unless somebody says otherwise, and the column
    -- default is the safe one rather than the convenient one.
    dry_run       boolean           NOT NULL DEFAULT true,

    -- The resolved targets at plan time, by id and name, and a fingerprint over them.
    --
    -- Stored rather than re-resolved, because the whole point of approving a run is that
    -- somebody looked at *this list*. Re-resolving at execution time would mean approving
    -- one thing and running another.
    targets       jsonb             NOT NULL,
    targets_fingerprint text        NOT NULL,

    -- Why it was started, in the starter's words.
    --
    -- Free text today because a person types it. The column is here rather than added
    -- later because M10 §2.8 defers auto-remediation and this is the field that would say
    -- *which alert* — shaping it now costs nothing and avoids a migration that changes
    -- the meaning of an existing column.
    reason        text              NOT NULL DEFAULT '',

    started_by    uuid              NOT NULL REFERENCES app_user (id),
    -- Ran without approval under the break-glass role — M10 §2.5. Recorded on the run
    -- itself, so it is visible for as long as the run is, rather than only in an audit
    -- entry somebody has to go and find.
    break_glass   boolean           NOT NULL DEFAULT false,

    created_at    timestamptz       NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz,
    -- Why it stopped, when it did not succeed. One sentence, for the list.
    failure       text,

    FOREIGN KEY (runbook_id, tenant_id)
        REFERENCES runbook (id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (version_id, tenant_id)
        REFERENCES runbook_version (id, tenant_id) ON DELETE CASCADE,

    -- The target of the composite key on `runbook_approval`, and the reason it exists.
    UNIQUE (id, started_by),
    UNIQUE (id, tenant_id)
);

CREATE INDEX runbook_run_tenant_idx ON runbook_run (tenant_id, created_at DESC);
CREATE INDEX runbook_run_runbook_idx ON runbook_run (runbook_id, tenant_id);
CREATE INDEX runbook_run_version_idx ON runbook_run (version_id, tenant_id);
CREATE INDEX runbook_run_started_by_idx ON runbook_run (started_by);
-- What a runner asks for: the runs waiting to be executed.
CREATE INDEX runbook_run_ready_idx ON runbook_run (created_at)
    WHERE state = 'ready';

-- ----------------------------------------------------------------------------
-- Approvals
-- ----------------------------------------------------------------------------

-- M10 §2.5, and PLAN §0b's two-person integrity note.
--
-- # Why `started_by` is carried here
--
-- It is denormalised, and that is the point. The pair `(run_id, started_by)` is a
-- composite foreign key into `runbook_run (id, started_by)` — so the value in this column
-- cannot be anything other than the person who actually started the run — and the CHECK
-- below then compares it to the approver.
--
-- The result is that **approving your own run is unrepresentable**. Not refused by the
-- application, not caught by a trigger: there is no row that expresses it. The same
-- mechanism the tenant-isolation keys have used since 0002, pointed at a different
-- property.
CREATE TABLE runbook_approval (
    run_id      uuid        NOT NULL,
    tenant_id   uuid        NOT NULL,
    approved_by uuid        NOT NULL REFERENCES app_user (id),
    -- Carried so the CHECK below can see it. See the note above.
    started_by  uuid        NOT NULL,

    at          timestamptz NOT NULL DEFAULT now(),
    -- What they were looking at. A run whose targets changed after approval is not the
    -- run that was approved — M10 §2.5.
    targets_fingerprint text NOT NULL,

    -- One person, one approval. Two from the same person are one person agreeing twice.
    PRIMARY KEY (run_id, approved_by),

    CONSTRAINT runbook_approval_not_self
        CHECK (approved_by <> started_by),

    FOREIGN KEY (run_id, started_by)
        REFERENCES runbook_run (id, started_by) ON DELETE CASCADE,
    FOREIGN KEY (run_id, tenant_id)
        REFERENCES runbook_run (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX runbook_approval_run_idx ON runbook_approval (run_id, tenant_id);
CREATE INDEX runbook_approval_approved_by_idx ON runbook_approval (approved_by);
CREATE INDEX runbook_approval_started_by_idx ON runbook_approval (run_id, started_by);

-- ----------------------------------------------------------------------------
-- What each step actually did
-- ----------------------------------------------------------------------------

CREATE TYPE runbook_step_state AS ENUM (
    'pending',
    -- Not executed: a dry run reached a step that changes something, or an earlier step
    -- failed. Distinct from `pending`, which is a step still to come.
    'skipped',
    'running',
    'ok',
    'failed'
);

CREATE TABLE runbook_run_step (
    run_id      uuid               NOT NULL,
    tenant_id   uuid               NOT NULL,
    -- Which device. A run acts on many, and every one of them has its own transcript.
    resource_id uuid               NOT NULL,
    step_index  integer            NOT NULL CHECK (step_index >= 0),

    name        text               NOT NULL,
    -- What was actually sent, rendered. This is the record an auditor reads, so it is the
    -- literal text rather than the template.
    rendered    text               NOT NULL,
    destructive boolean            NOT NULL,

    state       runbook_step_state NOT NULL DEFAULT 'pending',
    -- Captured output, **redacted and capped** — `uops_runbook::redact`.
    --
    -- The most sensitive column in this schema and the one most likely to become
    -- something nobody intended: a `show running-config` prints hashed passwords and a
    -- verbose HTTP call prints an Authorization header. It is redacted on the way in,
    -- and M10 §4 says plainly that this is not the place to read configuration from.
    output      text,
    exit_code   integer,

    started_at  timestamptz,
    finished_at timestamptz,

    PRIMARY KEY (run_id, resource_id, step_index),

    FOREIGN KEY (run_id, tenant_id)
        REFERENCES runbook_run (id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id, tenant_id)
        REFERENCES resource (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX runbook_run_step_run_idx ON runbook_run_step (run_id, tenant_id);
CREATE INDEX runbook_run_step_resource_idx ON runbook_run_step (resource_id, tenant_id);

-- ----------------------------------------------------------------------------
-- The lease this runs under
-- ----------------------------------------------------------------------------

-- M10 §2.9: a runner takes a lease, so two of them do not execute one queued run twice.
-- The same mechanism, and the same table, as the poller, the alert engine and the sweeper
-- — migration 0023.
ALTER TABLE lease DROP CONSTRAINT lease_name_is_known;
ALTER TABLE lease ADD CONSTRAINT lease_name_is_known
    CHECK (name IN ('poll', 'alert', 'sweep', 'run'));

-- Seeded already-expired and `unclaimed`, exactly as 0023 seeds the other three: the
-- claim is an UPDATE with no insert path, which is what makes it one statement with no
-- race, and the first runner to start should take it rather than waiting out a period
-- nobody held.
INSERT INTO lease (name, holder, expires_at, acquired_at)
VALUES ('run', 'unclaimed', to_timestamp(0), to_timestamp(0));
