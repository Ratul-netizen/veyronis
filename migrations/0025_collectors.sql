-- 0025 — the collector registry. M12 §2.3, `docs/M12-enterprise.md`.
--
-- Today every collector reads a YAML file naming its tenants. That is right for one
-- collector and wrong for forty across nine sites: nothing knows how many there are,
-- what versions they run, or that one of them stopped three days ago.
--
-- # What the enrolment token is, and what it is not
--
-- It is an **operational control, not a security boundary**, and saying so here is more
-- useful than implying otherwise. A collector in this deployment model holds PostgreSQL
-- and ClickHouse credentials — it has to, because that is where it writes — and those
-- are strictly more powerful than any token below. A malicious collector does not need
-- to enrol.
--
-- What enrolment does buy is real and worth having:
--
--   * a collector that was never enrolled serves **no tenant**, so a box that is brought
--     up with a copied config does not silently start carrying a customer's logs;
--   * the set of tenants a collector may serve is decided **server-side**, so editing a
--     collector's own YAML can no longer point it at another customer;
--   * an inventory exists, and a collector that goes quiet is visible.
--
-- It becomes a security boundary the day telemetry is routed through the server rather
-- than written directly to ClickHouse. That is a throughput decision — W1 measured
-- ~100 000 msg/s straight to ClickHouse — rather than a plumbing one, and it is not this
-- migration.
--
-- # There is no identity file
--
-- Enrolment is idempotent on `(org_id, kind, name)`, so a collector that restarts claims
-- the row it already had. The alternative — writing an id to disk on first start — adds a
-- file whose loss produces a second collector with the same job and no way to tell which
-- is which. A name defaults to the hostname, and two collectors of different kinds on one
-- host are two rows.

CREATE TYPE collector_kind AS ENUM ('syslog', 'otlp', 'flow', 'poller');

CREATE TABLE collector (
    id           uuid           PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid           NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    kind         collector_kind NOT NULL,

    -- What an operator calls it. Defaults to the hostname on the collector's side, which
    -- is what makes enrolment idempotent without an identity file.
    name         text           NOT NULL,

    -- What it last said about itself. Refreshed on every heartbeat rather than only at
    -- enrolment, because the question an operator asks is "what is running there *now*"
    -- and an upgrade that did not take is exactly the case where those differ.
    hostname     text,
    version      text,
    -- What it is bound to, as it reports it: `[{"tenant":"acme","udp":"0.0.0.0:514"}]`.
    -- Free-form on purpose — a flow collector's listeners and a poller's schedule are not
    -- the same shape, and a column per kind would be four columns three of which are NULL.
    reported     jsonb,

    enrolled_at  timestamptz    NOT NULL DEFAULT now(),

    -- NULL until the first heartbeat. A collector that enrolled and never reported is a
    -- different problem from one that reported and stopped, and a DEFAULT now() here
    -- would make them look identical.
    last_seen_at timestamptz,

    -- When the *process* started. The counters below are per-process and monotonic, so
    -- without this a restart looks like a collector that lost half its traffic.
    started_at   timestamptz,
    received     bigint         NOT NULL DEFAULT 0,
    written      bigint         NOT NULL DEFAULT 0,
    -- Everything lost at either end: a full queue and a full disk are different failures
    -- and one number is what somebody asking "did we lose anything" wants.
    lost         bigint         NOT NULL DEFAULT 0,

    -- Retired rather than deleted, for the same reason a user is disabled rather than
    -- deleted: the row is referenced by an audit trail and by an operator's memory of
    -- what used to be at that site.
    retired_at   timestamptz,

    -- Idempotent enrolment. See the header: this is what removes the identity file.
    UNIQUE (org_id, kind, name),
    -- The target of the composite key on `collector_tenant`.
    UNIQUE (id, org_id)
);

CREATE INDEX collector_org_idx ON collector (org_id);
-- "Which collectors have gone quiet" is the question this table exists to answer, and it
-- is asked against the live ones.
CREATE INDEX collector_last_seen_idx ON collector (last_seen_at) WHERE retired_at IS NULL;

-- NOTE — there is no `quiet` column, and that is deliberate.
--
-- A stored flag needs something to set it, and the something would be a sweeper. A
-- sweeper is a process; the processes this table watches are processes; and the failure
-- mode of a stored flag is that the thing which stopped is the thing that would have
-- written the flag. `last_seen_at < now() - interval` is computed at read time, costs a
-- comparison, and is right even when everything else has stopped.

CREATE TABLE collector_enrolment_token (
    id          uuid           PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid           NOT NULL REFERENCES organization (id) ON DELETE CASCADE,

    -- What an operator calls this token: "site-berlin", "rollout-2026-q4".
    label       text           NOT NULL,

    -- The HASH, never the token. Same posture as `session.token_hash` in 0006, and the
    -- same reasoning: a stolen database backup must not hand the thief a set of working
    -- enrolment tokens. The token is high-entropy random, so a plain SHA-256 is right —
    -- there is no low-entropy secret to make expensive.
    token_hash  bytea          NOT NULL UNIQUE,

    -- Restrict a token to one kind of collector, or NULL for any. A token handed to a
    -- site engineer to bring up a syslog box has no business enrolling a poller.
    kind        collector_kind,

    -- NULL means it does not expire, which is the right default for a token that lives in
    -- a configuration-management repository and brings up collectors for years. An
    -- operator who wants the tighter posture sets both this and `uses_left`.
    expires_at  timestamptz,
    -- NULL means unlimited. A single-use token is `uses_left = 1`.
    uses_left   integer        CHECK (uses_left IS NULL OR uses_left >= 0),

    created_at  timestamptz    NOT NULL DEFAULT now(),
    created_by  uuid           REFERENCES app_user (id),
    revoked_at  timestamptz,

    UNIQUE (org_id, label)
);

CREATE INDEX collector_enrolment_token_org_idx ON collector_enrolment_token (org_id);
CREATE INDEX collector_enrolment_token_created_by_idx
    ON collector_enrolment_token (created_by);

-- Which tenants a collector may serve. M12 §2.3: *configuration stays local; assignment
-- comes from the server.*
--
-- The division this encodes is the one that sentence describes. Which address to bind is
-- a property of where the box sits and stays in its own file — a server that pushed
-- addresses would be a server that can break a collector it cannot reach. Which customer
-- the box may carry is an assignment, and it lands here.
--
-- The practical consequence: a listener naming a tenant this collector is not assigned
-- fails at startup, naming the tenant. Before this table, any collector with database
-- credentials could carry any tenant by editing its own YAML.
CREATE TABLE collector_tenant (
    collector_id uuid        NOT NULL,
    -- Carried rather than joined, because it is half of both composite keys below —
    -- which is what makes "a collector cannot be assigned another organization's tenant"
    -- a schema fact rather than something the application remembers to check.
    org_id       uuid        NOT NULL,
    tenant_id    uuid        NOT NULL,

    assigned_at  timestamptz NOT NULL DEFAULT now(),
    assigned_by  uuid        REFERENCES app_user (id),

    PRIMARY KEY (collector_id, tenant_id),

    FOREIGN KEY (collector_id, org_id)
        REFERENCES collector (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, org_id)
        REFERENCES tenant (id, org_id) ON DELETE CASCADE
);

CREATE INDEX collector_tenant_collector_idx ON collector_tenant (collector_id, org_id);
CREATE INDEX collector_tenant_tenant_idx ON collector_tenant (tenant_id, org_id);
CREATE INDEX collector_tenant_assigned_by_idx ON collector_tenant (assigned_by);
