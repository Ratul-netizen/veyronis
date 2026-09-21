-- Incidents — M9, `docs/M9-incident.md`.
--
-- Two tables, and the shape of them is §2.1: **an incident is a human's unit of work and
-- an alert is a machine's.** An alert fires and resolves on its own and needs nobody; an
-- incident is what somebody is *working on*, and it outlives its alerts because the
-- router stopping its flapping at 02:14 is not the same event as somebody deciding at
-- 09:00 that it is understood.
--
-- These are in PostgreSQL rather than ClickHouse for the reason §2.7 gives: ClickHouse
-- holds immutable observations, and an incident is a mutable opinion with an owner, an
-- acknowledgement and an audit trail.

-- `alert_state` was given a primary key on `id` alone and a UNIQUE on
-- `(tenant_id, dedup_key)`, but not the composite every tenant-safe foreign key in this
-- schema points at. Nothing needed one until now, because nothing referenced an alert.
--
-- Added here rather than by editing 0014, which is applied everywhere and immutable.
ALTER TABLE alert_state ADD CONSTRAINT alert_state_id_is_tenant_scoped UNIQUE (id, tenant_id);

CREATE TABLE incident (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,

    -- 'open'   — alerts are firing
    -- 'quiet'  — every alert resolved, and nobody has said it is understood
    -- 'closed' — a human closed it
    --
    -- §2.1: resolving every alert moves an incident to `quiet` and never to `closed`.
    -- Closing is a *claim*, and the machine is not in a position to make it.
    state         text        NOT NULL DEFAULT 'open',

    -- The highest severity among this incident's alerts, denormalised so that listing a
    -- tenant's incidents ordered by severity does not join and aggregate per row. Kept
    -- honest by the engine, which is the only writer.
    severity      text        NOT NULL,

    -- §2.5 — the *candidate*, never the cause.
    --
    -- The resource in this incident with no other incident resource upstream of it,
    -- breaking ties by whichever alerted first. NULL when the tie cannot be broken: two
    -- disconnected roots, or an estate with no topology at all. An empty field is
    -- information, and the screen says there is no candidate rather than picking one.
    --
    -- ON DELETE SET NULL and not CASCADE: deleting the resource does not delete the
    -- incident. What happened still happened, and an incident that vanished when somebody
    -- decommissioned a switch would take its own explanation with it.
    candidate_resource_id uuid,
    -- `SET NULL (candidate_resource_id)` and not a bare `SET NULL`, which would null the
    -- whole key including `tenant_id` — a NOT NULL column, so the delete would fail at
    -- runtime rather than at review. Migration 0018 is the one that found this the hard
    -- way, and the schema test in `migrations/tests/invariants.sql` is what caught it
    -- here before it was committed.
    FOREIGN KEY (candidate_resource_id, tenant_id)
        REFERENCES resource (id, tenant_id) ON DELETE SET NULL (candidate_resource_id),

    -- Why there is no candidate, when there is none — §2.3 and §2.5. 'no_topology',
    -- 'disconnected', or empty when a candidate was found. A screen that says "no likely
    -- origin" without saying why is a screen that looks broken.
    candidate_absent_because text NOT NULL DEFAULT '',

    started_at    timestamptz NOT NULL DEFAULT now(),
    -- When the most recent alert joined. §2.2's five-minute join window measures from
    -- here, which is what makes it *slide*: a genuine cascade of twenty devices stays one
    -- incident however long the cascade takes, while a fresh failure five minutes after
    -- the last one is a fresh incident.
    last_alert_at timestamptz NOT NULL DEFAULT now(),
    -- When every alert had resolved. Cleared if one fires again while the incident is
    -- still open, because an incident that went quiet and came back was never over.
    quiet_at      timestamptz,
    closed_at     timestamptz,
    closed_by     uuid        REFERENCES app_user (id),

    -- Acknowledgement silences the notification and never the incident — the same rule
    -- `alert_state` holds, and for the same reason.
    acked_by      uuid        REFERENCES app_user (id),
    acked_at      timestamptz,

    -- What the engine could say in one line at the moment it grouped. Not a title a human
    -- edits: v0.1 has no incident editing, because an editable summary is the first half
    -- of a ticketing system and §5 says this is not one.
    summary       text        NOT NULL DEFAULT '',

    CONSTRAINT incident_state_is_known CHECK (state IN ('open', 'quiet', 'closed')),
    -- A close is a person and a time or it is neither.
    CONSTRAINT incident_close_is_whole CHECK ((closed_by IS NULL) = (closed_at IS NULL)),
    CONSTRAINT incident_ack_is_whole CHECK ((acked_by IS NULL) = (acked_at IS NULL)),
    -- 'closed' and a null closed_at would be an incident nobody can be shown to have
    -- closed. The reverse — a close time on an open incident — is the same row read the
    -- other way round.
    CONSTRAINT incident_closed_has_a_closer CHECK (
        (state = 'closed') = (closed_at IS NOT NULL)
    ),
    -- A candidate and a reason it is absent are mutually exclusive. Both would be a row
    -- that says "here is the likely origin, and here is why there isn't one".
    CONSTRAINT incident_candidate_or_a_reason CHECK (
        candidate_resource_id IS NULL OR candidate_absent_because = ''
    ),
    -- The composite target every foreign key in this schema needs.
    UNIQUE (id, tenant_id)
);

-- Listing is always "this tenant's incidents, newest first", and the partial index keeps
-- the common case — the ones that are not closed — off the closed history.
CREATE INDEX incident_by_tenant_recent ON incident (tenant_id, started_at DESC);
CREATE INDEX incident_open_by_tenant ON incident (tenant_id, last_alert_at DESC)
    WHERE state <> 'closed';

-- The rest are the referencing sides of this table's foreign keys. Migration 0010 tells
-- the story: PostgreSQL indexes the referenced side and never the referencing one, so an
-- unindexed key makes every parent DELETE scan this table once per deleted row — and the
-- schema test in `migrations/tests/invariants.sql` fails the build without them.
CREATE INDEX incident_candidate_idx ON incident (candidate_resource_id, tenant_id);
CREATE INDEX incident_closed_by_idx ON incident (closed_by);
CREATE INDEX incident_acked_by_idx ON incident (acked_by);

-- Which alerts are in which incident, and whether each one was allowed to notify.
CREATE TABLE incident_alert (
    incident_id     uuid        NOT NULL,
    tenant_id       uuid        NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
    FOREIGN KEY (incident_id, tenant_id) REFERENCES incident (id, tenant_id) ON DELETE CASCADE,

    alert_state_id  uuid        NOT NULL,
    FOREIGN KEY (alert_state_id, tenant_id)
        REFERENCES alert_state (id, tenant_id) ON DELETE CASCADE,

    joined_at       timestamptz NOT NULL DEFAULT now(),

    -- False when §2.4's topology suppression stopped the notification for this alert.
    --
    -- The alert still fired, is still recorded and is still on the incident's timeline —
    -- suppression is about the *page at 4am*, not about the record. Stored per alert
    -- rather than per incident because the notification for the cause has to be able to
    -- say how many it suppressed, and counting them is this column.
    notified        boolean     NOT NULL DEFAULT true,

    -- How far this alert's resource is from the candidate, in topology hops. NULL when
    -- there is no candidate. It is what the screen orders the blast radius by, and it is
    -- recorded at join time because the topology may change afterwards and the incident
    -- is a statement about what was true then.
    hops_from_candidate smallint,

    -- §2.1: an alert belongs to **at most one** incident. In the schema rather than in
    -- code, because an alert in two incidents means two people are working on the same
    -- failure without either knowing.
    PRIMARY KEY (alert_state_id),
    CONSTRAINT incident_alert_hops_are_not_negative CHECK (
        hops_from_candidate IS NULL OR hops_from_candidate >= 0
    )
);

-- Reading an incident's alerts is the common query, and the composite also serves the
-- (incident_id, tenant_id) foreign key.
CREATE INDEX incident_alert_by_incident ON incident_alert (incident_id, tenant_id);
CREATE INDEX incident_alert_tenant_idx ON incident_alert (tenant_id);
-- The primary key is `alert_state_id` alone — §2.1's "at most one incident" — so the
-- (alert_state_id, tenant_id) key needs its own index.
CREATE INDEX incident_alert_by_alert ON incident_alert (alert_state_id, tenant_id);

-- Whether this tenant lets topology suppression stop a notification.
--
-- §2.4, and the reason it is a column with a default of false: suppression is the one
-- feature in this milestone that can cause a **missed outage**. It earns its way on after
-- an operator has watched it group correctly on their own estate, and switching it on is
-- a decision with an audit entry rather than a default somebody inherits.
ALTER TABLE tenant ADD COLUMN suppress_downstream_alerts boolean NOT NULL DEFAULT false;
