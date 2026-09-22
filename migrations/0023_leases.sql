-- Leases — M12, `docs/M12-enterprise.md` §2.1.
--
-- One row per background job that must have exactly one owner: the poll scheduler, the
-- alert evaluator, the discovery sweeper. Today each of those assumes it is the only
-- instance, and two of any of them against one database is not a degraded mode — it is
-- double the SNMP load on a customer's fleet, duplicate samples in `metrics`, and two
-- pages for one alert.
--
-- # Why PostgreSQL and not a consensus system
--
-- Every one of those processes already cannot do useful work without the control plane,
-- so a lease here adds **no new failure mode**. etcd or Consul would mean a second thing
-- that can be down and a second thing an on-premise customer has to operate, to obtain a
-- guarantee a row lock already provides.
--
-- The trade is understood: this is not a distributed consensus protocol and does not
-- pretend to be. It is correct for as long as there is one PostgreSQL, which is the same
-- assumption every other write in this product makes.
--
-- # Why leases expire rather than being released
--
-- A process that crashes cannot release anything. A lease that *needs* releasing turns a
-- crash into a stuck estate, which is the opposite of what this is for: the worst case
-- has to be a gap of one period, recovered without a human.
--
-- A clean shutdown may still release early — that is an optimisation for a rolling
-- restart, not the mechanism.

CREATE TABLE lease (
    -- The job, not the process: `poll`, `alert`, `sweep`. Global rather than per tenant,
    -- because each of those schedulers walks every tenant in one pass — a lease per
    -- tenant would mean a thousand leases renewed every ten seconds to elect the same
    -- process a thousand times.
    name        text        PRIMARY KEY,

    -- Who holds it. A process identity that changes on every start, so a restarted
    -- process does not inherit its predecessor's claim by looking like it.
    --
    -- Written for a human to read in a support conversation — hostname and pid — rather
    -- than hashed. Knowing which box holds the poll lease is the first question asked
    -- when a fleet stops being polled.
    holder      text        NOT NULL,

    -- When the claim lapses. The holder renews well before this; anything that has passed
    -- it is fair game for whoever asks next.
    expires_at  timestamptz NOT NULL,

    -- When the current holder took it. Not the same as `expires_at - period`: a lease
    -- renewed for an hour still says when the process actually started holding it, which
    -- is what an operator wants when a takeover looks too frequent.
    acquired_at timestamptz NOT NULL DEFAULT now(),

    -- How many times this lease has changed hands. A counter rather than a log, because
    -- the question it answers is "is this flapping" and the answer is a rate.
    --
    -- A lease that changes holder every period is a process that cannot renew — an
    -- overloaded database, a paused VM, a clock that jumped — and it looks identical to
    -- healthy operation unless somebody is counting.
    takeovers   bigint      NOT NULL DEFAULT 0,

    CONSTRAINT lease_name_is_known CHECK (name IN ('poll', 'alert', 'sweep')),
    -- An empty holder is a row that claims to be held by nobody, which is what an expired
    -- lease already expresses.
    CONSTRAINT lease_has_a_holder CHECK (holder <> '')
);

-- The three jobs, pre-seeded and already expired.
--
-- Seeded rather than created on first claim, so that acquiring is an `UPDATE` with no
-- insert path — which is what makes it a single statement with no race. Two processes
-- starting at once both run the same `UPDATE … WHERE expires_at < now()`, and exactly one
-- row is affected because the other is blocked on the row lock and then finds the
-- predicate false.
--
-- `to_timestamp(0)` rather than `now()`: the first process to start should take the lease
-- immediately rather than waiting out a period nobody held.
INSERT INTO lease (name, holder, expires_at, acquired_at)
VALUES
    ('poll',  'unclaimed', to_timestamp(0), to_timestamp(0)),
    ('alert', 'unclaimed', to_timestamp(0), to_timestamp(0)),
    ('sweep', 'unclaimed', to_timestamp(0), to_timestamp(0));
