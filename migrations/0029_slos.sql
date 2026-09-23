-- 0029 — service level objectives. `docs/slo.md`.
--
-- One table, holding a definition. Nothing is computed here and nothing is stored that
-- could go stale: the indicator is a ratio over `service_5m`, which has carried `requests`
-- and `errors` per five-minute bucket since M8 with a 365-day TTL.
--
-- # Why there is no stored attainment
--
-- The obvious column — "current SLI" — is wrong the moment it is written, and a dashboard
-- reading a stale attainment is worse than one that waits a second for a fresh query. The
-- same reasoning migration 0028 applies to subnet utilisation.

CREATE TABLE slo (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,

    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',

    -- The service this is about — `docs/slo.md` §2.5.
    --
    -- **Not a foreign key to `resource`, deliberately.** A service appears in `service_5m`
    -- as soon as a span carries its id, and the inventory row arrives separately through
    -- identity resolution. A constraint here would refuse an objective for a service that
    -- is demonstrably running and simply has not been catalogued yet, which is exactly the
    -- moment somebody wants to set one.
    service_id  uuid        NOT NULL,

    -- The objective, as a proportion: 0.995 is "99.5% of requests succeeded".
    --
    -- Bounded strictly below 1: an SLO of 100% is not an objective, it is a statement that
    -- no error budget exists, and every burn-rate calculation divides by (1 - target).
    -- Refusing it here means the division downstream cannot produce an infinity.
    --
    -- And strictly above 0.5, because an objective that tolerates half the requests
    -- failing is a typo — most often 0.99 entered as 99.
    target      real        NOT NULL CHECK (target > 0.5 AND target < 1),

    -- Rolling, in days. `docs/slo.md` §2.3: a calendar month resets the budget at midnight
    -- on the first, which is when an outage on the 31st stops mattering — the arithmetic
    -- says so and nobody believes it.
    --
    -- At most 90: `service_5m` keeps a year, and a window longer than a quarter is a
    -- business report rather than an operational instrument. At least 1, because a window
    -- of hours is a monitor and this is not that.
    window_days int         NOT NULL CHECK (window_days BETWEEN 1 AND 90),

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- One objective per service per window. Two objectives on one service over the same
    -- window are two numbers that will be compared, and the comparison has no meaning.
    -- Two *different* windows on one service is the ordinary case — a 7-day and a 30-day
    -- objective on the same thing is how burn rate is read — so the window is in the key.
    UNIQUE (tenant_id, service_id, window_days),

    CONSTRAINT slo_has_a_name CHECK (length(trim(name)) > 0)
);

CREATE TRIGGER slo_updated_at
    BEFORE UPDATE ON slo
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX slo_by_tenant ON slo (tenant_id, name);
