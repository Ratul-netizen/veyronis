-- 0028 — address space, declared. `docs/ipam.md`.
--
-- One table, and the smallness is the point. Everything else an address-management screen
-- shows is already in this database and is computed at read time:
--
--   * which addresses belong to something  → `resource_identifier`, kind = 'mgmt_ip'
--   * which addresses answered             → `discovery_candidate.address`
--   * which MAC is behind one              → ARP, already walked by `uops-discover`
--   * when each was last seen              → `last_seen` on both
--
-- What cannot be computed is which ranges an operator *cares about*. `docs/ipam.md` §2.1
-- records why that is not derived from `discovery_job.ranges`: a job that sweeps a /16
-- sweeps two hundred and fifty-six /24s, so utilisation over it is a number nobody can act
-- on — and a DHCP scope or a reserved range is address space to manage that nobody sweeps.
-- Deriving would also make the discovery configuration load-bearing for an unrelated
-- feature, so editing a sweep would silently change the address inventory.
--
-- Nothing here stores a utilisation figure. A stored one is wrong between refreshes, and
-- the query that computes it is cheap.

-- ----------------------------------------------------------------------------
-- The arithmetic, in one place
-- ----------------------------------------------------------------------------
--
-- Beside the table rather than in the application, for the reason migration 0017 gives
-- about its own caps: *"a limit that lives only in the application is one a second caller
-- does not have."* The same holds for a formula.
--
-- **/31 and /32 are not edge cases to apologise for.** A /31 is a point-to-point link with
-- two usable addresses (RFC 3021) and a /32 is a single host; both are ordinary in a routed
-- estate. The textbook `2^(32-masklen) - 2` returns 0 for a /31 and -1 for a /32, so a
-- screen using it would report negative capacity on every loopback in the estate.
CREATE FUNCTION subnet_usable_addresses(range cidr) RETURNS bigint
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT CASE
        -- One host. Its own address is the usable one.
        WHEN masklen(range) = 32 THEN 1
        -- A point-to-point link: no network or broadcast address is reserved.
        WHEN masklen(range) = 31 THEN 2
        -- Everything else loses the network and the broadcast address.
        ELSE (2::numeric) ^ (32 - masklen(range)) - 2
    END::bigint
$$;

-- ----------------------------------------------------------------------------
-- The declaration
-- ----------------------------------------------------------------------------
CREATE TABLE subnet (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,

    -- `cidr` rather than text, for the reason 0017 gives: the type refuses 10.0.0.300/24
    -- and normalises 10.0.0.5/24 to 10.0.0.0/24, so two operators cannot enter the same
    -- range in two spellings and get two rows.
    range       cidr        NOT NULL,

    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',

    -- Which site this range serves. Optional, because a range that spans sites or belongs
    -- to none is ordinary — and composite, so a subnet cannot reference another tenant's
    -- site. The same mechanism tenant isolation has used since 0002.
    site_id     uuid,

    -- How the addresses in it are handed out. A declaration, **not** an integration: the
    -- product does not speak to a DHCP server, and `docs/ipam.md` §2.6 is explicit that
    -- this is an inventory of what the estate said rather than an authoritative registry.
    -- It exists because utilisation of a DHCP pool is read differently from utilisation of
    -- a statically-assigned range, and a reader cannot tell which they are looking at
    -- without being told.
    assignment  text        NOT NULL DEFAULT 'static'
                            CHECK (assignment IN ('static', 'dhcp', 'reserved')),

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- One row per range per tenant. Two operators declaring 10.0.1.0/24 twice is one
    -- subnet described twice, and the second attempt should say so rather than produce a
    -- second set of numbers that will diverge.
    --
    -- Deliberately *not* unique on `name`: two sites legitimately both have a range called
    -- "Voice", and `resource` made the same choice for the same reason.
    UNIQUE (tenant_id, range),

    CONSTRAINT subnet_site_is_in_this_tenant
        FOREIGN KEY (site_id, tenant_id) REFERENCES site (id, tenant_id),

    -- IPv4 only, and the schema says so rather than the handler. `docs/ipam.md` §2.2: on a
    -- /64 the capacity arithmetic returns a number with no meaning, and IPv6 address
    -- management asks different questions — which prefixes are delegated, what is in use —
    -- rather than how full a range is. A product that reported a utilisation percentage
    -- for a /64 would be stating something false.
    CONSTRAINT subnet_is_ipv4 CHECK (family(range) = 4),

    CONSTRAINT subnet_has_a_name CHECK (length(trim(name)) > 0)
);

CREATE TRIGGER subnet_updated_at
    BEFORE UPDATE ON subnet
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The listing is per tenant and ordered by range, which is how an operator reads address
-- space — 10.0.0.0/24 before 10.0.1.0/24, not alphabetically by name.
CREATE INDEX subnet_by_tenant ON subnet (tenant_id, range);

-- ----------------------------------------------------------------------------
-- Why there is no index on the addresses
-- ----------------------------------------------------------------------------
--
-- The utilisation read filters `resource_identifier` and `discovery_candidate` by
-- `address << range`, which no btree can accelerate. Both tables are already scoped to one
-- tenant by an index that exists, and an estate's address inventory is thousands of rows
-- rather than millions — the telemetry planes are where the volume is. A GiST index on
-- `inet` would be storage and write cost against a scan that is already small.
--
-- If that stops being true the fix is a `gist (tenant_id, address inet_ops)` on each, and
-- this comment is the note saying so.
