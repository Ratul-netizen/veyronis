-- 0032 — per-tenant ingest tokens. `docs/packaging.md` §4.2.
--
-- The blocker for handing an agent to anybody. `deploy/otlp/listeners.yaml` records the
-- position this replaces:
--
-- > An OTLP request carries resource attributes that describe the EMITTER — `host.id`,
-- > `service.name` — and nothing that says which customer it belongs to. Anything that did
-- > would be a field the sender controls.
-- >
-- > The alternative is stronger here than it was for syslog and is still not taken: OTLP
-- > exporters send arbitrary headers, so a per-tenant token would be idiomatic and would let
-- > one endpoint serve every tenant. It is deferred because it is a new credential type —
-- > something to mint, show once, rotate, revoke and audit — and `uops-secrets` already owns
-- > those decisions.
--
-- So the trust boundary today is the network segment: whatever can reach the listener writes
-- into its tenant. That is defensible for a concentrator inside a datacenter and is not
-- something to hand to fifty machines across an estate.
--
-- # The fourth credential, and deliberately not a new posture
--
-- Session tokens (0006), collector enrolment tokens (0025), user invitations (0030), and now
-- this. High-entropy random, SHA-256 at rest, shown once, revocable, carrying a label somebody
-- will recognise in six months. 0025's reasoning about the hash applies unchanged: the token
-- has no low-entropy secret in it, so there is nothing to make expensive.

CREATE TABLE ingest_token (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- One tenant. That is the whole point: it is the fact the listener could not infer from
    -- the payload, and the reason this table exists rather than a per-listener flag.
    --
    -- Cascading for the same reason 0030's invitations do, and with the same caveat: since
    -- 0031, removing a tenant is *retirement* rather than deletion, so this rarely fires. What
    -- does the work of stopping a retired tenant's traffic is the `retired_at` check in the
    -- authentication query — see `uops_store_pg::ingest`.
    tenant_id    uuid        NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,

    -- What an operator calls this token: "berlin-hosts", "laptop-fleet-2026q4". The same
    -- reasoning as `collector_enrolment_token.label`: a list of hashes is a list nobody can
    -- act on, and the question at revocation time is "which one is this".
    label        text        NOT NULL,

    -- The HASH, never the token.
    token_hash   bytea       NOT NULL UNIQUE,

    -- NULL means it does not expire, which is right for a token living in a
    -- configuration-management repository that brings up emitters for years. An operator who
    -- wants the tighter posture for a laptop fleet sets it.
    expires_at   timestamptz,

    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   uuid        REFERENCES app_user (id),

    -- Revocation is immediate and per token, which is why tokens are per *label* rather than
    -- one per tenant: revoking the only token a tenant has would stop every emitter it has.
    revoked_at   timestamptz,

    UNIQUE (tenant_id, label)
);

-- The authentication path is one probe on this, on the ingest hot path.
-- `token_hash` already has a UNIQUE index, which is that probe; this one is for the list an
-- operator reads.
CREATE INDEX ingest_token_tenant_idx ON ingest_token (tenant_id);

-- Deliberately absent: `last_used_at`.
--
-- It is the first column anybody asks for — "is this still in use before I revoke it" is a
-- real question. It is also a write on every ingested request, which on an OTLP endpoint is
-- the hottest path this product has, to record a fact that is stale the moment it is read. The
-- collector registry (M12 §2.3) already reports throughput per collector, which answers the
-- operator's actual question without a write per request.
--
-- If it is ever added it should be coarse — a bounded periodic flush, not an UPDATE per
-- request — and that is a decision, not an oversight.
