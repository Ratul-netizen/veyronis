-- 0024 — OpenID Connect single sign-on. M12 §2.2, `docs/M12-enterprise.md`.
--
-- # Sign-on is an *organization* property, not a tenant one
--
-- The milestone document said "a tenant may require SSO", and writing the schema is what
-- showed that sentence to be unimplementable. Authentication in this product happens
-- before any tenant is known: a user types an address, `app_user` is keyed on
-- `(org_id, email)`, and `user_tenant_role` — which is where tenants first appear — is
-- consulted *after* the password has already been checked. A per-tenant rule would have
-- to be enforced at a point where the answer it needs does not exist yet.
--
-- So `require_sso` sits on `organization`, and M12 §2.2 has been amended to say so. That
-- is also the right boundary on its own terms: requiring SSO is a statement about an
-- identity provider, an identity provider belongs to a company, and a company is an
-- organization here.
--
-- # Several providers per organization
--
-- Not one. An MSP that has acquired another MSP has two identity providers and will have
-- both for years, and a schema that allows one would make that a migration project.
-- The sign-in page lists them; the flow names one.

-- Needed by `identity_provider_grant` below, which is a composite foreign key on
-- `(tenant_id, org_id)` — the mechanism this schema has used since 0002 to make a row in
-- one tenant unable to reference a row in another. `tenant` never needed one because
-- nothing above it referenced it that way.
ALTER TABLE tenant ADD CONSTRAINT tenant_id_is_org_scoped UNIQUE (id, org_id);

CREATE TABLE identity_provider (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid        NOT NULL REFERENCES organization (id) ON DELETE CASCADE,

    -- What the sign-in button says. "Sign in with Acme SSO".
    name         text        NOT NULL,

    -- The `iss` in every token from this provider, compared **exactly** — no trailing
    -- slash forgiven, no case folding. See uops_oidc::token::Expected.
    issuer       text        NOT NULL,
    client_id    text        NOT NULL,

    -- Which claim carries group membership. Providers disagree: `groups` for Okta and
    -- Keycloak, and whatever an Entra ID administrator named their optional claim.
    -- A column rather than a constant, because it is their decision and not ours.
    groups_claim text        NOT NULL DEFAULT 'groups',

    -- The client secret, sealed — uops_secrets::envelope. Six columns because that is
    -- what an envelope is, and spelling them out beats a jsonb blob whose shape is
    -- enforced nowhere.
    --
    -- All NULL is legitimate: a public client, authenticated by PKCE alone. That is the
    -- correct configuration for a provider that will not issue a confidential client,
    -- and PKCE is on unconditionally, so it is not a weakening.
    kek_id       text,
    wrapped_dek  bytea,
    dek_nonce    bytea,
    ciphertext   bytea,
    nonce        bytea,
    backend_id   text,

    -- Disabled rather than deleted, so that the users provisioned through it keep an
    -- intact `idp_id` and the audit log stays readable. A disabled provider refuses
    -- sign-in and does not appear on the sign-in page.
    enabled      boolean     NOT NULL DEFAULT true,

    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    -- Six columns that mean one thing. Half-written is not a state: a row with a
    -- ciphertext and no KEK id is a secret nobody can open, and it would be discovered
    -- at the next sign-in rather than at the write that caused it.
    CONSTRAINT identity_provider_secret_is_whole CHECK (
        num_nonnulls(kek_id, wrapped_dek, dek_nonce, ciphertext, nonce, backend_id)
        IN (0, 6)
    ),

    -- Two providers in one organization with the same issuer would make "which provider
    -- minted this token" unanswerable, and that question is the first step of every
    -- verification.
    UNIQUE (org_id, issuer),

    -- The target of the composite keys below. Same mechanism as everywhere else in this
    -- schema; here it keeps a grant and a provisioned user inside one organization.
    UNIQUE (id, org_id)
);

-- Not partial, although only enabled providers are ever listed. This index's other job
-- is to support the foreign key to `organization`: a partial one leaves the DELETE of an
-- organization scanning for its disabled providers, which is the row set most likely to
-- still be there when somebody removes a customer.
CREATE INDEX identity_provider_org_idx ON identity_provider (org_id);

CREATE TRIGGER identity_provider_set_updated_at
    BEFORE UPDATE ON identity_provider
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- M12 §2.2: group-to-role mapping is configuration, not inference.
--
-- One row per (provider, group, tenant). A group may grant a role on several tenants —
-- which is the MSP case — and several groups may grant roles on one tenant, where
-- uops_oidc::mapping takes the highest.
CREATE TABLE identity_provider_grant (
    provider_id uuid        NOT NULL,
    -- Carried rather than joined, because it is half of both composite keys below. That
    -- is what makes "a grant cannot name another organization's tenant" a schema fact
    -- rather than something the application remembers to check.
    org_id      uuid        NOT NULL,

    -- As the provider sends it: a name from Okta, an object id from Entra ID. Opaque
    -- here on purpose.
    group_name  text        NOT NULL,
    tenant_id   uuid        NOT NULL,
    role        tenant_role NOT NULL,

    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid        REFERENCES app_user (id),

    PRIMARY KEY (provider_id, group_name, tenant_id),

    FOREIGN KEY (provider_id, org_id)
        REFERENCES identity_provider (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, org_id)
        REFERENCES tenant (id, org_id) ON DELETE CASCADE
);

-- One index per foreign key, in the key's own column order. PostgreSQL indexes the
-- referenced side automatically and the referencing side never, so without these a
-- deleted provider or tenant scans this table once per row — see the guard at the end of
-- `migrations/tests/invariants.sql`, which is what caught their absence.
CREATE INDEX identity_provider_grant_provider_idx
    ON identity_provider_grant (provider_id, org_id);
CREATE INDEX identity_provider_grant_tenant_idx
    ON identity_provider_grant (tenant_id, org_id);
CREATE INDEX identity_provider_grant_created_by_idx
    ON identity_provider_grant (created_by);

-- ----------------------------------------------------------------------------
-- What an account gained
-- ----------------------------------------------------------------------------

-- The provider's own identifier for this person, and which provider issued it.
--
-- `sub` rather than the email address, and this is the decision worth recording: an
-- address is reassigned when somebody leaves and their replacement is given it, and an
-- account keyed on one would hand the leaver's access to the new hire silently. `sub` is
-- stable for the life of the account at the provider and is reused for nobody.
ALTER TABLE app_user
    ADD COLUMN idp_id            uuid,
    ADD COLUMN idp_subject       text,
    ADD COLUMN idp_last_login_at timestamptz,
    -- M12 §2.2: the named account that may still use a password when the organization
    -- requires SSO. Its use is an audit event, which uops-api writes.
    ADD COLUMN break_glass       boolean NOT NULL DEFAULT false;

-- A user provisioned through SSO has no password, and that is the honest representation.
-- The alternative — a random hash nobody holds — is a row that claims to have a password
-- and cannot say so is untrue, which is exactly the kind of lie that survives into a
-- security questionnaire.
ALTER TABLE app_user ALTER COLUMN password_hash DROP NOT NULL;

ALTER TABLE app_user
    -- Both halves of an external identity, or neither.
    ADD CONSTRAINT app_user_idp_identity_is_whole
        CHECK (num_nonnulls(idp_id, idp_subject) IN (0, 2)),

    -- An account with neither a password nor a provider identity cannot authenticate at
    -- all. It is not a locked account — `disabled_at` is how one of those is written —
    -- it is a row that nothing can ever match, and it would be created by a partial
    -- write rather than by intent.
    ADD CONSTRAINT app_user_can_authenticate_somehow
        CHECK (password_hash IS NOT NULL OR idp_id IS NOT NULL),

    -- The break-glass account exists for the day the identity provider is unreachable.
    -- One without a password would be useless on exactly that day.
    ADD CONSTRAINT app_user_break_glass_has_a_password
        CHECK (NOT break_glass OR password_hash IS NOT NULL),

    ADD CONSTRAINT app_user_idp_belongs_to_the_same_org
        FOREIGN KEY (idp_id, org_id) REFERENCES identity_provider (id, org_id);

-- One account per subject per provider. Without this, a second sign-in that failed to
-- find the first account would provision a duplicate, and the two would drift — one
-- holding the roles and the other receiving the logins.
CREATE UNIQUE INDEX app_user_idp_subject_idx
    ON app_user (idp_id, idp_subject) WHERE idp_id IS NOT NULL;

-- And the same foreign-key index again, for `(idp_id, org_id)`. The unique index above
-- does not serve it: its columns are the wrong pair, and it is partial besides.
CREATE INDEX app_user_idp_idx ON app_user (idp_id, org_id);

-- At most one break-glass account per organization.
--
-- A deliberate limit rather than a technical one. The account's whole value is that its
-- use is exceptional and noticed; a second one halves that, a fifth one ends it, and
-- "how many break-glass accounts does this deployment have" is a question an auditor
-- asks and the answer should not be "however many somebody made".
CREATE UNIQUE INDEX app_user_one_break_glass_per_org
    ON app_user (org_id) WHERE break_glass;

-- ----------------------------------------------------------------------------
-- Requiring SSO
-- ----------------------------------------------------------------------------

-- M12 §2.2: local passwords are not removed; an organization may *require* SSO.
--
-- An air-gapped deployment may have no identity provider at all, and an installation
-- whose provider is unreachable must still be enterable by the person fixing it. The
-- rule is therefore a property of the organization that has one, not a build-time
-- decision that removes password login from the product.
ALTER TABLE organization ADD COLUMN require_sso boolean NOT NULL DEFAULT false;

-- ----------------------------------------------------------------------------
-- The audit log gains events that are above a tenant
-- ----------------------------------------------------------------------------
--
-- `audit_log.tenant_id` has been NOT NULL since 0006, because until now every auditable
-- act was an act on one customer's data. Authentication is not: signing in, configuring
-- an identity provider, and using the break-glass account all happen before any tenant
-- is chosen, and two of them are exactly the events an auditor asks about first.
--
-- Writing them against an arbitrary tenant would be a lie — and specifically the kind of
-- lie that an auditor reading the log has to be told about afterwards, which is worse
-- than a gap. So `tenant_id` becomes nullable, NULL means "organization-level", and
-- `org_id` says which organization.
--
-- No foreign key on `org_id`, for the same reason 0006 gives for the rest of this table:
-- the log outlives its subjects on purpose, and a cascade here would remove exactly the
-- rows an investigation needs at exactly the moment somebody wanted them gone.
ALTER TABLE audit_log ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE audit_log ADD COLUMN org_id uuid;

-- A row attributable to neither is a row nobody can find.
ALTER TABLE audit_log ADD CONSTRAINT audit_log_is_attributable
    CHECK (num_nonnulls(tenant_id, org_id) >= 1);

CREATE INDEX audit_log_org_at_idx ON audit_log (org_id, at DESC) WHERE tenant_id IS NULL;
