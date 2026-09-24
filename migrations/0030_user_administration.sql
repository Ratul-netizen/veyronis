-- 0030 — user administration. `docs/user-administration.md`.
--
-- The store functions this makes reachable have existed since M1 and were called by
-- seventeen test files and no production code. What was missing was a way to invite
-- somebody who does not have an account yet.
--
-- # Why the account does not exist until the invitation is accepted
--
-- The first draft of this migration created the account immediately, with no password, and
-- 0024's `app_user_can_authenticate_somehow` refused it — correctly. That constraint says:
--
-- > An account with neither a password nor a provider identity cannot authenticate at all.
-- > It is not a locked account — `disabled_at` is how one of those is written — it is a row
-- > that nothing can ever match, and it would be created by a partial write rather than by
-- > intent.
--
-- An invited account is the *intentional* version of exactly that state, so the choice was
-- to name it in the constraint or to not create the row yet. Not creating it wins, and the
-- deciding argument is not purity: `docs/user-administration.md` §4.4 offers no way to
-- delete a user, because `audit_log` and `access_log` name their actor. An account created
-- at invitation time would mean every mistyped email address is a permanent, undeletable
-- row in the user list. An unredeemed invitation is not a person yet, so it can simply
-- expire.
--
-- The consequence, recorded because it is a real cost: a role cannot be granted before
-- somebody accepts. That is arguably the right shape anyway — a role is granted to a person
-- who exists — but it is a consequence and not a feature.

CREATE TABLE user_invitation (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The organization they are being invited into. Users belong to an organization rather
    -- than a tenant, which is why a role has to be granted separately afterwards.
    org_id        uuid        NOT NULL REFERENCES organization (id) ON DELETE CASCADE,

    -- Who they will be. Held here rather than on `app_user` for the reason above. The
    -- address is not verified by anything except the fact that the invitation reaches it.
    email         text        NOT NULL,
    display_name  text        NOT NULL,

    -- The HASH, never the token. Same posture as `session.token_hash` in 0006 and
    -- `collector_enrolment_token.token_hash` in 0025, and the same reasoning: a stolen
    -- database backup must not hand the thief a set of working invitations. The token is
    -- high-entropy random, so a plain SHA-256 is right — there is no low-entropy secret
    -- here to make expensive.
    token_hash    bytea       NOT NULL UNIQUE,

    -- NOT NULL, unlike an enrolment token's. An enrolment token lives in a
    -- configuration-management repository and brings up collectors for years; an invitation
    -- is a message to one person that should stop working if they never read it. The
    -- interval is the caller's, so the policy is not frozen in the schema.
    expires_at    timestamptz NOT NULL,

    created_at    timestamptz NOT NULL DEFAULT now(),
    -- Who invited them. Every route that issues one is behind `OrgAdmin` and has a user to
    -- name; NULL is left available for a future automated path.
    created_by    uuid        REFERENCES app_user (id),

    -- Single use. The accept path is `UPDATE … WHERE accepted_at IS NULL`, so the database
    -- decides which of two concurrent redemptions wins rather than a check in the caller.
    accepted_at   timestamptz,
    -- The account it turned into, once redeemed. The link between an invitation and the
    -- person it produced, which is what makes "who let them in" answerable later.
    accepted_user uuid        REFERENCES app_user (id),

    -- Set when a *later* invitation to the same address is issued. Kept rather than deleted
    -- so that "this was re-sent three times" is answerable, which is the question an
    -- administrator actually has when somebody says the link does not work.
    superseded_at timestamptz,

    CONSTRAINT user_invitation_expires_after_creation CHECK (expires_at > created_at),
    -- Accepted and the account it produced arrive together or not at all. The same shape as
    -- 0024's `app_user_idp_identity_is_whole`, and for the same reason: half of this pair is
    -- only reachable by a partial write.
    CONSTRAINT user_invitation_acceptance_is_whole
        CHECK (num_nonnulls(accepted_at, accepted_user) IN (0, 2))
);

-- At most one live invitation per address per organization. Resending supersedes the
-- previous one in the same transaction as issuing the next, and this is what makes that a
-- rule rather than a habit. Case-insensitive to match `app_user_email_ci_idx`: an invitation
-- to `Ratul@` and one to `ratul@` are the same invitation, and two of them racing to accept
-- would be two accounts for one person.
CREATE UNIQUE INDEX user_invitation_one_live_per_email
    ON user_invitation (org_id, lower(email))
    WHERE accepted_at IS NULL AND superseded_at IS NULL;

CREATE INDEX user_invitation_org_idx ON user_invitation (org_id);
CREATE INDEX user_invitation_accepted_user_idx ON user_invitation (accepted_user);

-- Nothing here for the break-glass designation. Migration 0024 already created
-- `app_user_one_break_glass_per_org` — a partial unique index on `(org_id) WHERE
-- break_glass` — so "at most one per organization" is enforced and this migration adds
-- nothing. Said out loud because a first draft of this file created it a second time and
-- the migration failed on the duplicate, which is the cheapest possible way to learn that
-- the invariant was already someone else's decision.
