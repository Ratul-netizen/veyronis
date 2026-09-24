//! Administering the people in an organization — `docs/user-administration.md`.
//!
//! `auth.rs` is about authenticating somebody who already exists. This is about the ones
//! who do not yet, the ones who should stop, and who may see which customer. The functions
//! it needs — `create_user`, `grant_role`, `revoke_role`, `disable_user` — have existed
//! since M1 and were called by seventeen test files and no production code.
//!
//! # Why the administrative operations are org-scoped and the older ones are not
//!
//! `PgStore::disable_user` takes an `ActorId` and nothing else, which is correct for a
//! caller that already knows the account is theirs to disable. A route does not: it is
//! handed an id from a URL. So every function here that acts on a named user takes the
//! organization too and puts it in the `WHERE` clause, and an id belonging to somebody
//! else's organization is simply not found. That is the same reason `role_for` returning
//! `None` is what turns a cross-tenant request into a 404.
//!
//! # Why one lock per organization rather than a cleverer statement
//!
//! `docs/user-administration.md` §4.3 said the last-administrator rule would be enforced
//! *"inside the statement that performs the change"*. Writing it showed that is not enough
//! and the document is amended rather than worked around.
//!
//! The rule is "this change must not leave a tenant with no enabled administrator". A
//! single statement can check that against its own snapshot, but two concurrent statements
//! removing *different* administrators each see the other and both commit — no row is
//! contended, so no lock is taken and nothing conflicts. The check has to exclude the other
//! change, not just the other row.
//!
//! So every operation that can change the set of enabled administrators takes a
//! transaction-scoped advisory lock on the organization first. These are rare
//! administrative acts; serialising them per organization costs nothing anybody will
//! measure, and it removes the whole class of race rather than the instance somebody
//! thought of. It is the same instrument `bootstrap` uses, for the same reason.

use chrono::{DateTime, Duration, Utc};
use uops_core::{ActorId, OrgId, Result, Role, SessionId, TenantId, TenantScope};
use uops_secrets::{PasswordHashString, session};

use crate::error::map;
use crate::store::PgStore;

/// Namespace for the administrative advisory lock, paired with a hash of the organization.
///
/// Arbitrary, and must never collide with another advisory-lock class in this application.
/// `bootstrap` uses a single-argument key; this needs two so the lock can be per
/// organization, and the two-argument form occupies a different space from the one-argument
/// form, so the values cannot collide with `BOOTSTRAP_LOCK` even by accident.
const ADMIN_LOCK_CLASS: i32 = 0x7573_6572; // "user"

/// How long an invitation is good for, when the caller does not say.
pub const INVITATION_VALID_FOR: Duration = Duration::days(7);

/// One person, as an administrator sees them.
#[derive(Clone, Debug)]
pub struct AdminUser {
    pub id: ActorId,
    pub email: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    /// `Some` when the account is suspended. Suspension is reversible and is not deletion —
    /// `docs/user-administration.md` §4.4.
    pub disabled_at: Option<DateTime<Utc>>,
    /// The one account permitted to sign in with a password when the organization requires
    /// SSO. At most one per organization, enforced by migration 0024's partial unique index.
    pub break_glass: bool,
    /// Whether a password would work. False for an SSO-only account, which is why it is
    /// reported separately from `sso_linked` rather than inferred from it.
    pub has_password: bool,
    pub sso_linked: bool,
}

/// Somebody who has been invited and has not accepted. **Not an `AdminUser`** — there is no
/// account yet, which is migration 0030's whole decision: an account created at invitation
/// time would make every mistyped address a permanent row, since users are never deleted.
#[derive(Clone, Debug)]
pub struct PendingInvitation {
    pub id: uuid::Uuid,
    pub email: String,
    pub display_name: String,
    pub invited_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub invited_by: Option<ActorId>,
}

/// An invitation, at the one moment its token exists.
#[derive(Clone, Debug)]
pub struct Invited {
    pub invitation: uuid::Uuid,
    /// Returned **once**. Only the hash is stored, so this is the only moment it exists —
    /// the same posture as a session token and an enrolment token.
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// Somebody's membership of one tenant.
#[derive(Clone, Debug)]
pub struct Member {
    pub user: ActorId,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    pub disabled: bool,
}

/// What happened to a change that must leave an administrator behind.
///
/// Three outcomes rather than a `bool`, because "there is no such user here" and "this
/// would lock everybody out" need different sentences and a caller that collapsed them
/// would produce the wrong one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Done,
    /// No such user in this organization — which is also the answer for a user in somebody
    /// else's organization.
    NoSuchUser,
    /// Refused: it would leave a tenant with no enabled administrator, and no administrator
    /// means nobody who can appoint one.
    WouldLeaveNoAdmin,
}

impl PgStore {
    /// Take the administrative lock for one organization, for the rest of this transaction.
    async fn lock_admin(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        org: OrgId,
    ) -> Result<()> {
        // tenant-exempt: a lock acquires no rows. The organization is the scope precisely
        // because the invariant spans every tenant in it.
        sqlx::query!(
            r#"SELECT pg_advisory_xact_lock($1, hashtext($2))"#,
            ADMIN_LOCK_CLASS,
            org.to_string(),
        )
        .execute(&mut **tx)
        .await
        .map_err(|e| map("organization", org.to_string(), e))?;
        Ok(())
    }

    /// Everybody in an organization, with the state an administrator acts on.
    ///
    /// Includes disabled accounts: an administrator who cannot see a suspended account
    /// cannot re-enable it, and a list that silently omits people is how somebody concludes
    /// an account was deleted. Does **not** include people who have only been invited —
    /// they have no account yet. See [`Self::pending_invitations`].
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn users_in_org(&self, org: OrgId) -> Result<Vec<AdminUser>> {
        // tenant-exempt: users belong to an organization, which sits above the tenant
        // isolation boundary — the same reason `app_user` has no tenant_id.
        let rows = sqlx::query!(
            r#"
            SELECT id, email, display_name, created_at, disabled_at, break_glass,
                   password_hash IS NOT NULL AS "has_password!",
                   idp_id IS NOT NULL        AS "sso_linked!"
              FROM app_user
             WHERE org_id = $1
             ORDER BY lower(email)
            "#,
            org as OrgId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("user", org.to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| AdminUser {
                id: r.id.into(),
                email: r.email,
                display_name: r.display_name,
                created_at: r.created_at,
                disabled_at: r.disabled_at,
                break_glass: r.break_glass,
                has_password: r.has_password,
                sso_linked: r.sso_linked,
            })
            .collect())
    }

    /// Invitations that are still live — not accepted, not superseded, not expired.
    ///
    /// Listed separately from [`Self::users_in_org`] because they are a different kind of
    /// thing, and a screen that merged them would be inviting somebody to disable a row
    /// that is not an account.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn pending_invitations(&self, org: OrgId) -> Result<Vec<PendingInvitation>> {
        // tenant-exempt: an invitation is into an organization.
        let rows = sqlx::query!(
            r#"
            SELECT id, email, display_name, created_at, expires_at, created_by
              FROM user_invitation
             WHERE org_id = $1
               AND accepted_at IS NULL AND superseded_at IS NULL AND expires_at > now()
             ORDER BY lower(email)
            "#,
            org as OrgId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("invitation", org.to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| PendingInvitation {
                id: r.id,
                email: r.email,
                display_name: r.display_name,
                invited_at: r.created_at,
                expires_at: r.expires_at,
                invited_by: r.created_by.map(Into::into),
            })
            .collect())
    }

    /// Invite somebody who has no account, superseding any live invitation to the same
    /// address.
    ///
    /// **No password is passed in and none is generated.** `docs/user-administration.md`
    /// §4.1: an administrator who sets somebody's password knows a credential that person
    /// is then accountable for, and the audit log would name them for actions somebody else
    /// could have taken.
    ///
    /// No account is created here — see migration 0030. `Ok(None)` when the address already
    /// belongs to an account in this organization, which is not an error: the caller is
    /// asking for somebody to be let in, and "they are already in" is a complete answer.
    ///
    /// Re-inviting is this same call. There is no separate resend, because superseding the
    /// previous invitation is a precondition of the partial unique index either way.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn invite_person(
        &self,
        org: OrgId,
        email: &str,
        display_name: &str,
        by: ActorId,
        valid_for: Duration,
    ) -> Result<Option<Invited>> {
        let (token, hash) =
            session::issue().map_err(|e| uops_core::Error::Storage(e.to_string()))?;
        let expires_at = Utc::now() + valid_for;

        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("invitation", email.to_owned(), e))?;

        // Case-insensitively, as `app_user_email_ci_idx` and sign-in both are.
        // tenant-exempt: as `users_in_org`.
        let already_here = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM app_user WHERE org_id = $1 AND lower(email) = lower($2)
            ) AS "already_here!"
            "#,
            org as OrgId,
            email,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("user", email.to_owned(), e))?;

        if already_here {
            return Ok(None);
        }

        // Superseded rather than deleted, so "this was re-sent three times" stays
        // answerable — which is the question an administrator has when somebody says the
        // link does not work.
        // tenant-exempt: as above.
        sqlx::query!(
            r#"
            UPDATE user_invitation SET superseded_at = now()
             WHERE org_id = $1 AND lower(email) = lower($2)
               AND accepted_at IS NULL AND superseded_at IS NULL
            "#,
            org as OrgId,
            email,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("invitation", email.to_owned(), e))?;

        // tenant-exempt: an invitation is into an organization, not a tenant — a role on a
        // tenant is granted separately, after somebody accepts.
        let row = sqlx::query!(
            r#"
            INSERT INTO user_invitation
                (org_id, email, display_name, token_hash, expires_at, created_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
            org as OrgId,
            email,
            display_name,
            hash.as_bytes().as_slice(),
            expires_at,
            by as ActorId,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("invitation", email.to_owned(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("invitation", email.to_owned(), e))?;

        Ok(Some(Invited {
            invitation: row.id,
            token: token.expose().to_owned(),
            expires_at,
        }))
    }

    /// Redeem an invitation, creating the account with the password its owner chose.
    ///
    /// `None` for a token that is wrong, expired, already used or superseded, and for one
    /// whose address has been taken by an account created in the meantime. **The caller must
    /// not distinguish those in what it returns** — the same rule sign-in follows — so they
    /// are one answer here.
    ///
    /// Single use is decided by `WHERE accepted_at IS NULL` in the `UPDATE`, so two
    /// simultaneous redemptions of one link cannot both win: the second updates no row and
    /// no second account is created.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn accept_invitation(
        &self,
        token: &str,
        password_hash: &PasswordHashString,
    ) -> Result<Option<ActorId>> {
        let hash = session::hash_of(token);

        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("invitation", String::new(), e))?;

        // Locked, not yet claimed. The obvious order — mark it accepted first, then create
        // the account — sets `accepted_at` without `accepted_user`, and 0030's
        // `user_invitation_acceptance_is_whole` refuses that intermediate state. It is right
        // to: half of that pair is only reachable by a partial write, which is the same
        // argument 0024 makes about an identity.
        //
        // `FOR UPDATE` gives the single-winner property the claiming write would have. Under
        // `READ COMMITTED` a second transaction blocks here, then re-evaluates the predicate
        // against the committed row, finds `accepted_at` set, and matches nothing — so it
        // returns `None` and creates no second account.
        //
        // tenant-exempt: the presenter of an invitation has no session and names no tenant.
        // The token is the only thing identifying anything here.
        let claimed = sqlx::query!(
            r#"
            SELECT id, org_id, email, display_name
              FROM user_invitation
             WHERE token_hash = $1
               AND accepted_at IS NULL
               AND superseded_at IS NULL
               AND expires_at > now()
            FOR UPDATE
            "#,
            hash.as_bytes().as_slice(),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map("invitation", String::new(), e))?;

        let Some(invitation) = claimed else {
            return Ok(None);
        };

        let user = ActorId::new();

        // `ON CONFLICT DO NOTHING` against `app_user_email_ci_idx` rather than a prior
        // existence check: an account for this address may have been created between the
        // invitation and this moment, and the index is the only thing that can decide that
        // without a race.
        // tenant-exempt: as `users_in_org`.
        let created = sqlx::query!(
            r#"
            INSERT INTO app_user (id, org_id, email, display_name, password_hash)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING
            "#,
            user as ActorId,
            invitation.org_id,
            invitation.email,
            invitation.display_name,
            password_hash.as_str(),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("user", invitation.email.clone(), e))?
        .rows_affected();

        if created == 0 {
            // Dropped, which releases the lock and leaves the invitation unspent: it must
            // not be consumed for an account that was not created.
            return Ok(None);
        }

        // Both columns together, which is what the constraint asks for, and after the insert
        // because `accepted_user` is a foreign key to the row it created.
        // tenant-exempt: as above.
        sqlx::query!(
            r#"
            UPDATE user_invitation SET accepted_at = now(), accepted_user = $2
             WHERE id = $1
            "#,
            invitation.id,
            user as ActorId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("invitation", String::new(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("invitation", String::new(), e))?;

        Ok(Some(user))
    }

    /// Lift a suspension.
    ///
    /// `false` when there is no such account in this organization, or it was not suspended.
    /// Sessions are **not** restored — they ended when the account was disabled and a
    /// session is not a thing to resurrect.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn enable_user(&self, org: OrgId, user: ActorId) -> Result<bool> {
        // tenant-exempt: as `users_in_org`.
        let affected = sqlx::query!(
            r#"
            UPDATE app_user SET disabled_at = NULL, updated_at = now()
             WHERE id = $1 AND org_id = $2 AND disabled_at IS NOT NULL
            "#,
            user as ActorId,
            org as OrgId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("user", user.to_string(), e))?
        .rows_affected();
        Ok(affected > 0)
    }

    /// Suspend an account, unless that would leave a tenant with no administrator.
    ///
    /// Ends every session for the account in the same transaction, so a live session stops
    /// working immediately rather than at the next idle timeout.
    ///
    /// The caller is responsible for refusing a self-disable: that is a comparison of two
    /// ids it already holds, not a question about database state, and a route that asked
    /// this function would be asking the wrong layer.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn disable_user_in_org(&self, org: OrgId, user: ActorId) -> Result<Change> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("user", user.to_string(), e))?;

        Self::lock_admin(&mut tx, org).await?;

        // tenant-exempt: as `users_in_org`.
        let present = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM app_user WHERE id = $1 AND org_id = $2) AS "p!""#,
            user as ActorId,
            org as OrgId,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("user", user.to_string(), e))?;

        if !present {
            return Ok(Change::NoSuchUser);
        }

        // Every tenant where this account is the only enabled administrator. Asked as a
        // question about tenants rather than about this user, because the invariant belongs
        // to the tenant: it must keep somebody who can appoint the next administrator.
        //
        // tenant-exempt: the question spans every tenant in the organization, so there is
        // no single scope it could be asked within — the same shape as `is_org_admin`.
        let sole = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1
                  FROM user_tenant_role mine
                  JOIN tenant t ON t.id = mine.tenant_id AND t.org_id = $2
                 WHERE mine.user_id = $1 AND mine.role = 'admin'
                   AND NOT EXISTS (
                       SELECT 1 FROM user_tenant_role other
                         JOIN app_user u ON u.id = other.user_id AND u.disabled_at IS NULL
                        WHERE other.tenant_id = mine.tenant_id
                          AND other.role = 'admin'
                          AND other.user_id <> $1
                   )
            ) AS "sole!"
            "#,
            user as ActorId,
            org as OrgId,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("role", user.to_string(), e))?;

        if sole {
            return Ok(Change::WouldLeaveNoAdmin);
        }

        // tenant-exempt: as `users_in_org`.
        sqlx::query!(
            r#"
            UPDATE app_user SET disabled_at = now(), updated_at = now()
             WHERE id = $1 AND org_id = $2 AND disabled_at IS NULL
            "#,
            user as ActorId,
            org as OrgId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("user", user.to_string(), e))?;

        // tenant-exempt: sessions are not tenant-scoped.
        sqlx::query!(
            r#"UPDATE session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL"#,
            user as ActorId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("session", user.to_string(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("user", user.to_string(), e))?;

        Ok(Change::Done)
    }

    /// Name the one account allowed to sign in with a password when the organization
    /// requires SSO, clearing whoever held it.
    ///
    /// `false` when there is no such account here. At most one per organization is migration
    /// 0024's partial unique index, and clearing the previous holder in the same transaction
    /// is what keeps this from failing on it.
    ///
    /// `docs/user-administration.md` §4.5 refuses to forbid an administrator designating
    /// themselves: they could designate any account they control, so the rule would stop
    /// nothing while reading as though it did. Every use of the path is already audited as
    /// `auth.break_glass`, and designating it is audited by the caller.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn designate_break_glass(&self, org: OrgId, user: ActorId) -> Result<bool> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("user", user.to_string(), e))?;

        // tenant-exempt: as `users_in_org`.
        let present = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM app_user WHERE id = $1 AND org_id = $2) AS "p!""#,
            user as ActorId,
            org as OrgId,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("user", user.to_string(), e))?;

        if !present {
            return Ok(false);
        }

        // tenant-exempt: as `users_in_org`.
        sqlx::query!(
            r#"UPDATE app_user SET break_glass = false WHERE org_id = $1 AND break_glass"#,
            org as OrgId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("user", org.to_string(), e))?;

        // tenant-exempt: as above. Both halves of the move are in one transaction because
        // 0024's partial unique index allows only one holder per organization.
        sqlx::query!(
            r#"UPDATE app_user SET break_glass = true, updated_at = now()
                WHERE id = $1 AND org_id = $2"#,
            user as ActorId,
            org as OrgId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("user", user.to_string(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("user", user.to_string(), e))?;

        Ok(true)
    }

    /// Who may see one tenant, and as what.
    ///
    /// Named for the tenant rather than `members_of`, which `discovery.rs` already uses for
    /// the resources in a group. Two meanings on one word in one store is how a reader ends
    /// up confidently wrong — the same reason `docs/user-administration.md` §6 refuses to
    /// call a set of people a "group".
    ///
    /// Scoped, unlike the rest of this module: this is a question about one tenant's
    /// membership and the answer is a tenant's data, so it takes a [`TenantScope`] like any
    /// other repository read.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn tenant_members(&self, scope: &TenantScope) -> Result<Vec<Member>> {
        let rows = sqlx::query!(
            r#"
            SELECT u.id, u.email, u.display_name,
                   r.role AS "role: Role",
                   u.disabled_at IS NOT NULL AS "disabled!"
              FROM user_tenant_role r
              JOIN app_user u ON u.id = r.user_id
             WHERE r.tenant_id = $1
             ORDER BY lower(u.email)
            "#,
            scope.tenant_id() as TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("role", scope.tenant_id().to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| Member {
                user: r.id.into(),
                email: r.email,
                display_name: r.display_name,
                role: r.role,
                disabled: r.disabled,
            })
            .collect())
    }

    /// Grant or change somebody's role on one tenant.
    ///
    /// Refused when it would take the last enabled administrator away from the tenant,
    /// which a *change* does as surely as a revoke: lowering the only admin to viewer leaves
    /// nobody who can put them back.
    ///
    /// The user must already belong to the organization that owns this tenant. A role is how
    /// somebody sees a customer; it is not a way to add a person.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn grant_role_guarded(
        &self,
        org: OrgId,
        scope: &TenantScope,
        user: ActorId,
        role: Role,
        by: ActorId,
    ) -> Result<Change> {
        let tenant = scope.tenant_id();
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("role", user.to_string(), e))?;

        Self::lock_admin(&mut tx, org).await?;

        // The organization is checked against the tenant's, so a caller holding admin on
        // one organization's tenant cannot grant a role to another organization's user.
        // tenant-exempt: the tenant is a bound parameter and the join is the restriction.
        let present = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM app_user u JOIN tenant t ON t.org_id = u.org_id
                 WHERE u.id = $1 AND t.id = $2 AND u.org_id = $3
            ) AS "p!"
            "#,
            user as ActorId,
            tenant as TenantId,
            org as OrgId,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map("user", user.to_string(), e))?;

        if !present {
            return Ok(Change::NoSuchUser);
        }

        if role != Role::Admin && Self::is_last_admin(&mut tx, tenant, user).await? {
            return Ok(Change::WouldLeaveNoAdmin);
        }

        sqlx::query!(
            r#"
            INSERT INTO user_tenant_role (user_id, tenant_id, role, granted_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, tenant_id)
            DO UPDATE SET role = EXCLUDED.role,
                          granted_at = now(),
                          granted_by = EXCLUDED.granted_by
            "#,
            user as ActorId,
            tenant as TenantId,
            role as Role,
            by as ActorId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("role", user.to_string(), e))?;

        tx.commit()
            .await
            .map_err(|e| map("role", user.to_string(), e))?;

        Ok(Change::Done)
    }

    /// Take somebody's role on one tenant away.
    ///
    /// Refused when they are its last enabled administrator.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn revoke_role_guarded(
        &self,
        org: OrgId,
        scope: &TenantScope,
        user: ActorId,
    ) -> Result<Change> {
        let tenant = scope.tenant_id();
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("role", user.to_string(), e))?;

        Self::lock_admin(&mut tx, org).await?;

        if Self::is_last_admin(&mut tx, tenant, user).await? {
            return Ok(Change::WouldLeaveNoAdmin);
        }

        let affected = sqlx::query!(
            r#"DELETE FROM user_tenant_role WHERE user_id = $1 AND tenant_id = $2"#,
            user as ActorId,
            tenant as TenantId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("role", user.to_string(), e))?
        .rows_affected();

        if affected == 0 {
            return Ok(Change::NoSuchUser);
        }

        tx.commit()
            .await
            .map_err(|e| map("role", user.to_string(), e))?;

        Ok(Change::Done)
    }

    /// Whether this user is the only *enabled* administrator of this tenant.
    ///
    /// Called inside the administrative lock, which is what makes the answer still true when
    /// the change lands.
    async fn is_last_admin(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: TenantId,
        user: ActorId,
    ) -> Result<bool> {
        // tenant-exempt: the tenant is the first bound parameter, from the scope.
        let sole = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM user_tenant_role mine
                 WHERE mine.tenant_id = $1 AND mine.user_id = $2 AND mine.role = 'admin'
                   AND NOT EXISTS (
                       SELECT 1 FROM user_tenant_role other
                         JOIN app_user u ON u.id = other.user_id AND u.disabled_at IS NULL
                        WHERE other.tenant_id = $1
                          AND other.role = 'admin'
                          AND other.user_id <> $2
                   )
            ) AS "sole!"
            "#,
            tenant as TenantId,
            user as ActorId,
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map("role", user.to_string(), e))?;
        Ok(sole)
    }

    /// Replace one's own password, ending every other session.
    ///
    /// Verifying the *current* password belongs to the API, which is the only layer that
    /// ever holds a plaintext — the division `auth.rs` describes. This is the write.
    ///
    /// Returns how many other sessions ended. The session named by `keep` survives:
    /// somebody changing a password because they think it leaked wants the other sessions
    /// gone, and being signed out of the tab they are typing in reads as a bug.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn set_own_password(
        &self,
        user: ActorId,
        password_hash: &PasswordHashString,
        keep: SessionId,
    ) -> Result<u64> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("user", user.to_string(), e))?;

        // tenant-exempt: a user is an organization-level record. No org is bound because
        // the caller is the account itself, established by its own session.
        sqlx::query!(
            r#"
            UPDATE app_user SET password_hash = $2, updated_at = now()
             WHERE id = $1 AND disabled_at IS NULL
            "#,
            user as ActorId,
            password_hash.as_str(),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("user", user.to_string(), e))?;

        // tenant-exempt: sessions are not tenant-scoped.
        let ended = sqlx::query!(
            r#"
            UPDATE session SET revoked_at = now()
             WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL
            "#,
            user as ActorId,
            keep as SessionId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("session", user.to_string(), e))?
        .rows_affected();

        tx.commit()
            .await
            .map_err(|e| map("user", user.to_string(), e))?;

        Ok(ended)
    }
}
