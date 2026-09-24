//! Administering people, against a real PostgreSQL — `docs/user-administration.md`.
//!
//! The functions these exercise mostly existed before this file did. What did not exist was
//! any caller, and seventeen test files already called `create_user` directly — which is
//! exactly why nobody noticed. So the assertions here are about the *rules*, not about the
//! inserts: that an invitation works once, that a suspension ends a session, and above all
//! that a tenant cannot be left with nobody who can appoint an administrator.

use chrono::Duration;
use uops_core::{ActorId, OrgId, Result, Role, SessionId, TenantId, TenantScope};
use uops_secrets::{PasswordHashString, password, session};
use uops_store_pg::{Change, Config, PgStore};

fn url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into())
}

async fn store() -> PgStore {
    PgStore::connect(&Config {
        url: url(),
        ..Config::default()
    })
    .await
    .expect("connect")
}

fn hash(of: &str) -> PasswordHashString {
    password::hash(&uops_core::Secret::new(of.to_owned())).expect("hash")
}

/// One organization and one tenant, fresh, so these never contend with each other.
struct World {
    store: PgStore,
    org: OrgId,
    tenant: TenantId,
}

impl World {
    async fn new(slug: &str) -> Self {
        let store = store().await;
        let org = OrgId::new();
        sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
            .bind(org.into_uuid())
            .bind(format!("users-{slug}-{}", org.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("organization");

        let tenant = TenantId::new();
        sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
            .bind(tenant.into_uuid())
            .bind(org.into_uuid())
            .bind(format!("users-{slug}"))
            .bind(format!("{slug}-{}", tenant.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("tenant");

        Self { store, org, tenant }
    }

    fn scope(&self) -> TenantScope {
        TenantScope::system(self.tenant)
    }

    /// Somebody who already has a password, optionally an admin on the tenant.
    async fn person(&self, local: &str, role: Option<Role>) -> ActorId {
        let email = format!("{local}-{}@example.test", ActorId::new().into_uuid().simple());
        let user = self
            .store
            .create_user(self.org, &email, local, &hash("correct horse"))
            .await
            .expect("user");
        if let Some(role) = role {
            self.store
                .grant_role(user, self.tenant, role, None)
                .await
                .expect("role");
        }
        user
    }

    async fn live_sessions(&self, user: ActorId) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM session WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user.into_uuid())
        .fetch_one(self.store.pool())
        .await
        .expect("count")
    }

    async fn open_session(&self, user: ActorId) -> SessionId {
        let (_, h) = session::issue().expect("token");
        self.store
            .create_session(user, &h, None)
            .await
            .expect("session")
    }

    async fn find(&self, user: ActorId) -> uops_store_pg::AdminUser {
        self.store
            .users_in_org(self.org)
            .await
            .expect("list")
            .into_iter()
            .find(|u| u.id == user)
            .expect("the user is in its own organization's list")
    }
}

// ---- invitations ------------------------------------------------------------------

/// The finding that reshaped migration 0030. The first draft created the account at
/// invitation time, and 0024's `app_user_can_authenticate_somehow` refused it — an account
/// with neither a password nor a provider identity is a row nothing can ever match. Since
/// §4.4 offers no way to delete a user, creating one per invitation would have made every
/// mistyped address permanent.
#[tokio::test]
async fn nobody_exists_until_they_accept() -> Result<()> {
    let w = World::new("invited").await;
    let by = w.person("admin", Some(Role::Admin)).await;
    let email = format!("new-{}@example.test", ActorId::new().into_uuid().simple());

    let invited = w
        .store
        .invite_person(w.org, &email, "New Person", by, Duration::days(7))
        .await?
        .expect("invited");

    assert!(
        !w.store
            .users_in_org(w.org)
            .await?
            .iter()
            .any(|u| u.email == email),
        "an unaccepted invitation is not an account, so it is not in the user list"
    );
    let pending = w.store.pending_invitations(w.org).await?;
    assert!(
        pending.iter().any(|i| i.email == email && i.invited_by == Some(by)),
        "{pending:?}"
    );

    let user = w
        .store
        .accept_invitation(&invited.token, &hash("their own choice"))
        .await?
        .expect("accepted");

    let listed = w.find(user).await;
    assert_eq!(listed.email, email);
    assert!(listed.has_password, "the password is the one they chose");
    assert!(!listed.sso_linked);
    assert!(
        w.store.pending_invitations(w.org).await?.iter().all(|i| i.email != email),
        "an accepted invitation is no longer outstanding"
    );
    Ok(())
}

#[tokio::test]
async fn an_invitation_works_exactly_once() -> Result<()> {
    let w = World::new("once").await;
    let by = w.person("admin", Some(Role::Admin)).await;
    let invited = w
        .store
        .invite_person(
            w.org,
            &format!("once-{}@example.test", ActorId::new().into_uuid().simple()),
            "Once",
            by,
            Duration::days(7),
        )
        .await?
        .expect("invited");

    assert!(
        w.store
            .accept_invitation(&invited.token, &hash("first"))
            .await?
            .is_some()
    );
    assert!(
        w.store
            .accept_invitation(&invited.token, &hash("second"))
            .await?
            .is_none(),
        "a spent link must not produce a second account or replace a working password"
    );
    assert_eq!(
        w.store.users_in_org(w.org).await?.len(),
        2,
        "the admin and the one person who accepted — not two of them"
    );
    Ok(())
}

/// Aged rather than born expired. 0030 has `CHECK (expires_at > created_at)`, so an
/// invitation that is dead on arrival cannot be created at all — which is the constraint
/// doing its job and is why this backdates both columns instead of passing a negative
/// interval.
#[tokio::test]
async fn an_expired_invitation_is_refused() -> Result<()> {
    let w = World::new("expired").await;
    let by = w.person("admin", Some(Role::Admin)).await;
    let invited = w
        .store
        .invite_person(
            w.org,
            &format!("stale-{}@example.test", ActorId::new().into_uuid().simple()),
            "Stale",
            by,
            Duration::days(7),
        )
        .await?
        .expect("invited");

    sqlx::query(
        "UPDATE user_invitation
            SET created_at = now() - interval '30 days',
                expires_at = now() - interval '1 day'
          WHERE id = $1",
    )
    .bind(invited.invitation)
    .execute(w.store.pool())
    .await
    .expect("age the invitation");

    assert!(
        w.store
            .accept_invitation(&invited.token, &hash("too late"))
            .await?
            .is_none()
    );
    assert!(
        w.store.pending_invitations(w.org).await?.is_empty(),
        "and it is not offered as outstanding either"
    );
    Ok(())
}

#[tokio::test]
async fn a_wrong_token_is_refused_the_same_way() -> Result<()> {
    let w = World::new("wrongtoken").await;
    assert!(
        w.store
            .accept_invitation("not a token anybody issued", &hash("hopeful"))
            .await?
            .is_none(),
        "and indistinguishably from an expired one — the rule sign-in follows"
    );
    Ok(())
}

#[tokio::test]
async fn re_inviting_invalidates_the_previous_link() -> Result<()> {
    let w = World::new("resend").await;
    let by = w.person("admin", Some(Role::Admin)).await;
    let email = format!("re-{}@example.test", ActorId::new().into_uuid().simple());

    let first = w
        .store
        .invite_person(w.org, &email, "Re", by, Duration::days(7))
        .await?
        .expect("first");
    let second = w
        .store
        .invite_person(w.org, &email, "Re", by, Duration::days(7))
        .await?
        .expect("second");
    assert_ne!(first.token, second.token);

    assert_eq!(
        w.store.pending_invitations(w.org).await?.iter().filter(|i| i.email == email).count(),
        1,
        "one live invitation per address, or two links race to make two accounts"
    );
    assert!(
        w.store
            .accept_invitation(&first.token, &hash("old link"))
            .await?
            .is_none(),
        "the superseded link is dead — otherwise re-sending widens the window instead of \
         moving it"
    );
    assert!(
        w.store
            .accept_invitation(&second.token, &hash("new link"))
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn inviting_an_address_that_already_has_an_account_is_a_no_op() -> Result<()> {
    let w = World::new("hasped").await;
    let admin = w.person("admin", Some(Role::Admin)).await;
    let settled = w.person("settled", Some(Role::Viewer)).await;
    let email = w.find(settled).await.email;

    assert!(
        w.store
            .invite_person(w.org, &email, "Again", admin, Duration::days(7))
            .await?
            .is_none(),
        "re-inviting somebody who has a password would be a password reset, which is a \
         different decision"
    );
    // Upper-cased, because `app_user_email_ci_idx` and sign-in both match case-insensitively
    // and two accounts differing only in case is an account-takeover vector.
    assert!(
        w.store
            .invite_person(w.org, &email.to_uppercase(), "Again", admin, Duration::days(7))
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn an_invitation_only_creates_an_account_in_its_own_organization() -> Result<()> {
    let mine = World::new("imine").await;
    let theirs = World::new("itheirs").await;
    let by = theirs.person("admin", Some(Role::Admin)).await;
    let email = format!("x-{}@example.test", ActorId::new().into_uuid().simple());

    let invited = theirs
        .store
        .invite_person(theirs.org, &email, "Theirs", by, Duration::days(7))
        .await?
        .expect("invited");

    let user = theirs
        .store
        .accept_invitation(&invited.token, &hash("theirs"))
        .await?
        .expect("accepted");

    assert!(
        theirs.store.users_in_org(theirs.org).await?.iter().any(|u| u.id == user),
        "the account belongs to the organization that invited them"
    );
    assert!(
        !mine.store.users_in_org(mine.org).await?.iter().any(|u| u.id == user),
        "and to no other, whatever the token holder does"
    );
    Ok(())
}

// ---- suspension -------------------------------------------------------------------

#[tokio::test]
async fn disabling_ends_every_live_session() -> Result<()> {
    let w = World::new("ends").await;
    w.person("keeper", Some(Role::Admin)).await; // so the leaver is not the last admin
    let leaver = w.person("leaver", Some(Role::Admin)).await;

    w.open_session(leaver).await;
    w.open_session(leaver).await;
    assert_eq!(w.live_sessions(leaver).await, 2);

    assert_eq!(
        w.store.disable_user_in_org(w.org, leaver).await?,
        Change::Done
    );
    assert_eq!(
        w.live_sessions(leaver).await,
        0,
        "a departing employee's open tab must stop working now, not in twelve hours"
    );
    Ok(())
}

#[tokio::test]
async fn the_last_administrator_cannot_be_disabled() -> Result<()> {
    let w = World::new("lastadmin").await;
    let only = w.person("only", Some(Role::Admin)).await;
    w.person("viewer", Some(Role::Viewer)).await;

    assert_eq!(
        w.store.disable_user_in_org(w.org, only).await?,
        Change::WouldLeaveNoAdmin,
        "no administrator means nobody who can appoint one, and the way back is a \
         hand-written UPDATE against production"
    );

    // A second admin makes it allowed — the rule is about the tenant keeping one, not about
    // this person being special.
    w.person("second", Some(Role::Admin)).await;
    assert_eq!(w.store.disable_user_in_org(w.org, only).await?, Change::Done);
    Ok(())
}

#[tokio::test]
async fn a_disabled_administrator_does_not_count_as_one() -> Result<()> {
    let w = World::new("disabledadmin").await;
    let first = w.person("first", Some(Role::Admin)).await;
    let second = w.person("second", Some(Role::Admin)).await;

    assert_eq!(
        w.store.disable_user_in_org(w.org, second).await?,
        Change::Done
    );
    // `first` is now the only *enabled* admin, so the tenant must keep them.
    assert_eq!(
        w.store.disable_user_in_org(w.org, first).await?,
        Change::WouldLeaveNoAdmin
    );
    Ok(())
}

#[tokio::test]
async fn another_organizations_user_cannot_be_disabled() -> Result<()> {
    let mine = World::new("dmine").await;
    let theirs = World::new("dtheirs").await;
    theirs.person("keeper", Some(Role::Admin)).await;
    let target = theirs.person("target", Some(Role::Viewer)).await;

    assert_eq!(
        mine.store.disable_user_in_org(mine.org, target).await?,
        Change::NoSuchUser
    );

    let still = theirs.find(target).await;
    assert!(still.disabled_at.is_none(), "and it really did not happen");
    Ok(())
}

#[tokio::test]
async fn a_suspension_can_be_lifted() -> Result<()> {
    let w = World::new("lift").await;
    w.person("keeper", Some(Role::Admin)).await;
    let person = w.person("person", Some(Role::Viewer)).await;

    assert_eq!(
        w.store.disable_user_in_org(w.org, person).await?,
        Change::Done
    );
    assert!(w.find(person).await.disabled_at.is_some());

    assert!(w.store.enable_user(w.org, person).await?);
    assert!(
        w.find(person).await.disabled_at.is_none(),
        "an irreversible suspension forces a second account for one person, which splits \
         their audit history — §4.4"
    );

    assert!(
        !w.store.enable_user(w.org, person).await?,
        "enabling somebody who is not suspended changed nothing, and says so"
    );
    Ok(())
}

/// `enable_user` has no separate existence check — the `org_id` in its `UPDATE` is the only
/// thing standing between an id from a URL and somebody else's suspended account. Found by
/// mutation: relaxing that clause left every other test passing.
#[tokio::test]
async fn another_organizations_user_cannot_be_enabled() -> Result<()> {
    let mine = World::new("emine").await;
    let theirs = World::new("etheirs").await;
    theirs.person("keeper", Some(Role::Admin)).await;
    let suspended = theirs.person("suspended", Some(Role::Viewer)).await;
    assert_eq!(
        theirs
            .store
            .disable_user_in_org(theirs.org, suspended)
            .await?,
        Change::Done
    );

    assert!(
        !mine.store.enable_user(mine.org, suspended).await?,
        "an id from a URL is not proof the account is the caller's to restore"
    );
    assert!(
        theirs.find(suspended).await.disabled_at.is_some(),
        "and it really did not happen"
    );
    Ok(())
}

/// Pins the `accepted_at IS NULL` predicate specifically.
///
/// `an_invitation_works_exactly_once` passes even without it, because the second redemption
/// is stopped by `app_user_email_ci_idx` instead — genuine defence in depth, and a test that
/// cannot tell the two apart. This removes the account so only the predicate is left.
#[tokio::test]
async fn a_spent_invitation_is_refused_even_with_no_account_in_the_way() -> Result<()> {
    let w = World::new("spent").await;
    let by = w.person("admin", Some(Role::Admin)).await;
    let invited = w
        .store
        .invite_person(
            w.org,
            &format!("spent-{}@example.test", ActorId::new().into_uuid().simple()),
            "Spent",
            by,
            Duration::days(7),
        )
        .await?
        .expect("invited");

    let user = w
        .store
        .accept_invitation(&invited.token, &hash("first"))
        .await?
        .expect("accepted");

    // Move the account off the invited address, so `app_user_email_ci_idx` is no longer
    // what would refuse a second redemption. Deleting the account instead is impossible by
    // design: `accepted_user` is a foreign key to it, and nulling that alone trips
    // `user_invitation_acceptance_is_whole`. Both constraints doing their job.
    sqlx::query("UPDATE app_user SET email = $2 WHERE id = $1")
        .bind(user.into_uuid())
        .bind(format!("moved-{}@example.test", ActorId::new().into_uuid().simple()))
        .execute(w.store.pool())
        .await
        .expect("move the address");

    assert!(
        w.store
            .accept_invitation(&invited.token, &hash("again"))
            .await?
            .is_none(),
        "the invitation itself is spent, independently of whether the address is taken"
    );
    Ok(())
}

// ---- roles ------------------------------------------------------------------------

#[tokio::test]
async fn the_last_administrator_cannot_be_demoted_or_revoked() -> Result<()> {
    let w = World::new("demote").await;
    let only = w.person("only", Some(Role::Admin)).await;
    let by = only;

    assert_eq!(
        w.store
            .grant_role_guarded(&w.scope(), only, Role::Viewer, by)
            .await?,
        Change::WouldLeaveNoAdmin,
        "lowering the only admin leaves nobody who can put them back — a change does this \
         as surely as a revoke"
    );
    assert_eq!(
        w.store.revoke_role_guarded(&w.scope(), only).await?,
        Change::WouldLeaveNoAdmin
    );

    // Still an admin, and still able to act.
    assert_eq!(
        w.store.role_for(only, w.tenant).await?,
        Some(Role::Admin),
        "a refused change must not half-apply"
    );
    Ok(())
}

#[tokio::test]
async fn a_role_can_be_granted_changed_and_revoked() -> Result<()> {
    let w = World::new("grant").await;
    let admin = w.person("admin", Some(Role::Admin)).await;
    let person = w.person("person", None).await;

    assert_eq!(
        w.store
            .grant_role_guarded(&w.scope(), person, Role::Viewer, admin)
            .await?,
        Change::Done
    );
    assert_eq!(w.store.role_for(person, w.tenant).await?, Some(Role::Viewer));

    assert_eq!(
        w.store
            .grant_role_guarded(&w.scope(), person, Role::Operator, admin)
            .await?,
        Change::Done,
        "re-granting changes the role rather than failing, so there is no separate update"
    );
    assert_eq!(
        w.store.role_for(person, w.tenant).await?,
        Some(Role::Operator)
    );

    assert_eq!(
        w.store.revoke_role_guarded(&w.scope(), person).await?,
        Change::Done
    );
    assert_eq!(w.store.role_for(person, w.tenant).await?, None);
    Ok(())
}

#[tokio::test]
async fn a_grant_records_who_made_it() -> Result<()> {
    let w = World::new("provenance").await;
    let admin = w.person("admin", Some(Role::Admin)).await;
    let person = w.person("person", None).await;

    w.store
        .grant_role_guarded(&w.scope(), person, Role::Viewer, admin)
        .await?;

    let granted_by: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT granted_by FROM user_tenant_role WHERE user_id = $1 AND tenant_id = $2",
    )
    .bind(person.into_uuid())
    .bind(w.tenant.into_uuid())
    .fetch_one(w.store.pool())
    .await
    .expect("read");

    assert_eq!(
        granted_by,
        Some(admin.into_uuid()),
        "`granted_by` has been in the schema since M1 and passing NULL would waste it"
    );
    Ok(())
}

#[tokio::test]
async fn a_role_cannot_be_granted_to_another_organizations_user() -> Result<()> {
    let mine = World::new("rmine").await;
    let theirs = World::new("rtheirs").await;
    let admin = mine.person("admin", Some(Role::Admin)).await;
    let outsider = theirs.person("outsider", None).await;

    assert_eq!(
        mine.store
            .grant_role_guarded(&mine.scope(), outsider, Role::Admin, admin)
            .await?,
        Change::NoSuchUser
    );
    assert_eq!(mine.store.role_for(outsider, mine.tenant).await?, None);
    Ok(())
}

#[tokio::test]
async fn the_membership_list_names_roles_and_suspensions() -> Result<()> {
    let w = World::new("members").await;
    let admin = w.person("admin", Some(Role::Admin)).await;
    w.person("keeper", Some(Role::Admin)).await;
    let viewer = w.person("viewer", Some(Role::Viewer)).await;
    w.store.disable_user_in_org(w.org, viewer).await?;

    let members = w.store.tenant_members(&w.scope()).await?;

    let them = members
        .iter()
        .find(|m| m.user == viewer)
        .expect("a suspended member is still a member");
    assert_eq!(them.role, Role::Viewer);
    assert!(them.disabled);

    assert!(
        members.iter().any(|m| m.user == admin && !m.disabled),
        "{members:?}"
    );
    Ok(())
}

/// The test that distinguishes the advisory lock from a comment claiming there is one.
///
/// `docs/user-administration.md` §4.3 first said the rule would be enforced "inside the
/// statement that performs the change". It cannot be: two statements removing *different*
/// administrators contend for no row, so nothing blocks and both commit, leaving a tenant
/// with nobody who can appoint anybody. Two admins, two simultaneous revokes, exactly one
/// wins.
///
/// # Why it races eight times
///
/// Removing the lock and running this once fails about four times in five — the window is
/// wide but not certain, and a guard that reports a real defect 80% of the time is a guard
/// that will eventually be dismissed as flaky by whoever is unlucky. Eight rounds takes the
/// chance of missing it to roughly two in a million while still finishing in under a second.
/// A race can only be tested by racing; it can be tested often.
#[tokio::test]
async fn two_simultaneous_revocations_cannot_both_win() -> Result<()> {
    // Separate stores, so each call takes its own pool connection and the two really are in
    // flight together. One store would serialise them by connection availability and the
    // test would pass whether the lock existed or not.
    let (a, b) = (store().await, store().await);

    for round in 0..8 {
        // A fresh organization each round: after one revoke the previous tenant has a single
        // administrator, and the guard would refuse on that alone rather than on the race.
        let w = World::new(&format!("race{round}")).await;
        let first = w.person("first", Some(Role::Admin)).await;
        let second = w.person("second", Some(Role::Admin)).await;
        let (scope_a, scope_b) = (w.scope(), w.scope());

        let (ra, rb) = tokio::join!(
            a.revoke_role_guarded(&scope_a, first),
            b.revoke_role_guarded(&scope_b, second),
        );
        let (ra, rb) = (ra?, rb?);

        let won = [ra, rb].iter().filter(|c| **c == Change::Done).count();
        assert_eq!(won, 1, "round {round}: exactly one may succeed — {ra:?} {rb:?}");
        assert_eq!(
            [ra, rb]
                .iter()
                .filter(|c| **c == Change::WouldLeaveNoAdmin)
                .count(),
            1,
            "round {round}: and the other must be told why — {ra:?} {rb:?}"
        );

        let admins = w
            .store
            .tenant_members(&w.scope())
            .await?
            .into_iter()
            .filter(|m| m.role == Role::Admin && !m.disabled)
            .count();
        assert_eq!(
            admins, 1,
            "round {round}: the tenant keeps somebody who can appoint the next administrator"
        );
    }
    Ok(())
}

// ---- one's own password -----------------------------------------------------------

#[tokio::test]
async fn changing_a_password_ends_the_other_sessions_and_keeps_this_one() -> Result<()> {
    let w = World::new("ownpw").await;
    w.person("keeper", Some(Role::Admin)).await;
    let me = w.person("me", Some(Role::Viewer)).await;

    let mine = w.open_session(me).await;
    w.open_session(me).await;
    w.open_session(me).await;
    assert_eq!(w.live_sessions(me).await, 3);

    let ended = w.store.set_own_password(me, &hash("a new one"), mine).await?;

    assert_eq!(ended, 2, "the other two, and not the one doing the typing");
    assert_eq!(w.live_sessions(me).await, 1);

    let survivor: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM session WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(me.into_uuid())
    .fetch_one(w.store.pool())
    .await
    .expect("read");
    assert_eq!(
        survivor,
        mine.into_uuid(),
        "being signed out of the tab you are typing in reads as a bug"
    );
    Ok(())
}

// ---- break-glass ------------------------------------------------------------------

#[tokio::test]
async fn designating_break_glass_moves_it_rather_than_adding_one() -> Result<()> {
    let w = World::new("breakglass").await;
    let first = w.person("first", Some(Role::Admin)).await;
    let second = w.person("second", Some(Role::Viewer)).await;

    assert!(w.store.designate_break_glass(w.org, first).await?);
    assert!(w.find(first).await.break_glass);

    // Migration 0024's partial unique index allows one per organization, so this only works
    // if the previous holder is cleared in the same transaction.
    assert!(w.store.designate_break_glass(w.org, second).await?);
    assert!(w.find(second).await.break_glass);
    assert!(
        !w.find(first).await.break_glass,
        "two accounts bypassing a required SSO policy is the opposite of what it is for"
    );
    Ok(())
}

#[tokio::test]
async fn break_glass_cannot_be_given_to_another_organizations_user() -> Result<()> {
    let mine = World::new("bgmine").await;
    let theirs = World::new("bgtheirs").await;
    let outsider = theirs.person("outsider", None).await;

    assert!(!mine.store.designate_break_glass(mine.org, outsider).await?);
    assert!(!theirs.find(outsider).await.break_glass);
    Ok(())
}
