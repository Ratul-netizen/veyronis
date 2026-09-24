//! The people in an organization — `docs/user-administration.md`.
//!
//! ```text
//!   GET    /users                      everybody, with the state an admin acts on
//!   POST   /users                      invite somebody; also the resend
//!   GET    /users/invitations          the live invitations
//!   DELETE /users/invitations/{id}     withdraw one
//!   POST   /users/{id}/disable         suspend, ending every session now
//!   POST   /users/{id}/enable          lift a suspension
//!   POST   /users/{id}/break-glass     name the SSO bypass account
//!   GET    /tenants/roles              who may see the tenant in the header
//!   PUT    /users/{id}/role            grant or change a role on that tenant
//!   DELETE /users/{id}/role            take it away
//!   POST   /invitations/{token}        redeem an invitation — unauthenticated
//!   PUT    /me/password                change one's own
//! ```
//!
//! # Two authorisations, because there are two questions
//!
//! *Who is a person here* is organization-level: `OrgAdmin`, which requires admin on every
//! tenant. *Who may see this customer* is one tenant's business, so it takes `Caller` with
//! `Role::Admin` on the tenant in the request header — the same gate the credential and
//! audit-log routes use.
//!
//! # The one unauthenticated route
//!
//! `POST /invitations/{token}` is reached by somebody who has no account yet, so the token
//! is the whole authorisation. It gets the same discipline as `auth/login`: one sentence for
//! every failure, because distinguishing *expired* from *never existed* confirms that a
//! token was once real.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use uops_core::{ActorId, Role, Secret};
use uops_secrets::password;
use uops_store_pg::{Change, INVITATION_VALID_FOR};

use crate::csrf::CsrfChecked;
use crate::error::{ApiError, ApiResult};
use crate::extract::{Authenticated, Caller, OrgAdmin};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: ActorId,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
    /// Absent when the account is live. Suspension is reversible and is not deletion.
    pub disabled_at: Option<String>,
    pub break_glass: bool,
    /// Whether a password would work at all. Reported beside `sso_linked` rather than
    /// inferred from it, because an account can have both.
    pub has_password: bool,
    pub sso_linked: bool,
}

#[derive(Debug, Serialize)]
pub struct InvitationView {
    pub id: uuid::Uuid,
    pub email: String,
    pub display_name: String,
    pub invited_at: String,
    pub expires_at: String,
    pub invited_by: Option<ActorId>,
}

/// `GET /api/v1/users`
///
/// Everybody with an account, including suspended ones — an admin who cannot see a
/// suspension cannot lift it. People who have only been invited are **not** here; they have
/// no account yet, which is migration 0030's decision. See [`invitations`].
pub async fn list(State(state): State<AppState>, admin: OrgAdmin) -> ApiResult<Json<Vec<UserView>>> {
    let rows = state.store.users_in_org(admin.org_id).await?;

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "user.list",
            &admin.org_id.to_string(),
            None,
            None,
        )
        .await?;

    Ok(Json(
        rows.into_iter()
            .map(|u| UserView {
                id: u.id,
                email: u.email,
                display_name: u.display_name,
                created_at: u.created_at.to_rfc3339(),
                disabled_at: u.disabled_at.map(|t| t.to_rfc3339()),
                break_glass: u.break_glass,
                has_password: u.has_password,
                sso_linked: u.sso_linked,
            })
            .collect(),
    ))
}

/// `GET /api/v1/users/invitations`
///
/// Live invitations only — not accepted, not superseded, not expired. Listed apart from
/// [`list`] because they are a different kind of thing, and a screen that merged them would
/// offer to disable a row that is not an account.
pub async fn invitations(
    State(state): State<AppState>,
    admin: OrgAdmin,
) -> ApiResult<Json<Vec<InvitationView>>> {
    let rows = state.store.pending_invitations(admin.org_id).await?;

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "user.invitations.list",
            &admin.org_id.to_string(),
            None,
            None,
        )
        .await?;

    Ok(Json(
        rows.into_iter()
            .map(|i| InvitationView {
                id: i.id,
                email: i.email,
                display_name: i.display_name,
                invited_at: i.invited_at.to_rfc3339(),
                expires_at: i.expires_at.to_rfc3339(),
                invited_by: i.invited_by,
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// Inviting
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct InviteRequest {
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct InviteResponse {
    pub invitation: uuid::Uuid,
    pub expires_at: String,
    /// **The only moment this exists.** Only its hash is stored, so an administrator who
    /// loses it issues another rather than recovering this one.
    ///
    /// Returned in the body because the product has no organization-level mail transport
    /// yet and an air-gapped installation may never have one —
    /// `docs/user-administration.md` §4.1. The screen says to convey it out of band.
    pub link_token: String,
}

/// `POST /api/v1/users`
///
/// Invite somebody. **This is also the resend**: inviting an address that already has a live
/// invitation supersedes it, because the partial unique index requires that either way, and
/// one verb with one meaning beats two that differ only in whether something was there.
///
/// No password is accepted and none is generated. §4.1: an administrator who sets somebody's
/// password knows a credential that person is then accountable for.
pub async fn invite(
    State(state): State<AppState>,
    admin: OrgAdmin,
    _csrf: CsrfChecked,
    Json(body): Json<InviteRequest>,
) -> ApiResult<(StatusCode, Json<InviteResponse>)> {
    let email = body.email.trim();
    if email.is_empty() || !email.contains('@') {
        return Err(ApiError::BadRequest(
            "an email address is required, and it needs an @ in it".to_owned(),
        ));
    }
    let display_name = body.display_name.trim();
    if display_name.is_empty() {
        return Err(ApiError::BadRequest(
            "a name is required: a user list of email addresses is a list nobody can read"
                .to_owned(),
        ));
    }

    let Some(invited) = state
        .store
        .invite_person(
            admin.org_id,
            email,
            display_name,
            admin.user_id,
            INVITATION_VALID_FOR,
        )
        .await?
    else {
        return Err(ApiError::Conflict(
            "somebody with that address already has an account here".to_owned(),
        ));
    };

    // The address, never the token: the audit log is read by more people than the response
    // is, and a token in it is a working invitation sitting in a table.
    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "user.invite",
            email,
            Some(serde_json::json!({ "display_name": display_name })),
            None,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(InviteResponse {
            invitation: invited.invitation,
            expires_at: invited.expires_at.to_rfc3339(),
            link_token: invited.token,
        }),
    ))
}

/// `DELETE /api/v1/users/invitations/{id}`
///
/// Withdraw a live invitation — the answer to a mistyped address, and the reason no account
/// is created until somebody accepts.
pub async fn withdraw(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    if !state.store.withdraw_invitation(admin.org_id, id).await? {
        return Err(ApiError::NotFound);
    }

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "user.invite.withdraw",
            &id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct AcceptRequest {
    /// Wrapped in `Secret` on arrival, as `LoginRequest` does and for the same reason:
    /// `Secret<T>` is not `Deserialize`, precisely so that a plaintext password cannot be
    /// carried around in a struct that something might serialise or log.
    pub password: String,
}

/// `POST /api/v1/invitations/{token}`
///
/// Redeem an invitation, creating the account with the password its owner chose.
///
/// Unauthenticated, because whoever holds the link has no account yet. Every refusal is the
/// same sentence: a response that distinguished *expired* from *never existed* would confirm
/// that a token had once been real, which is a useful thing to learn while guessing.
pub async fn accept(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(body): Json<AcceptRequest>,
) -> ApiResult<StatusCode> {
    // Checked before the token is spent. A length floor is the whole policy —
    // `docs/user-administration.md` §6 declines composition rules, which measurably push
    // people toward worse passwords.
    let chosen = Secret::new(body.password);
    if chosen.expose().chars().count() < password::MINIMUM_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "a password needs at least {} characters",
            password::MINIMUM_LENGTH
        )));
    }

    let hash = password::hash(&chosen).map_err(|_| stored_badly())?;

    if state.store.accept_invitation(&token, &hash).await?.is_none() {
        return Err(ApiError::BadRequest(
            "this invitation cannot be used. It may have been used already, withdrawn, or \
             expired — ask whoever invited you for another"
                .to_owned(),
        ));
    }

    // No session is issued. Signing in is a separate act with its own audit entry and its
    // own cookie handling, and an accept path that also authenticated would be a second
    // login path to keep correct.
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Suspension
// ---------------------------------------------------------------------------

/// `POST /api/v1/users/{id}/disable`
///
/// Suspend an account and end every session it has, now.
pub async fn disable(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    let target = ActorId::from(id);

    // Refused here rather than in the store: this is a comparison of two ids the request
    // already holds, not a question about database state — §4.3.
    if target == admin.user_id {
        return Err(ApiError::BadRequest(
            "you cannot disable your own account. Ask another administrator".to_owned(),
        ));
    }

    match state.store.disable_user_in_org(admin.org_id, target).await? {
        Change::Done => {}
        Change::NoSuchUser => return Err(ApiError::NotFound),
        Change::WouldLeaveNoAdmin => {
            return Err(ApiError::Conflict(
                "this is the only administrator left on at least one tenant. Appoint another \
                 one first, or nobody will be able to"
                    .to_owned(),
            ));
        }
    }

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "user.disable",
            &id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/users/{id}/enable`
///
/// Lift a suspension. Sessions are not restored — they ended, and a session is not a thing
/// to resurrect.
pub async fn enable(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    if !state
        .store
        .enable_user(admin.org_id, ActorId::from(id))
        .await?
    {
        return Err(ApiError::NotFound);
    }

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "user.enable",
            &id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/users/{id}/break-glass`
///
/// Name the one account allowed to sign in with a password when the organization requires
/// SSO, clearing whoever held it.
///
/// §4.5 refuses to forbid an administrator designating themselves: they could designate any
/// account they control, so the rule would stop nothing while reading as though it did. The
/// designation is audited, and every *use* already is.
pub async fn break_glass(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    if !state
        .store
        .designate_break_glass(admin.org_id, ActorId::from(id))
        .await?
    {
        return Err(ApiError::NotFound);
    }

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "user.break_glass.designate",
            &id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Roles on one tenant
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct MemberView {
    pub user: ActorId,
    pub email: String,
    pub display_name: String,
    pub role: &'static str,
    pub disabled: bool,
}

/// `GET /api/v1/tenants/roles`
///
/// Who may see the tenant in the header, and as what. Admin on *that* tenant — this is one
/// customer's membership, not an organization-wide question.
pub async fn roles(
    State(state): State<AppState>,
    caller: Caller,
) -> ApiResult<Json<Vec<MemberView>>> {
    caller.require(Role::Admin)?;

    let members = state.store.tenant_members(caller.scope()).await?;

    caller.audit().read(
        "user.roles.list",
        Some(i64::try_from(members.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(
        members
            .into_iter()
            .map(|m| MemberView {
                user: m.user,
                email: m.email,
                display_name: m.display_name,
                role: m.role.as_str(),
                disabled: m.disabled,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct GrantRequest {
    pub role: Role,
}

/// `PUT /api/v1/users/{id}/role`
///
/// Grant or change somebody's role on the tenant in the header. Re-granting changes it, so
/// there is no separate update verb.
pub async fn grant(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
    Json(body): Json<GrantRequest>,
) -> ApiResult<StatusCode> {
    caller.require(Role::Admin)?;
    let target = ActorId::from(id);

    match state
        .store
        .grant_role_guarded(caller.scope(), target, body.role, caller.user_id())
        .await?
    {
        Change::Done => {}
        Change::NoSuchUser => return Err(ApiError::NotFound),
        Change::WouldLeaveNoAdmin => return Err(last_admin()),
    }

    caller.audit().wrote(
        "user.role.grant",
        id.to_string(),
        None,
        Some(serde_json::json!({ "role": body.role.as_str() })),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/users/{id}/role`
///
/// Take somebody's role on this tenant away. They keep their account and any role on any
/// other tenant.
pub async fn revoke(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    caller.require(Role::Admin)?;

    match state
        .store
        .revoke_role_guarded(caller.scope(), ActorId::from(id))
        .await?
    {
        Change::Done => {}
        Change::NoSuchUser => return Err(ApiError::NotFound),
        Change::WouldLeaveNoAdmin => return Err(last_admin()),
    }

    caller.audit().wrote("user.role.revoke", id.to_string(), None, None);
    Ok(StatusCode::NO_CONTENT)
}

/// Hashing failed, which is a fault in this process rather than in the request.
fn stored_badly() -> ApiError {
    ApiError::Internal(uops_core::Error::Storage(
        "the password could not be hashed".to_owned(),
    ))
}

fn last_admin() -> ApiError {
    ApiError::Conflict(
        "this is the only administrator left on this tenant. Appoint another one first, or \
         nobody will be able to"
            .to_owned(),
    )
}

// ---------------------------------------------------------------------------
// One's own password
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    /// Both wrapped on arrival — see [`AcceptRequest::password`].
    pub current: String,
    pub new: String,
}

/// `PUT /api/v1/me/password`
///
/// Change one's own password. Not administration — every user needs it and no role is
/// required — so it is on `/me` rather than the users screen.
///
/// The current password is required: a session cookie is not evidence of knowing the secret
/// being replaced, and a stolen session should not be able to lock its owner out.
///
/// Takes `Authenticated` rather than `Caller`, and the difference is the point: `Caller`
/// demands the tenant header, and a password is not about a tenant. Asking for one would
/// have made the route fail for a user who has not picked a customer yet.
pub async fn change_password(
    State(state): State<AppState>,
    who: Authenticated,
    _csrf: CsrfChecked,
    Json(body): Json<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    let (current, fresh) = (Secret::new(body.current), Secret::new(body.new));
    if fresh.expose().chars().count() < password::MINIMUM_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "a password needs at least {} characters",
            password::MINIMUM_LENGTH
        )));
    }

    let stored = state
        .store
        .password_hash_of(who.user_id)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "this account signs in through an identity provider and has no password here"
                    .to_owned(),
            )
        })?;

    if !password::verify(&current, &stored) {
        // Audited as a failure, because repeated wrong guesses against a live session are
        // worth being able to find later.
        state
            .store
            .record_org_audit(
                who.org_id,
                &format!("user:{}", who.user_id),
                "me.password.change.refused",
                &who.user_id.to_string(),
                None,
                None,
            )
            .await?;
        return Err(ApiError::BadRequest(
            "the current password is not right".to_owned(),
        ));
    }

    let hash = password::hash(&fresh).map_err(|_| stored_badly())?;

    let ended = state
        .store
        .set_own_password(who.user_id, &hash, who.session_id)
        .await?;

    // Recorded against the organization with a NULL tenant, which migration 0024 made
    // possible for exactly this class of act: a password belongs to a person, and writing it
    // against whichever tenant happened to be in a header would be a lie.
    state
        .store
        .record_org_audit(
            who.org_id,
            &format!("user:{}", who.user_id),
            "me.password.change",
            &who.user_id.to_string(),
            Some(serde_json::json!({ "other_sessions_ended": ended })),
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
