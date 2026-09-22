//! `POST /auth/login`, `POST /auth/logout`, `GET /me`.
//!
//! # Login must not be an oracle
//!
//! An unknown address and a wrong password have to be indistinguishable — in the
//! response, and in how long it takes to produce one. The response part is easy and
//! everyone does it. The timing part is where it usually goes wrong: returning early
//! when the user does not exist skips the Argon2 verification, and Argon2 is
//! *deliberately* slow, so "no such user" answers in a millisecond and "wrong password"
//! answers in twenty. That gap is a reliable account-enumeration oracle, and it is
//! measurable over the internet.
//!
//! So the handler verifies against a fixed dummy hash when the user is absent, and only
//! then decides. [`verify_credentials`] is arranged so that every path through it does
//! the same work.
//!
//! # What login hands back
//!
//! Two cookies. The session token, `HttpOnly`, which script must never read. And the
//! CSRF token, which script must read — see [`crate::csrf`].

use std::sync::OnceLock;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use uops_core::{Role, Secret, TenantId};
use uops_secrets::{PasswordHashString, password, session};

use crate::cookie::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::csrf::{self, CsrfChecked};
use crate::error::{ApiError, ApiResult};
use crate::extract::Authenticated;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    /// Wrapped on arrival so it cannot be logged or serialised onward: `Secret<T>` is
    /// not `Display` or `Serialize`, and the CI grep catches `.expose()` in a logging
    /// macro. `String` here would make a plaintext password one `tracing::info!` away
    /// from the log file.
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    /// Every tenant this user can reach, for the switcher. The list IS the access
    /// control surface a user sees; anything not here does not exist as far as they
    /// are concerned.
    pub tenants: Vec<TenantMembership>,
}

#[derive(Debug, Serialize)]
pub struct TenantMembership {
    pub tenant_id: TenantId,
    /// What the switcher shows. Without it the switcher shows UUIDs, and an MSP
    /// engineer with fourteen customers picks the wrong one.
    pub name: String,
    pub slug: String,
    pub role: &'static str,
}

/// A real Argon2 hash of a password nobody has.
///
/// Verified against when no user matches, so that path costs what a real verification
/// costs. Computed once — doing it per request would be the same work but would also
/// make login slower for everyone, and the point is to be *equal*, not slow.
fn absent_user_hash() -> &'static PasswordHashString {
    static HASH: OnceLock<PasswordHashString> = OnceLock::new();
    HASH.get_or_init(|| {
        password::hash(&Secret::new(
            "a password no account has, hashed so that a missing user costs \
             what a wrong password costs"
                .to_owned(),
        ))
        .expect("hashing a constant cannot fail")
    })
}

/// Record a sign-in against this installation — M11 §2.4.
///
/// # Why the organization audit log and not the `events` table
///
/// M11 §2.4 asked for product sign-ins to be *"the first source"* of authentication
/// events, and building it is what showed the shape was wrong. `events` is partitioned by
/// tenant, and **authentication precedes knowing a tenant** — the same fact M12 §2.2
/// discovered when it made SSO an organization property rather than a tenant one. A user
/// signs in to an organization and chooses a tenant afterwards.
///
/// Writing one event row per tenant in the organization would put an organization-level
/// fact into N tenant partitions, each copy inviting a tenant-scoped detection to count a
/// sign-in that was not against it. So these go where break-glass sign-ins already go: the
/// organization audit log, which is organization-scoped by construction.
///
/// **What that costs is named rather than hidden.** A detection cannot fire on these,
/// because the alert engine evaluates a `Query` against `ClickHouse` under a tenant scope
/// and this is a `PostgreSQL` row with no tenant. Detecting on them needs an
/// organization-scoped evaluation path, which does not exist — see the amendment in
/// §2.4.
///
/// # An address that resolves to no user is deliberately not recorded
///
/// There is no organization to attribute it to, and showing it to *an* organization would
/// tell them about an attempt that was not against them — which in a hosted deployment is
/// a leak between customers. Blind spraying at addresses that do not exist is what the
/// per-IP rate limit on auth endpoints is for (SPEC §M0.8); this records what can be
/// attributed truthfully.
async fn note_sign_in(
    state: &AppState,
    user_id: uops_core::ActorId,
    outcome: &'static str,
    why: &'static str,
    headers: &HeaderMap,
) {
    let Ok(Some(profile)) = state.store.user_profile(user_id).await else {
        return;
    };

    // Failure is swallowed, and this is the one place in the auth path where that is
    // right: a sign-in that worked must not be turned into a 500 because an audit insert
    // failed, and a sign-in that failed has already failed. The break-glass record above
    // is the opposite case — it is the entry worth failing a request over — and the
    // difference is that one of them is the only trace of a bypass.
    let _ = state
        .store
        .record_org_audit(
            profile.org_id,
            &format!("user:{user_id}"),
            outcome,
            &profile.email,
            Some(serde_json::json!({ "reason": why })),
            crate::audit::ip_from_headers(headers),
        )
        .await;
}

/// What a sign-in record is called.
///
/// ECS's `event.outcome` vocabulary, so that the day these become real events — see the
/// note on [`note_sign_in`] — the words do not have to change.
const SIGN_IN_OK: &str = "auth.sign_in.success";
const SIGN_IN_FAILED: &str = "auth.sign_in.failure";

/// Verify an address and password, doing equal work whether or not the user exists.
async fn verify_credentials(
    state: &AppState,
    email: &str,
    supplied: &Secret<String>,
    headers: &HeaderMap,
) -> ApiResult<Verified> {
    let found = state.store.user_credentials_by_email(email).await?;

    // The hash to verify against: the user's, or a stand-in. Both cost the same.
    //
    // An account provisioned through SSO has no password at all — migration 0024 — and
    // lands on the stand-in too. That is deliberate: a password-less account and an
    // absent one must be indistinguishable, or the login form becomes a way to ask which
    // of a company's addresses use SSO.
    let hash = found
        .as_ref()
        .and_then(|c| c.password_hash.clone())
        .unwrap_or_else(|| absent_user_hash().clone());

    let correct = password::verify(supplied, &hash);

    // Every failure below is the same failure to a caller: no user, wrong password, and
    // a disabled account are one answer. Telling a disabled user that their password was
    // right is also an answer about the password.
    let Some(credentials) = found else {
        return Err(ApiError::Unauthenticated);
    };
    if !correct || credentials.disabled {
        note_sign_in(
            state,
            credentials.user_id,
            SIGN_IN_FAILED,
            if credentials.disabled {
                "the account is disabled"
            } else {
                "the password did not match"
            },
            headers,
        )
        .await;
        return Err(ApiError::Unauthenticated);
    }

    // M12 §2.2. An organization may require SSO, which switches off password login for
    // everyone except one named break-glass account.
    //
    // Checked *after* the password, not before, and that ordering is the point: refusing
    // early would answer in a millisecond where a wrong password answers in twenty, and
    // the gap would say "this address exists and its organization uses SSO" to anybody
    // who can time a request.
    let policy = state.store.password_policy(credentials.user_id).await?;
    if !policy.allows_password() {
        note_sign_in(
            state,
            credentials.user_id,
            SIGN_IN_FAILED,
            "this organization requires SSO and this is not its break-glass account",
            headers,
        )
        .await;
        return Err(ApiError::Unauthenticated);
    }

    // The one moment the plaintext is in hand, so the one moment a hash written under
    // weaker parameters can be upgraded without asking the user for anything.
    if let Some(stored) = credentials.password_hash.as_ref()
        && password::needs_rehash(stored)
        && let Ok(stronger) = password::hash(supplied)
    {
        state
            .store
            .update_password_hash(credentials.user_id, &stronger)
            .await?;
    }

    Ok(Verified {
        user_id: credentials.user_id,
        break_glass: policy.is_break_glass_use(),
    })
}

/// A login that passed every check, and whether it was the exceptional one.
#[derive(Clone, Copy, Debug)]
struct Verified {
    user_id: uops_core::ActorId,
    /// The organization requires SSO and this is the account that may still use a
    /// password. M12 §2.2: its use is an audit event.
    break_glass: bool,
}

/// `POST /api/v1/auth/login`
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> ApiResult<Response> {
    let supplied = Secret::new(body.password);
    let verified = verify_credentials(&state, &body.email, &supplied, &headers).await?;
    let user_id = verified.user_id;

    if verified.break_glass {
        // M12 §2.2's acceptance criterion, and the reason the break-glass account exists
        // at all: an organization that requires SSO has exactly one way in that does not
        // go through its identity provider, and every use of it is on the record.
        //
        // Recorded before the session is issued rather than after. A failure to write
        // this must not be a break-glass login that happened and left no trace, which is
        // the one audit entry in this product worth failing a request over.
        if let Some(profile) = state.store.user_profile(user_id).await? {
            state
                .store
                .record_org_audit(
                    profile.org_id,
                    &format!("user:{user_id}"),
                    "auth.break_glass",
                    &profile.email,
                    Some(serde_json::json!({
                        "reason": "this organization requires SSO; a password was accepted                                    for the named break-glass account",
                    })),
                    None,
                )
                .await?;
        }
    }

    note_sign_in(&state, user_id, SIGN_IN_OK, "password", &headers).await;

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(256).collect::<String>());

    let (token, token_hash) = session::issue().map_err(|e| ApiError::Internal(e.into()))?;
    state
        .store
        .create_session(user_id, &token_hash, user_agent.as_deref())
        .await?;

    let csrf_token = csrf::issue()?;
    // The same number twice: a cookie that outlives its session leaves the browser
    // presenting a dead token, and one that dies first logs the user out early.
    let max_age = uops_store_pg::IDLE_TIMEOUT.num_seconds();

    let mut response = StatusCode::NO_CONTENT.into_response();
    let out = response.headers_mut();
    out.append(
        header::SET_COOKIE,
        cookie::header(&cookie::set(
            SESSION_COOKIE,
            token.expose(),
            max_age,
            true,
            state.secure_cookies,
        )),
    );
    out.append(
        header::SET_COOKIE,
        cookie::header(&cookie::set(
            CSRF_COOKIE,
            &csrf_token,
            max_age,
            false,
            state.secure_cookies,
        )),
    );

    Ok(response)
}

/// `POST /api/v1/auth/logout`
///
/// Takes [`CsrfChecked`] like any other mutation. Logging someone out from another
/// origin is a nuisance rather than a breach, but exempting it would mean one more
/// endpoint whose protection is a special case somebody has to remember.
pub async fn logout(
    State(state): State<AppState>,
    caller: Authenticated,
    _csrf: CsrfChecked,
) -> ApiResult<Response> {
    state.store.revoke_session(caller.session_id).await?;

    let mut response = StatusCode::NO_CONTENT.into_response();
    let out = response.headers_mut();
    out.append(
        header::SET_COOKIE,
        cookie::header(&cookie::clear(SESSION_COOKIE, true, state.secure_cookies)),
    );
    out.append(
        header::SET_COOKIE,
        cookie::header(&cookie::clear(CSRF_COOKIE, false, state.secure_cookies)),
    );
    Ok(response)
}

/// `GET /api/v1/me`
///
/// Takes [`Authenticated`] rather than [`crate::Caller`]: this is what the app calls
/// *before* it knows which tenant to ask about, and it is how the tenant switcher is
/// populated.
pub async fn me(
    State(state): State<AppState>,
    caller: Authenticated,
) -> ApiResult<Json<MeResponse>> {
    let profile = state
        .store
        .user_profile(caller.user_id)
        .await?
        .ok_or(ApiError::Unauthenticated)?;

    let tenants = state
        .store
        .tenant_memberships(caller.user_id)
        .await?
        .into_iter()
        .map(|m| TenantMembership {
            tenant_id: m.tenant_id,
            name: m.name,
            slug: m.slug,
            role: role_name(m.role),
        })
        .collect();

    Ok(Json(MeResponse {
        user_id: profile.user_id.to_string(),
        email: profile.email,
        display_name: profile.display_name,
        tenants,
    }))
}

const fn role_name(role: Role) -> &'static str {
    role.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stand_in_hash_is_a_real_one() {
        // If this were a constant string rather than a real Argon2 hash, verifying
        // against it would fail to parse and return in microseconds — which is exactly
        // the timing difference it exists to remove.
        let hash = absent_user_hash();
        assert!(hash.as_str().starts_with("$argon2id$"), "{}", hash.as_str());
        assert!(!password::needs_rehash(hash));
    }

    #[test]
    fn verifying_against_the_stand_in_costs_what_a_real_verification_costs() {
        // Not a timing assertion — a smoke test that the work actually happens. A
        // stand-in that failed fast would make "no such user" measurably quicker than
        // "wrong password", which is an account-enumeration oracle over the internet.
        let started = std::time::Instant::now();
        let matched = password::verify(&Secret::new("anything".to_owned()), absent_user_hash());
        assert!(!matched);
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(5),
            "the absent-user path finished in {:?} — it is not doing the work",
            started.elapsed()
        );
    }
}
