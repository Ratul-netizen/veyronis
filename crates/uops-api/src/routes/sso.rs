//! Signing in through an identity provider, and configuring one — M12 §2.2.
//!
//! ```text
//!   GET /auth/methods              the buttons to draw
//!   GET /auth/oidc/{id}/start      303 to the provider; the sign-in cookie goes out
//!   GET /auth/oidc/callback        the provider sends the browser back; a session comes out
//! ```
//!
//! # The first two are unauthenticated, and that is the whole point
//!
//! They are reached by somebody who has not signed in. Everything hostile that can be
//! done to them has to be closed here rather than by an extractor:
//!
//! | reached by anyone | what stops it being useful |
//! |---|---|
//! | listing providers | names only — no issuer, no client id. See `SignInOption` |
//! | starting sign-ins in a loop | nothing is written; the cost is one redirect |
//! | replaying a callback | `state` must match this browser's cookie, and the cookie is consumed |
//! | a token from elsewhere | `iss`, `aud` and `nonce`, checked in `uops-oidc` |
//! | an invented `kid` to force key fetches | `uops_oidc::fetch::REFRESH_FLOOR` |
//!
//! # Every failure is the same sentence
//!
//! *Sign-in failed.* Which check failed goes to the server log, where the operator who
//! can act on it will see it. Telling the browser that the audience was wrong confirms
//! that a token was well-formed and correctly signed, which is a useful thing to learn
//! while working out what to forge next.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use uops_core::{Role, Secret, TenantId};
use uops_oidc::{Expected, IdToken, Jws, Pending, flow};
use uops_secrets::session;
use uops_store_pg::Provisioned;

use crate::cookie::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::csrf::CsrfChecked;
use crate::error::{ApiError, ApiResult};
use crate::extract::OrgAdmin;
use crate::state::AppState;

/// The cookie that carries a sign-in in progress.
///
/// `HttpOnly`: it holds the PKCE verifier and the nonce, and script has no business with
/// either. `SameSite=Lax` is what lets it survive the provider's redirect back — `Strict`
/// would withhold it on exactly the request it exists for, and the sign-in would fail
/// every time with no indication why.
pub const PENDING_COOKIE: &str = "uops_oidc";

// ---------------------------------------------------------------------------
// Starting
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct MethodsResponse {
    /// The identity providers with a button on the sign-in page.
    pub providers: Vec<Method>,
}

#[derive(Debug, Serialize)]
pub struct Method {
    pub id: String,
    pub name: String,
    /// Where to send the browser. Built here so the page has nothing to assemble.
    pub start: String,
}

/// `GET /api/v1/auth/methods`
///
/// Unauthenticated, because it is what the sign-in page asks before anybody has signed
/// in. It returns names and nothing else — see `SignInOption` for why.
pub async fn methods(State(state): State<AppState>) -> ApiResult<Json<MethodsResponse>> {
    let providers = state
        .store
        .sign_in_options()
        .await?
        .into_iter()
        .map(|p| Method {
            start: format!("/api/v1/auth/oidc/{}/start", p.id),
            id: p.id.to_string(),
            name: p.name,
        })
        .collect();
    Ok(Json(MethodsResponse { providers }))
}

#[derive(Debug, Deserialize)]
pub struct StartQuery {
    /// Where to go after signing in. Sanitised by [`flow::safe_return_to`] — an open
    /// redirect here is worth more to a phisher than most bugs in this product.
    pub return_to: Option<String>,
}

/// `GET /api/v1/auth/oidc/{provider}/start`
pub async fn start(
    State(state): State<AppState>,
    Path(provider_id): Path<uuid::Uuid>,
    Query(query): Query<StartQuery>,
) -> ApiResult<Response> {
    let Some(provider) = state.store.enabled_provider(provider_id).await? else {
        // A 404 rather than "that provider is disabled": an unauthenticated caller
        // learning which of a company's providers exist but are switched off has learned
        // something about their migration.
        return Err(ApiError::NotFound);
    };

    let discovered = discover(&state, &provider).await?;
    let pending = Pending::start(query.return_to.as_deref()).map_err(|e| oidc_failed(&e))?;

    let url = pending.authorization_url(
        &discovered.authorization_endpoint,
        &provider.client_id,
        &state.oidc_redirect_uri,
        uops_oidc::SCOPES,
    );

    let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, url)]).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie::header(&cookie::set(
            PENDING_COOKIE,
            &encode_pending(provider_id, &pending),
            flow::WINDOW.num_seconds(),
            true,
            state.secure_cookies,
        )),
    );
    Ok(response)
}

// ---------------------------------------------------------------------------
// Coming back
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// The provider refusing — RFC 6749 §4.1.2.1. A user who pressed "cancel" arrives
    /// here, and so does a misconfiguration.
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// `GET /api/v1/auth/oidc/callback`
///
/// The provider sends the browser here. A dozen things have to be true — the cookie, the
/// `state`, the code, the provider, the client secret, the signature, `iss`, `aud`,
/// `nonce`, the validity window, and a group that maps to a role. Each is its own
/// refusal, and every one of them looks identical from outside.
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> ApiResult<Response> {
    // The cookie is consumed whatever happens below. A failed sign-in must not leave a
    // usable `state` and verifier in the browser for a second attempt to reuse — that is
    // the difference between a one-shot authorization code and a replayable one.
    let clear_pending = cookie::header(&cookie::clear(PENDING_COOKIE, true, state.secure_cookies));

    let outcome = complete(&state, &headers, &query).await;

    match outcome {
        Ok(mut response) => {
            response
                .headers_mut()
                .append(header::SET_COOKIE, clear_pending);
            Ok(response)
        }
        Err(e) => {
            // Logged here rather than returned: this is the only place the specific
            // reason exists, and the operator reading it is the only person who can act.
            eprintln!("sso: sign-in failed: {e}");
            let mut response = ApiError::Unauthenticated.into_response();
            response
                .headers_mut()
                .append(header::SET_COOKIE, clear_pending);
            Ok(response)
        }
    }
}

/// Everything the callback does, so that the cookie is cleared on every path out.
///
/// Long, and deliberately one function. It is the checks of a sign-in in the order they
/// have to happen, and every early return is one of them failing — splitting it
/// would turn a list a reviewer can read top to bottom into a call graph they have to
/// assemble. The day a check can be reordered without consequence is the day to split
/// it, and that day is not this one.
#[allow(clippy::too_many_lines)]
async fn complete(
    state: &AppState,
    headers: &HeaderMap,
    query: &CallbackQuery,
) -> Result<Response, String> {
    if let Some(error) = &query.error {
        return Err(match &query.error_description {
            Some(description) => format!("the provider refused: {error}: {description}"),
            None => format!("the provider refused: {error}"),
        });
    }

    let cookie_value =
        read_cookie(headers, PENDING_COOKIE).ok_or("no sign-in is in progress in this browser")?;
    let (provider_id, pending) =
        decode_pending(&cookie_value).ok_or("the sign-in cookie could not be read")?;

    let returned_state = query
        .state
        .as_deref()
        .ok_or("the callback carried no state")?;
    pending.accept(returned_state).map_err(|e| format!("{e}"))?;

    let code = query
        .code
        .as_deref()
        .ok_or("the callback carried no code")?;

    let provider = state
        .store
        .enabled_provider(provider_id)
        .await
        .map_err(|e| format!("{e}"))?
        .ok_or("that identity provider is no longer enabled")?;

    // The client secret, if this is a confidential client. A provider row with sealed
    // bytes this process cannot open is a deployment whose KEK is missing, and it says
    // so rather than silently attempting a public-client exchange that the provider will
    // reject for a different-looking reason.
    let sealed = state
        .store
        .provider_secret(provider_id)
        .await
        .map_err(|e| format!("{e}"))?;
    let secret: Option<Secret<String>> =
        match sealed {
            Some(ref value) => Some(state.sso.open(provider_id, value).ok_or(
                "this provider has a client secret and this server has no KEK to open it",
            )?),
            None => None,
        };

    // Discovery, the token exchange and the key fetch, on a blocking thread.
    //
    // `uops_oidc::fetch` is synchronous on purpose — three requests per sign-in, on a
    // path that has just waited for a human to type a password, is not worth a second
    // HTTP stack in this workspace. What it *is* worth is not running them on an async
    // worker: the client's global timeout is fifteen seconds, and a provider that hangs
    // would otherwise hold a runtime thread for all fifteen while everything else this
    // server does queues behind it.
    //
    // `spawn_blocking` rather than `block_in_place`, which requires a multi-threaded
    // runtime and would turn every `#[tokio::test]` in the suite into a panic.
    let payload = {
        let sso = std::sync::Arc::clone(&state.sso);
        let issuer = provider.issuer.clone();
        let client_id = provider.client_id.clone();
        let redirect_uri = state.oidc_redirect_uri.clone();
        let code = code.to_owned();
        let verifier = pending.verifier.clone();
        // `secret` is moved in as a `Secret`, not as the string inside it: a plain
        // `String` captured here would be a client secret that nothing zeroizes when
        // the task ends.
        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
            let discovered = uops_oidc::fetch::discover(sso.http(), &issuer)
                .map_err(|e| format!("discovery for {issuer} failed: {e}"))?;

            let response = uops_oidc::redeem(
                sso.http(),
                &discovered,
                &client_id,
                secret.as_ref().map(|s| s.expose().as_str()),
                &redirect_uri,
                &code,
                &verifier,
            )
            .map_err(|e| format!("{e}"))?;

            // Split before verified, so that the `kid` is available to choose a key and
            // the claims stay unreachable until the signature has been checked —
            // `Jws::verify` consumes the token and *returns* the payload, which is what
            // enforces the order rather than a comment asking for it.
            let jws = Jws::parse(&response.id_token).map_err(|e| format!("{e}"))?;
            let keys = sso
                .keys(provider_id)
                .for_token(
                    sso.http(),
                    &discovered.jwks_uri,
                    jws.kid.as_deref(),
                    chrono::Utc::now(),
                )
                .map_err(|e| format!("{e}"))?;
            jws.verify(&keys).map_err(|e| format!("{e}"))
        })
        .await
        .map_err(|e| format!("the sign-in task failed: {e}"))??
    };

    let token = IdToken::validate(
        &payload,
        &Expected {
            issuer: &provider.issuer,
            client_id: &provider.client_id,
            nonce: &pending.nonce,
            groups_claim: &provider.groups_claim,
        },
        chrono::Utc::now(),
    )
    .map_err(|e| format!("{e}"))?;

    // Authentication is done. Authorisation starts here, and they are different answers:
    // the provider has said who this is, and nobody has yet said what they may do.
    let mapping = state
        .store
        .mapping(provider_id)
        .await
        .map_err(|e| format!("{e}"))?;
    let entitlement = mapping.apply(&token.groups);

    if !entitlement.grants_access() {
        // Audited, because "somebody authenticated successfully and was refused" is
        // exactly the event an administrator debugging a rollout needs, and exactly the
        // event a security team wants to see a burst of.
        let _ = state
            .store
            .record_org_audit(
                provider.org_id,
                &format!("idp:{provider_id}"),
                "sso.refused",
                &token.subject,
                Some(serde_json::json!({
                    "reason": entitlement.refusal(),
                    "groups": token.groups,
                })),
                None,
            )
            .await;
        return Err(format!("{}: {}", token.describe(), entitlement.refusal()));
    }

    let roles: Vec<(TenantId, Role)> = entitlement.roles.into_iter().collect();
    let email = token.email.clone().unwrap_or_else(|| {
        // A provider that releases no address. The account still needs one, because
        // `app_user.email` is NOT NULL and the switcher shows it; making it obviously
        // synthetic is better than making it look like a real address nobody reads.
        format!(
            "{}@{}",
            token.subject,
            provider.issuer.trim_start_matches("https://")
        )
    });
    let display_name = token
        .name
        .clone()
        .or_else(|| token.email.clone())
        .unwrap_or_else(|| token.subject.clone());

    let (user_id, outcome) = state
        .store
        .provision(&provider, &token.subject, &email, &display_name, &roles)
        .await
        .map_err(|e| format!("{e}"))?;

    let _ = state
        .store
        .record_org_audit(
            provider.org_id,
            &format!("user:{user_id}"),
            match outcome {
                Provisioned::Created => "sso.provisioned",
                Provisioned::Matched => "sso.signed_in",
            },
            &token.subject,
            Some(serde_json::json!({
                "provider": provider.name,
                "issuer": provider.issuer,
                "tenants": roles.len(),
            })),
            None,
        )
        .await;

    issue_session(state, headers, user_id, &pending.return_to)
        .await
        .map_err(|e| format!("{e}"))
}

/// Open a session and send the browser where it was going.
async fn issue_session(
    state: &AppState,
    headers: &HeaderMap,
    user_id: uops_core::ActorId,
    return_to: &str,
) -> ApiResult<Response> {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(256).collect::<String>());

    let (token, token_hash) = session::issue().map_err(|e| ApiError::Internal(e.into()))?;
    state
        .store
        .create_session(user_id, &token_hash, user_agent.as_deref())
        .await?;

    let csrf_token = crate::csrf::issue()?;
    let max_age = uops_store_pg::IDLE_TIMEOUT.num_seconds();

    // A 303 rather than JSON: the browser arrived here by following the provider's
    // redirect, so it is a navigation and not a fetch, and answering with a body would
    // leave the user looking at a JSON document.
    let mut response = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, return_to.to_owned())],
    )
        .into_response();

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

// ---------------------------------------------------------------------------
// Configuring
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ProviderResponse {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub groups_claim: String,
    pub enabled: bool,
    /// Whether a client secret is stored. Never the secret.
    pub has_secret: bool,
}

/// `GET /api/v1/sso/providers`
pub async fn list_providers(
    State(state): State<AppState>,
    admin: OrgAdmin,
) -> ApiResult<Json<Vec<ProviderResponse>>> {
    let providers = state
        .store
        .providers(admin.org_id)
        .await?
        .into_iter()
        .map(|p| ProviderResponse {
            id: p.id.to_string(),
            name: p.name,
            issuer: p.issuer,
            client_id: p.client_id,
            groups_claim: p.groups_claim,
            enabled: p.enabled,
            has_secret: p.has_secret,
        })
        .collect();
    Ok(Json(providers))
}

#[derive(Debug, Deserialize)]
pub struct CreateProvider {
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    /// Absent for a public client, which PKCE makes a legitimate configuration.
    pub client_secret: Option<String>,
    pub groups_claim: Option<String>,
}

/// `POST /api/v1/sso/providers`
pub async fn create_provider(
    State(state): State<AppState>,
    admin: OrgAdmin,
    _csrf: CsrfChecked,
    Json(body): Json<CreateProvider>,
) -> ApiResult<Response> {
    if !body.issuer.starts_with("https://") {
        return Err(ApiError::BadRequest(
            "an issuer must be an https URL: the discovery document and the signing keys \
             are fetched from it, and over plain HTTP an on-path attacker chooses both"
                .to_owned(),
        ));
    }
    if body.client_secret.is_some() && !state.sso.can_seal() {
        return Err(ApiError::Unavailable(
            "this server has no key-encryption key, so a client secret cannot be sealed. \
             Set UOPS_KEK_FILE or UOPS_KEK, or configure this provider as a public client \
             — PKCE is always on, so that is a supported configuration rather than a \
             weaker one",
        ));
    }

    // Reached before anything is written, so a typo in the issuer is a message rather
    // than a row that fails at somebody's first sign-in.
    let discovered = {
        let sso = std::sync::Arc::clone(&state.sso);
        let issuer = body.issuer.clone();
        tokio::task::spawn_blocking(move || uops_oidc::fetch::discover(sso.http(), &issuer))
            .await
            .map_err(|e| {
                ApiError::Internal(uops_core::Error::Storage(format!(
                    "the discovery task failed: {e}"
                )))
            })?
            .map_err(|e| ApiError::BadRequest(format!("that issuer did not answer usably: {e}")))?
    };

    // The id is needed *before* the insert, because it is the sealing context — a secret
    // sealed under a different id could never be opened from the row it lands in.
    let id = uuid::Uuid::now_v7();
    let sealed = match body.client_secret {
        Some(secret) => Some(state.sso.seal(id, Secret::new(secret)).ok_or_else(|| {
            ApiError::Internal(uops_core::Error::Storage(
                "the client secret could not be sealed".to_owned(),
            ))
        })?),
        None => None,
    };

    let created = state
        .store
        .create_provider_with_id(
            id,
            admin.org_id,
            &body.name,
            &discovered.issuer,
            &body.client_id,
            body.groups_claim.as_deref().unwrap_or("groups"),
            sealed.as_ref(),
        )
        .await?;

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "sso.provider.create",
            &created.to_string(),
            Some(serde_json::json!({
                "name": body.name,
                "issuer": discovered.issuer,
                "confidential": sealed.is_some(),
            })),
            None,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": created })),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct SetEnabled {
    pub enabled: bool,
}

/// `PATCH /api/v1/sso/providers/{id}/enabled`
pub async fn set_provider_enabled(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
    Json(body): Json<SetEnabled>,
) -> ApiResult<StatusCode> {
    if !state
        .store
        .set_provider_enabled(admin.org_id, id, body.enabled)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    // A disabled provider must stop working now rather than after its key cache ages
    // out, and an operator who has just re-enabled one should not wait an hour either.
    state.sso.forget(id);

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            if body.enabled {
                "sso.provider.enable"
            } else {
                "sso.provider.disable"
            },
            &id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct GrantResponse {
    pub group: String,
    pub tenant_id: TenantId,
    pub role: &'static str,
}

/// `GET /api/v1/sso/providers/{id}/grants`
pub async fn list_grants(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
) -> ApiResult<Json<Vec<GrantResponse>>> {
    // Scoped by organization first, so the grants of another company's provider are a
    // 404 rather than a listing.
    if state.store.provider(admin.org_id, id).await?.is_none() {
        return Err(ApiError::NotFound);
    }
    let grants = state
        .store
        .grants(id)
        .await?
        .into_iter()
        .map(|g| GrantResponse {
            group: g.group,
            tenant_id: g.tenant_id,
            role: g.role.as_str(),
        })
        .collect();
    Ok(Json(grants))
}

#[derive(Debug, Deserialize)]
pub struct GrantRequest {
    pub group: String,
    pub tenant_id: TenantId,
    pub role: String,
}

/// `POST /api/v1/sso/providers/{id}/grants`
pub async fn grant(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
    Json(body): Json<GrantRequest>,
) -> ApiResult<StatusCode> {
    if state.store.provider(admin.org_id, id).await?.is_none() {
        return Err(ApiError::NotFound);
    }
    let role = parse_role(&body.role)?;
    if body.group.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "a grant needs a group; an empty one would match nothing and look configured"
                .to_owned(),
        ));
    }

    state
        .store
        .grant_group(
            admin.org_id,
            id,
            body.group.trim(),
            body.tenant_id,
            role,
            Some(admin.user_id),
        )
        .await?;

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "sso.grant",
            &format!("{id}:{}", body.group.trim()),
            Some(serde_json::json!({
                "tenant": body.tenant_id.to_string(),
                "role": role.as_str(),
            })),
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct RevokeQuery {
    pub group: String,
    pub tenant_id: TenantId,
}

/// `DELETE /api/v1/sso/providers/{id}/grants`
pub async fn revoke_grant(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    Query(query): Query<RevokeQuery>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    if state.store.provider(admin.org_id, id).await?.is_none() {
        return Err(ApiError::NotFound);
    }
    if !state
        .store
        .revoke_group(admin.org_id, id, &query.group, query.tenant_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "sso.revoke",
            &format!("{id}:{}", query.group),
            Some(serde_json::json!({ "tenant": query.tenant_id.to_string() })),
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct RequireSso {
    pub required: bool,
}

/// `PUT /api/v1/sso/require`
///
/// The setting that turns off password login for everybody but the break-glass account.
/// Refused unless an enabled provider exists, because the alternative is an organization
/// that has just locked itself out through a single API call.
pub async fn set_required(
    State(state): State<AppState>,
    admin: OrgAdmin,
    _csrf: CsrfChecked,
    Json(body): Json<RequireSso>,
) -> ApiResult<StatusCode> {
    if body.required {
        let providers = state.store.providers(admin.org_id).await?;
        if !providers.iter().any(|p| p.enabled) {
            return Err(ApiError::BadRequest(
                "this organization has no enabled identity provider, so requiring SSO \
                 would leave nobody able to sign in"
                    .to_owned(),
            ));
        }
    }

    state
        .store
        .set_require_sso(admin.org_id, body.required)
        .await?;
    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            if body.required {
                "sso.required"
            } else {
                "sso.not_required"
            },
            &admin.org_id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct AuditResponse {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: Option<serde_json::Value>,
    pub ip: Option<String>,
    pub at: chrono::DateTime<chrono::Utc>,
}

/// `GET /api/v1/sso/audit`
///
/// The organization-level half of the audit log: who signed in through a provider, who
/// was refused, who changed the configuration, and every use of the break-glass account.
pub async fn audit(
    State(state): State<AppState>,
    admin: OrgAdmin,
) -> ApiResult<Json<Vec<AuditResponse>>> {
    let entries = state
        .store
        .org_audit_entries(admin.org_id, 200)
        .await?
        .into_iter()
        .map(|e| AuditResponse {
            actor: e.actor,
            action: e.action,
            target: e.target,
            detail: e.detail,
            ip: e.ip,
            at: e.at,
        })
        .collect();
    Ok(Json(entries))
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// A sign-in in progress, as it travels in the cookie.
#[derive(Debug, Deserialize, Serialize)]
struct PendingCookie {
    p: String,
    s: String,
    n: String,
    v: String,
    r: String,
}

/// The pending sign-in, base64url of JSON.
///
/// Encoded rather than raw because a cookie value may not contain `;`, `,` or a space,
/// and a `return_to` legitimately can.
///
/// **Not signed, and that is a decision rather than an omission.** The cookie is
/// `HttpOnly`, so script cannot write it; an attacker who can set cookies in the
/// victim's browser can already complete a sign-in as themselves there, which is the
/// login-CSRF that `state` exists to prevent and which no signature over this value
/// would change. What a signature would add is a second key to manage for a value whose
/// integrity is already the browser's job.
fn encode_pending(provider: uuid::Uuid, pending: &Pending) -> String {
    let body = PendingCookie {
        p: provider.to_string(),
        s: pending.state.clone(),
        n: pending.nonce.clone(),
        v: pending.verifier.clone(),
        r: pending.return_to.clone(),
    };
    uops_oidc::b64::encode(serde_json::to_string(&body).unwrap_or_default().as_bytes())
}

fn decode_pending(value: &str) -> Option<(uuid::Uuid, Pending)> {
    let bytes = uops_oidc::b64::decode(value)?;
    let body: PendingCookie = serde_json::from_slice(&bytes).ok()?;
    Some((
        body.p.parse().ok()?,
        Pending {
            state: body.s,
            nonce: body.n,
            verifier: body.v,
            // Sanitised again on the way out, not only on the way in: the value has been
            // outside this process, and a check that only runs on entry is one an
            // attacker only has to get past once.
            return_to: flow::safe_return_to(Some(&body.r)),
        },
    ))
}

/// A cookie from a `HeaderMap`, for the handlers that have one rather than `Parts`.
fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let header = headers.get(header::COOKIE)?.to_str().ok()?;
    header.split(';').find_map(|pair| {
        let (found, value) = pair.split_once('=')?;
        (found.trim() == name).then(|| value.trim().to_owned())
    })
}

/// Fetch a provider's discovery document, off the async runtime.
///
/// See the note in [`complete`] for why the network calls run on a blocking thread. The
/// failure is a 503 rather than a 500: nothing here is broken, the provider did not
/// answer, and the difference matters to whoever reads the status code.
async fn discover(
    state: &AppState,
    provider: &uops_store_pg::Provider,
) -> ApiResult<uops_oidc::Discovered> {
    let sso = std::sync::Arc::clone(&state.sso);
    let issuer = provider.issuer.clone();

    let unreachable = || ApiError::Unavailable("the identity provider could not be reached");

    tokio::task::spawn_blocking(move || uops_oidc::fetch::discover(sso.http(), &issuer))
        .await
        .map_err(|e| {
            eprintln!("sso: the discovery task failed: {e}");
            unreachable()
        })?
        .map_err(|e| {
            eprintln!("sso: discovery for {} failed: {e}", provider.issuer);
            unreachable()
        })
}

fn oidc_failed(e: &uops_oidc::Error) -> ApiError {
    eprintln!("sso: {e}");
    ApiError::Internal(uops_core::Error::Storage(e.public_message().to_owned()))
}

fn parse_role(s: &str) -> ApiResult<Role> {
    match s {
        "viewer" => Ok(Role::Viewer),
        "operator" => Ok(Role::Operator),
        "admin" => Ok(Role::Admin),
        other => Err(ApiError::BadRequest(format!(
            "{other} is not a role; the roles are viewer, operator and admin"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pending_sign_in_survives_the_cookie_round_trip() {
        let provider = uuid::Uuid::now_v7();
        let pending = Pending::start(Some("/incidents?tab=timeline")).unwrap();
        let encoded = encode_pending(provider, &pending);

        // The characters a cookie value may not contain.
        for forbidden in [';', ',', ' ', '"', '\\'] {
            assert!(
                !encoded.contains(forbidden),
                "{encoded} contains {forbidden}"
            );
        }

        let (id, back) = decode_pending(&encoded).unwrap();
        assert_eq!(id, provider);
        assert_eq!(back.state, pending.state);
        assert_eq!(back.nonce, pending.nonce);
        assert_eq!(back.verifier, pending.verifier);
        assert_eq!(back.return_to, "/incidents?tab=timeline");
    }

    #[test]
    fn a_tampered_cookie_does_not_decode_into_something_usable() {
        assert!(decode_pending("not base64url!!").is_none());
        assert!(decode_pending(&uops_oidc::b64::encode(b"{}")).is_none());
        assert!(decode_pending("").is_none());
    }

    #[test]
    fn a_return_path_smuggled_through_the_cookie_is_still_refused() {
        // The check runs on the way out as well as the way in. A value that has been
        // outside this process and is only checked on entry is one an attacker has to
        // get past once.
        let smuggled = serde_json::to_string(&PendingCookie {
            p: uuid::Uuid::now_v7().to_string(),
            s: "s".to_owned(),
            n: "n".to_owned(),
            v: "v".to_owned(),
            r: "https://evil.example.com".to_owned(),
        })
        .unwrap();
        let (_, pending) = decode_pending(&uops_oidc::b64::encode(smuggled.as_bytes())).unwrap();
        assert_eq!(pending.return_to, "/");
    }

    #[test]
    fn a_cookie_is_read_from_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "theme=dark; uops_oidc=abc; uops_session=xyz"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            read_cookie(&headers, PENDING_COOKIE).as_deref(),
            Some("abc")
        );
        assert_eq!(read_cookie(&headers, "absent"), None);
    }

    #[test]
    fn only_the_three_roles_parse() {
        assert!(parse_role("admin").is_ok());
        assert!(parse_role("operator").is_ok());
        assert!(parse_role("viewer").is_ok());
        assert!(parse_role("owner").is_err());
        assert!(parse_role("Admin").is_err());
    }
}
