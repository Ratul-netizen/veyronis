//! The customers an installation carries — `docs/tenant-lifecycle.md`.
//!
//! ```text
//!   GET    /tenants              every tenant here, including retired ones
//!   POST   /tenants              create one; the creator becomes its administrator
//!   PATCH  /tenants/{id}         rename it, or change its slug
//!   POST   /tenants/{id}/retire  stop scheduling against it
//!   POST   /tenants/{id}/restore bring it back
//! ```
//!
//! # Organization-level, and no tenant header
//!
//! All five take `OrgAdmin`. Creating one has no tenant for the request to be *about*, and
//! `Caller` would demand a header naming a tenant that does not exist yet. Audited with a
//! `NULL` `tenant_id`, which migration 0024 made possible for exactly this class of act —
//! `sso.rs` puts it well: *"writing them against an arbitrary tenant would be a lie, and
//! specifically the kind an auditor has to be told about afterwards."*
//!
//! # `GET /tenants` is not `/me`
//!
//! `/me` lists the tenants the caller holds a role on, for the switcher. This lists every
//! tenant in the organization including retired ones and ones the caller cannot see, which is
//! information only an organization administrator should have.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use uops_core::TenantId;
use uops_store_pg::TenantChange;

use crate::csrf::CsrfChecked;
use crate::error::{ApiError, ApiResult};
use crate::extract::OrgAdmin;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct TenantView {
    pub id: TenantId,
    pub name: String,
    pub slug: String,
    pub created_at: String,
    /// Set when retired. Retirement is reversible and is not deletion — the estate is still
    /// there, because eight of the foreign keys referencing a tenant refuse to cascade.
    pub retired_at: Option<String>,
    /// Carries the installation's own events. Cannot be retired while it does.
    pub is_platform: bool,
    /// How many people hold a role here, so "who would lose access" is answerable *before*
    /// retiring one.
    pub members: i64,
}

fn view(t: uops_store_pg::TenantRow) -> TenantView {
    TenantView {
        id: t.id,
        name: t.name,
        slug: t.slug,
        created_at: t.created_at.to_rfc3339(),
        retired_at: t.retired_at.map(|d| d.to_rfc3339()),
        is_platform: t.is_platform,
        members: t.members,
    }
}

/// `GET /api/v1/tenants`
pub async fn list(
    State(state): State<AppState>,
    admin: OrgAdmin,
) -> ApiResult<Json<Vec<TenantView>>> {
    let rows = state.store.tenants_in_org(admin.org_id).await?;

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "tenant.list",
            &admin.org_id.to_string(),
            None,
            None,
        )
        .await?;

    Ok(Json(rows.into_iter().map(view).collect()))
}

#[derive(Debug, Deserialize)]
pub struct NewTenant {
    pub name: String,
    pub slug: String,
}

/// `POST /api/v1/tenants`
///
/// The creating administrator is granted `admin` on the new tenant in the same transaction,
/// and it is not optional: `is_org_admin` requires admin on *every* tenant, so without it the
/// creator loses organization-wide admin the instant this commits and cannot get it back.
/// `docs/tenant-lifecycle.md` §2.
pub async fn create(
    State(state): State<AppState>,
    admin: OrgAdmin,
    _csrf: CsrfChecked,
    Json(body): Json<NewTenant>,
) -> ApiResult<(StatusCode, Json<TenantView>)> {
    let name = body.name.trim();
    let slug = body.slug.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest(
            "a name is required: a tenant list of slugs is one nobody can read".to_owned(),
        ));
    }
    check_slug(slug)?;

    let created = state
        .store
        .create_tenant(admin.org_id, name, slug, admin.user_id)
        .await?
        .map_err(refusal)?;

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "tenant.create",
            &created.id.to_string(),
            Some(serde_json::json!({ "name": name, "slug": slug })),
            None,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(view(created))))
}

/// `PATCH /api/v1/tenants/{id}`
///
/// Renaming is permitted, and so is changing the slug. §3.2 declines to declare it immutable:
/// nothing durable references it, so immutability would be a rule that reads as a safeguard
/// and protects nothing.
pub async fn rename(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
    Json(body): Json<NewTenant>,
) -> ApiResult<StatusCode> {
    let name = body.name.trim();
    let slug = body.slug.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("a name is required".to_owned()));
    }
    check_slug(slug)?;

    match state
        .store
        .rename_tenant(admin.org_id, TenantId::from(id), name, slug)
        .await?
    {
        TenantChange::Done => {}
        other => return Err(refusal(other)),
    }

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "tenant.update",
            &id.to_string(),
            Some(serde_json::json!({ "name": name, "slug": slug })),
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/tenants/{id}/retire`
///
/// Stops the scheduling loops reaching it and hides it. **Does not delete anything** — not
/// its resources, not its telemetry. §4.3: a purge is a separate operation and is not built,
/// so the honest answer to "is the data gone" is no, and the retention table says when.
pub async fn retire(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    match state
        .store
        .retire_tenant(admin.org_id, TenantId::from(id))
        .await?
    {
        TenantChange::Done => {}
        other => return Err(refusal(other)),
    }

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "tenant.retire",
            &id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/tenants/{id}/restore`
pub async fn restore(
    State(state): State<AppState>,
    admin: OrgAdmin,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    if !state
        .store
        .restore_tenant(admin.org_id, TenantId::from(id))
        .await?
    {
        return Err(ApiError::NotFound);
    }

    state
        .store
        .record_org_audit(
            admin.org_id,
            &admin.actor(),
            "tenant.restore",
            &id.to_string(),
            None,
            None,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The slug rule, said in a sentence before the database says it in a constraint.
///
/// The constraint is the one that counts — it is in the schema because `bootstrap` writes a
/// tenant too, and a rule living in one caller is a rule the other caller breaks. This exists
/// so somebody is told what is wrong rather than handed a regular expression.
fn check_slug(slug: &str) -> Result<(), ApiError> {
    let shaped = !slug.is_empty()
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.contains("--");

    if !shaped || !(2..=63).contains(&slug.chars().count()) {
        return Err(ApiError::BadRequest(
            "a slug is 2 to 63 characters of lowercase letters, digits and single hyphens \
             between them — it is the short name that appears in the tenant switcher"
                .to_owned(),
        ));
    }
    Ok(())
}

/// A refusal, as the sentence somebody reads.
///
/// Each names what to do next. A 409 rather than a 400 for the three state refusals: nothing
/// about the request was wrong, and telling somebody to fix their input would send them
/// looking in the wrong place.
fn refusal(change: TenantChange) -> ApiError {
    match change {
        TenantChange::NoSuchTenant | TenantChange::Done => ApiError::NotFound,
        TenantChange::SlugTaken => ApiError::Conflict(
            "another tenant here already uses that short name. A retired tenant keeps its \
             name, so that restoring it cannot collide"
                .to_owned(),
        ),
        TenantChange::WouldLeaveNoTenant => ApiError::Conflict(
            "this is the only tenant left. An installation with none is one nobody can get \
             back into — create another first"
                .to_owned(),
        ),
        TenantChange::IsThePlatformTenant => ApiError::Conflict(
            "this tenant carries the events about the installation itself. Nominate another \
             one for that first"
                .to_owned(),
        ),
    }
}
