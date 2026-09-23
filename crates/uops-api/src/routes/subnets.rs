//! Address space — `docs/ipam.md`.
//!
//! Four verbs over one declared thing, and two reads that are entirely derived.
//!
//! # Why the counts are three numbers and not a percentage
//!
//! `docs/ipam.md` §2.6. "97% full" hides whether the other 3% is reserved, and an address
//! inventory whose headline number cannot be acted on is a decoration. The API sends
//! capacity, assigned and responding, and the screen shows all three — a reader who wants
//! a ratio can form one, and will know what went into it.
//!
//! `unaccounted` is the one that is not arithmetic on the other three: an address that
//! answered and that no resource claims. That is the finding — either a device nobody
//! inventoried or a device somebody plugged in — and the product does not guess which.
//!
//! # Reading address space is a read worth auditing
//!
//! The same reasoning M12 applied to telemetry reads: an inventory of every address in an
//! estate is exactly the reconnaissance an attacker would want, and for the buyer this
//! product is built for, "who listed the address space and when" is a question an assessor
//! asks. So both reads audit, like every other read here.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use uops_core::{Error as CoreError, ResourceId, Role, SiteId};
use uops_store_pg::NewSubnet;

use crate::csrf::CsrfChecked;
use crate::error::ApiResult;
use crate::extract::Caller;
use crate::state::AppState;

/// The most addresses one range will list.
///
/// A /16 has sixty-five thousand addresses and this endpoint returns only the ones
/// something is known about, so the cap is reached by an estate that really does have
/// thousands of devices in one range. It is a cap rather than a cursor because the screen
/// that reads this is a list somebody scans, not one they page through — and a range with
/// more than a thousand known addresses is a range that should be split, which is a thing
/// the screen can say.
const MAX_ADDRESSES: i64 = 1_000;

/// One declared range, with what is in it.
#[derive(Debug, Serialize)]
pub struct SubnetView {
    pub id: uuid::Uuid,
    /// In CIDR, exactly as `PostgreSQL` normalised it.
    pub range: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_id: Option<SiteId>,
    pub assignment: String,
    /// Usable addresses — /31 and /32 handled, see migration 0028.
    pub capacity: i64,
    /// Addresses a resource claims.
    pub assigned: i64,
    /// Addresses something answered on. Overlaps `assigned` and is not a sum.
    pub responding: i64,
    /// Answered, and nothing in the inventory claims it.
    pub unaccounted: i64,
}

/// One address inside a range.
#[derive(Debug, Serialize)]
pub struct AddressView {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<ResourceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    pub responding: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    /// Responding, and unclaimed. Sent rather than left to the client to derive, so two
    /// clients cannot disagree about what the word means.
    pub unaccounted: bool,
}

/// `GET /api/v1/subnets`
///
/// Every declared range with its counts. Not paginated, for the reason
/// `routes::sites::list` gives about sites: an estate declares ranges in the tens, and the
/// screen has to render in one round trip.
pub async fn list(State(state): State<AppState>, caller: Caller) -> ApiResult<Json<Vec<SubnetView>>> {
    caller.require(Role::Viewer)?;

    let rows = state.store.subnet_utilisation(caller.scope()).await?;
    caller.audit().read(
        "subnet.list",
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(
        rows.into_iter()
            .map(|u| SubnetView {
                id: u.subnet.id,
                range: u.subnet.range.to_string(),
                name: u.subnet.name,
                description: u.subnet.description,
                site_id: u.subnet.site_id,
                assignment: u.subnet.assignment,
                capacity: u.capacity,
                assigned: u.assigned,
                responding: u.responding,
                unaccounted: u.unaccounted,
            })
            .collect(),
    ))
}

/// What a client sends to declare a range.
#[derive(Debug, Deserialize)]
pub struct Declaration {
    /// CIDR. Parsed here so a malformed range is a 422 naming the field rather than a
    /// database error naming a constraint.
    pub range: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub site_id: Option<SiteId>,
    #[serde(default = "default_assignment")]
    pub assignment: String,
}

fn default_assignment() -> String {
    "static".to_owned()
}

/// How addresses in a range are handed out.
///
/// Checked here as well as by the schema's CHECK, and the duplication is the one this
/// codebase makes deliberately: the constraint is the guarantee, and this is the message
/// somebody can act on.
const ASSIGNMENTS: [&str; 3] = ["static", "dhcp", "reserved"];

/// `POST /api/v1/subnets`
///
/// Operator, not viewer: a declared range changes what every reader's utilisation says.
pub async fn declare(
    State(state): State<AppState>,
    caller: Caller,
    _csrf: CsrfChecked,
    Json(body): Json<Declaration>,
) -> ApiResult<(StatusCode, Json<SubnetView>)> {
    caller.require(Role::Operator)?;

    let range: uops_discover::Range = body.range.parse().map_err(|e| {
        CoreError::Invalid(format!(
            "`range` must be an IPv4 range in CIDR, such as 10.0.1.0/24: {e}"
        ))
    })?;

    if !ASSIGNMENTS.contains(&body.assignment.as_str()) {
        return Err(CoreError::Invalid(format!(
            "`assignment` must be one of {}, and was {:?}",
            ASSIGNMENTS.join(", "),
            body.assignment
        ))
        .into());
    }

    if body.name.trim().is_empty() {
        return Err(CoreError::Invalid("`name` must not be empty".to_owned()).into());
    }

    let created = state
        .store
        .declare_subnet(
            caller.scope(),
            &NewSubnet {
                range,
                name: body.name.trim().to_owned(),
                description: body.description,
                site_id: body.site_id,
                assignment: body.assignment,
            },
        )
        .await?;

    caller.audit().wrote(
        "subnet.declare",
        format!("subnet:{}", created.id),
        None,
        Some(serde_json::json!({
            "range": created.range.to_string(),
            "name": created.name,
            "assignment": created.assignment,
        })),
    );

    Ok((
        StatusCode::CREATED,
        Json(SubnetView {
            id: created.id,
            range: created.range.to_string(),
            name: created.name,
            description: created.description,
            site_id: created.site_id,
            assignment: created.assignment,
            // A range declared a moment ago has not been counted yet. Zeroes rather than a
            // second query: the client reloads the list, and inventing counts here would
            // mean two code paths computing the same numbers.
            capacity: 0,
            assigned: 0,
            responding: 0,
            unaccounted: 0,
        }),
    ))
}

/// `DELETE /api/v1/subnets/{id}`
///
/// Forgets the declaration. Nothing about the addresses themselves is stored, so this
/// removes a view and never touches the estate — which is the practical benefit of
/// computing utilisation rather than keeping it.
pub async fn forget(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    _csrf: CsrfChecked,
) -> ApiResult<StatusCode> {
    caller.require(Role::Operator)?;

    let existed = state.store.forget_subnet(caller.scope(), id).await?;
    if !existed {
        return Err(CoreError::NotFound {
            kind: "subnet",
            id: id.to_string(),
        }
        .into());
    }

    caller
        .audit()
        .wrote("subnet.forget", format!("subnet:{id}"), None, None);

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct Limit {
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /api/v1/subnets/{id}/addresses`
///
/// What is in one range, address by address. Only addresses something is known about: a
/// range's empty addresses are its capacity minus what is listed, and enumerating a /16 to
/// send sixty-five thousand "nothing here" rows would be a slow way to say very little.
pub async fn addresses(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<uuid::Uuid>,
    Query(q): Query<Limit>,
) -> ApiResult<Json<Vec<AddressView>>> {
    caller.require(Role::Viewer)?;

    let limit = q.limit.unwrap_or(MAX_ADDRESSES).clamp(1, MAX_ADDRESSES);
    // `None` is "not this tenant's range", and it must be a 404 rather than an empty list
    // — otherwise the owner of an empty range and somebody probing another tenant's ids
    // get the same answer. The isolation test is what found this.
    let Some(rows) = state
        .store
        .subnet_addresses(caller.scope(), id, limit)
        .await?
    else {
        return Err(CoreError::NotFound {
            kind: "subnet",
            id: id.to_string(),
        }
        .into());
    };

    caller.audit().read(
        "subnet.addresses",
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(
        rows.into_iter()
            .map(|a| AddressView {
                address: a.address.to_string(),
                unaccounted: a.is_unaccounted(),
                resource_id: a.resource_id,
                resource_name: a.resource_name,
                responding: a.responding,
                last_seen: a.last_seen,
            })
            .collect(),
    ))
}
