//! Reading the two logs — SPEC §M0.8.
//!
//! # Why this file exists, which is not a comfortable answer
//!
//! `audit_log` and `access_log` have been written since M1, by every mutating handler and
//! every read of a resource, a credential or a telemetry query. The writes are real and
//! tested. **Nothing could read them back.** `PgStore::audit_entries` and
//! `PgStore::access_entries` were called only from tests, so the only way to answer *"who
//! saw this customer's telemetry"* was to open `psql`.
//!
//! That matters more than an ordinary gap because read auditing is a *claim*. SPEC §M0.8
//! asks for it on the grounds that "defence and law-enforcement buyers audit who **saw**
//! this, not only who changed it", `docs/security-overview.md` offers it to buyers, and
//! `docs/PRODUCT-STRATEGY.md` listed it as an advantage that is "true today". It was true
//! of the rows and false of the product.
//!
//! Found by auditing the codebase for functions that only tests call — the sixth instance
//! of that shape in two days.
//!
//! # Two logs, two routes, and no merged view
//!
//! They answer different questions and an auditor asks one at a time: *who changed this*
//! and *who saw this*. Interleaving them would produce a stream where the interesting rows
//! — a handful of reads of one credential — are buried in the ordinary traffic of
//! acknowledging alerts. The shapes differ too: a change has a before and an after, a read
//! has a row count and a query fingerprint.
//!
//! # Admin, and audited itself
//!
//! Reading an audit log is itself a read worth recording: the first thing an investigator
//! wants to know about a log is who else has been through it. So these routes audit, which
//! means reading the access log appears in the access log — correctly, and by design.

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use uops_core::Role;

use crate::error::ApiResult;
use crate::extract::Caller;
use crate::state::AppState;

/// How many entries a page holds by default.
///
/// The store clamps to 1 000 whatever is asked. Two hundred here because an auditor scans
/// rather than reads, and a thousand rows of JSON before and after is megabytes.
const DEFAULT_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
pub struct Paging {
    #[serde(default)]
    pub limit: Option<i64>,
}

/// One mutating call.
#[derive(Debug, Serialize)]
pub struct ChangeView {
    /// `user:<uuid>` | `collector` | `system`.
    pub actor: String,
    /// Dotted and stable across releases, so an auditor's saved filter keeps working.
    pub action: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

/// One read.
#[derive(Debug, Serialize)]
pub struct ReadView {
    pub actor: String,
    /// `resource:<id>` | `resources` | `query` | `credential:<id>`.
    pub target: String,
    /// The *shape* of a query and never its parameters — those carry a customer's
    /// hostnames and addresses, and an auditor needs to know what was asked rather than to
    /// be handed a second copy of the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// How much was returned. The number that turns "somebody ran a query" into "somebody
    /// took the estate".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

/// `GET /api/v1/audit/changes`
///
/// Who changed what, with before and after. Admin: an audit log names people and shows the
/// values they touched, and a viewer has no business in it.
pub async fn changes(
    State(state): State<AppState>,
    caller: Caller,
    Query(paging): Query<Paging>,
) -> ApiResult<Json<Vec<ChangeView>>> {
    caller.require(Role::Admin)?;

    let limit = paging.limit.unwrap_or(DEFAULT_LIMIT);
    let rows = state
        .store
        .audit_entries(caller.scope().tenant_id(), limit)
        .await?;

    caller.audit().read(
        "audit.changes",
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(
        rows.into_iter()
            .map(|e| ChangeView {
                actor: e.actor,
                action: e.action,
                target: e.target,
                before: e.before,
                after: e.after,
                ip: e.ip.map(|a| a.to_string()),
            })
            .collect(),
    ))
}

/// `GET /api/v1/audit/reads`
///
/// Who *saw* what — the log SPEC §M0.8 exists for, and the one that had no reader.
pub async fn reads(
    State(state): State<AppState>,
    caller: Caller,
    Query(paging): Query<Paging>,
) -> ApiResult<Json<Vec<ReadView>>> {
    caller.require(Role::Admin)?;

    let limit = paging.limit.unwrap_or(DEFAULT_LIMIT);
    let rows = state
        .store
        .access_entries(caller.scope().tenant_id(), limit)
        .await?;

    // Reading the access log is itself an access, and it lands in the log being read.
    // That is correct: the first question about a log is who else has been through it.
    caller.audit().read(
        "audit.reads",
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(
        rows.into_iter()
            .map(|e| ReadView {
                actor: e.actor,
                target: e.target,
                fingerprint: e.fingerprint,
                row_count: e.row_count,
                ip: e.ip.map(|a| a.to_string()),
            })
            .collect(),
    ))
}
