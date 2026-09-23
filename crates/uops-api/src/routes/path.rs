//! The path to a target — `docs/traceroute.md`.
//!
//! # Why this is a POST and audited
//!
//! It sends packets. Every other read in this API asks `PostgreSQL` or `ClickHouse` what
//! it already knows; this one reaches out from the product to an address a caller named,
//! which is an *action* against somebody's network and is closer to a runbook run than to
//! a query. So: operator, not viewer, and an audit entry naming the target.
//!
//! # Why it is not stored
//!
//! A traceroute is a question asked now. Keeping a history of them is a different feature
//! with a retention decision attached, and nothing asks for one yet —
//! `docs/traceroute.md` §6.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use uops_core::{Error as CoreError, Role};

use crate::csrf::CsrfChecked;
use crate::error::ApiResult;
use crate::extract::Caller;
use crate::state::AppState;

/// What a client asks for.
#[derive(Debug, Deserialize)]
pub struct TraceRequest {
    /// An IPv4 address or a hostname. Validated before anything is spawned.
    pub target: String,
    #[serde(default)]
    pub max_hops: Option<u8>,
}

/// One step on the path, as the screen draws it.
#[derive(Debug, Serialize)]
pub struct HopView {
    pub number: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// `private`, `carrier_grade`, `link_local`, `loopback`, `public` or `unknown`.
    ///
    /// Sent rather than derived on the client, so two screens cannot disagree about where
    /// the estate ends — which is the distinction `docs/traceroute.md` §4 exists for.
    pub scope: uops_path::Scope,
    /// Whether this address is off the public internet.
    ///
    /// Deliberately **not** "is it yours": a private hop may belong to the carrier, which
    /// real output showed within minutes — see `uops_path::Scope::is_not_public`.
    pub not_public: bool,
    /// One entry per probe; `null` for each that timed out.
    pub rtt_ms: Vec<Option<f64>>,
    /// Fraction of probes lost at this hop, or `null` when none were sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss: Option<f64>,
    /// The fastest probe — the one least polluted by queueing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_ms: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct TraceView {
    pub target: String,
    pub hops: Vec<HopView>,
    /// Whether the path arrived.
    pub reached: bool,
    /// Exactly what the command printed. The parser reads prose and a reader must be able
    /// to see past it.
    pub raw: String,
}

/// `POST /api/v1/trace`
///
/// Operator, not viewer — see the module docs.
pub async fn run(
    State(_state): State<AppState>,
    caller: Caller,
    _csrf: CsrfChecked,
    Json(body): Json<TraceRequest>,
) -> ApiResult<Json<TraceView>> {
    caller.require(Role::Operator)?;

    let target = body.target.trim().to_owned();
    if !uops_path::probe::is_usable_target(&target) {
        return Err(CoreError::Invalid(format!(
            "`target` must be an IPv4 address or a hostname, and {target:?} is neither"
        ))
        .into());
    }

    // Audited before it runs, not after: a trace that hung or crashed the process still
    // happened, and "who asked this product to send packets at that address" is the
    // question an investigation starts from.
    caller.audit().wrote(
        "trace.run",
        format!("target:{target}"),
        None,
        Some(serde_json::json!({ "target": target })),
    );

    let trace = uops_path::trace(&target, body.max_hops.unwrap_or(uops_path::MAX_HOPS)).await?;

    Ok(Json(TraceView {
        target: trace.target,
        reached: trace.reached,
        raw: trace.raw,
        hops: trace
            .hops
            .into_iter()
            .map(|h| HopView {
                number: h.number,
                not_public: h.scope.is_not_public(),
                loss: h.loss(),
                best_ms: h.best_ms(),
                address: h.address,
                scope: h.scope,
                rtt_ms: h.rtt_ms,
            })
            .collect(),
    }))
}
