//! The service map — M8 §2.6.
//!
//! One route, one shape: which services called which, over a window.
//!
//! # Why this is a GET while `/api/v1/query` is a POST
//!
//! The query endpoint is a POST because the AST does not fit in a URL. This takes a
//! window and a limit, which do — so it is a GET, and a GET is what a read should be.
//! Nothing about it needs a CSRF token either, for the same reason: there is no state to
//! change and no cookie-authenticated write to forge.
//!
//! # Roles
//!
//! `Viewer`. It is a read of telemetry the tenant already has.
//!
//! # Nothing here is configured
//!
//! §2.6, and the property the shape has to preserve: an edge exists because a parent span
//! in one service has a child in another. There is no POST beside this one, because there
//! is nothing an operator could usefully assert — an edge that had to be declared would
//! be a second source of truth to reconcile, and the spans are already the first.

use axum::Json;
use axum::extract::{Query as UrlQuery, State};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uops_core::{ResourceId, Role};
use uops_store_ch::TraceStore;

use crate::error::{ApiError, ApiResult};
use crate::extract::Caller;
use crate::state::AppState;

/// The window a map covers when the caller does not say.
///
/// Fifteen minutes, which is what a map is for: *what is talking to what right now*. A
/// day's worth would draw every service that has ever spoken to another, including the
/// batch job that ran once at 03:00, and a map that never forgets is a map that cannot
/// show an edge disappearing.
const DEFAULT_WINDOW: Duration = Duration::minutes(15);

/// How many edges to draw.
const DEFAULT_EDGES: u32 = 200;

#[derive(Debug, Deserialize)]
pub struct MapParams {
    #[serde(default)]
    pub start: Option<DateTime<Utc>>,
    #[serde(default)]
    pub end: Option<DateTime<Utc>>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One directed call relationship.
#[derive(Debug, Serialize)]
pub struct EdgeView {
    pub from: ResourceId,
    pub to: ResourceId,
    /// How many calls were seen, and **not** how many were made.
    ///
    /// M8 §2.3: traces are sampled upstream of this product and an unsampled span is
    /// simply absent, so every count here is a count of *sampled* calls with an unknown
    /// denominator. The field is named for what it is so a client cannot render it as a
    /// total by accident.
    pub sampled_calls: u64,
    /// Of those calls, how many ended with `status_code = 'error'`.
    ///
    /// `unset` is `OTel`'s default and is not a failure — see `0008_spans.sql`.
    pub sampled_errors: u64,
    /// The 95th percentile of the child span's duration, in nanoseconds.
    ///
    /// Unlike the counts, this one is trustworthy under sampling: a percentile over a
    /// sample estimates the percentile over the whole. §2.3 spells out the asymmetry.
    pub p95_ns: u64,
}

#[derive(Debug, Serialize)]
pub struct ServiceMapView {
    pub edges: Vec<EdgeView>,
    /// The window actually read, which is not always the one asked for — a caller that
    /// named neither end gets the default and should be able to see which.
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Whether the map was cut off at the limit.
    ///
    /// A truncated map is a different picture from a complete one, and the edges past the
    /// cut are the rare ones because the statement orders by volume. A client that did
    /// not know would draw a confident diagram of the busiest half of an estate.
    pub truncated: bool,
}

/// `GET /api/v1/service-map`
pub async fn get(
    State(state): State<AppState>,
    caller: Caller,
    UrlQuery(params): UrlQuery<MapParams>,
) -> ApiResult<Json<ServiceMapView>> {
    caller.require(Role::Viewer)?;

    let end = params.end.unwrap_or_else(Utc::now);
    let start = params.start.unwrap_or(end - DEFAULT_WINDOW);
    let limit = params.limit.unwrap_or(DEFAULT_EDGES);

    let result = state
        .telemetry
        .service_map(caller.scope(), start, end, limit)
        .await
        .map_err(|e| ApiError::Internal(e.into()))?;

    let edges: Vec<EdgeView> = (0..result.len()).filter_map(|i| edge(&result, i)).collect();

    caller.audit().read(
        "service_map.get",
        Some(i64::try_from(edges.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(ServiceMapView {
        truncated: edges.len() >= limit.min(uops_query::MAX_EDGES) as usize,
        edges,
        start,
        end,
    }))
}

/// One row, or nothing if it is not one.
///
/// A row that cannot be read is skipped rather than turned into an edge with zeros in it.
/// A zero here would be indistinguishable from a real service pair that made no calls,
/// which cannot happen and would therefore be read as a fact.
fn edge(result: &uops_store_ch::ResultSet, i: usize) -> Option<EdgeView> {
    let id = |name: &str| -> Option<ResourceId> {
        result
            .value(i, name)?
            .as_str()?
            .parse()
            .ok()
            .map(ResourceId::from_uuid)
    };
    // `ClickHouse`'s JSON renders 64-bit integers as strings, because a `UInt64` does not
    // survive a double. Both forms are read so this does not depend on that staying true.
    let count = |name: &str| -> Option<u64> {
        let v = result.value(i, name)?;
        v.as_u64().or_else(|| v.as_str()?.parse().ok())
    };

    Some(EdgeView {
        from: id("from_service")?,
        to: id("to_service")?,
        sampled_calls: count("calls")?,
        sampled_errors: count("errors")?,
        p95_ns: count("p95")?,
    })
}
