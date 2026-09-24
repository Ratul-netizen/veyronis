//! The three OTLP/HTTP endpoints.
//!
//! # What an exporter is told, and why it matters
//!
//! OTLP defines a `partial_success` in every export response, and it is the difference
//! between a receiver that is honest and one that is not. A receiver that converted nine
//! records of ten and answered `200 {}` would be lying by omission — the exporter would
//! move on, the operator would never know, and the missing tenth would only surface as a
//! chart that is quietly wrong.
//!
//! So everything this cannot store is counted and named in the response: histograms,
//! summaries, and data points with no timestamp. An operator whose latency histograms
//! never appear learns it from their own collector's logs rather than from an absent
//! chart three weeks later.
//!
//! # Status codes
//!
//! `200` when the payload was understood, whatever fraction of it could be stored.
//! `400` when the protobuf did not decode, which is a bug in the sender and is not worth
//! retrying. `503` when the queue to the batcher is closed, which means this process is
//! shutting down and the exporter **should** retry — the OTLP specification says a 503 is
//! retryable and that is exactly the behaviour wanted.
//!
//! Notably not `429`. Backpressure here is the handler *waiting* on a bounded channel,
//! which becomes the exporter waiting on the response, which is what HTTP already does
//! well. Telling a collector to go away and come back is worse than making it wait.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsPartialSuccess, ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTracePartialSuccess, ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use prost::Message as _;

use crate::run::Listener;

/// `application/x-protobuf`, which is what the `otlphttp` exporter sends and expects.
///
/// OTLP/HTTP also defines a JSON encoding. It is not accepted here: the Collector does not
/// default to it, supporting it would mean a second decoder to keep in step with the
/// first, and the failure of a second decoder is rows that differ depending on how they
/// arrived — which is the thing this whole product is built to prevent.
const PROTOBUF: &str = "application/x-protobuf";

/// One of the three services' answers, encoded.
fn protobuf(message: &impl prost::Message) -> Response {
    let mut body = Vec::with_capacity(message.encoded_len());
    // Encoding into a Vec with enough capacity cannot fail; the Result is prost's
    // signature for writers that can.
    let _ = message.encode(&mut body);
    ([(axum::http::header::CONTENT_TYPE, PROTOBUF)], body).into_response()
}

/// A request body that was not a valid export request.
fn undecodable(what: &str, e: &prost::DecodeError) -> Response {
    // 400, not 500: the sender produced this and retrying it will produce it again.
    (
        StatusCode::BAD_REQUEST,
        format!("the {what} export request could not be decoded: {e}"),
    )
        .into_response()
}

/// The queue to the batcher has closed, which means this process is stopping.
///
/// 503 rather than 500, because OTLP says a 503 is retryable and an exporter that retries
/// into the *next* instance is the behaviour wanted during a rolling restart.
fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "the collector is shutting down; retry",
    )
        .into_response()
}

/// Whether this request may write into this listener's tenant.
///
/// `docs/packaging.md` §4.2. Returns the refusal to send back, or `None` to carry on.
///
/// # One sentence for every failure
///
/// A missing header, a malformed one, a wrong token, a revoked one, an expired one, and a
/// token for a *different* tenant all get the same 401. Telling an exporter which would
/// confirm that a token was once real, or that it is real but for somewhere else — and the
/// second is worse, because it says this endpoint serves a tenant somebody else has a
/// credential for. The server log gets the distinction; the wire does not.
///
/// # Why the token must match *this* listener's tenant
///
/// A token authorises writing into one tenant, and a listener is already bound to one. §4.2
/// describes an eventual single endpoint where the token picks the tenant; that is a larger
/// change to the listener model and this is the step before it. Until then, presenting tenant
/// A's token to tenant B's port is refused rather than quietly writing into A — which would
/// make the binding a suggestion.
async fn may_write(listener: &Listener, headers: &HeaderMap) -> Option<Response> {
    if !listener.require_token {
        return None;
    }

    let refused = || -> Option<Response> {
        Some(
            (
                StatusCode::UNAUTHORIZED,
                "this endpoint requires an ingest token for the tenant it serves",
            )
                .into_response(),
        )
    };

    let Some(presented) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        eprintln!("uops-collector-otlp: a request arrived with no bearer token");
        return refused();
    };

    match listener.store.tenant_for_ingest_token(presented).await {
        Ok(Some(tenant)) if tenant == listener.tenant_id => None,
        Ok(Some(_)) => {
            eprintln!(
                "uops-collector-otlp: a token for another tenant was presented to the listener \
                 for {}",
                listener.tenant_id
            );
            refused()
        }
        Ok(None) => {
            eprintln!("uops-collector-otlp: an unknown, revoked or expired token was presented");
            refused()
        }
        // The store is unreachable, which is not the sender's fault and must not read as one:
        // a 401 would have an exporter drop the batch and, worse, have an operator revoking
        // tokens that were never the problem. 503 is what the exporter retries.
        Err(e) => {
            eprintln!("uops-collector-otlp: cannot check an ingest token: {e}");
            Some(unavailable())
        }
    }
}

/// `POST /v1/logs`
pub async fn logs(
    State(listener): State<Arc<Listener>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Before decoding: a body from an unauthorised sender is not worth parsing, and
    // parsing it first would make the endpoint a decoder for anyone who can reach it.
    if let Some(refusal) = may_write(&listener, &headers).await {
        return refusal;
    }

    let request = match ExportLogsServiceRequest::decode(body) {
        Ok(r) => r,
        Err(e) => return undecodable("logs", &e),
    };

    match listener.ingest_logs(&request.resource_logs).await {
        Ok(rejected) => protobuf(&ExportLogsServiceResponse {
            partial_success: partial(rejected).map(|(count, message)| ExportLogsPartialSuccess {
                rejected_log_records: count,
                error_message: message,
            }),
        }),
        Err(_) => unavailable(),
    }
}

/// `POST /v1/metrics`
pub async fn metrics(
    State(listener): State<Arc<Listener>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Before decoding: a body from an unauthorised sender is not worth parsing, and
    // parsing it first would make the endpoint a decoder for anyone who can reach it.
    if let Some(refusal) = may_write(&listener, &headers).await {
        return refusal;
    }

    let request = match ExportMetricsServiceRequest::decode(body) {
        Ok(r) => r,
        Err(e) => return undecodable("metrics", &e),
    };

    match listener.ingest_metrics(&request.resource_metrics).await {
        Ok(rejected) => protobuf(&ExportMetricsServiceResponse {
            partial_success: partial(rejected).map(|(count, message)| {
                ExportMetricsPartialSuccess {
                    rejected_data_points: count,
                    error_message: message,
                }
            }),
        }),
        Err(_) => unavailable(),
    }
}

/// `POST /v1/traces`
///
/// Until M8 this counted the spans and reported them all as `rejected_spans`, because
/// SPEC §M3 asked for exactly that: *"trace accepts and stores nothing until M8 — accept
/// and drop with a counter, so instrumented apps don't error."*
///
/// They are stored now, so the apology goes. An exporter that kept being told its spans
/// were rejected would be right to stop sending them, and a `partial_success` that
/// outlives the thing it was reporting is worse than none at all — it is a receiver
/// lying about itself in the other direction.
pub async fn traces(
    State(listener): State<Arc<Listener>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Before decoding: a body from an unauthorised sender is not worth parsing, and
    // parsing it first would make the endpoint a decoder for anyone who can reach it.
    if let Some(refusal) = may_write(&listener, &headers).await {
        return refusal;
    }

    let request = match ExportTraceServiceRequest::decode(body) {
        Ok(r) => r,
        Err(e) => return undecodable("trace", &e),
    };

    match listener.ingest_traces(&request.resource_spans).await {
        Ok(rejected) => protobuf(&ExportTraceServiceResponse {
            partial_success: partial(rejected).map(|(count, message)| ExportTracePartialSuccess {
                rejected_spans: count,
                error_message: message,
            }),
        }),
        Err(_) => unavailable(),
    }
}

/// Turn a rejected count into the `partial_success` an exporter should see.
///
/// `None` when nothing was rejected: OTLP says an empty `partial_success` means full
/// success, and sending one populated with zeros is a message some collectors log as a
/// warning every batch.
fn partial(rejected: Rejected) -> Option<(i64, String)> {
    if rejected.count == 0 {
        return None;
    }
    Some((
        i64::try_from(rejected.count).unwrap_or(i64::MAX),
        rejected.why,
    ))
}

/// What could not be stored, and why — in the exporter's words rather than ours.
#[derive(Debug, Default, Clone)]
pub struct Rejected {
    pub count: u64,
    pub why: String,
}

impl Rejected {
    #[must_use]
    pub fn new(count: u64, why: impl Into<String>) -> Self {
        Self {
            count,
            why: why.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_rejected_is_no_partial_success_at_all() {
        // OTLP says an empty partial_success means full success, and one populated with
        // zeros is a message some collectors log as a warning every batch.
        assert!(partial(Rejected::default()).is_none());
        assert!(partial(Rejected::new(0, "unused")).is_none());
    }

    #[test]
    fn something_rejected_is_reported_with_a_reason() {
        // The difference between a receiver that is honest and one that converted nine
        // records of ten and answered 200 {}.
        let (count, why) =
            partial(Rejected::new(3, "histograms are not stored yet")).expect("a partial success");
        assert_eq!(count, 3);
        assert!(why.contains("histograms"));
    }
}
