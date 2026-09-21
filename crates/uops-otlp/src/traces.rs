//! `ExportTraceServiceRequest` → [`SpanRow`].
//!
//! The third signal this crate decodes, and the one the endpoint has been accepting and
//! discarding since M3 — `POST /v1/traces` has replied with a partial-success message
//! naming M8 all along, so that instrumented applications would not error while the store
//! was missing.
//!
//! # A span has two subjects, and both are on the row
//!
//! `docs/M8-observability.md` §2.1. A span ran on a **host** and is work done by a
//! **service**, and one service runs on many hosts. `resource_id` is the host, because
//! the sort key leads with it and a span keyed by service would stop sitting beside the
//! logs and metrics of the machine it ran on; `service_id` is the service, reached
//! through `service_5m`.
//!
//! This file fills neither. Both are resolved by the caller, which is the same split
//! [`crate::logs`] has and for the same reason: resolution awaits `PostgreSQL` and
//! decoding does not.
//!
//! # Sampling is recorded and never applied
//!
//! §2.3, and the place M8 deliberately differs from M7. Flow stored a rate and multiplied
//! at read time because sFlow states its rate reliably. Tracing does not: head sampling
//! happens in the SDK and tail sampling in a collector, both upstream, and an unsampled
//! span is simply *absent* with nothing left behind to say so.
//!
//! Where a probability is stated — in `tracestate`, as W3C's `th` threshold or as the
//! `ot=p:` probability sampler value — it is read into a column. Nothing multiplies by
//! it. A count of spans is a count of sampled spans, and the screens say so.

use uops_pipeline::Attribution;
use uops_store_ch::SpanRow;

use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, Span, Status, span, status};

use crate::{attributes, hex, instant, resource_attributes};

/// What the `kind` column calls an OTLP span kind.
///
/// `unspecified` becomes `internal`, which is what the specification says it means: a
/// span that did not say is a span that did not cross a process boundary. The column is
/// `LowCardinality` and a sixth value meaning "the exporter left it blank" would be a
/// value nobody can act on.
#[must_use]
pub fn kind(value: i32) -> &'static str {
    match span::SpanKind::try_from(value) {
        Ok(span::SpanKind::Server) => "server",
        Ok(span::SpanKind::Client) => "client",
        Ok(span::SpanKind::Producer) => "producer",
        Ok(span::SpanKind::Consumer) => "consumer",
        _ => "internal",
    }
}

/// What the `status_code` column calls an OTLP status.
///
/// **`unset` is not an error**, and the distinction is the whole reason the aggregate can
/// count failures at all. `OTel`'s default is `unset`: the instrumentation did not say, and
/// the overwhelming majority of healthy spans carry it. Treating it as a failure would
/// make every service look broken; treating it as `ok` would throw away the difference
/// between "it succeeded" and "nobody checked".
#[must_use]
pub fn status_code(status: Option<&Status>) -> &'static str {
    match status.map(|s| status::StatusCode::try_from(s.code)) {
        Some(Ok(status::StatusCode::Ok)) => "ok",
        Some(Ok(status::StatusCode::Error)) => "error",
        _ => "unset",
    }
}

/// Everything one `ResourceSpans` carries, ready for a caller that has resolved it.
///
/// The scope is kept here rather than flattened away, unlike [`crate::logs`]. A log
/// record's instrumentation library is trivia; a span's is a diagnosis — "only the gRPC
/// instrumentation is slow" is a real finding and it is unreachable once the scope is
/// discarded.
#[derive(Debug)]
pub struct Batch<'a> {
    pub resource: std::collections::BTreeMap<String, String>,
    pub spans: Vec<(&'a str, &'a Span)>,
}

/// Group a request by resource, which is the unit identity resolution works on.
#[must_use]
pub fn batches(request: &[ResourceSpans]) -> Vec<Batch<'_>> {
    request
        .iter()
        .map(|rs| Batch {
            resource: resource_attributes(rs.resource.as_ref()),
            spans: rs
                .scope_spans
                .iter()
                .flat_map(|ss| {
                    let scope = ss.scope.as_ref().map_or("", |s| s.name.as_str());
                    ss.spans.iter().map(move |span| (scope, span))
                })
                .collect(),
        })
        .collect()
}

/// Turn one resource's spans into rows.
///
/// `received_at` is when this process read the request, and becomes `ingested_at` for
/// every row.
#[must_use]
pub fn to_rows(
    batch: &Batch<'_>,
    attribution: &Attribution,
    service: uops_core::ResourceId,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Vec<SpanRow> {
    batch
        .spans
        .iter()
        .map(|(scope, span)| {
            to_row(
                &batch.resource,
                scope,
                span,
                attribution,
                service,
                received_at,
            )
        })
        .collect()
}

fn to_row(
    resource: &std::collections::BTreeMap<String, String>,
    scope: &str,
    span: &Span,
    attribution: &Attribution,
    service: uops_core::ResourceId,
    received_at: chrono::DateTime<chrono::Utc>,
) -> SpanRow {
    // Resource attributes first, then the span's own, so a span may override what its
    // resource said about itself — the same direction and the same reason as `logs`.
    let mut attrs = resource.clone();
    attrs.extend(attributes(&span.attributes));

    let start = instant(span.start_time_unix_nano);
    let end = instant(span.end_time_unix_nano);

    let observed_at = start.unwrap_or_else(|| {
        attrs.insert("otlp.timestamp.missing".to_owned(), "true".to_owned());
        received_at
    });

    // From the two timestamps, not from a duration field — OTLP has no duration field,
    // and a span whose end precedes its start is broken instrumentation rather than
    // negative time. Saturating, because the subtraction is on numbers off the wire:
    // M7's fuzzer found exactly this shape of arithmetic panicking in two decoders.
    let duration_ns = match (span.start_time_unix_nano, span.end_time_unix_nano) {
        (s, e) if e >= s => e - s,
        _ => {
            attrs.insert("otlp.duration.negative".to_owned(), "true".to_owned());
            0
        }
    };
    // A span with no end is one still in flight, or an exporter that forgot. Recorded so
    // the zero is readable as "not stated" rather than "instantaneous".
    if end.is_none() {
        attrs.insert("otlp.end.missing".to_owned(), "true".to_owned());
    }

    // The status message stays in its own column and out of the attributes. The column is
    // what the screens read, and duplicating it into the map would pay for it twice on a
    // table this size.
    let status = span.status.as_ref();

    SpanRow {
        tenant_id: attribution.tenant_id,
        resource_id: attribution.resource_id,
        service_id: service,
        site_id: attribution.site_id,
        observed_at,
        ingested_at: received_at,

        trace_id: hex(&span.trace_id),
        span_id: hex(&span.span_id),
        parent_span_id: hex(&span.parent_span_id),
        name: span.name.clone(),
        kind: kind(span.kind).to_owned(),
        duration_ns,
        status_code: status_code(status).to_owned(),
        status_message: status.map(|s| s.message.clone()).unwrap_or_default(),

        sampling_probability: sampling_probability(&span.trace_state),
        scope_name: scope.to_owned(),
        attributes: attrs,
    }
}

/// The sampling probability a `tracestate` states, or 0 for "it did not".
///
/// Two spellings are read, because both are in the wild and both live under the `ot`
/// vendor key:
///
/// * **`ot=p:N`** — the `OpenTelemetry` probability sampler's exponent. The probability is
///   `2^-N`, so `p:0` is every span and `p:10` is one in 1024.
/// * **`ot=th:HEX`** — W3C's rejection threshold, where the sampled fraction is
///   `1 - hex/2^56` and `th:0` is everything.
///
/// Anything else returns 0, which the column documents as "the exporter did not say" —
/// and §2.3 is the reason nothing may extrapolate from either value: a stated probability
/// describes the *sampler*, and what reached this process may have been sampled again by
/// a collector in between.
#[must_use]
pub fn sampling_probability(trace_state: &str) -> f32 {
    for entry in trace_state.split(',') {
        let Some((key, value)) = entry.split_once('=') else {
            continue;
        };
        if key.trim() != "ot" {
            continue;
        }
        for member in value.split(';') {
            let Some((name, raw)) = member.split_once(':') else {
                continue;
            };
            let raw = raw.trim();
            match name.trim() {
                // Parsed as `i32` rather than parsed-then-cast, so the range check is the
                // only thing standing between the wire and `powi`. An exponent past 62 is
                // not a sampler configuration, it is a typo.
                "p" => match raw.parse::<i32>() {
                    Ok(exponent) if (0..=62).contains(&exponent) => return 0.5f32.powi(exponent),
                    _ => {}
                },
                "th" => {
                    if let Some(probability) = threshold(raw) {
                        return probability;
                    }
                }
                _ => {}
            }
        }
    }
    0.0
}

/// W3C's rejection threshold, as the sampled fraction.
///
/// The encoding has a trap worth spelling out: the value is **left-aligned** hex, padded
/// on the right to 14 digits. `th:8` is `0x80000000000000`, which is *half* — reading it
/// as the integer 8 would report a sampling probability of essentially 1.0 for a trace
/// that dropped half its spans, and nothing downstream could tell.
fn threshold(raw: &str) -> Option<f32> {
    // 2^56, written out rather than shifted-and-cast: the span is a constant, and a
    // literal says so without asking a reader to trust a cast.
    const SPAN: f64 = 72_057_594_037_927_936.0;
    if raw.is_empty() || raw.len() > 14 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut padded = raw.to_owned();
    padded.push_str(&"0".repeat(14 - raw.len()));
    let rejected = u64::from_str_radix(&padded, 16).ok()?;

    // Both casts lose bits that cannot reach the result. The threshold is at most 56 bits
    // against f64's 52, and the answer is an f32 with 23 — so the discarded precision is
    // far below the resolution of the column this lands in.
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    Some((1.0 - (rejected as f64 / SPAN)).clamp(0.0, 1.0) as f32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, InstrumentationScope, KeyValue, any_value,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::ScopeSpans;
    use uops_core::semconv;

    fn string(v: &str) -> AnyValue {
        AnyValue {
            value: Some(any_value::Value::StringValue(v.to_owned())),
        }
    }

    fn attribution() -> Attribution {
        Attribution {
            tenant_id: uops_core::TenantId::new(),
            resource_id: uops_core::ResourceId::new(),
            site_id: uops_core::SiteId::nil(),
            vendor: String::new(),
        }
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("an instant")
            .with_timezone(&chrono::Utc)
    }

    const START: u64 = 1_700_000_000_000_000_000;

    fn span(name: &str) -> Span {
        Span {
            trace_id: vec![0x4b; 16],
            span_id: vec![0x01; 8],
            parent_span_id: Vec::new(),
            name: name.to_owned(),
            kind: span::SpanKind::Server as i32,
            start_time_unix_nano: START,
            end_time_unix_nano: START + 12_000_000,
            ..Span::default()
        }
    }

    fn request(spans: Vec<Span>) -> Vec<ResourceSpans> {
        vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![
                    KeyValue {
                        key: semconv::HOST_NAME.to_owned(),
                        value: Some(string("app-01")),
                        ..KeyValue::default()
                    },
                    KeyValue {
                        key: semconv::SERVICE_NAME.to_owned(),
                        value: Some(string("checkout")),
                        ..KeyValue::default()
                    },
                ],
                ..Resource::default()
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "io.opentelemetry.grpc".to_owned(),
                    ..InstrumentationScope::default()
                }),
                spans,
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }]
    }

    fn rows(spans: Vec<Span>) -> Vec<SpanRow> {
        let request = request(spans);
        let batches = batches(&request);
        to_rows(
            &batches[0],
            &attribution(),
            uops_core::ResourceId::new(),
            at("2026-09-21T10:00:00Z"),
        )
    }

    #[test]
    fn a_span_becomes_a_row_carrying_both_of_its_subjects() {
        // §2.1, the decision with no second chance: the host is in the sort key and the
        // service is a column beside it, and the decoder fills both from what the caller
        // resolved rather than guessing either.
        let attribution = attribution();
        let service = uops_core::ResourceId::new();
        let request = request(vec![span("GET /checkout")]);
        let batches = batches(&request);
        let rows = to_rows(
            &batches[0],
            &attribution,
            service,
            at("2026-09-21T10:00:00Z"),
        );

        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.resource_id, attribution.resource_id, "the host");
        assert_eq!(row.service_id, service, "the service, resolved separately");
        assert_ne!(
            row.resource_id, row.service_id,
            "one service runs on many hosts; the two ids are not interchangeable"
        );
        assert_eq!(row.name, "GET /checkout");
        assert_eq!(row.kind, "server");
        assert_eq!(row.trace_id, "4b".repeat(16));
        assert_eq!(row.span_id, "01".repeat(8));
        assert_eq!(row.parent_span_id, "", "a root span has no parent");
        assert_eq!(row.duration_ns, 12_000_000);
        assert_eq!(row.observed_at, instant(START).expect("a start"));
        assert_eq!(row.ingested_at, at("2026-09-21T10:00:00Z"));
    }

    #[test]
    fn the_instrumentation_scope_survives() {
        // Unlike a log record's, where it is trivia. "Only the gRPC instrumentation is
        // slow" is a real diagnosis and it is unreachable once the scope is flattened.
        assert_eq!(rows(vec![span("x")])[0].scope_name, "io.opentelemetry.grpc");
    }

    #[test]
    fn a_spans_timestamp_is_its_start_and_not_its_end() {
        // A span is an interval. `observed_at` sorts it and `duration_ns` measures from
        // it, so keying on the end would put a slow span in the wrong five-minute bucket
        // by exactly as much as it was slow — the worst possible direction for the error.
        let row = &rows(vec![span("slow")])[0];
        assert_eq!(row.observed_at, instant(START).expect("a start"));
        assert_ne!(
            row.observed_at,
            instant(START + 12_000_000).expect("an end")
        );
    }

    #[test]
    fn unset_is_not_an_error() {
        // OTel's default, carried by the overwhelming majority of healthy spans. Counting
        // it as a failure would make every service look broken; calling it `ok` would
        // throw away the difference between "it succeeded" and "nobody checked".
        assert_eq!(status_code(None), "unset");
        assert_eq!(
            status_code(Some(&Status {
                code: status::StatusCode::Unset as i32,
                ..Status::default()
            })),
            "unset"
        );
        assert_eq!(
            status_code(Some(&Status {
                code: status::StatusCode::Error as i32,
                message: "upstream timeout".to_owned(),
            })),
            "error"
        );
        assert_eq!(
            status_code(Some(&Status {
                code: status::StatusCode::Ok as i32,
                ..Status::default()
            })),
            "ok"
        );
    }

    #[test]
    fn the_status_message_reaches_its_column() {
        let mut s = span("failing");
        s.status = Some(Status {
            code: status::StatusCode::Error as i32,
            message: "upstream timeout".to_owned(),
        });
        let row = &rows(vec![s])[0];
        assert_eq!(row.status_code, "error");
        assert_eq!(row.status_message, "upstream timeout");
        assert!(
            !row.attributes.contains_key("status_message"),
            "it lives in a column, and paying for it twice on this table is not free"
        );
    }

    #[test]
    fn an_unspecified_kind_is_internal() {
        // Which is what the specification says it means: a span that did not say is a
        // span that did not cross a process boundary. A sixth enum value meaning "the
        // exporter left it blank" would be one nobody can act on.
        assert_eq!(kind(span::SpanKind::Unspecified as i32), "internal");
        assert_eq!(kind(9999), "internal", "and so is a value off the wire");
        assert_eq!(kind(span::SpanKind::Client as i32), "client");
        assert_eq!(kind(span::SpanKind::Producer as i32), "producer");
        assert_eq!(kind(span::SpanKind::Consumer as i32), "consumer");
    }

    #[test]
    fn a_backwards_span_does_not_panic_and_says_so() {
        // M7's fuzzer found this exact shape of arithmetic panicking in two decoders —
        // and worse, wrapping silently in release. A span whose end precedes its start is
        // broken instrumentation, not negative time, and §M0.2 rule 1 says it is still
        // ingested.
        let mut s = span("backwards");
        s.start_time_unix_nano = START;
        s.end_time_unix_nano = START - 1_000;
        let row = &rows(vec![s])[0];
        assert_eq!(row.duration_ns, 0);
        assert_eq!(
            row.attributes
                .get("otlp.duration.negative")
                .map(String::as_str),
            Some("true"),
            "the zero has to be readable as broken rather than instantaneous"
        );
    }

    #[test]
    fn a_span_with_no_timestamps_is_still_stored() {
        // Zero is *unset* in OTLP, not 1970 — the field is a plain fixed64. The row falls
        // back to receipt time and records that it did, rather than being dropped or
        // sorted to the top of every search.
        let mut s = span("unset");
        s.start_time_unix_nano = 0;
        s.end_time_unix_nano = 0;
        let row = &rows(vec![s])[0];
        assert_eq!(row.observed_at, at("2026-09-21T10:00:00Z"));
        assert_eq!(
            row.attributes
                .get("otlp.timestamp.missing")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            row.attributes.get("otlp.end.missing").map(String::as_str),
            Some("true")
        );
        assert_eq!(row.duration_ns, 0);
    }

    #[test]
    fn a_span_may_override_what_its_resource_said() {
        // The same direction as `logs`, and the direction OTLP intends: the resource
        // describes the emitter and the span describes the work, and the more specific of
        // the two wins.
        let mut s = span("override");
        s.attributes = vec![KeyValue {
            key: semconv::SERVICE_NAME.to_owned(),
            value: Some(string("checkout-worker")),
            ..KeyValue::default()
        }];
        let row = &rows(vec![s])[0];
        assert_eq!(
            row.attributes
                .get(semconv::SERVICE_NAME)
                .map(String::as_str),
            Some("checkout-worker")
        );
        // And the resource's own attributes are still there.
        assert_eq!(
            row.attributes.get(semconv::HOST_NAME).map(String::as_str),
            Some("app-01")
        );
    }

    #[test]
    fn every_scope_in_a_resource_is_collected() {
        let request = vec![ResourceSpans {
            resource: Some(Resource::default()),
            scope_spans: vec![
                ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: "a".to_owned(),
                        ..InstrumentationScope::default()
                    }),
                    spans: vec![span("one")],
                    ..ScopeSpans::default()
                },
                ScopeSpans {
                    scope: None,
                    spans: vec![span("two")],
                    ..ScopeSpans::default()
                },
            ],
            ..ResourceSpans::default()
        }];
        let batches = batches(&request);
        assert_eq!(batches.len(), 1, "one resource is one resolution");
        let rows = to_rows(
            &batches[0],
            &attribution(),
            uops_core::ResourceId::new(),
            at("2026-09-21T10:00:00Z"),
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].scope_name, "a");
        assert_eq!(
            rows[1].scope_name, "",
            "a scopeless span is not a dropped one"
        );
    }

    #[test]
    fn the_probability_sampler_exponent_is_read() {
        // `ot=p:N` is 2^-N: p:0 is everything, p:10 is one in 1024.
        assert!((sampling_probability("ot=p:0") - 1.0).abs() < f32::EPSILON);
        assert!((sampling_probability("ot=p:1") - 0.5).abs() < f32::EPSILON);
        assert!((sampling_probability("ot=p:10") - 1.0 / 1024.0).abs() < f32::EPSILON);
        // Other vendors' entries are stepped over rather than confusing the parse.
        assert!((sampling_probability("congo=t61rcWkgMzE,ot=p:2") - 0.25).abs() < f32::EPSILON);
        assert!((sampling_probability("ot=rv:abcd;p:2") - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn a_threshold_is_left_aligned_hex_and_not_an_integer() {
        // The trap. `th:8` is 0x80000000000000 — *half* — and reading it as the integer 8
        // would report a sampling probability of essentially 1.0 for a trace that dropped
        // half its spans, with nothing downstream able to tell.
        assert!((sampling_probability("ot=th:8") - 0.5).abs() < 1e-6);
        assert!((sampling_probability("ot=th:0") - 1.0).abs() < f32::EPSILON);
        assert!((sampling_probability("ot=th:c") - 0.25).abs() < 1e-6);
        // Fully written out, the same value.
        assert!((sampling_probability("ot=th:80000000000000") - 0.5).abs() < 1e-6);
    }

    #[test]
    fn a_tracestate_that_says_nothing_yields_zero() {
        // Which the column documents as "the exporter did not say" — and §2.3 is why that
        // is not a problem to paper over: nothing may extrapolate from this number, so a
        // zero costs nothing but honesty.
        assert!(sampling_probability("").abs() < f32::EPSILON);
        assert!(sampling_probability("congo=t61rcWkgMzE").abs() < f32::EPSILON);
        assert!(sampling_probability("ot=").abs() < f32::EPSILON);
        assert!(sampling_probability("ot=p:").abs() < f32::EPSILON);
        assert!(sampling_probability("ot=p:notanumber").abs() < f32::EPSILON);
        assert!(sampling_probability("ot=p:-3").abs() < f32::EPSILON);
        assert!(sampling_probability("ot=p:999").abs() < f32::EPSILON);
        assert!(sampling_probability("ot=th:zz").abs() < f32::EPSILON);
        // Longer than 14 digits is not a threshold, and must not silently truncate.
        assert!(sampling_probability("ot=th:800000000000000").abs() < f32::EPSILON);
    }

    #[test]
    fn nothing_here_multiplies_by_the_sampling_probability() {
        // §2.3, stated as a test because it is the rule somebody will assume the opposite
        // of, having read M7. Flow scaled its counts up because sFlow states its rate
        // reliably; tracing cannot, because an unsampled span is simply absent. The
        // probability is recorded, and one span is one row.
        let mut s = span("sampled");
        s.trace_state = "ot=p:10".to_owned();
        let rows = rows(vec![s]);
        assert_eq!(rows.len(), 1, "one in 1024 does not become 1024 rows");
        assert!((rows[0].sampling_probability - 1.0 / 1024.0).abs() < f32::EPSILON);
    }
}
