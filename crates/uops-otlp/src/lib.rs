//! OTLP, decoded into the rows the rest of the product already stores.
//!
//! SPEC §M3 asks for an OTLP receiver implementing `LogsService`, `MetricsService` and
//! `TraceService`. This crate is the half that has nothing to do with transport: protobuf
//! in, [`LogRow`] and [`MetricRow`] out, plus the [`ObservedIdentity`] that decides which
//! resource they belong to.
//!
//! # Why this is almost no work, and why that is the point
//!
//! A syslog message and an OTLP record become the *same row*. Not a similar row — the
//! same type, with the same keys, resolved by the same resolver, batched by the same
//! batcher. That is what SPEC §M0.3 bought when it required OpenTelemetry semantic
//! conventions instead of a bespoke schema:
//!
//! > `host.name`, `service.name`, `source.address` rather than `src_ip`
//!
//! `uops-syslog::normalize` had to *translate* into those names. This does not: OTLP is
//! already in them. The whole conversion is unwrapping protobuf `AnyValue`s and mapping a
//! severity number, which is why it fits in one file with no I/O and no async.
//!
//! # HTTP first, gRPC deferred, and the reason is the dependency tree
//!
//! SPEC names `opentelemetry-proto` with `gen-tonic`, which generates gRPC service stubs
//! and pulls **tonic, h2 and tower** in with them. `gen-tonic-messages` generates the
//! same protobuf structs and pulls neither, because OTLP/HTTP carries **byte-identical
//! protobuf bodies** — the difference is the framing, not the payload.
//!
//! So the receiver speaks OTLP/HTTP on the axum stack that already exists, and this crate
//! adds `prost` and `opentelemetry-proto` and nothing else. The OpenTelemetry Collector's
//! `otlphttp` exporter is first-class and needs no translation, so this is a complete
//! answer rather than a stopgap.
//!
//! gRPC is worth adding when something needs it. It is a feature and a service impl over
//! the same functions in this file, not a rewrite — and it is a decision about carrying
//! three more dependencies, which in this project is a decision rather than a default.
//!
//! # Traces, and why they were late
//!
//! SPEC was explicit that they should be: *"trace accepts and stores nothing until M8 —
//! accept and drop with a counter, so instrumented apps don't error."* An application
//! whose exporter gets a 404 logs an error every batch forever, so accepting and counting
//! was the difference between "traces are not stored yet" and "the endpoint is broken",
//! and only one of those was true.
//!
//! M8 arrived, so [`traces`] is here and the counter can stop. It is the same shape as
//! [`logs`] with one addition the other two do not have: a span belongs to a **host** and
//! a **service**, and the caller resolves both. See that module and
//! `docs/M8-observability.md` §2.1.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone as _, Utc};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use uops_core::{Identifier, IdentifierKind, ObservedIdentity, semconv};
use uops_pipeline::Attribution;
use uops_store_ch::{LogRow, MetricRow, SpanRow};

pub mod logs;
pub mod metrics;
pub mod traces;

/// What the `source_kind` column says about anything from here.
pub const SOURCE_KIND: &str = "otlp";

/// Flatten a protobuf value to the string the storage layer holds.
///
/// `attributes` is `Map(LowCardinality(String), String)` in `ClickHouse`, so everything
/// becomes a string eventually. Doing it here rather than at the edge keeps the shape of
/// an OTLP attribute out of the rest of the product.
///
/// Arrays and maps are rendered rather than dropped. They are rare, they are usually
/// somebody's structured context, and a missing attribute is harder to debug than an
/// ugly one.
#[must_use]
pub fn flatten(value: &AnyValue) -> String {
    match value.value.as_ref() {
        Some(any_value::Value::StringValue(s)) => s.clone(),
        Some(any_value::Value::BoolValue(b)) => b.to_string(),
        Some(any_value::Value::IntValue(i)) => i.to_string(),
        Some(any_value::Value::DoubleValue(d)) => d.to_string(),
        Some(any_value::Value::BytesValue(b)) => hex(b),
        Some(any_value::Value::ArrayValue(a)) => {
            let parts: Vec<String> = a.values.iter().map(flatten).collect();
            format!("[{}]", parts.join(","))
        }
        Some(any_value::Value::KvlistValue(kv)) => {
            let parts: Vec<String> = kv
                .values
                .iter()
                .map(|e| {
                    let v = e.value.as_ref().map_or_else(String::new, flatten);
                    format!("{}={v}", e.key)
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        // OTLP 1.8's experimental string table: the value is an *index* into a table
        // carried elsewhere in the request, not a string. Resolving it needs that table
        // threaded through every call here, and no exporter emits it by default.
        //
        // Rendered as a visible marker rather than an empty string, because the two mean
        // different things: empty is "the attribute was sent with no value", and this is
        // "the attribute was sent in a form this build does not read". An operator seeing
        // it has something to search for.
        Some(any_value::Value::StringValueStrindex(i)) => {
            format!("otlp:strindex:{i}")
        }
        None => String::new(),
    }
}

/// Collect a protobuf attribute list into the map a row carries.
#[must_use]
pub fn attributes(list: &[KeyValue]) -> BTreeMap<String, String> {
    list.iter()
        .map(|kv| {
            (
                kv.key.clone(),
                kv.value.as_ref().map_or_else(String::new, flatten),
            )
        })
        .collect()
}

/// One resource's attributes, as a map.
#[must_use]
pub fn resource_attributes(resource: Option<&Resource>) -> BTreeMap<String, String> {
    resource
        .map(|r| attributes(&r.attributes))
        .unwrap_or_default()
}

/// The identifiers that say which **host** sent this.
///
/// In descending order of what a match proves, which is SPEC §M0.2's ranking:
///
/// * **`host.id`** — tier 1, confidence 1.00. A machine ID, unique by specification, and
///   the strongest identifier any collector produces. When the `OTel` Collector's
///   `resourcedetection` processor is on, this is present and everything else is
///   corroboration.
/// * **`host.name`** — 0.65. Whatever the machine is called, with all the usual problems.
///
/// # `service.name` used to be here, and M8 moved it
///
/// It was offered last at 0.60, as a weak hint about which host sent the payload. M8 §2.1
/// makes the service **a resource of its own**, and an identifier belongs to exactly one
/// resource — `UNIQUE (tenant_id, kind, value)`. So a `service.name` claimed by a host is
/// a `service.name` the service can never be resolved by: every span would find the host
/// instead, and `service_id` would equal `resource_id` for every row.
///
/// The weighting was never the problem and has not changed. What changed is which
/// question it answers: [`service_identifiers`] asks *which service*, and this asks
/// *which host*.
///
/// A payload with neither host key therefore offers **nothing** here, and the caller must
/// not resolve an empty identity — that mints a fresh resource per request. See
/// [`service_observed`] for what to do instead, and `resourcedetection` for the fix at
/// the source.
#[must_use]
pub fn identifiers(resource: &BTreeMap<String, String>) -> Vec<Identifier> {
    let mut out = Vec::new();
    if let Some(id) = resource.get(semconv::HOST_ID).filter(|s| !s.is_empty()) {
        out.push(Identifier::new(IdentifierKind::OtelHostId, id.clone()));
    }
    if let Some(name) = resource.get(semconv::HOST_NAME).filter(|s| !s.is_empty()) {
        // Lowercased, as the syslog path does: DNS is case-insensitive and a host that
        // shouts its name must not become a second resource.
        out.push(Identifier::new(
            IdentifierKind::Hostname,
            name.to_lowercase(),
        ));
    }
    out
}

/// The identifier that says which **service** this is, if it says at all.
///
/// One identifier, never more. That is what makes it resolvable: the resolver treats an
/// observation whose every identifier matches one resource as a repeat sighting, so the
/// second export of a service is a match rather than a 0.60 review item — see
/// `uops_identity::resolver::exclusive_match`, which exists for exactly this shape.
///
/// The value is `namespace/name` when `service.namespace` is set and the bare name when
/// it is not, because that is `OTel`'s own disambiguator and two teams really do both run a
/// `checkout`. A namespace that appears later produces a *different* identifier and
/// therefore a second resource, which is honest: nothing here can know the two were the
/// same service, and a merge is a decision for the review queue rather than for a
/// decoder.
#[must_use]
pub fn service_identifiers(resource: &BTreeMap<String, String>) -> Vec<Identifier> {
    let Some(name) = resource
        .get(semconv::SERVICE_NAME)
        .filter(|s| !s.is_empty())
    else {
        return Vec::new();
    };
    let value = match resource
        .get(semconv::SERVICE_NAMESPACE)
        .filter(|s| !s.is_empty())
    {
        Some(namespace) => format!("{namespace}/{name}"),
        None => name.clone(),
    };
    vec![Identifier::new(IdentifierKind::ServiceName, value)]
}

/// What identity resolution is asked about the host one OTLP resource describes.
///
/// `None` when the payload named no host at all. A caller must not turn that into a
/// resolution: an `ObservedIdentity` with no identifiers creates a resource every time it
/// is resolved, so an SDK with no `resourcedetection` would mint one per export request.
#[must_use]
pub fn observed(resource: &BTreeMap<String, String>) -> Option<ObservedIdentity> {
    let identifiers = identifiers(resource);
    (!identifiers.is_empty()).then(|| ObservedIdentity {
        identifiers,
        source: SOURCE_KIND.to_owned(),
        site_hint: None,
    })
}

/// What identity resolution is asked about the service, or `None` when there is no
/// `service.name` to ask about.
///
/// The `OTel` SDKs set one on everything — an application that does not configure it gets
/// `unknown_service:<process>` — so `None` here means a hand-rolled exporter, and a
/// hand-rolled exporter with no host keys either is the one payload this can say nothing
/// about.
#[must_use]
pub fn service_observed(resource: &BTreeMap<String, String>) -> Option<ObservedIdentity> {
    let identifiers = service_identifiers(resource);
    (!identifiers.is_empty()).then(|| ObservedIdentity {
        identifiers,
        source: SOURCE_KIND.to_owned(),
        site_hint: None,
    })
}

/// Nanoseconds since the epoch, as the wire carries them.
///
/// Zero means *unset* in OTLP, not 1970 — the field is a plain `fixed64` with no
/// nullability, so "no timestamp" and "the epoch" are the same bytes. Treating zero as a
/// real instant would put those records at the top of every search, which is the same
/// trap the syslog path has and the same answer.
#[must_use]
pub fn instant(nanos: u64) -> Option<DateTime<Utc>> {
    if nanos == 0 {
        return None;
    }
    #[allow(clippy::cast_possible_wrap)]
    let seconds = (nanos / 1_000_000_000) as i64;
    #[allow(clippy::cast_possible_truncation)]
    let rest = (nanos % 1_000_000_000) as u32;
    Utc.timestamp_opt(seconds, rest).single()
}

/// Lower-case hex, for the trace and span ids OTLP sends as raw bytes.
///
/// The `logs` table stores them as strings and every other tool in the ecosystem prints
/// them this way, so a trace id copied out of here pastes into Jaeger.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The row types this crate produces, so a caller can hand them to one batcher.
#[derive(Debug, Default)]
pub struct Converted {
    pub logs: Vec<LogRow>,
    pub metrics: Vec<MetricRow>,
    pub spans: Vec<SpanRow>,
}

/// What an attribution is for, restated: the caller resolves, this fills in.
///
/// Re-exported so a receiver depends on this crate alone rather than on the pipeline for
/// one type.
pub type Attributed = Attribution;

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{ArrayValue, KeyValueList};

    fn string(v: &str) -> AnyValue {
        AnyValue {
            value: Some(any_value::Value::StringValue(v.to_owned())),
        }
    }

    #[test]
    fn every_attribute_shape_becomes_a_string() {
        // The storage column is Map(String, String), so something has to. Doing it here
        // keeps the shape of an OTLP attribute out of the rest of the product.
        assert_eq!(flatten(&string("x")), "x");
        assert_eq!(
            flatten(&AnyValue {
                value: Some(any_value::Value::IntValue(7))
            }),
            "7"
        );
        assert_eq!(
            flatten(&AnyValue {
                value: Some(any_value::Value::BoolValue(true))
            }),
            "true"
        );
        assert_eq!(
            flatten(&AnyValue {
                value: Some(any_value::Value::BytesValue(vec![0xde, 0xad]))
            }),
            "dead"
        );
        // An empty value is an empty string rather than a missing key: the attribute was
        // sent, and "sent as nothing" and "not sent" are different facts.
        assert_eq!(flatten(&AnyValue { value: None }), "");
    }

    #[test]
    fn a_nested_attribute_is_rendered_rather_than_dropped() {
        // Rare, usually somebody's structured context, and a missing attribute is harder
        // to debug than an ugly one.
        let array = AnyValue {
            value: Some(any_value::Value::ArrayValue(ArrayValue {
                values: vec![string("a"), string("b")],
            })),
        };
        assert_eq!(flatten(&array), "[a,b]");

        let map = AnyValue {
            value: Some(any_value::Value::KvlistValue(KeyValueList {
                values: vec![KeyValue {
                    key: "team".to_owned(),
                    value: Some(string("network")),
                    ..KeyValue::default()
                }],
            })),
        };
        assert_eq!(flatten(&map), "{team=network}");
    }

    #[test]
    fn the_identifiers_put_the_machine_id_first() {
        // host.id is tier 1 at 1.00 and is the strongest identifier any collector
        // produces; a hostname is 0.65 and corroborates it.
        let resource: BTreeMap<String, String> = [
            (semconv::SERVICE_NAME.to_owned(), "checkout".to_owned()),
            (semconv::HOST_NAME.to_owned(), "APP-01".to_owned()),
            (semconv::HOST_ID.to_owned(), "fa4d...".to_owned()),
        ]
        .into_iter()
        .collect();

        let ids = identifiers(&resource);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].kind, IdentifierKind::OtelHostId);
        assert_eq!(ids[1].kind, IdentifierKind::Hostname);
        assert_eq!(ids[1].value, "app-01", "a hostname is case-insensitive");
    }

    #[test]
    fn the_host_does_not_claim_the_service_name() {
        // M8 §2.1, and the reason `service_id` can exist at all. An identifier belongs to
        // exactly one resource, so a `service.name` claimed by a host is a `service.name`
        // the service can never be resolved by — every span would find the host instead.
        let resource: BTreeMap<String, String> = [
            (semconv::SERVICE_NAME.to_owned(), "checkout".to_owned()),
            (semconv::HOST_ID.to_owned(), "fa4d...".to_owned()),
        ]
        .into_iter()
        .collect();

        assert!(
            !identifiers(&resource)
                .iter()
                .any(|i| i.kind == IdentifierKind::ServiceName)
        );
        let service = service_identifiers(&resource);
        assert_eq!(service.len(), 1, "one identifier, so a repeat is a match");
        assert_eq!(service[0].kind, IdentifierKind::ServiceName);
        assert_eq!(service[0].value, "checkout");
    }

    #[test]
    fn a_namespaced_service_is_a_different_service() {
        // Two teams really do both run a `checkout`, and `service.namespace` is OTel's
        // own answer. Nothing here can know that a namespace appearing later belongs to
        // the same service as the bare name did, so it becomes a second resource and a
        // human decides — which is the review queue's whole job.
        let mut resource: BTreeMap<String, String> =
            [(semconv::SERVICE_NAME.to_owned(), "checkout".to_owned())]
                .into_iter()
                .collect();
        assert_eq!(service_identifiers(&resource)[0].value, "checkout");

        resource.insert(semconv::SERVICE_NAMESPACE.to_owned(), "payments".to_owned());
        assert_eq!(service_identifiers(&resource)[0].value, "payments/checkout");
    }

    #[test]
    fn an_empty_identifier_is_not_offered() {
        // An exporter that sets `host.name: ""` would otherwise mint one resource that
        // every unnamed host in the estate resolves to — a single bucket that looks like
        // a working join and is not.
        let resource: BTreeMap<String, String> = [
            (semconv::HOST_NAME.to_owned(), String::new()),
            (semconv::SERVICE_NAME.to_owned(), String::new()),
        ]
        .into_iter()
        .collect();
        assert!(identifiers(&resource).is_empty());
        assert!(service_identifiers(&resource).is_empty());
    }

    #[test]
    fn an_identity_with_nothing_in_it_is_never_offered_for_resolution() {
        // Resolving an empty `ObservedIdentity` creates a resource, every time — so an
        // SDK with no `resourcedetection` and no service name would mint one per export
        // request. `None` is the only safe answer, and it is the caller's cue to attribute
        // the rows to the service or to nothing.
        let empty = BTreeMap::new();
        assert!(observed(&empty).is_none());
        assert!(service_observed(&empty).is_none());

        let service: BTreeMap<String, String> =
            [(semconv::SERVICE_NAME.to_owned(), "checkout".to_owned())]
                .into_iter()
                .collect();
        assert!(
            observed(&service).is_none(),
            "a service name says nothing about which host"
        );
        assert!(service_observed(&service).is_some());
    }

    #[test]
    fn a_zero_timestamp_is_unset_rather_than_1970() {
        // OTLP's timestamps are plain fixed64 with no nullability, so "no timestamp" and
        // "the epoch" are the same bytes. Treating zero as an instant would sort those
        // records to the top of every search — the same trap the syslog path has, and the
        // same answer.
        assert_eq!(instant(0), None);
        assert_eq!(
            instant(1_700_000_000_123_456_789)
                .expect("an instant")
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "2023-11-14T22:13:20.123Z"
        );
    }

    #[test]
    fn trace_ids_print_the_way_every_other_tool_prints_them() {
        // So that an id copied out of here pastes into Jaeger.
        assert_eq!(hex(&[0x00, 0x01, 0xab, 0xff]), "0001abff");
        assert_eq!(hex(&[]), "");
    }
}
