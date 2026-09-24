//! The whole path, against real infrastructure.
//!
//! A protobuf body on a real socket, through the real resolver against real `PostgreSQL`,
//! into real `ClickHouse` — then read back with a query.
//!
//! The conversion has its own tests in `uops-otlp` and every one of them passes with the
//! stages wired together wrongly. What this proves is that an `otlphttp` exporter pointed
//! at this port produces rows somebody can find.

use std::net::SocketAddr;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::metrics::v1::{
    Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics,
    metric, number_data_point,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message as _;
use uops_collector_otlp::config::{Config, Listener};
use uops_collector_otlp::run;
use uops_store_ch::{ChClient, ChStore, TelemetryStore};
use uops_store_pg::{Config as PgConfig, PgStore};

macro_rules! infra_or_skip {
    ($what:expr) => {
        match $what {
            Ok(v) => v,
            Err(e) => {
                println!("SKIPPED: the infrastructure is not reachable ({e})");
                return;
            }
        }
    };
}

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into())
}

async fn tenant(store: &PgStore, slug: &str) -> (uops_core::TenantId, String) {
    let org = uuid::Uuid::now_v7();
    let id = uops_core::TenantId::new();
    let slug = format!("{slug}-{}", id.into_uuid().simple());

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org)
        .bind(format!("otlp-org-{slug}"))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(id.into_uuid())
        .bind(org)
        .bind(format!("otlp-{slug}"))
        .bind(&slug)
        .execute(store.pool())
        .await
        .expect("tenant");

    (id, slug)
}

/// Now, in the nanoseconds OTLP carries.
///
/// **Not a fixed instant.** `metrics` has a 30-day `DELETE` TTL and `logs` a 365-day one,
/// so a fixture dated 2023 is a row `ClickHouse` removes at the next merge — and the merge
/// is background, so the test either fails or passes depending on timing.
///
/// This is the third time this project has been caught by it. The first was the query
/// layer's golden fixtures; the second was a histogram against a pre-aggregated rollup;
/// this was a gauge that never appeared while the log beside it did, because the log's
/// TTL is twelve times longer and the merge had not reached it yet. A fixed timestamp in
/// a test against a table with retention is a test with an expiry date on it.
fn now_nanos() -> u64 {
    u64::try_from(
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .expect("a representable instant"),
    )
    .expect("after 1970")
}

fn free_port() -> SocketAddr {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
    socket.local_addr().expect("its address")
}

fn config(slug: &str, bind: SocketAddr) -> Config {
    Config {
        listeners: vec![Listener {
            tenant: slug.to_owned(),
            bind,
            vendor: String::new(),
            require_token: false,
        }],
        postgres: PgConfig {
            url: database_url(),
            ..PgConfig::default()
        },
        clickhouse: uops_store_ch::ChConfig::from_env(),
        spill: None,
        queue: 4_096,
        max_body: 4 * 1024 * 1024,
        // Not enrolled: these tests are about the path from a request to a row,
        // and the registry is a separate concern with its own tests in
        // `uops-store-pg/tests/collectors.rs`.
        collector_token: None,
        collector_name: "test".to_owned(),
    }
}

fn string(v: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(v.to_owned())),
    }
}

fn attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(string(value)),
        ..KeyValue::default()
    }
}

/// What the `OTel` Collector's `resourcedetection` processor produces.
fn resource(host: &str) -> Resource {
    Resource {
        attributes: vec![
            attribute(uops_core::semconv::HOST_NAME, host),
            attribute(uops_core::semconv::HOST_ID, &format!("machine-id-{host}")),
            attribute(uops_core::semconv::SERVICE_NAME, "checkout"),
        ],
        ..Resource::default()
    }
}

/// POST a protobuf body the way `otlphttp` does, without an HTTP client dependency.
///
/// Hand-written because the alternative is pulling reqwest in as a dev dependency for
/// four requests, and this is the whole of HTTP/1.1 that matters here: a request line,
/// two headers, a length and some bytes.
async fn post(address: SocketAddr, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut socket = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-protobuf\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    socket.write_all(head.as_bytes()).await.expect("head");
    socket.write_all(&body).await.expect("body");
    socket.flush().await.expect("flush");

    let mut raw = Vec::new();
    socket.read_to_end(&mut raw).await.expect("read");

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("a status line");

    (status, raw[split + 4..].to_vec())
}

/// The end of an HTTP head, as bytes.
///
/// A named constant rather than a literal, because a `b"..."` escape written by a generator is
/// exactly the sort of thing that silently becomes two bytes instead of four — which is what it
/// did, and the symptom was a parser that found no terminator in a perfectly good response.
const CRLF_CRLF: &[u8] = &[13, 10, 13, 10];

/// As [`post`], carrying an `Authorization: Bearer` header — what an `otlphttp` exporter sends
/// when its `headers:` block has one.
async fn post_with_token(
    address: SocketAddr,
    path: &str,
    token: &str,
    body: Vec<u8>,
) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut socket = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    // Built from a vector rather than one format string with eight escapes in it: the
    // escapes are the part that goes wrong, and a line here is a line on the wire.
    let lines = [
        format!("POST {path} HTTP/1.1"),
        "Host: localhost".to_owned(),
        "Content-Type: application/x-protobuf".to_owned(),
        format!("Authorization: Bearer {token}"),
        format!("Content-Length: {}", body.len()),
        "Connection: close".to_owned(),
    ];
    let mut head = lines.join("\r\n");
    head.push_str("\r\n\r\n");
    socket.write_all(head.as_bytes()).await.expect("head");
    socket.write_all(&body).await.expect("body");
    socket.flush().await.expect("flush");

    let mut raw = Vec::new();
    socket.read_to_end(&mut raw).await.expect("read");

    let split = raw
        .windows(4)
        .position(|w| w == CRLF_CRLF)
        .expect("a header terminator");
    let status: u16 = String::from_utf8_lossy(&raw[..split])
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("a status line");

    (status, raw[split + 4..].to_vec())
}

struct Running {
    address: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    serving: tokio::task::JoinHandle<Result<(), String>>,
}

async fn start(store: &PgStore, telemetry: &ChStore, slug: &str) -> Running {
    let address = free_port();
    let config = config(slug, address);
    let bound = run::resolve_tenants(store, &config)
        .await
        .expect("resolve the slug");

    let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn({
        let store = store.clone();
        let telemetry = telemetry.clone();
        async move {
            run::serve(store, telemetry, &config, bound, async move {
                let _ = stop_rx.await;
            })
            .await
        }
    });
    tokio::time::sleep(Duration::from_millis(250)).await;

    Running {
        address,
        stop,
        serving,
    }
}

async fn query(telemetry: &ChStore, sql: &str) -> String {
    telemetry
        .client()
        .run(sql, &[])
        .await
        .map(|raw| raw.body)
        .unwrap_or_default()
}

async fn wait_for(telemetry: &ChStore, sql: &str) -> String {
    for _ in 0..60 {
        let found = query(telemetry, sql).await;
        if !found.trim().is_empty() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    String::new()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_otlp_log_export_becomes_a_row_somebody_can_find() {
    let store = infra_or_skip!(
        PgStore::connect(&PgConfig {
            url: database_url(),
            ..PgConfig::default()
        })
        .await
        .map_err(|e| e.to_string())
    );
    let telemetry = ChStore::new(ChClient::new(uops_store_ch::ChConfig::from_env()));
    infra_or_skip!(telemetry.health().await.map_err(|e| e.to_string()));

    let (tenant_id, slug) = tenant(&store, "logs").await;
    let running = start(&store, &telemetry, &slug).await;

    let marker = format!("otlp-{}", uuid::Uuid::now_v7().simple());
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(resource("app-01")),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "test".to_owned(),
                    ..InstrumentationScope::default()
                }),
                log_records: vec![LogRecord {
                    time_unix_nano: now_nanos(),
                    severity_number: 17,
                    severity_text: "ERROR".to_owned(),
                    body: Some(string(&marker)),
                    attributes: vec![attribute("db.system", "postgresql")],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };

    let (status, body) = post(running.address, "/v1/logs", request.encode_to_vec()).await;
    assert_eq!(status, 200, "an export must be accepted");

    // A successful export carries no partial_success at all. One populated with zeros is
    // a message some collectors log as a warning every batch.
    let response = ExportLogsServiceResponse::decode(&body[..]).expect("a valid response");
    assert!(
        response.partial_success.is_none(),
        "nothing was rejected: {:?}",
        response.partial_success
    );

    let sql = format!(
        "SELECT body, severity FROM logs WHERE tenant_id = '{}' AND body = '{marker}' \
         FORMAT TabSeparated",
        tenant_id.into_uuid()
    );
    let found = wait_for(&telemetry, &sql).await;
    assert!(
        found.contains(&marker),
        "the row must be queryable: {found:?}"
    );
    assert!(
        found.contains("error"),
        "the severity must survive: {found:?}"
    );

    // And the emitter became a resource, because nothing was registered in advance.
    let resources = store
        .resources(
            &uops_core::TenantScope::system(tenant_id),
            &uops_store_pg::ResourceFilter::default(),
        )
        .await
        .expect("resources");
    assert_eq!(
        resources.items.len(),
        1,
        "an unknown emitter becomes one resource, not none and not several"
    );

    let _ = running.stop.send(());
    running.serving.await.expect("join").expect("serve");
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_are_stored_and_what_cannot_be_is_reported() {
    // Both halves at once, because the interesting property is that they travel together:
    // a request carrying a gauge and a histogram stores the gauge and *says* the histogram
    // was rejected. A receiver that answered 200 {} would be lying by omission.
    let store = infra_or_skip!(
        PgStore::connect(&PgConfig {
            url: database_url(),
            ..PgConfig::default()
        })
        .await
        .map_err(|e| e.to_string())
    );
    let telemetry = ChStore::new(ChClient::new(uops_store_ch::ChConfig::from_env()));
    infra_or_skip!(telemetry.health().await.map_err(|e| e.to_string()));

    let (tenant_id, slug) = tenant(&store, "metrics").await;
    let running = start(&store, &telemetry, &slug).await;

    let metric_name = format!("test.gauge.{}", uuid::Uuid::now_v7().simple());
    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(resource("host-02")),
            scope_metrics: vec![ScopeMetrics {
                metrics: vec![
                    Metric {
                        name: metric_name.clone(),
                        unit: "1".to_owned(),
                        data: Some(metric::Data::Gauge(Gauge {
                            data_points: vec![NumberDataPoint {
                                time_unix_nano: now_nanos(),
                                value: Some(number_data_point::Value::AsDouble(0.42)),
                                attributes: vec![attribute("cpu", "0")],
                                ..NumberDataPoint::default()
                            }],
                        })),
                        ..Metric::default()
                    },
                    Metric {
                        name: "http.server.duration".to_owned(),
                        data: Some(metric::Data::Histogram(Histogram {
                            data_points: vec![HistogramDataPoint::default()],
                            ..Histogram::default()
                        })),
                        ..Metric::default()
                    },
                ],
                ..ScopeMetrics::default()
            }],
            ..ResourceMetrics::default()
        }],
    };

    let (status, body) = post(running.address, "/v1/metrics", request.encode_to_vec()).await;
    assert_eq!(status, 200);

    let response = ExportMetricsServiceResponse::decode(&body[..]).expect("a valid response");
    let partial = response
        .partial_success
        .expect("the histogram must be reported as rejected");
    assert_eq!(partial.rejected_data_points, 1);
    assert!(
        partial.error_message.contains("histogram"),
        "the reason must name what was not stored: {:?}",
        partial.error_message
    );

    let sql = format!(
        "SELECT metric, value FROM metrics WHERE tenant_id = '{}' AND metric = '{metric_name}' \
         FORMAT TabSeparated",
        tenant_id.into_uuid()
    );
    let found = wait_for(&telemetry, &sql).await;
    assert!(
        found.contains(&metric_name) && found.contains("0.42"),
        "the gauge must be queryable: {found:?}"
    );

    let _ = running.stop.send(());
    running.serving.await.expect("join").expect("serve");
}

/// One span, with everything a trace view needs to draw it.
fn span(trace: &str, id: &str, parent: &str, name: &str) -> Span {
    let start = now_nanos();
    Span {
        trace_id: hex(trace),
        span_id: hex(id),
        parent_span_id: hex(parent),
        name: name.to_owned(),
        kind: 2, // SPAN_KIND_SERVER
        start_time_unix_nano: start,
        end_time_unix_nano: start + 12_000_000,
        ..Span::default()
    }
}

/// Ids arrive as raw bytes and come back as lower-case hex, so the fixtures are written
/// the way they will be read.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_otlp_trace_export_becomes_spans_carrying_both_of_their_subjects() {
    // The endpoint accepted and discarded from M3 until M8, because SPEC asked it to: an
    // exporter that got a 404 would retry, back off and log an error every batch forever,
    // and "traces are not stored yet" must not look like "the endpoint is broken". This
    // is the test that it stopped.
    let store = infra_or_skip!(
        PgStore::connect(&PgConfig {
            url: database_url(),
            ..PgConfig::default()
        })
        .await
        .map_err(|e| e.to_string())
    );
    let telemetry = ChStore::new(ChClient::new(uops_store_ch::ChConfig::from_env()));
    infra_or_skip!(telemetry.health().await.map_err(|e| e.to_string()));

    let (tenant_id, slug) = tenant(&store, "traces").await;
    let running = start(&store, &telemetry, &slug).await;

    let trace = uuid::Uuid::now_v7().simple().to_string();
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(resource("app-03")),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "io.opentelemetry.grpc".to_owned(),
                    ..InstrumentationScope::default()
                }),
                spans: vec![
                    span(&trace, "0000000000000001", "", "GET /checkout"),
                    span(&trace, "0000000000000002", "0000000000000001", "charge"),
                ],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };

    let (status, body) = post(running.address, "/v1/traces", request.encode_to_vec()).await;
    assert_eq!(status, 200, "an exporter must not see an error");

    // No partial success at all. A receiver that kept apologising for spans it now stores
    // would be lying in the other direction, and an exporter told its spans were rejected
    // would be right to stop sending them.
    let response = ExportTraceServiceResponse::decode(&body[..]).expect("a valid response");
    assert!(
        response.partial_success.is_none(),
        "the spans were stored: {:?}",
        response.partial_success
    );

    let sql = format!(
        "SELECT name, scope_name, toString(resource_id), toString(service_id),          toString(duration_ns), parent_span_id FROM spans          WHERE tenant_id = '{}' AND trace_id = '{trace}' ORDER BY name FORMAT TabSeparated",
        tenant_id.into_uuid()
    );
    let found = wait_for(&telemetry, &sql).await;
    let rows: Vec<&str> = found.trim().lines().collect();
    assert_eq!(rows.len(), 2, "one row per span: {found:?}");

    let columns: Vec<Vec<&str>> = rows.iter().map(|r| r.split('\t').collect()).collect();
    assert_eq!(columns[0][0], "GET /checkout");
    assert_eq!(columns[1][0], "charge");
    assert_eq!(columns[0][1], "io.opentelemetry.grpc", "the scope survives");
    assert_eq!(columns[0][4], "12000000", "the duration is end minus start");
    assert_eq!(columns[0][5], "", "the root span has no parent");
    assert_eq!(
        columns[1][5], "0000000000000001",
        "and the child points at it, which is what draws a trace"
    );

    // §2.1, the whole reason the table has two id columns: the host and the service are
    // different resources, resolved separately, and a row that conflated them would show
    // one id twice.
    let (host_id, service_id) = (columns[0][2], columns[0][3]);
    assert_ne!(host_id, service_id, "a span has two subjects, not one");
    assert_ne!(host_id, uops_core::ResourceId::nil().to_string());
    assert_ne!(service_id, uops_core::ResourceId::nil().to_string());
    assert_eq!(columns[1][2], host_id, "both spans ran on the one host");
    assert_eq!(columns[1][3], service_id, "and are the one service's work");

    // Two resources in the inventory, and the service is recorded as a service. The kind
    // is what stops a service map from drawing machines.
    let resources = store
        .resources(
            &uops_core::TenantScope::system(tenant_id),
            &uops_store_pg::ResourceFilter::default(),
        )
        .await
        .expect("resources");
    assert_eq!(resources.items.len(), 2, "one host and one service");
    let service = resources
        .items
        .iter()
        .find(|r| r.id.to_string() == service_id)
        .expect("the service is in the inventory");
    assert_eq!(service.kind, uops_core::ResourceKind::Service);
    assert_eq!(service.name, "checkout");

    let _ = running.stop.send(());
    running.serving.await.expect("join").expect("serve");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_hosts_running_one_service_are_two_hosts_and_one_service() {
    // M8 §2.1's acceptance criterion, and the reason `service.name` had to stop being one
    // of the *host's* identifiers. `UNIQUE (tenant_id, kind, value)` means an identifier
    // belongs to exactly one resource: while a host claimed the service name, the second
    // host running `checkout` matched the first at 0.60 and the service could never be
    // resolved as itself.
    let store = infra_or_skip!(
        PgStore::connect(&PgConfig {
            url: database_url(),
            ..PgConfig::default()
        })
        .await
        .map_err(|e| e.to_string())
    );
    let telemetry = ChStore::new(ChClient::new(uops_store_ch::ChConfig::from_env()));
    infra_or_skip!(telemetry.health().await.map_err(|e| e.to_string()));

    let (tenant_id, slug) = tenant(&store, "fleet").await;
    let running = start(&store, &telemetry, &slug).await;

    let trace = uuid::Uuid::now_v7().simple().to_string();
    for (i, host) in ["app-10", "app-11"].into_iter().enumerate() {
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(resource(host)),
                scope_spans: vec![ScopeSpans {
                    spans: vec![span(
                        &trace,
                        &format!("00000000000000a{i}"),
                        "",
                        "GET /checkout",
                    )],
                    ..ScopeSpans::default()
                }],
                ..ResourceSpans::default()
            }],
        };
        let (status, _) = post(running.address, "/v1/traces", request.encode_to_vec()).await;
        assert_eq!(status, 200);
    }

    let sql = format!(
        "SELECT toString(uniqExact(resource_id)), toString(uniqExact(service_id)) FROM spans          WHERE tenant_id = '{}' AND trace_id = '{trace}' HAVING count() = 2 FORMAT TabSeparated",
        tenant_id.into_uuid()
    );
    let found = wait_for(&telemetry, &sql).await;
    assert_eq!(
        found.trim(),
        "2\t1",
        "two hosts, one service — got {found:?}"
    );

    // Three resources, not four and not two: each machine is itself, and the service they
    // both run is one thing.
    let resources = store
        .resources(
            &uops_core::TenantScope::system(tenant_id),
            &uops_store_pg::ResourceFilter::default(),
        )
        .await
        .expect("resources");
    assert_eq!(
        resources.items.len(),
        3,
        "two hosts and one service: {:?}",
        resources
            .items
            .iter()
            .map(|r| (&r.name, r.kind))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        resources
            .items
            .iter()
            .filter(|r| r.kind == uops_core::ResourceKind::Service)
            .count(),
        1
    );

    // And nobody has to adjudicate any of it. This is the assertion that makes the
    // identity split load-bearing rather than tidy: while a host claimed the service
    // name, the *second* machine running `checkout` matched the first one on it at 0.60 —
    // under the auto-merge bar — so it arrived as a provisional resource with a queue item
    // asking whether it was itself. Every machine in a fleet, from its own traffic.
    let reviews = uops_identity::IdentityStore::pending_reviews(&store, tenant_id, 10)
        .await
        .expect("the review queue");
    assert!(
        reviews.is_empty(),
        "a fleet must not fill the review queue by existing: {reviews:?}"
    );

    let _ = running.stop.send(());
    running.serving.await.expect("join").expect("serve");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_service_that_does_not_say_which_host_it_runs_on_is_still_stored() {
    // The degenerate payload, and the one the identity split could have broken: an SDK
    // with no `resourcedetection` sends `service.name` and nothing else. Before M8 that
    // resolved weakly *as a host*; now it resolves as the service and both columns hold
    // it — one thing was described, and inventing a host to fill a column would be worse
    // than saying so.
    //
    // What must not happen is a resource per export request, which is what resolving an
    // empty identity does.
    let store = infra_or_skip!(
        PgStore::connect(&PgConfig {
            url: database_url(),
            ..PgConfig::default()
        })
        .await
        .map_err(|e| e.to_string())
    );
    let telemetry = ChStore::new(ChClient::new(uops_store_ch::ChConfig::from_env()));
    infra_or_skip!(telemetry.health().await.map_err(|e| e.to_string()));

    let (tenant_id, slug) = tenant(&store, "hostless").await;
    let running = start(&store, &telemetry, &slug).await;

    let trace = uuid::Uuid::now_v7().simple().to_string();
    for i in 0..3 {
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![attribute(uops_core::semconv::SERVICE_NAME, "cart")],
                    ..Resource::default()
                }),
                scope_spans: vec![ScopeSpans {
                    spans: vec![span(&trace, &format!("00000000000000b{i}"), "", "work")],
                    ..ScopeSpans::default()
                }],
                ..ResourceSpans::default()
            }],
        };
        let (status, _) = post(running.address, "/v1/traces", request.encode_to_vec()).await;
        assert_eq!(status, 200);
    }

    let sql = format!(
        "SELECT toString(uniqExact(resource_id)), toString(uniqExact(service_id)) FROM spans          WHERE tenant_id = '{}' AND trace_id = '{trace}' HAVING count() = 3 FORMAT TabSeparated",
        tenant_id.into_uuid()
    );
    assert_eq!(wait_for(&telemetry, &sql).await.trim(), "1\t1");

    let resources = store
        .resources(
            &uops_core::TenantScope::system(tenant_id),
            &uops_store_pg::ResourceFilter::default(),
        )
        .await
        .expect("resources");
    assert_eq!(
        resources.items.len(),
        1,
        "three exports, one resource — not one per request"
    );
    assert_eq!(resources.items[0].kind, uops_core::ResourceKind::Service);

    let _ = running.stop.send(());
    running.serving.await.expect("join").expect("serve");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_is_not_protobuf_is_the_senders_problem() {
    // 400, not 500: retrying it will produce the same result, and an exporter that backs
    // off on a 400 is wasting its own time.
    let store = infra_or_skip!(
        PgStore::connect(&PgConfig {
            url: database_url(),
            ..PgConfig::default()
        })
        .await
        .map_err(|e| e.to_string())
    );
    let telemetry = ChStore::new(ChClient::new(uops_store_ch::ChConfig::from_env()));
    infra_or_skip!(telemetry.health().await.map_err(|e| e.to_string()));

    let (_tenant_id, slug) = tenant(&store, "bad").await;
    let running = start(&store, &telemetry, &slug).await;

    // Valid protobuf framing is forgiving, so this is bytes that cannot be a message:
    // field 1 with a length longer than the body.
    let (status, _) = post(
        running.address,
        "/v1/logs",
        vec![0x0a, 0xff, 0xff, 0xff, 0x7f, 0x01],
    )
    .await;
    assert_eq!(status, 400, "a malformed body is the sender's problem");

    let _ = running.stop.send(());
    running.serving.await.expect("join").expect("serve");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_tenants_on_two_ports_do_not_mix() {
    // The tenant-attribution decision, tested rather than asserted in a comment. The
    // request bodies are identical; only the port differs, which is the one thing the
    // sender cannot influence.
    let store = infra_or_skip!(
        PgStore::connect(&PgConfig {
            url: database_url(),
            ..PgConfig::default()
        })
        .await
        .map_err(|e| e.to_string())
    );
    let telemetry = ChStore::new(ChClient::new(uops_store_ch::ChConfig::from_env()));
    infra_or_skip!(telemetry.health().await.map_err(|e| e.to_string()));

    let (first_id, first_slug) = tenant(&store, "mix-a").await;
    let (second_id, second_slug) = tenant(&store, "mix-b").await;

    let (first_addr, second_addr) = (free_port(), free_port());
    let mut config = config(&first_slug, first_addr);
    config.listeners.push(Listener {
        tenant: second_slug,
        bind: second_addr,
        vendor: String::new(),
            require_token: false,
    });
    let bound = run::resolve_tenants(&store, &config)
        .await
        .expect("resolve both slugs");

    let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn({
        let store = store.clone();
        let telemetry = telemetry.clone();
        let config = config.clone();
        async move {
            run::serve(store, telemetry, &config, bound, async move {
                let _ = stop_rx.await;
            })
            .await
        }
    });
    tokio::time::sleep(Duration::from_millis(250)).await;

    let marker = format!("mix-{}", uuid::Uuid::now_v7().simple());
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(resource("shared-name")),
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: now_nanos(),
                    severity_number: 9,
                    body: Some(string(&marker)),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };
    let encoded = request.encode_to_vec();

    for address in [first_addr, second_addr] {
        let (status, _) = post(address, "/v1/logs", encoded.clone()).await;
        assert_eq!(status, 200);
    }

    for tenant_id in [first_id, second_id] {
        let sql = format!(
            "SELECT body FROM logs WHERE tenant_id = '{}' AND body = '{marker}' \
             FORMAT TabSeparated",
            tenant_id.into_uuid()
        );
        assert!(
            wait_for(&telemetry, &sql).await.contains(&marker),
            "each tenant must have its own copy"
        );

        // And its own resource. `shared-name` and its machine id are the same bytes in
        // both requests, and every managed-service customer has an `app-01`.
        let resources = store
            .resources(
                &uops_core::TenantScope::system(tenant_id),
                &uops_store_pg::ResourceFilter::default(),
            )
            .await
            .expect("resources");
        assert_eq!(resources.items.len(), 1);
    }

    let _ = stop.send(());
    serving.await.expect("join").expect("serve");
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_log_and_a_span_from_one_request_meet_on_the_trace_id() {
    // M8 §2.5, end to end and the whole of it: `logs.trace_id` has been a column since M3
    // and `uops_otlp::logs` has populated it for as long — the other end was simply
    // missing. This is the test that the two ends now agree.
    //
    // What it is really guarding is the encoding. Both decoders turn OTLP's raw bytes
    // into hex through the same function, so they agree today; if one ever stopped —
    // upper case, a `0x` prefix, a dash every four bytes — every trace in the product
    // would appear to have logged nothing. That is a plausible thing for a trace to do,
    // which is why nobody would notice.
    let store = infra_or_skip!(
        PgStore::connect(&PgConfig {
            url: database_url(),
            ..PgConfig::default()
        })
        .await
        .map_err(|e| e.to_string())
    );
    let telemetry = ChStore::new(ChClient::new(uops_store_ch::ChConfig::from_env()));
    infra_or_skip!(telemetry.health().await.map_err(|e| e.to_string()));

    let (tenant_id, slug) = tenant(&store, "join").await;
    let running = start(&store, &telemetry, &slug).await;

    // The same 16 bytes on the wire for both signals, which is what an SDK's log appender
    // does: it reads the ambient span's context and stamps the record with it.
    let trace = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
    let trace_bytes = hex(trace);
    let root = hex("00000000000000a1");

    let marker = format!("join-{}", uuid::Uuid::now_v7().simple());

    let spans = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(resource("app-20")),
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: trace_bytes.clone(),
                    span_id: root.clone(),
                    parent_span_id: Vec::new(),
                    name: "GET /checkout".to_owned(),
                    kind: 2,
                    start_time_unix_nano: now_nanos(),
                    end_time_unix_nano: now_nanos() + 5_000_000,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };

    let logs = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(resource("app-20")),
            scope_logs: vec![ScopeLogs {
                log_records: vec![
                    LogRecord {
                        time_unix_nano: now_nanos(),
                        severity_number: 17,
                        body: Some(string(&marker)),
                        trace_id: trace_bytes.clone(),
                        span_id: root.clone(),
                        ..LogRecord::default()
                    },
                    // And one from the same application with no span in scope. It must
                    // not come back: `trace_id` is empty on it, and an empty id matching
                    // everything is the failure `uops_query::correlate` refuses.
                    LogRecord {
                        time_unix_nano: now_nanos(),
                        severity_number: 9,
                        body: Some(string(&format!("{marker}-untraced"))),
                        ..LogRecord::default()
                    },
                ],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };

    for (path, body) in [
        ("/v1/traces", spans.encode_to_vec()),
        ("/v1/logs", logs.encode_to_vec()),
    ] {
        let (status, _) = post(running.address, path, body).await;
        assert_eq!(status, 200, "{path}");
    }

    // Both queries come from the correlation helpers, so the predicate is written once.
    let scope = uops_core::TenantScope::system(tenant_id);
    let window = uops_query::TimeRange::new(
        chrono::Utc::now() - chrono::Duration::minutes(10),
        chrono::Utc::now() + chrono::Duration::minutes(10),
    );
    let resources = uops_query::ResolvedResources::whole_tenant(&scope);

    let span_rows = wait_for_rows(
        &telemetry,
        &uops_query::trace_spans(trace, window).expect("a span query"),
        &scope,
        &resources,
    )
    .await;
    assert_eq!(span_rows.len(), 1, "the span: {:?}", span_rows.rows);
    assert_eq!(span_rows.table, "spans");

    let log_rows = wait_for_rows(
        &telemetry,
        &uops_query::trace_logs(trace, window).expect("a log query"),
        &scope,
        &resources,
    )
    .await;
    assert_eq!(log_rows.table, "logs");
    assert_eq!(
        log_rows.len(),
        1,
        "the traced log and not the untraced one: {:?}",
        log_rows.rows
    );
    assert_eq!(
        log_rows.value(0, "body").and_then(|v| v.as_str()),
        Some(marker.as_str())
    );

    // The join key itself, byte for byte across two decoders and two tables. Asserted on
    // the values that came back rather than on the ones that went in, because what the
    // decoders wrote is the only thing a query can match on.
    let span_trace = span_rows
        .value(0, "trace_id")
        .and_then(|v| v.as_str())
        .expect("the span's trace id")
        .to_owned();
    let log_trace = log_rows
        .value(0, "trace_id")
        .and_then(|v| v.as_str())
        .expect("the log's trace id")
        .to_owned();
    assert_eq!(span_trace, log_trace);
    assert_eq!(span_trace, trace, "and both are what the exporter sent");

    // And the log points at the span, which is what turns "during this trace" into
    // "during this operation".
    assert_eq!(
        log_rows.value(0, "span_id").and_then(|v| v.as_str()),
        span_rows.value(0, "span_id").and_then(|v| v.as_str())
    );

    let _ = running.stop.send(());
    running.serving.await.expect("join").expect("serve");
}

/// Run a compiled query until it returns something, or give up.
///
/// The batcher flushes on a deadline, so a query issued immediately after an export is
/// reliably empty. The existing `wait_for` does this for raw SQL; this does it for the
/// AST, which is what the correlation helpers produce.
async fn wait_for_rows(
    telemetry: &ChStore,
    query: &uops_query::Query,
    scope: &uops_core::TenantScope,
    resources: &uops_query::ResolvedResources,
) -> uops_store_ch::ResultSet {
    let mut last = None;
    for _ in 0..60 {
        let result = telemetry
            .query(query, scope, resources)
            .await
            .expect("the statement must be one ClickHouse accepts");
        if !result.rows.is_empty() {
            return result;
        }
        last = Some(result);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    last.expect("at least one attempt")
}

// ---------------------------------------------------------------------------
// Ingest tokens — `docs/packaging.md` §4.2
// ---------------------------------------------------------------------------

/// The refusal, end to end, over a real socket.
///
/// The store half is tested in `uops-store-pg/tests/ingest.rs`. What that cannot show is whether
/// the *listener* asks — and a token nothing checks is the same defect as a component nothing
/// calls, which is the shape this repository keeps producing. So this starts a listener with
/// `require_token` set and posts at it five ways.
///
/// One sentence for every failure is the property being protected, so the assertions are all on
/// the same status: a response that distinguished *expired* from *never existed* would confirm
/// that a token had once been real, and one that distinguished *another tenant's* would say this
/// endpoint serves a tenant somebody else holds a credential for.
#[tokio::test(flavor = "multi_thread")]
async fn a_listener_that_requires_a_token_refuses_everything_else() {
    let store = infra_or_skip!(
        PgStore::connect(&PgConfig {
            url: database_url(),
            ..PgConfig::default()
        })
        .await
        .map_err(|e| e.to_string())
    );
    let telemetry = ChStore::new(ChClient::new(uops_store_ch::ChConfig::from_env()));
    infra_or_skip!(telemetry.health().await.map_err(|e| e.to_string()));

    let (tenant_id, slug) = tenant(&store, "tok").await;

    // A listener that requires a token, unlike `start`'s.
    let address = free_port();
    let mut config = config(&slug, address);
    config.listeners[0].require_token = true;
    let bound = run::resolve_tenants(&store, &config)
        .await
        .expect("resolve the slug");

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn({
        let store = store.clone();
        let telemetry = telemetry.clone();
        async move {
            run::serve(store, telemetry, &config, bound, async move {
                let _ = stop_rx.await;
            })
            .await
        }
    });
    // The same settling `start` relies on: the socket is bound inside `serve`.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let body = ExportLogsServiceRequest::default().encode_to_vec();
    let scope = uops_core::TenantScope::system(tenant_id);

    // 1. No header at all.
    let (status, _) = post(address, "/v1/logs", body.clone()).await;
    assert_eq!(status, 401, "a request with no token was accepted");

    // 2. A token nobody minted.
    let (status, _) = post_with_token(address, "/v1/logs", "not-a-token", body.clone()).await;
    assert_eq!(status, 401);

    // 3. Another tenant's token. Refused rather than quietly written into *its* tenant, which
    //    would make this listener's binding a suggestion.
    let (other_id, _) = tenant(&store, "oth").await;
    let theirs = store
        .issue_ingest_token(
            &uops_core::TenantScope::system(other_id),
            "theirs",
            None,
            None,
        )
        .await
        .expect("mint");
    let (status, _) = post_with_token(address, "/v1/logs", &theirs.token, body.clone()).await;
    assert_eq!(status, 401, "another tenant's token was accepted here");

    // 4. This tenant's own token — the one that must work.
    let mine = store
        .issue_ingest_token(&scope, "mine", None, None)
        .await
        .expect("mint");
    let (status, _) = post_with_token(address, "/v1/logs", &mine.token, body.clone()).await;
    assert_eq!(status, 200, "a valid token was refused");

    // 5. Revocation takes effect on the next export, because the listener holds no cache.
    assert!(
        store
            .revoke_ingest_token(&scope, mine.id)
            .await
            .expect("revoke")
    );
    let (status, _) = post_with_token(address, "/v1/logs", &mine.token, body).await;
    assert_eq!(
        status, 401,
        "a revoked token still worked, so \"revocation is immediate\" is not true of the listener"
    );

    let _ = stop_tx.send(());
    let _ = serving.await;
}
