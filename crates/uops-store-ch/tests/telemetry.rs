//! Telemetry, end to end, against a real `ClickHouse`.
//!
//! The seam these tests exist for: `uops-query` compiles SQL, `ch-migrations` creates
//! the schema, and until this crate nothing had ever run one against the other. Both
//! sides have had their own tests pass for weeks while disagreeing — that is exactly how
//! `searchAll()` survived as long as it did.
//!
//! ```bash
//! docker compose -f deploy/docker-compose.yml up -d
//! bash scripts/ch.sh apply
//! cargo test -p uops-store-ch
//! ```

use std::collections::BTreeMap;

use chrono::{Duration, TimeZone, Utc};
use uops_core::{ResourceId, SiteId, TenantId, TenantScope};
use uops_query::{
    AggFunc, Aggregation, CompareOp, Expr, Field, Query, ResolvedResources, SignalType, TextMode,
    TimeRange, Value,
};
use uops_store_ch::{
    ChClient, ChConfig, ChStore, FlowRow, FlowStore, LogRow, LogStore, MetricRow, MetricStore,
    SpanRow, TelemetryStore, TraceStore,
};

fn store() -> ChStore {
    ChStore::new(ChClient::new(ChConfig {
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "uops".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "uops".into()),
        ..ChConfig::from_env()
    }))
}

/// The five-minute boundary `secs_ago` seconds in the past.
///
/// # Why these fixtures are not at a fixed instant
///
/// They used to be, at `1_700_000_000` — 2023-11-14. Every table these tests write to
/// carries a retention TTL (`logs` and the pre-aggregates 365 days, `metrics` 30), so by
/// the time this was found the fixtures were nearly three years past retention: the rows
/// were inserted and then removed by a background TTL merge. Whether a test passed
/// depended on whether that merge had run against its part yet, which made
/// `the_explorer_histogram_is_served_from_the_pre_aggregate` fail about one run in
/// fifteen with an empty result. A `SELECT` at the time of the diagnosis found 335 rows
/// still in `logs` for that window and **zero** in `logs_counts_5m` — the aggregate had
/// already been swept.
///
/// Anchored to now instead, and truncated to a five-minute boundary so
/// `toStartOfFiveMinute` puts a fixture in a predictable bucket rather than one that
/// depends on when the suite ran. Backdated far enough that the whole window is in the
/// past: a row in the future is not a retention problem but it is not a measurement
/// either.
fn bucket_aligned(secs_ago: i64) -> chrono::DateTime<Utc> {
    let secs = Utc::now().timestamp() - secs_ago;
    Utc.timestamp_opt(secs - secs.rem_euclid(300), 0)
        .single()
        .expect("a truncated unix timestamp is a valid instant")
}

/// A window that contains the fixtures below, and nothing else.
///
/// One hour, two hours back. Tests share this `ClickHouse` and each uses its own
/// `TenantId`, so two runs whose windows differ still cannot see each other's rows.
fn window() -> TimeRange {
    let start = window_start();
    TimeRange::new(start, start + Duration::hours(1))
}

/// Where the window begins.
///
/// Computed once per process. Every call must return the same instant, because the
/// fixtures are written relative to it and then queried relative to it — if a run
/// crosses a five-minute boundary between the `INSERT` and the `SELECT`, a recomputed
/// start lands in the next bucket and the query looks in the wrong place. That is how
/// three of these tests failed on the run right after the window stopped being a
/// constant.
fn window_start() -> chrono::DateTime<Utc> {
    static START: std::sync::OnceLock<chrono::DateTime<Utc>> = std::sync::OnceLock::new();
    *START.get_or_init(|| bucket_aligned(2 * 3600))
}

/// The shortest retention any table these fixtures write to has.
///
/// `flows` and `spans` are 7 days, `metrics` 30, and `logs`, `events` and the
/// pre-aggregates 365 or
/// more. The shortest one is what binds, because a fixture outside it is removed from
/// that table and left in the others — which is precisely the half-present state that
/// made this hard to see. Keep it in step with `ch-migrations/`.
///
/// It became 7 when M7 added `flows` with the retention §2.5 asks for. `scripts/ch.sh`
/// learned the same lesson on the same day, from the other direction: its fixtures were
/// at a fixed date and silently fell out of the new table's window.
const SHORTEST_RETENTION_DAYS: i64 = 7;

#[test]
fn the_fixtures_are_inside_every_retention_window() {
    // The guard on the bug, checked by the test suite on itself rather than by a CI
    // mutation, because the failure it prevents is not deterministic: TTL is applied by
    // a background merge on ClickHouse's own schedule, so an expired fixture passes
    // until the moment a merge lands between the INSERT and the SELECT. That is a test
    // that fails once a fortnight for a reason nobody can reproduce.
    //
    // This assertion has no such timing in it. It fails immediately, on every run, the
    // day somebody writes a fixed timestamp here again or shortens a TTL past it.
    let age = Utc::now() - window_start();
    assert!(
        age < Duration::days(SHORTEST_RETENTION_DAYS),
        "the fixtures are {} days old and the shortest retention is {SHORTEST_RETENTION_DAYS};          ClickHouse will delete them on its next TTL merge, which makes every test in this          file pass or fail depending on when that merge runs",
        age.num_days()
    );
    assert!(
        age > Duration::zero(),
        "the fixtures are in the future, which is not a measurement"
    );
}

fn log_row(tenant: TenantId, resource: ResourceId, body: &str, offset_secs: i64) -> LogRow {
    let at = window().start + Duration::seconds(offset_secs);
    let mut attributes = BTreeMap::new();
    attributes.insert("host.name".to_owned(), "rtr-01".to_owned());
    attributes.insert("service.name".to_owned(), "bgpd".to_owned());

    LogRow {
        tenant_id: tenant,
        resource_id: resource,
        site_id: SiteId::nil(),
        observed_at: at,
        ingested_at: at,
        source_kind: "syslog".to_owned(),
        source_vendor: "cisco".to_owned(),
        severity: "error".to_owned(),
        facility: 23,
        body: body.to_owned(),
        attributes,
        trace_id: String::new(),
        span_id: String::new(),
    }
}

/// Each test gets its own tenant, so they neither collide nor need cleaning up — and
/// "another tenant cannot see this" is asserted against data that genuinely exists.
fn scope_for(tenant: TenantId) -> TenantScope {
    TenantScope::system(tenant)
}

/// A number from a result cell, however `ClickHouse` chose to encode it.
///
/// 64-bit integers arrive quoted when `output_format_json_quote_64bit_integers` is on,
/// which is the default, and unquoted otherwise — and which of the two you get depends
/// on the aggregate's result type. A test that assumes one silently reads every value
/// as absent, which looks exactly like an empty table.
fn number(value: &serde_json::Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

#[tokio::test]
async fn health_reports_the_version_that_is_actually_running() {
    // On-premise support asks this constantly, and it is not idle curiosity: the text
    // index's function names moved between versions, which this project has already
    // been caught by once.
    let health = store().health().await.unwrap();
    assert!(health.reachable);
    assert!(
        health.version.starts_with("26."),
        "the schema is pinned to 26.8; found {}",
        health.version
    );
}

#[tokio::test]
async fn rows_go_in_and_come_back_out() {
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();
    let scope = scope_for(tenant);

    store
        .insert_logs(&[
            log_row(
                tenant,
                resource,
                "%LINK-3-UPDOWN: changed state to down",
                10,
            ),
            log_row(tenant, resource, "%LINK-3-UPDOWN: changed state to up", 20),
        ])
        .await
        .unwrap();

    let result = store
        .query(
            &Query::new(SignalType::Log, window()),
            &scope,
            &ResolvedResources::whole_tenant(&scope),
        )
        .await
        .unwrap();

    assert_eq!(result.len(), 2, "{:?}", result.rows);
    assert_eq!(result.table, "logs");
    assert!(
        result
            .value(0, "body")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("UPDOWN"),
        "{:?}",
        result.rows
    );
    // The column types come back too — a client guessing from the JSON gets
    // DateTime64 wrong, because it arrives as a string.
    assert_eq!(
        result
            .columns
            .iter()
            .find(|c| c.name == "observed_at")
            .unwrap()
            .ty,
        "DateTime64(3, 'UTC')"
    );
}

#[tokio::test]
async fn a_query_cannot_see_another_tenants_telemetry() {
    // The guarantee the whole stack is arranged around, asserted at the last place it
    // could still be lost. The predicate is written by the compiler from the scope —
    // nothing in uops-store-ch can produce SQL.
    let store = store();
    let mine = TenantId::new();
    let theirs = TenantId::new();
    let resource = ResourceId::new();

    store
        .insert_logs(&[
            log_row(mine, resource, "mine", 30),
            log_row(theirs, resource, "theirs", 30),
        ])
        .await
        .unwrap();

    let scope = scope_for(mine);
    let result = store
        .query(
            &Query::new(SignalType::Log, window()),
            &scope,
            &ResolvedResources::whole_tenant(&scope),
        )
        .await
        .unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result.value(0, "body").unwrap(), "mine");
}

#[tokio::test]
async fn a_resolved_resource_set_narrows_the_read() {
    // What PgCatalog produces, reaching the predicate it was compiled into. The two
    // halves were built a commit apart and never ran together until now.
    let store = store();
    let tenant = TenantId::new();
    let wanted = ResourceId::new();
    let other = ResourceId::new();
    let scope = scope_for(tenant);

    store
        .insert_logs(&[
            log_row(tenant, wanted, "from the device we asked about", 40),
            log_row(tenant, other, "from a different device", 40),
        ])
        .await
        .unwrap();

    let resolved = ResolvedResources::already_resolved(&scope, vec![wanted]);
    let result = store
        .query(&Query::new(SignalType::Log, window()), &scope, &resolved)
        .await
        .unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(
        result.value(0, "resource_id").unwrap(),
        &serde_json::Value::String(wanted.to_string())
    );
}

#[tokio::test]
async fn token_search_reaches_the_text_index() {
    // The function names the compiler emits, against the index the DDL creates. This is
    // the exact pair that was wrong for weeks — searchAll() does not exist — and it was
    // only ever going to be caught by running one against the other.
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();
    let scope = scope_for(tenant);

    store
        .insert_logs(&[
            log_row(
                tenant,
                resource,
                "%LINK-3-UPDOWN: changed state to down",
                50,
            ),
            log_row(
                tenant,
                resource,
                "%SYS-5-CONFIG_I: configured from console",
                51,
            ),
        ])
        .await
        .unwrap();

    let hit = Query::new(SignalType::Log, window()).with_filter(Expr::Text {
        field: Field::Body,
        mode: TextMode::AllToken,
        terms: vec!["changed".into(), "down".into()],
    });
    let result = store
        .query(&hit, &scope, &ResolvedResources::whole_tenant(&scope))
        .await
        .unwrap();
    assert_eq!(result.len(), 1, "{:?}", result.rows);

    let miss = Query::new(SignalType::Log, window()).with_filter(Expr::Text {
        field: Field::Body,
        mode: TextMode::AnyToken,
        terms: vec!["zzqx".into()],
    });
    assert!(
        store
            .query(&miss, &scope, &ResolvedResources::whole_tenant(&scope))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_materialised_attribute_is_grouped_as_a_real_column() {
    // W1's most expensive finding: GROUP BY attributes['host.name'] was the slowest
    // query in the suite. The compiler rewrites it onto host_name, which only works if
    // the DDL actually declares that column — and only this proves it does.
    let store = store();
    let tenant = TenantId::new();
    let scope = scope_for(tenant);

    store
        .insert_logs(&[log_row(tenant, ResourceId::new(), "grouped", 60)])
        .await
        .unwrap();

    let mut grouped = Query::new(SignalType::Log, window());
    grouped.aggregations = vec![Aggregation {
        func: AggFunc::Count,
        field: None,
        alias: "n".into(),
    }];
    grouped.group_by = vec![Field::Attr {
        key: "host.name".into(),
    }];

    let result = store
        .query(&grouped, &scope, &ResolvedResources::whole_tenant(&scope))
        .await
        .unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result.rows[0][0], "rtr-01", "{:?}", result.rows);
}

#[tokio::test]
async fn the_explorer_histogram_is_served_from_the_pre_aggregate() {
    // W1 FIX 2, end to end: the planner routes here, the materialised view populates it
    // on insert, and countMerge reads it back. Three separate pieces, first time
    // together.
    let store = store();
    let tenant = TenantId::new();
    let scope = scope_for(tenant);

    store
        .insert_logs(&[
            log_row(tenant, ResourceId::new(), "one", 70),
            log_row(tenant, ResourceId::new(), "two", 80),
        ])
        .await
        .unwrap();

    let mut histogram = Query::new(SignalType::Log, window());
    histogram.aggregations = vec![Aggregation {
        func: AggFunc::Count,
        field: None,
        alias: "c".into(),
    }];
    histogram.group_by = vec![Field::TimeBucket { seconds: 300 }];

    let result = store
        .query(&histogram, &scope, &ResolvedResources::whole_tenant(&scope))
        .await
        .unwrap();

    assert_eq!(
        result.table, "logs_counts_5m",
        "the histogram must not fall back to the base table"
    );
    let total: f64 = result.rows.iter().filter_map(|row| number(&row[1])).sum();
    assert!(
        (total - 2.0).abs() < f64::EPSILON,
        "the pre-aggregate must account for both rows: {:?}",
        result.rows
    );
}

#[tokio::test]
async fn a_slow_query_still_runs_and_says_it_was_slow() {
    // Substring search reads the whole tenant — W1 measured 1 928 ms at 100M rows. It
    // still works, and the warning travels with the result so the UI can say so before
    // somebody waits.
    let store = store();
    let tenant = TenantId::new();
    let scope = scope_for(tenant);

    store
        .insert_logs(&[log_row(tenant, ResourceId::new(), "interface reset", 90)])
        .await
        .unwrap();

    let query = Query::new(SignalType::Log, window()).with_filter(Expr::Text {
        field: Field::Body,
        mode: TextMode::Substring,
        terms: vec!["terface res".into()],
    });

    let result = store
        .query(&query, &scope, &ResolvedResources::whole_tenant(&scope))
        .await
        .unwrap();

    assert_eq!(result.len(), 1, "a substring must still match mid-token");
    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            uops_query::QueryWarning::NotIndexAccelerated { .. }
        )),
        "{:?}",
        result.warnings
    );
}

#[tokio::test]
async fn the_server_reports_how_much_it_read() {
    // The number W1 was written around. Latency says a query was slow; rows read says
    // whether it pruned or scanned the tenant — and it is what the access log records.
    let store = store();
    let tenant = TenantId::new();
    let scope = scope_for(tenant);

    store
        .insert_logs(&[log_row(tenant, ResourceId::new(), "counted", 100)])
        .await
        .unwrap();

    let result = store
        .query(
            &Query::new(SignalType::Log, window()),
            &scope,
            &ResolvedResources::whole_tenant(&scope),
        )
        .await
        .unwrap();

    assert!(result.rows_read > 0, "the summary header was not parsed");
}

#[tokio::test]
async fn metrics_go_in_and_the_rollup_answers_a_long_window() {
    // raw → 5m → 1h, and the planner choosing between them by span. The chain is built
    // by materialised views on insert, so this exercises all three at once.
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();
    let scope = scope_for(tenant);

    let rows: Vec<MetricRow> = (0..12)
        .map(|i| MetricRow {
            tenant_id: tenant,
            resource_id: resource,
            site_id: SiteId::nil(),
            metric: "system.cpu.utilization".to_owned(),
            observed_at: window().start + Duration::minutes(i * 5),
            ingested_at: window().start,
            #[allow(clippy::cast_precision_loss)]
            value: (i + 1) as f64,
            unit: "1".to_owned(),
            labels: BTreeMap::new(),
        })
        .collect();
    store.insert_metrics(&rows).await.unwrap();

    // A window longer than raw retention: the planner must reach for a rollup.
    let mut long = Query::new(
        SignalType::Metric,
        TimeRange::new(window().start, window().start + Duration::days(60)),
    );
    long.aggregations = vec![Aggregation {
        func: AggFunc::Avg,
        field: Some(Field::Value),
        alias: "avg_cpu".into(),
    }];

    let result = store
        .query(&long, &scope, &ResolvedResources::whole_tenant(&scope))
        .await
        .unwrap();

    assert_eq!(result.table, "metrics_1h");
    assert!(
        result
            .warnings
            .iter()
            .any(|w| matches!(w.warning, uops_query::QueryWarning::Downsampled { .. })),
        "downsampling must never be silent: {:?}",
        result.warnings
    );

    // The mean of 1..=12 is 6.5, and it must survive two levels of state merging —
    // five-minute states re-aggregated into an hourly one. An average of averages
    // would also give 6.5 here (every bucket holds one point), so the weighting is
    // proven separately in scripts/ch.sh smoke, where the buckets are uneven.
    let avg = number(&result.rows[0][0]).expect("an average came back");
    assert!(
        (avg - 6.5).abs() < 0.001,
        "got {avg} from {:?}",
        result.rows
    );
}

#[tokio::test]
async fn a_query_the_compiler_refuses_never_reaches_the_server() {
    // It must fail as a caller error rather than as a ClickHouse exception — the
    // difference between "you asked for something that does not exist" and "the database
    // is broken", which is what an operator reads off the status code.
    //
    // This used to be a trace query, declared in the AST and unimplemented. M8 built
    // them, so the example is now a field from another signal: `body` is a logs column
    // and a span does not have one.
    let store = store();
    let tenant = TenantId::new();
    let scope = scope_for(tenant);

    let mut q = Query::new(SignalType::Trace, window());
    q.filter = Some(Expr::Compare {
        field: Field::Body,
        cmp: CompareOp::Eq,
        value: Value::Str("anything".into()),
    });

    let err = store
        .query(&q, &scope, &ResolvedResources::whole_tenant(&scope))
        .await
        .unwrap_err();

    let mapped: uops_core::Error = err.into();
    assert_eq!(mapped.status_code(), 400, "{mapped}");
}

/// One counter reading on a named interface.
fn counter_row(
    tenant: TenantId,
    resource: ResourceId,
    interface: &str,
    minute: i64,
    value: f64,
) -> MetricRow {
    let mut labels = BTreeMap::new();
    labels.insert("network.interface.index".to_owned(), interface.to_owned());
    MetricRow {
        tenant_id: tenant,
        resource_id: resource,
        site_id: SiteId::nil(),
        metric: "network.io.receive".to_owned(),
        observed_at: window().start + Duration::minutes(minute),
        ingested_at: window().start,
        value,
        unit: "By".to_owned(),
        labels,
    }
}

/// Ask for the per-bucket rate of `network.io.receive`, as a dashboard panel would.
fn rate_query(bucket_seconds: u32) -> Query {
    let mut q = Query::new(SignalType::Metric, window());
    q.filter = Some(Expr::Compare {
        field: Field::Metric,
        cmp: uops_query::CompareOp::Eq,
        value: uops_query::Value::Str("network.io.receive".into()),
    });
    q.aggregations = vec![
        Aggregation {
            func: AggFunc::Avg,
            field: Some(Field::Rate),
            alias: "bps".into(),
        },
        Aggregation {
            func: AggFunc::Min,
            field: Some(Field::Rate),
            alias: "low".into(),
        },
    ];
    q.group_by = vec![Field::TimeBucket {
        seconds: bucket_seconds,
    }];
    q.limit = 100;
    q
}

#[tokio::test]
async fn a_counter_wrap_produces_no_negative_rate() {
    // SPEC section M2's fourth acceptance criterion, in the place it has to hold: "a
    // 32-bit counter wrap produces no negative rate in any query". `uops_poll::counter`
    // states the rule in Rust and is thoroughly tested; nothing executes that Rust on a
    // query path, so this is the assertion that the criterion is actually met.
    //
    // A 32-bit counter near its ceiling, wrapping between two consecutive polls — which
    // on a 1 Gbps link with a 32-bit ifInOctets happens about every 34 seconds.
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();
    let scope = scope_for(tenant);

    let ceiling = f64::from(u32::MAX);
    let rows = vec![
        counter_row(tenant, resource, "1", 0, ceiling - 3_000.0),
        counter_row(tenant, resource, "1", 1, ceiling - 1_000.0), // +2 000, forwards
        counter_row(tenant, resource, "1", 2, 1_000.0),           // wrapped
        counter_row(tenant, resource, "1", 3, 3_000.0),           // +2 000, forwards
    ];
    store.insert_metrics(&rows).await.unwrap();

    // One bucket per sample, so each pair is visible on its own.
    let result = store
        .query(
            &rate_query(60),
            &scope,
            &ResolvedResources::whole_tenant(&scope),
        )
        .await
        .unwrap();

    let rates: Vec<Option<f64>> = result.rows.iter().map(|row| number(&row[1])).collect();
    assert!(
        rates.iter().flatten().all(|r| *r >= 0.0),
        "a wrap produced a negative rate: {rates:?}"
    );

    // And the minimum, which is where a negative would show up first.
    let lows: Vec<Option<f64>> = result.rows.iter().map(|row| number(&row[2])).collect();
    assert!(
        lows.iter().flatten().all(|r| *r >= 0.0),
        "a wrap produced a negative minimum: {lows:?}"
    );

    // Not vacuous: the forward pairs must have produced real numbers. 2 000 bytes over
    // 60 seconds is 33.3 B/s.
    let real: Vec<f64> = rates.iter().flatten().copied().collect();
    assert_eq!(
        real.len(),
        2,
        "two of the three pairs step forwards and must each yield a rate: {rates:?}"
    );
    for r in real {
        assert!(
            (r - 2_000.0 / 60.0).abs() < 0.001,
            "expected 33.3 B/s, got {r}"
        );
    }
}

#[tokio::test]
async fn a_wrap_is_a_gap_rather_than_a_repaired_number() {
    // The other half of the criterion, and the one a "fix" would break. The obvious
    // repair is 2^32 - previous + current; it is right exactly once, and on a 10 Gbps
    // link a 32-bit byte counter goes round seventeen times a minute, so it would report
    // one seventeenth of the traffic with total confidence.
    //
    // So the wrapped pair must yield *nothing* — not a large number and not a small one.
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();
    let scope = scope_for(tenant);

    let ceiling = f64::from(u32::MAX);
    store
        .insert_metrics(&[
            counter_row(tenant, resource, "1", 0, ceiling - 1_000.0),
            counter_row(tenant, resource, "1", 1, 1_000.0),
        ])
        .await
        .unwrap();

    let result = store
        .query(
            &rate_query(60),
            &scope,
            &ResolvedResources::whole_tenant(&scope),
        )
        .await
        .unwrap();

    let real: Vec<f64> = result
        .rows
        .iter()
        .filter_map(|row| number(&row[1]))
        .collect();
    assert!(
        real.is_empty(),
        "the only pair in this series wrapped; nothing should have been reported: {real:?}"
    );
}

#[tokio::test]
async fn two_interfaces_counters_are_not_differenced_against_each_other() {
    // A series is one resource, one metric, one set of labels. Partition by less and
    // interface 2 gets subtracted from interface 1 — which produces a number rather than
    // an error, and a plausible-looking one.
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();
    let scope = scope_for(tenant);

    // Interface 1 climbs slowly, interface 2 is far ahead and climbs at the same rate.
    // Interleaved in time, so a query ignoring the labels would see the sequence
    // 1 000, 900 000, 2 000, 901 000 and report enormous alternating rates.
    store
        .insert_metrics(&[
            counter_row(tenant, resource, "1", 0, 1_000.0),
            counter_row(tenant, resource, "2", 0, 900_000.0),
            counter_row(tenant, resource, "1", 1, 2_000.0),
            counter_row(tenant, resource, "2", 1, 901_000.0),
        ])
        .await
        .unwrap();

    let result = store
        .query(
            &rate_query(3600),
            &scope,
            &ResolvedResources::whole_tenant(&scope),
        )
        .await
        .unwrap();

    // Both interfaces moved 1 000 bytes in 60 seconds: 16.67 B/s each, so the average
    // over the two is the same number.
    let rates: Vec<f64> = result
        .rows
        .iter()
        .filter_map(|row| number(&row[1]))
        .collect();
    assert_eq!(rates.len(), 1, "one bucket: {rates:?}");
    assert!(
        (rates[0] - 1_000.0 / 60.0).abs() < 0.001,
        "expected 16.67 B/s per interface; got {} — the series were mixed",
        rates[0]
    );
}

#[tokio::test]
async fn the_first_sample_of_a_series_has_no_rate() {
    // `lagInFrame` returns the column default when there is no previous row — zero for a
    // Float64, the epoch for a DateTime64 — and the arithmetic would accept both,
    // yielding a plausible rate over fifty-six years. A single sample is not a rate.
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();
    let scope = scope_for(tenant);

    store
        .insert_metrics(&[counter_row(tenant, resource, "1", 0, 5_000.0)])
        .await
        .unwrap();

    let result = store
        .query(
            &rate_query(3600),
            &scope,
            &ResolvedResources::whole_tenant(&scope),
        )
        .await
        .unwrap();

    let real: Vec<f64> = result
        .rows
        .iter()
        .filter_map(|row| number(&row[1]))
        .collect();
    assert!(real.is_empty(), "one sample is not a rate: {real:?}");
}

/// The property that makes the tail a stream rather than a repeated search.
///
/// Two consecutive polls over `[t0, t1)` and `[t1, t2)` must between them deliver every
/// row once and no row twice. The window is half-open on `ingested_at`, so a row that
/// lands exactly on a boundary belongs to the later poll and only to it — which is the
/// one case that is impossible to get right by eye and trivial to get wrong.
#[tokio::test]
async fn consecutive_tail_polls_deliver_every_row_exactly_once() {
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();
    let scope = scope_for(tenant);

    let t0 = window().start;
    let t1 = t0 + Duration::seconds(10);
    let t2 = t1 + Duration::seconds(10);

    // Two in the first poll's window, one exactly on the boundary, one in the second's.
    let rows = [
        ingested_at_row(tenant, resource, "first", t0),
        ingested_at_row(tenant, resource, "second", t0 + Duration::seconds(5)),
        ingested_at_row(tenant, resource, "on the boundary", t1),
        ingested_at_row(tenant, resource, "third", t1 + Duration::seconds(5)),
    ];
    store.insert_logs(&rows).await.unwrap();

    let base = Query::new(SignalType::Log, window());
    let first = bodies(&store, &scope, &uops_query::follow(&base, t0, t1)).await;
    let second = bodies(&store, &scope, &uops_query::follow(&base, t1, t2)).await;

    assert_eq!(first, ["second", "first"], "half-open at the end");
    assert_eq!(
        second,
        ["third", "on the boundary"],
        "a row ingested exactly at the watermark belongs to the next poll"
    );
}

/// The reason the window is on `ingested_at` and not on `observed_at`.
///
/// A row is written with a timestamp two minutes older than the moment it reached
/// storage — a WAL segment replayed after a `ClickHouse` restart, or a device whose
/// clock is slow. Windowing on `observed_at` would have the tail skip past it while it
/// was still in flight and never show it. This is the regression test for that, and it
/// fails against the obvious implementation.
#[tokio::test]
async fn a_row_that_arrives_late_still_reaches_the_tail() {
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();
    let scope = scope_for(tenant);

    let t0 = window().start + Duration::seconds(600);
    let t1 = t0 + Duration::seconds(10);

    let mut late = ingested_at_row(tenant, resource, "replayed from the WAL", t0);
    late.observed_at = t0 - Duration::minutes(2);
    store.insert_logs(&[late]).await.unwrap();

    let base = Query::new(SignalType::Log, window());
    assert_eq!(
        bodies(&store, &scope, &uops_query::follow(&base, t0, t1)).await,
        ["replayed from the WAL"]
    );
}

/// A tenant cannot tail another tenant's ingest, for the same reason it cannot query it:
/// the predicate is the compiler's, from the scope, on this path too.
#[tokio::test]
async fn a_tail_cannot_see_another_tenants_telemetry() {
    let store = store();
    let mine = TenantId::new();
    let theirs = TenantId::new();
    let resource = ResourceId::new();

    let t0 = window().start + Duration::seconds(1200);
    let t1 = t0 + Duration::seconds(10);

    store
        .insert_logs(&[ingested_at_row(theirs, resource, "not yours", t0)])
        .await
        .unwrap();

    let base = Query::new(SignalType::Log, window());
    let seen = bodies(&store, &scope_for(mine), &uops_query::follow(&base, t0, t1)).await;
    assert!(seen.is_empty(), "{seen:?}");
}

/// A log row that reached storage at `ingested_at`, stamped at the same instant unless a
/// test says otherwise.
fn ingested_at_row(
    tenant: TenantId,
    resource: ResourceId,
    body: &str,
    ingested_at: chrono::DateTime<Utc>,
) -> LogRow {
    LogRow {
        observed_at: ingested_at,
        ingested_at,
        ..log_row(tenant, resource, body, 0)
    }
}

/// One poll of the tail, as bodies in the order it delivered them.
async fn bodies(store: &ChStore, scope: &TenantScope, q: &Query) -> Vec<String> {
    let result = store
        .tail(q, scope, &ResolvedResources::whole_tenant(scope))
        .await
        .unwrap();
    (0..result.len())
        .map(|i| {
            result
                .value(i, "body")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

// --- flows, M7 -------------------------------------------------------------------
//
// The rows go in through `FlowRow` rather than hand-written JSON, which is the point of
// these tests existing: a column renamed in `ch-migrations/` and not here is an insert
// failure on the ingestion path, and this is where it is found instead.

/// One value, read with raw SQL.
///
/// `uops-query` has no flow support yet — `SignalType::Flow` compiles to a refusal until
/// the planner learns the table — so these read through the client rather than through
/// the AST. That is a gap being worked around, not a preference.
async fn scalar(sql: &str) -> String {
    let client = ChClient::new(ChConfig {
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "uops".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "uops".into()),
        ..ChConfig::from_env()
    });
    client
        .run(&format!("{sql} FORMAT TSV"), &[])
        .await
        .expect("the statement should run")
        .body
        .trim()
        .to_owned()
}

fn flow(
    tenant: TenantId,
    resource: ResourceId,
    src: &str,
    dst: &str,
    bytes: u64,
    rate: u32,
) -> FlowRow {
    let at = window().start + Duration::seconds(10);
    FlowRow {
        tenant_id: tenant,
        resource_id: resource,
        site_id: SiteId::nil(),
        observed_at: at,
        started_at: at - Duration::seconds(5),
        ingested_at: at,
        src_address: src.parse().expect("a fixture address"),
        dst_address: dst.parse().expect("a fixture address"),
        src_port: 51_000,
        dst_port: 443,
        protocol: 6,
        bytes,
        packets: 42,
        sampling_rate: rate,
        tcp_flags: 0x18,
        tos: 0x10,
        input_if: Some(11),
        output_if: None,
        src_as: None,
        dst_as: Some(15169),
        src_resource_id: ResourceId::nil(),
        dst_resource_id: ResourceId::nil(),
        attributes: BTreeMap::new(),
    }
}

#[tokio::test]
async fn a_flow_goes_in_and_comes_back_out() {
    let store = store();
    let tenant = TenantId::new();

    store
        .insert_flows(&[flow(
            tenant,
            ResourceId::new(),
            "10.0.0.7",
            "8.8.8.8",
            6000,
            1000,
        )])
        .await
        .unwrap();

    let got = scalar(&format!(
        "SELECT concat(toString(bytes), '/', toString(sampling_rate), '/', \
         IPv6NumToString(src_address)) FROM flows WHERE tenant_id = '{tenant}'"
    ))
    .await;

    // IPv4 stored mapped, which is the one column decision in 0007 a reader could trip
    // over, and the counts stored as observed rather than scaled by the rate.
    assert_eq!(got, "6000/1000/::ffff:10.0.0.7");
}

#[tokio::test]
async fn an_ipv6_flow_is_stored_unmapped() {
    let store = store();
    let tenant = TenantId::new();

    store
        .insert_flows(&[flow(
            tenant,
            ResourceId::new(),
            "2001:db8::1",
            "2001:db8::2",
            100,
            1,
        )])
        .await
        .unwrap();

    let got = scalar(&format!(
        "SELECT IPv6NumToString(src_address) FROM flows WHERE tenant_id = '{tenant}'"
    ))
    .await;
    assert_eq!(got, "2001:db8::1");
}

#[tokio::test]
async fn a_null_as_number_stays_null_rather_than_becoming_zero() {
    // 0 is a legitimate AS number and a legitimate ifIndex, so the column has to be able
    // to say "the exporter did not report it" — see `FlowRow`.
    let store = store();
    let tenant = TenantId::new();

    store
        .insert_flows(&[flow(
            tenant,
            ResourceId::new(),
            "10.0.0.1",
            "10.0.0.2",
            1,
            1,
        )])
        .await
        .unwrap();

    let got = scalar(&format!(
        "SELECT concat(toString(isNull(src_as)), '/', toString(dst_as), '/', \
         toString(isNull(output_if)), '/', toString(input_if)) \
         FROM flows WHERE tenant_id = '{tenant}'"
    ))
    .await;
    assert_eq!(got, "1/15169/1/11");
}

#[tokio::test]
async fn the_aggregate_keeps_differently_sampled_traffic_apart() {
    // The decision `0007_flows.sql` exists to make. Three flows of one conversation in
    // one bucket, sampled at two rates: summing them together gives a number that is
    // neither an estimate nor a measurement.
    let store = store();
    let tenant = TenantId::new();
    let resource = ResourceId::new();

    store
        .insert_flows(&[
            flow(tenant, resource, "10.0.0.7", "8.8.8.8", 6000, 1000),
            flow(tenant, resource, "10.0.0.7", "8.8.8.8", 4000, 1000),
            flow(tenant, resource, "10.0.0.7", "8.8.8.8", 100, 1),
        ])
        .await
        .unwrap();

    let where_tenant = format!("FROM flows_5m WHERE tenant_id = '{tenant}'");

    assert_eq!(
        scalar(&format!("SELECT count() {where_tenant}")).await,
        "2",
        "the two sampling rates were merged into one row"
    );
    assert_eq!(
        scalar(&format!(
            "SELECT sum(bytes) {where_tenant} AND sampling_rate = 1000"
        ))
        .await,
        "10000"
    );
    assert_eq!(
        scalar(&format!(
            "SELECT sum(bytes) {where_tenant} AND sampling_rate = 1"
        ))
        .await,
        "100"
    );
    assert_eq!(
        scalar(&format!(
            "SELECT sum(records) {where_tenant} AND sampling_rate = 1000"
        ))
        .await,
        "2"
    );
    // What a screen shows: the reader multiplies, and the two rates are multiplied
    // separately because they mean different things.
    assert_eq!(
        scalar(&format!("SELECT sum(bytes * sampling_rate) {where_tenant}")).await,
        "10000100"
    );
}

// --- spans, M8 -------------------------------------------------------------------
//
// The same seam as the flow block above, for the same reason: the rows go in through
// `SpanRow` rather than hand-written JSON, so a column renamed in `ch-migrations/` and
// not here fails on the ingestion path in this file instead of in production.
//
// `SignalType::Trace` still compiles to a refusal, so these read through raw SQL too.

#[allow(clippy::too_many_arguments)]
fn span(
    tenant: TenantId,
    host: ResourceId,
    service: ResourceId,
    name: &str,
    status: &str,
    duration_ns: u64,
    trace: &str,
    parent: &str,
) -> SpanRow {
    SpanRow {
        tenant_id: tenant,
        resource_id: host,
        service_id: service,
        site_id: SiteId::nil(),
        observed_at: window().start + Duration::seconds(10),
        ingested_at: window().start + Duration::seconds(11),
        trace_id: trace.to_owned(),
        span_id: format!("{duration_ns:016x}"),
        parent_span_id: parent.to_owned(),
        name: name.to_owned(),
        kind: "server".to_owned(),
        duration_ns,
        status_code: status.to_owned(),
        status_message: String::new(),
        sampling_probability: 0.0,
        scope_name: "io.opentelemetry.grpc".to_owned(),
        attributes: BTreeMap::new(),
    }
}

#[tokio::test]
async fn a_span_goes_in_and_comes_back_out() {
    let store = store();
    let tenant = TenantId::new();
    let host = ResourceId::new();
    let service = ResourceId::new();

    let mut row = span(
        tenant,
        host,
        service,
        "GET /checkout",
        "error",
        12_000_000,
        &"4b".repeat(16),
        "",
    );
    row.status_message = "upstream timeout".to_owned();
    row.sampling_probability = 1.0 / 1024.0;
    row.attributes
        .insert("http.route".to_owned(), "/checkout".to_owned());

    store.insert_spans(&[row]).await.unwrap();

    // §2.1 read back as one string: the host and the service are *different* columns and
    // a row that conflated them would show the same id twice.
    let got = scalar(&format!(
        "SELECT concat(toString(resource_id), '|', toString(service_id), '|', name, '|', \
         status_code, '|', status_message, '|', toString(duration_ns), '|', \
         toString(sampling_probability), '|', scope_name, '|', attributes['http.route']) \
         FROM spans WHERE tenant_id = '{tenant}'"
    ))
    .await;

    assert_eq!(
        got,
        format!(
            "{host}|{service}|GET /checkout|error|upstream timeout|12000000|\
             0.0009765625|io.opentelemetry.grpc|/checkout"
        )
    );
}

#[tokio::test]
async fn one_service_on_two_hosts_is_one_service() {
    // §2.1's whole reason for two columns. The aggregate is keyed on the service, so
    // "the checkout service's p99" spans both machines without a scan — and the raw rows
    // still sit beside each host's own logs and metrics.
    let store = store();
    let tenant = TenantId::new();
    let service = ResourceId::new();

    store
        .insert_spans(&[
            span(
                tenant,
                ResourceId::new(),
                service,
                "GET /checkout",
                "unset",
                1_000_000,
                &"01".repeat(16),
                "",
            ),
            span(
                tenant,
                ResourceId::new(),
                service,
                "GET /checkout",
                "unset",
                2_000_000,
                &"02".repeat(16),
                "",
            ),
        ])
        .await
        .unwrap();

    let got = scalar(&format!(
        "SELECT concat(toString(uniqExact(resource_id)), '/', toString(uniqExact(service_id))) \
         FROM spans WHERE tenant_id = '{tenant}'"
    ))
    .await;
    assert_eq!(got, "2/1", "two hosts, one service");
}

#[tokio::test]
async fn the_aggregate_counts_only_error_as_a_failure() {
    // The decision `0008_spans.sql` exists to make, and the one that would quietly ruin
    // every error rate in the product. `unset` is OTel's default and is what a healthy
    // span carries when nobody said otherwise; counting it as a failure would show every
    // service at a 100% error rate, and calling it `ok` would erase the difference
    // between "it succeeded" and "nobody checked".
    let store = store();
    let tenant = TenantId::new();
    let service = ResourceId::new();
    let host = ResourceId::new();

    store
        .insert_spans(&[
            span(
                tenant,
                host,
                service,
                "op",
                "unset",
                1_000_000,
                &"aa".repeat(16),
                "",
            ),
            span(
                tenant,
                host,
                service,
                "op",
                "ok",
                2_000_000,
                &"bb".repeat(16),
                "",
            ),
            span(
                tenant,
                host,
                service,
                "op",
                "error",
                3_000_000,
                &"cc".repeat(16),
                "",
            ),
        ])
        .await
        .unwrap();

    let got = scalar(&format!(
        "SELECT concat(toString(sum(requests)), '/', toString(sum(errors))) \
         FROM service_5m WHERE tenant_id = '{tenant}'"
    ))
    .await;
    assert_eq!(got, "3/1");
}

#[tokio::test]
async fn a_percentile_survives_the_aggregate() {
    // §2.4: a p99 cannot be summed, averaged or re-bucketed, so the column holds a
    // t-digest *state* and the reader merges it. This is the check that the state really
    // is mergeable and really does agree with the raw spans — if the view had stored a
    // number, this would be the test that found out.
    let store = store();
    let tenant = TenantId::new();
    let service = ResourceId::new();
    let host = ResourceId::new();

    let rows: Vec<SpanRow> = (1..=100)
        .map(|i| {
            span(
                tenant,
                host,
                service,
                "op",
                "unset",
                i * 1_000_000,
                &format!("{i:032x}"),
                "",
            )
        })
        .collect();
    store.insert_spans(&rows).await.unwrap();

    let merged = scalar(&format!(
        "SELECT toUInt64(quantilesTDigestMerge(0.5, 0.95, 0.99)(latency)[2]) \
         FROM service_5m WHERE tenant_id = '{tenant}'"
    ))
    .await;
    let raw = scalar(&format!(
        "SELECT toUInt64(quantileTDigest(0.95)(duration_ns)) \
         FROM spans WHERE tenant_id = '{tenant}'"
    ))
    .await;

    let (merged, raw): (f64, f64) = (merged.parse().unwrap(), raw.parse().unwrap());
    assert!(
        (merged - raw).abs() <= raw * 0.01,
        "a merged p95 of {merged} should agree with the raw {raw} within what a t-digest allows"
    );
}

#[tokio::test]
async fn a_trace_is_retrievable_across_the_hosts_it_ran_on() {
    // §2.2, and the query the sort key cannot help with: the spans of one trace are
    // scattered across services on as many hosts, so nothing about
    // `(tenant, resource, observed_at)` narrows it. The bloom filter on `trace_id` is
    // what prunes it, and this is the test that the lookup is correct — the *cost* is
    // §2.2's separate measurement at scale, which a three-row fixture cannot make.
    let store = store();
    let tenant = TenantId::new();
    let trace = "7f".repeat(16);
    let root = format!("{:016x}", 1_000_000u64);

    store
        .insert_spans(&[
            span(
                tenant,
                ResourceId::new(),
                ResourceId::new(),
                "GET /checkout",
                "unset",
                1_000_000,
                &trace,
                "",
            ),
            span(
                tenant,
                ResourceId::new(),
                ResourceId::new(),
                "charge",
                "unset",
                2_000_000,
                &trace,
                &root,
            ),
            span(
                tenant,
                ResourceId::new(),
                ResourceId::new(),
                "SELECT",
                "unset",
                3_000_000,
                &trace,
                &root,
            ),
            // A second trace on the same tenant, to prove the filter is doing something.
            span(
                tenant,
                ResourceId::new(),
                ResourceId::new(),
                "unrelated",
                "unset",
                4_000_000,
                &"11".repeat(16),
                "",
            ),
        ])
        .await
        .unwrap();

    let got = scalar(&format!(
        "SELECT concat(toString(count()), '/', toString(countIf(parent_span_id = '')), '/', \
         toString(uniqExact(resource_id))) \
         FROM spans WHERE tenant_id = '{tenant}' AND trace_id = '{trace}'"
    ))
    .await;
    // Three spans, exactly one root, on three hosts — which is the shape a trace view
    // needs before it can draw anything.
    assert_eq!(got, "3/1/3");
}

#[tokio::test]
async fn spans_from_one_tenant_are_unreachable_from_another() {
    // The same adversarial test M7 used, asked of the new table. Tenancy is the one
    // property that has to hold for every signal, and a table added without it looks
    // fine until the first shared deployment.
    let store = store();
    let victim = TenantId::new();
    let attacker = TenantId::new();
    let trace = "9c".repeat(16);

    store
        .insert_spans(&[span(
            victim,
            ResourceId::new(),
            ResourceId::new(),
            "secret",
            "error",
            5_000_000,
            &trace,
            "",
        )])
        .await
        .unwrap();

    // Knowing the trace id exactly — the strongest position an attacker could be in — is
    // still not enough, because the tenant is the first thing every predicate carries.
    assert_eq!(
        scalar(&format!(
            "SELECT count() FROM spans WHERE tenant_id = '{attacker}' AND trace_id = '{trace}'"
        ))
        .await,
        "0"
    );
    assert_eq!(
        scalar(&format!(
            "SELECT count() FROM service_5m WHERE tenant_id = '{attacker}'"
        ))
        .await,
        "0"
    );
    assert_eq!(
        scalar(&format!(
            "SELECT count() FROM spans WHERE tenant_id = '{victim}' AND trace_id = '{trace}'"
        ))
        .await,
        "1",
        "and the row really was written, so the zeros above mean something"
    );
}

// --- traces through the planner, M8 ------------------------------------------------
//
// The flow block above reads with raw SQL because `SignalType::Flow` had no planner when
// it was written. Traces do, so these go through the AST — which is the only way to find
// out whether what the planner emits is a statement `ClickHouse` accepts. Both sides'
// unit tests were happy about the timezone bug too.

/// A query over the fixture window, whole-tenant.
fn trace_query(tenant: TenantId) -> (Query, TenantScope) {
    (
        Query::new(SignalType::Trace, window()),
        TenantScope::system(tenant),
    )
}

#[tokio::test]
async fn a_trace_is_looked_up_by_id_through_the_ast() {
    // §2.2's query, compiled rather than hand-written. The one that made the planner
    // worth having: `trace_id` is 32 hex characters, which is exactly a UUID without its
    // dashes, so the value arrives as `Value::Uuid` and has to be bound as a `String` or
    // the statement compares a UUID to a String column and fails.
    let store = store();
    let tenant = TenantId::new();
    let trace = "4b".repeat(16);

    store
        .insert_spans(&[
            span(
                tenant,
                ResourceId::new(),
                ResourceId::new(),
                "GET /checkout",
                "unset",
                1_000_000,
                &trace,
                "",
            ),
            span(
                tenant,
                ResourceId::new(),
                ResourceId::new(),
                "charge",
                "error",
                2_000_000,
                &trace,
                &format!("{:016x}", 1_000_000u64),
            ),
            span(
                tenant,
                ResourceId::new(),
                ResourceId::new(),
                "unrelated",
                "unset",
                3_000_000,
                &"11".repeat(16),
                "",
            ),
        ])
        .await
        .unwrap();

    let (mut q, scope) = trace_query(tenant);
    // Parsed the way the API parses it, rather than constructed. That is the whole point:
    // `Value` is untagged, so 32 hex characters deserialise into `Value::Uuid` and nothing
    // downstream can tell them from a real UUID — and `trace_id` is a `String` column.
    let value: Value = serde_json::from_str(&format!("\"{trace}\"")).expect("a literal");
    assert!(
        matches!(value, Value::Uuid(_)),
        "the trap this test exists for: {value:?}"
    );
    q.filter = Some(Expr::Compare {
        field: Field::TraceId,
        cmp: CompareOp::Eq,
        value,
    });
    let result = store
        .query(&q, &scope, &ResolvedResources::whole_tenant(&scope))
        .await
        .unwrap();

    assert_eq!(result.table, "spans");
    assert_eq!(
        result.len(),
        2,
        "one trace, not the tenant: {:?}",
        result.rows
    );
    // And the two subjects came back as two columns, which is what a trace view draws
    // from.
    assert!(result.columns.iter().any(|c| c.name == "service_id"));
    assert!(result.columns.iter().any(|c| c.name == "resource_id"));
}

#[tokio::test]
async fn the_apm_screen_compiles_to_a_statement_clickhouse_accepts() {
    // Count, error count and two percentiles in one query, off `service_5m` — the shape
    // M8 §2.4 says every APM screen asks. Running it is the point: a
    // `quantilesTDigestMerge` whose declared quantiles disagree with the column's type is
    // a runtime error that no amount of unit testing the planner would find.
    let store = store();
    let tenant = TenantId::new();
    let service = ResourceId::new();
    let host = ResourceId::new();

    let mut rows: Vec<SpanRow> = (1..=100)
        .map(|i| {
            span(
                tenant,
                host,
                service,
                "op",
                "unset",
                i * 1_000_000,
                &format!("{i:032x}"),
                "",
            )
        })
        .collect();
    rows.push(span(
        tenant,
        host,
        service,
        "op",
        "error",
        5_000_000,
        &"ee".repeat(16),
        "",
    ));
    store.insert_spans(&rows).await.unwrap();

    let (mut q, scope) = trace_query(tenant);
    q.aggregations = vec![
        Aggregation {
            func: AggFunc::Count,
            field: None,
            alias: "requests".into(),
        },
        Aggregation {
            func: AggFunc::Sum,
            field: Some(Field::Errors),
            alias: "errors".into(),
        },
        Aggregation {
            func: AggFunc::P95,
            field: Some(Field::DurationNs),
            alias: "p95".into(),
        },
    ];
    q.group_by = vec![Field::ServiceId];
    q.filter = Some(Expr::Compare {
        field: Field::ServiceId,
        cmp: CompareOp::Eq,
        value: Value::Uuid(service.into_uuid()),
    });

    let result = store
        .query(&q, &scope, &ResolvedResources::whole_tenant(&scope))
        .await
        .unwrap();

    assert_eq!(result.table, "service_5m", "the aggregate answers this");
    assert_eq!(result.len(), 1, "{:?}", result.rows);

    let number = |name: &str| -> f64 {
        let v = result.value(0, name).unwrap_or_else(|| panic!("{name}"));
        v.as_f64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .unwrap_or_else(|| panic!("{name} is not a number: {v:?}"))
    };

    assert!(
        (number("requests") - 101.0).abs() < f64::EPSILON,
        "every span is a request: {:?}",
        result.rows
    );
    // §2.3's other half, and the decision `0008` exists to make: `unset` is not a
    // failure. One of the 101 is.
    assert!(
        (number("errors") - 1.0).abs() < f64::EPSILON,
        "only `error` is an error: {:?}",
        result.rows
    );
    // The t-digest, merged. The durations are 1ms..100ms, so a p95 lands near 95ms —
    // and the bound is tight enough to exclude the p99 beside it in the same state,
    // because indexing the wrong element of the merged array is exactly the mistake this
    // is here to catch.
    let p95 = number("p95");
    assert!(
        (92_000_000.0..=97_000_000.0).contains(&p95),
        "a merged p95 should land near 95ms, not at another quantile: {p95}"
    );
}

#[tokio::test]
async fn a_resource_scoped_trace_query_reads_the_raw_table() {
    // The planner rule that keeps a silent wrong answer out of the product: `service_5m`
    // carries no `resource_id`, so a question scoped to a host cannot be answered from
    // it. The scoped query has to land on `spans` — and this is the test that the
    // statement it produces is one the server will actually run.
    let store = store();
    let tenant = TenantId::new();
    let service = ResourceId::new();
    let (mine, theirs) = (ResourceId::new(), ResourceId::new());
    let scope = TenantScope::system(tenant);

    store
        .insert_spans(&[
            span(
                tenant,
                mine,
                service,
                "op",
                "unset",
                1_000_000,
                &"c1".repeat(16),
                "",
            ),
            span(
                tenant,
                mine,
                service,
                "op",
                "error",
                1_500_000,
                &"c3".repeat(16),
                "",
            ),
            span(
                tenant,
                theirs,
                service,
                "op",
                "unset",
                2_000_000,
                &"c2".repeat(16),
                "",
            ),
        ])
        .await
        .unwrap();

    let mut q = Query::new(SignalType::Trace, window());
    q.aggregations = vec![
        Aggregation {
            func: AggFunc::Count,
            field: None,
            alias: "spans".into(),
        },
        Aggregation {
            func: AggFunc::Sum,
            field: Some(Field::Errors),
            alias: "errors".into(),
        },
    ];
    q.group_by = vec![Field::ServiceId];

    let result = store
        .query(
            &q,
            &scope,
            &ResolvedResources::already_resolved(&scope, vec![mine]),
        )
        .await
        .unwrap();

    assert_eq!(result.table, "spans", "a host-scoped question is a raw one");
    assert_eq!(result.len(), 1);

    let count = |name: &str| -> u64 {
        let v = result.value(0, name).unwrap_or_else(|| panic!("{name}"));
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .unwrap_or_else(|| panic!("{name} is not a count: {v:?}"))
    };

    assert_eq!(
        count("spans"),
        2,
        "one host's spans, not both: {:?}",
        result.rows
    );
    // And `errors` means the same thing here as it does on the aggregate, which is the
    // entire reason it is a field rather than a filter. `unset` is not a failure on
    // either table — reading it as `!= 'ok'` would make the other span an error too.
    assert_eq!(count("errors"), 1, "{:?}", result.rows);
}

// --- the service map, M8 §2.6 -------------------------------------------------------

/// One span with an explicit id, so a test can make a parent of it.
#[allow(clippy::too_many_arguments)]
fn linked(
    tenant: TenantId,
    service: ResourceId,
    span_id: &str,
    parent: &str,
    name: &str,
    status: &str,
    duration_ns: u64,
    trace: &str,
) -> SpanRow {
    let mut row = span(
        tenant,
        ResourceId::new(),
        service,
        name,
        status,
        duration_ns,
        trace,
        parent,
    );
    span_id.clone_into(&mut row.span_id);
    row
}

/// The map's rows as `(from, to, calls, errors)`, whatever shape `ClickHouse` returned
/// the numbers in.
fn edges(result: &uops_store_ch::ResultSet) -> Vec<(String, String, u64, u64)> {
    let number = |i: usize, name: &str| -> u64 {
        let v = result.value(i, name).unwrap_or_else(|| panic!("{name}"));
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .unwrap_or_else(|| panic!("{name} is not a count: {v:?}"))
    };
    (0..result.len())
        .map(|i| {
            (
                result
                    .value(i, "from_service")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
                result
                    .value(i, "to_service")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
                number(i, "calls"),
                number(i, "errors"),
            )
        })
        .collect()
}

#[tokio::test]
async fn an_edge_exists_because_a_parent_in_one_service_has_a_child_in_another() {
    // §2.6's acceptance criterion, and the whole of the map: nothing is configured,
    // nothing is stored, and the edge is what the spans already say.
    let store = store();
    let tenant = TenantId::new();
    let scope = TenantScope::system(tenant);
    let (web, checkout, database) = (ResourceId::new(), ResourceId::new(), ResourceId::new());
    let trace = "d0".repeat(16);

    store
        .insert_spans(&[
            // web → checkout → database, plus a span checkout makes of itself.
            linked(
                tenant,
                web,
                "0000000000000001",
                "",
                "GET /",
                "unset",
                9_000_000,
                &trace,
            ),
            linked(
                tenant,
                checkout,
                "0000000000000002",
                "0000000000000001",
                "charge",
                "unset",
                5_000_000,
                &trace,
            ),
            linked(
                tenant,
                checkout,
                "0000000000000003",
                "0000000000000002",
                "validate",
                "unset",
                1_000_000,
                &trace,
            ),
            linked(
                tenant,
                database,
                "0000000000000004",
                "0000000000000003",
                "SELECT",
                "error",
                2_000_000,
                &trace,
            ),
        ])
        .await
        .unwrap();

    let result = store
        .service_map(&scope, window().start, window().end, 50)
        .await
        .unwrap();

    let mut found = edges(&result);
    found.sort();
    let mut expected = vec![
        (web.to_string(), checkout.to_string(), 1, 0),
        (checkout.to_string(), database.to_string(), 1, 1),
    ];
    expected.sort();

    // Two edges, not three: `checkout → checkout` is the service calling itself, which is
    // a flame graph and drawn on a map would be a loop on every node.
    assert_eq!(found, expected, "{:?}", result.rows);
}

#[tokio::test]
async fn an_edge_disappears_when_the_calls_stop() {
    // The other half of §2.6, and the reason the map is derived: an edge stops existing
    // when the calls stop, rather than when somebody remembers to delete it.
    let store = store();
    let tenant = TenantId::new();
    let scope = TenantScope::system(tenant);
    let (front, back) = (ResourceId::new(), ResourceId::new());
    let trace = "d1".repeat(16);

    store
        .insert_spans(&[
            linked(
                tenant,
                front,
                "0000000000000011",
                "",
                "GET /",
                "unset",
                9_000_000,
                &trace,
            ),
            linked(
                tenant,
                back,
                "0000000000000012",
                "0000000000000011",
                "work",
                "unset",
                1_000_000,
                &trace,
            ),
        ])
        .await
        .unwrap();

    let present = store
        .service_map(&scope, window().start, window().end, 50)
        .await
        .unwrap();
    assert_eq!(edges(&present).len(), 1);

    // A later window, in which those services said nothing. No configuration changed and
    // nothing was deleted; there is simply no evidence in it.
    let quiet = store
        .service_map(&scope, window().end, window().end + Duration::hours(1), 50)
        .await
        .unwrap();
    assert!(edges(&quiet).is_empty(), "{:?}", quiet.rows);
}

#[tokio::test]
async fn a_crafted_span_id_cannot_attach_one_tenant_to_another() {
    // The adversarial test the module docs promise, and the reason the tenant predicate
    // appears twice in the statement.
    //
    // A span id is eight bytes chosen by whoever instrumented the application, so a
    // tenant can pick one that collides with another tenant's deliberately — it costs
    // nothing and nothing rejects it. A join whose right-hand side was not itself scoped
    // would read the collision as a parent and draw an edge from the victim's service
    // into the attacker's.
    let store = store();
    let (victim, attacker) = (TenantId::new(), TenantId::new());
    let (victim_service, attacker_service) = (ResourceId::new(), ResourceId::new());
    let shared = "00000000000000ff";

    store
        .insert_spans(&[
            // The victim's parent span, with an id the attacker will guess.
            linked(
                victim,
                victim_service,
                shared,
                "",
                "GET /",
                "unset",
                9_000_000,
                &"d2".repeat(16),
            ),
            // The attacker's child, claiming it as its parent.
            linked(
                attacker,
                attacker_service,
                "00000000000000fe",
                shared,
                "steal",
                "unset",
                1_000_000,
                &"d3".repeat(16),
            ),
        ])
        .await
        .unwrap();

    for tenant in [victim, attacker] {
        let scope = TenantScope::system(tenant);
        let result = store
            .service_map(&scope, window().start, window().end, 50)
            .await
            .unwrap();
        assert!(
            edges(&result).is_empty(),
            "a span id chosen by one tenant must not reach another's map: {:?}",
            result.rows
        );
    }
}

#[tokio::test]
async fn an_unidentified_service_is_not_drawn_as_a_node() {
    // Every service that did not resolve carries the nil uuid, so one node would be the
    // union of all of them — and it would look like a real service with an implausible
    // number of edges.
    let store = store();
    let tenant = TenantId::new();
    let scope = TenantScope::system(tenant);
    let known = ResourceId::new();
    let trace = "d4".repeat(16);

    store
        .insert_spans(&[
            linked(
                tenant,
                ResourceId::nil(),
                "0000000000000021",
                "",
                "GET /",
                "unset",
                9_000_000,
                &trace,
            ),
            linked(
                tenant,
                known,
                "0000000000000022",
                "0000000000000021",
                "work",
                "unset",
                1_000_000,
                &trace,
            ),
        ])
        .await
        .unwrap();

    let result = store
        .service_map(&scope, window().start, window().end, 50)
        .await
        .unwrap();
    assert!(edges(&result).is_empty(), "{:?}", result.rows);
}
