//! Table selection — which physical table answers this query.
//!
//! The caller never names a table (SPEC §M0.6). It says "logs, this window, grouped
//! into five-minute buckets" and the planner decides whether that is the base table,
//! the pre-aggregate, or a rollup. This is where the two W1 fixes actually take effect:
//!
//! | W1 finding | what the planner does |
//! |---|---|
//! | Explorer histogram 1 066 ms, and the `p_by_time` projection does **not** help — a histogram over the retention window touches every row whatever the sort order | routes count-only bucket queries to `logs_counts_5m` |
//! | `GROUP BY attributes['host.name']` was the slowest query in the suite at 2 252 ms | rewrites materialised semconv keys to their real columns, and warns on the ones that are not |
//!
//! The tail's fix — the `p_by_time` projection — needs nothing here: `ClickHouse`
//! chooses a projection itself when the `ORDER BY` matches. That is why
//! [`crate::compile_tail`] is a separate entry point rather than a separate table.

use uops_core::attr::semconv;

use crate::ast::{AggFunc, Aggregation, Field, Query, SignalType, SortKey, fields_of};
use crate::error::{Error, Result};
use crate::warning::QueryWarning;

/// Longest window still answered from raw metric points. Beyond this the raw rows are
/// past their 30-day TTL for part of the range, so a raw query would quietly return a
/// truncated series — worse than downsampling, because it looks complete.
pub const RAW_METRIC_SPAN: chrono::TimeDelta = chrono::TimeDelta::hours(6);
/// Beyond this, the 5-minute rollup is itself past retention and the hourly one serves.
pub const FIVE_MINUTE_SPAN: chrono::TimeDelta = chrono::TimeDelta::days(30);

/// Longest window still answered from raw flow rows.
///
/// Seven days, which is `flows`' TTL in `ch-migrations/0007_flows.sql`. The same argument
/// `RAW_METRIC_SPAN` makes and a sharper version of it: raw flow is the shortest-retained
/// table in the product, so a month-long query against it returns the last week and looks
/// like a month.
pub const RAW_FLOW_SPAN: chrono::TimeDelta = chrono::TimeDelta::days(7);

/// Longest window still answered from raw spans.
///
/// Seven days, which is `spans`' TTL in `ch-migrations/0008_spans.sql` — the same number
/// `flows` has and for the same reason M8 §2.4 gives: raw spans answer *"show me this
/// trace"*, which is an investigation and therefore recent.
pub const RAW_SPAN_SPAN: chrono::TimeDelta = chrono::TimeDelta::days(7);

/// The bucket width of `logs_counts_5m` and `metrics_5m`. A histogram finer than this
/// cannot be served from them.
pub const PREAGGREGATE_BUCKET_SECONDS: u32 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableKind {
    /// The base `MergeTree` table. Every column is available.
    Base,
    /// `logs_counts_5m` — `AggregatingMergeTree`, counts only.
    LogCounts,
    /// `metrics_5m` / `metrics_1h` — `AggregatingMergeTree` states, not raw values.
    MetricRollup,
    /// `flows_5m` — sums per conversation per five minutes.
    ///
    /// Not a `MetricRollup` despite the shape, because what it stores is different:
    /// `SimpleAggregateFunction(sum)` rather than aggregate states, so a reader writes
    /// `sum(bytes)` and never `sumMerge(bytes)`.
    FlowAggregate,
    /// `service_5m` — requests, errors and a latency state per service per operation.
    ///
    /// Both of the other two at once, which is why it is its own kind: `requests` and
    /// `errors` are `SimpleAggregateFunction(sum)` and read with a plain `sum`, while
    /// `latency` is an `AggregateFunction` state and read with a merge.
    ///
    /// It is also the only pre-aggregate with **no `resource_id`**. M8 §2.1 ordered it
    /// service-first because every question it answers starts with a service, and the
    /// host is simply not in it — see [`serves_from_service_5m`].
    ServiceAggregate,
}

/// Which table, and the handful of facts codegen needs about its shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TablePlan {
    pub table: &'static str,
    pub kind: TableKind,
    pub signal: SignalType,
    /// The time column to filter and bucket on: `observed_at`, or `bucket` on a
    /// pre-aggregate.
    pub time_col: &'static str,
    /// Name of the map column holding attributes on this signal.
    pub attr_map: &'static str,
    /// Bucket width already baked into the stored rows, if any.
    pub stored_bucket_seconds: u32,
}

/// A resolved column reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Col {
    /// A real column. Always from a fixed set — never caller text.
    Plain(&'static str),
    /// A map lookup. The key is bound as a parameter.
    Attr { map: &'static str, key: String },
    /// `toStartOfInterval` over the plan's time column.
    Bucket { seconds: u32, base: &'static str },
    /// A fixed SQL expression standing in for a column that is not stored.
    ///
    /// `&'static str` and nothing else, for the same reason [`Col::Plain`] is: this is
    /// emitted verbatim, so it must never be able to carry caller text. The only one so
    /// far is `Field::Errors`, which is a column on the aggregate and a comparison on the
    /// raw table.
    Expr(&'static str),
}

/// Pick the table, and say what was given up to get there.
///
/// `whole_tenant` is whether the query's resource selector resolved to everything. It
/// matters to exactly one table — `service_5m`, which has no `resource_id` column at all —
/// and the alternative was letting the compiler emit `resource_id IN (…)` against a table
/// that does not have it.
pub(crate) fn plan(q: &Query, whole_tenant: bool) -> Result<(TablePlan, Vec<QueryWarning>)> {
    let mut warnings = Vec::new();

    let base = |table: &'static str, attr_map: &'static str| TablePlan {
        table,
        kind: TableKind::Base,
        signal: q.signal,
        time_col: "observed_at",
        attr_map,
        stored_bucket_seconds: 0,
    };

    let plan = match q.signal {
        SignalType::Trace => {
            if serves_from_service_5m(q, whole_tenant) {
                if q.time.span() > RAW_SPAN_SPAN {
                    warnings.push(QueryWarning::Downsampled {
                        table: "service_5m".into(),
                        bucket_seconds: PREAGGREGATE_BUCKET_SECONDS,
                    });
                }
                TablePlan {
                    table: "service_5m",
                    kind: TableKind::ServiceAggregate,
                    signal: q.signal,
                    time_col: "bucket",
                    attr_map: "attributes",
                    stored_bucket_seconds: PREAGGREGATE_BUCKET_SECONDS,
                }
            } else {
                // The flow rule, unchanged: a window past what raw keeps is answered and
                // said out loud, because a truncated answer the caller knows about beats
                // no answer — and beats one that looks complete.
                if q.time.span() > RAW_SPAN_SPAN {
                    warnings.push(QueryWarning::BeyondRetention {
                        table: "spans".into(),
                        days: RAW_SPAN_SPAN.num_days(),
                    });
                }
                base("spans", "attributes")
            }
        }
        SignalType::Flow => {
            if serves_from_flows_5m(q) {
                if q.time.span() > RAW_FLOW_SPAN {
                    warnings.push(QueryWarning::Downsampled {
                        table: "flows_5m".into(),
                        bucket_seconds: PREAGGREGATE_BUCKET_SECONDS,
                    });
                }
                TablePlan {
                    table: "flows_5m",
                    kind: TableKind::FlowAggregate,
                    signal: q.signal,
                    time_col: "bucket",
                    attr_map: "attributes",
                    stored_bucket_seconds: PREAGGREGATE_BUCKET_SECONDS,
                }
            } else {
                // Raw, and said out loud when the window reaches past what raw keeps.
                // Refusing would be worse: the caller asked for something the aggregate
                // cannot answer, and a truncated answer they know about beats no answer.
                if q.time.span() > RAW_FLOW_SPAN {
                    warnings.push(QueryWarning::BeyondRetention {
                        table: "flows".into(),
                        days: RAW_FLOW_SPAN.num_days(),
                    });
                }
                base("flows", "attributes")
            }
        }
        SignalType::Event => base("events", "attributes"),
        SignalType::State => base("states", "attributes"),
        SignalType::Log => {
            if serves_from_log_counts(q) {
                TablePlan {
                    table: "logs_counts_5m",
                    kind: TableKind::LogCounts,
                    signal: q.signal,
                    time_col: "bucket",
                    attr_map: "attributes",
                    stored_bucket_seconds: PREAGGREGATE_BUCKET_SECONDS,
                }
            } else {
                base("logs", "attributes")
            }
        }
        SignalType::Metric => match metric_rollup(q)? {
            None => base("metrics", "labels"),
            Some((table, bucket)) => {
                warnings.push(QueryWarning::Downsampled {
                    table: table.into(),
                    bucket_seconds: bucket,
                });
                TablePlan {
                    table,
                    kind: TableKind::MetricRollup,
                    signal: q.signal,
                    time_col: "bucket",
                    attr_map: "labels",
                    stored_bucket_seconds: bucket,
                }
            }
        },
    };

    Ok((plan, warnings))
}

/// W1 FIX 2. `logs_counts_5m` stores `(tenant_id, resource_id, severity, bucket)` and
/// nothing else, so it can answer the Explorer histogram and only the Explorer
/// histogram. Every condition below is a column that table does not have.
fn serves_from_log_counts(q: &Query) -> bool {
    let count_only = q.aggregations.len() == 1
        && matches!(
            q.aggregations[0],
            Aggregation {
                func: AggFunc::Count,
                field: None,
                ..
            }
        );
    if !count_only {
        return false;
    }

    let available = |f: &Field| match f {
        Field::ResourceId | Field::Severity => true,
        // A finer bucket than the stored one cannot be recovered by re-bucketing.
        Field::TimeBucket { seconds } => {
            *seconds >= PREAGGREGATE_BUCKET_SECONDS && seconds % PREAGGREGATE_BUCKET_SECONDS == 0
        }
        _ => false,
    };

    if !q.group_by.iter().all(available) {
        return false;
    }
    if let Some(f) = &q.filter {
        let mut fields = Vec::new();
        fields_of(f, &mut fields);
        if !fields.iter().all(available) {
            return false;
        }
    }
    q.order_by.iter().all(|s| match &s.key {
        SortKey::Field { field } => available(field),
        SortKey::Alias { .. } => true,
    })
}

/// The column a field names on a pre-aggregate.
///
/// Each of these tables was built to answer one shape of question, and holds only what
/// that shape needs — so the honest answer to anything else is that the column is not
/// there. Naming the *table* rather than the signal in the error is deliberate: "severity
/// is not available on `flows_5m`" tells an operator which table they landed on, which is
/// the thing they did not choose and cannot see.
fn preaggregate_column(f: &Field, p: &TablePlan) -> Result<Col> {
    match (p.kind, f) {
        // Not `(_, ResourceId)`: `service_5m` is keyed by service and has no host column,
        // so the blanket arm would have compiled to SQL naming a column that is not there.
        (
            TableKind::LogCounts | TableKind::MetricRollup | TableKind::FlowAggregate,
            Field::ResourceId,
        ) => Ok(Col::Plain("resource_id")),
        (TableKind::LogCounts, Field::Severity) => Ok(Col::Plain("severity")),
        (TableKind::MetricRollup, Field::Metric) => Ok(Col::Plain("metric")),

        // Exactly what `0008_spans.sql` gave `service_5m`. `errors` is absent here on
        // purpose: it is only ever an aggregation's field, and the compiler reads it
        // straight off the stored column without asking for a reference to it.
        (TableKind::ServiceAggregate, Field::ServiceId) => Ok(Col::Plain("service_id")),
        (TableKind::ServiceAggregate, Field::SpanName) => Ok(Col::Plain("name")),
        (TableKind::ServiceAggregate, Field::SpanKind) => Ok(Col::Plain("kind")),

        // Exactly the columns `0007_flows.sql` gave `flows_5m`, and no others.
        // `src_port` is deliberately absent — it is ephemeral, and the aggregate drops it
        // rather than carry one row per connection.
        (
            TableKind::FlowAggregate,
            Field::SrcAddress
            | Field::DstAddress
            | Field::DstPort
            | Field::Protocol
            | Field::SamplingRate
            | Field::Bytes
            | Field::Packets,
        ) => Ok(Col::Plain(match f {
            Field::SrcAddress => "src_address",
            Field::DstAddress => "dst_address",
            Field::DstPort => "dst_port",
            Field::Protocol => "protocol",
            Field::SamplingRate => "sampling_rate",
            Field::Bytes => "bytes",
            _ => "packets",
        })),

        // Re-bucketing rows that are already at the requested width is a function call
        // per row for no change in the result.
        (_, Field::TimeBucket { seconds }) if *seconds == p.stored_bucket_seconds => {
            Ok(Col::Plain(p.time_col))
        }
        (_, Field::TimeBucket { seconds }) => Ok(Col::Bucket {
            seconds: *seconds,
            base: p.time_col,
        }),
        (_, Field::ObservedAt) => Ok(Col::Plain(p.time_col)),

        _ => Err(Error::FieldNotAvailable {
            field: f.label(),
            signal: p.table,
        }),
    }
}

/// The `flows` column a flow-only field names, on a flow query.
///
/// `None` on any other signal, which the caller turns into the same
/// `FieldNotAvailable` every other mismatched field gets.
fn flow_column(f: &Field, signal: SignalType) -> Option<Col> {
    if signal != SignalType::Flow {
        return None;
    }
    Some(match f {
        Field::SrcAddress => Col::Plain("src_address"),
        Field::DstAddress => Col::Plain("dst_address"),
        Field::SrcPort => Col::Plain("src_port"),
        Field::DstPort => Col::Plain("dst_port"),
        Field::Protocol => Col::Plain("protocol"),
        Field::Bytes => Col::Plain("bytes"),
        Field::Packets => Col::Plain("packets"),
        Field::SamplingRate => Col::Plain("sampling_rate"),
        _ => return None,
    })
}

/// The `spans` column a trace-only field names, on a trace query.
///
/// `None` on any other signal, which the caller turns into the same `FieldNotAvailable`
/// every other mismatched field gets.
fn span_column(f: &Field, signal: SignalType) -> Option<Col> {
    if signal != SignalType::Trace {
        return None;
    }
    Some(match f {
        Field::ServiceId => Col::Plain("service_id"),
        Field::SpanName => Col::Plain("name"),
        Field::SpanKind => Col::Plain("kind"),
        Field::DurationNs => Col::Plain("duration_ns"),
        Field::StatusCode => Col::Plain("status_code"),
        Field::ParentSpanId => Col::Plain("parent_span_id"),
        Field::ScopeName => Col::Plain("scope_name"),
        // The derived one. `unset` is OTel's default and is not a failure, so this is an
        // equality against `error` and never `!= 'ok'` — the difference is every healthy
        // span in the estate.
        Field::Errors => Col::Expr("status_code = 'error'"),
        _ => return None,
    })
}

/// Whether `service_5m` can answer this, rather than the raw table.
///
/// The aggregate holds request count, error count and a latency state per service per
/// operation per five minutes — which is every question an APM screen asks, and nothing
/// else. Anything naming a trace, a host, a status or an individual duration is an
/// investigation and belongs on raw spans.
///
/// # The host is not in this table
///
/// `service_5m` is ordered `(tenant_id, service_id, name, kind, bucket)` and carries no
/// `resource_id`, because M8 §2.1 put the host in the *base* table's sort key and the
/// service in this one's. So a resource-scoped query cannot be served here at all, and
/// the refusal has to happen in the planner: by the time the compiler is writing
/// `resource_id IN (…)` it is too late, and the alternative — quietly answering a
/// host-scoped question with the whole tenant's traffic — is the kind of wrong that looks
/// right on a screen.
fn serves_from_service_5m(q: &Query, whole_tenant: bool) -> bool {
    if !q.is_aggregate() || !whole_tenant {
        return false;
    }

    // Three shapes, which are the three columns. A `sum(duration_ns)` is not among them:
    // the table stores a t-digest, and a total latency cannot be recovered from one.
    let servable = q.aggregations.iter().all(|a| {
        matches!(
            (a.func, &a.field),
            (AggFunc::Count, None)
                | (AggFunc::Sum, Some(Field::Errors))
                | (
                    AggFunc::P50 | AggFunc::P95 | AggFunc::P99,
                    Some(Field::DurationNs)
                )
        )
    });
    if !servable {
        return false;
    }

    let available = |f: &Field| match f {
        Field::ServiceId | Field::SpanName | Field::SpanKind => true,
        Field::TimeBucket { seconds } => {
            *seconds >= PREAGGREGATE_BUCKET_SECONDS && seconds % PREAGGREGATE_BUCKET_SECONDS == 0
        }
        _ => false,
    };

    if !q.group_by.iter().all(available) {
        return false;
    }

    if let Some(f) = &q.filter {
        let mut fields = Vec::new();
        fields_of(f, &mut fields);
        if !fields.iter().all(available) {
            return false;
        }
    }

    q.order_by.iter().all(|s| match &s.key {
        SortKey::Field { field } => available(field),
        SortKey::Alias { .. } => true,
    })
}

/// Whether `flows_5m` can answer this, rather than the raw table.
///
/// The aggregate holds sums per conversation per five minutes, so it serves the questions
/// every flow screen asks — top talkers, what changed, who is this host speaking to — and
/// nothing else. A query wanting a source port, a TCP flag or an individual conversation
/// is asking about *one* flow, which is an investigation and belongs on raw rows.
///
/// # `sampling_rate` is not optional here
///
/// A query that sums bytes across the aggregate without grouping by the rate adds numbers
/// measured 1-in-1000 to numbers measured 1-in-1. 0007 keeps the rate in the sort key so
/// the rows stay apart; this keeps them apart in the *answer*, by refusing to serve a
/// grouped sum that does not carry the rate through. Raw rows have the same problem and
/// the same fix, but there the caller can at least see every row's rate.
fn serves_from_flows_5m(q: &Query) -> bool {
    if !q.is_aggregate() {
        return false;
    }

    // Sums only. The aggregate stores `SimpleAggregateFunction(sum, …)`, so a max or a
    // quantile over it would be a max of sums — a different number wearing the right
    // name.
    let summable = q.aggregations.iter().all(|a| {
        matches!(
            (a.func, &a.field),
            (AggFunc::Count, None) | (AggFunc::Sum, Some(Field::Bytes | Field::Packets))
        )
    });
    if !summable {
        return false;
    }

    let available = |f: &Field| match f {
        Field::ResourceId
        | Field::SrcAddress
        | Field::DstAddress
        | Field::DstPort
        | Field::Protocol
        | Field::SamplingRate => true,
        Field::TimeBucket { seconds } => {
            *seconds >= PREAGGREGATE_BUCKET_SECONDS && seconds % PREAGGREGATE_BUCKET_SECONDS == 0
        }
        _ => false,
    };

    if !q.group_by.iter().all(available) {
        return false;
    }

    // Summing bytes without the rate in the grouping mixes differently-measured traffic.
    // §2.4, as a planner rule rather than a comment.
    let sums_counters = q
        .aggregations
        .iter()
        .any(|a| matches!(a.field, Some(Field::Bytes | Field::Packets)));
    let carries_rate = q.group_by.contains(&Field::SamplingRate)
        || q.filter.as_ref().is_some_and(|f| {
            let mut fields = Vec::new();
            fields_of(f, &mut fields);
            fields.contains(&Field::SamplingRate)
        });
    if sums_counters && !carries_rate {
        return false;
    }

    if let Some(f) = &q.filter {
        let mut fields = Vec::new();
        fields_of(f, &mut fields);
        if !fields.iter().all(available) {
            return false;
        }
    }

    q.order_by.iter().all(|s| match &s.key {
        SortKey::Field { field } => available(field),
        SortKey::Alias { .. } => true,
    })
}

/// Which metric rollup, if any. `None` means the raw table.
fn metric_rollup(q: &Query) -> Result<Option<(&'static str, u32)>> {
    // Rollups hold aggregate states, not points. A query asking for individual samples
    // can only be answered from raw rows, however wide its window is.
    if !q.is_aggregate() {
        return Ok(None);
    }

    let span = q.time.span();
    let (table, bucket) = if span <= RAW_METRIC_SPAN {
        return Ok(None);
    } else if span <= FIVE_MINUTE_SPAN {
        ("metrics_5m", 300)
    } else {
        ("metrics_1h", 3_600)
    };

    // AggregatingMergeTree stores the states that were declared in the materialised
    // view — min, max, avg, count. A sum cannot be recovered from an average without
    // the exact count per bucket, and a quantile cannot be recovered at all. Erroring
    // is the honest answer: the raw rows those need are past their TTL.
    for a in &q.aggregations {
        let ok = matches!(
            a.func,
            AggFunc::Count | AggFunc::Min | AggFunc::Max | AggFunc::Avg
        );
        if !ok {
            return Err(Error::RollupCannotServe {
                what: a.func.label().to_owned(),
                table,
                why: "the rollup stores min, max, avg and count states only; \
                      narrow the window to reach raw points",
            });
        }
    }

    // Labels are not carried into the rollup, by design — that is most of why it is
    // small enough to keep for three years.
    let mut referenced: Vec<Field> = q.group_by.clone();
    if let Some(f) = &q.filter {
        fields_of(f, &mut referenced);
    }
    for f in &referenced {
        let ok = matches!(
            f,
            Field::ResourceId | Field::Metric | Field::TimeBucket { .. }
        );
        if !ok {
            return Err(Error::RollupCannotServe {
                what: f.label(),
                table,
                why: "the rollup keeps resource, metric and bucket only; \
                      labels are dropped when points are aggregated",
            });
        }
    }

    Ok(Some((table, bucket)))
}

/// Resolve a field to a column on the planned table, or explain why it is not there.
pub(crate) fn column_of(f: &Field, p: &TablePlan, warnings: &mut Vec<QueryWarning>) -> Result<Col> {
    use SignalType as S;

    let unavailable = || {
        Err(Error::FieldNotAvailable {
            field: f.label(),
            signal: p.signal.as_str(),
        })
    };

    // A pre-aggregate holds a handful of columns and no more. Checked before the
    // per-signal mapping so the error names the real reason.
    if p.kind != TableKind::Base {
        return preaggregate_column(f, p);
    }

    Ok(match f {
        Field::ResourceId => Col::Plain("resource_id"),
        Field::SiteId => Col::Plain("site_id"),
        Field::ObservedAt => Col::Plain("observed_at"),
        Field::IngestedAt => Col::Plain("ingested_at"),
        Field::TimeBucket { seconds } => Col::Bucket {
            seconds: *seconds,
            base: p.time_col,
        },

        Field::Severity => match p.signal {
            S::Log | S::Event | S::State => Col::Plain("severity"),
            _ => return unavailable(),
        },
        Field::SourceKind => match p.signal {
            S::Log | S::Event => Col::Plain("source_kind"),
            _ => return unavailable(),
        },
        Field::SourceVendor => match p.signal {
            S::Log | S::Event => Col::Plain("source_vendor"),
            _ => return unavailable(),
        },
        // The two columns that exist on both signals, which is what makes correlation a
        // join rather than a second identity model — M8 §2.5. `logs.trace_id` has been
        // populated since M3; until M8 the other end of it was missing.
        Field::Facility | Field::Body | Field::TraceId | Field::SpanId => match (p.signal, f) {
            (S::Log, Field::Facility) => Col::Plain("facility"),
            (S::Log, Field::Body) => Col::Plain("body"),
            (S::Log | S::Trace, Field::TraceId) => Col::Plain("trace_id"),
            (S::Log | S::Trace, Field::SpanId) => Col::Plain("span_id"),
            _ => return unavailable(),
        },
        Field::Metric | Field::Value | Field::Unit => match (p.signal, f) {
            (S::Metric, Field::Metric) => Col::Plain("metric"),
            (S::Metric, Field::Value) => Col::Plain("value"),
            (S::Metric, Field::Unit) => Col::Plain("unit"),
            _ => return unavailable(),
        },

        Field::SrcAddress
        | Field::DstAddress
        | Field::SrcPort
        | Field::DstPort
        | Field::Protocol
        | Field::Bytes
        | Field::Packets
        | Field::SamplingRate => match flow_column(f, p.signal) {
            Some(c) => c,
            None => return unavailable(),
        },

        Field::ServiceId
        | Field::SpanName
        | Field::SpanKind
        | Field::DurationNs
        | Field::StatusCode
        | Field::ParentSpanId
        | Field::ScopeName
        | Field::Errors => match span_column(f, p.signal) {
            Some(c) => c,
            None => return unavailable(),
        },

        // A column of the rate subquery the compiler wraps the table in — see
        // `compile::rate_source`. It is only ever reachable on the base metrics table:
        // the branch above this one already refused every pre-aggregate, which is right,
        // because a rollup holds averages of a counter and the difference between two
        // averages is not a rate of anything.
        Field::Rate => match p.signal {
            S::Metric => Col::Plain("rate"),
            _ => return unavailable(),
        },
        Field::EventCategory | Field::EventType => match (p.signal, f) {
            (S::Event, Field::EventCategory) => Col::Plain("event_category"),
            (S::Event, Field::EventType) => Col::Plain("event_type"),
            _ => return unavailable(),
        },
        Field::PreviousStatus | Field::CurrentStatus => match (p.signal, f) {
            (S::State, Field::PreviousStatus) => Col::Plain("previous_status"),
            (S::State, Field::CurrentStatus) => Col::Plain("current_status"),
            _ => return unavailable(),
        },

        Field::Attr { key } => {
            if let Some(col) = materialised_column(key, p) {
                Col::Plain(col)
            } else {
                warnings.push(QueryWarning::AttributeNotMaterialised { key: key.clone() });
                Col::Attr {
                    map: p.attr_map,
                    key: key.clone(),
                }
            }
        }
    })
}

/// W1's expensive finding, in eight lines: a semconv key that the DDL materialises is a
/// real column, and must be read as one. The list lives in `uops_core` so that the
/// `ClickHouse` DDL and the query compiler cannot drift apart.
fn materialised_column(key: &str, p: &TablePlan) -> Option<&'static str> {
    // Only the log-shaped tables carry the MATERIALIZED columns; metric labels do not.
    if !matches!(p.signal, SignalType::Log | SignalType::Event) {
        return None;
    }
    match key {
        semconv::HOST_NAME => Some("host_name"),
        semconv::SERVICE_NAME => Some("service_name"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{CompareOp, Expr, TimeRange, Value};
    use chrono::{Duration, TimeZone, Utc};

    fn at(secs: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn logs(span: Duration) -> Query {
        Query::new(
            SignalType::Log,
            TimeRange::new(at(0), at(span.num_seconds())),
        )
    }

    fn count() -> Aggregation {
        Aggregation {
            func: AggFunc::Count,
            field: None,
            alias: "c".into(),
        }
    }

    #[test]
    fn the_explorer_histogram_is_answered_from_the_pre_aggregate() {
        // W1: this exact shape re-renders on every search and every filter change, and
        // the p_by_time projection does not help it. If this test goes red, the
        // Explorer has silently regressed to a 1-second full scan per keystroke.
        let mut q = logs(Duration::days(1));
        q.aggregations = vec![count()];
        q.group_by = vec![Field::TimeBucket { seconds: 300 }];

        let (p, _) = plan(&q, true).unwrap();
        assert_eq!(p.table, "logs_counts_5m");
        assert_eq!(p.kind, TableKind::LogCounts);
    }

    #[test]
    fn a_histogram_finer_than_the_stored_bucket_falls_back_to_raw() {
        let mut q = logs(Duration::hours(1));
        q.aggregations = vec![count()];
        q.group_by = vec![Field::TimeBucket { seconds: 60 }];
        assert_eq!(plan(&q, true).unwrap().0.table, "logs");
    }

    #[test]
    fn a_histogram_filtered_on_text_cannot_use_the_pre_aggregate() {
        // The counts table has no body column. Getting this wrong would not be slow,
        // it would be wrong: counts unfiltered by the user's search term.
        let mut q = logs(Duration::days(1));
        q.aggregations = vec![count()];
        q.group_by = vec![Field::TimeBucket { seconds: 300 }];
        q.filter = Some(Expr::Text {
            field: Field::Body,
            mode: crate::ast::TextMode::AnyToken,
            terms: vec!["bgp".into()],
        });
        assert_eq!(plan(&q, true).unwrap().0.table, "logs");
    }

    #[test]
    fn metric_rollup_follows_the_window() {
        let mut q = Query::new(SignalType::Metric, TimeRange::new(at(0), at(0)));
        q.aggregations = vec![Aggregation {
            func: AggFunc::Avg,
            field: Some(Field::Value),
            alias: "v".into(),
        }];

        for (span, table) in [
            (Duration::hours(1), "metrics"),
            (Duration::days(7), "metrics_5m"),
            (Duration::days(90), "metrics_1h"),
        ] {
            q.time = TimeRange::new(at(0), at(span.num_seconds()));
            assert_eq!(plan(&q, true).unwrap().0.table, table, "span {span}");
        }
    }

    #[test]
    fn downsampling_is_never_silent() {
        let mut q = Query::new(
            SignalType::Metric,
            TimeRange::new(at(0), at(Duration::days(7).num_seconds())),
        );
        q.aggregations = vec![Aggregation {
            func: AggFunc::Avg,
            field: Some(Field::Value),
            alias: "v".into(),
        }];
        let (_, warnings) = plan(&q, true).unwrap();
        assert!(
            warnings.contains(&QueryWarning::Downsampled {
                table: "metrics_5m".into(),
                bucket_seconds: 300,
            }),
            "a 5-minute average plotted as if it were raw is a misread graph: {warnings:?}"
        );
    }

    #[test]
    fn raw_points_over_a_long_window_stay_on_the_raw_table() {
        // Not aggregate: there is nothing to downsample to.
        let q = Query::new(
            SignalType::Metric,
            TimeRange::new(at(0), at(Duration::days(90).num_seconds())),
        );
        assert_eq!(plan(&q, true).unwrap().0.table, "metrics");
    }

    #[test]
    fn a_quantile_over_a_long_window_errors_instead_of_lying() {
        let mut q = Query::new(
            SignalType::Metric,
            TimeRange::new(at(0), at(Duration::days(90).num_seconds())),
        );
        q.aggregations = vec![Aggregation {
            func: AggFunc::P95,
            field: Some(Field::Value),
            alias: "p95".into(),
        }];
        let err = plan(&q, true).unwrap_err();
        assert!(
            matches!(err, Error::RollupCannotServe { .. }),
            "a p95 of hourly averages is not a p95: {err}"
        );
    }

    #[test]
    fn grouping_on_a_label_over_a_long_window_errors() {
        let mut q = Query::new(
            SignalType::Metric,
            TimeRange::new(at(0), at(Duration::days(90).num_seconds())),
        );
        q.aggregations = vec![Aggregation {
            func: AggFunc::Avg,
            field: Some(Field::Value),
            alias: "v".into(),
        }];
        q.group_by = vec![Field::Attr {
            key: "interface".into(),
        }];
        assert!(matches!(
            plan(&q, true).unwrap_err(),
            Error::RollupCannotServe { .. }
        ));
    }

    #[test]
    fn materialised_attributes_become_real_columns() {
        let (p, _) = plan(&logs(Duration::hours(1)), true).unwrap();
        let mut w = Vec::new();
        let col = column_of(
            &Field::Attr {
                key: "host.name".into(),
            },
            &p,
            &mut w,
        )
        .unwrap();
        assert_eq!(col, Col::Plain("host_name"));
        assert!(w.is_empty(), "a materialised column is not slow: {w:?}");
    }

    #[test]
    fn an_unmaterialised_attribute_is_allowed_but_flagged() {
        let (p, _) = plan(&logs(Duration::hours(1)), true).unwrap();
        let mut w = Vec::new();
        let col = column_of(
            &Field::Attr {
                key: "custom.tag".into(),
            },
            &p,
            &mut w,
        )
        .unwrap();
        assert!(matches!(col, Col::Attr { .. }));
        assert_eq!(w.len(), 1, "the 2 252 ms case must warn");
    }

    #[test]
    fn a_field_from_another_signal_is_rejected() {
        let (p, _) = plan(&logs(Duration::hours(1)), true).unwrap();
        let err = column_of(&Field::Value, &p, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, Error::FieldNotAvailable { .. }), "{err}");
    }

    // --- traces, M8 --------------------------------------------------------------
    //
    // This block used to be one test asserting that trace queries refused to compile,
    // the way flows did before M7.

    fn traces(span: Duration) -> Query {
        Query::new(
            SignalType::Trace,
            TimeRange::new(at(0), at(span.num_seconds())),
        )
    }

    fn counted(alias: &str) -> Aggregation {
        Aggregation {
            func: AggFunc::Count,
            field: None,
            alias: alias.into(),
        }
    }

    fn quantile(func: AggFunc, alias: &str) -> Aggregation {
        Aggregation {
            func,
            field: Some(Field::DurationNs),
            alias: alias.into(),
        }
    }

    /// The shape an APM screen asks: latency and volume per service per bucket.
    fn apm(span: Duration) -> Query {
        let mut q = traces(span);
        q.aggregations = vec![
            counted("requests"),
            sum(Field::Errors, "errors"),
            quantile(AggFunc::P99, "p99"),
        ];
        q.group_by = vec![Field::TimeBucket { seconds: 300 }, Field::ServiceId];
        q
    }

    #[test]
    fn a_trace_lookup_reads_the_raw_spans() {
        // "Show me this trace" is an investigation: it wants individual spans, and no
        // aggregate has them. §2.2 — and the bloom filter, not the planner, is what makes
        // it cheap.
        let mut q = traces(Duration::hours(1));
        q.filter = Some(Expr::Compare {
            field: Field::TraceId,
            cmp: CompareOp::Eq,
            value: Value::Str("4b".repeat(16)),
        });
        let (p, warnings) = plan(&q, true).unwrap();
        assert_eq!(p.table, "spans");
        assert_eq!(p.kind, TableKind::Base);
        assert!(warnings.is_empty());
    }

    #[test]
    fn the_apm_screen_is_answered_from_the_aggregate() {
        let (p, _) = plan(&apm(Duration::days(1)), true).unwrap();
        assert_eq!(p.table, "service_5m");
        assert_eq!(p.kind, TableKind::ServiceAggregate);
        assert_eq!(p.time_col, "bucket");
    }

    #[test]
    fn a_resource_scoped_trace_query_never_reaches_the_aggregate() {
        // The one that would have been a silent wrong answer. `service_5m` is ordered
        // service-first and carries no `resource_id` at all, so a host-scoped question
        // compiled against it would either name a column that is not there or — worse —
        // quietly answer with the whole tenant's traffic.
        let q = apm(Duration::days(1));
        let (p, _) = plan(&q, false).unwrap();
        assert_eq!(p.table, "spans", "a scoped query belongs on the raw table");
        assert_eq!(p.kind, TableKind::Base);
    }

    #[test]
    fn a_question_about_one_operations_status_reads_raw_spans() {
        // `status_code` is not a column on the aggregate — the view folded it into a
        // count of errors. Filtering on it is therefore a raw question.
        let mut q = apm(Duration::hours(1));
        q.filter = Some(Expr::Compare {
            field: Field::StatusCode,
            cmp: CompareOp::Eq,
            value: Value::Str("error".into()),
        });
        assert_eq!(plan(&q, true).unwrap().0.table, "spans");
    }

    #[test]
    fn a_percentile_the_state_does_not_hold_is_not_offered() {
        // The quantiles are part of the column's type. A p90 is not in the t-digest and
        // interpolating between p50 and p95 would be a number wearing a percentile's
        // name, so the query goes to raw spans where a real p90 can be computed.
        let mut q = apm(Duration::days(1));
        q.aggregations = vec![Aggregation {
            func: AggFunc::Avg,
            field: Some(Field::DurationNs),
            alias: "mean".into(),
        }];
        assert_eq!(
            plan(&q, true).unwrap().0.table,
            "spans",
            "an average is not recoverable from a t-digest"
        );
    }

    #[test]
    fn a_window_past_what_raw_spans_keep_is_said_out_loud() {
        // `spans` has a 7-day TTL, so a month-long raw query returns the last week and
        // looks like a month. The flow rule, and the same refusal to answer silently.
        let mut q = traces(Duration::days(30));
        q.filter = Some(Expr::Compare {
            field: Field::TraceId,
            cmp: CompareOp::Eq,
            value: Value::Str("4b".repeat(16)),
        });
        let (p, warnings) = plan(&q, true).unwrap();
        assert_eq!(p.table, "spans");
        assert!(
            matches!(
                warnings.as_slice(),
                [QueryWarning::BeyondRetention { days: 7, .. }]
            ),
            "{warnings:?}"
        );
    }

    #[test]
    fn the_aggregate_is_flagged_as_downsampled_past_the_raw_window() {
        let (p, warnings) = plan(&apm(Duration::days(30)), true).unwrap();
        assert_eq!(p.table, "service_5m");
        assert!(
            matches!(
                warnings.as_slice(),
                [QueryWarning::Downsampled {
                    bucket_seconds: 300,
                    ..
                }]
            ),
            "{warnings:?}"
        );
    }

    #[test]
    fn the_host_column_is_not_offered_on_the_service_aggregate() {
        // The blanket `resource_id` arm that every other pre-aggregate shares would have
        // compiled to SQL naming a column `service_5m` does not have.
        let (p, _) = plan(&apm(Duration::days(1)), true).unwrap();
        let err = column_of(&Field::ResourceId, &p, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, Error::FieldNotAvailable { .. }), "{err}");
    }

    #[test]
    fn a_spans_two_subjects_are_two_different_columns() {
        // §2.1 reaching the query layer: the host is `resource_id` and the service is
        // `service_id`, and a caller asking for one must never silently get the other.
        let (p, _) = plan(&traces(Duration::hours(1)), true).unwrap();
        let mut w = Vec::new();
        assert_eq!(
            column_of(&Field::ResourceId, &p, &mut w).unwrap(),
            Col::Plain("resource_id")
        );
        assert_eq!(
            column_of(&Field::ServiceId, &p, &mut w).unwrap(),
            Col::Plain("service_id")
        );
    }

    #[test]
    fn errors_are_the_same_question_on_both_tables() {
        // The field exists so that one query shape survives the choice of table. On raw
        // spans it compares against OTel's status; on the aggregate it is the column the
        // view maintains. `unset` is not an error on either — that is the comparison the
        // expression has to be, and `!= 'ok'` would make every healthy span a failure.
        let (raw, _) = plan(&traces(Duration::hours(1)), true).unwrap();
        assert_eq!(
            column_of(&Field::Errors, &raw, &mut Vec::new()).unwrap(),
            Col::Expr("status_code = 'error'")
        );

        // And on the aggregate it never becomes a column reference at all: the compiler
        // reads `errors` straight off the stored row.
        let (agg, _) = plan(&apm(Duration::days(1)), true).unwrap();
        assert!(column_of(&Field::Errors, &agg, &mut Vec::new()).is_err());
    }

    #[test]
    fn a_trace_field_on_another_signal_is_refused() {
        let (p, _) = plan(&logs(Duration::hours(1)), true).unwrap();
        for f in [Field::ServiceId, Field::DurationNs, Field::Errors] {
            let err = column_of(&f, &p, &mut Vec::new()).unwrap_err();
            assert!(
                matches!(err, Error::FieldNotAvailable { .. }),
                "{f:?}: {err}"
            );
        }
    }

    #[test]
    fn a_log_and_a_span_agree_on_what_a_trace_id_is() {
        // M8 §2.5: correlation is a join on a column both tables already have, not a
        // second identity model. `logs.trace_id` has been populated since M3.
        let (logs, _) = plan(&logs(Duration::hours(1)), true).unwrap();
        let (spans, _) = plan(&traces(Duration::hours(1)), true).unwrap();
        for p in [&logs, &spans] {
            assert_eq!(
                column_of(&Field::TraceId, p, &mut Vec::new()).unwrap(),
                Col::Plain("trace_id")
            );
        }
    }

    // --- flows, M7 ---------------------------------------------------------------

    fn flows(span: Duration) -> Query {
        Query::new(
            SignalType::Flow,
            TimeRange::new(at(0), at(span.num_seconds())),
        )
    }

    fn sum(field: Field, alias: &str) -> Aggregation {
        Aggregation {
            func: AggFunc::Sum,
            field: Some(field),
            alias: alias.into(),
        }
    }

    #[test]
    fn a_flow_query_for_individual_conversations_reads_the_raw_table() {
        // Not an aggregate, so nothing pre-aggregated can answer it: this is somebody
        // looking at the actual conversations in a minute, which is an investigation.
        let (p, _) = plan(&flows(Duration::hours(1)), true).unwrap();
        assert_eq!(p.table, "flows");
        assert_eq!(p.kind, TableKind::Base);
    }

    #[test]
    fn top_talkers_is_answered_from_the_aggregate() {
        // The shape every flow screen asks: bytes per conversation per bucket. Carrying
        // the sampling rate through is what makes the sum mean anything.
        let mut q = flows(Duration::days(1));
        q.aggregations = vec![sum(Field::Bytes, "b")];
        q.group_by = vec![
            Field::TimeBucket { seconds: 300 },
            Field::SrcAddress,
            Field::DstAddress,
            Field::SamplingRate,
        ];

        let (p, _) = plan(&q, true).unwrap();
        assert_eq!(p.table, "flows_5m");
        assert_eq!(p.kind, TableKind::FlowAggregate);
    }

    #[test]
    fn a_summed_flow_query_that_drops_the_sampling_rate_does_not_get_the_aggregate() {
        // §2.4 as a planner rule. Summing bytes across rows sampled 1-in-1000 and 1-in-1
        // gives a number that is neither an estimate nor a measurement, and the aggregate
        // is exactly where those rows sit side by side.
        let mut q = flows(Duration::days(1));
        q.aggregations = vec![sum(Field::Bytes, "b")];
        q.group_by = vec![Field::TimeBucket { seconds: 300 }, Field::SrcAddress];

        assert_eq!(plan(&q, true).unwrap().0.table, "flows");
    }

    #[test]
    fn counting_flows_needs_no_sampling_rate() {
        // A count of records is not a count of traffic, so mixing rates does not spoil
        // it. Only the byte and packet sums carry the hazard.
        let mut q = flows(Duration::days(1));
        q.aggregations = vec![count()];
        q.group_by = vec![Field::TimeBucket { seconds: 300 }, Field::DstPort];

        assert_eq!(plan(&q, true).unwrap().0.table, "flows_5m");
    }

    #[test]
    fn a_query_naming_the_source_port_stays_on_raw_rows() {
        // `src_port` is ephemeral and the aggregate drops it — see 0007. Asking for it
        // is asking about one connection, which raw rows answer.
        let mut q = flows(Duration::days(1));
        q.aggregations = vec![count()];
        q.group_by = vec![Field::TimeBucket { seconds: 300 }, Field::SrcPort];

        assert_eq!(plan(&q, true).unwrap().0.table, "flows");
    }

    #[test]
    fn a_bucket_finer_than_five_minutes_cannot_come_from_the_aggregate() {
        let mut q = flows(Duration::days(1));
        q.aggregations = vec![count()];
        q.group_by = vec![Field::TimeBucket { seconds: 60 }];

        assert_eq!(plan(&q, true).unwrap().0.table, "flows");
    }

    #[test]
    fn a_window_past_raw_retention_says_so_rather_than_answering_short() {
        // Raw flow keeps seven days. A month-long query that needs a raw-only column
        // gets the last week — which looks exactly like a quiet month unless somebody
        // says otherwise.
        let mut q = flows(Duration::days(30));
        q.aggregations = vec![count()];
        q.group_by = vec![Field::SrcPort];

        let (p, warnings) = plan(&q, true).unwrap();
        assert_eq!(p.table, "flows");
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, QueryWarning::BeyondRetention { .. })),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_long_window_the_aggregate_can_serve_is_downsampled_rather_than_truncated() {
        let mut q = flows(Duration::days(30));
        q.aggregations = vec![count()];
        q.group_by = vec![Field::TimeBucket { seconds: 300 }];

        let (p, warnings) = plan(&q, true).unwrap();
        assert_eq!(p.table, "flows_5m");
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, QueryWarning::Downsampled { .. })),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_flow_column_is_not_available_on_another_signal() {
        let (p, _) = plan(&logs(Duration::hours(1)), true).unwrap();
        for f in [Field::SrcAddress, Field::Bytes, Field::SamplingRate] {
            let err = column_of(&f, &p, &mut Vec::new()).unwrap_err();
            assert!(matches!(err, Error::FieldNotAvailable { .. }), "{err}");
        }
    }

    #[test]
    fn a_column_the_aggregate_dropped_is_refused_by_name() {
        let mut q = flows(Duration::days(1));
        q.aggregations = vec![count()];
        q.group_by = vec![Field::TimeBucket { seconds: 300 }];
        let (p, _) = plan(&q, true).unwrap();

        // The planner would not have chosen flows_5m for a query naming these, but the
        // mapping has to refuse them anyway: a caller reaching column_of directly must
        // not get a column that is not there.
        for f in [Field::SrcPort, Field::SiteId] {
            assert!(column_of(&f, &p, &mut Vec::new()).is_err(), "{f:?}");
        }
    }
}
