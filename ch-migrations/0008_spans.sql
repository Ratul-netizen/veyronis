-- 0008 — spans, and the per-service aggregate. M8, `docs/M8-observability.md`.
--
-- Promoted from `deferred/traces.sql`, read with the suspicion that file's own header
-- asks for after what promoting `flows` turned up. It was right about the sort key and
-- the bloom filter, and short of three things §2 names.
--
-- **The table is `spans`, not `traces`.** A row here is one span; a trace is the set of
-- them sharing a `trace_id` and is never a row anywhere. SPEC had this right in M0 when
-- it declared `TraceStore` taking `SpanRow`, and renaming costs nothing before anything
-- exists.

CREATE TABLE IF NOT EXISTS spans
(
    tenant_id       UUID,
    -- §2.1, and the decision with no second chance. `resource_id` is the **host**,
    -- because the sort key leads with it and SPEC's Investigation Workspace promise is
    -- that all signals for one resource in one window are a contiguous range read — a
    -- span keyed by service would stop sitting beside the logs and metrics of the machine
    -- it ran on.
    resource_id     UUID,
    -- And the service, because "the checkout service's p99" is the question APM exists
    -- for and one service runs on many hosts. Reached through `service_5m`, which is
    -- ordered service-first for exactly that reason.
    service_id      UUID,
    site_id         UUID,

    -- A span is an interval, and this is its start: the instant the work began, which is
    -- what `duration_ns` is measured from and what sorting by time should mean.
    observed_at     DateTime64(3, 'UTC'),
    ingested_at     DateTime64(3, 'UTC'),

    trace_id        String,
    span_id         String,
    parent_span_id  String,
    -- The operation. `LowCardinality` because a service has tens of operations and
    -- millions of spans, which is exactly the shape that dictionary encoding is for.
    name            LowCardinality(String),
    -- server | client | internal | producer | consumer
    kind            LowCardinality(String),
    duration_ns     UInt64,
    -- unset | ok | error
    status_code     LowCardinality(String),
    status_message  String,

    -- §2.3. The probability the exporter said it sampled at, or 0 for "it did not say".
    --
    -- Stored and never applied. Flow could multiply its counts up because sFlow states
    -- its rate reliably; tracing cannot, because head sampling happens in the SDK and
    -- tail sampling in a collector and an unsampled span is simply absent. A screen may
    -- show this number; nothing may extrapolate from it.
    sampling_probability Float32,

    -- The instrumentation library. Kept because "only the gRPC instrumentation is slow"
    -- is a real diagnosis and it is unreachable if the scope is flattened away.
    scope_name      LowCardinality(String),
    attributes      Map(LowCardinality(String), String),

    -- §2.2. The sort key leads with the resource, so it cannot find one trace whose spans
    -- are scattered across a dozen services on as many hosts — and that lookup is the
    -- commonest thing anybody asks of this table. A bloom filter prunes granules so the
    -- lookup reads a handful rather than the tenant.
    --
    -- This is a bet, and §2.2 says it has to be *measured* at scale rather than assumed.
    -- If it disappoints, the fallback is a trace_id-ordered projection, which is the same
    -- shape W1 added to `logs` for the tail and costs storage the same way.
    INDEX idx_trace trace_id TYPE bloom_filter GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (tenant_id, resource_id, observed_at)
-- §2.4, and the `flows` lesson: the deferred file said 30 days, which is right for
-- something low-volume and wrong for this. Raw spans answer "show me this trace", which
-- is an investigation and therefore recent. Provisional, like flow's — a number to settle
-- with a measurement.
TTL toDateTime(observed_at) + INTERVAL 7 DAY DELETE;

-- What every APM screen reads: how many requests, how many failed, and how slow.
--
-- # Why latency is a state and not a number
--
-- A p99 cannot be summed, averaged or re-bucketed — a p99 of p99s is not a p99. So the
-- column holds a t-digest *state*, merged at read time, exactly as `metrics_5m` stores
-- `avgState` rather than an average. The quantiles are fixed in the type: adding one
-- later is a new column, because the state's shape is part of its type.
--
-- # Why this is ordered service-first
--
-- The opposite of `spans`, and deliberately. Every question here begins with a service —
-- "is checkout slower than last week" — where the base table's questions begin with a
-- host. That is the same reasoning `logs_counts_5m` records for being ordered time-first
-- while `logs` is ordered resource-first.
CREATE TABLE IF NOT EXISTS service_5m
(
    tenant_id   UUID,
    service_id  UUID,
    name        LowCardinality(String),
    kind        LowCardinality(String),
    bucket      DateTime('UTC'),

    requests    SimpleAggregateFunction(sum, UInt64),
    errors      SimpleAggregateFunction(sum, UInt64),
    latency     AggregateFunction(quantilesTDigest(0.5, 0.95, 0.99), UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket)
ORDER BY (tenant_id, service_id, name, kind, bucket)
TTL bucket + INTERVAL 365 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS service_5m_mv TO service_5m AS
SELECT
    tenant_id,
    service_id,
    name,
    kind,
    toStartOfFiveMinute(observed_at) AS bucket,
    count() AS requests,
    -- `status_code` is OTel's, where `error` is the only value that means failure:
    -- `unset` is the default a span carries when nothing went wrong and nobody said so,
    -- and counting it as an error would make every healthy service look broken.
    countIf(status_code = 'error') AS errors,
    quantilesTDigestState(0.5, 0.95, 0.99)(duration_ns) AS latency
FROM spans
GROUP BY tenant_id, service_id, name, kind, bucket;
