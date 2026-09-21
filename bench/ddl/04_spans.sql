-- M8 §2.2 and §2.6 — the table whose two bets need measuring.
--
-- Column for column and index for index, this is `ch-migrations/0008_spans.sql`. It has
-- to be: what is being measured is whether a bloom filter on `trace_id` can find one
-- trace when the sort key leads with the resource, and a benchmark against a table with
-- a different index measures a different product.
--
-- The `service_5m` materialised view is deliberately **absent**. Neither measurement
-- reads it, and attaching it would make the load slower for no gain — the ingest cost of
-- the view is a separate question from the read cost of the two queries.

CREATE DATABASE IF NOT EXISTS bench;

CREATE TABLE IF NOT EXISTS bench.spans
(
    tenant_id       UUID,
    resource_id     UUID,
    service_id      UUID,
    site_id         UUID,

    observed_at     DateTime64(3, 'UTC'),
    ingested_at     DateTime64(3, 'UTC'),

    trace_id        String,
    span_id         String,
    parent_span_id  String,
    name            LowCardinality(String),
    kind            LowCardinality(String),
    duration_ns     UInt64,
    status_code     LowCardinality(String),
    status_message  String,
    sampling_probability Float32,
    scope_name      LowCardinality(String),
    attributes      Map(LowCardinality(String), String),

    -- `bloom_filter(0.001)` and not a bare `bloom_filter`, which takes ClickHouse's
    -- default false-positive rate of 0.025. Measuring the difference is what this table
    -- exists for, and the result became `ch-migrations/0009_spans_trace_index.sql`:
    -- 827 392 rows read at the default, 73 728 at 0.001, for 1% more storage.
    --
    -- The recorded run in bench/results/ measured both, by adding the second index and
    -- pointing `ignore_data_skipping_indices` at one or the other.
    INDEX idx_trace trace_id TYPE bloom_filter(0.001) GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (tenant_id, resource_id, observed_at)
-- No TTL. The benchmark table is loaded once and read many times; a `DELETE` TTL would
-- remove the fixtures out from under a run, which is how three tests in this repo have
-- already failed intermittently.
SETTINGS index_granularity = 8192;
