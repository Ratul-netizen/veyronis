-- DECLARED, NOT CREATED. M8 (traces).
--
-- Kept here so that the sort key, the tenant column and the attribute shape are settled
-- before anything is written against them — the same reason the traits exist in
-- uops-core and the signal variants exist in the Query AST.
--
-- `flows` used to live in this file. It left for `0007_flows.sql` when M7 built the
-- decoders that fill it, which is what `README.md` here says is meant to happen. Two
-- things about it were wrong on the way out, and both are worth knowing before this one
-- is promoted in its turn:
--
--   * it had no column for the sampling rate, without which its byte counts are wrong by
--     whatever factor the exporter was sampling at;
--   * it carried this file's thirty-day retention, which is right for traces and much too
--     long for the highest-volume signal in the product.
--
-- Neither was a typo. They are what happens when a shape is declared before the thing
-- that fills it exists — which is the price of declaring early, and still cheaper than
-- discovering the sort key was wrong after ingest. Read this table with the same
-- suspicion when M8 comes to promote it.

CREATE TABLE IF NOT EXISTS traces
(
    tenant_id     UUID,
    resource_id   UUID,
    site_id       UUID,
    observed_at   DateTime64(3, 'UTC'),
    ingested_at   DateTime64(3, 'UTC'),
    trace_id      String,
    span_id       String,
    parent_span_id String,
    name          LowCardinality(String),
    kind          LowCardinality(String),
    duration_ns   UInt64,
    status_code   LowCardinality(String),
    attributes    Map(LowCardinality(String), String),

    -- Trace lookup is by trace_id, which the sort key cannot serve: it leads with
    -- resource. A skip index is the difference between a lookup and a tenant scan.
    INDEX idx_trace trace_id TYPE bloom_filter GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (tenant_id, resource_id, observed_at)
TTL toDateTime(observed_at) + INTERVAL 30 DAY DELETE;
