-- 0007 — flows, and the five-minute aggregate. M7, `docs/M7-flow.md` §2.4 and §2.5.
--
-- Promoted from `deferred/`, where it was declared in M0 to settle the sort key and the
-- tenant column before anything was written against them. Two things it got wrong are
-- corrected here, and both are corrections the spec asked for by name.
--
-- **It had no sampling column.** §2.4: sFlow is sampled by definition and NetFlow can be,
-- so a flow's counters stand for `sampling_rate` times as much traffic as they say. The
-- rate is stored beside the counts and the multiplication happens at query time —
-- pre-multiplying cannot be undone, and it launders an estimate into something no screen
-- downstream can tell from a measurement.
--
-- **Its raw retention was thirty days**, copied from the same file's `traces`. §2.5: flow
-- is the highest-volume signal this product ingests, and a busy edge router emits tens of
-- thousands of records a second, none interesting on its own. Raw keeps days and answers
-- "show me the actual conversations in this minute", which is an investigation;
-- the aggregate keeps the long window and answers everything on a screen.
--
-- The retentions below are provisional. §2.5 says the numbers are to be picked with a
-- measurement rather than an opinion, and W1's method is the one to copy; seven days and a
-- year are a defensible starting point and not a measured one.

CREATE TABLE IF NOT EXISTS flows
(
    tenant_id        UUID,
    resource_id      UUID,       -- the exporter
    site_id          UUID,
    -- When the flow ended, and when it began. Both, because a flow has a duration and
    -- the decoders already recover it: `observed_at` alone cannot tell a one-second
    -- burst from an hour-long transfer of the same size.
    observed_at      DateTime64(3, 'UTC'),
    started_at       DateTime64(3, 'UTC'),
    ingested_at      DateTime64(3, 'UTC'),

    src_address      IPv6,       -- IPv4 is stored mapped; one column, both families
    dst_address      IPv6,
    src_port         UInt16,
    dst_port         UInt16,
    protocol         UInt8,

    -- As observed. Never scaled — see the header, and §2.4.
    bytes            UInt64,
    packets          UInt64,
    -- One in how many packets was sampled. 1 means "not sampled", which for an exporter
    -- that never mentions sampling is an assumption rather than a statement; the decoder
    -- counts those separately so the collector can say which it was.
    sampling_rate    UInt32,

    tcp_flags        UInt16,
    tos              UInt8,

    -- `ifIndex` as the exporter numbers them, which is the numbering SNMP uses — so
    -- these join to interfaces discovery already found. Nullable because 0 is a
    -- legitimate ifIndex and a legitimate AS number, and a column that cannot tell
    -- "not reported" from "reported as zero" will eventually be drawn as if it could.
    input_if         Nullable(UInt32),
    output_if        Nullable(UInt32),
    src_as           Nullable(UInt32),
    dst_as           Nullable(UInt32),

    -- Resolved endpoints, when identity can place them. The nil UUID is "not placed",
    -- which is the convention `site_id` already uses on every telemetry table — and it
    -- is the common case rather than a gap: every flow to the internet has one.
    src_resource_id  UUID,
    dst_resource_id  UUID,

    attributes       Map(LowCardinality(String), String)
)
ENGINE = MergeTree
-- Daily, which with a seven-day TTL is seven partitions and makes expiry a file drop
-- rather than a merge.
PARTITION BY toYYYYMMDD(observed_at)
-- SPEC's Investigation Workspace decision, identical on every telemetry table: "all
-- signals for resource R in window W" is one contiguous range read. Changing it is a full
-- re-ingest rather than a migration.
ORDER BY (tenant_id, resource_id, observed_at)
TTL toDateTime(observed_at) + INTERVAL 7 DAY DELETE;

-- The aggregate every screen actually reads: top talkers, what changed, who is this host
-- speaking to.
--
-- # Why `sampling_rate` is in the key
--
-- This is the part that would be silently wrong without thinking about it. Summing bytes
-- across rows sampled at different rates produces a number that means nothing — one
-- exporter at 1-in-1000 and another at 1-in-1 added together is neither an estimate nor a
-- measurement. Keeping the rate in the sort key means every row aggregates only over
-- traffic sampled the same way, so `sum(bytes) * sampling_rate` is a coherent estimate and
-- the reader still does the multiplying.
--
-- An exporter that changes its rate mid-window therefore produces two rows for the same
-- conversation. That is correct rather than a defect: they are two differently-measured
-- things and adding them would be the error this avoids.
--
-- # Why `src_port` is not in the key
--
-- It is ephemeral. A client picks a random high port per connection, so including it would
-- give one row per connection and an aggregate the size of the raw table. `dst_port` is
-- the one that names a service, and it is the one every question asks about.
CREATE TABLE IF NOT EXISTS flows_5m
(
    tenant_id       UUID,
    resource_id     UUID,
    bucket          DateTime('UTC'),
    src_address     IPv6,
    dst_address     IPv6,
    dst_port        UInt16,
    protocol        UInt8,
    sampling_rate   UInt32,

    -- `SimpleAggregateFunction` rather than `AggregateFunction`, unlike `metrics_5m`:
    -- every aggregate here is a sum, and a sum needs no intermediate state. The reader
    -- writes `sum(bytes)` rather than `sumMerge(bytes)`, and the stored bytes are the
    -- values themselves.
    bytes           SimpleAggregateFunction(sum, UInt64),
    packets         SimpleAggregateFunction(sum, UInt64),
    -- How many raw flow records went into this row. The denominator for anything that
    -- wants an average, and the honest answer to "how much was this built from".
    records         SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket)
-- Time first, which is the opposite of the base table and is the whole point of this one
-- existing: every question it answers starts with a window and then asks what was in it.
-- The same reasoning `logs_counts_5m` records.
ORDER BY (tenant_id, bucket, resource_id, src_address, dst_address, dst_port, protocol, sampling_rate)
TTL bucket + INTERVAL 365 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_5m_mv TO flows_5m AS
SELECT
    tenant_id,
    resource_id,
    toStartOfFiveMinute(observed_at) AS bucket,
    src_address,
    dst_address,
    dst_port,
    protocol,
    sampling_rate,
    sum(bytes)   AS bytes,
    sum(packets) AS packets,
    count()      AS records
FROM flows
GROUP BY
    tenant_id,
    resource_id,
    bucket,
    src_address,
    dst_address,
    dst_port,
    protocol,
    sampling_rate;
