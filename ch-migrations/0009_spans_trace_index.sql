-- 0009 — the trace lookup's bloom filter, with its false-positive rate chosen.
--
-- `0008_spans.sql` declared `INDEX idx_trace trace_id TYPE bloom_filter GRANULARITY 1`
-- and `docs/M8-observability.md` §2.2 attached an obligation to it: *"It must be measured
-- rather than assumed. The number to record is granules read for a single-trace lookup at
-- 100M spans."*
--
-- It was measured. `bench/results/m8-spans-100000000rows.md` has the run; the finding is
-- that the bet was right and the *parameter* was never chosen.
--
-- `bloom_filter` with no argument takes ClickHouse's default false-positive rate of
-- **0.025**. At 100M spans that leaves a single-trace lookup reading 827 392 rows to find
-- five, because one granule in forty survives the filter by accident. At 0.001 it reads
-- 73 728 — eleven times fewer, and twice as fast:
--
--   | index                     | rows read  | ms   |
--   |---------------------------|-----------:|-----:|
--   | none                      | 33 447 936 | 2015 |
--   | bloom_filter (default)    |    827 392 |  108 |
--   | bloom_filter(0.001)       |     73 728 |   49 |
--
-- The cost is 83 MiB on an 8.26 GiB table — **one per cent of the data** for an order of
-- magnitude on the query the table exists to answer. That is not a close call, and the
-- only reason it was not made in 0008 is that nobody had looked at what the default was.
--
-- # Why this is a new migration rather than an edit to 0008
--
-- Migrations are checksummed and immutable once applied. Editing 0008 would change its
-- checksum and every installation that already ran it would refuse to start — which is
-- the rule working, not the rule getting in the way.
--
-- # What this does to an existing table
--
-- `DROP INDEX` removes the index files; `ADD INDEX` declares the new one; `MATERIALIZE`
-- builds it over the parts that already exist. On a table with 100M rows the rebuild took
-- 17 seconds and touched no data column — a skip index is small and built from one
-- column. New inserts carry it from the moment it is declared.

ALTER TABLE spans DROP INDEX IF EXISTS idx_trace;

ALTER TABLE spans ADD INDEX idx_trace trace_id TYPE bloom_filter(0.001) GRANULARITY 1;

ALTER TABLE spans MATERIALIZE INDEX idx_trace SETTINGS mutations_sync = 2;
