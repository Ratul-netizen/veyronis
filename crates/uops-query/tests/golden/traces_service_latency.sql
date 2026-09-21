SELECT bucket AS g0, service_id AS g1, name AS g2, sum(requests) AS requests, sum(errors) AS errors, quantilesTDigestMerge(0.5, 0.95, 0.99)(latency)[1] AS p50, quantilesTDigestMerge(0.5, 0.95, 0.99)(latency)[3] AS p99 FROM service_5m WHERE tenant_id = {p0:UUID} AND bucket >= {p1:DateTime64(3, 'UTC')} AND bucket < {p2:DateTime64(3, 'UTC')} GROUP BY g0, g1, g2 ORDER BY p99 DESC LIMIT 50

-- params
--   p0 UUID = 018f0000-0000-7000-8000-000000000001
--   p1 DateTime64(3, 'UTC') = 2026-09-01 00:00:00.000
--   p2 DateTime64(3, 'UTC') = 2026-09-08 00:00:00.000

-- table: service_5m
-- warnings: none
