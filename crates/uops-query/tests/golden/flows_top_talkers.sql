SELECT bucket AS g0, src_address AS g1, dst_address AS g2, sampling_rate AS g3, sum(bytes) AS bytes FROM flows_5m WHERE tenant_id = {p0:UUID} AND bucket >= {p1:DateTime64(3, 'UTC')} AND bucket < {p2:DateTime64(3, 'UTC')} GROUP BY g0, g1, g2, g3 ORDER BY bytes DESC LIMIT 50

-- params
--   p0 UUID = 018f0000-0000-7000-8000-000000000001
--   p1 DateTime64(3, 'UTC') = 2026-09-01 00:00:00.000
--   p2 DateTime64(3, 'UTC') = 2026-09-02 00:00:00.000

-- table: flows_5m
-- warnings: none
