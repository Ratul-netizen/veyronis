SELECT name AS g0, count() AS spans, quantile(0.95)(duration_ns) AS p95 FROM spans WHERE tenant_id = {p0:UUID} AND observed_at >= {p1:DateTime64(3, 'UTC')} AND observed_at < {p2:DateTime64(3, 'UTC')} AND resource_id IN ({p3:UUID}) AND status_code = {p4:String} GROUP BY g0 ORDER BY p95 DESC LIMIT 20

-- params
--   p0 UUID = 018f0000-0000-7000-8000-000000000001
--   p1 DateTime64(3, 'UTC') = 2026-09-01 00:00:00.000
--   p2 DateTime64(3, 'UTC') = 2026-09-01 06:00:00.000
--   p3 UUID = 018f0000-0000-7000-8000-0000000000aa
--   p4 String = error

-- table: spans
-- warnings: none
