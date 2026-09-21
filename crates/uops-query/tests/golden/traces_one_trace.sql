SELECT tenant_id, resource_id, service_id, site_id, observed_at, ingested_at, trace_id, span_id, parent_span_id, name, kind, duration_ns, status_code, status_message, sampling_probability, scope_name, attributes FROM spans WHERE tenant_id = {p0:UUID} AND observed_at >= {p1:DateTime64(3, 'UTC')} AND observed_at < {p2:DateTime64(3, 'UTC')} AND trace_id = {p3:String} ORDER BY observed_at ASC LIMIT 500

-- params
--   p0 UUID = 018f0000-0000-7000-8000-000000000001
--   p1 DateTime64(3, 'UTC') = 2026-09-01 00:00:00.000
--   p2 DateTime64(3, 'UTC') = 2026-09-01 01:00:00.000
--   p3 String = 4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b

-- table: spans
-- warnings:
--   this reads every resource in the tenant; narrowing to a resource is much faster
