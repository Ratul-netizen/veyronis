SELECT tenant_id, resource_id, site_id, observed_at, started_at, ingested_at, src_address, dst_address, src_port, dst_port, protocol, bytes, packets, sampling_rate, tcp_flags, tos, input_if, output_if, src_as, dst_as, src_resource_id, dst_resource_id, attributes FROM flows WHERE tenant_id = {p0:UUID} AND observed_at >= {p1:DateTime64(3, 'UTC')} AND observed_at < {p2:DateTime64(3, 'UTC')} AND dst_port = {p3:Int64} ORDER BY resource_id ASC, observed_at DESC LIMIT 200

-- params
--   p0 UUID = 018f0000-0000-7000-8000-000000000001
--   p1 DateTime64(3, 'UTC') = 2026-09-01 00:00:00.000
--   p2 DateTime64(3, 'UTC') = 2026-09-01 01:00:00.000
--   p3 Int64 = 443

-- table: flows
-- warnings:
--   this reads every resource in the tenant; narrowing to a resource is much faster
