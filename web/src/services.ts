/**
 * The queries the services screen asks, and the honesty it has to carry.
 *
 * # A count of spans is not a count of requests
 *
 * `docs/M8-observability.md` §2.3, and the place this screen differs from every APM
 * product that draws a big number: traces are sampled *upstream of this product*. Head
 * sampling happens in the SDK and tail sampling in a collector, and a span that was not
 * sampled is simply **absent** — with nothing left behind to say so. There is no rate to
 * multiply by, the way flow has one.
 *
 * So the counts here are counts of sampled spans with an unknown denominator, and every
 * name in this file says so. `sampledRequests`, not `requests`. The API names its fields
 * the same way for the same reason: a field called `calls` is one a client renders as a
 * total without ever deciding to.
 *
 * # And a percentile *is* trustworthy
 *
 * The asymmetry is the useful part. A p99 over a sample is a good estimate of the p99
 * over everything, because a quantile is a property of the distribution and sampling
 * preserves the distribution. A count is a fraction of the truth.
 *
 * That is why the latency columns carry no qualifier and the count columns do. Marking
 * everything would tell a reader nothing; marking nothing would be the lie.
 */

import { api, request } from "./api";
import { runQuery, type Query, type ResultSet } from "./query";

/** How many services and how many edges the screen lists. */
export const TOP_N = 25;

/**
 * The slowest services in a window.
 *
 * Grouped by service alone, which is what lets the planner answer it from `service_5m`:
 * that table is ordered service-first and carries no `resource_id` at all, because a
 * service runs on many hosts. Adding a host to this grouping would move the query to raw
 * spans and answer a different question.
 */
export function serviceLatency(start: string, end: string, limit = TOP_N): Query {
  return {
    signal: "trace",
    time: { start, end },
    resources: { type: "all" },
    aggregations: [
      { func: "count", alias: "requests" },
      { func: "sum", field: { field: "errors" }, alias: "errors" },
      { func: "p50", field: { field: "duration_ns" }, alias: "p50" },
      { func: "p95", field: { field: "duration_ns" }, alias: "p95" },
      { func: "p99", field: { field: "duration_ns" }, alias: "p99" },
    ],
    group_by: [{ field: "service_id" }],
    order_by: [{ key: { by: "alias", alias: "p99" }, desc: true }],
    limit,
  };
}

/** One service, as the screen shows it. */
export interface ServiceRow {
  serviceId: string;
  /** Spans seen, which is not spans served. See the module docs. */
  sampledRequests: number;
  /** Of those, the ones whose `status_code` was `error`. `unset` is not a failure. */
  sampledErrors: number;
  p50Ns: number;
  p95Ns: number;
  p99Ns: number;
}

/** Column index by name, because the server sends rows as arrays and not objects. */
function indexer(result: ResultSet): (name: string) => number {
  const at = new Map(result.columns.map((c, i) => [c.name, i]));
  return (name) => at.get(name) ?? -1;
}

/**
 * Turn a result set into services.
 *
 * The grouped column comes back as `g0` — the compiler names them positionally — so this
 * has to match [`serviceLatency`]'s `group_by`, which is why the two are adjacent.
 */
export function services(result: ResultSet): ServiceRow[] {
  const index = indexer(result);
  const at = {
    service: index("g0"),
    requests: index("requests"),
    errors: index("errors"),
    p50: index("p50"),
    p95: index("p95"),
    p99: index("p99"),
  };
  // A column the query asked for and the server did not send means the two have drifted.
  // Nothing is the honest answer: a partial row would be one service's latency beside
  // another's count.
  if (Object.values(at).some((i) => i < 0)) return [];

  return result.rows.map((row) => ({
    serviceId: String(row[at.service] ?? ""),
    sampledRequests: number(row[at.requests]),
    sampledErrors: number(row[at.errors]),
    p50Ns: number(row[at.p50]),
    p95Ns: number(row[at.p95]),
    p99Ns: number(row[at.p99]),
  }));
}

/**
 * One directed call relationship, as `GET /api/v1/service-map` sends it.
 *
 * Mirrors `uops_api::routes::servicemap::EdgeView`, field for field and name for name.
 * The `sampled` prefixes are the server's, and keeping them here means a component
 * cannot render a total by reaching for a shorter name that does not exist.
 */
export interface Edge {
  from: string;
  to: string;
  sampled_calls: number;
  sampled_errors: number;
  p95_ns: number;
}

export interface ServiceMap {
  edges: Edge[];
  start: string;
  end: string;
  /** True when the map was cut off at the limit, so the picture is the busiest part. */
  truncated: boolean;
}

export function fetchServiceMap(
  tenant: string,
  start: string,
  end: string,
  limit = TOP_N,
): Promise<ServiceMap> {
  const query = new URLSearchParams({ start, end, limit: String(limit) });
  return request<ServiceMap>(`/api/v1/service-map?${query.toString()}`, { tenant });
}

/**
 * The share of sampled spans that failed, or `null` when nothing was sampled.
 *
 * `null` rather than 0: a service with no spans in the window has no error rate, and
 * showing 0% would say it was healthy when what happened is that nobody asked it
 * anything.
 *
 * # This ratio is safer than the counts and not as safe as the percentiles
 *
 * A ratio of two sampled counts estimates the true ratio *only if the sampling did not
 * care which spans failed*. Head sampling does not care, so it holds. Tail samplers
 * routinely keep every error on purpose — it is the sensible thing for them to do — and
 * under one of those this is an over-estimate, sometimes a large one.
 *
 * Nothing in the payload says which was used. Inventing a correction would be worse than
 * saying so, so the screen shows the rate and says what it is a rate over.
 */
export function errorRate(row: {
  sampledRequests: number;
  sampledErrors: number;
}): number | null {
  if (row.sampledRequests <= 0) return null;
  return row.sampledErrors / row.sampledRequests;
}

/** A rate, as a percentage a person reads. */
export function humanPercent(rate: number): string {
  if (rate <= 0) return "0%";
  // One failure in ten thousand is not 0%, and printing it as 0% is the difference
  // between a service that is fine and one that is quietly dropping requests.
  if (rate < 0.001) return "<0.1%";
  return `${(rate * 100).toFixed(rate < 0.1 ? 1 : 0)}%`;
}

/**
 * A duration, as a person reads it.
 *
 * Nanoseconds is what OTLP carries and what the column stores, and nobody reads
 * nanoseconds. The unit is chosen per value rather than per column, because a service
 * map mixes a 200-microsecond cache lookup with a two-second report and one shared unit
 * makes one of them unreadable.
 */
export function humanDuration(ns: number): string {
  if (!Number.isFinite(ns) || ns <= 0) return "0 ms";
  if (ns < 1_000) return `${Math.round(ns)} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(ns < 10_000 ? 1 : 0)} µs`;
  if (ns < 1_000_000_000) return `${(ns / 1_000_000).toFixed(ns < 10_000_000 ? 1 : 0)} ms`;
  return `${(ns / 1_000_000_000).toFixed(1)} s`;
}

/** The count, grouped with thousands separators. */
export function humanCount(value: number): string {
  return value.toLocaleString("en-GB");
}

/**
 * A number, however `ClickHouse` chose to encode it.
 *
 * 64-bit integers arrive quoted when `output_format_json_quote_64bit_integers` is on, and
 * a nanosecond duration is exactly the column where that matters.
 */
function number(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

/**
 * What to call a service, given what the inventory knows.
 *
 * A service is a resource like any other, so it has a name — but a span carries an id and
 * the inventory is a separate read, so the two can disagree for as long as it takes one
 * to arrive. When they do, this shows the id rather than a placeholder: the context bar
 * made the same choice in §13, because "Unknown service" is a claim and an id is a fact
 * somebody can paste into a search.
 */
export function serviceName(id: string, names: Map<string, string>): string {
  return names.get(id) ?? id;
}

/** Names for the services the inventory knows about. */
export async function serviceNames(tenant: string): Promise<Map<string, string>> {
  const page = await api.resources(tenant, { kind: "service", limit: "200" });
  return new Map(page.items.map((r) => [r.id, r.display_name || r.name]));
}

export { runQuery };
