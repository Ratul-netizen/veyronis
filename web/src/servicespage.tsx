/**
 * Services — how slow, how often it fails, and what calls what.
 *
 * Two tables. The first is the APM question: which services are slow, read from
 * `service_5m`. The second is the service map, which is not a diagram here but a list of
 * edges — a force-directed graph of forty services is a picture of a hairball, and the
 * question during an incident is *which* call is failing, which a sorted table answers
 * and a drawing does not.
 *
 * # Every count on this screen says it is a sample
 *
 * `docs/M8-observability.md` §2.3, and the reason this file exists in the shape it does.
 * Traces are sampled upstream of this product: head sampling in the SDK, tail sampling in
 * a collector, and an unsampled span is simply *absent*. Flow could multiply its counts
 * up because sFlow states its rate; there is no rate here to multiply by.
 *
 * So the count columns are headed "sampled" and carry a footnote, and the latency columns
 * carry neither — because a percentile over a sample really is an estimate of the
 * percentile over everything, and marking it would teach a reader to distrust the one
 * number they can rely on. UI-SPEC: the product may visualise backend truth and may not
 * invent it. An unqualified "1,204 requests" would be inventing it.
 */

import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";

import { message } from "./query";
import {
  errorRate,
  fetchServiceMap,
  humanCount,
  humanDuration,
  humanPercent,
  runQuery,
  serviceLatency,
  serviceName,
  serviceNames,
  services,
  TOP_N,
} from "./services";
import { describeRange, resolveRange, useShell } from "./shell";

export function ServicesPage() {
  const { tenant, range } = useShell();

  const window = useMemo(() => resolveRange(range), [range]);
  const query = useMemo(
    () =>
      window
        ? serviceLatency(window.from.toISOString(), window.to.toISOString(), TOP_N)
        : null,
    [window],
  );

  const latency = useQuery({
    queryKey: ["services", tenant.tenant_id, JSON.stringify(query)],
    queryFn: () => runQuery(tenant.tenant_id, query!),
    enabled: query !== null,
    retry: false,
    staleTime: 30_000,
  });

  const map = useQuery({
    queryKey: [
      "service-map",
      tenant.tenant_id,
      window?.from.toISOString(),
      window?.to.toISOString(),
    ],
    queryFn: () =>
      fetchServiceMap(
        tenant.tenant_id,
        window!.from.toISOString(),
        window!.to.toISOString(),
        TOP_N,
      ),
    enabled: window !== null,
    retry: false,
    staleTime: 30_000,
  });

  // The inventory, for names. A separate read from a separate plane, so it can be absent
  // or stale for a moment — which is why `serviceName` falls back to the id rather than
  // to a placeholder.
  const names = useQuery({
    queryKey: ["service-names", tenant.tenant_id],
    queryFn: () => serviceNames(tenant.tenant_id),
    retry: false,
    staleTime: 60_000,
  });
  const naming = names.data ?? new Map<string, string>();

  const rows = useMemo(
    () => (latency.data ? services(latency.data) : []),
    [latency.data],
  );
  const edges = map.data?.edges ?? [];

  if (!window) {
    return (
      <div className="problem" role="alert">
        {describeRange(range)} is not a range this can read.
      </div>
    );
  }

  return (
    <>
      <h1>Services</h1>

      {latency.isPending && <p className="dim">Loading…</p>}

      {latency.isError && (
        <div className="problem" role="alert">
          {message(latency.error)}
        </div>
      )}

      {latency.data?.warnings.map((w) => (
        <div key={w.message} className="notice" role="status">
          {w.message}
        </div>
      ))}

      {latency.data && rows.length === 0 && (
        <div className="empty-state">
          <h1>No traces in this window</h1>
          <p>
            Nothing has sent spans to {tenant.name} in{" "}
            {describeRange(range).toLowerCase()}. Traces arrive over OTLP from an
            instrumented application or an OpenTelemetry Collector; until one is pointed
            at this receiver, this screen stays empty.
          </p>
        </div>
      )}

      {rows.length > 0 && (
        <>
          <p className="dim">
            {rows.length >= TOP_N
              ? `The ${TOP_N} slowest services`
              : `${rows.length} service${rows.length === 1 ? "" : "s"}`}
            , read from {latency.data?.table}.
          </p>

          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>Service</th>
                  <th className="num">Sampled spans</th>
                  <th className="num">Failed</th>
                  <th className="num">p50</th>
                  <th className="num">p95</th>
                  <th className="num">p99</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const rate = errorRate(row);
                  return (
                    <tr key={row.serviceId}>
                      <td>{serviceName(row.serviceId, naming)}</td>
                      <td className="num mono">{humanCount(row.sampledRequests)}</td>
                      <td className="num mono">
                        {/* The count and the rate together. A rate alone hides that 50%
                            of two spans is two spans, and a count alone makes a reader
                            do the division. */}
                        {humanCount(row.sampledErrors)}
                        {rate !== null && rate > 0 && (
                          <span className="dim"> ({humanPercent(rate)})</span>
                        )}
                      </td>
                      <td className="num mono">{humanDuration(row.p50Ns)}</td>
                      <td className="num mono">{humanDuration(row.p95Ns)}</td>
                      <td className="num mono">{humanDuration(row.p99Ns)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <p className="dim">
            Span counts are counts of <strong>sampled</strong> spans. Tracing is sampled
            before it reaches this product — in the application’s SDK, or in a collector —
            and an unsampled span leaves nothing behind to count, so there is no rate to
            scale these up by. The percentiles do not carry the same caveat: a percentile
            over a sample estimates the percentile over everything. A failure rate sits
            between the two — it holds if the sampling did not care which spans failed,
            and a collector configured to keep every error will read high here.
          </p>
        </>
      )}

      <h2>Calls between services</h2>

      {map.isError && (
        <div className="problem" role="alert">
          {message(map.error)}
        </div>
      )}

      {map.data && edges.length === 0 && (
        <p className="dim">
          No service called another in this window. An edge appears here because a span in
          one service is the parent of a span in another — nothing is configured, and
          nothing is remembered once the calls stop.
        </p>
      )}

      {edges.length > 0 && (
        <>
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>Caller</th>
                  <th>Callee</th>
                  <th className="num">Sampled calls</th>
                  <th className="num">Failed</th>
                  <th className="num">p95</th>
                </tr>
              </thead>
              <tbody>
                {edges.map((edge) => {
                  const rate = errorRate({
                    sampledRequests: edge.sampled_calls,
                    sampledErrors: edge.sampled_errors,
                  });
                  return (
                    <tr key={`${edge.from}-${edge.to}`}>
                      <td>{serviceName(edge.from, naming)}</td>
                      <td>{serviceName(edge.to, naming)}</td>
                      <td className="num mono">{humanCount(edge.sampled_calls)}</td>
                      <td className="num mono">
                        {humanCount(edge.sampled_errors)}
                        {rate !== null && rate > 0 && (
                          <span className="dim"> ({humanPercent(rate)})</span>
                        )}
                      </td>
                      <td className="num mono">{humanDuration(edge.p95_ns)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {map.data?.truncated && (
            <p className="notice" role="status">
              Only the {TOP_N} busiest calls are shown. There are more, and they are the
              quieter ones — a rare call is still a call, and one of them may be the one
              that is failing.
            </p>
          )}
        </>
      )}
    </>
  );
}
