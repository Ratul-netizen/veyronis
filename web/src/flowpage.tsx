/**
 * Flow — what the traffic is, where it is going, and how much to trust the number.
 *
 * One table: the busiest conversations in the current time range. That is the question
 * flow is asked during an incident, and the one `flows_5m` was built to answer.
 *
 * # The sampling marker is the whole screen
 *
 * A sampled exporter reports one packet in N, so the traffic figure is an extrapolation.
 * `./flow` explains why the estimate is what gets shown; this file's job is to make sure
 * nobody reads it as a measurement. Every estimated number carries `≈` and its row says
 * the rate, and a row from an unsampled exporter carries neither — because there is
 * nothing uncertain about it.
 *
 * Marking it per row rather than once at the top is deliberate: an estate mixes sampled
 * and unsampled exporters, and a banner saying "some of this is estimated" leaves the
 * reader unable to tell which.
 */

import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";

import {
  conversations,
  displayAddress,
  hasPorts,
  humanBytes,
  humanCount,
  protocolName,
  runQuery,
  topTalkers,
  traffic,
  TOP_N,
} from "./flow";
import { message } from "./query";
import { describeRange, resolveRange, useShell } from "./shell";

export function FlowPage() {
  const { tenant, range } = useShell();

  const window = useMemo(() => resolveRange(range), [range]);
  const query = useMemo(
    () =>
      window
        ? topTalkers(window.from.toISOString(), window.to.toISOString(), TOP_N)
        : null,
    [window],
  );

  const result = useQuery({
    queryKey: ["flow-top", tenant.tenant_id, JSON.stringify(query)],
    queryFn: () => runQuery(tenant.tenant_id, query!),
    enabled: query !== null,
    retry: false,
    staleTime: 30_000,
  });

  const rows = useMemo(
    () => (result.data ? conversations(result.data) : []),
    [result.data],
  );

  // Whether anything on screen is an extrapolation at all. Used only to decide whether
  // the footnote explaining `≈` is worth the space — the marks themselves are per row.
  const anySampled = rows.some((r) => r.samplingRate > 1);

  if (!window) {
    return (
      <div className="problem" role="alert">
        {describeRange(range)} is not a range this can read.
      </div>
    );
  }

  return (
    <>
      <h1>Flow</h1>

      {result.isPending && <p className="dim">Loading…</p>}

      {result.isError && (
        <div className="problem" role="alert">
          {message(result.error)}
        </div>
      )}

      {result.data?.warnings.map((w) => (
        <div key={w.message} className="notice" role="status">
          {w.message}
        </div>
      ))}

      {result.data && rows.length === 0 && (
        <div className="empty-state">
          <h1>No flow in this window</h1>
          <p>
            Nothing has been exported to {tenant.name} in {describeRange(range).toLowerCase()}.
            Flow arrives from routers and switches configured to send NetFlow, IPFIX or
            sFlow to this collector; until one is, this screen stays empty.
          </p>
        </div>
      )}

      {rows.length > 0 && (
        <>
          <p className="dim">
            {/* "The 25 busiest" only when there were more to be busiest of. Below the
                limit these are simply all of them, and saying otherwise implies a
                remainder that does not exist. */}
            {rows.length >= TOP_N
              ? `The ${TOP_N} busiest conversations`
              : `${rows.length} conversation${rows.length === 1 ? "" : "s"}`}
            , read from {result.data?.table}.
          </p>

          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th className="num">Traffic</th>
                  <th className="num">Packets</th>
                  <th>Sampling</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const bytes = traffic(row.observedBytes, row.samplingRate);
                  const packets = traffic(row.observedPackets, row.samplingRate);
                  return (
                    <tr key={`${row.src}-${row.dst}-${row.port}-${row.protocol}-${row.samplingRate}`}>
                      <td className="mono">{displayAddress(row.src)}</td>
                      <td className="mono">{displayAddress(row.dst)}</td>
                      <td className="mono num">
                        {hasPorts(row.protocol) ? row.port : <span className="dim">—</span>}
                      </td>
                      <td>{protocolName(row.protocol)}</td>
                      <td className="num mono">
                        {bytes.estimated && <span aria-hidden="true">≈ </span>}
                        {humanBytes(bytes.value)}
                      </td>
                      <td className="num mono">
                        {packets.estimated && <span aria-hidden="true">≈ </span>}
                        {humanCount(packets.value)}
                      </td>
                      <td className="dim">
                        {row.samplingRate > 1 ? `1 in ${humanCount(row.samplingRate)}` : "every packet"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {anySampled && (
            <p className="dim">
              ≈ marks a figure estimated from sampled traffic: the exporter reported one
              packet in the number shown, and the total is that count multiplied up. Rows
              without it were counted in full.
            </p>
          )}
        </>
      )}
    </>
  );
}
