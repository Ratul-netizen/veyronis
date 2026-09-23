/**
 * The path to this device — `docs/traceroute.md`.
 *
 * On the resource page, because that is where somebody stands when they ask why they
 * cannot reach something. The Topology screen answers *what is next to what*; this answers
 * *what is between here and there*, which is a different question and was unanswerable.
 *
 * # It does not run on its own
 *
 * A traceroute sends packets. Firing one every time somebody opens a device page would
 * make browsing the inventory a scanning activity, which is both rude and the sort of
 * thing that gets a monitoring product blamed for traffic. So there is a button.
 */

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

import {
  type Hop,
  describeScope,
  humanRtt,
  leavesPrivateSpaceAt,
  pathTo,
  slowestHop,
  summarise,
} from "./path";
import { message } from "./query";
import { useShell } from "./shell";

export function PathPanel({ address, name }: { address: string | null; name: string }) {
  const { tenant } = useShell();
  const [showRaw, setShowRaw] = useState(false);

  const run = useMutation({
    mutationFn: () => pathTo(tenant.tenant_id, address ?? ""),
  });

  if (!address) {
    // Honest about why the button is absent rather than showing one that cannot work.
    return (
      <p className="dim">
        No management address is recorded for {name}, so there is nowhere to trace to.
      </p>
    );
  }

  const result = run.data;
  const widest = result ? slowestHop(result.hops) : null;
  const leaves = result ? leavesPrivateSpaceAt(result.hops) : null;

  return (
    <>
      <p className="dim">
        Where the traffic goes between this product and {address}. Sends packets, so it runs
        only when asked.
      </p>

      <p>
        <button
          type="button"
          className="primary"
          onClick={() => run.mutate()}
          disabled={run.isPending}
        >
          {run.isPending ? "Tracing…" : "Trace the path"}
        </button>
      </p>

      {run.isError && (
        <div className="problem" role="alert">
          {message(run.error)}
        </div>
      )}

      {result && (
        <>
          <p>{summarise(result)}</p>

          {result.hops.length > 0 && (
            <table className="rows hops">
              <thead>
                <tr>
                  <th scope="col" className="num">
                    Hop
                  </th>
                  <th scope="col">Address</th>
                  <th scope="col">Space</th>
                  <th scope="col" className="num">
                    Best
                  </th>
                  <th scope="col">Latency</th>
                  <th scope="col" className="num">
                    Loss
                  </th>
                </tr>
              </thead>
              <tbody>
                {result.hops.map((h) => (
                  <HopRow key={h.number} hop={h} widest={widest} boundary={leaves === h.number} />
                ))}
              </tbody>
            </table>
          )}

          {/* The parser reads another program's prose, so the prose travels with the
              result — `docs/traceroute.md` §3. Collapsed, because it is the thing you
              look at when you disbelieve the table above it. */}
          <p>
            <button type="button" className="quiet" onClick={() => setShowRaw((was) => !was)}>
              {showRaw ? "Hide" : "Show"} what the command printed
            </button>
          </p>
          {showRaw && <pre className="mono raw-trace">{result.raw}</pre>}
        </>
      )}
    </>
  );
}

function HopRow({
  hop,
  widest,
  boundary,
}: {
  hop: Hop;
  widest: number | null;
  boundary: boolean;
}) {
  const best = hop.best_ms;
  const width = widest && best ? Math.max((best / widest) * 100, 2) : 0;
  const lossy = (hop.loss ?? 0) > 0;

  return (
    <tr className={boundary ? "leaves-private" : undefined}>
      <td className="num mono">{hop.number}</td>
      <td className="mono">{hop.address ?? <span className="dim">no reply</span>}</td>
      <td className="dim">{describeScope(hop.scope)}</td>
      <td className="num mono">{best === undefined ? "—" : humanRtt(best)}</td>
      <td>
        <div className="track">
          <div
            className={`bar${lossy ? " warn" : ""}`}
            style={{ width: `${width}%` }}
            aria-hidden="true"
          />
        </div>
      </td>
      {/* Loss is shown only when there is some. A column of "0%" trains people to stop
          reading it, which is exactly when the one that is not zero appears. */}
      <td className="num mono">
        {lossy ? `${Math.round((hop.loss ?? 0) * 100)}%` : <span className="dim">—</span>}
      </td>
    </tr>
  );
}
