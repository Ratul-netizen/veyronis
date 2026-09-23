/**
 * Is anything arriving? — the question the Overview could not previously answer.
 *
 * A monitoring product that says "nothing is firing" is making one of two very different
 * statements, and until this existed it could not tell them apart:
 *
 * * **the estate is healthy**, or
 * * **the estate stopped talking and nothing noticed.**
 *
 * The second is the failure mode that matters most, because every other panel on the
 * screen looks *better* as it gets worse. A collector that died makes the error count fall
 * to zero. `docs/PRODUCT-STRATEGY.md` §8.1 names this as the tile most competitors
 * approximate and this product can answer directly, because all five signals land in one
 * place and are read through one query AST.
 *
 * # Why this counts rather than asking when each signal last arrived
 *
 * "Last seen" is the better number and it is **not safely expressible today**, which is
 * worth writing down rather than discovering again.
 *
 * `max(observed_at)` looks like the obvious query. On a raw table it compiles to `max(…)`
 * and is correct. But the planner may answer a metric query from `metrics_5m`, and on a
 * rollup the compiler emits `maxMerge(max_v)` — which is the maximum metric **value**, not
 * the latest timestamp. The query would succeed, return a number, and the screen would
 * render a timestamp built from somebody's CPU percentage.
 *
 * A count over a window has no such ambiguity on either table shape. So the tile answers
 * *"did anything arrive in this window"*, which is the question that separates the two
 * statements above, and it does not claim to answer *"when exactly"*.
 */

import type { Query, ResultSet, Signal } from "./query";

/**
 * The signals the tile reports on, in the order it lists them.
 *
 * Ordered by how loudly their absence matters in a network estate: metrics stop first when
 * a poller dies, logs when a collector does. Traces are last because an estate with no
 * instrumented applications legitimately has none, and a permanent "nothing" in the first
 * row would train people to ignore the tile.
 */
export const WATCHED: { signal: Signal; label: string }[] = [
  { signal: "metric", label: "Metrics" },
  { signal: "log", label: "Logs" },
  { signal: "event", label: "Events" },
  { signal: "state", label: "State changes" },
  { signal: "flow", label: "Flows" },
  { signal: "trace", label: "Traces" },
];

/**
 * How many rows of one signal arrived in the window.
 *
 * No `group_by`, so this is one number from one aggregate — the cheapest question that can
 * be asked of a telemetry table, and cheap matters because the Overview asks it six times.
 */
export function arrivals(signal: Signal, start: string, end: string): Query {
  return {
    signal,
    time: { start, end },
    resources: { type: "all" },
    aggregations: [{ func: "count", alias: "n" }],
    limit: 1,
  };
}

/** What one signal's row on the tile says. */
export interface Arrival {
  signal: Signal;
  label: string;
  /** `null` while the query is in flight or after it failed. */
  count: number | null;
  /** True when the query failed — distinct from a successful zero. */
  failed: boolean;
}

/**
 * The single number out of a count result.
 *
 * `null` rather than 0 for a result with no rows: an aggregate with no `group_by` returns
 * exactly one row, so no rows at all means something other than "nothing arrived", and
 * showing it as a confident zero would be the same lie this module exists to prevent.
 */
export function countOf(result: ResultSet | undefined): number | null {
  if (!result || result.rows.length === 0) return null;
  const at = result.columns.findIndex((c) => c.name === "n");
  const cell = result.rows[0]?.[at >= 0 ? at : 0];
  if (typeof cell === "number") return cell;
  if (typeof cell === "string") {
    const parsed = Number(cell);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

/**
 * What the tile says as a whole.
 *
 * * `quiet` — every signal that could report did.
 * * `partial` — at least one signal is silent while another is arriving. **The interesting
 *   state**, and the one a single "healthy" badge hides.
 * * `silent` — nothing at all arrived. Either the estate is off or this product is.
 * * `unknown` — nothing has answered yet, or the reads failed.
 *
 * Traces are excluded from `silent`: an estate with no instrumented applications has none
 * by design, and letting that one row decide the verdict would make the tile permanently
 * wrong for every network-only deployment — which is most of them.
 */
export function verdict(arrivals: Arrival[]): "quiet" | "partial" | "silent" | "unknown" {
  const decided = arrivals.filter((a) => !a.failed && a.count !== null);
  if (decided.length === 0) return "unknown";

  const counting = decided.filter((a) => a.signal !== "trace");
  if (counting.length === 0) return "unknown";

  const arriving = counting.filter((a) => (a.count ?? 0) > 0);
  if (arriving.length === 0) return "silent";
  return arriving.length === counting.length ? "quiet" : "partial";
}

/** The signals that reported nothing, for the sentence the tile writes. */
export function silent(arrivals: Arrival[]): string[] {
  return arrivals
    .filter((a) => !a.failed && a.count === 0 && a.signal !== "trace")
    .map((a) => a.label);
}

/** A count, grouped, or a dash while it is unknown. */
export function humanArrivals(count: number | null): string {
  return count === null ? "—" : count.toLocaleString("en-GB");
}
