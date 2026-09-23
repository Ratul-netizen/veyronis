/**
 * The path to a device — `docs/traceroute.md`.
 *
 * # Why this is "path" and not "trace"
 *
 * In this product a *trace* is a distributed trace: `trace.ts` is the OTLP span waterfall
 * and `trace_id` is a column on logs. A traceroute is a different thing entirely, and
 * calling both of them "trace" would make every reference ambiguous. The collision was
 * found by trying to create a second `trace.ts`.
 *
 * The product knew adjacency — `connected_to` edges from LLDP — and nothing about path.
 * This is what answers "why can't I reach it".
 */

import { request } from "./api";

/** Where a hop sits. Sent by the server so two screens cannot disagree about it. */
export type HopScope =
  | "private"
  | "carrier_grade"
  | "link_local"
  | "loopback"
  | "public"
  | "unknown";

export interface Hop {
  number: number;
  address?: string;
  scope: HopScope;
  /**
   * Off the public internet — **not** "yours".
   *
   * A private hop may well be the carrier's: the first real trace taken while building
   * this crossed two of the ISP's own RFC 1918 routers before reaching CGNAT space.
   */
  not_public: boolean;
  rtt_ms: (number | null)[];
  loss?: number;
  best_ms?: number;
}

export interface PathResult {
  target: string;
  hops: Hop[];
  reached: boolean;
  /** Exactly what the command printed, because the parser reads prose. */
  raw: string;
}

export function pathTo(tenant: string, target: string, maxHops = 30): Promise<PathResult> {
  return request<PathResult>("/api/v1/path", {
    method: "POST",
    body: { target, max_hops: maxHops },
    tenant,
  });
}

/** How a scope reads on screen. */
export function describeScope(scope: HopScope): string {
  switch (scope) {
    case "private":
      return "private";
    case "carrier_grade":
      return "carrier";
    case "link_local":
      return "link-local";
    case "loopback":
      return "loopback";
    case "public":
      return "public";
    case "unknown":
      return "no reply";
  }
}

/**
 * Where the path first leaves private address space, as a hop number.
 *
 * `null` when it never does — an entirely internal path, the ordinary case for a device in
 * the estate. Used to draw one divider rather than a badge on every row.
 *
 * Deliberately *not* "where your network ends": the product cannot tell whose a private
 * address is. It marks a change of address space and lets the reader conclude.
 */
export function leavesPrivateSpaceAt(hops: Hop[]): number | null {
  const first = hops.find((h) => h.address && !h.not_public);
  return first ? first.number : null;
}

/**
 * The slowest round trip in the path, for scaling a bar.
 *
 * `null` when nothing answered, so the caller draws no bars rather than dividing by zero.
 */
export function slowestHop(hops: Hop[]): number | null {
  const times = hops.map((h) => h.best_ms).filter((t): t is number => typeof t === "number");
  return times.length > 0 ? Math.max(...times) : null;
}

/**
 * A round trip, at a scale a person reads.
 *
 * Sub-millisecond values arrive as fractions — `tracert` prints `<1 ms` and the parser
 * records half a millisecond rather than a whole one — so they need a decimal place that
 * larger values do not.
 */
export function humanRtt(ms: number): string {
  return ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`;
}

/**
 * What the path says as a whole, in one sentence.
 *
 * The distinction worth making: a path that ran out of hops and a path that was blocked
 * look identical in a table of hops and are different problems.
 */
export function summarise(result: PathResult): string {
  if (result.hops.length === 0) {
    return "Nothing answered. The target may be unreachable from this product, or the trace was refused.";
  }
  if (result.reached) {
    const n = result.hops.length;
    return `Reached in ${n} hop${n === 1 ? "" : "s"}.`;
  }
  const answered = result.hops.filter((h) => h.address).length;
  const last = [...result.hops].reverse().find((h) => h.address);
  return last
    ? `Did not arrive. ${answered} of ${result.hops.length} hops answered; the last was ${last.address}.`
    : "Did not arrive, and no hop answered at all.";
}
