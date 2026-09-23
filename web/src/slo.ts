/**
 * Service level objectives — `docs/slo.md`.
 *
 * # The one number this file will not compute
 *
 * A remaining error count. §2.2 is the decision and it is worth restating where the
 * arithmetic lives, because it is the number every competitor prints:
 *
 * Traces are sampled upstream of this product, and an unsampled span is *absent*. A
 * **ratio** over an unbiased sample estimates the same ratio over everything — so an SLI of
 * 99.4% and a burn rate of 2.1 are defensible numbers, for the same reason `services.ts`
 * treats a percentile over a sample as sound. A **count** is not: "4 213 errors remaining"
 * needs the real denominator, and this product does not know the sampling rate.
 *
 * So the budget is expressed as a *proportion consumed*, never as events left.
 *
 * # A window with no traffic has no SLI
 *
 * `null`, not 100%. A service nobody called did not succeed, and an objective that reads
 * green because nothing happened is the failure mode that makes people stop trusting the
 * screen.
 */

import { request } from "./api";
import type { Query, ResultSet } from "./query";

/** A stored objective. */
export interface Slo {
  id: string;
  name: string;
  description: string;
  service_id: string;
  /** A proportion. `0.995` is "99.5% of requests succeeded". */
  target: number;
  window_days: number;
}

export function listSlos(tenant: string): Promise<Slo[]> {
  return request<Slo[]>("/api/v1/slos", { tenant });
}

export function setSlo(
  tenant: string,
  body: { name: string; service_id: string; target: number; window_days: number },
): Promise<Slo> {
  return request<Slo>("/api/v1/slos", { method: "POST", body, tenant });
}

export function removeSlo(tenant: string, id: string): Promise<void> {
  return request<void>(`/api/v1/slos/${id}`, { method: "DELETE", tenant });
}

/**
 * Requests and errors for one service over the objective's window.
 *
 * Grouped by service alone, which is what lets the planner answer it from `service_5m` —
 * the same constraint `services.ts` records. The window comes from the objective rather
 * than from the shell's time range: an SLO over thirty days does not change because
 * somebody set the picker to an hour.
 */
export function attainmentQuery(slo: Slo, now: Date): Query {
  const end = now.toISOString();
  const start = new Date(now.getTime() - slo.window_days * 86_400_000).toISOString();
  return {
    signal: "trace",
    time: { start, end },
    resources: { type: "all" },
    filter: {
      op: "compare",
      field: { field: "service_id" },
      cmp: "eq",
      value: slo.service_id,
    },
    aggregations: [
      { func: "count", alias: "requests" },
      { func: "sum", field: { field: "errors" }, alias: "errors" },
    ],
    group_by: [{ field: "service_id" }],
    limit: 1,
  };
}

/** What a window contained. */
export interface Counted {
  requests: number;
  errors: number;
}

function number(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

/** Sampled requests and errors out of a result, or `null` when the window was empty. */
export function counted(result: ResultSet | undefined): Counted | null {
  if (!result || result.rows.length === 0) return null;
  const at = new Map(result.columns.map((c, i) => [c.name, i]));
  const row = result.rows[0] ?? [];
  const requests = number(row[at.get("requests") ?? -1]);
  // A bucket with rows but no requests is not a window with traffic in it.
  if (requests <= 0) return null;
  return { requests, errors: number(row[at.get("errors") ?? -1]) };
}

/**
 * The indicator: the share of sampled requests that succeeded.
 *
 * `null` for a window with no traffic. Sound over a sample — see the module docs.
 */
export function sli(counts: Counted | null): number | null {
  if (!counts || counts.requests <= 0) return null;
  const good = counts.requests - counts.errors;
  // Clamped: `errors` and `requests` are summed from different aggregate columns, and a
  // merge in flight could momentarily make errors exceed requests. A negative SLI on a
  // dashboard is worse than a zero.
  return Math.min(Math.max(good / counts.requests, 0), 1);
}

/**
 * The share of the error budget that has been consumed, 0–1.
 *
 * A **proportion**, never a count of events — the module docs say why. Above 1 means the
 * objective has been missed for this window, and the number keeps going so an operator can
 * see by how much.
 *
 * `null` when there is no traffic, because a budget with no requests in it has not been
 * spent and has not been preserved either.
 */
export function budgetConsumed(slo: Slo, counts: Counted | null): number | null {
  const indicator = sli(counts);
  if (indicator === null) return null;
  const allowed = 1 - slo.target;
  // The schema refuses a target of 1, so this cannot divide by zero — but the guard stays,
  // because the schema is not the only thing that could hand this a target.
  if (allowed <= 0) return null;
  return (1 - indicator) / allowed;
}

/**
 * How fast the budget is being spent relative to the window.
 *
 * A burn rate of 1 spends exactly the whole budget over exactly the window. 2 spends it in
 * half the time. It is a ratio of ratios, so it is sound over a sample.
 */
export function burnRate(slo: Slo, counts: Counted | null): number | null {
  return budgetConsumed(slo, counts);
}

/** Whether the objective is currently met. `null` when there is nothing to say. */
export function isMet(slo: Slo, counts: Counted | null): boolean | null {
  const indicator = sli(counts);
  return indicator === null ? null : indicator >= slo.target;
}

/**
 * An objective, as a percentage with the digits that matter.
 *
 * 99.9 and 99.95 are different objectives and rounding to one decimal would make them the
 * same number on screen. Trailing zeroes are trimmed so 99.5 does not read as 99.500.
 */
export function asPercent(proportion: number): string {
  const pct = proportion * 100;
  return `${Number(pct.toFixed(3))}%`;
}

/** How a window reads in a sentence. */
export function describeWindow(days: number): string {
  if (days === 1) return "24 hours";
  if (days === 7) return "7 days";
  if (days === 28) return "28 days";
  if (days === 30) return "30 days";
  return `${days} days`;
}

/**
 * What to say about an objective, in the order of what an operator needs to know.
 *
 * `unknown` first, because a window with no traffic is not a pass and must not be drawn as
 * one. `missed` before `at-risk` because it has already happened.
 */
export function verdict(
  slo: Slo,
  counts: Counted | null,
): "unknown" | "missed" | "at-risk" | "met" {
  const consumed = budgetConsumed(slo, counts);
  if (consumed === null) return "unknown";
  if (consumed > 1) return "missed";
  // Three quarters of the budget gone is the conventional point at which somebody should
  // look. It is a display threshold, not an alert — `docs/slo.md` §2.4: nothing here pages
  // anybody, and the thresholds that page are the organisation's to choose.
  if (consumed >= 0.75) return "at-risk";
  return "met";
}
