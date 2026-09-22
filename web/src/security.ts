/**
 * The security screen's questions, as Query ASTs — M11.
 *
 * # There is no security API
 *
 * Every question on this screen is a `Query` the product could already express, pointed at
 * a table it could already read. So this builds ASTs and posts them to `/api/v1/query` like
 * the Explorer does, and M11 adds **no new HTTP surface at all**.
 *
 * That is worth saying plainly because the obvious alternative — a `/api/v1/security/*`
 * route returning pre-shaped JSON — would have been faster to write and would have been a
 * second path to the same rows, with its own tenant check to get right, its own audit
 * entry to remember, and its own idea of what a window means. PLAN's frozen decision about
 * the Query AST is *"never a parallel code path"*, and a bespoke analytics route is exactly
 * that.
 *
 * It also means the cross-tenant isolation these queries need is the isolation
 * `/api/v1/query` already has and is already tested for.
 *
 * # What the screen is allowed to say
 *
 * Counts and the fields a device reported. **Not verdicts.** §2.4 is explicit that the
 * three failed-authentication shapes are arithmetic and that "password spraying" is an
 * interpretation, so the table has a column for distinct users and no column for a
 * judgement. §2.5 is the same for DNS: a frequency table, and a sentence saying that a
 * burst of `NXDOMAIN` is software looking for a command server that has been taken down
 * *and* is a misconfigured search domain.
 */

import type { Expr, Query, ResultSet } from "./query";

/** How many rows any of these tables shows. */
export const LIMIT = 50;

/** How many recent events the list shows. */
export const RECENT = 100;

/**
 * ECS's `event.category`, as this product produces them — `uops_security::Category`.
 *
 * A closed list rather than whatever came back, because the screen offers them as filters
 * and a filter built from the data disappears when the data does — which is exactly when
 * somebody wants to select it.
 */
export const CATEGORIES = ["authentication", "network", "dns", "vpn"] as const;
export type Category = (typeof CATEGORIES)[number];

/** What a category means, for the filter's label. */
export function describeCategory(category: string): string {
  switch (category) {
    case "authentication":
      return "Sign-ins, as devices reported them";
    case "network":
      return "Firewall and ACL decisions";
    case "dns":
      return "Resolver queries";
    case "vpn":
      return "Tunnel sessions";
    default:
      return category;
  }
}

/**
 * Whether an event type is one somebody is usually looking for.
 *
 * Used to order a list, never to hide anything: an `allowed` event is not less true than a
 * `denied` one, and a screen that dropped them would make "how much does this firewall
 * pass" unanswerable.
 */
export function isRefusal(eventType: string): boolean {
  return eventType === "denied" || eventType === "failure";
}

function window(from: string, to: string) {
  return { start: from, end: to };
}

/**
 * The most recent security events.
 *
 * No aggregation: the raw rows, newest first, so the list is what the devices said rather
 * than a summary of it.
 */
export function recentEvents(from: string, to: string, category?: Category): Query {
  const query: Query = {
    signal: "event",
    time: window(from, to),
    resources: { type: "all" },
    order_by: [{ key: { by: "field", field: { field: "observed_at" } }, desc: true }],
    limit: RECENT,
  };
  if (category) {
    query.filter = {
      op: "compare",
      field: { field: "event_category" },
      cmp: "eq",
      value: category,
    };
  }
  return query;
}

/** Failed authentications only. */
const FAILED_AUTH: Expr = {
  op: "and",
  of: [
    {
      op: "compare",
      field: { field: "event_category" },
      cmp: "eq",
      value: "authentication",
    },
    { op: "compare", field: { field: "event_type" }, cmp: "eq", value: "failure" },
  ],
};

/**
 * Failed sign-ins per source address, with how many distinct accounts each was against.
 *
 * The second number is the one that matters and the reason §2.4 groups on a *pair*: twenty
 * failures against one account is somebody mistyping, and twenty against five accounts from
 * one address is not. The screen shows both and names neither.
 */
export function failuresBySource(from: string, to: string): Query {
  return {
    signal: "event",
    time: window(from, to),
    resources: { type: "all" },
    filter: FAILED_AUTH,
    aggregations: [
      { func: "count", field: null, alias: "failures" },
      { func: "count_distinct", field: { field: "attr", key: "user.name" }, alias: "users" },
    ],
    group_by: [{ field: "attr", key: "source.ip" }],
    order_by: [{ key: { by: "alias", alias: "failures" }, desc: true }],
    limit: LIMIT,
  };
}

/**
 * Failed sign-ins per account, with how many distinct addresses each came from.
 *
 * The other half of the pair. One account failing from many addresses is a credential in
 * more than one place, and it is invisible in the table above — each address on its own has
 * few failures.
 */
export function failuresByUser(from: string, to: string): Query {
  return {
    signal: "event",
    time: window(from, to),
    resources: { type: "all" },
    filter: FAILED_AUTH,
    aggregations: [
      { func: "count", field: null, alias: "failures" },
      { func: "count_distinct", field: { field: "attr", key: "source.ip" }, alias: "sources" },
    ],
    group_by: [{ field: "attr", key: "user.name" }],
    order_by: [{ key: { by: "alias", alias: "failures" }, desc: true }],
    limit: LIMIT,
  };
}

/**
 * Names that did not resolve, by how often.
 *
 * §2.5: one of the few DNS signals that means something without external knowledge, and the
 * product reports the count rather than a verdict — the same shape is software looking for
 * a command server that has been taken down, and it is a misconfigured search domain.
 */
export function unresolvedNames(from: string, to: string): Query {
  return {
    signal: "event",
    time: window(from, to),
    resources: { type: "all" },
    filter: {
      op: "compare",
      field: { field: "attr", key: "dns.response_code" },
      cmp: "eq",
      value: "NXDOMAIN",
    },
    aggregations: [{ func: "count", field: null, alias: "queries" }],
    group_by: [{ field: "attr", key: "dns.question.name" }],
    order_by: [{ key: { by: "alias", alias: "queries" }, desc: true }],
    limit: LIMIT,
  };
}

/**
 * A grouped result as `{ key, a, b }` rows.
 *
 * The server sends JSONCompact — values in column order, no names — so a screen that read
 * `row[1]` directly would break silently when a column was added. This reads the *names*
 * out of `columns` and is the one place that mapping happens.
 */
export interface Grouped {
  key: string;
  counts: Record<string, number>;
}

export function grouped(result: ResultSet | undefined): Grouped[] {
  if (!result) return [];
  const names = result.columns.map((c) => c.name);
  return result.rows.map((row) => {
    const counts: Record<string, number> = {};
    names.forEach((name, index) => {
      if (index === 0) return;
      counts[name] = count(row[index]);
    });
    return { key: text(row[0]), counts };
  });
}

/**
 * A count from a result cell.
 *
 * `UInt64` arrives quoted or unquoted depending on a server setting and on the aggregate's
 * result type — the same hazard the Rust tests document. Reading only one form makes every
 * value zero, which looks exactly like an empty table.
 */
export function count(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function text(value: unknown): string {
  return typeof value === "string" ? value : String(value ?? "");
}

/** One security event, as the list shows it. */
export interface EventRow {
  observedAt: string;
  category: string;
  type: string;
  summary: string;
  resourceId: string;
}

/**
 * Raw event rows, read by column name.
 *
 * Absent columns become empty strings rather than throwing: the query asks for no explicit
 * projection, so what comes back is whatever the compiler chose, and a screen that crashed
 * on an unexpected shape would be worse than one that renders a blank cell.
 */
export function events(result: ResultSet | undefined): EventRow[] {
  if (!result) return [];
  const at = (name: string) => result.columns.findIndex((c) => c.name === name);
  const observed = at("observed_at");
  const category = at("event_category");
  const type = at("event_type");
  const summary = at("summary");
  const resource = at("resource_id");

  return result.rows.map((row) => ({
    observedAt: observed >= 0 ? text(row[observed]) : "",
    category: category >= 0 ? text(row[category]) : "",
    type: type >= 0 ? text(row[type]) : "",
    summary: summary >= 0 ? text(row[summary]) : "",
    resourceId: resource >= 0 ? text(row[resource]) : "",
  }));
}
