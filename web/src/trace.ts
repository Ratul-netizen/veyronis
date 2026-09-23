/**
 * One trace, as a tree — M8 §2.5, and the screen M8 said was missing.
 *
 * M8 closed with the backend for this complete and no screen drawing it:
 *
 * > `uops_query::correlate` builds the queries — the spans of one trace, the logs emitted
 * > during it, the children of one span — and `GET /api/v1/query` runs them, but no screen
 * > draws the tree yet.
 *
 * # This mirrors `uops_query::correlate`, deliberately
 *
 * `query.ts` already mirrors `uops_query::ast` because SPEC §M0.5 says the UI builds the
 * AST. This module continues that: the two constructors here are the same two questions
 * `correlate.rs` asks, written in the same shape, so a reader can hold them side by side.
 *
 * **The refusal below is the reason this is a module and not four lines in a component.**
 * `correlate.rs` names three things a caller gets wrong and marks one of them dangerous:
 *
 * > **An empty id matches everything.** `trace_id` is `''` on every log line that was
 * > never part of a trace — which is every syslog message in the estate. A UI that passed
 * > a missing id through would render the tenant's entire log history under the heading
 * > "logs from this trace", and it would look like a working feature.
 *
 * That is exactly the mistake a screen makes, because a screen gets its id from a URL and
 * a URL can be edited. So it is refused here, once, and tested.
 *
 * # A trace is tenant-wide, and that is not a scoping bug
 *
 * A trace crosses services on as many machines, so neither query narrows by resource.
 * Narrowing would silently drop the half of the trace that ran somewhere else, which is
 * usually the half being looked for. The tenant scope is still applied by the server.
 */

import type { Field, Query, ResultSet } from "./query";

/**
 * The most spans one trace may draw.
 *
 * A trace with more spans than this exists — a fan-out over a thousand shards is real —
 * but a waterfall with two thousand rows is not a diagram, it is a wall. The screen says
 * when it has truncated rather than silently drawing a partial tree, because a partial
 * tree read as a whole one is how somebody concludes the wrong service was at fault.
 */
export const MAX_SPANS = 500;

/** The most log lines shown beside a trace. */
export const MAX_LOGS = 200;

/**
 * A trace id that cannot be used to ask a question.
 *
 * Thrown rather than returned as a falsy value: every caller of these builders is about to
 * put the result on the wire, and a builder that returned `null` would be a builder whose
 * failure a caller could forget to check.
 */
export class NoTraceId extends Error {
  constructor() {
    super("a trace id is required, and an empty one would match every row that has none");
    this.name = "NoTraceId";
  }
}

/** Whether a string is usable as a trace or span id. */
export function usableId(id: string | null | undefined): id is string {
  return typeof id === "string" && id.trim().length > 0;
}

/** Spelled once, so the two builders cannot disagree about the column. */
export const TRACE_ID: Field = { field: "trace_id" };

/**
 * The spans of one trace, oldest first.
 *
 * Ordered by time because a trace read in any other order is a list of fragments: the root
 * is the earliest span, and the shape of the rest only means something against it. That
 * sentence is `correlate.rs`'s, and the ordering is the same one for the same reason.
 */
export function traceSpans(traceId: string, start: string, end: string, limit = MAX_SPANS): Query {
  if (!usableId(traceId)) throw new NoTraceId();
  return {
    signal: "trace",
    time: { start, end },
    resources: { type: "all" },
    filter: { op: "compare", field: TRACE_ID, cmp: "eq", value: traceId.trim() },
    order_by: [{ key: { by: "field", field: { field: "observed_at" } }, desc: false }],
    limit,
  };
}

/**
 * The logs emitted during one trace.
 *
 * Not a join. `logs.trace_id` has been a column since M3 and the OTLP path has populated
 * it for as long, so this is the ordinary log query with one more predicate — compiled by
 * the same compiler, against a column that is already there.
 */
export function traceLogs(traceId: string, start: string, end: string, limit = MAX_LOGS): Query {
  if (!usableId(traceId)) throw new NoTraceId();
  return {
    signal: "log",
    time: { start, end },
    resources: { type: "all" },
    filter: { op: "compare", field: TRACE_ID, cmp: "eq", value: traceId.trim() },
    order_by: [{ key: { by: "field", field: { field: "observed_at" } }, desc: false }],
    limit,
  };
}

/** One span, as the waterfall needs it. */
export interface Span {
  spanId: string;
  parentSpanId: string;
  traceId: string;
  serviceId: string;
  name: string;
  kind: string;
  /** Wall-clock start. */
  startMs: number;
  durationNs: number;
  statusCode: string;
  statusMessage: string;
  scopeName: string;
}

/** A span placed in the tree, with the geometry the bar needs. */
export interface SpanNode extends Span {
  depth: number;
  children: SpanNode[];
  /** Fraction of the trace's span, 0–1, where this bar starts. */
  offset: number;
  /** Fraction of the trace's span, 0–1, that this bar covers. */
  width: number;
  /**
   * Whether this node's parent is absent from the result.
   *
   * True for the real root, and also for a span whose parent was sampled away or fell
   * outside the window. The screen distinguishes the two — see `rootKind`.
   */
  orphaned: boolean;
}

/** Index of each column in a result set, by name. */
function indexOf(result: ResultSet): Map<string, number> {
  return new Map(result.columns.map((c, i) => [c.name, i]));
}

function str(row: unknown[], at: number | undefined): string {
  if (at === undefined) return "";
  const v = row[at];
  return typeof v === "string" ? v : v === null || v === undefined ? "" : String(v);
}

/**
 * A number, however `ClickHouse` chose to encode it.
 *
 * 64-bit integers arrive quoted when `output_format_json_quote_64bit_integers` is on, and
 * a nanosecond duration is exactly the column where that matters — the same note
 * `services.ts` carries, for the same column.
 */
function num(row: unknown[], at: number | undefined): number {
  if (at === undefined) return 0;
  const v = row[at];
  if (typeof v === "number") return v;
  if (typeof v === "string") {
    const parsed = Number(v);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function millis(row: unknown[], at: number | undefined): number {
  if (at === undefined) return 0;
  const v = row[at];
  if (typeof v === "number") return v;
  if (typeof v === "string") {
    // `ClickHouse` sends `DateTime64(3)` as `2026-09-23 14:04:05.123`, which `Date` reads
    // as local time unless it is told otherwise. The screen only ever uses these values
    // relative to each other, so a uniform shift is harmless — but it must be uniform,
    // which is why every span goes through this one function.
    const iso = v.includes("T") ? v : `${v.replace(" ", "T")}Z`;
    const parsed = Date.parse(iso);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

/** Spans out of a raw trace result. */
export function toSpans(result: ResultSet): Span[] {
  const at = indexOf(result);
  return result.rows.map((row) => ({
    spanId: str(row, at.get("span_id")),
    parentSpanId: str(row, at.get("parent_span_id")),
    traceId: str(row, at.get("trace_id")),
    serviceId: str(row, at.get("service_id")),
    name: str(row, at.get("name")),
    kind: str(row, at.get("kind")),
    startMs: millis(row, at.get("observed_at")),
    durationNs: num(row, at.get("duration_ns")),
    statusCode: str(row, at.get("status_code")),
    statusMessage: str(row, at.get("status_message")),
    scopeName: str(row, at.get("scope_name")),
  }));
}

/** The window a trace occupies, in wall-clock milliseconds. */
export interface Extent {
  startMs: number;
  endMs: number;
}

/** Earliest start and latest end across the spans. */
export function extent(spans: Span[]): Extent {
  if (spans.length === 0) return { startMs: 0, endMs: 0 };
  let startMs = Infinity;
  let endMs = -Infinity;
  for (const s of spans) {
    const end = s.startMs + s.durationNs / 1e6;
    if (s.startMs < startMs) startMs = s.startMs;
    if (end > endMs) endMs = end;
  }
  return { startMs, endMs };
}

/**
 * The spans, as a tree.
 *
 * # Three things this has to survive, because a sampled trace is not a clean one
 *
 * 1. **A missing parent.** Tail sampling, a dropped batch or a window that starts after
 *    the root all produce a span whose parent is not in the result. It becomes a root and
 *    is marked `orphaned`, rather than being dropped — a span that ran is evidence even
 *    when its parent is missing, and dropping it would make a slow child invisible.
 * 2. **More than one root.** Follows from the above, and is the ordinary case on a window
 *    that clips a trace.
 * 3. **A cycle.** Should be impossible and is not worth trusting: a span whose ancestry
 *    loops back to itself would recurse until the tab dies. Visited-tracking makes the
 *    second visit a root instead, so a corrupt trace renders oddly rather than hanging.
 *
 * Children keep their arrival order, which is start-time order, because the query asked
 * for it.
 */
export function buildTree(spans: Span[]): SpanNode[] {
  const { startMs, endMs } = extent(spans);
  const span = Math.max(endMs - startMs, 1);

  const nodes = new Map<string, SpanNode>();
  for (const s of spans) {
    // A span with no id of its own cannot be a parent and cannot be deduplicated. It is
    // kept — it still ran — under a key nothing will ever reference.
    const key = usableId(s.spanId) ? s.spanId : `anonymous:${nodes.size}`;
    nodes.set(key, {
      ...s,
      depth: 0,
      children: [],
      offset: (s.startMs - startMs) / span,
      width: Math.max(s.durationNs / 1e6 / span, 0),
      orphaned: false,
    });
  }

  const roots: SpanNode[] = [];
  for (const node of nodes.values()) {
    const parent = usableId(node.parentSpanId) ? nodes.get(node.parentSpanId) : undefined;
    if (parent && parent !== node) {
      parent.children.push(node);
    } else {
      node.orphaned = usableId(node.parentSpanId);
      roots.push(node);
    }
  }

  // Depth, and the cycle guard. Done as a walk rather than during linking because a
  // node's depth is not known until its whole ancestry is.
  const seen = new Set<SpanNode>();
  const walk = (node: SpanNode, depth: number) => {
    if (seen.has(node)) return;
    seen.add(node);
    node.depth = depth;
    for (const child of node.children) walk(child, depth + 1);
  };
  for (const root of roots) walk(root, 0);

  // Anything still unseen is in a cycle that never touched a root. Promote the first node
  // of each cycle to a root so it is drawn rather than silently lost — and **detach it
  // from its parent**, which is what actually breaks the cycle. Marking it visited would
  // only protect this walk; `flatten` and the renderer walk the same structure, and a
  // structure that is still cyclic recurses until the tab dies.
  for (const node of nodes.values()) {
    if (seen.has(node)) continue;
    const parent = usableId(node.parentSpanId) ? nodes.get(node.parentSpanId) : undefined;
    if (parent) {
      const at = parent.children.indexOf(node);
      if (at >= 0) parent.children.splice(at, 1);
    }
    node.orphaned = true;
    roots.push(node);
    walk(node, 0);
  }

  return roots;
}

/** The tree, flattened for rendering, parents immediately before their children. */
export function flatten(roots: SpanNode[]): SpanNode[] {
  const out: SpanNode[] = [];
  const push = (node: SpanNode) => {
    out.push(node);
    for (const child of node.children) push(child);
  };
  for (const root of roots) push(root);
  return out;
}

/**
 * The slowest chain from a root to a leaf — the critical path.
 *
 * Chosen by *duration at each step*, not by summing children: a parent's duration already
 * contains its children's, so summing would double-count. At each level the slowest child
 * is followed, which is the question an operator is asking — "what was this waiting for".
 *
 * This is a heuristic and the screen labels it as one. A true critical path needs the gaps
 * between siblings, and a sampled trace does not reliably have the spans to compute them.
 */
export function criticalPath(roots: SpanNode[]): Set<string> {
  const path = new Set<string>();
  let node = roots.reduce<SpanNode | undefined>(
    (slowest, r) => (!slowest || r.durationNs > slowest.durationNs ? r : slowest),
    undefined,
  );
  const guard = new Set<SpanNode>();
  while (node && !guard.has(node)) {
    guard.add(node);
    if (usableId(node.spanId)) path.add(node.spanId);
    node = node.children.reduce<SpanNode | undefined>(
      (slowest, c) => (!slowest || c.durationNs > slowest.durationNs ? c : slowest),
      undefined,
    );
  }
  return path;
}

/**
 * A duration, at a scale a person reads.
 *
 * Nanoseconds are the stored unit and almost never the useful one. Three significant
 * figures, because a waterfall is read by comparing bars and the number is confirmation.
 */
export function duration(ns: number): string {
  if (!Number.isFinite(ns) || ns < 0) return "—";
  if (ns < 1_000) return `${Math.round(ns)} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toPrecision(3)} µs`;
  if (ns < 1_000_000_000) return `${(ns / 1_000_000).toPrecision(3)} ms`;
  return `${(ns / 1_000_000_000).toPrecision(3)} s`;
}

/**
 * Whether a span failed.
 *
 * `unset` is not a failure — it is the default a span carries when nobody said. Treating
 * it as an error would paint most traces red, which is the same mistake M8 records about
 * the error-rate calculation in `services.ts`.
 */
export function failed(span: Span): boolean {
  return span.statusCode === "error";
}

/** How many spans failed. */
export function errorCount(spans: Span[]): number {
  return spans.filter(failed).length;
}

/**
 * What to say about a root.
 *
 * A trace whose root has no parent is complete as far as this window can tell. A root that
 * *names* a parent it does not have is a clipped or sampled trace, and saying so is the
 * difference between "this is the request" and "this is part of a request".
 */
export function rootKind(roots: SpanNode[]): "complete" | "clipped" | "empty" {
  if (roots.length === 0) return "empty";
  return roots.some((r) => r.orphaned) ? "clipped" : "complete";
}

/** The services a trace touched, in first-seen order. */
export function servicesIn(spans: Span[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const s of spans) {
    if (usableId(s.serviceId) && !seen.has(s.serviceId)) {
      seen.add(s.serviceId);
      out.push(s.serviceId);
    }
  }
  return out;
}

