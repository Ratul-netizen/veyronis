/**
 * What the waterfall asks, and what it is allowed to draw.
 *
 * Two kinds of test here, and they exist for different reasons.
 *
 * The **query builders** are tested the way `security.test.ts` tests its own: a filter that
 * quietly stopped matching would turn "the spans of this trace" into "every span", and the
 * screen would look identical. The empty-id case is the one `uops_query::correlate` marks
 * dangerous, and it is the one a URL can produce.
 *
 * The **tree builder** is tested against traces that are not clean, because sampled traces
 * are not clean. A missing parent, several roots and a cycle are all reachable from real
 * data, and each has a failure mode worse than drawing nothing: dropping a span hides a
 * slow child, and a cycle hangs the tab.
 */

import { describe, expect, it } from "vitest";

import type { ResultSet } from "./query";
import {
  MAX_SPANS,
  NoTraceId,
  type Span,
  buildTree,
  criticalPath,
  duration,
  errorCount,
  extent,
  flatten,
  rootKind,
  servicesIn,
  toSpans,
  traceLogs,
  traceSpans,
  usableId,
} from "./trace";

const START = "2026-09-23T12:00:00Z";
const END = "2026-09-23T13:00:00Z";

function span(over: Partial<Span> = {}): Span {
  return {
    spanId: "a",
    parentSpanId: "",
    traceId: "t",
    serviceId: "svc",
    name: "GET /",
    kind: "server",
    startMs: 1_000,
    durationNs: 1_000_000,
    statusCode: "unset",
    statusMessage: "",
    scopeName: "",
    ...over,
  };
}

describe("the questions", () => {
  it("asks for one trace's spans, oldest first", () => {
    const q = traceSpans("abc", START, END);
    expect(q.signal).toBe("trace");
    expect(q.filter).toEqual({
      op: "compare",
      field: { field: "trace_id" },
      cmp: "eq",
      value: "abc",
    });
    // The root is the earliest span and the rest only mean something against it.
    expect(q.order_by?.[0]?.desc).toBe(false);
    expect(q.limit).toBe(MAX_SPANS);
  });

  it("asks for the logs of that same trace, not a join", () => {
    const q = traceLogs("abc", START, END);
    // An ordinary log query with one more predicate — the whole point of M8 §2.5.
    expect(q.signal).toBe("log");
    expect(q.filter).toEqual({
      op: "compare",
      field: { field: "trace_id" },
      cmp: "eq",
      value: "abc",
    });
  });

  it("refuses an empty trace id rather than matching every row that has none", () => {
    // The dangerous one. `trace_id` is '' on every syslog line in the estate, so a blank
    // id would render the tenant's entire log history under "logs from this trace" and
    // look like a working feature. A URL can produce every one of these.
    for (const bad of ["", "   ", null, undefined]) {
      expect(() => traceSpans(bad as string, START, END)).toThrow(NoTraceId);
      expect(() => traceLogs(bad as string, START, END)).toThrow(NoTraceId);
    }
  });

  it("trims an id rather than sending the spaces", () => {
    expect(traceSpans(" abc ", START, END).filter).toEqual({
      op: "compare",
      field: { field: "trace_id" },
      cmp: "eq",
      value: "abc",
    });
  });

  it("knows which ids are usable", () => {
    expect(usableId("a")).toBe(true);
    expect(usableId(" ")).toBe(false);
    expect(usableId(null)).toBe(false);
  });
});

describe("reading the result", () => {
  const result: ResultSet = {
    columns: [
      { name: "span_id", type: "String" },
      { name: "parent_span_id", type: "String" },
      { name: "observed_at", type: "DateTime64(3)" },
      { name: "duration_ns", type: "UInt64" },
      { name: "name", type: "String" },
      { name: "status_code", type: "String" },
    ],
    rows: [["a", "", "2026-09-23 12:00:00.000", "5000000", "GET /", "unset"]],
    table: "spans",
    warnings: [],
    rows_read: 1,
    bytes_read: 1,
  };

  it("reads a quoted 64-bit duration as a number", () => {
    // `output_format_json_quote_64bit_integers` sends this as a string, and a duration is
    // exactly the column where that matters.
    expect(toSpans(result)[0]?.durationNs).toBe(5_000_000);
  });

  it("does not invent values for columns the query did not select", () => {
    const s = toSpans(result)[0];
    expect(s?.serviceId).toBe("");
    expect(s?.scopeName).toBe("");
  });
});

describe("the tree", () => {
  it("nests children under parents and gives them depth", () => {
    const roots = buildTree([
      span({ spanId: "root" }),
      span({ spanId: "child", parentSpanId: "root" }),
      span({ spanId: "grandchild", parentSpanId: "child" }),
    ]);
    expect(roots).toHaveLength(1);
    const order = flatten(roots);
    expect(order.map((n) => n.spanId)).toEqual(["root", "child", "grandchild"]);
    expect(order.map((n) => n.depth)).toEqual([0, 1, 2]);
  });

  it("keeps a span whose parent is missing, and says the trace is clipped", () => {
    // Tail sampling and a window that starts after the root both produce this. Dropping
    // the span would make a slow child invisible, which is the opposite of the job.
    const roots = buildTree([span({ spanId: "orphan", parentSpanId: "gone" })]);
    expect(roots).toHaveLength(1);
    expect(roots[0]?.orphaned).toBe(true);
    expect(rootKind(roots)).toBe("clipped");
  });

  it("calls a trace complete only when no root names a parent it does not have", () => {
    expect(rootKind(buildTree([span({ spanId: "root" })]))).toBe("complete");
    expect(rootKind([])).toBe("empty");
  });

  it("survives a cycle instead of recursing until the tab dies", () => {
    // Should be impossible; not worth trusting. Both spans must still be drawn.
    const roots = buildTree([
      span({ spanId: "a", parentSpanId: "b" }),
      span({ spanId: "b", parentSpanId: "a" }),
    ]);
    expect(flatten(roots)).toHaveLength(2);
  });

  it("does not make a span its own parent", () => {
    const roots = buildTree([span({ spanId: "a", parentSpanId: "a" })]);
    expect(roots).toHaveLength(1);
    expect(flatten(roots)).toHaveLength(1);
  });

  it("keeps a span that carries no id of its own", () => {
    const roots = buildTree([span({ spanId: "" }), span({ spanId: "" })]);
    expect(flatten(roots)).toHaveLength(2);
  });

  it("places bars against the whole trace's extent", () => {
    const roots = buildTree([
      // Ten seconds from 1_000 ms, in nanoseconds.
      span({ spanId: "root", startMs: 1_000, durationNs: 10_000 * 1e6 }),
      span({ spanId: "late", parentSpanId: "root", startMs: 6_000, durationNs: 5_000 * 1e6 }),
    ]);
    const [root, late] = flatten(roots);
    expect(root?.offset).toBe(0);
    expect(root?.width).toBeCloseTo(1, 5);
    // Starts halfway through a ten-second trace and runs to the end.
    expect(late?.offset).toBeCloseTo(0.5, 5);
    expect(late?.width).toBeCloseTo(0.5, 5);
  });

  it("gives an empty trace an extent rather than dividing by zero", () => {
    expect(extent([])).toEqual({ startMs: 0, endMs: 0 });
    expect(buildTree([])).toEqual([]);
  });
});

describe("what the screen says about it", () => {
  it("follows the slowest child at each step rather than summing", () => {
    // A parent's duration already contains its children's, so summing double-counts.
    const roots = buildTree([
      span({ spanId: "root", durationNs: 100 }),
      span({ spanId: "slow", parentSpanId: "root", durationNs: 80 }),
      span({ spanId: "fast", parentSpanId: "root", durationNs: 5 }),
      span({ spanId: "leaf", parentSpanId: "slow", durationNs: 70 }),
    ]);
    const path = criticalPath(roots);
    expect([...path].sort()).toEqual(["leaf", "root", "slow"]);
    expect(path.has("fast")).toBe(false);
  });

  it("counts only spans that actually failed", () => {
    // `unset` is the default nobody set. Reading it as an error would paint most traces
    // red — the same mistake `services.ts` records about error rate.
    expect(
      errorCount([
        span({ statusCode: "error" }),
        span({ statusCode: "unset" }),
        span({ statusCode: "ok" }),
      ]),
    ).toBe(1);
  });

  it("lists the services a trace touched, once each, in the order seen", () => {
    expect(
      servicesIn([
        span({ serviceId: "web" }),
        span({ serviceId: "db" }),
        span({ serviceId: "web" }),
        span({ serviceId: "" }),
      ]),
    ).toEqual(["web", "db"]);
  });

  it("scales a duration to something a person reads", () => {
    expect(duration(500)).toBe("500 ns");
    expect(duration(1_500)).toBe("1.50 µs");
    expect(duration(2_500_000)).toBe("2.50 ms");
    expect(duration(1_250_000_000)).toBe("1.25 s");
    expect(duration(-1)).toBe("—");
  });
});
