/**
 * What the freshness tile is allowed to conclude.
 *
 * The whole value of this tile is the distinction between *"nothing is wrong"* and
 * *"nothing is arriving"*, so the tests are almost entirely about the states in between —
 * a partial silence, a failed read, and a zero that is real. Each of those has a wrong
 * answer that would look completely normal on screen, which is why they are asserted
 * rather than trusted.
 */

import { describe, expect, it } from "vitest";

import type { ResultSet } from "./query";
import {
  type Arrival,
  WATCHED,
  arrivals,
  countOf,
  humanArrivals,
  silent,
  verdict,
} from "./freshness";

const START = "2026-09-23T12:00:00Z";
const END = "2026-09-23T13:00:00Z";

function arrival(over: Partial<Arrival> & Pick<Arrival, "signal">): Arrival {
  return { label: over.signal, count: 0, failed: false, ...over } as Arrival;
}

function result(rows: unknown[][]): ResultSet {
  return {
    columns: [{ name: "n", type: "UInt64" }],
    rows,
    table: "logs",
    warnings: [],
    rows_read: 1,
    bytes_read: 1,
  };
}

describe("the question", () => {
  it("asks for one number and nothing else", () => {
    const q = arrivals("log", START, END);
    // No group_by: the Overview asks this six times, so it has to be the cheapest question
    // a telemetry table can answer.
    expect(q.aggregations).toEqual([{ func: "count", alias: "n" }]);
    expect(q.group_by).toBeUndefined();
    expect(q.signal).toBe("log");
  });

  it("watches every signal the product stores", () => {
    expect(WATCHED.map((w) => w.signal).sort()).toEqual(
      ["event", "flow", "log", "metric", "state", "trace"].sort(),
    );
  });
});

describe("reading the count", () => {
  it("reads a quoted 64-bit count", () => {
    expect(countOf(result([["12345"]]))).toBe(12345);
  });

  it("is null rather than zero when no row came back", () => {
    // An aggregate with no group_by returns exactly one row. No rows means something other
    // than "nothing arrived", and a confident zero there is the lie this module prevents.
    expect(countOf(result([]))).toBeNull();
    expect(countOf(undefined)).toBeNull();
  });

  it("keeps a real zero as zero", () => {
    expect(countOf(result([[0]]))).toBe(0);
  });
});

describe("the verdict", () => {
  it("is quiet when everything that can report did", () => {
    expect(
      verdict([
        arrival({ signal: "metric", count: 10 }),
        arrival({ signal: "log", count: 4 }),
      ]),
    ).toBe("quiet");
  });

  it("is partial when one signal stopped and another did not", () => {
    // The state a single green badge hides, and the reason this tile exists.
    expect(
      verdict([
        arrival({ signal: "metric", count: 10 }),
        arrival({ signal: "log", count: 0 }),
      ]),
    ).toBe("partial");
    expect(
      silent([arrival({ signal: "metric", count: 10, label: "Metrics" }), arrival({ signal: "log", count: 0, label: "Logs" })]),
    ).toEqual(["Logs"]);
  });

  it("is silent when nothing arrived at all", () => {
    expect(
      verdict([
        arrival({ signal: "metric", count: 0 }),
        arrival({ signal: "log", count: 0 }),
      ]),
    ).toBe("silent");
  });

  it("does not let an estate with no traces read as silent", () => {
    // Most deployments of this product are network-only and legitimately have no
    // instrumented applications. Letting that one row decide would make the tile
    // permanently wrong for the majority case.
    expect(
      verdict([
        arrival({ signal: "metric", count: 10 }),
        arrival({ signal: "log", count: 3 }),
        arrival({ signal: "trace", count: 0 }),
      ]),
    ).toBe("quiet");
  });

  it("is unknown rather than silent when nothing has answered", () => {
    // A failed read must never render as "the estate stopped talking".
    expect(verdict([])).toBe("unknown");
    expect(
      verdict([
        arrival({ signal: "metric", count: null, failed: true }),
        arrival({ signal: "log", count: null, failed: true }),
      ]),
    ).toBe("unknown");
  });

  it("is unknown when only traces answered", () => {
    expect(verdict([arrival({ signal: "trace", count: 5 })])).toBe("unknown");
  });

  it("ignores a failed signal rather than counting it as silent", () => {
    expect(
      verdict([
        arrival({ signal: "metric", count: 10 }),
        arrival({ signal: "log", count: null, failed: true }),
      ]),
    ).toBe("quiet");
    expect(silent([arrival({ signal: "log", count: null, failed: true })])).toEqual([]);
  });
});

describe("presentation", () => {
  it("shows a dash rather than a zero for an unknown count", () => {
    expect(humanArrivals(null)).toBe("—");
    expect(humanArrivals(0)).toBe("0");
    expect(humanArrivals(1234)).toBe("1,234");
  });
});
