/**
 * What an objective is allowed to conclude.
 *
 * The important tests here are the ones about *absence*. An SLO screen that reads green
 * because no traffic arrived is the failure that makes people stop believing the whole
 * dashboard, and it is the natural result of computing `good / total` with a zero
 * denominator and rounding the NaN away.
 */

import { describe, expect, it } from "vitest";

import type { ResultSet } from "./query";
import {
  type Slo,
  asPercent,
  attainmentQuery,
  budgetConsumed,
  counted,
  describeWindow,
  isMet,
  sli,
  verdict,
} from "./slo";

function slo(over: Partial<Slo> = {}): Slo {
  return {
    id: "o1",
    name: "checkout",
    description: "",
    service_id: "svc-1",
    target: 0.99,
    window_days: 30,
    ...over,
  };
}

function result(rows: unknown[][]): ResultSet {
  return {
    columns: [
      { name: "g0", type: "UUID" },
      { name: "requests", type: "UInt64" },
      { name: "errors", type: "UInt64" },
    ],
    rows,
    table: "service_5m",
    warnings: [],
    rows_read: 1,
    bytes_read: 1,
  };
}

describe("the question", () => {
  it("covers the objective's window, not the shell's time picker", () => {
    // An SLO over thirty days does not change because somebody set the picker to an hour.
    const now = new Date("2026-09-23T12:00:00Z");
    const q = attainmentQuery(slo({ window_days: 30 }), now);
    expect(q.time.end).toBe("2026-09-23T12:00:00.000Z");
    expect(q.time.start).toBe("2026-08-24T12:00:00.000Z");
  });

  it("groups by service alone so the planner can use service_5m", () => {
    const q = attainmentQuery(slo(), new Date());
    expect(q.group_by).toEqual([{ field: "service_id" }]);
    expect(q.signal).toBe("trace");
  });
});

describe("reading the counts", () => {
  it("reads quoted 64-bit counts", () => {
    expect(counted(result([["svc-1", "1000", "10"]]))).toEqual({
      requests: 1000,
      errors: 10,
    });
  });

  it("treats an empty window as no data rather than as zero traffic", () => {
    expect(counted(result([]))).toBeNull();
    expect(counted(undefined)).toBeNull();
  });

  it("treats a row with no requests as no data", () => {
    expect(counted(result([["svc-1", 0, 0]]))).toBeNull();
  });
});

describe("the indicator", () => {
  it("is the share of sampled requests that succeeded", () => {
    expect(sli({ requests: 1000, errors: 10 })).toBeCloseTo(0.99, 6);
  });

  it("is null for a window with no traffic, never 1", () => {
    // A service nobody called did not succeed. This is the whole reason the type is
    // nullable — an objective reading green because nothing happened is the failure that
    // makes an operator stop believing the screen.
    expect(sli(null)).toBeNull();
    expect(sli({ requests: 0, errors: 0 })).toBeNull();
  });

  it("never reports a negative rate when the aggregates disagree in flight", () => {
    // `requests` and `errors` are summed from different aggregate columns, and a merge in
    // progress can momentarily make errors exceed requests.
    expect(sli({ requests: 10, errors: 12 })).toBe(0);
  });
});

describe("the error budget", () => {
  it("is a proportion consumed, and reaches 1 exactly at the target", () => {
    // 1% allowed, 1% used.
    expect(budgetConsumed(slo({ target: 0.99 }), { requests: 1000, errors: 10 })).toBeCloseTo(1, 6);
    // Half the budget.
    expect(budgetConsumed(slo({ target: 0.99 }), { requests: 1000, errors: 5 })).toBeCloseTo(0.5, 6);
  });

  it("keeps counting past 1 so an operator can see by how much", () => {
    expect(budgetConsumed(slo({ target: 0.99 }), { requests: 1000, errors: 30 })).toBeCloseTo(3, 6);
  });

  it("is null when there was no traffic", () => {
    expect(budgetConsumed(slo(), null)).toBeNull();
  });

  it("does not divide by zero for an objective of 1", () => {
    // The schema refuses this, and the guard stays because the schema is not the only
    // thing that could hand this a target.
    expect(budgetConsumed(slo({ target: 1 }), { requests: 100, errors: 1 })).toBeNull();
  });
});

describe("the verdict", () => {
  it("is unknown for a window with no traffic", () => {
    expect(verdict(slo(), null)).toBe("unknown");
    expect(isMet(slo(), null)).toBeNull();
  });

  it("is met while the budget holds", () => {
    expect(verdict(slo({ target: 0.99 }), { requests: 10_000, errors: 10 })).toBe("met");
    expect(isMet(slo({ target: 0.99 }), { requests: 10_000, errors: 10 })).toBe(true);
  });

  it("is at risk at three quarters of the budget", () => {
    expect(verdict(slo({ target: 0.99 }), { requests: 1000, errors: 8 })).toBe("at-risk");
  });

  it("is missed once the budget is spent", () => {
    expect(verdict(slo({ target: 0.99 }), { requests: 1000, errors: 11 })).toBe("missed");
    expect(isMet(slo({ target: 0.99 }), { requests: 1000, errors: 11 })).toBe(false);
  });

  it("exactly at the target is met rather than missed", () => {
    // 99% of 1000 with 10 errors is exactly the objective. A boundary that reads as a
    // miss would make every objective one request stricter than it says.
    expect(isMet(slo({ target: 0.99 }), { requests: 1000, errors: 10 })).toBe(true);
  });
});

describe("presentation", () => {
  it("keeps the digits that distinguish one objective from another", () => {
    // 99.9 and 99.95 are different objectives; one decimal place makes them one number.
    expect(asPercent(0.999)).toBe("99.9%");
    expect(asPercent(0.9995)).toBe("99.95%");
    expect(asPercent(0.995)).toBe("99.5%");
  });

  it("describes a window the way somebody says it", () => {
    expect(describeWindow(1)).toBe("24 hours");
    expect(describeWindow(30)).toBe("30 days");
    expect(describeWindow(45)).toBe("45 days");
  });
});
