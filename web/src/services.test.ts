/**
 * The services screen's logic, and mostly the one thing it must never do.
 *
 * §2.3: a count of spans is a count of *sampled* spans. There is no rate to scale it up
 * by, so the only honest thing a screen can do is name it for what it is — which makes
 * the naming a testable property rather than a matter of taste.
 */

import { describe, expect, it } from "vitest";

import {
  errorRate,
  humanCount,
  humanDuration,
  humanPercent,
  serviceLatency,
  serviceName,
  services,
  TOP_N,
} from "./services";
import type { ResultSet } from "./query";

function result(rows: unknown[][]): ResultSet {
  return {
    columns: [
      { name: "g0", type: "UUID" },
      { name: "requests", type: "UInt64" },
      { name: "errors", type: "UInt64" },
      { name: "p50", type: "UInt64" },
      { name: "p95", type: "UInt64" },
      { name: "p99", type: "UInt64" },
    ],
    rows,
    table: "service_5m",
    warnings: [],
    rows_read: rows.length,
    bytes_read: 0,
  };
}

const SERVICE = "018f0000-0000-7000-8000-0000000000aa";

describe("the query", () => {
  it("groups by the service alone, so the aggregate can answer it", () => {
    // `service_5m` is ordered service-first and carries no `resource_id` at all, because
    // a service runs on many hosts. Adding one to this grouping would move the query onto
    // raw spans and answer a different question — M8 §2.1.
    const q = serviceLatency("2026-09-01T00:00:00Z", "2026-09-01T01:00:00Z");
    expect(q.signal).toBe("trace");
    expect(q.group_by).toEqual([{ field: "service_id" }]);
    expect(q.resources).toEqual({ type: "all" });
  });

  it("asks only for the percentiles the stored state holds", () => {
    // The quantiles are part of the column's type — `quantilesTDigest(0.5, 0.95, 0.99)`.
    // A p90 is not a missing feature, it is a number the state does not contain, and the
    // planner would send the whole query to raw spans to get one.
    const funcs = serviceLatency("a", "b").aggregations?.map((a) => a.func);
    expect(funcs).toEqual(["count", "sum", "p50", "p95", "p99"]);
  });

  it("counts failures with the derived field rather than a status filter", () => {
    // `errors` is `status_code = 'error'` on raw spans and a stored column on the
    // aggregate. Filtering on `status_code` instead would be a question the aggregate
    // cannot answer, and the whole query would fall back to raw spans.
    const q = serviceLatency("a", "b");
    expect(q.aggregations).toContainEqual({
      func: "sum",
      field: { field: "errors" },
      alias: "errors",
    });
    expect(q.filter).toBeUndefined();
  });

  it("defaults to a readable number of services", () => {
    expect(serviceLatency("a", "b").limit).toBe(TOP_N);
  });
});

describe("reading the result", () => {
  it("round-trips a row the server actually sends", () => {
    // Positional group columns: the compiler names them g0, g1, … in `group_by` order, so
    // this test is what keeps the reader and the query in step.
    const rows = services(result([[SERVICE, "101", "1", "5000000", "95000000", "99000000"]]));
    expect(rows).toEqual([
      {
        serviceId: SERVICE,
        sampledRequests: 101,
        sampledErrors: 1,
        p50Ns: 5_000_000,
        p95Ns: 95_000_000,
        p99Ns: 99_000_000,
      },
    ]);
  });

  it("reads a 64-bit count however ClickHouse encoded it", () => {
    // They arrive quoted when `output_format_json_quote_64bit_integers` is on, and a
    // nanosecond duration is exactly the column where that matters.
    const quoted = services(result([[SERVICE, "7", "0", "1", "2", "3"]]))[0];
    const bare = services(result([[SERVICE, 7, 0, 1, 2, 3]]))[0];
    expect(quoted).toEqual(bare);
  });

  it("returns nothing when a column it asked for is missing", () => {
    // The query and the reader have drifted. A partial row would be one service's latency
    // beside another's count, which is worse than an empty table.
    const missing: ResultSet = {
      ...result([[SERVICE, "1", "0", "1", "2", "3"]]),
      columns: [{ name: "g0", type: "UUID" }],
    };
    expect(services(missing)).toEqual([]);
  });

  it("names every count for what it is", () => {
    // The assertion this file exists for. A field called `requests` is one a component
    // renders as a total without ever deciding to; `sampledRequests` is one somebody has
    // to think about. §2.3.
    const [row] = services(result([[SERVICE, "1", "0", "1", "2", "3"]]));
    expect(Object.keys(row ?? {})).toEqual([
      "serviceId",
      "sampledRequests",
      "sampledErrors",
      "p50Ns",
      "p95Ns",
      "p99Ns",
    ]);
  });
});

describe("the error rate", () => {
  it("is null rather than zero when nothing was sampled", () => {
    // A service nobody called has no error rate. 0% would say it was healthy, when what
    // happened is that nobody asked it anything.
    expect(errorRate({ sampledRequests: 0, sampledErrors: 0 })).toBeNull();
    expect(errorRate({ sampledRequests: 0, sampledErrors: 5 })).toBeNull();
  });

  it("is the share of what was sampled", () => {
    expect(errorRate({ sampledRequests: 200, sampledErrors: 4 })).toBeCloseTo(0.02);
  });

  it("does not round a small rate away to nothing", () => {
    // One failure in ten thousand is not 0%, and printing it as 0% is the difference
    // between a service that is fine and one that is quietly dropping requests.
    expect(humanPercent(0.0001)).toBe("<0.1%");
    expect(humanPercent(0)).toBe("0%");
    expect(humanPercent(0.023)).toBe("2.3%");
    expect(humanPercent(0.5)).toBe("50%");
  });
});

describe("durations", () => {
  it("picks a unit per value, because a map mixes cache lookups with reports", () => {
    expect(humanDuration(500)).toBe("500 ns");
    expect(humanDuration(1_500)).toBe("1.5 µs");
    expect(humanDuration(200_000)).toBe("200 µs");
    expect(humanDuration(1_500_000)).toBe("1.5 ms");
    expect(humanDuration(95_000_000)).toBe("95 ms");
    expect(humanDuration(2_400_000_000)).toBe("2.4 s");
  });

  it("shows a zero duration as zero rather than as nothing", () => {
    // `duration_ns` is 0 on a span whose end never arrived, and the decoder records why
    // in the row's attributes. Here it is just a zero, and a blank cell would read as a
    // missing column.
    expect(humanDuration(0)).toBe("0 ms");
    expect(humanDuration(Number.NaN)).toBe("0 ms");
  });
});

describe("naming a service", () => {
  it("falls back to the id rather than to a placeholder", () => {
    // The inventory is a separate read from a separate plane, so it can be absent for a
    // moment. "Unknown service" is a claim; an id is a fact somebody can paste into a
    // search. The context bar made the same choice in §13.
    expect(serviceName(SERVICE, new Map())).toBe(SERVICE);
    expect(serviceName(SERVICE, new Map([[SERVICE, "checkout"]]))).toBe("checkout");
  });
});

describe("counts", () => {
  it("groups thousands, because a span count gets large", () => {
    expect(humanCount(1234567)).toBe("1,234,567");
  });
});
