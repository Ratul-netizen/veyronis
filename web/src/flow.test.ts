/**
 * The flow screen's arithmetic — M7 §2.4, on the read side.
 *
 * The one thing that must not go wrong here is presenting an extrapolation as a
 * measurement, so most of these are about `estimated` rather than about `value`.
 */

import { describe, expect, it } from "vitest";

import {
  conversations,
  displayAddress,
  humanBytes,
  humanCount,
  hasPorts,
  protocolName,
  topTalkers,
  traffic,
} from "./flow";
import type { ResultSet } from "./query";

function result(rows: unknown[][]): ResultSet {
  return {
    columns: [
      { name: "g0", type: "IPv6" },
      { name: "g1", type: "IPv6" },
      { name: "g2", type: "UInt16" },
      { name: "g3", type: "UInt8" },
      { name: "g4", type: "UInt32" },
      { name: "bytes", type: "UInt64" },
      { name: "packets", type: "UInt64" },
    ],
    rows,
    table: "flows_5m",
    warnings: [],
    rows_read: rows.length,
    bytes_read: 0,
  };
}

describe("topTalkers", () => {
  it("groups by the sampling rate, which is what lets the aggregate answer it", () => {
    // The planner refuses `flows_5m` for a summed query that drops the rate, because
    // adding traffic sampled 1-in-1000 to traffic sampled 1-in-1 is meaningless. Losing
    // this line would quietly move the screen onto the raw table *and* make its numbers
    // wrong at the same time.
    const q = topTalkers("2026-09-01T00:00:00Z", "2026-09-01T01:00:00Z");
    expect(q.group_by).toContainEqual({ field: "sampling_rate" });
    expect(q.signal).toBe("flow");
  });

  it("orders by traffic, descending, because the question is 'what is busiest'", () => {
    const q = topTalkers("2026-09-01T00:00:00Z", "2026-09-01T01:00:00Z");
    expect(q.order_by).toEqual([{ key: { by: "alias", alias: "bytes" }, desc: true }]);
  });
});

describe("traffic", () => {
  it("multiplies by the sampling rate", () => {
    expect(traffic(6000, 1000).value).toBe(6_000_000);
  });

  it("marks a sampled figure as an estimate", () => {
    expect(traffic(6000, 1000).estimated).toBe(true);
  });

  it("does not mark an unsampled figure, because it is a measurement", () => {
    // The distinction the whole screen turns on. A rate of 1 means every packet was
    // seen, so there is nothing uncertain to warn about — and marking it anyway would
    // train people to ignore the mark where it matters.
    const t = traffic(6000, 1);
    expect(t.value).toBe(6000);
    expect(t.estimated).toBe(false);
  });
});

describe("conversations", () => {
  it("reads the grouped columns in the order topTalkers grouped them", () => {
    const rows = conversations(
      result([["::ffff:10.0.0.7", "::ffff:8.8.8.8", 443, 6, 1000, "6000", "42"]]),
    );

    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual({
      src: "::ffff:10.0.0.7",
      dst: "::ffff:8.8.8.8",
      port: 443,
      protocol: 6,
      samplingRate: 1000,
      observedBytes: 6000,
      observedPackets: 42,
    });
  });

  it("reads 64-bit counts that arrived as strings", () => {
    // ClickHouse quotes 64-bit integers in JSON by default, and a byte count is exactly
    // the column where that bites: `"6000" * 1000` is a number, but `"6000"` compared
    // against anything is not.
    const rows = conversations(
      result([["::ffff:10.0.0.1", "::ffff:10.0.0.2", 53, 17, "1", "18446744073", "9"]]),
    );
    expect(rows[0]?.observedBytes).toBe(18_446_744_073);
    expect(rows[0]?.samplingRate).toBe(1);
  });

  it("never reports a sampling rate below one, whatever arrived", () => {
    // Every consumer multiplies by this. A zero would turn the row's traffic into
    // nothing, silently, for one misconfigured exporter.
    const rows = conversations(
      result([["::ffff:10.0.0.1", "::ffff:10.0.0.2", 53, 17, 0, "100", "2"]]),
    );
    expect(rows[0]?.samplingRate).toBe(1);
    expect(traffic(rows[0]!.observedBytes, rows[0]!.samplingRate).value).toBe(100);
  });

  it("returns nothing when a column it needs is absent", () => {
    // The query and the server have drifted. A partial row would be a conversation with
    // somebody else's address in it, which is worse than an empty table.
    const missing: ResultSet = {
      ...result([["a", "b", 1, 6, 1, "1", "1"]]),
      columns: [
        { name: "g0", type: "IPv6" },
        { name: "bytes", type: "UInt64" },
      ],
    };
    expect(conversations(missing)).toEqual([]);
  });

  it("handles an empty result", () => {
    expect(conversations(result([]))).toEqual([]);
  });
});

describe("displayAddress", () => {
  it("unmaps an IPv4 address stored in the IPv6 column", () => {
    // One column holds both families, so a v4 address comes back mapped. An operator
    // looking for 10.0.0.7 should not have to decode ::ffff:10.0.0.7.
    expect(displayAddress("::ffff:10.0.0.7")).toBe("10.0.0.7");
  });

  it("leaves a real IPv6 address alone", () => {
    expect(displayAddress("2001:db8::1")).toBe("2001:db8::1");
  });

  it("leaves anything it does not recognise alone rather than guessing", () => {
    expect(displayAddress("::1")).toBe("::1");
    expect(displayAddress("")).toBe("");
  });
});

describe("protocolName", () => {
  it("names the ones worth naming", () => {
    expect(protocolName(6)).toBe("TCP");
    expect(protocolName(17)).toBe("UDP");
    expect(protocolName(1)).toBe("ICMP");
  });

  it("shows the number for anything else rather than inventing a name", () => {
    expect(protocolName(253)).toBe("253");
  });
});

describe("humanBytes", () => {
  it("counts in decimal, because network equipment does", () => {
    // A vendor's "1 Gbps" is 10^9. Reading 1 000 000 000 as 0.93 GB would disagree with
    // every interface counter it sits beside.
    expect(humanBytes(1000)).toBe("1.0 kB");
    expect(humanBytes(1_000_000)).toBe("1.0 MB");
    expect(humanBytes(6_000_000)).toBe("6.0 MB");
  });

  it("shows whole bytes without a decimal point", () => {
    expect(humanBytes(0)).toBe("0 B");
    expect(humanBytes(512)).toBe("512 B");
  });

  it("drops the decimal once the number is large enough not to need it", () => {
    expect(humanBytes(15_400_000)).toBe("15 MB");
  });

  it("does not run out of units", () => {
    expect(humanBytes(5e18)).toContain("PB");
  });
});

describe("humanCount", () => {
  it("groups thousands, because a packet count is read at a glance", () => {
    expect(humanCount(42)).toBe("42");
    expect(humanCount(1_234_567)).toBe("1,234,567");
  });
});

describe("hasPorts", () => {
  it("is true for the protocols that have them", () => {
    expect(hasPorts(6)).toBe(true);
    expect(hasPorts(17)).toBe(true);
  });

  it("is false for ICMP, whose port column holds a zero that means nothing", () => {
    // The same rule the decoders follow for an AS number: a legitimate value must not
    // stand in for an absent one.
    expect(hasPorts(1)).toBe(false);
    expect(hasPorts(58)).toBe(false);
  });
});
