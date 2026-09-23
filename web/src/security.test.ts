/**
 * What the security screen asks, and what it is allowed to say — M11.
 *
 * These are query builders, so the tests are about the *shape of the question*. That is
 * worth testing rather than trusting: a filter that quietly stopped matching would make a
 * table of denials into a table of everything, and the screen would look identical.
 */

import { describe, expect, it } from "vitest";

import type { ResultSet } from "./query";
import {
  CATEGORIES,
  LIMIT,
  count,
  describeCategory,
  events,
  failuresBySource,
  failuresByUser,
  grouped,
  isRefusal,
  denialsFor,
  recentEvents,
  reportingDevices,
  unresolvedNames,
} from "./security";

const FROM = "2026-09-23T00:00:00Z";
const TO = "2026-09-23T01:00:00Z";

/** Every query this screen builds. */
const ALL = [
  recentEvents(FROM, TO),
  failuresBySource(FROM, TO),
  failuresByUser(FROM, TO),
  unresolvedNames(FROM, TO),
];

describe("every query the screen builds", () => {
  it("asks the events table and nothing else", () => {
    // M11 §2.1: a security event is an `events` row. A query here against `log` would be
    // reading the raw text the event was derived from, which is a different question.
    for (const query of ALL) {
      expect(query.signal).toBe("event");
    }
  });

  it("carries the window it was given", () => {
    for (const query of ALL) {
      expect(query.time).toEqual({ start: FROM, end: TO });
    }
  });

  it("is bounded", () => {
    // An unbounded group-by over a busy firewall feed is a page that never renders.
    for (const query of ALL) {
      expect(query.limit).toBeGreaterThan(0);
    }
  });
});

describe("the failed-authentication tables", () => {
  it("count failures and distinct counterparties, which is the pair §2.4 groups on", () => {
    // Twenty failures against one account is somebody mistyping; twenty against five
    // accounts from one address is not. The second number is what separates them, and a
    // table with only the first cannot.
    const bySource = failuresBySource(FROM, TO);
    expect(bySource.group_by).toEqual([{ field: "attr", key: "source.ip" }]);
    expect(bySource.aggregations?.map((a) => a.func)).toEqual(["count", "count_distinct"]);
    expect(bySource.aggregations?.[1]?.field).toEqual({ field: "attr", key: "user.name" });

    const byUser = failuresByUser(FROM, TO);
    expect(byUser.group_by).toEqual([{ field: "attr", key: "user.name" }]);
    expect(byUser.aggregations?.[1]?.field).toEqual({ field: "attr", key: "source.ip" });
  });

  it("are the two halves of one pair, not one query twice", () => {
    // One account failing from many addresses is invisible in the per-source table — each
    // address on its own has few failures. That asymmetry is why there are two.
    const bySource = failuresBySource(FROM, TO);
    const byUser = failuresByUser(FROM, TO);
    expect(bySource.group_by).not.toEqual(byUser.group_by);
  });

  it("filter to failures, so a success is never counted as one", () => {
    const filter = failuresBySource(FROM, TO).filter;
    const said = JSON.stringify(filter);
    expect(said).toContain("authentication");
    expect(said).toContain("failure");
    expect(said).not.toContain("success");
  });

  it("order by failures, so the table opens on what somebody is looking for", () => {
    for (const query of [failuresBySource(FROM, TO), failuresByUser(FROM, TO)]) {
      expect(query.order_by?.[0]).toEqual({
        key: { by: "alias", alias: "failures" },
        desc: true,
      });
      expect(query.limit).toBe(LIMIT);
    }
  });
});

describe("the unresolved-name table", () => {
  it("counts only the names that did not resolve", () => {
    const query = unresolvedNames(FROM, TO);
    expect(query.filter).toEqual({
      op: "compare",
      field: { field: "attr", key: "dns.response_code" },
      cmp: "eq",
      value: "NXDOMAIN",
    });
    expect(query.group_by).toEqual([{ field: "attr", key: "dns.question.name" }]);
  });

  it("asks for a count and nothing cleverer", () => {
    // §2.5. Reputation, entropy and DGA scoring need a feed this product will not ship or
    // a model whose false-positive rate nobody here has measured. This is a frequency
    // table.
    const query = unresolvedNames(FROM, TO);
    expect(query.aggregations?.map((a) => a.func)).toEqual(["count"]);
  });
});

describe("the recent list", () => {
  it("is newest first and unaggregated", () => {
    // What the devices said, not a summary of it.
    const query = recentEvents(FROM, TO);
    expect(query.aggregations).toBeUndefined();
    expect(query.order_by?.[0]?.desc).toBe(true);
  });

  it("filters by category only when one is chosen", () => {
    expect(recentEvents(FROM, TO).filter).toBeUndefined();
    expect(JSON.stringify(recentEvents(FROM, TO, "dns").filter)).toContain("dns");
  });
});

describe("what the screen says", () => {
  it("describes every category it offers", () => {
    for (const category of CATEGORIES) {
      expect(describeCategory(category).length).toBeGreaterThan(0);
    }
    // A category the backend grew and this build has not heard of renders as itself rather
    // than as blank.
    expect(describeCategory("process")).toBe("process");
  });

  it("never calls anything an attack", () => {
    // M11 §1's last row: this product reports what a device said. An assertion that
    // something is malicious is a claim that needs an analyst.
    const said = CATEGORIES.map(describeCategory).join(" ").toLowerCase();
    for (const verdict of ["attack", "malicious", "threat", "suspicious", "breach"]) {
      expect(said).not.toContain(verdict);
    }
  });

  it("marks a refusal without hiding anything else", () => {
    expect(isRefusal("denied")).toBe(true);
    expect(isRefusal("failure")).toBe(true);
    // An allowed event is not less true than a denied one, and dropping them would make
    // "how much does this firewall pass" unanswerable.
    expect(isRefusal("allowed")).toBe(false);
    expect(isRefusal("start")).toBe(false);
  });
});

describe("reading a result", () => {
  const result = (columns: string[], rows: unknown[][]): ResultSet => ({
    columns: columns.map((name) => ({ name, type: "String" })),
    rows,
    table: "events",
    warnings: [],
    rows_read: rows.length,
    bytes_read: 0,
  });

  it("reads a grouped table by column name rather than by position", () => {
    // The server sends JSONCompact — values in column order, no names — so a screen that
    // read `row[1]` directly would break silently when a column was added.
    const rows = grouped(
      result(
        ["source.ip", "failures", "users"],
        [["198.51.100.7", 20, 5]],
      ),
    );
    expect(rows).toEqual([
      { key: "198.51.100.7", counts: { failures: 20, users: 5 } },
    ]);
  });

  it("reads a count however ClickHouse encoded it", () => {
    // `UInt64` arrives quoted or unquoted depending on a server setting and on the
    // aggregate's result type. Reading only one form makes every value zero, which looks
    // exactly like an empty table.
    expect(count(12)).toBe(12);
    expect(count("12")).toBe(12);
    expect(count(null)).toBe(0);
    expect(count("not a number")).toBe(0);
  });

  it("renders an unexpected result shape rather than crashing on it", () => {
    // The query asks for no explicit projection, so what comes back is whatever the
    // compiler chose. A blank cell beats a blank screen.
    const rows = events(result(["observed_at", "summary"], [["2026-09-23T00:00:00Z", "Denied"]]));
    expect(rows[0]?.summary).toBe("Denied");
    expect(rows[0]?.category).toBe("");
    expect(events(undefined)).toEqual([]);
    expect(grouped(undefined)).toEqual([]);
  });
});

describe("one device, both signals — §2.6", () => {
  const DEVICE = "11111111-2222-3333-4444-555555555555";

  it("scopes the denials to one device", () => {
    const query = denialsFor(DEVICE, FROM, TO);
    expect(query.resources).toEqual({ type: "ids", ids: [DEVICE] });
    expect(query.signal).toBe("event");
  });

  it("asks for refusals and not for everything the device reported", () => {
    const said = JSON.stringify(denialsFor(DEVICE, FROM, TO).filter);
    expect(said).toContain("network");
    expect(said).toContain("denied");
    expect(said).not.toContain("allowed");
  });

  it("does not aggregate, because the rows are the evidence", () => {
    // A count of denials is the table further up the page. This section is the lines
    // themselves, beside the traffic, for somebody deciding whether they are related.
    expect(denialsFor(DEVICE, FROM, TO).aggregations).toBeUndefined();
  });

  it("offers only devices that reported something", () => {
    // Taken from the events already on screen. A device with no security events has
    // nothing on either side of the comparison, and offering it would be offering an
    // empty answer.
    const rows = [
      { observedAt: "t1", category: "network", type: "denied", summary: "", resourceId: "a" },
      { observedAt: "t2", category: "network", type: "allowed", summary: "", resourceId: "b" },
      { observedAt: "t3", category: "network", type: "denied", summary: "", resourceId: "a" },
      { observedAt: "t4", category: "dns", type: "query", summary: "", resourceId: "" },
    ];
    // Deduplicated, in the order they were first seen, and a row with no resource is not
    // a device.
    expect(reportingDevices(rows)).toEqual(["a", "b"]);
    expect(reportingDevices([])).toEqual([]);
  });
});
