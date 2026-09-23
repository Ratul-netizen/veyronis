/**
 * What the path screen is allowed to conclude.
 *
 * The one to read first is `private_space_is_not_ownership`. It pins a correction made
 * after looking at real output rather than at the code: RFC 1918 means *not globally
 * routable*, and a private hop is as likely to be the carrier's as the estate's.
 */

import { describe, expect, it } from "vitest";

import {
  type Hop,
  type PathResult,
  describeScope,
  humanRtt,
  leavesPrivateSpaceAt,
  slowestHop,
  summarise,
} from "./path";

function hop(over: Partial<Hop> & Pick<Hop, "number">): Hop {
  return {
    address: `10.0.0.${over.number}`,
    scope: "private",
    not_public: true,
    rtt_ms: [1],
    ...over,
  };
}

function result(over: Partial<PathResult> = {}): PathResult {
  return { target: "1.1.1.1", hops: [], reached: false, raw: "", ...over };
}

describe("where the address space changes", () => {
  it("finds the first hop off private space", () => {
    const hops = [
      hop({ number: 1 }),
      hop({ number: 2 }),
      hop({ number: 3, scope: "carrier_grade", not_public: false, address: "100.64.0.1" }),
      hop({ number: 4, scope: "public", not_public: false, address: "1.1.1.1" }),
    ];
    expect(leavesPrivateSpaceAt(hops)).toBe(3);
  });

  it("is null for a path that never leaves, which is the ordinary internal case", () => {
    expect(leavesPrivateSpaceAt([hop({ number: 1 }), hop({ number: 2 })])).toBeNull();
  });

  it("ignores hops that did not answer", () => {
    // A silent hop has no address and therefore no scope to change at.
    const hops = [
      hop({ number: 1 }),
      { number: 2, scope: "unknown" as const, not_public: false, rtt_ms: [null] },
      hop({ number: 3, scope: "public", not_public: false, address: "1.1.1.1" }),
    ];
    expect(leavesPrivateSpaceAt(hops)).toBe(3);
  });
});

describe("private space is not ownership", () => {
  it("separates carrier space from both private and public", () => {
    // The first real trace crossed 10.153.77.1 and 10.20.251.97 — the ISP's own RFC 1918
    // routers — before reaching 100.64/10. Three names, because two would put the
    // operator's responsibility in the wrong place.
    expect(describeScope("private")).toBe("private");
    expect(describeScope("carrier_grade")).toBe("carrier");
    expect(describeScope("public")).toBe("public");
  });

  it("names every scope the server can send", () => {
    for (const s of ["private", "carrier_grade", "link_local", "loopback", "public", "unknown"] as const) {
      expect(describeScope(s)).not.toBe("");
    }
  });
});

describe("what the path says as a whole", () => {
  it("distinguishes arriving from running out of hops", () => {
    expect(summarise(result({ hops: [hop({ number: 1 })], reached: true }))).toContain("Reached in 1 hop");
    const stalled = summarise(
      result({
        hops: [hop({ number: 1, address: "10.0.0.1" }), { number: 2, scope: "unknown", not_public: false, rtt_ms: [null] }],
      }),
    );
    expect(stalled).toContain("Did not arrive");
    expect(stalled).toContain("10.0.0.1");
  });

  it("says nothing answered rather than showing an empty table", () => {
    expect(summarise(result())).toContain("Nothing answered");
  });

  it("handles a path where no hop answered at all", () => {
    const silent = result({
      hops: [{ number: 1, scope: "unknown", not_public: false, rtt_ms: [null] }],
    });
    expect(summarise(silent)).toContain("no hop answered");
  });
});

describe("presentation", () => {
  it("keeps a decimal place for sub-millisecond hops", () => {
    // "<1 ms" arrives as 0.5 from the parser. Rounding it would print "0 ms".
    expect(humanRtt(0.5)).toBe("0.5 ms");
    expect(humanRtt(3)).toBe("3.0 ms");
    expect(humanRtt(42.4)).toBe("42 ms");
  });

  it("scales bars against the slowest hop, or none at all", () => {
    expect(slowestHop([hop({ number: 1, best_ms: 2 }), hop({ number: 2, best_ms: 40 })])).toBe(40);
    expect(slowestHop([{ number: 1, scope: "unknown", not_public: false, rtt_ms: [null] }])).toBeNull();
  });
});
