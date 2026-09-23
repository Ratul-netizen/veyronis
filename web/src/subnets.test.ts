/**
 * What the address screen is allowed to say about a range.
 *
 * These are almost all about refusing to overstate. An address inventory's numbers look
 * authoritative, and this product's are not — it reports what answered and what the
 * inventory claims, not what a DHCP server has leased. Each test below pins one place
 * where the confident version of the number would be wrong.
 */

import { describe, expect, it } from "vitest";

import {
  type Subnet,
  describeGuess,
  inAddressOrder,
  needsAttention,
  occupancy,
  unknownAddresses,
} from "./subnets";

function subnet(over: Partial<Subnet> = {}): Subnet {
  return {
    id: "s1",
    range: "10.0.0.0/24",
    name: "range",
    description: "",
    assignment: "static",
    capacity: 254,
    assigned: 0,
    responding: 0,
    unaccounted: 0,
    ...over,
  };
}

describe("what is left in a range", () => {
  it("counts an address once when it is both assigned and responding", () => {
    // The ordinary case: a device that was discovered and then classified is in both
    // numbers. Adding them would report a /24 with two devices as having four.
    const s = subnet({ assigned: 2, responding: 2 });
    expect(unknownAddresses(s)).toBe(252);
  });

  it("does not go negative when an identifier sits outside the usable range", () => {
    // Somebody records a management address on the broadcast address. It happens, and a
    // negative "free" count is a screen nobody trusts again.
    expect(unknownAddresses(subnet({ capacity: 2, assigned: 5 }))).toBe(0);
  });

  it("treats a /31 as having two usable addresses", () => {
    // RFC 3021. The schema computes this; the screen must not re-derive it wrongly.
    expect(unknownAddresses(subnet({ capacity: 2, assigned: 1 }))).toBe(1);
  });
});

describe("occupancy", () => {
  it("is a fraction for a bar and never exceeds one", () => {
    expect(occupancy(subnet({ capacity: 254, assigned: 127 }))).toBeCloseTo(0.5, 3);
    expect(occupancy(subnet({ capacity: 10, responding: 50 }))).toBe(1);
  });

  it("is null rather than infinite when there is no capacity", () => {
    expect(occupancy(subnet({ capacity: 0 }))).toBeNull();
  });
});

describe("attention", () => {
  it("is drawn only by something answering that nothing claims", () => {
    // The single judgement this screen makes. A full range is not a problem; a stranger
    // in it is.
    expect(needsAttention(subnet({ assigned: 254, capacity: 254 }))).toBe(false);
    expect(needsAttention(subnet({ unaccounted: 1 }))).toBe(true);
  });
});

describe("ordering", () => {
  it("reads address space numerically, not alphabetically", () => {
    // "10.0.10.0/24" sorts before "10.0.9.0/24" as text, and an operator scanning a list
    // for a gap will not find one that is in the wrong place.
    const ordered = inAddressOrder([
      subnet({ range: "10.0.10.0/24" }),
      subnet({ range: "10.0.9.0/24" }),
      subnet({ range: "10.0.2.0/24" }),
    ]);
    expect(ordered.map((s) => s.range)).toEqual([
      "10.0.2.0/24",
      "10.0.9.0/24",
      "10.0.10.0/24",
    ]);
  });

  it("orders ranges above 127 correctly", () => {
    // A bit shift would overflow into a negative here, which would sort the whole of
    // 192.168 space before 10.
    const ordered = inAddressOrder([
      subnet({ range: "192.168.1.0/24" }),
      subnet({ range: "10.0.0.0/24" }),
      subnet({ range: "172.16.0.0/24" }),
    ]);
    expect(ordered.map((s) => s.range)).toEqual([
      "10.0.0.0/24",
      "172.16.0.0/24",
      "192.168.1.0/24",
    ]);
  });

  it("does not throw on a range it cannot parse", () => {
    expect(() => inAddressOrder([subnet({ range: "nonsense" })])).not.toThrow();
  });
});

describe("describing a guess", () => {
  const base = { role: "printer", confidence: "likely" as const, because: [] };

  it("hedges in the sentence rather than in a badge", () => {
    // A badge is read as fact by the second time somebody sees it; a sentence is not.
    expect(describeGuess(base)).toBe("probably a printer");
    expect(describeGuess({ ...base, confidence: "possible" })).toBe("possibly a printer");
  });

  it("falls back to the manufacturer when the role is unknown", () => {
    // "Cisco" beats nothing, which is the whole argument for keeping the vendor.
    expect(describeGuess({ role: "unknown", confidence: "unknown", because: [], vendor: "Cisco Systems, Inc" }))
      .toBe("made by Cisco Systems, Inc");
  });

  it("says unidentified rather than inventing something", () => {
    expect(describeGuess({ role: "unknown", confidence: "unknown", because: [] }))
      .toBe("unidentified");
  });

  it("reads a multi-word role as words", () => {
    expect(describeGuess({ ...base, role: "access_point" })).toBe("probably a access point");
  });
});
