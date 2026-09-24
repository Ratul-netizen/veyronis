import { describe, expect, it } from "vitest";

import {
  SLUG_MAX,
  type Tenant,
  retireConsequences,
  slugProblem,
  suggestSlug,
  whyNotRetire,
} from "./tenants";

function tenant(over: Partial<Tenant> = {}): Tenant {
  return {
    id: "018f0000-0000-7000-8000-00000000aaaa",
    name: "A Customer",
    slug: "a-customer",
    created_at: "2026-09-01T10:00:00Z",
    is_platform: false,
    members: 3,
    ...over,
  };
}

describe("the slug rule", () => {
  it("accepts what migration 0031 accepts", () => {
    expect(slugProblem("acme")).toBeNull();
    expect(slugProblem("acme-north")).toBeNull();
    expect(slugProblem("a1")).toBeNull();
    expect(slugProblem("x".repeat(SLUG_MAX))).toBeNull();
  });

  it("refuses what it refuses, with a sentence rather than a pattern", () => {
    expect(slugProblem("a")).toMatch(/at least/i);
    expect(slugProblem("x".repeat(SLUG_MAX + 1))).toMatch(/at most/i);
    expect(slugProblem("Acme")).toMatch(/lowercase/i);
    expect(slugProblem("with space")).toMatch(/lowercase/i);
    expect(slugProblem("under_score")).toMatch(/lowercase/i);
    expect(slugProblem("-leading")).toMatch(/hyphen/i);
    expect(slugProblem("trailing-")).toMatch(/hyphen/i);
    expect(slugProblem("double--hyphen")).toMatch(/one hyphen/i);
  });
});

describe("suggesting a slug from a name", () => {
  it("does the obvious thing", () => {
    expect(suggestSlug("Acme North")).toBe("acme-north");
    expect(suggestSlug("ACME")).toBe("acme");
  });

  it("never suggests something the server would refuse", () => {
    // The property that matters: whatever it returns is either valid or empty, so it cannot
    // put the form into a state the database will reject.
    for (const name of [
      "Müller & Co.",
      "   ",
      "!!!",
      "A",
      "-leading-",
      "double  space",
      "x".repeat(200),
      "ünïcödé çø",
      "7",
    ]) {
      const suggested = suggestSlug(name);
      if (suggested !== "") {
        expect(slugProblem(suggested), `for ${name}`).toBeNull();
      }
    }
  });

  it("gives up rather than guessing when there is nothing to work with", () => {
    // A name with no ASCII letters or digits has no honest short form, and the field stays
    // editable — a customer should not have its short name decided by a transliteration table.
    expect(suggestSlug("Müller")).toBe("m-ller");
    expect(suggestSlug("!!!")).toBe("");
    expect(suggestSlug("A")).toBe("");
  });

  it("truncates without leaving a trailing hyphen", () => {
    const long = `${"a".repeat(SLUG_MAX - 1)} b`;
    const suggested = suggestSlug(long);
    expect(slugProblem(suggested)).toBeNull();
    expect(suggested.endsWith("-")).toBe(false);
  });
});

describe("whether a tenant can be retired", () => {
  it("refuses the platform tenant and says what to do first", () => {
    const platform = tenant({ is_platform: true });
    const other = tenant({ id: "other", slug: "other" });
    expect(whyNotRetire(platform, [platform, other])).toMatch(/Nominate another/);
  });

  it("refuses the only live tenant", () => {
    const only = tenant();
    expect(whyNotRetire(only, [only])).toMatch(/only tenant left/);
  });

  it("counts retired tenants as not standing in the way", () => {
    const live = tenant();
    const gone = tenant({ id: "gone", slug: "gone", retired_at: "2026-09-02T00:00:00Z" });
    expect(whyNotRetire(live, [live, gone])).toMatch(/only tenant left/);
  });

  it("allows it when another live one remains", () => {
    const one = tenant();
    const two = tenant({ id: "two", slug: "two" });
    expect(whyNotRetire(one, [one, two])).toBeNull();
  });

  it("says nothing about one that is already retired", () => {
    const gone = tenant({ retired_at: "2026-09-02T00:00:00Z" });
    expect(whyNotRetire(gone, [gone])).toBeNull();
  });
});

describe("what somebody is told before retiring one", () => {
  const said = (t: Tenant) => retireConsequences(t).join(" ");

  it("says scheduling stops and names the tenant", () => {
    expect(said(tenant())).toMatch(/Polling, sweeping and alerting stop for A Customer/);
  });

  it("counts who loses access, in the singular when it is one", () => {
    expect(said(tenant({ members: 1 }))).toMatch(/One person loses access/);
    expect(said(tenant({ members: 4 }))).toMatch(/4 people lose access/);
  });

  it("says plainly that this is not a deletion", () => {
    expect(said(tenant())).toMatch(/not a deletion/);
    expect(said(tenant())).toMatch(/can be undone/);
  });

  it("does not claim the telemetry is gone", () => {
    // The one place this product could lie. §4.3: retention runs up to three years for the
    // hourly metric rollup and there is no purge, so the dialogue says so.
    expect(said(tenant())).toMatch(/three years/);
    expect(said(tenant())).toMatch(/no purge/);
  });
});
