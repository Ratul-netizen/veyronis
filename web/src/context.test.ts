/** The context model's promises — UI-SPEC §13.1, §13.2 and §13.3. */

import { describe, expect, it } from "vitest";

import {
  EVERYTHING,
  contextParams,
  formatContext,
  parseContext,
  unscopedBecause,
  type Context,
} from "./context";

describe("parseContext", () => {
  it("reads each of the three narrowings", () => {
    expect(parseContext("site:s-1")).toEqual({ kind: "site", id: "s-1" });
    expect(parseContext("group:g-1")).toEqual({ kind: "group", id: "g-1" });
    expect(parseContext("resource:r-1")).toEqual({ kind: "resource", id: "r-1" });
  });

  it("falls back to everything rather than refusing", () => {
    // A URL is something people edit. Every one of these renders an unscoped page that
    // says it is unscoped, which beats a blank screen and an error.
    const bad = [undefined, null, "", "site", "site:", ":s-1", "tenant:t-1", "nonsense"];
    for (const value of bad) {
      expect(parseContext(value)).toEqual(EVERYTHING);
    }
  });

  it("keeps a colon inside an id, because only the first one separates", () => {
    expect(parseContext("resource:a:b")).toEqual({ kind: "resource", id: "a:b" });
  });

  it("round-trips through the URL", () => {
    const each: Context[] = [
      EVERYTHING,
      { kind: "site", id: "s-1" },
      { kind: "group", id: "g-1" },
      { kind: "resource", id: "r-1" },
    ];
    for (const context of each) {
      expect(parseContext(formatContext(context))).toEqual(context);
    }
  });
});

describe("formatContext", () => {
  it("leaves the URL clean when there is no context", () => {
    // Not "ctx=all". The default must not appear, or every link anybody copies carries a
    // parameter that means nothing.
    expect(formatContext(EVERYTHING)).toBeUndefined();
  });
});

describe("contextParams", () => {
  it("narrows the one list every screen reads", () => {
    expect(contextParams(EVERYTHING)).toEqual({});
    expect(contextParams({ kind: "site", id: "s-1" })).toEqual({ site: "s-1" });
    expect(contextParams({ kind: "group", id: "g-1" })).toEqual({ group: "g-1" });
    expect(contextParams({ kind: "resource", id: "r-1" })).toEqual({ only: "r-1" });
  });

  it("sets exactly one parameter, so no screen has two filters to reconcile", () => {
    const narrowed: Context[] = [
      { kind: "site", id: "x" },
      { kind: "group", id: "x" },
      { kind: "resource", id: "x" },
    ];
    for (const context of narrowed) {
      expect(Object.keys(contextParams(context))).toHaveLength(1);
    }
  });
});

describe("unscopedBecause", () => {
  it("says nothing about the screens the context reaches", () => {
    expect(unscopedBecause("/")).toBeNull();
    expect(unscopedBecause("/resources")).toBeNull();
  });

  it("owns up to the screens that are not wired yet", () => {
    // Not a temporary embarrassment to be hidden: a narrowed bar over a whole-tenant
    // screen is the same lie whether the reason is design or unfinished work. Deleting
    // either of these entries is the last step of scoping that screen, not the first.
    expect(unscopedBecause("/topology")).toMatch(/whole tenant/);
    expect(unscopedBecause("/alerts")).toMatch(/not yet/);
  });

  it("gives a reason for the ones it does not", () => {
    // §13.3's other half: a context that is not applied must not look as if it were.
    expect(unscopedBecause("/discovery")).toMatch(/per tenant/);
    expect(unscopedBecause("/explore")).toBeTruthy();
    expect(unscopedBecause("/map")).toBeTruthy();
  });

  it("lets a longer prefix win, so /alerts and /alerts/rules give different reasons", () => {
    // Both are unscoped today and for different reasons, and the reason is the point:
    // the alert list will be narrowed one day, and a rule's own selector never will be.
    expect(unscopedBecause("/alerts")).toMatch(/not yet/);
    expect(unscopedBecause("/alerts/rules")).toMatch(/selector/);
    expect(unscopedBecause("/alerts/channels")).toMatch(/tenant/);
  });

  it("covers a child route the way it covers its parent", () => {
    expect(unscopedBecause("/discovery/runs")).toBeTruthy();
    expect(unscopedBecause("/dashboards/abc")).toBeTruthy();
  });
});
