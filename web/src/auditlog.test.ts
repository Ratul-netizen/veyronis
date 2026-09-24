/**
 * What the audit screen is allowed to say.
 *
 * The rules here are about not making judgements the product cannot make. It knows how many
 * rows a query returned; it does not know which of its users is supposed to be running a
 * big one. So `isLargeRead` is about volume and never about identity.
 */

import { describe, expect, it } from "vitest";

import {
  type Change,
  type Read,
  LARGE_READ,
  describeActor,
  humanRows,
  isLargeRead,
  touchedACredential,
} from "./auditlog";

describe("describing an actor", () => {
  it("says plainly when the actor is not a person", () => {
    // An auditor scanning for a human needs to see at a glance that these are not one.
    expect(describeActor("system")).toBe("the product itself");
    expect(describeActor("collector")).toBe("a collector");
  });

  it("shortens a user id rather than printing a whole uuid", () => {
    expect(describeActor("user:01a0cfb6-8f7c-74c5-b5c2-785e9c4b3ed0")).toBe("user 01a0cfb6");
  });

  it("passes through anything it does not recognise", () => {
    // A new actor kind must not render as blank; the raw value is a fact.
    expect(describeActor("service-account:ci")).toBe("service-account:ci");
  });
});

describe("which reads are worth a second look", () => {
  const read = (over: Partial<Read> = {}): Read => ({ actor: "user:a", target: "query", ...over });

  it("flags volume, which is the difference between a lookup and a copy", () => {
    expect(isLargeRead(read({ row_count: LARGE_READ }))).toBe(true);
    expect(isLargeRead(read({ row_count: LARGE_READ - 1 }))).toBe(false);
  });

  it("does not flag a read whose size was not recorded", () => {
    // A missing count is not a large read, and treating it as one would make every
    // credential read look like an exfiltration.
    expect(isLargeRead(read())).toBe(false);
  });
});

describe("which changes an investigator starts from", () => {
  const change = (action: string): Change => ({ actor: "user:a", action, target: "x" });

  it("recognises credential actions by their stable prefix", () => {
    expect(touchedACredential(change("credential.create"))).toBe(true);
    expect(touchedACredential(change("credential.revoke"))).toBe(true);
    expect(touchedACredential(change("resource.create"))).toBe(false);
    // Not a substring match: a rule named "rotate.credential.thing" is not a credential
    // action, and the log's names are dotted and stable for exactly this reason.
    expect(touchedACredential(change("runbook.credential"))).toBe(false);
  });
});

describe("presentation", () => {
  it("shows a dash rather than a zero when nothing was recorded", () => {
    expect(humanRows(undefined)).toBe("—");
    expect(humanRows(0)).toBe("0");
    expect(humanRows(12345)).toBe("12,345");
  });
});
