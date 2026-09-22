import { describe, expect, it } from "vitest";

import {
  ago,
  describeBound,
  describeHealth,
  describeUses,
  health,
  tokenState,
  type Collector,
  type EnrolmentToken,
} from "./collectors";

function collector(over: Partial<Collector> = {}): Collector {
  return {
    id: "c1",
    kind: "syslog",
    name: "berlin-01",
    hostname: "berlin-01.example.invalid",
    version: "0.0.1",
    reported: null,
    enrolled_at: "2026-09-01T00:00:00Z",
    last_seen_at: "2026-09-22T12:00:00Z",
    started_at: "2026-09-22T09:00:00Z",
    received: 10,
    written: 10,
    lost: 0,
    retired: false,
    quiet: false,
    never_reported: false,
    tenants: [],
    ...over,
  };
}

function token(over: Partial<EnrolmentToken> = {}): EnrolmentToken {
  return {
    id: "t1",
    label: "site-berlin",
    kind: null,
    expires_at: null,
    uses_left: null,
    created_at: "2026-09-01T00:00:00Z",
    revoked: false,
    ...over,
  };
}

describe("health", () => {
  it("separates a collector that stopped from one that never started", () => {
    // The distinction this screen exists to make. One is an outage and one is a
    // configuration problem, and they need different people.
    expect(health(collector({ quiet: true }))).toBe("quiet");
    expect(health(collector({ never_reported: true }))).toBe("silent");

    expect(describeHealth(collector({ quiet: true })).detail).toContain("running");
    expect(describeHealth(collector({ never_reported: true })).detail).toContain(
      "configuration",
    );
  });

  it("puts retired above everything else", () => {
    // A box somebody has retired is not a box anybody should be paged about. Showing it
    // as quiet would put it back in the worry list the moment it stopped.
    expect(health(collector({ retired: true, quiet: true }))).toBe("retired");
    expect(health(collector({ retired: true, never_reported: true }))).toBe("retired");
  });

  it("is reporting when nothing is wrong", () => {
    expect(health(collector())).toBe("reporting");
    expect(describeHealth(collector()).label).toBe("Reporting");
  });

  it("has a sentence for every state", () => {
    for (const over of [
      {},
      { quiet: true },
      { never_reported: true },
      { retired: true },
    ]) {
      const { label, detail } = describeHealth(collector(over));
      expect(label.length).toBeGreaterThan(0);
      // Not a restatement of the badge — the detail is what somebody reads when the
      // badge is not enough, so it has to say more than the badge does.
      expect(detail.length).toBeGreaterThan(label.length);
    }
  });
});

describe("ago", () => {
  const now = Date.parse("2026-09-22T12:00:00Z");

  it("never says zero seconds", () => {
    expect(ago("2026-09-22T12:00:00Z", now)).toBe("just now");
    expect(ago("2026-09-22T11:59:30Z", now)).toBe("just now");
  });

  it("counts up through the units", () => {
    expect(ago("2026-09-22T11:58:00Z", now)).toBe("2 minutes ago");
    expect(ago("2026-09-22T11:00:00Z", now)).toBe("an hour ago");
    expect(ago("2026-09-22T06:00:00Z", now)).toBe("6 hours ago");
    expect(ago("2026-09-21T12:00:00Z", now)).toBe("a day ago");
    expect(ago("2026-09-19T12:00:00Z", now)).toBe("3 days ago");
  });

  it("says never rather than inventing a time", () => {
    expect(ago(null, now)).toBe("never");
    expect(ago("not a date", now)).toBe("never");
  });

  it("does not report the future as a long time ago", () => {
    // A collector whose clock is ahead would otherwise read as "-1 minutes ago".
    expect(ago("2026-09-22T12:05:00Z", now)).toBe("just now");
  });
});

describe("describeBound", () => {
  it("reads a syslog collector's listeners", () => {
    expect(
      describeBound([
        { tenant: "acme", udp: "0.0.0.0:514", tcp: null },
        { tenant: "globex", udp: null, tcp: "0.0.0.0:601" },
      ]),
    ).toBe("acme on 0.0.0.0:514, globex on 0.0.0.0:601");
  });

  it("reads an OTLP collector's bind", () => {
    expect(describeBound([{ tenant: "acme", bind: "0.0.0.0:4318" }])).toBe(
      "acme on 0.0.0.0:4318",
    );
  });

  it("reads a poller, which binds nothing", () => {
    expect(describeBound({ reload_every_secs: 300, device_limit: 5000 })).toBe(
      "up to 5000 devices per tenant",
    );
  });

  it("renders nothing rather than something wrong for a shape it has not met", () => {
    // An empty cell beats `[object Object]`, and a future collector kind will send a
    // shape this build has never seen.
    expect(describeBound(null)).toBe("");
    expect(describeBound({ something: "else" })).toBe("");
    expect(describeBound([{ unexpected: true }])).toBe("");
    expect(describeBound("a string")).toBe("");
  });
});

describe("tokenState", () => {
  const now = Date.parse("2026-09-22T12:00:00Z");

  it("distinguishes the three ways a token stops working", () => {
    // Revoked is a decision, expired is a clock, and spent is a count. Only one of them
    // is somebody's doing, which is the one an operator may want to explain.
    expect(tokenState(token(), now)).toBe("usable");
    expect(tokenState(token({ revoked: true }), now)).toBe("revoked");
    expect(tokenState(token({ expires_at: "2026-09-01T00:00:00Z" }), now)).toBe("expired");
    expect(tokenState(token({ uses_left: 0 }), now)).toBe("spent");
  });

  it("puts a revocation above an expiry", () => {
    // Both are true of a token somebody revoked last year. The revocation is the one a
    // person did, so it is the one worth showing.
    expect(
      tokenState(token({ revoked: true, expires_at: "2026-09-01T00:00:00Z" }), now),
    ).toBe("revoked");
  });

  it("treats a token expiring exactly now as expired", () => {
    expect(tokenState(token({ expires_at: "2026-09-22T12:00:00Z" }), now)).toBe("expired");
  });

  it("counts unlimited uses as unlimited rather than zero", () => {
    expect(describeUses(token())).toBe("unlimited");
    expect(describeUses(token({ uses_left: 1 }))).toBe("1 use left");
    expect(describeUses(token({ uses_left: 7 }))).toBe("7 uses left");
  });
});
