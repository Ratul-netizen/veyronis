import { describe, expect, it } from "vitest";

import {
  SHOWN_ONCE,
  type IngestToken,
  expiryNote,
  exporterConfig,
  labelProblem,
  tokenState,
} from "./ingest";

function token(over: Partial<IngestToken> = {}): IngestToken {
  return {
    id: "018f0000-0000-7000-8000-00000000aaaa",
    label: "berlin-hosts",
    created_at: "2026-09-01T10:00:00Z",
    live: true,
    ...over,
  };
}

describe("naming a token", () => {
  it("requires a name, because at revocation time the question is which one this is", () => {
    expect(labelProblem("", [])).toMatch(/required/i);
    expect(labelProblem("   ", [])).toMatch(/required/i);
    expect(labelProblem("berlin-hosts", [])).toBeNull();
  });

  it("refuses a duplicate of a live token, matching the unique index", () => {
    const existing = [token({ label: "berlin-hosts" })];
    expect(labelProblem("berlin-hosts", existing)).toMatch(/already uses/i);
    expect(labelProblem("  berlin-hosts  ", existing)).toMatch(/already uses/i);
  });

  it("allows reusing the name of a revoked one", () => {
    // The index is partial on nothing — the server's UNIQUE covers revoked rows too — so this
    // is the one place the screen is deliberately more permissive than the database, and the
    // 409 is what corrects it. Better than refusing a name an operator can see is dead.
    const dead = [token({ label: "berlin-hosts", revoked_at: "2026-09-02T00:00:00Z" })];
    expect(labelProblem("berlin-hosts", dead)).toBeNull();
  });

  it("bounds the length", () => {
    expect(labelProblem("x".repeat(60), [])).toBeNull();
    expect(labelProblem("x".repeat(61), [])).toMatch(/at most/i);
  });
});

describe("what state a token is in", () => {
  const now = new Date("2026-09-24T12:00:00Z");

  it("tells revoked from expired, because they mean different things", () => {
    // "Somebody revoked this" and "nobody renewed it" send an operator to different people.
    expect(tokenState(token(), now)).toBe("live");
    expect(tokenState(token({ revoked_at: "2026-09-20T00:00:00Z" }), now)).toBe("revoked");
    expect(tokenState(token({ expires_at: "2026-09-23T00:00:00Z" }), now)).toBe("expired");
  });

  it("reports revoked even when it would also have expired", () => {
    const both = token({
      revoked_at: "2026-09-20T00:00:00Z",
      expires_at: "2026-09-21T00:00:00Z",
    });
    expect(tokenState(both, now)).toBe("revoked");
  });

  it("treats a token with no expiry as live", () => {
    // `exactOptionalPropertyTypes` is on, so absence is expressed by omitting the key rather
    // than by assigning undefined to it — which is the distinction the flag exists to keep.
    expect(tokenState(token(), now)).toBe("live");
  });
});

describe("when it stops working", () => {
  const now = new Date("2026-09-24T12:00:00Z");

  it("says so plainly when it never does", () => {
    expect(expiryNote(token(), now)).toBe("does not expire");
  });

  it("counts days, then hours, then says within the hour", () => {
    expect(expiryNote(token({ expires_at: "2026-10-01T12:00:00Z" }), now)).toBe(
      "expires in 7 days",
    );
    expect(expiryNote(token({ expires_at: "2026-09-24T15:00:00Z" }), now)).toBe(
      "expires in 3 hours",
    );
    expect(expiryNote(token({ expires_at: "2026-09-24T12:30:00Z" }), now)).toBe(
      "expires within the hour",
    );
  });

  it("says expired rather than a negative count", () => {
    expect(expiryNote(token({ expires_at: "2026-09-01T00:00:00Z" }), now)).toBe("expired");
  });

  it("does not render NaN for a timestamp it cannot read", () => {
    expect(expiryNote(token({ expires_at: "not a date" }), now)).toBe("unknown");
  });
});

describe("the configuration handed to an operator", () => {
  it("carries the token in the header an OTel exporter already sends", () => {
    const config = exporterConfig("deadbeef");
    expect(config).toContain('Authorization: "Bearer deadbeef"');
    expect(config).toContain("otlphttp");
  });

  it("leaves the endpoint a placeholder rather than guessing it", () => {
    // The product does not know it: the listener binds inside a collector on some network, and
    // guessing from the browser's URL would be wrong in exactly the deployments that matter —
    // a reverse proxy in front, or a collector on another segment.
    expect(exporterConfig("deadbeef")).toContain("<your-otlp-endpoint>");
    expect(exporterConfig("deadbeef", "otlp.internal")).toContain("http://otlp.internal:4318");
  });

  it("says the token is shown once and what to do if it is lost", () => {
    expect(SHOWN_ONCE).toMatch(/cannot be shown again/);
    expect(SHOWN_ONCE).toMatch(/mint another/);
  });
});
