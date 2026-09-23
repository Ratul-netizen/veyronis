/**
 * The incident screen's logic, and the three things it must never say.
 *
 * §2.5 no "root cause", §2.1 no "resolved", §2.6 no silent gap. Each is a testable
 * property rather than a matter of wording, which is why they are here rather than only
 * in a comment on the component.
 */

import { describe, expect, it } from "vitest";

import {
  SUPPRESSION_ADVICE,
  SUPPRESSION_RISK,
  describeCoverage,
  describeNoCandidate,
  describeSignal,
  describeState,
  describeSuppression,
  merge,
  observedAt,
  summarise,
  type Timeline,
  type Track,
  pivotWindow,
} from "./incidents";

function track(signal: string, columns: string[], rows: unknown[][], extra?: Partial<Track>): Track {
  return {
    signal,
    coverage: "whole",
    from: null,
    retention_days: 365,
    columns: columns.map((name) => ({ name, type: "String" })),
    rows,
    ...extra,
  };
}

describe("what the screen says about state", () => {
  it("explains quiet, because nobody has seen the word before", () => {
    // §2.1's distinction in one sentence: not resolved, not closed. The alerts stopped
    // and nobody has said it is understood.
    expect(describeState("quiet")).toContain("nobody has closed it");
    expect(describeState("quiet")).not.toContain("resolved.");
  });

  it("never calls a closed incident anything but closed by a person", () => {
    expect(describeState("closed")).toContain("person");
  });
});

describe("the candidate", () => {
  it("explains its own absence rather than leaving a blank", () => {
    // §2.5. A screen that shows nothing where an explanation belongs reads as broken
    // rather than as careful, and an absent candidate is information.
    expect(describeNoCandidate("no_topology")).toContain("nothing links this estate");
    expect(describeNoCandidate("disconnected")).toContain("two stories");
  });

  it("has something to say about a reason it has never seen", () => {
    // A server that grows a third reason must not produce an empty cell here.
    expect(describeNoCandidate("something_new")).not.toBe("");
  });
});

describe("coverage", () => {
  it("says nothing when the whole window is there", () => {
    // A note on every row is a note nobody reads. The point is that the exceptions stand
    // out, so a complete track carries no note at all.
    expect(describeCoverage(track("log", [], []))).toBeNull();
  });

  it("says a signal expired, and how long it is kept", () => {
    // §2.6, and the whole reason `Coverage` exists: an empty track reads as silence.
    // "This is gone" and "nothing was happening" are opposite conclusions.
    const note = describeCoverage(
      track("flow", [], [], { coverage: "expired", retention_days: 7 }),
    );
    expect(note).toContain("expired");
    expect(note).toContain("7 days");
  });

  it("says when only part of the window survives", () => {
    const note = describeCoverage(
      track("trace", [], [], { coverage: "partial", retention_days: 7, from: "2026-09-01T00:00:00Z" }),
    );
    expect(note).toContain("earlier rows have expired");
  });
});

describe("reading a row of any signal", () => {
  it("shows a log's body", () => {
    const t = track("log", ["observed_at", "body"], [["2026-09-22T10:00:00Z", "link down"]]);
    expect(summarise(t, t.rows[0]!)).toBe("link down");
  });

  it("shows a state change as a transition", () => {
    // Two columns, because "down" alone does not say what it was before — and what it was
    // before is the thing an operator is looking for on a timeline.
    const t = track(
      "state",
      ["observed_at", "previous_status", "current_status"],
      [["2026-09-22T10:00:00Z", "up", "down"]],
    );
    expect(summarise(t, t.rows[0]!)).toBe("up → down");
  });

  it("shows a flow as a conversation", () => {
    const t = track(
      "flow",
      ["observed_at", "src_address", "dst_address"],
      [["2026-09-22T10:00:00Z", "10.0.0.7", "8.8.8.8"]],
    );
    expect(summarise(t, t.rows[0]!)).toBe("10.0.0.7 → 8.8.8.8");
  });

  it("stays readable for a signal it has never heard of", () => {
    // A seventh signal must not render a blank line. Falling back to the first column
    // that is not a timestamp keeps it legible before this function learns about it.
    const t = track("profile", ["observed_at", "stack"], [["2026-09-22T10:00:00Z", "main()"]]);
    expect(summarise(t, t.rows[0]!)).toBe("main()");
  });

  it("returns an empty string rather than undefined for a missing column", () => {
    const t = track("log", ["observed_at"], [["2026-09-22T10:00:00Z"]]);
    expect(summarise(t, t.rows[0]!)).toBe("");
    expect(observedAt(t, t.rows[0]!)).toBe("2026-09-22T10:00:00Z");
  });
});

describe("merging onto one axis", () => {
  const timeline: Timeline = {
    incident: "01a0c7e7-0000-7000-8000-000000000001",
    start: "2026-09-22T09:00:00Z",
    end: "2026-09-22T11:00:00Z",
    resources: ["018f0000-0000-7000-8000-0000000000aa"],
    tracks: [
      track(
        "state",
        ["observed_at", "previous_status", "current_status"],
        [["2026-09-22T10:00:05Z", "up", "down"]],
      ),
      track("log", ["observed_at", "body"], [
        ["2026-09-22T10:00:01Z", "link state changed"],
        ["2026-09-22T10:00:09Z", "bgp reset"],
      ]),
    ],
  };

  it("interleaves signals in time order", () => {
    // The point of a timeline: the log that arrived four seconds before the status change
    // is what an operator is looking for, and it is on a different track.
    const moments = merge(timeline);
    expect(moments.map((m) => m.text)).toEqual([
      "link state changed",
      "up → down",
      "bgp reset",
    ]);
  });

  it("keeps the signal on each row, because one axis is not one source", () => {
    const moments = merge(timeline);
    expect(moments.map((m) => m.signal)).toEqual(["log", "state", "log"]);
  });

  it("contributes nothing for an expired track", () => {
    // It has no rows. The note carries the fact, and the axis stays honest — an expired
    // signal must not put a placeholder on the timeline.
    const withExpired: Timeline = {
      ...timeline,
      tracks: [...timeline.tracks, track("flow", [], [], { coverage: "expired", retention_days: 7 })],
    };
    expect(merge(withExpired)).toHaveLength(3);
  });
});

describe("signal names", () => {
  it("uses words a person would say", () => {
    expect(describeSignal("state")).toBe("Status changes");
    expect(describeSignal("trace")).toBe("Traces");
  });

  it("falls back to the server's word for one it does not know", () => {
    expect(describeSignal("profile")).toBe("profile");
  });
});

describe("topology suppression", () => {
  it("says what each position means in terms of who gets woken up", () => {
    // Not "enabled"/"disabled". The reader is deciding whether a page will arrive, and a
    // label naming the feature rather than the consequence makes them guess.
    expect(describeSuppression(true)).toMatch(/only the cause is notified/i);
    expect(describeSuppression(true)).toMatch(/still on the incident/i);
    expect(describeSuppression(false)).toMatch(/every alert notifies/i);
  });

  it("states the specific failure rather than a general caution", () => {
    // "Are you sure?" tells the reader nothing they did not already know.
    expect(SUPPRESSION_RISK).toMatch(/missed outage/i);
    expect(SUPPRESSION_RISK).toMatch(/topology is wrong/i);
    expect(SUPPRESSION_RISK).not.toMatch(/are you sure/i);
  });

  it("keeps the advice separate from the standing risk", () => {
    // The risk is shown in both positions; the advice is about a decision that has not
    // been made yet, so it has no place beside a switch that is already on.
    expect(SUPPRESSION_ADVICE).toMatch(/turn it on after/i);
    expect(SUPPRESSION_RISK).not.toMatch(/turn it on/i);
  });
});

describe("pivoting out of an incident", () => {
  it("opens a window centred on the moment, not starting at it", () => {
    // M9 §2.6: the record that explains a status change arrives seconds *before* it. A
    // window that began at the incident's start would exclude the thing worth reading.
    const { from, to } = pivotWindow("2026-09-24T12:00:00.000Z");
    expect(from).toBe("2026-09-24T11:55:00.000Z");
    expect(to).toBe("2026-09-24T12:05:00.000Z");
  });

  it("takes a wider window when asked", () => {
    const { from, to } = pivotWindow("2026-09-24T12:00:00.000Z", 30);
    expect(from).toBe("2026-09-24T11:30:00.000Z");
    expect(to).toBe("2026-09-24T12:30:00.000Z");
  });

  it("does not invent a window from a timestamp it cannot read", () => {
    // The shell validates its own search params and falls back to a default. Returning
    // NaN dates here would put "Invalid Date" in a URL somebody pastes into a ticket.
    expect(pivotWindow("not a time")).toEqual({ from: "not a time", to: "not a time" });
  });
});
