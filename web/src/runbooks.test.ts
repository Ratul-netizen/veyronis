/**
 * What the runbook screens are allowed to say — M10.
 *
 * The two that matter are `canApprove` and `whatIsTrue`. The first draws the button that
 * two-person integrity is about; the second is the sentence an operator reads at 3 a.m.,
 * and the failure mode is that it promises something.
 */

import { describe, expect, it } from "vitest";

import {
  byResource,
  canApprove,
  canCancel,
  describeState,
  describeStep,
  hasTranscript,
  outstanding,
  stepTone,
  toneOf,
  whatIsTrue,
  whyNotApprove,
  whyNotCancel,
  type Run,
  type RunState,
  type RunStep,
  type StepState,
} from "./runbooks";

const STATES: RunState[] = [
  "awaiting_approval",
  "ready",
  "running",
  "succeeded",
  "failed",
  "refused",
  "cancelled",
];

function run(over: Partial<Run> = {}): Run {
  return {
    id: "run-1",
    runbook_id: "rb-1",
    runbook_name: "restart-bgp",
    version: 1,
    state: "awaiting_approval",
    dry_run: false,
    targets: [{ id: "r1", name: "core-01" }],
    reason: "the session is stuck",
    started_by: "alice",
    break_glass: false,
    created_at: "2026-09-22T10:00:00Z",
    approvals: [],
    touched_a_device: false,
    ...over,
  };
}

function step(over: Partial<RunStep> = {}): RunStep {
  return {
    resource_id: "r1",
    step_index: 0,
    name: "check",
    rendered: "show bgp summary",
    destructive: false,
    state: "ok",
    ...over,
  };
}

describe("states", () => {
  it("has words for every one", () => {
    for (const state of STATES) {
      expect(describeState(state).length).toBeGreaterThan(0);
      expect(toneOf(state).startsWith("--")).toBe(true);
    }
  });

  it("does not print the enum's own name", () => {
    // `awaiting_approval` on a screen makes the reader translate. Worse, `refused` and
    // `failed` are one word apart and mean completely different things.
    expect(describeState("awaiting_approval")).not.toContain("_");
    expect(describeState("refused")).toMatch(/before anything was sent/i);
  });

  it("does not colour a refusal as a failure", () => {
    // Nothing reached a device. It is a thing to look at, not a thing that happened to
    // somebody's network — which is the whole reason `refused` is its own state.
    expect(toneOf("refused")).not.toBe(toneOf("failed"));
    expect(toneOf("failed")).toBe("--danger");
  });

  it("has a tone for every step state too", () => {
    for (const state of ["pending", "skipped", "running", "ok", "failed"] as StepState[]) {
      expect(stepTone(state).startsWith("--")).toBe(true);
    }
  });
});

describe("canApprove", () => {
  it("refuses the person who started the run", () => {
    // The whole of two-person integrity. The schema makes the row unrepresentable; this
    // only decides whether to draw a button that would be refused.
    expect(canApprove(run({ started_by: "alice" }), "alice")).toBe(false);
    expect(canApprove(run({ started_by: "alice" }), "bob")).toBe(true);
  });

  it("refuses somebody who has already approved", () => {
    const already = run({
      approvals: [{ approved_by: "bob", at: "2026-09-22T10:01:00Z" }],
    });
    expect(canApprove(already, "bob")).toBe(false);
    expect(canApprove(already, "carol")).toBe(true);
  });

  it("offers nothing on a run that is not waiting", () => {
    for (const state of STATES.filter((s) => s !== "awaiting_approval")) {
      expect(canApprove(run({ state }), "bob")).toBe(false);
    }
  });

  it("explains itself in the words the server would use", () => {
    // A disabled button with no explanation is how a product teaches people it is broken.
    expect(whyNotApprove(run({ started_by: "alice" }), "alice")).toMatch(/cannot approve/i);
    expect(
      whyNotApprove(
        run({ approvals: [{ approved_by: "bob", at: "x" }] }),
        "bob",
      ),
    ).toMatch(/already approved/i);
    expect(whyNotApprove(run({ state: "ready" }), "bob")).toMatch(/not waiting/i);
    expect(whyNotApprove(run(), "bob")).toBeNull();
  });
});

describe("canCancel", () => {
  it("allows it before a runner takes the run", () => {
    expect(canCancel(run({ state: "awaiting_approval", touched_a_device: false }))).toBe(true);
    expect(canCancel(run({ state: "ready", touched_a_device: false }))).toBe(true);
  });

  it("refuses it once anything has been sent", () => {
    // "Cancel" on a run that has already sent a command would be a promise the product
    // cannot keep — M10 §2.6.
    const running = run({ state: "running", touched_a_device: true });
    expect(canCancel(running)).toBe(false);
    expect(whyNotCancel(running)).toMatch(/cannot be called back/i);
    expect(whyNotCancel(running)).toMatch(/rollback/i);
  });

  it("refuses it on a run that is over", () => {
    for (const state of ["succeeded", "failed", "refused", "cancelled"] as RunState[]) {
      expect(canCancel(run({ state, touched_a_device: state !== "cancelled" }))).toBe(false);
    }
  });
});

describe("outstanding", () => {
  it("counts distinct people other than the starter", () => {
    // What the server counts. A screen that counted rows would show "2 of 2" for a run the
    // server still considers unapproved.
    const r = run({
      started_by: "alice",
      approvals: [
        { approved_by: "alice", at: "x" },
        { approved_by: "bob", at: "y" },
      ],
    });
    expect(outstanding(r, 2)).toBe(1);
  });

  it("never goes below zero", () => {
    const r = run({
      approvals: [
        { approved_by: "bob", at: "x" },
        { approved_by: "carol", at: "y" },
      ],
    });
    expect(outstanding(r, 1)).toBe(0);
  });
});

describe("whatIsTrue", () => {
  it("never promises when something will happen", () => {
    // An estate whose runner has stopped would otherwise show "starting shortly" for ever.
    for (const state of STATES) {
      const said = whatIsTrue(run({ state }), 1);
      expect(said).not.toMatch(/shortly|soon|in a moment|will finish/i);
    }
  });

  it("says a dry run sent nothing that changes anything", () => {
    const said = whatIsTrue(run({ state: "succeeded", dry_run: true }), 0);
    expect(said).toMatch(/dry run/i);
    expect(said).toMatch(/nothing that changes/i);
  });

  it("says a failed run stopped and sent nothing after", () => {
    // The question an operator asks first, and the answer M10 §2.6 requires.
    const said = whatIsTrue(run({ state: "failed" }), 0);
    expect(said).toMatch(/stopped/i);
    expect(said).toMatch(/nothing after it/i);
  });

  it("says a break-glass run was unapproved, for as long as it exists", () => {
    const said = whatIsTrue(run({ state: "succeeded", break_glass: true }), 2);
    expect(said).toMatch(/without approval/i);
    expect(said).toMatch(/for as long as it exists/i);
  });

  it("does not call a break-glass run unapproved while it is still waiting", () => {
    // A run cannot be both. If it is waiting for approval then break-glass was not taken,
    // and saying otherwise would make the record wrong in the one direction that matters.
    const said = whatIsTrue(run({ state: "awaiting_approval", break_glass: true }), 1);
    expect(said).toMatch(/approve/i);
  });

  it("names how many more people are needed", () => {
    expect(whatIsTrue(run({ state: "awaiting_approval" }), 1)).toMatch(/One more person/);
    expect(whatIsTrue(run({ state: "awaiting_approval" }), 2)).toMatch(/2 more people/);
  });
});

describe("the transcript", () => {
  it("shows nothing for a step that produced nothing", () => {
    expect(hasTranscript(step({}))).toBe(false);
    expect(hasTranscript(step({ output: "   \n" }))).toBe(false);
    expect(hasTranscript(step({ output: "Neighbor is Idle" }))).toBe(true);
  });

  it("says why a skipped destructive step was skipped", () => {
    expect(describeStep({ state: "skipped", destructive: true })).toMatch(/changes something/i);
    expect(describeStep({ state: "skipped", destructive: false })).toBe("Not run");
    expect(describeStep({ state: "pending", destructive: false })).toMatch(/still to come/i);
  });

  it("groups steps by device, in order, by name", () => {
    const steps = [
      step({ resource_id: "r2", step_index: 1, name: "clear" }),
      step({ resource_id: "r1", step_index: 1, name: "clear" }),
      step({ resource_id: "r2", step_index: 0, name: "check" }),
      step({ resource_id: "r1", step_index: 0, name: "check" }),
    ];
    const grouped = byResource(steps, [
      { id: "r1", name: "zz-last" },
      { id: "r2", name: "aa-first" },
    ]);
    expect(grouped.map((g) => g.name)).toEqual(["aa-first", "zz-last"]);
    expect(grouped[0]?.steps.map((s) => s.step_index)).toEqual([0, 1]);
  });

  it("keeps a transcript for a device it has no name for", () => {
    // A device renamed or removed since the run still has a transcript, and dropping the
    // rows would lose the record of what was sent to it.
    const grouped = byResource([step({ resource_id: "gone" })], []);
    expect(grouped).toHaveLength(1);
    expect(grouped[0]?.name).toBe("gone");
  });
});
