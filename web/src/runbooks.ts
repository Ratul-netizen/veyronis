/**
 * What a run's state means, in words — M10, `docs/M10-automation.md`.
 *
 * # Why the decisions are here rather than in the screen
 *
 * Everything in this file is a pure function of a run. That is what makes it testable
 * without a browser, and these are the decisions worth testing: which button to offer,
 * what the state means, and — the one that matters — whether anything was actually sent to
 * a device.
 *
 * # Nothing here is the rule
 *
 * `canApprove` decides whether to *show* a button. Whether an approval is accepted is the
 * server's, and underneath that it is the schema's: migration 0026 makes a self-approval
 * unrepresentable. A client-side check that disagreed with the server would show an enabled
 * button that always fails, which is the kind of thing that teaches people the product is
 * broken — so these mirror the rules and never replace them, and the screen shows whatever
 * the server says when it refuses.
 */

/** Every state a run can be in. Mirrors `runbook_run_state` in migration 0026. */
export type RunState =
  | "awaiting_approval"
  | "ready"
  | "running"
  | "succeeded"
  | "failed"
  | "refused"
  | "cancelled";

/** Every state one step of a run can be in. */
export type StepState = "pending" | "skipped" | "running" | "ok" | "failed";

export interface RunApproval {
  approved_by: string;
  at: string;
}

export interface RunTarget {
  id: string;
  name: string;
}

export interface Run {
  id: string;
  runbook_id: string;
  runbook_name: string;
  version: number;
  state: RunState;
  dry_run: boolean;
  targets: RunTarget[];
  reason: string;
  started_by: string;
  break_glass: boolean;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  failure?: string;
  approvals: RunApproval[];
  touched_a_device: boolean;
}

export interface RunStep {
  resource_id: string;
  step_index: number;
  name: string;
  rendered: string;
  destructive: boolean;
  state: StepState;
  output?: string;
  exit_code?: number;
  finished_at?: string;
}

export interface RunDetail extends Run {
  steps: RunStep[];
}

export interface PlannedStep {
  name: string;
  kind: string;
  rendered: string[];
  destructive: boolean;
  runs_in_dry_run: boolean;
  rollback?: string;
}

export interface Plan {
  runbook: string;
  targets: RunTarget[];
  steps: { resource: string; steps: PlannedStep[] }[];
  summary: string;
  total_steps: number;
  destructive_steps: number;
  approvals_required: number;
  blocked?: string;
}

export interface Runbook {
  id: string;
  version_id: string;
  version: number;
  retired: boolean;
  created_at: string;
  name: string;
  description: string;
  targets: unknown;
  steps: unknown[];
  max_targets: number;
  concurrency: number;
  approvals: "none" | "one" | "two";
  maintenance_only: boolean;
  destructive: boolean;
}

/**
 * What a state means to somebody reading a list.
 *
 * Not the enum's name. `refused` and `failed` are one word apart and mean completely
 * different things — one of them touched a device — and a screen that prints the raw value
 * makes the reader learn that distinction from folklore.
 */
export function describeState(state: RunState): string {
  switch (state) {
    case "awaiting_approval":
      return "Waiting for approval";
    case "ready":
      return "Queued";
    case "running":
      return "Running";
    case "succeeded":
      return "Succeeded";
    case "failed":
      return "Failed";
    case "refused":
      return "Refused before anything was sent";
    case "cancelled":
      return "Cancelled";
  }
}

/**
 * Which semantic colour a state uses.
 *
 * `refused` is a warning rather than a danger, and that is the whole point of it being its
 * own state: nothing reached a device, so it is a thing to look at rather than a thing
 * that happened to somebody's network.
 */
export function toneOf(state: RunState): string {
  switch (state) {
    case "succeeded":
      return "--ok";
    case "failed":
      return "--danger";
    case "refused":
    case "cancelled":
      return "--warn";
    case "running":
    case "ready":
      return "--info";
    case "awaiting_approval":
      return "--unknown";
  }
}

/** The same, for one step of a run. */
export function stepTone(state: StepState): string {
  switch (state) {
    case "ok":
      return "--ok";
    case "failed":
      return "--danger";
    case "running":
      return "--info";
    case "skipped":
    case "pending":
      return "--unknown";
  }
}

/**
 * Whether this run may still be called back.
 *
 * Only before a runner has taken it. A run that has sent something cannot be cancelled,
 * and offering the button would be a promise the product cannot keep — M10 §2.6. What it
 * offers instead is the transcript and the declared rollback.
 */
export function canCancel(run: Pick<Run, "state" | "touched_a_device">): boolean {
  return !run.touched_a_device && (run.state === "awaiting_approval" || run.state === "ready");
}

/** Why the cancel button is not there, for a tooltip. */
export function whyNotCancel(run: Pick<Run, "state" | "touched_a_device">): string | null {
  if (canCancel(run)) return null;
  if (run.touched_a_device) {
    return "This run has already started sending commands. It cannot be called back — read the transcript and decide about the rollback it declared.";
  }
  return "This run has already finished.";
}

/**
 * Whether to offer `me` the approve button on this run.
 *
 * Three conditions, and the first is the one this milestone exists for: **the person who
 * started a run cannot approve it**. That is two-person integrity, and it is enforced by
 * the schema — this only decides whether to draw a button that would be refused.
 */
export function canApprove(
  run: Pick<Run, "state" | "started_by" | "approvals">,
  me: string,
): boolean {
  if (run.state !== "awaiting_approval") return false;
  if (run.started_by === me) return false;
  return !run.approvals.some((a) => a.approved_by === me);
}

/** Why the approve button is not there, in the words the server would use. */
export function whyNotApprove(
  run: Pick<Run, "state" | "started_by" | "approvals">,
  me: string,
): string | null {
  if (canApprove(run, me)) return null;
  if (run.started_by === me) {
    return "You started this run, so you cannot approve it. Two-person integrity is the whole point: ask a colleague.";
  }
  if (run.approvals.some((a) => a.approved_by === me)) {
    return "You have already approved this run. Two approvals from one person are one person agreeing twice.";
  }
  return "This run is not waiting for approval.";
}

/**
 * How many more people have to say yes.
 *
 * Counts distinct approvers other than the starter, which is what the server counts — a
 * screen that counted rows would show "2 of 2" for a run the server still considers
 * unapproved.
 */
export function outstanding(run: Pick<Run, "started_by" | "approvals">, required: number): number {
  const distinct = new Set(
    run.approvals.filter((a) => a.approved_by !== run.started_by).map((a) => a.approved_by),
  );
  return Math.max(0, required - distinct.size);
}

/**
 * The sentence under a run, saying what is true of it now.
 *
 * Deliberately never says what will happen. A run that is `ready` is waiting for a runner
 * to pick it up, and this product does not know when that will be — an estate whose runner
 * has stopped would otherwise show "starting shortly" for ever.
 */
export function whatIsTrue(run: Run, required: number): string {
  if (run.break_glass && run.state !== "awaiting_approval") {
    return "Started without approval under the break-glass account. That is recorded on this run for as long as it exists.";
  }
  switch (run.state) {
    case "awaiting_approval": {
      const left = outstanding(run, required);
      return left === 1
        ? "One more person has to approve this, and it cannot be the person who started it."
        : `${left} more people have to approve this, and none of them can be the person who started it.`;
    }
    case "ready":
      return run.dry_run
        ? "Queued. A runner will execute the read-only steps and skip everything that changes anything."
        : "Queued. A runner will pick this up.";
    case "running":
      return "A runner is executing this now.";
    case "succeeded":
      return run.dry_run
        ? "Every read-only step ran. Nothing that changes anything was sent — this was a dry run."
        : "Every step ran.";
    case "failed":
      return "A step failed and the run stopped there. Nothing after it was sent.";
    case "refused":
      return "The product declined before anything reached a device.";
    case "cancelled":
      return "Cancelled before it started.";
  }
}

/**
 * Whether a step's output is worth a panel of its own.
 *
 * A `wait` step and a skipped step have nothing to show, and an empty `<pre>` under every
 * row is a transcript that is mostly whitespace.
 */
export function hasTranscript(step: Pick<RunStep, "output">): boolean {
  return typeof step.output === "string" && step.output.trim().length > 0;
}

/** What a step's state means, in words. */
export function describeStep(step: Pick<RunStep, "state" | "destructive">): string {
  switch (step.state) {
    case "ok":
      return "Ran";
    case "failed":
      return "Failed";
    case "running":
      return "Running";
    case "skipped":
      return step.destructive ? "Not run — it changes something" : "Not run";
    case "pending":
      return "Still to come";
  }
}

/** The steps of a run, grouped by the device they were sent to. */
export function byResource(steps: RunStep[], targets: RunTarget[]): {
  resource: string;
  name: string;
  steps: RunStep[];
}[] {
  const names = new Map(targets.map((t) => [t.id, t.name]));
  const groups = new Map<string, RunStep[]>();
  for (const step of steps) {
    const list = groups.get(step.resource_id) ?? [];
    list.push(step);
    groups.set(step.resource_id, list);
  }
  return [...groups.entries()]
    .map(([resource, list]) => ({
      resource,
      // A device that has since been renamed, or one the caller cannot see, still has a
      // transcript. Falling back to the id keeps the rows rather than dropping them.
      name: names.get(resource) ?? resource,
      steps: [...list].sort((a, b) => a.step_index - b.step_index),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
