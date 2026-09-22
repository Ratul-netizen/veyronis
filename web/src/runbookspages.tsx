/**
 * Runbooks, dry runs, approvals and transcripts — M10.
 *
 * Three screens, and the middle one is the reason the other two exist.
 *
 * # The dry-run review is the product
 *
 * `RunbooksPage` lists what exists and `RunPage` says what happened. `PlanPage` is where
 * somebody decides, and every decision M10 §2.2 argues for lives on it: the resolved
 * targets **by name**, the count in front of the reader, the literal command that would be
 * sent to each device, and a mark against every step saying whether a dry run executes it.
 *
 * The one thing it never says is that anything would succeed. `Plan::describe` on the
 * server produces *"would run 3 steps on 4 resources"*, and this screen prints that
 * sentence rather than composing its own — a safety feature that lies is worse than no
 * safety feature, because somebody trusts it once.
 *
 * # Starting a run is two clicks, and the second one is not styled as the easy path
 *
 * A dry run is the primary button. A real run is behind a checkbox that says what it means
 * and a confirmation that repeats the count. That is deliberate friction on the only
 * action in this product that changes somebody else's equipment.
 *
 * # There is no editor here
 *
 * A runbook is written as JSON and posted. An editor for a typed step tree is a screen of
 * its own and it is not what M10 §3 asks for — what it asks for is that a runbook is
 * created, validated and versioned, and that the refusal names the step. The textarea
 * does that honestly and the refusal is shown in full, every problem at once.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { api } from "./api";
import { message } from "./query";
import {
  byResource,
  canApprove,
  canCancel,
  describeState,
  describeStep,
  hasTranscript,
  stepTone,
  toneOf,
  whatIsTrue,
  whyNotApprove,
  whyNotCancel,
  type Plan,
  type Run,
  type Runbook,
} from "./runbooks";
import { useShell } from "./shell";

/** How often a run in flight is re-read. */
const WHILE_RUNNING = 5_000;

function required(runbook: Pick<Runbook, "approvals"> | undefined): number {
  switch (runbook?.approvals) {
    case "two":
      return 2;
    case "one":
      return 1;
    default:
      return 0;
  }
}

// ---- the list ------------------------------------------------------------------

export function RunbooksPage() {
  const { tenant } = useShell();
  const queryClient = useQueryClient();
  const [writing, setWriting] = useState(false);
  const [draft, setDraft] = useState(EXAMPLE);
  const [problem, setProblem] = useState<string | null>(null);

  const runbooks = useQuery({
    queryKey: ["runbooks", tenant.tenant_id],
    queryFn: () => api.runbooks(tenant.tenant_id),
    retry: false,
  });

  const save = useMutation({
    mutationFn: (body: unknown) => api.saveRunbook(tenant.tenant_id, body),
    onSuccess: () => {
      setWriting(false);
      setProblem(null);
      void queryClient.invalidateQueries({ queryKey: ["runbooks", tenant.tenant_id] });
    },
    onError: (error: unknown) => setProblem(message(error)),
  });

  const retire = useMutation({
    mutationFn: (id: string) => api.retireRunbook(tenant.tenant_id, id),
    onSuccess: () =>
      void queryClient.invalidateQueries({ queryKey: ["runbooks", tenant.tenant_id] }),
  });

  const submit = () => {
    let body: unknown;
    try {
      body = JSON.parse(draft);
    } catch (error) {
      // Parsed here rather than posted, so a missing comma is answered instantly and by
      // the thing that knows where it is.
      setProblem(`That is not valid JSON: ${(error as Error).message}`);
      return;
    }
    save.mutate(body);
  };

  if (runbooks.isError) {
    return (
      <>
        <h1>Runbooks</h1>
        <div className="problem" role="alert">
          {message(runbooks.error)}
        </div>
      </>
    );
  }

  const live = (runbooks.data ?? []).filter((r) => !r.retired);
  const retired = (runbooks.data ?? []).filter((r) => r.retired);

  return (
    <>
      <h1>Runbooks</h1>
      <p className="dim">
        A reviewed list of steps, run against resources a selector picks out. Editing one
        writes a new version and leaves the old one readable, because a run names the
        version it executed.
      </p>

      <div className="topo-controls">
        <button type="button" onClick={() => setWriting((was) => !was)}>
          {writing ? "Cancel" : "New version"}
        </button>
        <Link to="/runs">
          <button type="button" className="quiet">
            Runs
          </button>
        </Link>
      </div>

      {writing && (
        <div className="panel">
          <p className="dim">
            A runbook, as JSON. Posting one whose name already exists saves version{" "}
            <em>n+1</em>.
          </p>
          <textarea
            className="runbook-source"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            aria-label="Runbook JSON"
            rows={18}
            spellCheck={false}
          />
          <div className="scene3d-actions">
            <button type="button" onClick={submit} disabled={save.isPending}>
              {save.isPending ? "Saving…" : "Save"}
            </button>
          </div>
          {problem && (
            // Every problem at once, on its own lines. An author fixing a runbook one
            // refusal at a time saves six times.
            <pre className="problem" role="alert">
              {problem}
            </pre>
          )}
        </div>
      )}

      {runbooks.isPending ? (
        <p className="dim">Loading…</p>
      ) : live.length === 0 ? (
        <p className="dim">
          Nothing yet. A runbook is a small number of typed steps — an SSH command, an HTTP
          request, a wait — with a selector saying which resources they run against.
        </p>
      ) : (
        <table className="grid">
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Steps</th>
              <th>Changes things</th>
              <th>Approvals</th>
              <th>Max resources</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {live.map((r) => (
              <tr key={r.id}>
                <td>
                  <strong>{r.name}</strong>
                  {r.description && <div className="dim">{r.description}</div>}
                  {r.maintenance_only && (
                    <div className="dim">Only during a maintenance window.</div>
                  )}
                </td>
                <td>{r.version}</td>
                <td>{r.steps.length}</td>
                <td>{r.destructive ? "Yes" : "No"}</td>
                <td>{required(r) === 0 ? "None" : required(r)}</td>
                <td>{r.max_targets}</td>
                <td>
                  <Link to="/runbooks/$id" params={{ id: r.id }}>
                    <button type="button">Dry run</button>
                  </Link>{" "}
                  <button
                    type="button"
                    className="quiet"
                    onClick={() => retire.mutate(r.id)}
                    title="Its run history stays readable"
                  >
                    Retire
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {retired.length > 0 && (
        <p className="dim">
          {retired.length} retired {retired.length === 1 ? "runbook is" : "runbooks are"} not
          shown. They cannot be run; their history still reads.
        </p>
      )}
    </>
  );
}

/** A runbook to start from, so the first thing anybody sees is a valid one. */
const EXAMPLE = JSON.stringify(
  {
    name: "restart-bgp-session",
    description: "Check a BGP session is down, then clear it",
    targets: { type: "all" },
    steps: [
      {
        name: "check the session is actually down",
        action: {
          kind: "ssh_command",
          command: "show bgp summary",
          credential: "00000000-0000-0000-0000-000000000000",
        },
        destructive: false,
        expect: { kind: "contains", text: "Idle" },
      },
      {
        name: "clear it",
        action: {
          kind: "ssh_command",
          command: "clear bgp neighbor {{ resource.name }}",
          credential: "00000000-0000-0000-0000-000000000000",
        },
        destructive: true,
        rollback: { kind: "none", because: "a cleared session cannot be un-cleared" },
      },
    ],
    max_targets: 10,
    concurrency: 2,
    approvals: "one",
    maintenance_only: false,
  },
  null,
  2,
);

// ---- the dry-run review --------------------------------------------------------

export function PlanPage({ id }: { id: string }) {
  const { tenant } = useShell();
  const navigate = useNavigate();
  const [reason, setReason] = useState("");
  const [forReal, setForReal] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  const runbooks = useQuery({
    queryKey: ["runbooks", tenant.tenant_id],
    queryFn: () => api.runbooks(tenant.tenant_id),
    retry: false,
  });
  const runbook = runbooks.data?.find((r) => r.id === id);

  const plan = useQuery({
    queryKey: ["plan", tenant.tenant_id, id],
    queryFn: () => api.planRun(tenant.tenant_id, id),
    retry: false,
  });

  const start = useMutation({
    mutationFn: (dry: boolean) => api.startRun(tenant.tenant_id, id, reason.trim(), dry),
    onSuccess: (run: Run) => {
      void navigate({ to: "/runs/$id", params: { id: run.id } });
    },
    onError: (error: unknown) => {
      setConfirming(false);
      setProblem(message(error));
    },
  });

  if (plan.isError) {
    return (
      <>
        <h1>Dry run</h1>
        {/* The refusal an operator most often sees here is the blast-radius one, and it
            carries the two numbers. It is shown in full rather than summarised. */}
        <div className="problem" role="alert">
          {message(plan.error)}
        </div>
        <Link to="/runbooks">Back to runbooks</Link>
      </>
    );
  }

  if (plan.isPending || !plan.data) return <p className="dim">Resolving the targets…</p>;
  const it: Plan = plan.data;
  const blocked = it.blocked;

  return (
    <>
      <h1>{it.runbook}</h1>
      {/* The server's own sentence. It says what would run and never what would succeed. */}
      <p className="plan-summary">{it.summary}</p>
      <p className="dim">
        This is what would be sent. A dry run executes only the steps the author marked as
        changing nothing — it is not a simulation, and it cannot predict the effect of the
        steps it does not run.
      </p>

      {blocked && (
        <p className="warn" role="status">
          {blocked}
        </p>
      )}

      <h2>Resources ({it.targets.length})</h2>
      <p className="dim">
        The number to check before anything else: a selector meant to match one switch and
        matching four hundred is the most common way automation causes an outage.
      </p>
      <ul className="scene3d-links">
        {it.targets.map((t) => (
          <li key={t.id}>
            <Link to="/resources/$id" params={{ id: t.id }}>
              {t.name}
            </Link>
          </li>
        ))}
      </ul>

      <h2>Commands</h2>
      {it.steps.map((group) => (
        <div key={group.resource} className="panel">
          <h3>{it.targets.find((t) => t.id === group.resource)?.name ?? group.resource}</h3>
          <ol className="plan-steps">
            {group.steps.map((step, index) => (
              <li key={`${step.name}-${index}`}>
                <div className="plan-step-head">
                  <strong>{step.name}</strong>
                  <span className="dim"> · {step.kind}</span>
                  {step.destructive && <span className="tag tag-danger">changes something</span>}
                  {!step.runs_in_dry_run && <span className="tag">not run in a dry run</span>}
                </div>
                {step.rendered.map((text, n) => (
                  // The literal text. A template is what the mistake hides in.
                  <pre key={n} className="plan-rendered">
                    {text}
                  </pre>
                ))}
                {step.rollback && <p className="dim">{step.rollback}</p>}
              </li>
            ))}
          </ol>
        </div>
      ))}

      <h2>Start</h2>
      <div className="panel">
        <label className="field">
          <span>Why is this happening?</span>
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="the session on core-01 is stuck"
            aria-label="Why is this happening?"
          />
        </label>

        <label className="field field-check">
          <input
            type="checkbox"
            checked={forReal}
            onChange={(event) => {
              setForReal(event.target.checked);
              setConfirming(false);
            }}
          />
          <span>
            Send the steps that change something.{" "}
            {it.approvals_required > 0 && (
              <>
                This needs {it.approvals_required} approval
                {it.approvals_required === 1 ? "" : "s"} from somebody else before a runner
                will pick it up.
              </>
            )}
          </span>
        </label>

        {confirming ? (
          <div className="scene3d-actions">
            <p className="warn">
              {it.destructive_steps} step{it.destructive_steps === 1 ? "" : "s"} that change
              something, across {it.targets.length} resource
              {it.targets.length === 1 ? "" : "s"}.
            </p>
            <button
              type="button"
              className="danger"
              disabled={start.isPending}
              onClick={() => start.mutate(false)}
            >
              Yes, start it
            </button>
            <button type="button" className="quiet" onClick={() => setConfirming(false)}>
              No
            </button>
          </div>
        ) : (
          <div className="scene3d-actions">
            <button
              type="button"
              disabled={!reason.trim() || start.isPending || Boolean(blocked)}
              onClick={() => (forReal ? setConfirming(true) : start.mutate(true))}
            >
              {forReal ? "Start a real run…" : "Start a dry run"}
            </button>
          </div>
        )}

        {!reason.trim() && (
          <p className="dim">
            Say why. It is the first thing anybody reading the record afterwards looks for.
          </p>
        )}
        {problem && (
          <pre className="problem" role="alert">
            {problem}
          </pre>
        )}
      </div>

      <p className="dim">
        <Link to="/runs" search={{ runbook: id } as never}>
          Previous runs of {runbook?.name ?? "this runbook"}
        </Link>
      </p>
    </>
  );
}

// ---- runs ----------------------------------------------------------------------

export function RunsPage() {
  const { tenant } = useShell();

  const runs = useQuery({
    queryKey: ["runs", tenant.tenant_id],
    queryFn: () => api.runs(tenant.tenant_id),
    retry: false,
    refetchInterval: WHILE_RUNNING,
  });

  if (runs.isError) {
    return (
      <>
        <h1>Runs</h1>
        <div className="problem" role="alert">
          {message(runs.error)}
        </div>
      </>
    );
  }

  const rows = runs.data ?? [];

  return (
    <>
      <h1>Runs</h1>
      <p className="dim">
        What has been run, by whom, and what happened. The most recent {rows.length}.
      </p>

      {rows.length === 0 ? (
        <p className="dim">
          Nothing has been run. Start from <Link to="/runbooks">a runbook</Link>.
        </p>
      ) : (
        <table className="grid">
          <thead>
            <tr>
              <th>Runbook</th>
              <th>State</th>
              <th>Kind</th>
              <th>Resources</th>
              <th>Reason</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((run) => (
              <tr key={run.id}>
                <td>
                  <Link to="/runs/$id" params={{ id: run.id }}>
                    {run.runbook_name}
                  </Link>{" "}
                  <span className="dim">v{run.version}</span>
                </td>
                <td style={{ color: `var(${toneOf(run.state)})` }}>
                  {describeState(run.state)}
                  {run.break_glass && <div className="tag tag-danger">unapproved</div>}
                </td>
                <td>{run.dry_run ? "Dry run" : "Real"}</td>
                <td>{run.targets.length}</td>
                <td className="dim">{run.reason}</td>
                <td className="dim">{new Date(run.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

export function RunPage({ id }: { id: string }) {
  const { tenant, me } = useShell();
  const queryClient = useQueryClient();
  const [problem, setProblem] = useState<string | null>(null);

  const run = useQuery({
    queryKey: ["run", tenant.tenant_id, id],
    queryFn: () => api.run(tenant.tenant_id, id),
    retry: false,
    // While something is in flight. Polling rather than pushing: a websocket for one
    // screen would be a second transport to operate.
    refetchInterval: (query) =>
      query.state.data && ["ready", "running"].includes(query.state.data.state)
        ? WHILE_RUNNING
        : false,
  });

  const runbooks = useQuery({
    queryKey: ["runbooks", tenant.tenant_id],
    queryFn: () => api.runbooks(tenant.tenant_id),
    retry: false,
  });

  const refresh = () => {
    setProblem(null);
    void queryClient.invalidateQueries({ queryKey: ["run", tenant.tenant_id, id] });
    void queryClient.invalidateQueries({ queryKey: ["runs", tenant.tenant_id] });
  };

  const approve = useMutation({
    mutationFn: () => api.approveRun(tenant.tenant_id, id),
    onSuccess: refresh,
    onError: (error: unknown) => setProblem(message(error)),
  });

  const cancel = useMutation({
    mutationFn: () => api.cancelRun(tenant.tenant_id, id),
    onSuccess: refresh,
    onError: (error: unknown) => setProblem(message(error)),
  });

  if (run.isError) {
    return (
      <>
        <h1>Run</h1>
        <div className="problem" role="alert">
          {message(run.error)}
        </div>
      </>
    );
  }
  if (run.isPending || !run.data) return <p className="dim">Loading…</p>;

  const it = run.data;
  const need = required(runbooks.data?.find((r) => r.id === it.runbook_id));
  const groups = byResource(it.steps, it.targets);
  const approvable = canApprove(it, me.user_id);
  const cancellable = canCancel(it);

  return (
    <>
      <h1>
        {it.runbook_name} <span className="dim">v{it.version}</span>
      </h1>
      <p style={{ color: `var(${toneOf(it.state)})` }}>
        <strong>{describeState(it.state)}</strong>
        {it.dry_run && " · dry run"}
      </p>
      <p className="dim">{whatIsTrue(it, need)}</p>
      <p className="dim">
        “{it.reason}” · started {new Date(it.created_at).toLocaleString()}
      </p>

      {it.failure && (
        // The declared rollback is in here, with the sentence that it has *not* been run.
        // A rollback is another runbook and it can fail too — M10 §2.6.
        <div className="problem" role="alert">
          {it.failure}
        </div>
      )}

      <div className="topo-controls">
        <button
          type="button"
          disabled={!approvable || approve.isPending}
          title={whyNotApprove(it, me.user_id) ?? "Approve this run"}
          onClick={() => approve.mutate()}
        >
          Approve
        </button>
        <button
          type="button"
          className="quiet"
          disabled={!cancellable || cancel.isPending}
          title={whyNotCancel(it) ?? "Cancel before a runner takes it"}
          onClick={() => cancel.mutate()}
        >
          Cancel
        </button>
      </div>

      {/* The reason the button is disabled, said out loud. A disabled control with no
          explanation is how a product teaches people it is broken. */}
      {!approvable && it.state === "awaiting_approval" && (
        <p className="dim">{whyNotApprove(it, me.user_id)}</p>
      )}
      {problem && (
        <pre className="problem" role="alert">
          {problem}
        </pre>
      )}

      {it.approvals.length > 0 && (
        <>
          <h2>Approvals</h2>
          <ul className="scene3d-links">
            {it.approvals.map((a) => (
              <li key={a.approved_by}>
                {a.approved_by} <span className="dim">{new Date(a.at).toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      <h2>Transcript</h2>
      {groups.length === 0 ? (
        <p className="dim">
          Nothing has been executed yet, so there is nothing to read. A run that is queued
          has sent nothing.
        </p>
      ) : (
        groups.map((group) => (
          <div key={group.resource} className="panel">
            <h3>{group.name}</h3>
            <ol className="plan-steps">
              {group.steps.map((step) => (
                <li key={step.step_index}>
                  <div className="plan-step-head">
                    <strong>{step.name}</strong>
                    <span style={{ color: `var(${stepTone(step.state)})` }}>
                      {" "}
                      · {describeStep(step)}
                    </span>
                    {step.destructive && (
                      <span className="tag tag-danger">changes something</span>
                    )}
                    {typeof step.exit_code === "number" && (
                      <span className="dim"> · exit {step.exit_code}</span>
                    )}
                  </div>
                  {step.rendered && <pre className="plan-rendered">{step.rendered}</pre>}
                  {hasTranscript(step) && <pre className="run-output">{step.output}</pre>}
                </li>
              ))}
            </ol>
          </div>
        ))
      )}
      <p className="dim">
        Output is redacted and capped. This is not where configuration backup lives.
      </p>
    </>
  );
}
