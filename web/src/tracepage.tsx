/**
 * One trace — the waterfall M8 left open.
 *
 * The Services screen answers *which service*. This answers the other half: **what was
 * this one request waiting for.** M8 §"A trace waterfall" recorded that the queries
 * existed and the screen did not, and that it needed nothing new from the backend. It did
 * not — the two questions are built in `trace.ts` against the same AST the Explorer uses.
 *
 * # Why the bars are laid out against the whole trace and not against their parent
 *
 * A child bar positioned inside its parent reads as "this is the part of the parent it
 * took", which is true only when there is one child. With three children running
 * concurrently it draws them as sequential, and the shape of a fan-out — the thing the
 * screen exists to show — disappears. Every bar is therefore placed against the trace's
 * own extent, so two bars that overlap on screen really did overlap in time.
 *
 * # What this screen will not claim
 *
 * **That the trace is complete.** A sampled trace is routinely missing spans, so a root
 * that names a parent it does not have is labelled *clipped* rather than drawn as a root.
 * Reading a clipped trace as a whole one is how somebody blames the wrong service.
 *
 * **That the critical path is exact.** It follows the slowest child at each step, which is
 * a heuristic and is labelled as one — a true critical path needs the gaps between
 * siblings, and a sampled trace does not reliably carry the spans to compute them.
 *
 * **A percentage of time "spent in" a service.** A parent's duration contains its
 * children's, so the obvious sum double-counts. Until there is a defensible formula the
 * screen shows durations and lets the reader compare them, which is what the bars are for.
 */

import { Link } from "@tanstack/react-router";
import { useMemo } from "react";

import { message, runQuery } from "./query";
import { serviceName, serviceNames } from "./services";
import { useShell, resolveRange, describeRange } from "./shell";
import { useQuery } from "@tanstack/react-query";
import {
  MAX_LOGS,
  MAX_SPANS,
  type SpanNode,
  buildTree,
  criticalPath,
  duration,
  errorCount,
  failed,
  flatten,
  rootKind,
  servicesIn,
  toSpans,
  traceLogs,
  traceSpans,
  usableId,
} from "./trace";

/** Indent per level. Enough to read the nesting, small enough that depth 12 still fits. */
const INDENT_PX = 14;

export function TracePage({ id }: { id: string }) {
  const { tenant, range } = useShell();
  const window = useMemo(() => resolveRange(range), [range]);

  const spansQuery = useMemo(() => {
    if (!window || !usableId(id)) return null;
    return traceSpans(id, window.from.toISOString(), window.to.toISOString());
  }, [id, window]);

  const logsQuery = useMemo(() => {
    if (!window || !usableId(id)) return null;
    return traceLogs(id, window.from.toISOString(), window.to.toISOString());
  }, [id, window]);

  const spans = useQuery({
    queryKey: ["trace-spans", tenant.tenant_id, JSON.stringify(spansQuery)],
    queryFn: () => runQuery(tenant.tenant_id, spansQuery!),
    enabled: spansQuery !== null,
    retry: false,
    staleTime: 30_000,
  });

  // A separate request, so a failing log query does not take the waterfall with it — the
  // Overview's rule, and the one that matters most here: the spans are the screen.
  const logs = useQuery({
    queryKey: ["trace-logs", tenant.tenant_id, JSON.stringify(logsQuery)],
    queryFn: () => runQuery(tenant.tenant_id, logsQuery!),
    enabled: logsQuery !== null,
    retry: false,
    staleTime: 30_000,
  });

  const names = useQuery({
    queryKey: ["service-names", tenant.tenant_id],
    queryFn: () => serviceNames(tenant.tenant_id),
    retry: false,
    staleTime: 60_000,
  });
  const naming = names.data ?? new Map<string, string>();

  const rows = useMemo(() => (spans.data ? toSpans(spans.data) : []), [spans.data]);
  const tree = useMemo(() => buildTree(rows), [rows]);
  const ordered = useMemo(() => flatten(tree), [tree]);
  const critical = useMemo(() => criticalPath(tree), [tree]);

  if (!usableId(id)) {
    // The case `trace.ts` refuses. Reached by editing the URL, and it must say so rather
    // than run a query that would match every row with no trace id.
    return (
      <div className="problem" role="alert">
        No trace id. A trace is opened from a span, a log line or a search result.
      </div>
    );
  }

  if (!window) {
    return (
      <div className="problem" role="alert">
        {describeRange(range)} is not a range this can read.
      </div>
    );
  }

  const kind = rootKind(tree);
  const errors = errorCount(rows);
  const touched = servicesIn(rows);
  const truncated = rows.length >= MAX_SPANS;

  return (
    <>
      <h1>Trace</h1>
      <p className="dim">
        <code>{id}</code>
      </p>

      {spans.isPending && <p className="dim">Reading the trace…</p>}

      {spans.isError && (
        <div className="problem" role="alert">
          {message(spans.error)}
        </div>
      )}

      {!spans.isPending && !spans.isError && rows.length === 0 && (
        // Not an error. A trace outside the window, or sampled away, is the ordinary case
        // — and the window is the thing the reader can actually change.
        <div className="empty-state">
          <p>No spans for this trace in {describeRange(range)}.</p>
          <p className="dim">
            A trace is only readable inside the window it happened in, and an unsampled span
            is absent rather than lost. Widen the range, or open the trace from the log line
            that named it.
          </p>
        </div>
      )}

      {rows.length > 0 && (
        <>
          <dl className="facts">
            <div>
              <dt>Spans</dt>
              <dd>{rows.length}</dd>
            </div>
            <div>
              <dt>Services</dt>
              <dd>{touched.length}</dd>
            </div>
            <div>
              <dt>Failed spans</dt>
              <dd>{errors === 0 ? "None" : errors}</dd>
            </div>
            <div>
              <dt>Root</dt>
              <dd>{kind === "clipped" ? "Clipped" : "Complete"}</dd>
            </div>
          </dl>

          {kind === "clipped" && (
            <p className="notice" role="note">
              This trace is <strong>clipped</strong>: a span here names a parent that is not
              in the result. It was sampled away, dropped, or started before the window.
              What is drawn is part of a request, not the whole one.
            </p>
          )}

          {truncated && (
            <p className="notice" role="note">
              Showing the first {MAX_SPANS} spans. This trace has at least that many, so the
              tree below is incomplete.
            </p>
          )}

          <table className="waterfall">
            <caption className="dim">
              Bars are placed against the whole trace, so bars that overlap really did run
              at the same time. The highlighted chain is the slowest child at each step — a
              heuristic, not a measured critical path.
            </caption>
            <thead>
              <tr>
                <th scope="col">Span</th>
                <th scope="col">Service</th>
                <th scope="col" className="num">
                  Duration
                </th>
                <th scope="col">Timeline</th>
              </tr>
            </thead>
            <tbody>
              {ordered.map((node, i) => (
                <SpanRow
                  key={node.spanId || `anonymous-${i}`}
                  node={node}
                  name={serviceName(node.serviceId, naming)}
                  onCriticalPath={usableId(node.spanId) && critical.has(node.spanId)}
                />
              ))}
            </tbody>
          </table>
        </>
      )}

      <h2>Logs from this trace</h2>
      <p className="dim">
        Not a join. <code>trace_id</code> has been a column on logs since M3, so this is the
        ordinary log query with one more predicate.
      </p>

      {logs.isPending && <p className="dim">Reading the logs…</p>}

      {logs.isError && (
        <div className="problem" role="alert">
          {message(logs.error)}
        </div>
      )}

      {logs.data && logs.data.rows.length === 0 && (
        <p className="dim">
          No log lines carry this trace id. Only logs emitted through OTLP carry one; a
          syslog message never will.
        </p>
      )}

      {logs.data && logs.data.rows.length > 0 && (
        <>
          {logs.data.rows.length >= MAX_LOGS && (
            <p className="notice" role="note">
              Showing the first {MAX_LOGS} lines.
            </p>
          )}
          <LogLines result={logs.data} />
        </>
      )}
    </>
  );
}

/** One row of the waterfall. */
function SpanRow({
  node,
  name,
  onCriticalPath,
}: {
  node: SpanNode;
  name: string;
  onCriticalPath: boolean;
}) {
  const bad = failed(node);
  return (
    <tr className={bad ? "failed" : undefined}>
      <th scope="row" style={{ paddingLeft: `${node.depth * INDENT_PX}px` }}>
        {node.orphaned && (
          <span className="dim" title="This span's parent is not in the result">
            ⤷{" "}
          </span>
        )}
        {node.name || <span className="dim">unnamed</span>}
        {node.kind && <span className="dim"> · {node.kind}</span>}
      </th>
      <td>{name || <span className="dim">—</span>}</td>
      <td className="num">{duration(node.durationNs)}</td>
      <td>
        <div className="track">
          <div
            className={`bar${onCriticalPath ? " critical" : ""}${bad ? " bad" : ""}`}
            style={{
              // Clamped so a span that ran past the window's end — which happens when a
              // trace is still open — cannot draw outside its track.
              marginLeft: `${Math.min(Math.max(node.offset, 0), 1) * 100}%`,
              width: `${Math.min(Math.max(node.width, 0), 1) * 100}%`,
            }}
            title={`${node.name} — ${duration(node.durationNs)}${
              node.statusMessage ? ` — ${node.statusMessage}` : ""
            }`}
          />
        </div>
      </td>
    </tr>
  );
}

/** The log lines, in the columns the result happens to carry. */
function LogLines({ result }: { result: { columns: { name: string }[]; rows: unknown[][] } }) {
  const at = new Map(result.columns.map((c, i) => [c.name, i]));
  const time = at.get("observed_at");
  const severity = at.get("severity");
  const body = at.get("body");

  return (
    <table className="rows">
      <thead>
        <tr>
          <th scope="col">Time</th>
          <th scope="col">Severity</th>
          <th scope="col">Message</th>
        </tr>
      </thead>
      <tbody>
        {result.rows.map((row, i) => (
          <tr key={i}>
            <td className="num">{time === undefined ? "" : String(row[time] ?? "")}</td>
            <td>{severity === undefined ? "" : String(row[severity] ?? "")}</td>
            <td>{body === undefined ? "" : String(row[body] ?? "")}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * A link to one trace.
 *
 * Exported so the screens that hold a trace id — a log row, a span, a search result — all
 * spell the destination the same way. A link built inline in three places is three places
 * that can disagree about whether the id needs trimming.
 */
export function TraceLink({ id, children }: { id: string; children?: React.ReactNode }) {
  if (!usableId(id)) return <span className="dim">—</span>;
  return (
    <Link to="/traces/$id" params={{ id: id.trim() }} title="Open this trace">
      {children ?? <code>{id.slice(0, 12)}…</code>}
    </Link>
  );
}
