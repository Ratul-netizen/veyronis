/**
 * The Operations Overview — UI-SPEC §8, `UI.md` §3.
 *
 * The landing page, and the one screen somebody sees before they have configured
 * anything. `UI.md`'s argument for it: *"a product whose first screen is empty has to be
 * learned before it can be judged."*
 *
 * # Six panels, four telemetry queries and one control-plane read
 *
 * Every number on it is sourced in the spec's table, and each panel is its own request —
 * one slow panel spins alone, one failing panel says so in its own corner. Well inside
 * the twenty-panel budget measured at p95 0.42 s.
 *
 * # Three things it deliberately does not draw
 *
 * **A health percentage.** `UI.md` §3's mock shows a 97.4% ring. There is no defensible
 * formula for it yet — availability with maintenance windows excluded is M9 — and a
 * number nobody can explain is worse than an absent one on the screen an operator trusts
 * first.
 *
 * **A topology panel.** Until M6 it would be a box saying "coming soon", which is the
 * product telling the operator it is unfinished every time they open it.
 *
 * **A zero in a red tile.** Nothing firing is "Nothing is firing", not a `0` drawn in the
 * colour of danger.
 */

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo } from "react";

import { ago, listAlerts, order, type Alert } from "./alerting";
import { api } from "./api";
import { message, runQuery, type Query, type ResultSet } from "./query";
import { describeRange, resolveRange, useShell } from "./shell";

/** How often the control-plane panels re-read — UI-SPEC §5. */
const REFRESH_MS = 10_000;

/** Severities that count as "an error somebody should look at". */
const BAD = ["error", "critical", "alert", "emergency"];

/**
 * The severities the log-volume chart stacks, in the order they stack.
 *
 * Quiet at the bottom, loud at the top, so the shape of the bar reads as "how much of
 * this is bad" without anybody consulting a legend.
 */
const STACK: { severity: string; colour: string }[] = [
  { severity: "debug", colour: "var(--sev-debug)" },
  { severity: "info", colour: "var(--sev-info)" },
  { severity: "notice", colour: "var(--sev-notice)" },
  { severity: "warn", colour: "var(--sev-warn)" },
  { severity: "error", colour: "var(--sev-error)" },
  { severity: "critical", colour: "var(--sev-critical)" },
];

export function OverviewPage() {
  const { tenant, range } = useShell();

  // Memoised on the *descriptor* rather than computed inline, and this is not a tidying:
  // `resolveRange` turns "last 1 hour" into two instants ending at `now`, so calling it
  // during render produces a different window every time the component renders. Every
  // panel's query key is derived from that window, so a fresh window is a fresh key, a
  // fresh fetch, a re-render — and the page fetches in a loop until somebody navigates
  // away. It renders as three panels stuck on their loading state, forever, while the
  // server takes three queries a frame.
  //
  // Found by pointing a browser at it. No test would have: each query is correct, each
  // one returns 200, and the only symptom is the count of them.
  const { from, to } = useMemo(() => {
    const resolved = resolveRange(range);
    return { from: resolved?.from, to: resolved?.to };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range.from, range.to]);

  // ---- what exists, and what is wrong with it -------------------------------
  const resources = useQuery({
    queryKey: ["overview-resources", tenant.tenant_id],
    queryFn: () => api.resources(tenant.tenant_id),
    retry: false,
  });

  const alerts = useQuery({
    queryKey: ["alerts", tenant.tenant_id],
    queryFn: () => listAlerts(tenant.tenant_id),
    refetchInterval: REFRESH_MS,
    retry: false,
  });

  // ---- what is still talking ------------------------------------------------
  //
  // One row per resource that produced a metric in the window. Counting the rows is the
  // honest "how many are reporting" this product can answer today — and it is not called
  // availability, which implies an SLA calculation with maintenance excluded.
  const reporting = usePanel(
    ["overview-reporting", tenant.tenant_id],
    from && to
      ? {
          signal: "metric",
          time: { start: from.toISOString(), end: to.toISOString() },
          resources: { type: "all" },
          aggregations: [{ func: "count", alias: "n" }],
          group_by: [{ field: "resource_id" }],
          limit: 10_000,
        }
      : null,
  );

  // ---- how much is arriving, and how much of it is bad ----------------------
  const volume = usePanel(
    ["overview-volume", tenant.tenant_id],
    from && to
      ? {
          signal: "log",
          time: { start: from.toISOString(), end: to.toISOString() },
          resources: { type: "all" },
          aggregations: [{ func: "count", alias: "n" }],
          group_by: [
            { field: "time_bucket", seconds: bucketFor(from, to) },
            { field: "severity" },
          ],
          limit: 1000,
        }
      : null,
  );

  // ---- who is producing the errors -----------------------------------------
  //
  // Grouped on `host.name`, which is a materialised column in `logs` — W1 measured
  // grouping on a Map key at 2 252 ms and it is the slowest thing in the whole suite.
  // It also means the name comes back with the count, rather than forty requests to
  // resolve forty ids.
  const busiest = usePanel(
    ["overview-busiest", tenant.tenant_id],
    from && to
      ? {
          signal: "log",
          time: { start: from.toISOString(), end: to.toISOString() },
          resources: { type: "all" },
          filter: {
            op: "compare",
            field: { field: "severity" },
            cmp: "in",
            value: BAD,
          },
          aggregations: [{ func: "count", alias: "n" }],
          group_by: [{ field: "attr", key: "host.name" }],
          order_by: [{ key: { by: "alias", alias: "n" }, desc: true }],
          limit: 8,
        }
      : null,
  );

  const rows = order(alerts.data ?? []);
  const firing = rows.filter((a) => a.state === "firing");
  const pending = rows.filter((a) => a.state === "pending");
  const total = resources.data?.items.length ?? null;
  // id → name, for the panels that group by resource_id. Memoised on the list itself so
  // it is rebuilt when the inventory changes and not on every render.
  const names = useMemo(
    () =>
      new Map(
        (resources.data?.items ?? []).map((r) => [r.id, r.display_name ?? r.name]),
      ),
    [resources.data],
  );
  const talking = reporting.data?.rows.length ?? null;

  const worst = firing.length > 0 ? "firing" : pending.length > 0 ? "pending" : "quiet";

  return (
    <>
      <h1>Operations overview</h1>
      <p className="dim">
        {tenant.name}, all sites, {describeRange(range).toLowerCase()}
      </p>

      {alerts.isError ? (
        <p className="warn">{message(alerts.error)}</p>
      ) : worst === "quiet" ? (
        /* No colour on this screen at all. The estate is stated as a sentence because
           that is what somebody asked: is anything wrong, and how much am I watching. */
        <p className="all-quiet">
          Nothing is firing.
          <span className="estate">
            {total === null
              ? "Counting what is out there…"
              : `${total.toLocaleString()} resources, ${
                  talking === null ? "…" : talking.toLocaleString()
                } of them reporting in this window.`}
          </span>
        </p>
      ) : (
        <div className="wrong">
          {firing.length > 0 && (
            <Link className="wrong-count firing" to="/alerts">
              <span className="n">{firing.length}</span>
              <span className="what">firing</span>
            </Link>
          )}
          {pending.length > 0 && (
            <Link className="wrong-count pending" to="/alerts">
              <span className="n">{pending.length}</span>
              {/* What separates pending from firing is that nobody has been told, and
                  that is the whole reason the two are counted apart. */}
              <span className="what">pending, nobody notified</span>
            </Link>
          )}
        </div>
      )}

      {worst !== "quiet" && (
        <ul className="wrong-list">
          {rows.slice(0, 6).map((alert: Alert) => (
            <li
              key={alert.id}
              className="rail"
              style={{ "--tone": toneOf(alert) } as React.CSSProperties}
            >
              <span className={`severity ${alert.severity}`}>{alert.severity}</span>
              <Link to="/resources/$id" params={{ id: alert.resource_id }}>
                {alert.resource}
              </Link>
              <span className="rule">{alert.rule}</span>
              <span className="when">
                {alert.state === "pending" ? "pending, " : ""}
                {ago(alert.since)}
              </span>
            </li>
          ))}
        </ul>
      )}

      {/* Always shown, in both states: an operator who has just dealt with an alert wants
          to know the estate is still the size they think it is. When the screen is calm
          these numbers are in the sentence above instead, so this row only appears when
          the sentence has been replaced by a count. */}
      {worst !== "quiet" && total !== null && (
        <p className="facts">
          <span>
            <b>{total.toLocaleString()}</b> resources
          </span>
          <span>
            <b>{talking === null ? "…" : talking.toLocaleString()}</b> reporting in this
            window
          </span>
        </p>
      )}

      <div className="regions">
        <section className="region">
          <header>
            <h3>Log volume by severity</h3>
            <Link to="/explore">Explore</Link>
          </header>
          <PanelState panel={volume}>
            {(result) => <Volume result={result} />}
          </PanelState>
        </section>

        <section className="region">
          <header>
            <h3>Busiest resources</h3>
            <span className="dim">errors and worse</span>
          </header>
          <PanelState panel={busiest}>
            {(result) => <Busiest result={result} names={names} />}
          </PanelState>
        </section>
      </div>
    </>
  );
}

/**
 * The colour of an alert's rail.
 *
 * A pending alert is one evaluation from firing and nobody has been told, so it is amber
 * whatever its configured severity: the rail answers "has this woken somebody", which is
 * the question being asked at the moment somebody looks at this list.
 */
function toneOf(alert: Alert): string {
  if (alert.state === "pending") return "var(--warn)";
  return alert.severity === "critical" ? "var(--danger)" : "var(--warn)";
}

/** One telemetry panel's query, with the five states the widget contract requires. */
function usePanel(key: unknown[], query: Query | null) {
  return useQuery({
    queryKey: [...key, JSON.stringify(query)],
    queryFn: () => runQuery(String(key[1]), query as Query),
    enabled: query !== null,
    retry: false,
    staleTime: 60_000,
  });
}

/**
 * Loading, error, empty and data — the four a panel can be in before it has drawn
 * anything. Written once so every panel on this page behaves the same way, which is the
 * whole point of the widget contract having states at all.
 */
function PanelState({
  panel,
  children,
}: {
  panel: ReturnType<typeof usePanel>;
  children: (result: ResultSet) => React.ReactNode;
}) {
  if (panel.isPending) return <p className="dim">…</p>;
  // The server's own sentence, in this panel's corner, with the rest of the page alive.
  if (panel.isError) return <p className="warn">{message(panel.error)}</p>;
  if (panel.data.rows.length === 0) return <p className="dim">No data in this window.</p>;
  return <>{children(panel.data)}</>;
}


function Volume({ result }: { result: ResultSet }) {
  // [bucket, severity, n] — group_by order, then the aggregate.
  const buckets = new Map<string, Map<string, number>>();
  for (const row of result.rows) {
    const at = String(row[0]);
    const severity = String(row[1]);
    const n = Number(row[2]) || 0;
    const bucket = buckets.get(at) ?? new Map<string, number>();
    bucket.set(severity, (bucket.get(severity) ?? 0) + n);
    buckets.set(at, bucket);
  }

  const ordered = [...buckets.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  if (ordered.length === 0) return <p className="dim">No data in this window.</p>;

  const totals = ordered.map(([, bucket]) => [...bucket.values()].reduce((a, b) => a + b, 0));
  const tallest = Math.max(...totals, 1);
  const width = 600;
  const height = 150;
  const gap = 1;
  const barWidth = Math.max(1, width / ordered.length - gap);

  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" preserveAspectRatio="none">
        {ordered.map(([at, bucket], i) => {
          let y = height;
          return (
            <g key={at}>
              {STACK.map(({ severity, colour }) => {
                const n = bucket.get(severity) ?? 0;
                if (n === 0) return null;
                const h = (n / tallest) * (height - 4);
                y -= h;
                return (
                  <rect
                    key={severity}
                    x={i * (barWidth + gap)}
                    y={y}
                    width={barWidth}
                    height={h}
                    fill={colour}
                  >
                    <title>{`${severity}: ${n.toLocaleString()}`}</title>
                  </rect>
                );
              })}
            </g>
          );
        })}
      </svg>
      <figcaption className="legend">
        {STACK.map(({ severity, colour }) => (
          <span key={severity}>
            <i style={{ background: colour }} />
            {severity}
          </span>
        ))}
      </figcaption>
    </figure>
  );
}

/** Who is producing the errors, by host name. */
/**
 * The resources producing the most errors.
 *
 * `names` turns the `resource_id` the query groups by into something a person can read.
 * Telemetry is stored against the id — that is the whole point of the identity model —
 * so the panel used to render the uuid, which is not a thing anybody can act on at 3am
 * and is not what UI-SPEC §8.1 asked for ("links to the resource page"). The page has
 * already fetched the tenant's resources for the count above, so this costs no request.
 *
 * An id with no name is still shown, in mono, rather than dropped: a resource that is
 * producing errors and is not in the inventory is a fact worth seeing, not a row to hide.
 */
function Busiest({
  result,
  names,
}: {
  result: ResultSet;
  names: Map<string, string>;
}) {
  const rows = result.rows
    .map((row) => ({ id: String(row[0] ?? ""), n: Number(row[1]) || 0 }))
    .filter((row) => row.id !== "");
  if (rows.length === 0) return <p className="dim">No errors in this window.</p>;

  const worst = Math.max(...rows.map((r) => r.n), 1);

  return (
    <ul className="ranked">
      {rows.map((row) => {
        const name = names.get(row.id);
        return (
          // A bar as well as a number: "4 200 and 3 900" is two numbers, and two bars of
          // almost the same length is a fact. Drawn as the row's own background — see the
          // note in styles.css on why a child element cannot do it.
          <li key={row.id} style={{ ["--fill" as string]: `${(row.n / worst) * 100}%` }}>
            <span className={`ranked-name${name ? "" : " mono"}`}>
              <Link to="/resources/$id" params={{ id: row.id }}>
                {name ?? row.id}
              </Link>
            </span>
            <span className="ranked-count">{row.n.toLocaleString()}</span>
          </li>
        );
      })}
    </ul>
  );
}

/**
 * A bucket width that puts roughly sixty bars in the window.
 *
 * The same arithmetic the Explorer uses, and for the same reason: a bar has to be a span
 * of time somebody can name.
 */
function bucketFor(from: Date, to: Date): number {
  const span = Math.max(1, Math.round((to.getTime() - from.getTime()) / 1000));
  const steps = [60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400];
  return steps.find((s) => s >= span / 60) ?? 86400;
}
