/**
 * The audit log — SPEC §M0.8.
 *
 * Two tabs, not one merged stream. They answer different questions and an auditor asks one
 * at a time: *who changed this* and *who saw this*. Interleaving would bury a handful of
 * credential reads in the ordinary traffic of acknowledging alerts, and the shapes differ —
 * a change has a before and an after, a read has a row count and a query fingerprint.
 *
 * # This screen is the reason the logs are worth writing
 *
 * Both tables have been filled since M1 and neither could be read without `psql`. Read
 * auditing is offered to buyers in `docs/security-overview.md` and was listed in
 * `docs/PRODUCT-STRATEGY.md` as an advantage that is "true today" — true of the rows and
 * false of the product.
 *
 * # What it does not do
 *
 * **Judge.** It marks a read that returned a great many rows, because that is the
 * difference between somebody looking something up and somebody taking a copy of the
 * estate. It does not mark a *person*: the product does not know which of its users is
 * supposed to be running a big query, and a screen that implied otherwise would have
 * somebody explaining themselves for doing their job.
 */

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import {
  type Change,
  type Read,
  LARGE_READ,
  describeActor,
  humanRows,
  isLargeRead,
  listChanges,
  listReads,
  touchedACredential,
} from "./auditlog";
import { message } from "./query";
import { useShell } from "./shell";

type Tab = "reads" | "changes";

export function AuditPage() {
  const { tenant } = useShell();
  // Reads first. It is the log SPEC §M0.8 exists for and the one nothing else surfaces;
  // changes are at least partly visible through the things they changed.
  const [tab, setTab] = useState<Tab>("reads");

  if (tenant.role !== "admin") {
    // An audit log names people and shows the values they touched. Said plainly rather
    // than rendering an empty table and a 403 in the console.
    return (
      <>
        <h1>Audit</h1>
        <div className="problem" role="alert">
          The audit log needs the admin role on {tenant.name}. It names people and shows
          what they read.
        </div>
      </>
    );
  }

  return (
    <>
      <h1>Audit</h1>
      <p className="dim">
        Who changed this estate, and who saw it. Written since the first release; readable
        here.
      </p>

      <div className="topo-controls">
        <span className="presets">
          <button type="button" aria-pressed={tab === "reads"} onClick={() => setTab("reads")}>
            Reads
          </button>
          <button
            type="button"
            aria-pressed={tab === "changes"}
            onClick={() => setTab("changes")}
          >
            Changes
          </button>
        </span>
      </div>

      {tab === "reads" ? <Reads tenant={tenant.tenant_id} /> : <Changes tenant={tenant.tenant_id} />}
    </>
  );
}

function Reads({ tenant }: { tenant: string }) {
  const reads = useQuery({
    queryKey: ["audit-reads", tenant],
    queryFn: () => listReads(tenant),
    retry: false,
  });

  if (reads.isPending) return <p className="dim">Reading the access log…</p>;
  if (reads.isError)
    return (
      <div className="problem" role="alert">
        {message(reads.error)}
      </div>
    );

  const rows = reads.data ?? [];
  if (rows.length === 0)
    return (
      <div className="empty-state">
        <h1>Nothing read yet</h1>
        <p>
          Every read of a resource, a credential or a telemetry query lands here. An empty
          log on a new installation is the honest answer; on an old one it is worth asking
          about.
        </p>
      </div>
    );

  const large = rows.filter(isLargeRead).length;

  return (
    <>
      {large > 0 && (
        <p className="notice" role="note">
          {large} of these returned {LARGE_READ.toLocaleString("en-GB")} rows or more. That
          is the difference between looking something up and taking a copy — it is not an
          accusation, and the product does not know who is supposed to be running one.
        </p>
      )}
      <table className="rows audit">
        <thead>
          <tr>
            <th scope="col">Who</th>
            <th scope="col">Read</th>
            <th scope="col">What was asked</th>
            <th scope="col" className="num">
              Rows
            </th>
            <th scope="col">From</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <ReadRow key={i} read={r} />
          ))}
        </tbody>
      </table>
    </>
  );
}

function ReadRow({ read }: { read: Read }) {
  return (
    <tr className={isLargeRead(read) ? "attention" : undefined}>
      <td>{describeActor(read.actor)}</td>
      <td className="mono">{read.target}</td>
      {/* The query's shape, never its parameters — those carry a customer's hostnames and
          addresses, and an auditor needs to know what was asked rather than be handed a
          second copy of the data. */}
      <td className="mono dim">{read.fingerprint ?? "—"}</td>
      <td className="num mono">{humanRows(read.row_count)}</td>
      <td className="mono dim">{read.ip ?? "—"}</td>
    </tr>
  );
}

function Changes({ tenant }: { tenant: string }) {
  const changes = useQuery({
    queryKey: ["audit-changes", tenant],
    queryFn: () => listChanges(tenant),
    retry: false,
  });

  if (changes.isPending) return <p className="dim">Reading the audit log…</p>;
  if (changes.isError)
    return (
      <div className="problem" role="alert">
        {message(changes.error)}
      </div>
    );

  const rows = changes.data ?? [];
  if (rows.length === 0)
    return (
      <div className="empty-state">
        <h1>Nothing changed yet</h1>
        <p>Every mutating call lands here, with what it was before and what it became.</p>
      </div>
    );

  return (
    <table className="rows audit">
      <thead>
        <tr>
          <th scope="col">Who</th>
          <th scope="col">Did</th>
          <th scope="col">To</th>
          <th scope="col">Before → after</th>
          <th scope="col">From</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((c, i) => (
          <ChangeRow key={i} change={c} />
        ))}
      </tbody>
    </table>
  );
}

function ChangeRow({ change }: { change: Change }) {
  const [open, setOpen] = useState(false);
  const has = change.before !== undefined || change.after !== undefined;

  return (
    <>
      {/* A credential action is where an investigation starts, so it is marked. */}
      <tr className={touchedACredential(change) ? "attention" : undefined}>
        <td>{describeActor(change.actor)}</td>
        <td className="mono">{change.action}</td>
        <td className="mono">{change.target}</td>
        <td>
          {has ? (
            <button type="button" className="quiet" onClick={() => setOpen((was) => !was)}>
              {open ? "Hide" : "Show"}
            </button>
          ) : (
            <span className="dim">—</span>
          )}
        </td>
        <td className="mono dim">{change.ip ?? "—"}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={5}>
            <pre className="mono raw-trace">
              {JSON.stringify({ before: change.before, after: change.after }, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}
