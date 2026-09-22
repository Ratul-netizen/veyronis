/**
 * Security — M11.
 *
 * Four questions, one table each, and every one of them a `Query` posted to
 * `/api/v1/query`. There is no security API: see `security.ts` on why a bespoke route
 * would have been a second path to the same rows with its own tenant check to get right.
 *
 * # What this screen refuses to say
 *
 * **"Attack."** M11 §1's last row, and it is the whole posture: this product reports what
 * a device reported and what it is connected to. An assertion that something is malicious
 * needs an analyst, and the value here is getting the analyst to the evidence in one step
 * rather than guessing on their behalf.
 *
 * **A severity of its own.** §2.8. A firewall says `deny`; the row says `denied` and the
 * device's own severity. Once a number nobody can explain is on a row, every screen sorts
 * by it and nobody reads the row again.
 *
 * **A name for the shapes.** §2.4 groups failed sign-ins by a pair and shows two counts —
 * failures, and *distinct counterparties*. "Password spraying" is an interpretation; twenty
 * failures across five accounts from one address is arithmetic. The table shows the
 * arithmetic and the caption explains what to look at.
 *
 * # Why the two failure tables are both here
 *
 * They are the two halves of one pair. An account failing from many addresses is invisible
 * in the per-source table — each address on its own has few failures — and an address
 * working through many accounts is invisible in the per-account one. Either alone reads as
 * a complete answer, which is the reason to show both.
 */

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";

import { message, runQuery, type Query } from "./query";
import {
  CATEGORIES,
  describeCategory,
  events,
  failuresBySource,
  failuresByUser,
  grouped,
  isRefusal,
  recentEvents,
  unresolvedNames,
  type Category,
} from "./security";
import { describeRange, resolveRange, useShell } from "./shell";

export function SecurityPage() {
  // The tenant is read by `useSecurityQuery`, once per query, rather than here.
  const { range } = useShell();
  const [category, setCategory] = useState<Category | null>(null);

  const window = useMemo(() => resolveRange(range), [range]);
  const from = window?.from.toISOString();
  const to = window?.to.toISOString();

  const recent = useSecurityQuery(
    "recent",
    from && to ? recentEvents(from, to, category ?? undefined) : null,
  );
  const bySource = useSecurityQuery("by-source", from && to ? failuresBySource(from, to) : null);
  const byUser = useSecurityQuery("by-user", from && to ? failuresByUser(from, to) : null);
  const unresolved = useSecurityQuery("nxdomain", from && to ? unresolvedNames(from, to) : null);

  const rows = useMemo(() => events(recent.data), [recent.data]);
  const sources = useMemo(() => grouped(bySource.data), [bySource.data]);
  const users = useMemo(() => grouped(byUser.data), [byUser.data]);
  const names = useMemo(() => grouped(unresolved.data), [unresolved.data]);

  const nothing =
    !recent.isPending && rows.length === 0 && sources.length === 0 && names.length === 0;

  return (
    <>
      <h1>Security</h1>
      <p className="dim">
        What the estate reported about sign-ins, firewall decisions, tunnels and name
        resolution — {describeRange(range)}. These are the devices&rsquo; own words,
        categorised. Nothing here is a judgement about whether something is an attack.
      </p>

      {recent.isError && (
        <div className="problem" role="alert">
          {message(recent.error)}
        </div>
      )}

      {nothing && (
        <div className="empty-state">
          <h1>No security events</h1>
          <p>
            A security event appears when a device sends a log this product recognises —
            a firewall decision, a sign-in, a resolver query. Every log line is still
            stored and searchable in <Link to="/explore">Explore</Link> whether or not one
            is produced; a message in no recognised shape produces no event, which is the
            correct answer rather than a failure.
          </p>
        </div>
      )}

      <section className="panel">
        <h2>Failed sign-ins by source</h2>
        <p className="dim">
          The second column is the one to look at. Twenty failures against one account is
          somebody mistyping; twenty across five accounts from one address is not. The
          product does not name the difference — it counts it.
        </p>
        <CountTable
          heading="Source address"
          columns={["failures", "users"]}
          labels={["Failures", "Accounts tried"]}
          rows={sources}
          empty="No failed sign-ins in this window."
        />
      </section>

      <section className="panel">
        <h2>Failed sign-ins by account</h2>
        <p className="dim">
          The other half of the pair. One account failing from several addresses is
          invisible above, because each address on its own has few failures.
        </p>
        <CountTable
          heading="Account"
          columns={["failures", "sources"]}
          labels={["Failures", "Addresses"]}
          rows={users}
          empty="No failed sign-ins in this window."
        />
      </section>

      <section className="panel">
        <h2>Names that did not resolve</h2>
        <p className="dim">
          A burst of <code>NXDOMAIN</code> from one host is software looking for a command
          server that has been taken down. It is also a misconfigured search domain. This
          reports the count and does not choose between them.
        </p>
        <CountTable
          heading="Name"
          columns={["queries"]}
          labels={["Queries"]}
          rows={names}
          empty="Every name resolved in this window, or no resolver is sending logs here."
        />
      </section>

      <section className="panel">
        <h2>Recent events</h2>
        <div className="topo-controls">
          <span className="presets" role="group" aria-label="Category">
            <button
              type="button"
              aria-pressed={category === null}
              onClick={() => setCategory(null)}
            >
              All
            </button>
            {CATEGORIES.map((it) => (
              <button
                key={it}
                type="button"
                aria-pressed={category === it}
                title={describeCategory(it)}
                onClick={() => setCategory(it)}
              >
                {it}
              </button>
            ))}
          </span>
        </div>

        {rows.length === 0 ? (
          <p className="dim">Nothing in this window.</p>
        ) : (
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Category</th>
                  <th>Type</th>
                  <th>What the device said</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, n) => (
                  <tr key={`${row.observedAt}-${n}`}>
                    <td className="dim">{row.observedAt}</td>
                    <td>{row.category}</td>
                    <td>
                      {/* A refusal is marked, and nothing is hidden: an allowed event is
                          not less true than a denied one. */}
                      {isRefusal(row.type) ? (
                        <span className="tag tag-danger">{row.type}</span>
                      ) : (
                        <span className="tag">{row.type}</span>
                      )}
                    </td>
                    <td>{row.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

/** One of this screen's four queries. */
function useSecurityQuery(name: string, query: Query | null) {
  const { tenant } = useShell();
  return useQuery({
    queryKey: ["security", name, tenant.tenant_id, JSON.stringify(query)],
    queryFn: () => runQuery(tenant.tenant_id, query!),
    enabled: query !== null,
    retry: false,
    staleTime: 30_000,
  });
}

/**
 * A grouped table: one key column and however many counts.
 *
 * Reads the counts by **name**, not position — the server sends values in column order
 * with no names, and a screen that indexed into the row would break silently when a column
 * moved.
 */
function CountTable({
  heading,
  columns,
  labels,
  rows,
  empty,
}: {
  heading: string;
  columns: string[];
  labels: string[];
  rows: { key: string; counts: Record<string, number> }[];
  empty: string;
}) {
  if (rows.length === 0) return <p className="dim">{empty}</p>;
  return (
    <div className="scroll-x">
      <table>
        <thead>
          <tr>
            <th>{heading}</th>
            {labels.map((label) => (
              <th key={label} className="num">
                {label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <td>{row.key}</td>
              {columns.map((column) => (
                <td key={column} className="num">
                  {row.counts[column] ?? 0}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
