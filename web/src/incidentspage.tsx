/**
 * Incidents, and the Investigation Workspace — M9, and PLAN §6.
 *
 * Two views in one screen. A list of what is happening, and — when one is selected — the
 * thing this product was arranged around from M0:
 *
 * ```text
 * Incident ─→ Investigation
 *             ├── likely origin, and the evidence for it
 *             ├── blast radius: the resources it touches
 *             └── timeline: every signal, one axis
 * ```
 *
 * # What the screen refuses to say
 *
 * **"Root cause."** §2.5. The heading is *Likely origin*, and beside it are the two facts
 * it was derived from: this resource has nothing above it in the topology, and it alerted
 * first. When there is no candidate the screen says why, because an empty field where an
 * explanation belongs reads as broken rather than careful.
 *
 * **"Resolved."** §2.1. An incident whose alerts have all stopped is *quiet*, and the word
 * is explained in place — it is not resolved and it is not closed, and that distinction is
 * the difference between a machine's opinion and a person's.
 *
 * **"Nothing happened."** §2.6. A signal past its retention is marked *expired* on its own
 * row. An empty track with no note reads as silence, and "this is gone" and "nothing was
 * happening" are opposite conclusions to reach at 3am.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ago } from "./alerting";
import { message } from "./query";
import {
  acknowledgeIncident,
  closeIncident,
  describeCoverage,
  describeNoCandidate,
  describeSignal,
  describeState,
  fetchTimeline,
  listIncidents,
  merge,
  type Incident,
} from "./incidents";
import { useShell } from "./shell";

export function IncidentsPage() {
  const { tenant } = useShell();
  const [selected, setSelected] = useState<string | null>(null);

  const incidents = useQuery({
    queryKey: ["incidents", tenant.tenant_id],
    queryFn: () => listIncidents(tenant.tenant_id),
    retry: false,
    // The same reasoning the alert list carries: this is a small indexed read of the
    // control plane, and it is the one screen whose purpose is to be current. An operator
    // watching a cascade must not have to press anything to learn that a fourth device
    // went.
    refetchInterval: 15_000,
  });

  const rows = incidents.data ?? [];
  const open = rows.find((i) => i.id === selected) ?? null;

  return (
    <>
      <h1>Incidents</h1>

      {incidents.isPending && <p className="dim">Loading…</p>}

      {incidents.isError && (
        <div className="problem" role="alert">
          {message(incidents.error)}
        </div>
      )}

      {incidents.data && rows.length === 0 && (
        <div className="empty-state">
          <h1>Nothing is broken</h1>
          <p>
            An incident appears here when an alert fires — grouped with the others it is
            connected to, in time and through the topology. Nothing is configured and
            nothing is raised by hand.
          </p>
        </div>
      )}

      {rows.length > 0 && (
        <div className="scroll-x">
          <table>
            <thead>
              <tr>
                <th>State</th>
                <th>Severity</th>
                <th>Likely origin</th>
                <th>Summary</th>
                <th className="num">Alerts</th>
                <th>Started</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((incident) => (
                <Row
                  key={incident.id}
                  incident={incident}
                  selected={incident.id === selected}
                  onSelect={() => setSelected(incident.id === selected ? null : incident.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {open && <Investigation incident={open} />}
    </>
  );
}

function Row({
  incident,
  selected,
  onSelect,
}: {
  incident: Incident;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <tr>
      <td>
        {/* The word and what it means. `quiet` is the one nobody has seen before. */}
        <span title={describeState(incident.state)}>{incident.state}</span>
      </td>
      <td>{incident.severity}</td>
      <td>
        {incident.candidate_name ?? (
          <span className="dim" title={describeNoCandidate(incident.candidate_absent_because)}>
            none —{" "}
            {describeNoCandidate(incident.candidate_absent_because)}
          </span>
        )}
      </td>
      <td>{incident.summary}</td>
      <td className="num mono">
        {incident.alerts}
        {/* §2.4: shown whenever it is non-zero, because a suppression nobody can see is
            indistinguishable from a bug. */}
        {incident.suppressed > 0 && (
          <span className="dim" title="silenced because something upstream already notified">
            {" "}
            ({incident.suppressed} silenced)
          </span>
        )}
      </td>
      <td className="dim">{ago(incident.started_at)} ago</td>
      <td>
        <button type="button" onClick={onSelect}>
          {selected ? "Close view" : "Investigate"}
        </button>
      </td>
    </tr>
  );
}

function Investigation({ incident }: { incident: Incident }) {
  const { tenant } = useShell();
  const queryClient = useQueryClient();

  const timeline = useQuery({
    queryKey: ["incident-timeline", tenant.tenant_id, incident.id],
    queryFn: () => fetchTimeline(tenant.tenant_id, incident.id),
    retry: false,
    staleTime: 15_000,
  });

  const act = (fn: (tenant: string, id: string) => Promise<Incident>) => ({
    mutationFn: () => fn(tenant.tenant_id, incident.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["incidents"] }),
  });

  const ack = useMutation(act(acknowledgeIncident));
  const close = useMutation(act(closeIncident));

  const moments = timeline.data ? merge(timeline.data) : [];

  return (
    <section>
      <h2>{incident.summary}</h2>

      <p className="dim">
        {describeState(incident.state)}. Started {ago(incident.started_at)} ago, last alert{" "}
        {ago(incident.last_alert_at)} ago.
      </p>

      <div className="actions">
        <button type="button" onClick={() => ack.mutate()} disabled={ack.isPending || !!incident.acked_at}>
          {incident.acked_at ? "Acknowledged" : "Acknowledge"}
        </button>
        <button
          type="button"
          className="primary"
          onClick={() => close.mutate()}
          disabled={close.isPending || incident.state === "closed"}
        >
          {incident.state === "closed" ? "Closed" : "Close incident"}
        </button>
      </div>

      {close.isError && (
        <div className="problem" role="alert">
          {message(close.error)}
        </div>
      )}

      <h3>Likely origin</h3>
      {incident.candidate_name ? (
        <p>
          <strong>{incident.candidate_name}</strong>{" "}
          <span className="dim">
            — nothing else in this incident is upstream of it, and it alerted first. That is
            the evidence, not a diagnosis.
          </span>
        </p>
      ) : (
        <p className="dim">
          No likely origin: {describeNoCandidate(incident.candidate_absent_because)}.
        </p>
      )}

      <h3>Timeline</h3>

      {timeline.isPending && <p className="dim">Reading every signal…</p>}

      {timeline.isError && (
        <div className="problem" role="alert">
          {message(timeline.error)}
        </div>
      )}

      {timeline.data && (
        <>
          <p className="dim">
            {timeline.data.resources.length} resource
            {timeline.data.resources.length === 1 ? "" : "s"}, every signal, on one axis.
          </p>

          {/* The coverage notes come first and only for the exceptions. A note on every
              row is a note nobody reads; the point is that expiry stands out. */}
          {timeline.data.tracks
            .map((track) => ({ track, note: describeCoverage(track) }))
            .filter(({ note }) => note !== null)
            .map(({ track, note }) => (
              <div key={track.signal} className="notice" role="status">
                {describeSignal(track.signal)}: {note}
              </div>
            ))}

          {moments.length === 0 ? (
            <p className="dim">
              No telemetry in this window from the resources this incident is about.
            </p>
          ) : (
            <div className="scroll-x">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Signal</th>
                    <th>What happened</th>
                  </tr>
                </thead>
                <tbody>
                  {moments.map((moment, i) => (
                    <tr key={`${moment.signal}-${moment.at}-${i}`}>
                      <td className="mono">{moment.at}</td>
                      <td>{describeSignal(moment.signal)}</td>
                      <td>{moment.text}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}
