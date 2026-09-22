/**
 * Incidents — M9, `docs/M9-incident.md`, as the client sees them.
 *
 * # The three words this file refuses to say
 *
 * **"Root cause."** §2.5: nothing here observes causation. The topology observes
 * direction and the incident observes order, so the field is `candidate` and the screen
 * says *likely origin*, always beside the two facts it was derived from.
 *
 * **"Resolved."** §2.1: every alert going quiet moves an incident to `quiet`, never to
 * `closed`. Closing is a claim that it is understood, and only a human makes one.
 *
 * **"Nothing happened."** §2.6: a signal whose retention has passed comes back `expired`
 * rather than empty, because an empty track reads as silence — and "this is gone" and
 * "nothing was happening" are opposite conclusions to reach during an investigation.
 */

import { request } from "./api";

export type IncidentState = "open" | "quiet" | "closed";

/** Whether a signal could answer for the window, and what survives if only some of it. */
export type CoverageKind = "whole" | "partial" | "expired";

export interface Incident {
  id: string;
  state: IncidentState;
  severity: "info" | "warning" | "critical";
  /** §2.5 — the candidate, never the cause. `null` when there is none. */
  candidate_resource_id: string | null;
  /** What to call it. The server falls back to the id, because an id is a fact. */
  candidate_name: string | null;
  /**
   * `no_topology` or `disconnected`, and empty when there *is* a candidate.
   *
   * §2.3: an incident of one on an estate with no links is correct and looks identical
   * to a bug unless it can say why.
   */
  candidate_absent_because: string;
  started_at: string;
  last_alert_at: string;
  quiet_at: string | null;
  closed_at: string | null;
  acked_at: string | null;
  summary: string;
  alerts: number;
  /** How many alerts §2.4 silenced. Sent even when zero. */
  suppressed: number;
}

export interface Column {
  name: string;
  type: string;
}

export interface Track {
  signal: string;
  coverage: CoverageKind;
  /** Where the rows start when the window was clamped to what survives. */
  from: string | null;
  retention_days: number;
  columns: Column[];
  rows: unknown[][];
}

export interface Timeline {
  incident: string;
  start: string;
  end: string;
  resources: string[];
  tracks: Track[];
}

export function listIncidents(tenant: string) {
  return request<Incident[]>("/api/v1/incidents", { tenant });
}

export function fetchTimeline(tenant: string, id: string) {
  return request<Timeline>(`/api/v1/incidents/${id}/timeline`, { tenant });
}

export function acknowledgeIncident(tenant: string, id: string) {
  return request<Incident>(`/api/v1/incidents/${id}/ack`, { method: "POST", tenant });
}

export function closeIncident(tenant: string, id: string) {
  return request<Incident>(`/api/v1/incidents/${id}/close`, { method: "POST", tenant });
}

/**
 * Whether this tenant lets topology suppression stop a notification — M9 §2.4.
 *
 * The one setting in the incident engine that can cause a **missed outage**: the product
 * deciding, from a topology it inferred, that somebody does not need to be woken up.
 */
export interface Suppression {
  suppress_downstream_alerts: boolean;
}

export function fetchSuppression(tenant: string) {
  return request<Suppression>("/api/v1/incidents/suppression", { tenant });
}

export function setSuppression(tenant: string, on: boolean) {
  return request<Suppression>("/api/v1/incidents/suppression", {
    method: "PUT",
    tenant,
    body: { suppress_downstream_alerts: on },
  });
}

/**
 * What switching it says, in the words somebody needs before clicking.
 *
 * Both directions have a consequence and the screen says which. "On" is the one that can
 * lose a page; "off" is the one that brings back every downstream alert an operator may
 * have turned this on to stop.
 */
export function describeSuppression(on: boolean): string {
  return on
    ? "When one device's failure explains another's, only the cause is notified. Every suppressed alert is still on the incident, and the notification says how many it stood for."
    : "Every alert notifies, including the ones a failure upstream already explains. A switch going down pages once for the switch and once for everything behind it.";
}

/**
 * The standing caveat, shown in both positions.
 *
 * Not a general caution: the specific failure. A product that says "are you sure?" and
 * nothing else has told the reader nothing they did not already know.
 *
 * Shown when the switch is **on** as well as off, and that is the point — the risk is not
 * in the moment of clicking, it is in every page that does not arrive afterwards. A
 * warning that disappears once somebody accepts it is a warning nobody sees again.
 */
export const SUPPRESSION_RISK =
  "This is the only setting here that can cause a missed outage: if the topology is wrong about which device explains which, the notification that was suppressed was the one somebody needed.";

/**
 * The extra line shown only while it is off.
 *
 * Advice about a decision that has not been made yet, so it has no place beside a switch
 * that is already on.
 */
export const SUPPRESSION_ADVICE =
  "Turn it on after you have watched it group correctly on this estate.";

/**
 * What the state word means, in a sentence.
 *
 * `quiet` is the one that needs explaining: it is not resolved and it is not closed. The
 * alerts stopped and nobody has said it is understood, which is a real and common state —
 * the router stopped flapping at 02:14 and somebody will look at it at 09:00.
 */
export function describeState(state: IncidentState): string {
  switch (state) {
    case "open":
      return "alerts are still firing";
    case "quiet":
      return "every alert resolved; nobody has closed it";
    case "closed":
      return "closed by a person";
  }
}

/**
 * Why there is no likely origin.
 *
 * Never an empty cell. §2.5: an absent candidate is information, and a screen that shows
 * a blank where an explanation belongs looks broken rather than careful.
 */
export function describeNoCandidate(because: string): string {
  switch (because) {
    case "no_topology":
      return "nothing links this estate yet, so nothing is upstream of anything";
    case "disconnected":
      return "two resources failed with nothing above either; that is two stories";
    default:
      return "no single resource is upstream of the others";
  }
}

/**
 * One line about a track's coverage, or `null` when the whole window is there.
 *
 * `null` rather than "complete": a note on every row is a note nobody reads, and the
 * point is that the exceptions stand out.
 */
export function describeCoverage(track: Track): string | null {
  switch (track.coverage) {
    case "whole":
      return null;
    case "partial":
      return `kept ${track.retention_days} days — earlier rows have expired`;
    case "expired":
      return `expired: ${track.signal} is kept ${track.retention_days} days`;
  }
}

/** A signal's name, as a person reads it. */
export function describeSignal(signal: string): string {
  const names: Record<string, string> = {
    state: "Status changes",
    event: "Events",
    log: "Logs",
    metric: "Metrics",
    flow: "Flows",
    trace: "Traces",
  };
  return names[signal] ?? signal;
}

/**
 * Column index by name, because the server sends rows as arrays and not objects.
 *
 * The timeline's tracks each have their own column set — a log row and a flow row share
 * almost nothing — so this is resolved per track rather than once.
 */
export function indexer(track: Track): (name: string) => number {
  const at = new Map(track.columns.map((c, i) => [c.name, i]));
  return (name) => at.get(name) ?? -1;
}

/**
 * The one cell worth showing from a row of any signal.
 *
 * A timeline is one axis, so each row gets one line. Which column carries the meaning
 * depends on the signal: a log has a body, a state change has a transition, a flow has a
 * conversation. Falling back to the first non-timestamp column keeps a new signal
 * readable before this function learns about it.
 */
export function summarise(track: Track, row: unknown[]): string {
  const at = indexer(track);
  const cell = (name: string) => {
    const i = at(name);
    return i < 0 ? undefined : row[i];
  };

  switch (track.signal) {
    case "log":
    case "event":
      return String(cell("body") ?? cell("summary") ?? "");
    case "state":
      return `${cell("previous_status") ?? "?"} → ${cell("current_status") ?? "?"}`;
    case "metric":
      return `${cell("metric") ?? ""} ${cell("value") ?? ""}`.trim();
    case "flow":
      return `${cell("src_address") ?? ""} → ${cell("dst_address") ?? ""}`;
    case "trace":
      return `${cell("name") ?? ""} ${cell("status_code") ?? ""}`.trim();
    default: {
      const first = track.columns.findIndex(
        (c) => c.name !== "observed_at" && c.name !== "ingested_at",
      );
      return first < 0 ? "" : String(row[first] ?? "");
    }
  }
}

/** When a row happened, for the one axis everything is merged onto. */
export function observedAt(track: Track, row: unknown[]): string {
  const i = indexer(track)("observed_at");
  return i < 0 ? "" : String(row[i] ?? "");
}

/** One row of any signal, placed on the shared axis. */
export interface Moment {
  signal: string;
  at: string;
  text: string;
}

/**
 * Every track's rows on one axis, oldest first.
 *
 * The merge is here rather than on the server because the server already did the part
 * that needs a database: six range reads. Interleaving a few hundred rows by timestamp is
 * work the client can do while it draws them, and doing it server-side would mean a
 * second shape to keep in step with the first.
 */
export function merge(timeline: Timeline): Moment[] {
  const moments: Moment[] = [];
  for (const track of timeline.tracks) {
    for (const row of track.rows) {
      moments.push({
        signal: track.signal,
        at: observedAt(track, row),
        text: summarise(track, row),
      });
    }
  }
  // Stable within an instant: two rows with the same timestamp keep the order their
  // signals were returned in, which is the order §2.6 draws them — what changed, what was
  // said about it, what the traffic did.
  return moments.sort((a, b) => a.at.localeCompare(b.at));
}
