/**
 * The two logs — SPEC §M0.8.
 *
 * `audit_log` answers *who changed this, and to what*. `access_log` answers *who **saw**
 * this*, which is the unusual one and the reason SPEC asks for it: defence and
 * law-enforcement buyers audit reads, not only writes.
 *
 * Both have been written since M1 and neither could be read back until now — the store
 * functions were called only from tests.
 */

import { request } from "./api";

/** One mutating call. */
export interface Change {
  /** `user:<uuid>` | `collector` | `system`. */
  actor: string;
  /** Dotted and stable across releases: `resource.create`, `identity.merge`. */
  action: string;
  target: string;
  before?: unknown;
  after?: unknown;
  ip?: string;
}

/** One read. */
export interface Read {
  actor: string;
  /** `resource:<id>` | `resources` | `query` | `credential:<id>`. */
  target: string;
  /** The *shape* of a query and never its parameters — see the route's own docs. */
  fingerprint?: string;
  row_count?: number;
  ip?: string;
}

export function listChanges(tenant: string, limit = 200): Promise<Change[]> {
  return request<Change[]>(`/api/v1/audit/changes?limit=${limit}`, { tenant });
}

export function listReads(tenant: string, limit = 200): Promise<Read[]> {
  return request<Read[]>(`/api/v1/audit/reads?limit=${limit}`, { tenant });
}

/**
 * What an actor string means in words.
 *
 * `system` and `collector` are not people, and an auditor scanning for a person needs to
 * see that at a glance rather than decoding a prefix.
 */
export function describeActor(actor: string): string {
  if (actor === "system") return "the product itself";
  if (actor === "collector") return "a collector";
  const user = actor.startsWith("user:") ? actor.slice(5) : null;
  return user ? `user ${user.slice(0, 8)}` : actor;
}

/**
 * Whether a read is worth a second look.
 *
 * One rule, and it is about volume rather than identity: a query that returned a great
 * many rows is the difference between somebody looking something up and somebody taking a
 * copy of the estate. Deliberately not a judgement about *who* — the product does not know
 * which of its users is supposed to be running a big query.
 */
export const LARGE_READ = 10_000;

export function isLargeRead(read: Read): boolean {
  return (read.row_count ?? 0) >= LARGE_READ;
}

/**
 * Whether a change touched a credential.
 *
 * Credential actions are the ones an investigator starts from, and `audit_log` records
 * them by action name rather than by a flag — so this is a prefix test and is kept in one
 * place rather than spelled in the screen.
 */
export function touchedACredential(change: Change): boolean {
  return change.action.startsWith("credential.");
}

/** A count, grouped, or a dash when the log did not record one. */
export function humanRows(count: number | undefined): string {
  return count === undefined ? "—" : count.toLocaleString("en-GB");
}
