/**
 * Ingest tokens — `docs/packaging.md` §4.2.
 *
 * The credential that lets a machine somebody else administers send telemetry into this
 * customer's estate. Until it existed the OTLP listener authenticated nobody: whatever could
 * reach the port wrote into its tenant, as any resource it named.
 *
 * # Why this screen is not optional
 *
 * A token that can only be minted with `psql` is a feature nobody has. This product has
 * produced that shape repeatedly — the audit log, user administration, the LLDP walk — and the
 * lesson each time was that a capability is not reachable until there is a screen.
 */

import { request } from "./api";

export interface IngestToken {
  id: string;
  /** What somebody will recognise in six months. */
  label: string;
  created_at: string;
  created_by?: string;
  /** Absent means it does not expire. */
  expires_at?: string;
  revoked_at?: string;
  /** Whether it would authorise a write right now — the server computes it. */
  live: boolean;
}

/** What the server returns once, and never again. */
export interface MintedToken {
  id: string;
  expires_at?: string;
  token: string;
}

export function listTokens(tenant: string): Promise<IngestToken[]> {
  return request<IngestToken[]>("/api/v1/ingest/tokens", { tenant });
}

export function mintToken(
  tenant: string,
  label: string,
  expiresInDays?: number,
): Promise<MintedToken> {
  return request<MintedToken>("/api/v1/ingest/tokens", {
    method: "POST",
    tenant,
    body: { label, expires_in_days: expiresInDays },
  });
}

export function revokeToken(tenant: string, id: string): Promise<void> {
  return request<void>(`/api/v1/ingest/tokens/${id}`, { method: "DELETE", tenant });
}

// ---------------------------------------------------------------------------
// The rules the screen shows, testable without a browser.
// ---------------------------------------------------------------------------

/** Matches `ingest_token`'s `UNIQUE (tenant_id, label)` — a name within one tenant. */
export function labelProblem(label: string, existing: IngestToken[]): string | null {
  const trimmed = label.trim();
  if (trimmed.length === 0) return "A name is required";
  if (trimmed.length > 60) return "At most 60 characters";
  if (existing.some((t) => t.label === trimmed && !t.revoked_at)) {
    return "A live token already uses that name";
  }
  return null;
}

/**
 * What state a token is in, in one word.
 *
 * Three states and not two: *revoked* and *expired* both mean it will not authorise a write,
 * and they mean different things about what happened. An operator scanning for "why did that
 * host stop reporting" needs to tell "somebody revoked this" from "nobody renewed it".
 */
export function tokenState(token: IngestToken, now = new Date()): "live" | "revoked" | "expired" {
  if (token.revoked_at) return "revoked";
  if (token.expires_at && new Date(token.expires_at).getTime() <= now.getTime()) {
    return "expired";
  }
  return "live";
}

/** When it stops working, in words somebody can act on. */
export function expiryNote(token: IngestToken, now = new Date()): string {
  if (!token.expires_at) return "does not expire";
  const ms = new Date(token.expires_at).getTime() - now.getTime();
  if (Number.isNaN(ms)) return "unknown";
  if (ms <= 0) return "expired";
  const days = Math.floor(ms / 86_400_000);
  if (days >= 2) return `expires in ${days} days`;
  const hours = Math.floor(ms / 3_600_000);
  if (hours >= 1) return `expires in ${hours} hour${hours === 1 ? "" : "s"}`;
  return "expires within the hour";
}

/**
 * The command somebody runs on the host they want telemetry from.
 *
 * An OTel Collector exporter block rather than a `curl`, because that is what the thing at the
 * other end actually is — `PLAN` settled that the per-host agent is a distribution of theirs
 * and not an agent of ours, so the useful artefact is their configuration with our endpoint and
 * this token in it.
 *
 * The endpoint is left as a placeholder the operator fills in. The product genuinely does not
 * know it: the listener binds inside a collector on some network, and the address an emitter
 * should use is a routing question about the estate rather than a fact the server holds.
 * Guessing it from the browser's own URL would be wrong in exactly the deployments that matter
 * — a reverse proxy in front, a collector on a different segment.
 */
export function exporterConfig(token: string, endpoint = "<your-otlp-endpoint>"): string {
  return `exporters:
  otlphttp:
    endpoint: http://${endpoint}:4318
    headers:
      Authorization: "Bearer ${token}"

service:
  pipelines:
    metrics: { exporters: [otlphttp] }
    logs:    { exporters: [otlphttp] }`;
}

/**
 * The sentence beside a freshly minted token.
 *
 * Shown once, and the product has no mail transport — the same position
 * `docs/user-administration.md` §4.1 takes for invitations, and for the same reason: an
 * air-gapped installation may never have one.
 */
export const SHOWN_ONCE =
  "Copy this now. Only a hash of it is stored, so it cannot be shown again — if you lose it, \
revoke it and mint another.";
