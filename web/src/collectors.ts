/**
 * The collector inventory — M12 §2.3.
 *
 * # What this screen exists to answer
 *
 * *Which of our collectors has stopped.* Everything else here is context for that one
 * question, which before this screen had no answer at all: a syslog daemon that died
 * three days ago looked exactly like a quiet network.
 *
 * # Three states, not two
 *
 * A collector is **reporting**, **quiet**, or has **never reported**, and conflating the
 * last two is the mistake worth avoiding. A box that enrolled and never sent a heartbeat
 * is a misconfiguration — wrong database, wrong credentials, a process that crashed on
 * its first tick — and somebody should go and look at the configuration. A box that
 * reported for a month and stopped is an outage, and somebody should go and look at the
 * box. They need different people.
 *
 * The server decides which is which, because the threshold is a product decision and a
 * client applying its own would disagree with the server about whether a site is down.
 */

import { request } from "./api";

/** A collector as the inventory lists it. */
export interface Collector {
  id: string;
  kind: string;
  name: string;
  hostname: string | null;
  version: string | null;
  /** What it says it is bound to. Shape varies by kind. */
  reported: unknown;
  enrolled_at: string;
  last_seen_at: string | null;
  started_at: string | null;
  received: number;
  written: number;
  lost: number;
  retired: boolean;
  quiet: boolean;
  never_reported: boolean;
  tenants: string[];
}

/** An enrolment token, without the token. */
export interface EnrolmentToken {
  id: string;
  label: string;
  kind: string | null;
  expires_at: string | null;
  uses_left: number | null;
  created_at: string;
  revoked: boolean;
}

export const api = {
  collectors: () => request<Collector[]>("/api/v1/collectors"),
  tokens: () => request<EnrolmentToken[]>("/api/v1/collectors/tokens"),

  /**
   * Mint a token. The response carries it **once** — only its hash is stored, so a
   * caller that loses it has to mint another.
   */
  issueToken: (body: {
    label: string;
    kind?: string;
    expires_at?: string;
    uses?: number;
  }) =>
    request<{ id: string; token: string }>("/api/v1/collectors/tokens", {
      method: "POST",
      body,
    }),

  revokeToken: (id: string) =>
    request<void>(`/api/v1/collectors/tokens/${id}`, { method: "DELETE" }),

  assign: (id: string, tenant_id: string) =>
    request<void>(`/api/v1/collectors/${id}/tenants`, {
      method: "POST",
      body: { tenant_id },
    }),

  unassign: (id: string, tenant_id: string) =>
    request<void>(
      `/api/v1/collectors/${id}/tenants?tenant_id=${encodeURIComponent(tenant_id)}`,
      { method: "DELETE" },
    ),

  retire: (id: string) =>
    request<void>(`/api/v1/collectors/${id}`, { method: "DELETE" }),
};

/** How a collector is doing, as one word plus the sentence behind it. */
export type Health = "reporting" | "quiet" | "silent" | "retired";

/**
 * Which of the four a row is in.
 *
 * Retired wins over everything: a box somebody has retired is not a box anybody should
 * be paged about, and showing it as quiet would put it back in the list of things to
 * worry about the moment it stopped.
 */
export function health(c: Collector): Health {
  if (c.retired) return "retired";
  if (c.never_reported) return "silent";
  if (c.quiet) return "quiet";
  return "reporting";
}

/** What the badge says, and what it means underneath. */
export function describeHealth(c: Collector): { label: string; detail: string } {
  switch (health(c)) {
    case "retired":
      return {
        label: "Retired",
        detail:
          "Somebody retired this collector. If it starts reporting again it will come back on its own.",
      };
    case "silent":
      return {
        label: "Never reported",
        detail:
          "It enrolled and has never sent a heartbeat. That is a configuration problem rather than an outage — check what it was given for a database and a token.",
      };
    case "quiet":
      return {
        label: "Quiet",
        detail: "It reported and then stopped. Check whether the process is running.",
      };
    case "reporting":
      return { label: "Reporting", detail: "Heard from within the last few minutes." };
  }
}

/**
 * How long ago, in words.
 *
 * Rounded down and never "0 seconds ago": a heartbeat that arrived this instant reads as
 * "just now", which is what somebody glancing at a list wants, and the exact second is
 * in the timestamp beside it for anybody who needs it.
 */
export function ago(iso: string | null, now = Date.now()): string {
  if (!iso) return "never";
  const seconds = Math.floor((now - Date.parse(iso)) / 1000);
  if (!Number.isFinite(seconds)) return "never";
  if (seconds < 0) return "just now";
  if (seconds < 45) return "just now";
  if (seconds < 90) return "a minute ago";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minutes ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours === 1 ? "an hour ago" : `${hours} hours ago`;
  const days = Math.floor(hours / 24);
  return days === 1 ? "a day ago" : `${days} days ago`;
}

/**
 * What a collector is bound to, as one line.
 *
 * The `reported` blob is whatever its kind sends, so this reads the two shapes that
 * exist rather than assuming one. Anything else renders as nothing at all, which is the
 * right outcome for a kind this build has not met: an empty cell beats `[object Object]`.
 */
export function describeBound(reported: unknown): string {
  if (!Array.isArray(reported)) {
    // The poller's shape: a description of what it is doing rather than what it is
    // bound to, because it binds nothing.
    if (reported && typeof reported === "object") {
      const o = reported as Record<string, unknown>;
      if (typeof o.device_limit === "number") {
        return `up to ${o.device_limit} devices per tenant`;
      }
    }
    return "";
  }

  return reported
    .map((entry) => {
      if (!entry || typeof entry !== "object") return "";
      const o = entry as Record<string, unknown>;
      const on = [o.udp, o.tcp, o.bind].filter(
        (v): v is string => typeof v === "string" && v.length > 0,
      );
      const tenant = typeof o.tenant === "string" ? o.tenant : "";
      return on.length > 0 ? `${tenant} on ${on.join(" + ")}` : tenant;
    })
    .filter((line) => line.length > 0)
    .join(", ");
}

/**
 * Whether a token can still bring anything up.
 *
 * Three ways it cannot, and they are worth distinguishing in the list: revoked is a
 * decision somebody made, expired is a clock, and spent is a count. All three read as
 * "no longer usable" and only one of them is somebody's doing.
 */
export function tokenState(
  t: EnrolmentToken,
  now = Date.now(),
): "usable" | "revoked" | "expired" | "spent" {
  if (t.revoked) return "revoked";
  if (t.expires_at && Date.parse(t.expires_at) <= now) return "expired";
  if (t.uses_left !== null && t.uses_left <= 0) return "spent";
  return "usable";
}

/** What a token's remaining uses say, in words. */
export function describeUses(t: EnrolmentToken): string {
  if (t.uses_left === null) return "unlimited";
  if (t.uses_left === 1) return "1 use left";
  return `${t.uses_left} uses left`;
}
