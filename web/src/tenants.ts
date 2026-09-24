/**
 * The customers an installation carries — `docs/tenant-lifecycle.md`.
 *
 * Until this existed, `bootstrap_first_run` held the only `INSERT INTO tenant` outside tests
 * and runs once, so an installation had exactly one tenant permanently — and the MSP shape
 * `docs/security-overview.md` describes (*"admin on one customer and viewer on another with a
 * single account"*) was not reachable.
 */

import { request } from "./api";

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  created_at: string;
  /** Set when retired. Reversible, and not deletion — the estate is still there. */
  retired_at?: string;
  /** Carries the installation's own events. Cannot be retired while it does. */
  is_platform: boolean;
  /** How many people hold a role here. */
  members: number;
}

export function listTenants(): Promise<Tenant[]> {
  return request<Tenant[]>("/api/v1/tenants");
}

export function createTenant(name: string, slug: string): Promise<Tenant> {
  return request<Tenant>("/api/v1/tenants", { method: "POST", body: { name, slug } });
}

export function renameTenant(id: string, name: string, slug: string): Promise<void> {
  return request<void>(`/api/v1/tenants/${id}`, { method: "PATCH", body: { name, slug } });
}

export function retireTenant(id: string): Promise<void> {
  return request<void>(`/api/v1/tenants/${id}/retire`, { method: "POST" });
}

export function restoreTenant(id: string): Promise<void> {
  return request<void>(`/api/v1/tenants/${id}/restore`, { method: "POST" });
}

// ---------------------------------------------------------------------------
// The rules the screen shows, kept here so they can be tested without a browser.
// ---------------------------------------------------------------------------

export const SLUG_MIN = 2;
/** A DNS label, which is the shape a slug ends up in — migration 0031 says why. */
export const SLUG_MAX = 63;

/**
 * Why this slug will be refused, or `null` when it will not.
 *
 * Mirrors `tenant_slug_is_a_label` in migration 0031 and `check_slug` in the route. Three
 * places, and the schema is the one that counts — this exists so somebody reads a sentence
 * while typing rather than a constraint name after submitting.
 */
export function slugProblem(slug: string): string | null {
  if (slug.length < SLUG_MIN) return `At least ${SLUG_MIN} characters`;
  if (slug.length > SLUG_MAX) return `At most ${SLUG_MAX} characters`;
  if (!/^[a-z0-9-]+$/.test(slug)) return "Lowercase letters, digits and hyphens only";
  if (slug.startsWith("-") || slug.endsWith("-")) return "It cannot start or end with a hyphen";
  if (slug.includes("--")) return "One hyphen at a time";
  return null;
}

/**
 * A slug suggested from a name, as somebody types it.
 *
 * A convenience and never a constraint: the field stays editable, because a customer called
 * "Müller & Co." should not have its short name decided by a transliteration table. What this
 * produces is always valid or empty, so it can never put the form into a state the server
 * will refuse.
 */
export function suggestSlug(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, SLUG_MAX)
    .replace(/-$/, "");
  return slug.length >= SLUG_MIN ? slug : "";
}

/**
 * Why this tenant cannot be retired from here, or `null` when it can.
 *
 * Both refusals are knowable in the browser from what the list already carries, unlike the
 * last-administrator rule on the People screen — so both are said before the click. The
 * server refuses them too; this is the explanation, not the check.
 */
export function whyNotRetire(tenant: Tenant, tenants: Tenant[]): string | null {
  if (tenant.retired_at) return null;
  if (tenant.is_platform) {
    return "This tenant carries the events about the installation itself. Nominate another for that first";
  }
  const otherLive = tenants.filter((t) => t.id !== tenant.id && !t.retired_at).length;
  if (otherLive === 0) {
    return "This is the only tenant left. An installation with none is one nobody can get back into";
  }
  return null;
}

/**
 * What retiring actually does, in the words somebody needs before confirming.
 *
 * Deliberately says what it does *not* do. `docs/tenant-lifecycle.md` §4.3: telemetry is left
 * to its retention, which runs up to three years for the hourly metric rollup, and a purge is
 * not built. A dialogue that implied "removed" would be the one place this product lied.
 */
export function retireConsequences(tenant: Tenant): string[] {
  return [
    `Polling, sweeping and alerting stop for ${tenant.name}.`,
    tenant.members === 1
      ? "One person loses access to it."
      : `${tenant.members} people lose access to it.`,
    "Its resources, sites, credentials and identity history are kept — this is not a deletion, and it can be undone.",
    "Telemetry already collected stays until its retention expires, which is up to three years for hourly metric rollups. There is no purge yet.",
  ];
}
