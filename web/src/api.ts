/**
 * The only place this app talks to the server.
 *
 * Three things are true of every request, and each is a decision made on the Rust side
 * that this file is the mirror of:
 *
 * 1. **The session is a cookie nothing here can read.** `uops_session` is HttpOnly, so
 *    there is no token in JavaScript, no token in `localStorage`, and nothing for an
 *    XSS to steal and replay from another machine. The cost is that every request must
 *    say `credentials: "include"`, and a request that forgets is simply unauthenticated.
 *    That is why there is one `request` function and not a `fetch` anywhere else.
 *
 * 2. **Mutations echo the CSRF cookie in a header.** `uops_csrf` is deliberately *not*
 *    HttpOnly — it exists to be read by this file and sent back in `X-Uops-Csrf`. A
 *    cross-site form post carries the cookie but cannot read it to set the header, which
 *    is the whole of the double-submit defence. `POST /api/v1/query` is a read and still
 *    sends it: the exemption list is where this kind of mistake lives.
 *
 * 3. **Every scoped request names its tenant.** The server will not guess. A request
 *    without `X-Uops-Tenant` is rejected rather than defaulted, and a tenant the user
 *    cannot see comes back 404 rather than 403 — so this file cannot tell "does not
 *    exist" from "not yours", which is exactly the point.
 */

/** RFC 7807, which is what every error from this API is. */
import type { Plan, Run, RunDetail, Runbook } from "./runbooks";

export interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly problem: Problem | null;

  constructor(status: number, problem: Problem | null, fallback: string) {
    super(problem?.detail ?? problem?.title ?? fallback);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }

  /** The session is gone or was never there. The router sends these to /login. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }
}

/**
 * Read a cookie by name.
 *
 * Only ever used for `uops_csrf`, which is the one cookie this app is meant to see. If
 * this is ever called with `uops_session` it will return undefined, because that cookie
 * is HttpOnly — and that is the design working, not a bug to route around.
 */
function cookie(name: string): string | undefined {
  for (const part of document.cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

const CSRF_COOKIE = "uops_csrf";
const CSRF_HEADER = "X-Uops-Csrf";
const TENANT_HEADER = "X-Uops-Tenant";

export interface RequestOptions {
  method?: string;
  body?: unknown;
  /** Required for every route except /auth/login, /auth/logout, /me and /health. */
  tenant?: string;
  signal?: AbortSignal;
}

/**
 * One request to the API.
 *
 * @throws {ApiError} for any non-2xx response, with the server's problem document when
 * it sent one. A network failure throws too, with status 0 — the caller has to handle
 * "the server said no" and "there was no server" the same way, because a user cannot
 * tell them apart either.
 */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers = new Headers();

  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.tenant) headers.set(TENANT_HEADER, options.tenant);

  // Sent on every method that is not a plain read, including POST /query — see above.
  if (method !== "GET" && method !== "HEAD") {
    const token = cookie(CSRF_COOKIE);
    if (token) headers.set(CSRF_HEADER, token);
  }

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: "include",
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError(0, null, "the server could not be reached");
  }

  if (response.status === 204) return undefined as T;

  const text = await response.text();

  if (!response.ok) {
    let problem: Problem | null = null;
    try {
      problem = JSON.parse(text) as Problem;
    } catch {
      // A proxy or a crash, not this API. Fall through to the status line.
    }
    throw new ApiError(response.status, problem, `${response.status} ${response.statusText}`);
  }

  return text ? (JSON.parse(text) as T) : (undefined as T);
}

// ---------------------------------------------------------------------------
// The shapes the server actually returns. Kept next to the client rather than in a
// types file, so that a change to a handler and a change to its type are one diff.
// ---------------------------------------------------------------------------

export type Role = "viewer" | "operator" | "admin";

export interface TenantMembership {
  tenant_id: string;
  name: string;
  slug: string;
  role: Role;
}

export interface Me {
  user_id: string;
  email: string;
  display_name: string;
  tenants: TenantMembership[];
}

/** Matches ResourceStatus in uops-core. */
export const STATUSES = [
  "up",
  "down",
  "degraded",
  "unknown",
  "maintenance",
  "decommissioned",
] as const;

export type ResourceStatus = (typeof STATUSES)[number];

/** How a device identified itself. Inventory, not secrets — a viewer may read these. */
export interface Identifier {
  kind: string;
  value: string;
  confidence: number;
  source: string;
}

export interface Resource {
  id: string;
  tenant_id: string;
  kind: string;
  name: string;
  display_name: string | null;
  vendor: string | null;
  model: string | null;
  os: string | null;
  os_version: string | null;
  status: ResourceStatus;
  site_id: string | null;
  parent_id: string | null;
  attributes: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
}

export interface Page<T> {
  items: T[];
  /**
   * An opaque keyset cursor, or null at the end.
   *
   * Opaque on purpose: it encodes the sort key of the last row, and a client that takes
   * it apart is a client that breaks when the sort changes. Pass it back verbatim.
   */
  next: string | null;
}

/** Signed degrees, WGS 84 — what a phone or a map reports. */
export interface Coordinate {
  latitude: number;
  longitude: number;
}

/** Resources at a site, by status. */
export interface SiteCounts {
  up: number;
  down: number;
  degraded: number;
  unknown: number;
  maintenance: number;
  /** Decommissioned resources are in none of the above and not in this either. */
  total: number;
}

/**
 * A site as the map draws it.
 *
 * `location` is absent for most sites, for most customers: an operator places the ones
 * that matter. The map lists the rest beside it rather than dropping them, because a
 * site missing from a map looks like a site with nothing wrong.
 */
export interface Site {
  id: string;
  name: string;
  timezone: string;
  location?: Coordinate;
  resources: SiteCounts;
}

/**
 * A resource group, as the context picker lists them.
 *
 * `members` rather than the members themselves: a picker showing forty groups must not
 * read forty membership lists to render forty numbers.
 */
export interface Group {
  id: string;
  name: string;
  description: string;
  members: number;
}

/**
 * One identity provider's button on the sign-in page.
 *
 * A name and a URL, and nothing else — no issuer, no client id. The endpoint that
 * produces these is reachable without a session, and an unauthenticated stranger
 * enumerating a company's identity provider is a gift to whoever is phishing that
 * company. See `SignInOption` on the server.
 */
export interface SignInMethod {
  id: string;
  name: string;
  start: string;
}

export const api = {
  /**
   * The sign-in methods this deployment offers.
   *
   * Asked before anybody has signed in, so it takes no tenant and carries no session.
   * An empty list is the ordinary answer for a deployment with no SSO configured, and
   * the page simply shows the password form on its own.
   */
  signInMethods: () =>
    request<{ providers: SignInMethod[] }>("/api/v1/auth/methods"),

  login: (email: string, password: string) =>
    request<void>("/api/v1/auth/login", { method: "POST", body: { email, password } }),

  logout: () => request<void>("/api/v1/auth/logout", { method: "POST" }),

  me: () => request<Me>("/api/v1/me"),

  /**
   * The inventory, narrowed.
   *
   * `filter` is whatever the shell's context means — see `contextParams` — plus a cursor.
   * Undefined entries are dropped rather than sent empty, because `?site=` is a filter
   * the server would have to decide the meaning of, and the answer it would pick is not
   * obviously "no filter".
   */
  /** Everything known about who a device is — used to find its management address. */
  identifiers: (tenant: string, id: string) =>
    request<Identifier[]>(`/api/v1/resources/${id}/identifiers`, { tenant }),

  resources: (tenant: string, filter: Record<string, string | undefined> = {}) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(filter)) {
      if (value) query.set(key, value);
    }
    const suffix = query.size > 0 ? `?${query.toString()}` : "";
    return request<Page<Resource>>(`/api/v1/resources${suffix}`, { tenant });
  },

  sites: (tenant: string) => request<Site[]>("/api/v1/sites", { tenant }),

  groups: (tenant: string) => request<Group[]>("/api/v1/groups", { tenant }),

  placeSite: (tenant: string, id: string, location: Coordinate | null) =>
    request<void>(`/api/v1/sites/${encodeURIComponent(id)}/location`, {
      method: "PUT",
      tenant,
      body: { location },
    }),

  resource: (tenant: string, id: string) =>
    request<Resource>(`/api/v1/resources/${encodeURIComponent(id)}`, { tenant }),

  setResourceStatus: (tenant: string, id: string, status: string) =>
    request<Resource>(`/api/v1/resources/${encodeURIComponent(id)}/status`, {
      method: "PATCH",
      body: { status },
      tenant,
    }),

  decommission: (tenant: string, id: string) =>
    request<Resource>(`/api/v1/resources/${encodeURIComponent(id)}`, {
      method: "DELETE",
      tenant,
    }),

  // --- runbooks, M10 -----------------------------------------------------------
  //
  // Note what is absent: nothing here executes anything. `startRun` posts a row and
  // `uops-runner` picks it up, so every one of these returns in milliseconds and the
  // run's own state is what says what happened to it.

  runbooks: (tenant: string) => request<Runbook[]>("/api/v1/runbooks", { tenant }),

  saveRunbook: (tenant: string, runbook: unknown) =>
    request<Runbook>("/api/v1/runbooks", { method: "POST", tenant, body: runbook }),

  retireRunbook: (tenant: string, id: string) =>
    request<void>(`/api/v1/runbooks/${encodeURIComponent(id)}`, {
      method: "DELETE",
      tenant,
    }),

  /**
   * What a run would do, without creating one.
   *
   * A POST despite writing nothing: it resolves a selector across the estate, and that is
   * not a thing to put in a URL a reverse proxy will log.
   */
  planRun: (tenant: string, id: string) =>
    request<Plan>(`/api/v1/runbooks/${encodeURIComponent(id)}/plan`, {
      method: "POST",
      tenant,
      body: {},
    }),

  /**
   * Record a run.
   *
   * `dryRun` is required at this boundary although the server defaults it to `true`: a
   * caller here has a screen in front of it and has made the choice, and an omitted
   * argument that silently means "safe" is how the *other* branch gets taken by accident
   * somewhere else later.
   */
  startRun: (tenant: string, id: string, reason: string, dryRun: boolean) =>
    request<Run>(`/api/v1/runbooks/${encodeURIComponent(id)}/runs`, {
      method: "POST",
      tenant,
      body: { reason, dry_run: dryRun },
    }),

  runs: (tenant: string, runbook?: string) => {
    const suffix = runbook ? `?runbook=${encodeURIComponent(runbook)}` : "";
    return request<Run[]>(`/api/v1/runs${suffix}`, { tenant });
  },

  run: (tenant: string, id: string) =>
    request<RunDetail>(`/api/v1/runs/${encodeURIComponent(id)}`, { tenant }),

  approveRun: (tenant: string, id: string) =>
    request<Run>(`/api/v1/runs/${encodeURIComponent(id)}/approve`, {
      method: "POST",
      tenant,
      body: {},
    }),

  cancelRun: (tenant: string, id: string) =>
    request<Run>(`/api/v1/runs/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
      tenant,
      body: {},
    }),
};
