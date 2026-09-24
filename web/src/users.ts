/**
 * The people in an organization — `docs/user-administration.md`.
 *
 * Two questions, two authorisations, and the screen keeps them apart because the server
 * does. *Who is a person here* is organization-level and needs admin on every tenant.
 * *Who may see this customer* belongs to one tenant.
 *
 * # Why an invited person is not a user
 *
 * There is no account until somebody accepts, which is migration 0030's decision: users are
 * never deleted, so an account per invitation would make every mistyped address a permanent
 * row. So this file reads two lists and the screen shows them as two things — a pending
 * invitation is not somebody you can disable.
 */

import { request } from "./api";
import type { Role } from "./api";

export interface User {
  id: string;
  email: string;
  display_name: string;
  created_at: string;
  /** Set when suspended. Suspension is reversible and is not deletion. */
  disabled_at?: string;
  /** The one account allowed a password when the organization requires SSO. */
  break_glass: boolean;
  has_password: boolean;
  sso_linked: boolean;
}

export interface Invitation {
  id: string;
  email: string;
  display_name: string;
  invited_at: string;
  expires_at: string;
  invited_by?: string;
}

/** What the server returns once, and never again. */
export interface Invited {
  invitation: string;
  expires_at: string;
  link_token: string;
}

export interface Member {
  user: string;
  email: string;
  display_name: string;
  role: Role;
  disabled: boolean;
}

export function listUsers(): Promise<User[]> {
  return request<User[]>("/api/v1/users");
}

export function listInvitations(): Promise<Invitation[]> {
  return request<Invitation[]>("/api/v1/users/invitations");
}

export function invite(email: string, displayName: string): Promise<Invited> {
  return request<Invited>("/api/v1/users", {
    method: "POST",
    body: { email, display_name: displayName },
  });
}

export function withdraw(id: string): Promise<void> {
  return request<void>(`/api/v1/users/invitations/${id}`, { method: "DELETE" });
}

export function disable(id: string): Promise<void> {
  return request<void>(`/api/v1/users/${id}/disable`, { method: "POST" });
}

export function enable(id: string): Promise<void> {
  return request<void>(`/api/v1/users/${id}/enable`, { method: "POST" });
}

export function designateBreakGlass(id: string): Promise<void> {
  return request<void>(`/api/v1/users/${id}/break-glass`, { method: "POST" });
}

export function listMembers(tenant: string): Promise<Member[]> {
  return request<Member[]>("/api/v1/tenants/roles", { tenant });
}

export function grantRole(tenant: string, id: string, role: Role): Promise<void> {
  return request<void>(`/api/v1/users/${id}/role`, {
    method: "PUT",
    tenant,
    body: { role },
  });
}

export function revokeRole(tenant: string, id: string): Promise<void> {
  return request<void>(`/api/v1/users/${id}/role`, { method: "DELETE", tenant });
}

/** Redeem an invitation. Unauthenticated — whoever holds the link has no account yet. */
export function accept(token: string, password: string): Promise<void> {
  return request<void>(`/api/v1/invitations/${encodeURIComponent(token)}`, {
    method: "POST",
    body: { password },
  });
}

export function changePassword(current: string, next: string): Promise<void> {
  return request<void>("/api/v1/me/password", {
    method: "PUT",
    body: { current, new: next },
  });
}

// ---------------------------------------------------------------------------
// The rules the screen shows, kept here so they can be tested without a browser.
// ---------------------------------------------------------------------------

/** Matches `uops_secrets::password::MINIMUM_LENGTH`. A floor, and the whole policy. */
export const MINIMUM_PASSWORD_LENGTH = 12;

/**
 * How somebody can sign in, in words.
 *
 * Three states the product genuinely distinguishes, and the screen has to as well: an
 * account with a password, one that comes from the identity provider, and one that has
 * neither — which is only reachable if an administrator has been in the database, because
 * migration 0024 refuses it.
 */
export function describeSignIn(user: User): string {
  if (user.has_password && user.sso_linked) return "password or single sign-on";
  if (user.sso_linked) return "single sign-on";
  if (user.has_password) return "password";
  return "cannot sign in";
}

/**
 * Why this account cannot be suspended from here, or `null` when it can.
 *
 * Only one refusal is knowable in the browser: that the account is the caller's own. That
 * one is worth saying *before* the click, because "ask another administrator" is an
 * instruction and a 400 afterwards is a surprise.
 *
 * The other refusal — the last administrator of a tenant — deliberately is **not** guessed
 * at here. The server decides it under a lock, across every tenant in the organization, and
 * a screen that tried would need every tenant's membership to do it. Guessing wrong means
 * hiding a control somebody needs, which is worse than a 409 that explains itself. So the
 * button stays and the conflict is shown.
 */
export function whyNotDisable(user: User, me: string): string | null {
  if (user.disabled_at) return null;
  if (user.id === me) {
    return "You cannot disable your own account. Ask another administrator";
  }
  return null;
}

/** A password the server will accept, or the reason it will not. */
export function passwordProblem(password: string, confirm?: string): string | null {
  if ([...password].length < MINIMUM_PASSWORD_LENGTH) {
    return `At least ${MINIMUM_PASSWORD_LENGTH} characters. Length is what makes a password \
expensive to attack; nothing here asks for a symbol.`;
  }
  if (confirm !== undefined && password !== confirm) return "The two do not match";
  return null;
}

/**
 * When an invitation stops working, in words somebody can act on.
 *
 * Hours rather than a timestamp near the end: "expires in 3 hours" is the difference
 * between re-sending now and discovering tomorrow that they never got in.
 */
export function expiresIn(invitation: Invitation, now = new Date()): string {
  const ms = new Date(invitation.expires_at).getTime() - now.getTime();
  if (Number.isNaN(ms)) return "unknown";
  if (ms <= 0) return "expired";
  const hours = Math.floor(ms / 3_600_000);
  if (hours < 1) return "expires within the hour";
  if (hours < 48) return `expires in ${hours} hour${hours === 1 ? "" : "s"}`;
  return `expires in ${Math.floor(hours / 24)} days`;
}

/**
 * The sentence shown beside a freshly minted invitation link.
 *
 * `docs/user-administration.md` §4.1: the product has no organization-level mail transport,
 * and an air-gapped installation may never have one. So the link is shown once and the
 * screen says what to do with it — an invitation that silently goes nowhere is the failure
 * mode of every product that assumed it had a mail server.
 */
export const CONVEY_OUT_OF_BAND =
  "Send this link to them yourself — over chat, in person, however you already talk. \
It is shown once and is not stored anywhere it can be read back, so if you lose it, \
invite them again.";
