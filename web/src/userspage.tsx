/**
 * The people in an organization — `docs/user-administration.md`.
 *
 * Two tabs, because there are two questions and two authorisations behind them. **People**
 * is organization-level: who exists, who is suspended, who holds break-glass. **Access** is
 * one tenant's membership: who may see this customer, and as what.
 *
 * # This screen is why the store functions were worth having
 *
 * `create_user`, `grant_role`, `revoke_role` and `disable_user` have existed since M1 and
 * were called by seventeen test files and nothing in production. An installation using
 * passwords had one user, forever; nobody could disable a departing employee without `psql`.
 *
 * # An invited person is not a user, and the screen says so
 *
 * There is no account until somebody accepts — migration 0030, because users are never
 * deleted and an account per invitation would make every mistyped address permanent. So
 * pending invitations are their own list, with *withdraw* rather than *disable*.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import type { Role } from "./api";
import { message } from "./query";
import { useShell } from "./shell";
import {
  CONVEY_OUT_OF_BAND,
  type Invitation,
  type Invited,
  type Member,
  type User,
  describeSignIn,
  designateBreakGlass,
  disable,
  enable,
  expiresIn,
  grantRole,
  invite,
  listInvitations,
  listMembers,
  listUsers,
  revokeRole,
  withdraw,
} from "./users";

type Tab = "people" | "access";

export function UsersPage() {
  const { tenant } = useShell();
  const [tab, setTab] = useState<Tab>("people");

  if (tenant.role !== "admin") {
    // Said rather than hidden, for the reason the audit log's nav entry gives: a control
    // that vanishes by role is one people ask each other about.
    return (
      <>
        <h1>People</h1>
        <div className="problem" role="alert">
          Managing people needs the admin role. Organization-wide changes need it on every
          tenant, which is what stops one customer's admin administering another's.
        </div>
      </>
    );
  }

  return (
    <>
      <h1>People</h1>
      <p className="dim">
        Who can sign in to this installation, and who may see which customer.
      </p>

      <div className="topo-controls">
        <span className="presets">
          <button type="button" aria-pressed={tab === "people"} onClick={() => setTab("people")}>
            People
          </button>
          <button type="button" aria-pressed={tab === "access"} onClick={() => setTab("access")}>
            Access to {tenant.name}
          </button>
        </span>
      </div>

      {tab === "people" ? <People /> : <Access tenant={tenant.tenant_id} />}
    </>
  );
}

// ---------------------------------------------------------------------------
// People — organization-level
// ---------------------------------------------------------------------------

function People() {
  const { me } = useShell();
  const queries = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: listUsers, retry: false });
  const invitations = useQuery({
    queryKey: ["invitations"],
    queryFn: listInvitations,
    retry: false,
  });

  const [issued, setIssued] = useState<Invited | null>(null);

  const refresh = () => {
    void queries.invalidateQueries({ queryKey: ["users"] });
    void queries.invalidateQueries({ queryKey: ["invitations"] });
  };

  if (users.isPending) return <p className="dim">Reading the list…</p>;
  if (users.isError)
    return (
      <div className="problem" role="alert">
        {message(users.error)}
      </div>
    );

  return (
    <>
      <Invite
        onInvited={(i) => {
          setIssued(i);
          refresh();
        }}
      />

      {issued && <TheLink invited={issued} onDismiss={() => setIssued(null)} />}

      {(invitations.data?.length ?? 0) > 0 && (
        <Pending invitations={invitations.data ?? []} onChanged={refresh} />
      )}

      <h2>Accounts</h2>
      <table className="rows">
        <thead>
          <tr>
            <th scope="col">Who</th>
            <th scope="col">Signs in with</th>
            <th scope="col">State</th>
            <th scope="col" />
          </tr>
        </thead>
        <tbody>
          {(users.data ?? []).map((u) => (
            <Person key={u.id} user={u} me={me.user_id} onChanged={refresh} />
          ))}
        </tbody>
      </table>
    </>
  );
}

function Person({
  user,
  me,
  onChanged,
}: {
  user: User;
  me: string;
  onChanged: () => void;
}) {
  const [problem, setProblem] = useState<string | null>(null);

  const act = useMutation({
    mutationFn: (what: "disable" | "enable" | "break-glass") =>
      what === "disable"
        ? disable(user.id)
        : what === "enable"
          ? enable(user.id)
          : designateBreakGlass(user.id),
    onSuccess: () => {
      setProblem(null);
      onChanged();
    },
    // The last-administrator refusal arrives here as a 409 and is shown verbatim. The
    // screen does not try to predict it — see `whyNotDisable`.
    onError: (e) => setProblem(message(e)),
  });

  const suspended = Boolean(user.disabled_at);
  const isMe = user.id === me;

  return (
    <>
      <tr className={suspended ? "dim" : undefined}>
        <td>
          {user.display_name}
          {isMe && <span className="dim"> — you</span>}
          <br />
          <span className="mono dim">{user.email}</span>
        </td>
        <td>{describeSignIn(user)}</td>
        <td>
          {suspended ? (
            <span className="attention">suspended</span>
          ) : (
            <span>active</span>
          )}
          {user.break_glass && (
            <>
              <br />
              <span className="mono dim" title="The one account allowed a password when this organization requires single sign-on">
                break-glass
              </span>
            </>
          )}
        </td>
        <td>
          {suspended ? (
            <button type="button" disabled={act.isPending} onClick={() => act.mutate("enable")}>
              Restore
            </button>
          ) : (
            <button
              type="button"
              className="quiet"
              disabled={act.isPending || isMe}
              title={
                isMe
                  ? "You cannot disable your own account. Ask another administrator"
                  : "Ends every session immediately"
              }
              onClick={() => act.mutate("disable")}
            >
              Suspend
            </button>
          )}
          {!user.break_glass && !suspended && (
            <button
              type="button"
              className="quiet"
              disabled={act.isPending}
              title="Allow this account a password even when single sign-on is required"
              onClick={() => act.mutate("break-glass")}
            >
              Make break-glass
            </button>
          )}
        </td>
      </tr>
      {problem && (
        <tr>
          <td colSpan={4}>
            <div className="problem" role="alert">
              {problem}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Inviting
// ---------------------------------------------------------------------------

function Invite({ onInvited }: { onInvited: (i: Invited) => void }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");

  const send = useMutation({
    mutationFn: () => invite(email.trim(), name.trim()),
    onSuccess: (i) => {
      onInvited(i);
      setEmail("");
      setName("");
    },
  });

  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        send.mutate();
      }}
    >
      <h2>Invite somebody</h2>
      <p className="dim">
        They choose their own password. Nobody here sets it — an administrator who knew it
        would make this installation&rsquo;s audit log name the wrong person.
      </p>
      <label>
        Their name
        <input value={name} onChange={(e) => setName(e.target.value)} required />
      </label>
      <label>
        Email
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
      </label>
      <button type="submit" disabled={send.isPending || !email.trim() || !name.trim()}>
        {send.isPending ? "Inviting…" : "Invite"}
      </button>
      {send.isError && (
        <div className="problem" role="alert">
          {message(send.error)}
        </div>
      )}
    </form>
  );
}

/**
 * The link, shown once.
 *
 * `docs/user-administration.md` §4.1: there is no organization-level mail transport, and an
 * air-gapped installation may never have one. So this is the delivery mechanism, and it says
 * so — an invitation that silently goes nowhere is the failure mode of every product that
 * assumed it had a mail server.
 */
function TheLink({ invited, onDismiss }: { invited: Invited; onDismiss: () => void }) {
  const url = `${window.location.origin}/invitation/${invited.link_token}`;
  const [copied, setCopied] = useState(false);

  return (
    <div className="notice" role="note">
      <h2>Send them this link</h2>
      <p>{CONVEY_OUT_OF_BAND}</p>
      <pre className="mono raw-trace">{url}</pre>
      <button
        type="button"
        onClick={() => {
          void navigator.clipboard?.writeText(url).then(() => setCopied(true));
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
      <button type="button" className="quiet" onClick={onDismiss}>
        Done
      </button>
    </div>
  );
}

function Pending({
  invitations,
  onChanged,
}: {
  invitations: Invitation[];
  onChanged: () => void;
}) {
  return (
    <>
      <h2>Invited, not yet accepted</h2>
      <p className="dim">
        No account exists for these yet, which is why they are withdrawn rather than
        suspended — a mistyped address leaves nothing behind.
      </p>
      <table className="rows">
        <thead>
          <tr>
            <th scope="col">Who</th>
            <th scope="col">Link</th>
            <th scope="col" />
          </tr>
        </thead>
        <tbody>
          {invitations.map((i) => (
            <PendingRow key={i.id} invitation={i} onChanged={onChanged} />
          ))}
        </tbody>
      </table>
    </>
  );
}

function PendingRow({
  invitation,
  onChanged,
}: {
  invitation: Invitation;
  onChanged: () => void;
}) {
  const drop = useMutation({
    mutationFn: () => withdraw(invitation.id),
    onSuccess: onChanged,
  });

  return (
    <tr>
      <td>
        {invitation.display_name}
        <br />
        <span className="mono dim">{invitation.email}</span>
      </td>
      <td className="dim">{expiresIn(invitation)}</td>
      <td>
        <button
          type="button"
          className="quiet"
          disabled={drop.isPending}
          onClick={() => drop.mutate()}
        >
          Withdraw
        </button>
        {drop.isError && (
          <div className="problem" role="alert">
            {message(drop.error)}
          </div>
        )}
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Access — one tenant's membership
// ---------------------------------------------------------------------------

const ROLES: Role[] = ["viewer", "operator", "admin"];

function Access({ tenant }: { tenant: string }) {
  const queries = useQueryClient();
  const members = useQuery({
    queryKey: ["members", tenant],
    queryFn: () => listMembers(tenant),
    retry: false,
  });
  const users = useQuery({ queryKey: ["users"], queryFn: listUsers, retry: false });

  const refresh = () => void queries.invalidateQueries({ queryKey: ["members", tenant] });

  if (members.isPending) return <p className="dim">Reading who has access…</p>;
  if (members.isError)
    return (
      <div className="problem" role="alert">
        {message(members.error)}
      </div>
    );

  const rows = members.data ?? [];
  const holding = new Set(rows.map((m) => m.user));
  const without = (users.data ?? []).filter((u) => !holding.has(u.id) && !u.disabled_at);

  return (
    <>
      <p className="dim">
        A role is per customer. Somebody can be an administrator here and see nothing at all
        of the next tenant, which is what the isolation guarantee is for.
      </p>

      <table className="rows">
        <thead>
          <tr>
            <th scope="col">Who</th>
            <th scope="col">Role</th>
            <th scope="col" />
          </tr>
        </thead>
        <tbody>
          {rows.map((m) => (
            <MemberRow key={m.user} member={m} tenant={tenant} onChanged={refresh} />
          ))}
        </tbody>
      </table>

      {without.length > 0 && <Add tenant={tenant} candidates={without} onChanged={refresh} />}
    </>
  );
}

function MemberRow({
  member,
  tenant,
  onChanged,
}: {
  member: Member;
  tenant: string;
  onChanged: () => void;
}) {
  const [problem, setProblem] = useState<string | null>(null);

  const change = useMutation({
    mutationFn: (role: Role) => grantRole(tenant, member.user, role),
    onSuccess: () => {
      setProblem(null);
      onChanged();
    },
    onError: (e) => setProblem(message(e)),
  });
  const remove = useMutation({
    mutationFn: () => revokeRole(tenant, member.user),
    onSuccess: () => {
      setProblem(null);
      onChanged();
    },
    onError: (e) => setProblem(message(e)),
  });

  const busy = change.isPending || remove.isPending;

  return (
    <>
      <tr className={member.disabled ? "dim" : undefined}>
        <td>
          {member.display_name}
          {member.disabled && <span className="attention"> — suspended</span>}
          <br />
          <span className="mono dim">{member.email}</span>
        </td>
        <td>
          <select
            value={member.role}
            disabled={busy}
            onChange={(e) => change.mutate(e.target.value as Role)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </td>
        <td>
          <button
            type="button"
            className="quiet"
            disabled={busy}
            onClick={() => remove.mutate()}
          >
            Remove
          </button>
        </td>
      </tr>
      {problem && (
        <tr>
          <td colSpan={3}>
            <div className="problem" role="alert">
              {problem}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function Add({
  tenant,
  candidates,
  onChanged,
}: {
  tenant: string;
  candidates: User[];
  onChanged: () => void;
}) {
  const [who, setWho] = useState("");
  const [role, setRole] = useState<Role>("viewer");

  const give = useMutation({
    mutationFn: () => grantRole(tenant, who, role),
    onSuccess: () => {
      setWho("");
      onChanged();
    },
  });

  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        give.mutate();
      }}
    >
      <h2>Give somebody access</h2>
      <label>
        Who
        <select value={who} onChange={(e) => setWho(e.target.value)} required>
          <option value="">Choose…</option>
          {candidates.map((u) => (
            <option key={u.id} value={u.id}>
              {u.display_name} — {u.email}
            </option>
          ))}
        </select>
      </label>
      <label>
        As
        <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </label>
      <button type="submit" disabled={give.isPending || !who}>
        Give access
      </button>
      {give.isError && (
        <div className="problem" role="alert">
          {message(give.error)}
        </div>
      )}
    </form>
  );
}
