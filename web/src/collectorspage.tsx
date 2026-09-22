/**
 * Collectors — what is running, what has stopped, and which customers each may carry.
 *
 * M12 §2.3. Before this screen a syslog daemon that died three days ago looked exactly
 * like a quiet network, and nothing in the product could tell the difference.
 *
 * # Not tenant-scoped, unlike every other screen
 *
 * A collector belongs to an organization and often serves several of its tenants, so the
 * context bar's tenant does not narrow this list — and the routes behind it need the
 * admin role on *every* tenant, which is why a viewer sees a refusal rather than an empty
 * table. Both are stated on the screen rather than left to be inferred from a list that
 * does not change when the tenant switcher does.
 *
 * # The token is shown once
 *
 * Only its hash is stored, so the response to minting one is the single moment it exists.
 * That is a real constraint rather than a UI flourish, and the screen says so where
 * somebody is about to close the panel.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ApiError } from "./api";
import {
  ago,
  api,
  describeBound,
  describeHealth,
  describeUses,
  health,
  tokenState,
  type Collector,
} from "./collectors";
import { useShell } from "./shell";

export function CollectorsPage() {
  const { me } = useShell();
  const queryClient = useQueryClient();

  const collectors = useQuery({
    queryKey: ["collectors"],
    queryFn: () => api.collectors(),
    retry: false,
    // Half the heartbeat interval, so a collector that stopped shows up within about a
    // minute of the server deciding it has. Polling rather than pushing: this is a
    // screen somebody leaves open on a wall, and a websocket for one table would be a
    // second transport to operate.
    refetchInterval: 15_000,
  });

  const tokens = useQuery({
    queryKey: ["collector-tokens"],
    queryFn: () => api.tokens(),
    retry: false,
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["collectors"] });
    void queryClient.invalidateQueries({ queryKey: ["collector-tokens"] });
  };

  const forbidden =
    collectors.error instanceof ApiError && collectors.error.status === 403;

  if (forbidden) {
    return (
      <>
        <h1>Collectors</h1>
        <div className="problem" role="alert">
          Managing collectors needs the admin role on every tenant in this organization.
          An assignment decides whose telemetry a collector may carry, so it is a decision
          about more than one customer.
        </div>
      </>
    );
  }

  const rows = collectors.data ?? [];

  return (
    <>
      <h1>Collectors</h1>
      <p className="dim">
        Every collector this organization has enrolled, across all of its tenants — so the
        tenant switcher does not narrow this list.
      </p>

      {collectors.isPending && <p className="dim">Loading…</p>}

      {collectors.isError && !forbidden && (
        <div className="problem" role="alert">
          The collector inventory could not be read.
        </div>
      )}

      {collectors.data && rows.length === 0 && (
        <div className="empty-state">
          <h1>No collectors enrolled</h1>
          <p>
            Collectors keep working without enrolling — they read their own listener file,
            the way they always have. Enrolling one puts it in this list, notices when it
            stops, and moves the decision about which customers it may carry from its own
            configuration to here.
          </p>
          <p>
            Issue an enrolment token below, then set <code>UOPS_COLLECTOR_TOKEN</code> on
            the collector and restart it.
          </p>
        </div>
      )}

      {rows.length > 0 && <Inventory rows={rows} onChange={refresh} tenants={me.tenants} />}

      <Tokens
        tokens={tokens.data ?? []}
        pending={tokens.isPending}
        failed={tokens.isError}
        onChange={refresh}
      />
    </>
  );
}

function Inventory({
  rows,
  tenants,
  onChange,
}: {
  rows: Collector[];
  tenants: { tenant_id: string; name: string }[];
  onChange: () => void;
}) {
  const named = new Map(tenants.map((t) => [t.tenant_id, t.name]));

  // Quiet first, then never-reported, then everything else. The list is read during an
  // incident, and a box that has stopped is what somebody is looking for — sorting by
  // name would bury it at position nineteen.
  const rank = (c: Collector): number =>
    ({ quiet: 0, silent: 1, reporting: 2, retired: 3 })[health(c)];
  const sorted = [...rows].sort((a, b) => {
    const by = rank(a) - rank(b);
    return by !== 0 ? by : a.name.localeCompare(b.name);
  });

  return (
    <div className="scroll-x">
      <table>
        <thead>
          <tr>
            <th>Collector</th>
            <th>Kind</th>
            <th>State</th>
            <th>Last heard</th>
            <th>Version</th>
            <th>Serving</th>
            <th className="num">Received</th>
            <th className="num">Written</th>
            <th className="num">Lost</th>
            <th>Bound to</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {sorted.map((c) => (
            <Row key={c.id} collector={c} named={named} tenants={tenants} onChange={onChange} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Row({
  collector,
  named,
  tenants,
  onChange,
}: {
  collector: Collector;
  named: Map<string, string>;
  tenants: { tenant_id: string; name: string }[];
  onChange: () => void;
}) {
  const state = health(collector);
  const { label, detail } = describeHealth(collector);
  const [assigning, setAssigning] = useState(false);

  const retire = useMutation({
    mutationFn: () => api.retire(collector.id),
    onSuccess: onChange,
  });
  const assign = useMutation({
    mutationFn: (tenantId: string) => api.assign(collector.id, tenantId),
    onSuccess: () => {
      setAssigning(false);
      onChange();
    },
  });
  const unassign = useMutation({
    mutationFn: (tenantId: string) => api.unassign(collector.id, tenantId),
    onSuccess: onChange,
  });

  const unassigned = tenants.filter((t) => !collector.tenants.includes(t.tenant_id));

  return (
    <tr>
      <td>
        {collector.name}
        {collector.hostname && collector.hostname !== collector.name && (
          <>
            <br />
            <span className="dim">{collector.hostname}</span>
          </>
        )}
      </td>
      <td>{collector.kind}</td>
      <td>
        {/* A word in the colour of its state, like `.severity` — not an outlined
            capsule, for the reason styles.css gives: a page of pills reads as a page of
            buttons. `title` is where somebody finds out that "quiet" means go and look
            at the box rather than at the configuration. */}
        <span className={`state ${state}`} title={detail}>
          {label}
        </span>
      </td>
      <td title={collector.last_seen_at ?? "never"}>{ago(collector.last_seen_at)}</td>
      <td>{collector.version ?? "—"}</td>
      <td>
        {collector.tenants.length === 0 ? (
          // Not an empty cell. A collector assigned nothing serves nothing, and that is
          // a state somebody has to act on rather than one to leave looking blank.
          <span className="warn">nothing assigned</span>
        ) : (
          <ul className="chips">
            {collector.tenants.map((id) => (
              <li key={id}>
                {named.get(id) ?? id}
                <button
                  type="button"
                  className="chip-remove"
                  aria-label={`Stop ${collector.name} serving ${named.get(id) ?? id}`}
                  onClick={() => unassign.mutate(id)}
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        )}
        {assigning ? (
          <select
            aria-label={`Assign a tenant to ${collector.name}`}
            defaultValue=""
            onChange={(e) => e.target.value && assign.mutate(e.target.value)}
          >
            <option value="" disabled>
              Choose a tenant…
            </option>
            {unassigned.map((t) => (
              <option key={t.tenant_id} value={t.tenant_id}>
                {t.name}
              </option>
            ))}
          </select>
        ) : (
          unassigned.length > 0 && (
            <button type="button" className="link" onClick={() => setAssigning(true)}>
              Assign a tenant
            </button>
          )
        )}
      </td>
      <td className="num">{collector.received.toLocaleString()}</td>
      <td className="num">{collector.written.toLocaleString()}</td>
      {/* The one number that means data loss, so it is marked when it is not zero
          rather than left to be noticed in a column of three. */}
      <td className={collector.lost > 0 ? "num bad" : "num"}>
        {collector.lost.toLocaleString()}
      </td>
      <td className="dim">{describeBound(collector.reported)}</td>
      <td className="actions">
        {!collector.retired && (
          <button
            type="button"
            onClick={() => retire.mutate()}
            disabled={retire.isPending}
            title="Retire this collector. If it starts reporting again it comes back on its own."
          >
            Retire
          </button>
        )}
      </td>
    </tr>
  );
}

function Tokens({
  tokens,
  pending,
  failed,
  onChange,
}: {
  tokens: import("./collectors").EnrolmentToken[];
  pending: boolean;
  failed: boolean;
  onChange: () => void;
}) {
  const [label, setLabel] = useState("");
  const [uses, setUses] = useState("");
  const [minted, setMinted] = useState<string | null>(null);

  const issue = useMutation({
    // Built rather than spread with an `undefined`: `exactOptionalPropertyTypes` draws
    // the distinction between "absent" and "present and undefined", and absent is what
    // "unlimited uses" means on the wire.
    mutationFn: () =>
      api.issueToken(
        uses.trim() === ""
          ? { label: label.trim() }
          : { label: label.trim(), uses: Number(uses) },
      ),
    onSuccess: (result) => {
      setMinted(result.token);
      setLabel("");
      setUses("");
      onChange();
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeToken(id),
    onSuccess: onChange,
  });

  return (
    <section>
      <h2>Enrolment tokens</h2>
      <p className="dim">
        A token puts a collector in this inventory. It is not a credential for the
        databases — a collector already holds those — so what it decides is which
        collectors exist and, through the assignment above, which customers they may
        carry.
      </p>

      {minted && (
        <div className="notice" role="status">
          <strong>Copy this now.</strong> Only its hash is stored, so this is the one time
          it is shown. Set it as <code>UOPS_COLLECTOR_TOKEN</code> on the collector.
          <pre className="token">{minted}</pre>
          <button type="button" onClick={() => setMinted(null)}>
            Done
          </button>
        </div>
      )}

      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          issue.mutate();
        }}
      >
        <label>
          Label
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="site-berlin"
            required
          />
        </label>
        <label>
          Uses
          <input
            type="number"
            min={1}
            value={uses}
            onChange={(e) => setUses(e.target.value)}
            placeholder="unlimited"
          />
        </label>
        <button type="submit" className="primary" disabled={issue.isPending}>
          {issue.isPending ? "Issuing…" : "Issue a token"}
        </button>
      </form>

      {issue.isError && (
        <div className="problem" role="alert">
          {issue.error instanceof ApiError
            ? issue.error.message
            : "The token could not be issued."}
        </div>
      )}

      {pending && <p className="dim">Loading…</p>}
      {failed && (
        <div className="problem" role="alert">
          The enrolment tokens could not be read.
        </div>
      )}

      {tokens.length > 0 && (
        <div className="scroll-x">
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>Kind</th>
                <th>Uses</th>
                <th>State</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => {
                const state = tokenState(t);
                return (
                  <tr key={t.id}>
                    <td>{t.label}</td>
                    <td>{t.kind ?? "any"}</td>
                    <td>{describeUses(t)}</td>
                    <td>
                      <span className={`state ${state}`}>{state}</span>
                    </td>
                    <td title={t.created_at}>{ago(t.created_at)}</td>
                    <td className="actions">
                      {state === "usable" && (
                        <button
                          type="button"
                          onClick={() => revoke.mutate(t.id)}
                          title="Revoke this token. Collectors it already brought up keep working."
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
