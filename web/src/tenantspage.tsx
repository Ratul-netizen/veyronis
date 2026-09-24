/**
 * The customers this installation carries — `docs/tenant-lifecycle.md`.
 *
 * # Why this screen is the one that makes the rest mean something
 *
 * `TenantScope` is enforced by the type system, asserted across every route in
 * `isolation.rs`, and sold to buyers as *"one MSP engineer is admin on one customer and viewer
 * on another with a single account."* All of that was true and none of it was reachable:
 * `bootstrap_first_run` held the only `INSERT INTO tenant` outside tests and runs once, so an
 * installation had exactly one tenant, permanently.
 *
 * # Retiring says what it does not do
 *
 * §4.3 — telemetry is left to its retention, which runs up to three years for the hourly
 * metric rollup, and a purge is not built. So the confirmation lists the consequences
 * including that one. A dialogue that said "removed" would be the single place this product
 * lied to somebody who then told a regulator.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { message } from "./query";
import { useShell } from "./shell";
import {
  SLUG_MAX,
  type Tenant,
  createTenant,
  listTenants,
  renameTenant,
  restoreTenant,
  retireConsequences,
  retireTenant,
  slugProblem,
  suggestSlug,
  whyNotRetire,
} from "./tenants";

export function TenantsPage() {
  const { tenant: current } = useShell();
  const queries = useQueryClient();
  const tenants = useQuery({ queryKey: ["tenants"], queryFn: listTenants, retry: false });

  const refresh = () => {
    void queries.invalidateQueries({ queryKey: ["tenants"] });
    // `/me` is what the switcher reads, and a new tenant has to appear in it.
    void queries.invalidateQueries({ queryKey: ["me"] });
  };

  if (current.role !== "admin") {
    return (
      <>
        <h1>Customers</h1>
        <div className="problem" role="alert">
          Managing customers needs the admin role on every tenant in this organization — the
          same requirement as identity providers and collector assignment, because the decision
          is about more than one customer.
        </div>
      </>
    );
  }

  if (tenants.isPending) return <p className="dim">Reading the list…</p>;
  if (tenants.isError)
    return (
      <>
        <h1>Customers</h1>
        <div className="problem" role="alert">
          {message(tenants.error)}
        </div>
      </>
    );

  const rows = tenants.data ?? [];

  return (
    <>
      <h1>Customers</h1>
      <p className="dim">
        Each one is a separate estate. Somebody can be an administrator of one and see nothing
        at all of the next, which is what the isolation boundary is for.
      </p>

      <New onCreated={refresh} />

      <table className="rows">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Short name</th>
            <th scope="col" className="num">
              People
            </th>
            <th scope="col">State</th>
            <th scope="col" />
          </tr>
        </thead>
        <tbody>
          {rows.map((t) => (
            <Row key={t.id} tenant={t} tenants={rows} onChanged={refresh} />
          ))}
        </tbody>
      </table>
    </>
  );
}

function Row({
  tenant,
  tenants,
  onChanged,
}: {
  tenant: Tenant;
  tenants: Tenant[];
  onChanged: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  const act = useMutation({
    mutationFn: (what: "retire" | "restore") =>
      what === "retire" ? retireTenant(tenant.id) : restoreTenant(tenant.id),
    onSuccess: () => {
      setProblem(null);
      setConfirming(false);
      onChanged();
    },
    onError: (e) => setProblem(message(e)),
  });

  const retired = Boolean(tenant.retired_at);
  const blocked = whyNotRetire(tenant, tenants);

  return (
    <>
      <tr className={retired ? "dim" : undefined}>
        <td>
          {tenant.name}
          {tenant.is_platform && (
            <>
              {" "}
              <span
                className="mono dim"
                title="Carries the events about this installation itself"
              >
                platform
              </span>
            </>
          )}
        </td>
        <td className="mono">{tenant.slug}</td>
        <td className="num">{tenant.members}</td>
        <td>{retired ? <span className="attention">retired</span> : <span>active</span>}</td>
        <td>
          {retired ? (
            <button type="button" disabled={act.isPending} onClick={() => act.mutate("restore")}>
              Restore
            </button>
          ) : (
            <button
              type="button"
              className="quiet"
              disabled={act.isPending || Boolean(blocked)}
              title={blocked ?? "Stops polling and alerting. Keeps the estate"}
              onClick={() => setConfirming(true)}
            >
              Retire
            </button>
          )}
          <button
            type="button"
            className="quiet"
            onClick={() => setRenaming((was) => !was)}
            disabled={act.isPending}
          >
            {renaming ? "Cancel" : "Rename"}
          </button>
        </td>
      </tr>

      {blocked && !retired && (
        <tr>
          <td colSpan={5}>
            <p className="dim">{blocked}</p>
          </td>
        </tr>
      )}

      {problem && (
        <tr>
          <td colSpan={5}>
            <div className="problem" role="alert">
              {problem}
            </div>
          </td>
        </tr>
      )}

      {confirming && (
        <tr>
          <td colSpan={5}>
            <div className="notice" role="note">
              <h2>Retire {tenant.name}?</h2>
              <ul>
                {retireConsequences(tenant).map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
              <button type="button" disabled={act.isPending} onClick={() => act.mutate("retire")}>
                {act.isPending ? "Retiring…" : "Retire it"}
              </button>
              <button type="button" className="quiet" onClick={() => setConfirming(false)}>
                Keep it
              </button>
            </div>
          </td>
        </tr>
      )}

      {renaming && (
        <tr>
          <td colSpan={5}>
            <Rename
              tenant={tenant}
              onDone={() => {
                setRenaming(false);
                onChanged();
              }}
            />
          </td>
        </tr>
      )}
    </>
  );
}

function Rename({ tenant, onDone }: { tenant: Tenant; onDone: () => void }) {
  const [name, setName] = useState(tenant.name);
  const [slug, setSlug] = useState(tenant.slug);

  const save = useMutation({
    mutationFn: () => renameTenant(tenant.id, name.trim(), slug.trim()),
    onSuccess: onDone,
  });

  const problem = slugProblem(slug.trim());

  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (!problem) save.mutate();
      }}
    >
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} required />
      </label>
      <label>
        Short name
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          required
          maxLength={SLUG_MAX}
        />
      </label>
      {problem && (
        <div className="problem" role="alert">
          {problem}
        </div>
      )}
      <button type="submit" disabled={save.isPending || Boolean(problem) || !name.trim()}>
        Save
      </button>
      {save.isError && (
        <div className="problem" role="alert">
          {message(save.error)}
        </div>
      )}
    </form>
  );
}

function New({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  // Tracked so the suggestion stops following the name the moment somebody edits it — a field
  // that keeps overwriting what you typed is worse than one that never helped.
  const [touched, setTouched] = useState(false);

  const create = useMutation({
    mutationFn: () => createTenant(name.trim(), slug.trim()),
    onSuccess: () => {
      setName("");
      setSlug("");
      setTouched(false);
      onCreated();
    },
  });

  const problem = slug ? slugProblem(slug.trim()) : null;

  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (!problem) create.mutate();
      }}
    >
      <h2>Add a customer</h2>
      <p className="dim">
        You become its administrator — somebody has to be able to grant the next person
        access, and nothing else could.
      </p>
      <label>
        Name
        <input
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            if (!touched) setSlug(suggestSlug(e.target.value));
          }}
          required
        />
      </label>
      <label>
        Short name
        <input
          value={slug}
          onChange={(e) => {
            setTouched(true);
            setSlug(e.target.value);
          }}
          required
          maxLength={SLUG_MAX}
        />
      </label>
      {problem && (
        <div className="problem" role="alert">
          {problem}
        </div>
      )}
      <button
        type="submit"
        disabled={create.isPending || Boolean(problem) || !name.trim() || !slug.trim()}
      >
        {create.isPending ? "Adding…" : "Add"}
      </button>
      {create.isError && (
        <div className="problem" role="alert">
          {message(create.error)}
        </div>
      )}
    </form>
  );
}
