/**
 * Objectives — `docs/slo.md`.
 *
 * Under **Observability**, beside Services, because an objective is a statement about a
 * service.
 *
 * # Three things this screen says out loud
 *
 * **"sampled"**, wherever a number comes from traces. §2.2: the ratio is sound over a
 * sample and a count is not, so the screen shows the ratio and never prints a remaining
 * error count — the number every competitor shows and this product cannot honestly
 * produce, because it does not know the sampling denominator.
 *
 * **"no traffic"**, for a window with no requests in it. Not 100%. An objective that reads
 * green because nobody called the service is the failure that makes an operator stop
 * believing the screen.
 *
 * **"nothing pages anybody"**, once, near the objectives it applies to. §2.4 ships the
 * measurement and deliberately not the alert, and a screen full of green badges implies a
 * promise the product is not keeping unless it says so.
 */

import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { message, runQuery } from "./query";
import { serviceName, serviceNames } from "./services";
import { useShell } from "./shell";
import {
  type Counted,
  type Slo,
  asPercent,
  attainmentQuery,
  budgetConsumed,
  counted,
  describeWindow,
  listSlos,
  removeSlo,
  setSlo,
  sli,
  verdict,
} from "./slo";

/** The windows offered. The ones people actually set. */
const WINDOWS = [7, 28, 30, 90];

export function SloPage() {
  const { tenant } = useShell();
  const client = useQueryClient();

  // One instant for every objective on the screen, so two rows cannot be measured over
  // windows that end a second apart — and so the queries are stable across re-renders
  // rather than producing a fresh key each time, which is the loop `overview.tsx` records
  // finding by pointing a browser at it.
  const [now] = useState(() => new Date());

  const slos = useQuery({
    queryKey: ["slos", tenant.tenant_id],
    queryFn: () => listSlos(tenant.tenant_id),
    retry: false,
  });

  const rows = useMemo(() => slos.data ?? [], [slos.data]);

  const attainment = useQueries({
    queries: rows.map((s) => ({
      queryKey: ["slo-attainment", tenant.tenant_id, s.id, now.toISOString()],
      queryFn: () => runQuery(tenant.tenant_id, attainmentQuery(s, now)),
      retry: false,
      staleTime: 60_000,
    })),
  });

  const names = useQuery({
    queryKey: ["service-names", tenant.tenant_id],
    queryFn: () => serviceNames(tenant.tenant_id),
    retry: false,
    staleTime: 60_000,
  });
  const naming = names.data ?? new Map<string, string>();

  return (
    <>
      <h1>Objectives</h1>
      <p className="dim">
        What share of requests should succeed, over what window.
      </p>

      {slos.isError && (
        <div className="problem" role="alert">
          {message(slos.error)}
        </div>
      )}

      <Declare
        tenant={tenant.tenant_id}
        onDone={() => void client.invalidateQueries({ queryKey: ["slos"] })}
      />

      {slos.isPending && <p className="dim">Reading objectives…</p>}

      {!slos.isPending && rows.length === 0 && (
        <div className="empty-state">
          <h1>No objectives set</h1>
          <p>
            An objective is a target this organisation chooses — this product does not ship
            defaults, because the share of requests that may fail is a business decision
            rather than a technical one.
          </p>
        </div>
      )}

      {rows.length > 0 && (
        <>
          <p className="notice" role="note">
            These are measurements. <strong>Nothing here pages anybody</strong> when an
            objective is missed — burn-rate alerting is an alert rule, and the windows that
            should wake somebody are yours to choose.
          </p>

          <table className="rows slos">
            <thead>
              <tr>
                <th scope="col">Objective</th>
                <th scope="col">Service</th>
                <th scope="col">Window</th>
                <th scope="col" className="num">
                  Target
                </th>
                <th scope="col" className="num">
                  Sampled SLI
                </th>
                <th scope="col">Error budget</th>
                <th scope="col" />
              </tr>
            </thead>
            <tbody>
              {rows.map((s, i) => (
                <Row
                  key={s.id}
                  slo={s}
                  service={serviceName(s.service_id, naming)}
                  counts={counted(attainment[i]?.data)}
                  pending={attainment[i]?.isPending ?? true}
                  failed={attainment[i]?.isError ?? false}
                  tenant={tenant.tenant_id}
                  onRemoved={() => void client.invalidateQueries({ queryKey: ["slos"] })}
                />
              ))}
            </tbody>
          </table>

          <p className="dim">
            The SLI is a ratio over <strong>sampled</strong> spans. A ratio over an unbiased
            sample estimates the ratio over everything, which is why it is shown — and why a
            remaining error <em>count</em> is not: that needs the sampling denominator, and
            this product does not know it.
          </p>
        </>
      )}
    </>
  );
}

function Row({
  slo,
  service,
  counts,
  pending,
  failed,
  tenant,
  onRemoved,
}: {
  slo: Slo;
  service: string;
  counts: Counted | null;
  pending: boolean;
  failed: boolean;
  tenant: string;
  onRemoved: () => void;
}) {
  const { tenant: membership } = useShell();
  const indicator = sli(counts);
  const consumed = budgetConsumed(slo, counts);
  const state = verdict(slo, counts);

  const remove = useMutation({
    mutationFn: () => removeSlo(tenant, slo.id),
    onSuccess: onRemoved,
  });

  return (
    <tr className={state === "missed" ? "attention" : undefined}>
      <th scope="row">{slo.name}</th>
      <td>{service}</td>
      <td className="dim">{describeWindow(slo.window_days)}</td>
      <td className="num mono">{asPercent(slo.target)}</td>
      <td className="num mono">
        {pending ? (
          <span className="dim">…</span>
        ) : failed ? (
          <span className="dim">unreadable</span>
        ) : indicator === null ? (
          // Not 100%. A service nobody called did not succeed.
          <span className="dim" title="No sampled requests in this window">
            no traffic
          </span>
        ) : (
          asPercent(indicator)
        )}
      </td>
      <td>
        {consumed === null ? (
          <span className="dim">—</span>
        ) : (
          <div
            className="track"
            title={`${Math.round(consumed * 100)}% of the error budget consumed`}
          >
            <div
              className={`bar${state === "missed" ? " bad" : state === "at-risk" ? " warn" : ""}`}
              style={{ width: `${Math.min(consumed, 1) * 100}%` }}
              aria-hidden="true"
            />
          </div>
        )}
      </td>
      <td>
        {membership.role !== "viewer" && (
          <button
            type="button"
            className="danger"
            onClick={() => remove.mutate()}
            disabled={remove.isPending}
          >
            Remove
          </button>
        )}
        {remove.isError && <span className="problem-inline">{message(remove.error)}</span>}
      </td>
    </tr>
  );
}

/** Setting an objective. Operator only — the server enforces it; this hides the form. */
function Declare({ tenant, onDone }: { tenant: string; onDone: () => void }) {
  const { tenant: membership } = useShell();
  const [name, setName] = useState("");
  const [serviceId, setServiceId] = useState("");
  const [percent, setPercent] = useState("99.9");
  const [windowDays, setWindowDays] = useState(30);

  const services = useQuery({
    queryKey: ["service-names", tenant],
    queryFn: () => serviceNames(tenant),
    retry: false,
    staleTime: 60_000,
  });

  const save = useMutation({
    mutationFn: () =>
      setSlo(tenant, {
        name,
        service_id: serviceId,
        // The form takes a percentage because that is how people say it, and converts
        // once, here. The API takes a proportion and says so if it is handed 99.
        target: Number(percent) / 100,
        window_days: windowDays,
      }),
    onSuccess: () => {
      setName("");
      onDone();
    },
  });

  if (membership.role === "viewer") return null;

  const known = [...(services.data ?? new Map<string, string>()).entries()];

  return (
    <form
      className="explore-form"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Checkout" required />
      </label>
      <label>
        Service
        {known.length > 0 ? (
          <select value={serviceId} onChange={(e) => setServiceId(e.target.value)} required>
            <option value="">Choose a service</option>
            {known.map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </select>
        ) : (
          // A service appears in `service_5m` as soon as a span carries it, and the
          // inventory row arrives separately — so an id typed by hand is legitimate.
          <input
            value={serviceId}
            onChange={(e) => setServiceId(e.target.value)}
            placeholder="service id"
            required
          />
        )}
      </label>
      <label>
        Target
        <input
          type="number"
          value={percent}
          onChange={(e) => setPercent(e.target.value)}
          min="50.001"
          max="99.999"
          step="0.001"
          required
        />
        %
      </label>
      <label>
        Window
        <select value={windowDays} onChange={(e) => setWindowDays(Number(e.target.value))}>
          {WINDOWS.map((d) => (
            <option key={d} value={d}>
              {describeWindow(d)}
            </option>
          ))}
        </select>
      </label>
      <button type="submit" className="primary" disabled={save.isPending}>
        Set
      </button>
      {save.isError && (
        <p className="problem-inline" role="alert">
          {message(save.error)}
        </p>
      )}
    </form>
  );
}
