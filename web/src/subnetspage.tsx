/**
 * Addresses — `docs/ipam.md`.
 *
 * Under **Network**, because a range is inventory: what the estate is made of rather than
 * what it is doing.
 *
 * # The screen makes one judgement and shows the rest as numbers
 *
 * The judgement is *"something answered here that nothing in the inventory claims"*. That
 * is the finding an address inventory is bought for and it is the only row this screen
 * marks. Everything else — capacity, assigned, responding — is reported and left to the
 * reader, because `docs/ipam.md` §2.6 refuses "97% full": a single percentage hides
 * whether the remaining space is reserved.
 *
 * # What the empty state says
 *
 * That a range is a declaration. There is no discovery of subnets here and there
 * deliberately is not — §2.1 records why the list is not derived from the sweep
 * configuration — so a product that showed an empty screen with no explanation would look
 * broken rather than unconfigured.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { message } from "./query";
import { useShell } from "./shell";
import {
  ASSIGNMENTS,
  type Assignment,
  describeGuess,
  type Subnet,
  declareSubnet,
  forgetSubnet,
  listSubnets,
  needsAttention,
  occupancy,
  subnetAddresses,
  unknownAddresses,
} from "./subnets";

export function SubnetsPage() {
  const { tenant } = useShell();
  const client = useQueryClient();
  const [open, setOpen] = useState<string | null>(null);

  const subnets = useQuery({
    queryKey: ["subnets", tenant.tenant_id],
    queryFn: () => listSubnets(tenant.tenant_id),
    retry: false,
  });

  const rows = subnets.data ?? [];
  const strangers = rows.reduce((n, s) => n + s.unaccounted, 0);

  return (
    <>
      <h1>Addresses</h1>
      <p className="dim">
        Declared ranges, and what this product has seen in them.
      </p>

      {subnets.isError && (
        <div className="problem" role="alert">
          {message(subnets.error)}
        </div>
      )}

      {strangers > 0 && (
        <p className="notice" role="note">
          <strong>{strangers}</strong> address{strangers === 1 ? "" : "es"} answered in a
          declared range and nothing in the inventory claims{" "}
          {strangers === 1 ? "it" : "them"}. That is either a device nobody inventoried or a
          device somebody plugged in — this product does not guess which.
        </p>
      )}

      <Declare tenant={tenant.tenant_id} onDone={() => void client.invalidateQueries({ queryKey: ["subnets"] })} />

      {subnets.isPending && <p className="dim">Reading declared ranges…</p>}

      {!subnets.isPending && rows.length === 0 && (
        <div className="empty-state">
          <h1>No ranges declared</h1>
          <p>
            A range is something you declare, not something this product finds. Sweeping
            <Link to="/discovery"> discovers devices</Link>; this is the address space you
            want to keep an eye on, which is not always the same thing — a DHCP scope or a
            range reserved for a project that has not been built yet is address space with
            nothing in it.
          </p>
        </div>
      )}

      {rows.length > 0 && (
        <table className="rows subnets">
          <thead>
            <tr>
              <th scope="col">Range</th>
              <th scope="col">Name</th>
              <th scope="col">Assignment</th>
              <th scope="col" className="num">
                Usable
              </th>
              <th scope="col" className="num">
                Assigned
              </th>
              <th scope="col" className="num">
                Responding
              </th>
              <th scope="col" className="num">
                Unknown
              </th>
              <th scope="col">In use</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <SubnetRow
                key={s.id}
                subnet={s}
                tenant={tenant.tenant_id}
                open={open === s.id}
                onToggle={() => setOpen(open === s.id ? null : s.id)}
                onForget={() => void client.invalidateQueries({ queryKey: ["subnets"] })}
              />
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function SubnetRow({
  subnet,
  tenant,
  open,
  onToggle,
  onForget,
}: {
  subnet: Subnet;
  tenant: string;
  open: boolean;
  onToggle: () => void;
  onForget: () => void;
}) {
  const fraction = occupancy(subnet);
  const attention = needsAttention(subnet);

  const forget = useMutation({
    mutationFn: () => forgetSubnet(tenant, subnet.id),
    onSuccess: onForget,
  });

  return (
    <>
      <tr className={attention ? "attention" : undefined}>
        <td className="mono">{subnet.range}</td>
        <td>{subnet.name}</td>
        <td className="dim">{subnet.assignment}</td>
        <td className="num mono">{subnet.capacity.toLocaleString("en-GB")}</td>
        <td className="num mono">{subnet.assigned.toLocaleString("en-GB")}</td>
        <td className="num mono">{subnet.responding.toLocaleString("en-GB")}</td>
        {/* "Unknown", not "available": a device that is switched off answers nothing and
            still owns its address. */}
        <td className="num mono" title="Addresses nothing is known about — not necessarily free">
          {unknownAddresses(subnet).toLocaleString("en-GB")}
        </td>
        <td>
          {/* A bar, and no number beside it. §2.6 refuses a percentage; the bar is a
              shape for scanning a list, not a measurement. */}
          <div className="track" title="Share of usable addresses something is known about">
            <div
              className="bar"
              style={{ width: `${(fraction ?? 0) * 100}%` }}
              aria-hidden="true"
            />
          </div>
        </td>
        <td>
          <button type="button" onClick={onToggle} aria-expanded={open}>
            {open ? "Hide" : "Addresses"}
          </button>{" "}
          <button
            type="button"
            className="danger"
            onClick={() => forget.mutate()}
            disabled={forget.isPending}
            title="Forget this declaration. Nothing about the estate changes."
          >
            Forget
          </button>
        </td>
      </tr>
      {forget.isError && (
        <tr>
          <td colSpan={9} className="problem-inline">
            {message(forget.error)}
          </td>
        </tr>
      )}
      {open && (
        <tr>
          <td colSpan={9}>
            <Addresses tenant={tenant} id={subnet.id} />
          </td>
        </tr>
      )}
    </>
  );
}

/** What is in one range. Only addresses something is known about — a /16 is not listed. */
function Addresses({ tenant, id }: { tenant: string; id: string }) {
  const addresses = useQuery({
    queryKey: ["subnet-addresses", tenant, id],
    queryFn: () => subnetAddresses(tenant, id),
    retry: false,
  });

  if (addresses.isPending) return <p className="dim">Reading addresses…</p>;
  if (addresses.isError)
    return (
      <div className="problem" role="alert">
        {message(addresses.error)}
      </div>
    );

  const rows = addresses.data ?? [];
  if (rows.length === 0)
    return (
      <p className="dim">
        Nothing has been seen in this range. That is not the same as it being empty — a
        device that is switched off answers nothing.
      </p>
    );

  return (
    <table className="rows">
      <thead>
        <tr>
          <th scope="col">Address</th>
          <th scope="col">Resource</th>
          <th scope="col">Responding</th>
          <th scope="col">Last seen</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((a) => (
          <tr key={a.address} className={a.unaccounted ? "attention" : undefined}>
            <td className="mono">{a.address}</td>
            <td>
              {a.resource_id ? (
                <Link to="/resources/$id" params={{ id: a.resource_id }}>
                  {a.resource_name || a.resource_id}
                </Link>
              ) : (
                <>
                  <span className="warn">nothing claims this address</span>
                  {/* What it probably is, with the evidence in the tooltip. A guess a
                      reader cannot argue with is one they cannot safely act on — so the
                      hedge is in the sentence and the reasons are one hover away. */}
                  {a.guess && (
                    <span
                      className="dim"
                      title={a.guess.because.map((r) => `${r.from}: ${r.saying}`).join(" · ")}
                    >
                      {" "}
                      — {describeGuess(a.guess)}
                    </span>
                  )}
                </>
              )}
            </td>
            <td>{a.responding ? "yes" : <span className="dim">no</span>}</td>
            <td className="dim">{a.last_seen ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Declaring a range. Operator only — the server enforces it; this hides the form. */
function Declare({ tenant, onDone }: { tenant: string; onDone: () => void }) {
  const { tenant: membership } = useShell();
  const [range, setRange] = useState("");
  const [name, setName] = useState("");
  const [assignment, setAssignment] = useState<Assignment>("static");

  const declare = useMutation({
    mutationFn: () => declareSubnet(tenant, { range, name, assignment }),
    onSuccess: () => {
      setRange("");
      setName("");
      onDone();
    },
  });

  if (membership.role === "viewer") return null;

  return (
    <form
      className="explore-form"
      onSubmit={(e) => {
        e.preventDefault();
        declare.mutate();
      }}
    >
      <label>
        Range
        <input
          value={range}
          onChange={(e) => setRange(e.target.value)}
          placeholder="10.0.1.0/24"
          required
          // Not `pattern`-validated here: the server parses it and says what is wrong, and
          // a regex in the browser that disagrees with the parser is a second rule.
          aria-describedby="range-hint"
        />
      </label>
      <label>
        Name
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Voice — Berlin"
          required
        />
      </label>
      <label>
        Assignment
        <select value={assignment} onChange={(e) => setAssignment(e.target.value as Assignment)}>
          {ASSIGNMENTS.map((a) => (
            <option key={a.value} value={a.value} title={a.hint}>
              {a.label}
            </option>
          ))}
        </select>
      </label>
      <button type="submit" className="primary" disabled={declare.isPending}>
        Declare
      </button>
      <p id="range-hint" className="dim">
        IPv4 only — an IPv6 prefix has no meaningful utilisation, so the product does not
        pretend to compute one.
      </p>
      {declare.isError && (
        <p className="problem-inline" role="alert">
          {message(declare.error)}
        </p>
      )}
    </form>
  );
}
