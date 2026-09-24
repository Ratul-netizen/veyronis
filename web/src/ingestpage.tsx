/**
 * Sending telemetry in — `docs/packaging.md` §4.2.
 *
 * The screen an operator uses to let a machine they do not own report into this customer's
 * estate. Before it existed, the OTLP listener authenticated nobody: whatever could reach the
 * port wrote into its tenant, as any resource it named. That is defensible for a concentrator
 * inside a datacenter and is not something to hand to fifty hosts.
 *
 * # Why the screen is the feature
 *
 * A token that can only be minted with `psql` is a capability nobody has. This product has
 * produced that shape repeatedly — the audit log filled since M1 and readable only through
 * `psql`, user administration with seventeen test files and no route, an LLDP walk nothing
 * called — and each time the lesson was the same.
 *
 * # What it shows once
 *
 * The token, and the exporter configuration with the token in it. Only a hash is stored, so
 * there is no second chance and the screen says so rather than letting somebody discover it.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { message } from "./query";
import { useShell } from "./shell";
import {
  SHOWN_ONCE,
  type IngestToken,
  type MintedToken,
  expiryNote,
  exporterConfig,
  labelProblem,
  listTokens,
  mintToken,
  revokeToken,
  tokenState,
} from "./ingest";

export function IngestPage() {
  const { tenant } = useShell();
  const queries = useQueryClient();
  const tokens = useQuery({
    queryKey: ["ingest-tokens", tenant.tenant_id],
    queryFn: () => listTokens(tenant.tenant_id),
    retry: false,
  });
  const [minted, setMinted] = useState<MintedToken | null>(null);

  const refresh = () =>
    void queries.invalidateQueries({ queryKey: ["ingest-tokens", tenant.tenant_id] });

  if (tenant.role !== "admin") {
    // Said rather than hidden — the same reasoning the audit log's navigation entry gives.
    return (
      <>
        <h1>Sending telemetry in</h1>
        <div className="problem" role="alert">
          Minting an ingest token needs the admin role on {tenant.name}. A token lets a machine
          write into this customer&rsquo;s estate until somebody revokes it.
        </div>
      </>
    );
  }

  if (tokens.isPending) return <p className="dim">Reading the tokens…</p>;
  if (tokens.isError)
    return (
      <>
        <h1>Sending telemetry in</h1>
        <div className="problem" role="alert">
          {message(tokens.error)}
        </div>
      </>
    );

  const rows = tokens.data ?? [];

  return (
    <>
      <h1>Sending telemetry in</h1>
      <p className="dim">
        A host reports into {tenant.name} by presenting one of these. Each authorises writing
        into this customer and no other — it does not let the sender claim to be a particular
        device, which identity resolution still decides from what the telemetry says about
        itself.
      </p>

      <Mint
        tenant={tenant.tenant_id}
        existing={rows}
        onMinted={(t) => {
          setMinted(t);
          refresh();
        }}
      />

      {minted && <TheToken minted={minted} onDismiss={() => setMinted(null)} />}

      <h2>Tokens</h2>
      {rows.length === 0 ? (
        <div className="empty-state">
          <h1>No tokens yet</h1>
          <p>
            Until one exists, a listener with <span className="mono">require_token</span> set
            accepts nothing — and one without it accepts anything that can reach the port.
          </p>
        </div>
      ) : (
        <table className="rows">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">State</th>
              <th scope="col">Expiry</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => (
              <Row key={t.id} token={t} tenant={tenant.tenant_id} onChanged={refresh} />
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function Row({
  token,
  tenant,
  onChanged,
}: {
  token: IngestToken;
  tenant: string;
  onChanged: () => void;
}) {
  const [problem, setProblem] = useState<string | null>(null);
  const state = tokenState(token);

  const drop = useMutation({
    mutationFn: () => revokeToken(tenant, token.id),
    onSuccess: () => {
      setProblem(null);
      onChanged();
    },
    onError: (e) => setProblem(message(e)),
  });

  return (
    <>
      <tr className={state === "live" ? undefined : "dim"}>
        <td className="mono">{token.label}</td>
        <td>
          {state === "live" ? (
            <span>live</span>
          ) : (
            // Revoked and expired both mean it will not authorise a write, and they mean
            // different things about what happened — one sends you to a person, the other to
            // a calendar.
            <span className="attention">{state}</span>
          )}
        </td>
        <td className="dim">{expiryNote(token)}</td>
        <td>
          {state === "live" && (
            <button
              type="button"
              className="quiet"
              disabled={drop.isPending}
              title="Takes effect on the next export — the listener holds no cache"
              onClick={() => drop.mutate()}
            >
              Revoke
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

function Mint({
  tenant,
  existing,
  onMinted,
}: {
  tenant: string;
  existing: IngestToken[];
  onMinted: (t: MintedToken) => void;
}) {
  const [label, setLabel] = useState("");
  const [days, setDays] = useState("");

  const mint = useMutation({
    mutationFn: () =>
      mintToken(tenant, label.trim(), days.trim() === "" ? undefined : Number(days)),
    onSuccess: (t) => {
      onMinted(t);
      setLabel("");
      setDays("");
    },
  });

  const problem = label ? labelProblem(label, existing) : null;

  return (
    <form
      className="inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (!problem) mint.mutate();
      }}
    >
      <h2>Mint a token</h2>
      <label>
        Name
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="berlin-hosts"
          required
        />
      </label>
      <label>
        Expires after (days)
        <input
          type="number"
          min={1}
          value={days}
          onChange={(e) => setDays(e.target.value)}
          placeholder="never"
        />
      </label>
      <p className="dim">
        Leave the expiry empty for a token that lives in configuration management and brings up
        hosts for years. Set it for a laptop fleet.
      </p>
      {problem && (
        <div className="problem" role="alert">
          {problem}
        </div>
      )}
      <button type="submit" disabled={mint.isPending || Boolean(problem) || !label.trim()}>
        {mint.isPending ? "Minting…" : "Mint"}
      </button>
      {mint.isError && (
        <div className="problem" role="alert">
          {message(mint.error)}
        </div>
      )}
    </form>
  );
}

/**
 * The token, and what to do with it — shown once.
 *
 * The exporter block rather than a bare string, because the thing at the other end is an
 * OpenTelemetry Collector: `PLAN` settled that the per-host agent is a distribution of theirs
 * with our configuration, so the useful artefact is their YAML with this token in it.
 */
function TheToken({
  minted,
  onDismiss,
}: {
  minted: MintedToken;
  onDismiss: () => void;
}) {
  const [endpoint, setEndpoint] = useState("");
  const [copied, setCopied] = useState<"token" | "config" | null>(null);
  const config = exporterConfig(minted.token, endpoint.trim() || undefined);

  return (
    <div className="notice" role="note">
      <h2>Your token</h2>
      <p>{SHOWN_ONCE}</p>
      <pre className="mono raw-trace">{minted.token}</pre>
      <button
        type="button"
        onClick={() => {
          void navigator.clipboard?.writeText(minted.token).then(() => setCopied("token"));
        }}
      >
        {copied === "token" ? "Copied" : "Copy the token"}
      </button>

      <h2>On the host</h2>
      <label>
        Your OTLP endpoint
        <input
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
          placeholder="the address your collector listens on"
        />
      </label>
      <p className="dim">
        Left to you because this product does not know it: the listener binds inside a collector
        on some network, and guessing from this browser&rsquo;s address would be wrong in exactly
        the deployments where it matters — a proxy in front, or a collector on another segment.
      </p>
      <pre className="mono raw-trace">{config}</pre>
      <button
        type="button"
        onClick={() => {
          void navigator.clipboard?.writeText(config).then(() => setCopied("config"));
        }}
      >
        {copied === "config" ? "Copied" : "Copy the configuration"}
      </button>
      <button type="button" className="quiet" onClick={onDismiss}>
        Done
      </button>
    </div>
  );
}
