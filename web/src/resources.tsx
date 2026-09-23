/**
 * The resource inventory: the list, and one resource.
 *
 * This is the first screen that shows a customer their own data, and the proof that the
 * session cookie, the tenant header, the scope extractor and the keyset pagination all
 * line up in a browser rather than only in a test.
 */

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";

import {
  ApiError,
  STATUSES,
  api,
  type Resource,
  type ResourceStatus,
  type Role,
} from "./api";
import { contextParams } from "./context";
import { PathPanel } from "./pathpanel";
import { AllSignals } from "./signals";
import type { ShellSearch } from "./shell";
import { resolveRange, useShell } from "./shell";

function statusColour(status: ResourceStatus): string {
  switch (status) {
    case "up":
      return "var(--ok)";
    case "down":
      return "var(--danger)";
    case "degraded":
    case "maintenance":
      return "var(--warn)";
    default:
      return "var(--text-dim)";
  }
}

/** Roles are ordered; a check is "at least this". */
const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

function atLeast(role: Role, needed: Role): boolean {
  return RANK[role] >= RANK[needed];
}

function keepSearch(old: ShellSearch): ShellSearch {
  return old;
}

export function ResourcesPage() {
  const { tenant, context } = useShell();
  const narrow = contextParams(context);

  // Keyed by tenant *and* by the context, so switching either is a different cache entry
  // rather than a refetch drawn over the previous customer's — or the previous site's —
  // rows.
  const resources = useInfiniteQuery({
    queryKey: ["resources", tenant.tenant_id, narrow],
    queryFn: ({ pageParam }) =>
      api.resources(tenant.tenant_id, { ...narrow, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    // The cursor is opaque and the server decides when there are no more pages. A
    // client that computed "is there more" from the page size would be wrong exactly
    // when the last page is full.
    getNextPageParam: (last) => last.next ?? undefined,
  });

  if (resources.isPending) return <p className="dim">Loading…</p>;

  if (resources.isError) {
    return (
      <div className="problem" role="alert">
        {resources.error instanceof ApiError
          ? resources.error.message
          : "Could not load resources."}
      </div>
    );
  }

  const items: Resource[] = resources.data.pages.flatMap((p) => p.items);

  if (items.length === 0) {
    return (
      <div className="empty-state">
        <h1>{context.kind === "all" ? "No resources yet" : "Nothing in this context"}</h1>
        {context.kind === "all" ? (
          <p>
            Nothing has been discovered or created in {tenant.name}. Resources appear here
            as collectors report them, or when one is created through the API.
          </p>
        ) : (
          // §13.3. An operator who cannot find a device because of a context they forgot
          // about will conclude the product lost it. The bar above says what the context
          // is and offers the way out; this says the emptiness is its doing.
          <p>
            The context above is what narrowed this to nothing. Widening it shows the rest
            of the estate.
          </p>
        )}
      </div>
    );
  }

  return (
    <>
      <h1>Resources</h1>
      <p className="dim">
        {items.length} loaded in {tenant.name}
        {context.kind !== "all" && ", in the current context"}
        {resources.hasNextPage && ", more available"}
      </p>

      <div className="scroll-x">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Kind</th>
              <th>Status</th>
              <th>Vendor</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link
                    to="/resources/$id"
                    params={{ id: r.id }}
                    search={keepSearch}
                    className="row-link"
                  >
                    {r.display_name ?? r.name}
                  </Link>
                </td>
                <td className="dim">{r.kind}</td>
                <td style={{ color: statusColour(r.status) }}>{r.status}</td>
                <td className="dim">{r.vendor ?? "—"}</td>
                <td className="mono dim">{r.last_seen.slice(0, 19).replace("T", " ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {resources.hasNextPage && (
        <p>
          <button
            onClick={() => void resources.fetchNextPage()}
            disabled={resources.isFetchingNextPage}
          >
            {resources.isFetchingNextPage ? "Loading…" : "Load more"}
          </button>
        </p>
      )}
    </>
  );
}

/**
 * The instant a range is "about".
 *
 * The midpoint rather than the end, because the links that bring somebody here set a
 * window *centred* on a moment — an incident's start, a log line's timestamp — and the end
 * of that window is five minutes after the thing they came to look at.
 *
 * Falls back to now for an unreadable range, which is what the picker itself does.
 */
function momentOf(range: Parameters<typeof resolveRange>[0]): Date {
  const window = resolveRange(range);
  if (!window) return new Date();
  return new Date((window.from.getTime() + window.to.getTime()) / 2);
}

export function ResourcePage() {
  const { tenant, range } = useShell();
  const { id } = useParams({ from: "/shell/resources/$id" });
  const queryClient = useQueryClient();

  const resource = useQuery({
    queryKey: ["resource", tenant.tenant_id, id],
    queryFn: () => api.resource(tenant.tenant_id, id),
  });

  const invalidate = async () => {
    await queryClient.invalidateQueries({ queryKey: ["resource", tenant.tenant_id, id] });
    await queryClient.invalidateQueries({ queryKey: ["resources", tenant.tenant_id] });
  };

  // Read for the path panel: the resource itself does not carry its management address,
  // because a device may have several and identity resolution owns that decision.
  const identifiers = useQuery({
    queryKey: ["identifiers", tenant.tenant_id, id],
    queryFn: () => api.identifiers(tenant.tenant_id, id),
    retry: false,
    staleTime: 60_000,
  });

  const setStatus = useMutation({
    mutationFn: (status: ResourceStatus) =>
      api.setResourceStatus(tenant.tenant_id, id, status),
    onSuccess: invalidate,
  });

  const decommission = useMutation({
    mutationFn: () => api.decommission(tenant.tenant_id, id),
    onSuccess: invalidate,
  });

  if (resource.isPending) return <p className="dim">Loading…</p>;

  if (resource.isError) {
    // 404 here is either "no such resource" or "not in this tenant", and the server
    // deliberately does not distinguish them. Neither does this.
    const notFound = resource.error instanceof ApiError && resource.error.status === 404;
    return (
      <div className="empty-state">
        <h1>{notFound ? "No such resource" : "Could not load this resource"}</h1>
        <p>
          {notFound
            ? `Nothing with that id exists in ${tenant.name}.`
            : resource.error instanceof ApiError
              ? resource.error.message
              : String(resource.error)}
        </p>
        <p>
          <Link to="/resources" search={keepSearch}>
            Back to resources
          </Link>
        </p>
      </div>
    );
  }

  const r = resource.data;
  // The address the product would poll, which is the one worth tracing to.
  const managementAddress =
    identifiers.data?.find((i) => i.kind === "mgmt_ip")?.value ?? null;
  const canEdit = atLeast(tenant.role, "operator");
  const attributes = Object.entries(r.attributes);

  return (
    <>
      <p className="dim">
        <Link to="/resources" search={keepSearch}>
          Resources
        </Link>{" "}
        /
      </p>
      <h1>{r.display_name ?? r.name}</h1>
      <p className="dim">
        <span className="mono">{r.kind}</span> ·{" "}
        <span style={{ color: statusColour(r.status) }}>{r.status}</span>
      </p>

      <table className="detail">
        <tbody>
          <Row label="Id" value={r.id} mono />
          <Row label="Name" value={r.name} />
          <Row label="Vendor" value={r.vendor} />
          <Row label="Model" value={r.model} />
          <Row label="OS" value={[r.os, r.os_version].filter(Boolean).join(" ") || null} />
          <Row label="Site" value={r.site_id} mono />
          <Row label="Parent" value={r.parent_id} mono />
          <Row label="First seen" value={r.first_seen.replace("T", " ")} mono />
          <Row label="Last seen" value={r.last_seen.replace("T", " ")} mono />
        </tbody>
      </table>

      {/* The signature interaction, on the screen it belongs on.
       *
       * SPEC §M3 calls this "the seed of the Investigation Workspace, and the one
       * interaction that demonstrates the product thesis in ten seconds" — and until now
       * it was reachable only by opening a log row in the Explorer. A resource page that
       * showed a device's name, its attributes and its status but none of what it had
       * *said* was the product hiding its own argument.
       *
       * `at` comes from the shell's range rather than from now, so arriving here from an
       * incident lands on the moment the incident is about. */}
      {/* Where the traffic goes between here and this device. On the resource page
       *  because that is where somebody stands when they ask why they cannot reach it —
       *  Topology answers what is next to what, and never answered what is in between. */}
      <h2>Path</h2>
      <PathPanel address={managementAddress} name={r.display_name || r.name} />

      <h2>Signals</h2>
      <AllSignals tenant={tenant.tenant_id} resourceId={r.id} at={momentOf(range)} />

      <h2>Attributes</h2>
      {attributes.length === 0 ? (
        <p className="dim">None. Collectors set OpenTelemetry semconv keys here.</p>
      ) : (
        <table className="detail">
          <tbody>
            {attributes.map(([key, value]) => (
              <Row key={key} label={key} value={String(value)} mono />
            ))}
          </tbody>
        </table>
      )}

      {canEdit && (
        <>
          <h2>Status</h2>
          <div className="range">
            <select
              value={r.status}
              onChange={(e) => setStatus.mutate(e.target.value as ResourceStatus)}
              disabled={setStatus.isPending}
              aria-label="Status"
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <button
              onClick={() => decommission.mutate()}
              disabled={decommission.isPending || r.status === "decommissioned"}
              title="Retires the resource. Telemetry already written keeps resolving to it."
            >
              Decommission
            </button>
          </div>
          {(setStatus.isError || decommission.isError) && (
            <div className="problem" role="alert">
              {String(setStatus.error ?? decommission.error)}
            </div>
          )}
          <p className="dim">
            Decommissioning is a soft delete. History that resolves to nothing is worse
            than a row marked retired.
          </p>
        </>
      )}
    </>
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: string | null | undefined;
  mono?: boolean;
}) {
  return (
    <tr>
      <th scope="row">{label}</th>
      <td className={mono ? "mono" : undefined}>{value ?? "—"}</td>
    </tr>
  );
}
