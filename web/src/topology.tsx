/**
 * The network, drawn — UI-SPEC §14.
 *
 * Its data is the `connected_to` edges M5's neighbour walk writes: two devices that
 * reported each other over LLDP, CDP or ARP. Nothing here is inferred.
 *
 * # What it deliberately does not draw
 *
 * **Traffic.** No animated particles along the links, no utilisation colouring, no
 * bandwidth labels. There is no flow data in this product yet — that is M7 — so all of
 * those would be an animation of nothing, on the screen an operator is most likely to
 * believe. §14.0: the UI may visualise backend truth; it may not invent backend
 * semantics. When M7 lands they can be drawn, and they will mean something.
 *
 * **Interfaces.** `member_of` is containment, not adjacency; it would triple the node
 * count and it is what the resource page is for.
 *
 * # Why the picture does not move
 *
 * The layout is computed once, synchronously, and stops — see `graph.ts`. A graph that is
 * still settling is a graph you cannot point at while talking to somebody, and on a NOC
 * wall a permanent simulation is a machine that never idles.
 */

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Suspense, lazy, useCallback, useMemo, useState } from "react";

import { listTopology, type TopologyEdge } from "./discovery";
import { depths, layout, neighboursOf, type Placed } from "./graph";
import { message } from "./query";
import { useShell } from "./shell";

/**
 * The 3D scene, on demand.
 *
 * `three` is about half the size of the rest of this application, and an operator who
 * never opens the 3D mode should never download it. Nothing in the 2D path imports it.
 */
const Scene3d = lazy(() => import("./scene3d"));

/** The box the graph is laid out in. Scaled to the viewport by the SVG's viewBox. */
const SIZE = 1000;
const NODE_R = 9;

/** The semantic colour of a resource's state. */
function toneOf(status: string): string {
  switch (status) {
    case "up":
      return "var(--ok)";
    case "down":
      return "var(--danger)";
    case "degraded":
      return "var(--warn)";
    case "maintenance":
      return "var(--maintenance)";
    default:
      return "var(--unknown)";
  }
}

/**
 * How an edge is drawn.
 *
 * ARP is dashed. §2.5 is right that an ARP sighting is much weaker evidence than a
 * neighbour protocol — it proves an address was in use on a subnet — and the picture
 * should say so without anybody having to ask.
 */
function dashOf(edge: TopologyEdge): string | undefined {
  return edge.discovered_by === "arp" ? "6 5" : undefined;
}

export function TopologyPage() {
  const { tenant } = useShell();
  const [selected, setSelected] = useState<string | null>(null);
  const [onlyUnhealthy, setOnlyUnhealthy] = useState(false);
  const [find, setFind] = useState("");
  const [solid, setSolid] = useState(false);

  const graph = useQuery({
    queryKey: ["topology", tenant.tenant_id],
    queryFn: () => listTopology(tenant.tenant_id),
    retry: false,
  });

  const placed = useMemo(() => {
    const nodes = graph.data?.nodes ?? [];
    const edges = graph.data?.edges ?? [];
    if (!onlyUnhealthy) return layout(nodes, edges, SIZE);

    // Filtering happens before the layout, not after: laying out the whole estate and
    // then hiding most of it leaves the survivors scattered across a plane sized for a
    // graph that is not on screen.
    const keep = new Set(nodes.filter((n) => n.status !== "up").map((n) => n.id));
    return layout(
      nodes.filter((n) => keep.has(n.id)),
      edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
      SIZE,
    );
  }, [graph.data, onlyUnhealthy]);

  // Computed for both modes, because the caption under the 2D view explains what the 3D
  // one would stack by — and the number of layers is worth knowing before switching.
  const layers = useMemo(
    () => depths(placed.nodes, placed.edges),
    [placed.nodes, placed.edges],
  );

  const pick = useCallback((id: string | null) => setSelected(id), []);

  const near = useMemo(
    () => (selected ? neighboursOf(selected, placed.edges) : null),
    [selected, placed.edges],
  );

  const needle = find.trim().toLowerCase();
  const chosen = placed.nodes.find((n) => n.id === selected);

  if (graph.isError) {
    return (
      <>
        <h1>Topology</h1>
        <div className="problem" role="alert">
          {message(graph.error)}
        </div>
      </>
    );
  }

  const empty = !graph.isPending && placed.nodes.length === 0;

  return (
    <>
      <h1>Topology</h1>
      <p className="dim">
        What the estate reports about itself. Links come from LLDP, CDP and ARP.
        {solid && " Height is hops from the most connected device."}
      </p>

      {/* Controls belong to the screen, not to global settings — §14.5. */}
      <div className="topo-controls">
        <input
          value={find}
          onChange={(event) => setFind(event.target.value)}
          placeholder="Find a device"
          aria-label="Find a device"
        />
        <button
          type="button"
          aria-pressed={onlyUnhealthy}
          className={onlyUnhealthy ? undefined : "quiet"}
          onClick={() => setOnlyUnhealthy((was) => !was)}
        >
          Only what is not up
        </button>
        {/* There is a 2D/3D switch now because there is a 3D mode. §14.5's rule is that a
            control which is present and does nothing is the dead-navigation problem in
            miniature — so this arrived with the thing it switches to, not before it. */}
        <span className="presets">
          <button type="button" aria-pressed={!solid} onClick={() => setSolid(false)}>
            2D
          </button>
          <button type="button" aria-pressed={solid} onClick={() => setSolid(true)}>
            3D
          </button>
        </span>
        {selected && (
          <button type="button" className="quiet" onClick={() => setSelected(null)}>
            Clear selection
          </button>
        )}
      </div>

      {placed.omitted > 0 && (
        // Never silent truncation — §14.4. An operator who cannot find a device and is
        // not told it is hidden concludes the product lost it.
        <p className="warn">
          Showing the largest {placed.nodes.length} devices. {placed.omitted} more in{" "}
          {placed.omittedComponents} separate{" "}
          {placed.omittedComponents === 1 ? "group" : "groups"} are not drawn.
        </p>
      )}

      {empty ? (
        <p className="dim">
          Nothing is linked yet. Links appear once discovery has walked a device that
          reports its neighbours — <Link to="/discovery">run a discovery job</Link> against
          a switch or a router.
        </p>
      ) : (
        <div className="topo">
          {solid ? (
            <Suspense fallback={<p className="dim topo-loading">Loading the 3D view…</p>}>
              <Scene3d
                nodes={placed.nodes}
                edges={placed.edges}
                depths={layers}
                selected={selected}
                onSelect={pick}
              />
            </Suspense>
          ) : (
          <svg
            className="topo-canvas"
            viewBox={`0 0 ${SIZE} ${SIZE}`}
            role="img"
            aria-label={`Network topology: ${placed.nodes.length} devices, ${placed.edges.length} links`}
            onClick={() => setSelected(null)}
          >
            {placed.edges.map((edge) => {
              const a = placed.nodes.find((n) => n.id === edge.source);
              const b = placed.nodes.find((n) => n.id === edge.target);
              if (!a || !b) return null;
              // With something selected, everything not touching it drops back, so
              // "what is this connected to" is answered by looking — §14.6.
              const lit = !near || (near.has(edge.source) && near.has(edge.target));
              return (
                <line
                  key={`${edge.source}-${edge.target}`}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  className={lit ? "topo-edge" : "topo-edge faded"}
                  strokeDasharray={dashOf(edge)}
                />
              );
            })}

            {placed.nodes.map((node) => (
              <Node
                key={node.id}
                node={node}
                lit={!near || near.has(node.id)}
                hit={needle !== "" && node.name.toLowerCase().includes(needle)}
                selected={node.id === selected}
                onPick={() => setSelected(node.id === selected ? null : node.id)}
              />
            ))}
          </svg>
          )}

          {chosen && <Detail node={chosen} edges={placed.edges} nodes={placed.nodes} />}
        </div>
      )}
    </>
  );
}

function Node({
  node,
  lit,
  hit,
  selected,
  onPick,
}: {
  node: Placed;
  lit: boolean;
  hit: boolean;
  selected: boolean;
  onPick: () => void;
}) {
  return (
    <g
      className={`topo-node${lit ? "" : " faded"}${selected ? " on" : ""}`}
      transform={`translate(${node.x} ${node.y})`}
      tabIndex={0}
      role="button"
      aria-label={`${node.name}, ${node.status}`}
      onClick={(event) => {
        event.stopPropagation();
        onPick();
      }}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onPick();
        }
      }}
    >
      {/* The hit area, invisible and larger than the dot.
          A 9px radius is an 18px target, and UI-SPEC §1.5 sets `--tap` — the smallest
          interactive target — at 32px. Drawing a circle and making it the control meant
          the control was half the size the token system requires; found by a click that
          landed between the dot and its label and hit the canvas instead. */}
      <circle r={NODE_R + 8} fill="transparent" />
      {/* A ring around a search hit: the name is already written beside the node, so the
          ring says "this is one of the ones you asked for" without a second label. */}
      {hit && <circle r={NODE_R + 6} className="topo-hit" />}
      <circle r={NODE_R} fill={toneOf(node.status)} className="topo-dot" />
      {/* The state is the fill, and the state is also the word in the detail panel and
          the title — rule 4, nothing by hue alone. */}
      <title>
        {node.name} — {node.status}
      </title>
      <text y={NODE_R + 16} textAnchor="middle">
        {node.name}
      </text>
    </g>
  );
}

/**
 * What is known about the selected device, and the ways on.
 *
 * Selection is not navigation — §14.6. Leaving the topology you have just oriented
 * yourself in is expensive during an incident, so going to the resource is a deliberate
 * act rather than a side effect of clicking a circle.
 */
function Detail({
  node,
  edges,
  nodes,
}: {
  node: Placed;
  edges: TopologyEdge[];
  nodes: Placed[];
}) {
  const links = edges.filter((e) => e.source === node.id || e.target === node.id);
  const nameOf = (id: string) => nodes.find((n) => n.id === id)?.name ?? id;

  return (
    <aside className="topo-detail">
      <h3>{node.name}</h3>
      <p className="dim">
        {node.kind} · <span style={{ color: toneOf(node.status) }}>{node.status}</span>
      </p>

      <h3 className="topo-detail-heading">
        {links.length === 0
          ? "No links"
          : `${links.length} ${links.length === 1 ? "link" : "links"}`}
      </h3>
      <ul className="topo-links">
        {links.map((edge) => {
          const other = edge.source === node.id ? edge.target : edge.source;
          return (
            <li key={`${edge.source}-${edge.target}`}>
              <span>{nameOf(other)}</span>
              {/* Which protocol said so. An operator deciding whether to trust a link
                  needs to know whether it came from LLDP or from an ARP table. */}
              <span className="dim">{edge.discovered_by}</span>
            </li>
          );
        })}
      </ul>

      <p>
        <Link to="/resources/$id" params={{ id: node.id }}>
          Open {node.name}
        </Link>
      </p>
    </aside>
  );
}
