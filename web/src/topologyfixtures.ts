/**
 * Estates to look at and to measure against — `docs/UI-3D-DEVICE-EXPLORER.md` §0.3, §9, §10.
 *
 * # Why fixtures are a deliverable rather than test scaffolding
 *
 * §9 says it plainly: *"Do not publish a performance number from a four-node demo as if it
 * described a customer estate."* A topology screen is only interesting at the sizes it
 * fails at, and the failures are all about scale — a layout that is legible at twelve
 * nodes and a black circle at four hundred, a scene that opens instantly with one
 * component and takes a second with forty.
 *
 * So these are the three estates §10's visual QA asks for, as data, in the shipped
 * bundle's *test* graph only — nothing here is imported by the application. They are the
 * same shapes a reviewer looks at by eye and a test asserts on, which is the point: a
 * fixture that the tests use and nobody ever sees is a fixture that drifts.
 *
 * # What each one is for
 *
 * | fixture | what it is there to expose |
 * |---|---|
 * | {@link smallCampus} | every shape at once, and a link nobody should trust |
 * | {@link mixedEstate} | logical resources beside physical ones, and a component on its own |
 * | {@link largeEstate} | the node budget, and what is said about what was dropped |
 *
 * Every one of them contains an unhealthy node, because a topology of entirely green
 * boxes is the one state an operator never opens this screen in.
 */

import type { GraphEdge, GraphNode } from "./graph";

export interface Estate {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

function node(id: string, name: string, kind: string, status: string): GraphNode {
  return { id, name, kind, status };
}

function link(source: string, target: string, discovered_by = "lldp"): GraphEdge {
  return { source, target, discovered_by };
}

/**
 * A small campus: one core, two distribution boxes, access devices, servers and an AP.
 *
 * Note what is *not* in the data. There is no "core" and no "access" — every one of these
 * is `kind: "device"`, because that is all migration 0002 has. The names say what a human
 * called them and the graph says which is most connected; neither is the product claiming
 * a layer. The caption on the screen is careful about this and so is this fixture.
 *
 * Contains the one link that matters for evidence: `sw-acc-02 — ap-01` is ARP-only, so it
 * is the pair whose line must be dashed in both 2D and 3D.
 */
export function smallCampus(): Estate {
  return {
    nodes: [
      node("c1", "core-01", "device", "up"),
      node("d1", "dist-01", "device", "up"),
      node("d2", "dist-02", "device", "degraded"),
      node("a1", "sw-acc-01", "device", "up"),
      node("a2", "sw-acc-02", "device", "up"),
      node("ap", "ap-floor-2", "device", "unknown"),
      node("h1", "esx-01", "host", "up"),
      node("h2", "esx-02", "host", "down"),
      node("v1", "vm-billing", "vm", "up"),
      node("db", "pg-primary", "database", "up"),
    ],
    edges: [
      link("c1", "d1"),
      link("c1", "d2"),
      link("d1", "a1"),
      link("d2", "a2"),
      // The link with weaker evidence. An ARP sighting says two addresses were seen on one
      // segment, not that a cable runs between them.
      link("a2", "ap", "arp"),
      link("a1", "h1"),
      link("a1", "h2"),
      link("h1", "v1"),
      link("d1", "db"),
    ],
  };
}

/**
 * A mixed estate: boxes, logical services, and a component with nothing joining it.
 *
 * The disconnected pair is the case §14.4's omitted-component warning exists for and the
 * case a layout gets wrong: a force simulation with nothing pulling two islands together
 * will push them apart until one leaves the frame.
 */
export function mixedEstate(): Estate {
  return {
    nodes: [
      node("r1", "wan-gw-01", "device", "up"),
      node("fw", "edge-fw-01", "device", "up"),
      node("s1", "core-01", "device", "up"),
      node("h1", "app-host-01", "host", "up"),
      node("c1", "checkout", "container", "degraded"),
      node("svc", "payments-api", "service", "up"),
      node("app", "billing", "application", "up"),
      node("cr", "s3-invoices", "cloud_resource", "up"),
      node("db", "pg-orders", "database", "degraded"),
      // Its own component: two devices in a branch office nothing has discovered a path to.
      node("b1", "branch-sw-01", "device", "up"),
      node("b2", "branch-ap-01", "device", "down"),
      // A resource of a kind that carries no shape.
      node("u1", "unclassified-7", "site", "unknown"),
    ],
    edges: [
      link("r1", "fw"),
      link("fw", "s1"),
      link("s1", "h1"),
      link("h1", "c1"),
      link("c1", "svc"),
      link("svc", "app"),
      link("app", "db"),
      link("svc", "cr", "manual"),
      link("s1", "h1", "arp"),
      link("b1", "b2"),
    ],
  };
}

/**
 * More nodes than the budget allows, in several components.
 *
 * `count` is deliberately a parameter: §9 asks for 50, 200 and 400, and a fixture that
 * only produced one of them would make two of the three measurements somebody's ad-hoc
 * script.
 *
 * The shape is a set of stars — one hub per twenty leaves — because that is what an access
 * layer looks like and because it is the shape that makes a hop-distance view mean
 * something. A random graph would settle into a uniform blob and measure nothing but
 * draw-call count.
 */
export function largeEstate(count: number): Estate {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const perComponent = 20;

  for (let i = 0; i < count; i++) {
    const component = Math.floor(i / perComponent);
    const isHub = i % perComponent === 0;
    // One in eleven is not up, so every fixture has something to look at and the count is
    // stable across sizes rather than random.
    const status = i % 11 === 0 ? "down" : i % 7 === 0 ? "degraded" : "up";
    const kind = i % 5 === 0 ? "host" : "device";
    nodes.push(node(`n${i}`, isHub ? `hub-${component}` : `node-${i}`, kind, status));
    if (!isHub) {
      edges.push(link(`n${component * perComponent}`, `n${i}`, i % 9 === 0 ? "arp" : "lldp"));
    }
  }

  // Join the hubs into a chain, leaving the last component deliberately unattached so
  // there is always something for the omitted-component disclosure to be about.
  for (let c = 1; c < Math.floor(count / perComponent) - 1; c++) {
    edges.push(link(`n${(c - 1) * perComponent}`, `n${c * perComponent}`));
  }

  return { nodes, edges };
}

/** The three estates §10's visual QA reviews, by the names it uses. */
export const ESTATES: ReadonlyArray<{ name: string; estate: () => Estate }> = [
  { name: "small campus", estate: smallCampus },
  { name: "mixed estate", estate: mixedEstate },
  { name: "large graph", estate: () => largeEstate(440) },
];
