/**
 * The layout's promises — UI-SPEC §14.3 and §14.4.
 *
 * Testable at all because placing a graph is a pure function rather than an animation
 * loop: give it a graph, get coordinates. That is the main reason it was written that way.
 */

import { describe, expect, it } from "vitest";

import {
  NODE_BUDGET,
  depths,
  layout,
  neighboursOf,
  type GraphEdge,
  type GraphNode,
} from "./graph";

function device(n: number): GraphNode {
  return { id: `r${n}`, name: `sw-${n}`, kind: "device", status: "up" };
}

/** A chain: r0 — r1 — r2 — … */
function chain(count: number): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes = Array.from({ length: count }, (_, i) => device(i));
  const edges: GraphEdge[] = [];
  for (let i = 1; i < count; i++) {
    edges.push({ source: `r${i - 1}`, target: `r${i}`, discovered_by: "lldp" });
  }
  return { nodes, edges };
}

describe("layout", () => {
  it("places the same estate the same way every time", () => {
    // The promise §14.3 makes. An operator comparing this morning's topology against last
    // week's screenshot is comparing two pictures of the same shape, and a bug in a graph
    // nobody can reproduce is a bug nobody can fix.
    const { nodes, edges } = chain(12);
    const a = layout(nodes, edges);
    const b = layout(nodes, edges);
    expect(a.nodes.map((n) => [n.id, n.x, n.y])).toEqual(
      b.nodes.map((n) => [n.id, n.x, n.y]),
    );
  });

  it("does not depend on the order the nodes arrived in", () => {
    // Two runs of the same sweep can return rows in a different order; the picture must
    // not change because of it.
    const { nodes, edges } = chain(10);
    const forward = layout(nodes, edges);
    const backward = layout([...nodes].reverse(), edges);

    const byId = (l: typeof forward) =>
      Object.fromEntries(l.nodes.map((n) => [n.id, [Math.round(n.x), Math.round(n.y)]]));
    expect(byId(forward)).toEqual(byId(backward));
  });

  it("keeps every node inside the box", () => {
    const { nodes, edges } = chain(30);
    const placed = layout(nodes, edges, 1000);
    for (const n of placed.nodes) {
      expect(n.x).toBeGreaterThanOrEqual(0);
      expect(n.x).toBeLessThanOrEqual(1000);
      expect(n.y).toBeGreaterThanOrEqual(0);
      expect(n.y).toBeLessThanOrEqual(1000);
    }
  });

  it("separates nodes that are not connected to each other", () => {
    // The whole point of the repulsion term: a graph where everything lands on one spot
    // is a graph that tells you nothing.
    const nodes = Array.from({ length: 8 }, (_, i) => device(i));
    const placed = layout(nodes, [], 1000);
    const seen = new Set(placed.nodes.map((n) => `${Math.round(n.x)},${Math.round(n.y)}`));
    expect(seen.size).toBe(nodes.length);
  });

  it("puts connected nodes closer than unconnected ones", () => {
    // Two pairs, joined within each pair and not between them.
    const nodes = [device(0), device(1), device(2), device(3)];
    const edges: GraphEdge[] = [
      { source: "r0", target: "r1", discovered_by: "lldp" },
      { source: "r2", target: "r3", discovered_by: "lldp" },
    ];
    const placed = layout(nodes, edges, 1000);
    const at = (id: string) => placed.nodes.find((n) => n.id === id) as { x: number; y: number };
    const gap = (a: string, b: string) =>
      Math.hypot(at(a).x - at(b).x, at(a).y - at(b).y);

    expect(gap("r0", "r1")).toBeLessThan(gap("r0", "r2"));
    expect(gap("r2", "r3")).toBeLessThan(gap("r1", "r3"));
  });

  it("drops an edge whose far end is not in the graph", () => {
    // A dangling edge is a bug somewhere else, and a line drawn to a node that is not
    // there makes it look like one here.
    const placed = layout(
      [device(0)],
      [{ source: "r0", target: "missing", discovered_by: "lldp" }],
    );
    expect(placed.edges).toHaveLength(0);
  });

  it("keeps the largest component and says how much it left out", () => {
    // §14.4. Not silent truncation: the count is what the screen shows the operator.
    const big = chain(12);
    const small = {
      nodes: [device(100), device(101)],
      edges: [{ source: "r100", target: "r101", discovered_by: "arp" }],
    };
    const placed = layout(
      [...big.nodes, ...small.nodes],
      [...big.edges, ...small.edges],
      1000,
      12,
    );

    expect(placed.nodes).toHaveLength(12);
    expect(placed.omitted).toBe(2);
    expect(placed.omittedComponents).toBe(1);
    // And it kept the *large* one, not whichever arrived first.
    expect(placed.nodes.some((n) => n.id === "r0")).toBe(true);
    expect(placed.nodes.some((n) => n.id === "r100")).toBe(false);
  });

  it("omits nothing when the graph fits", () => {
    const { nodes, edges } = chain(5);
    const placed = layout(nodes, edges);
    expect(placed.omitted).toBe(0);
    expect(placed.omittedComponents).toBe(0);
  });

  it("handles one node, and none", () => {
    expect(layout([], [])).toMatchObject({ nodes: [], edges: [], omitted: 0 });
    const one = layout([device(0)], []);
    expect(one.nodes).toHaveLength(1);
    expect(Number.isFinite((one.nodes[0] as { x: number }).x)).toBe(true);
  });

  it("has a budget big enough to be a legibility limit rather than a speed one", () => {
    // If this ever drops to something small, the reason in §14.4 no longer holds and the
    // sentence in the docs is wrong.
    expect(NODE_BUDGET).toBeGreaterThanOrEqual(200);
  });
});

describe("neighboursOf", () => {
  it("includes the node itself, so selection can dim by set membership", () => {
    const { edges } = chain(4);
    expect(neighboursOf("r1", edges)).toEqual(new Set(["r1", "r0", "r2"]));
  });

  it("treats an edge as undirected, whichever end it was written from", () => {
    const edges: GraphEdge[] = [{ source: "a", target: "b", discovered_by: "lldp" }];
    expect(neighboursOf("b", edges)).toEqual(new Set(["b", "a"]));
  });
});

describe("depths", () => {
  it("roots at the most connected device and counts hops from it", () => {
    // A star: r0 in the middle. It is what everything is cabled to, so it is the root and
    // everything else is one hop away.
    const nodes = [device(0), device(1), device(2), device(3)];
    const edges: GraphEdge[] = [
      { source: "r0", target: "r1", discovered_by: "lldp" },
      { source: "r0", target: "r2", discovered_by: "lldp" },
      { source: "r0", target: "r3", discovered_by: "lldp" },
    ];
    const d = depths(nodes, edges);
    expect(d.get("r0")).toBe(0);
    expect(d.get("r1")).toBe(1);
    expect(d.get("r2")).toBe(1);
    expect(d.get("r3")).toBe(1);
  });

  it("layers a chain by hop distance from whichever node it rooted at", () => {
    // In a chain every interior node has degree two, so "the middle" is not uniquely the
    // most connected and the id tie-break decides. That is fine and it is the point of
    // the tie-break — so the property to assert is the *distance*, not which node won.
    const { nodes, edges } = chain(5);
    const d = depths(nodes, edges);

    const roots = [...d.entries()].filter(([, depth]) => depth === 0);
    expect(roots).toHaveLength(1);
    const root = Number((roots[0] as [string, number])[0].slice(1));

    // r0—r1—r2—r3—r4, so hop distance along the chain is the difference in index.
    for (const [id, depth] of d) {
      expect(depth).toBe(Math.abs(Number(id.slice(1)) - root));
    }
  });

  it("gives every component its own root", () => {
    // An isolated pair must not be pushed to the bottom of the world because it happens
    // to be far from another component's root — there is no path between them at all.
    const nodes = [device(0), device(1), device(2), device(3)];
    const edges: GraphEdge[] = [
      { source: "r0", target: "r1", discovered_by: "lldp" },
      { source: "r2", target: "r3", discovered_by: "lldp" },
    ];
    const d = depths(nodes, edges);
    expect(Math.max(...d.values())).toBe(1);
    expect([...d.values()].filter((n) => n === 0)).toHaveLength(2);
  });

  it("is the same every time, including which node it roots at", () => {
    // Two nodes of equal degree must not swap roots between loads: the root moving moves
    // every node beneath it.
    const { nodes, edges } = chain(6);
    const a = depths(nodes, edges);
    const b = depths([...nodes].reverse(), edges);
    expect([...a.entries()].sort()).toEqual([...b.entries()].sort());
  });

  it("places a node with no links at all at the top of its own layer", () => {
    const d = depths([device(0)], []);
    expect(d.get("r0")).toBe(0);
  });
});
