/**
 * Placing a network graph on a plane — UI-SPEC §14.3.
 *
 * A force simulation, run to a fixed iteration count and then stopped. No animation loop,
 * no `requestAnimationFrame`, no settling: this is a function from a graph to a set of
 * coordinates, which makes it testable without a browser and means the picture does not
 * move after it arrives.
 *
 * # Why it is deterministic
 *
 * Seeded from each resource's id rather than from `Math.random`, so the same estate always
 * draws the same picture. That matters more than it sounds: an operator comparing this
 * morning's topology against a screenshot from last week needs to be comparing two
 * pictures of the same shape, and a bug report about a graph nobody can reproduce is a bug
 * report nobody can act on.
 *
 * # Why not a library
 *
 * The algorithm is Fruchterman-Reingold and it is forty lines. Every graph library that
 * would supply it also supplies its own node and edge rendering, which is the part this
 * product has an opinion about — see the dependency rule in UI-SPEC's part 2 preamble.
 */

export interface GraphNode {
  id: string;
  name: string;
  kind: string;
  status: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  /** Which protocol last confirmed it: `lldp`, `cdp`, `arp`, `manual`. */
  discovered_by: string;
}

export interface Placed extends GraphNode {
  x: number;
  y: number;
}

export interface Layout {
  nodes: Placed[];
  edges: GraphEdge[];
  /** Nodes not drawn because the graph was over budget — §14.4. */
  omitted: number;
  /** Components not drawn, for the same reason. */
  omittedComponents: number;
}

/**
 * How many nodes are drawn before the picture becomes a black circle.
 *
 * Not a performance limit — SVG handles far more than this. It is a legibility limit: a
 * force layout of two thousand nodes conveys nothing no matter how fast it renders.
 */
export const NODE_BUDGET = 400;

/** Iterations. Enough to settle a few hundred nodes; cheap enough to run synchronously. */
const ITERATIONS = 300;

/**
 * A stable number in [0, 1) from a string.
 *
 * The same mixing function `uops_poll::wheel` uses on the Rust side, for the same reason:
 * consecutive ids must not land in consecutive places, or every estate created in one
 * loop comes out in a line.
 */
function seeded(id: string): number {
  let h = 0x9e3779b9;
  for (let i = 0; i < id.length; i++) {
    h = Math.imul(h ^ id.charCodeAt(i), 0x85ebca6b);
    h = (h ^ (h >>> 13)) >>> 0;
  }
  h = Math.imul(h ^ (h >>> 16), 0xc2b2ae35) >>> 0;
  return (h >>> 0) / 4294967296;
}

/** Connected components, largest first. */
function components(nodes: GraphNode[], edges: GraphEdge[]): string[][] {
  const near = new Map<string, string[]>();
  for (const n of nodes) near.set(n.id, []);
  for (const e of edges) {
    near.get(e.source)?.push(e.target);
    near.get(e.target)?.push(e.source);
  }

  const seen = new Set<string>();
  const out: string[][] = [];
  for (const n of nodes) {
    if (seen.has(n.id)) continue;
    const group: string[] = [];
    const queue = [n.id];
    seen.add(n.id);
    while (queue.length > 0) {
      const id = queue.pop() as string;
      group.push(id);
      for (const next of near.get(id) ?? []) {
        if (!seen.has(next)) {
          seen.add(next);
          queue.push(next);
        }
      }
    }
    out.push(group);
  }
  // Largest first, ties broken by id so the order is stable across loads.
  return out.sort((a, b) => b.length - a.length || (a[0] ?? "").localeCompare(b[0] ?? ""));
}

/**
 * Place a graph in a `size` × `size` box.
 *
 * Over `NODE_BUDGET` the largest components are kept and the rest reported in `omitted`
 * — §14.4's rule that an operator is told what is not being shown rather than left to
 * conclude the product lost it.
 */
export function layout(
  allNodes: GraphNode[],
  allEdges: GraphEdge[],
  size = 1000,
  budget = NODE_BUDGET,
): Layout {
  // Edges whose ends are both present. A dangling edge is a bug elsewhere, and drawing a
  // line to a node that is not there would make it look like one.
  const present = new Set(allNodes.map((n) => n.id));
  const real = allEdges.filter((e) => present.has(e.source) && present.has(e.target));

  const groups = components(allNodes, real);
  const keep = new Set<string>();
  let omittedComponents = 0;
  for (const group of groups) {
    if (keep.size + group.length <= budget) for (const id of group) keep.add(id);
    else omittedComponents += 1;
  }

  // Sorted by id before anything is placed.
  //
  // Determinism is not enough on its own: the initial ring is laid out by position in the
  // array, and floating-point addition is not associative, so the same graph arriving in
  // a different order produced a different picture. Two runs of the same sweep genuinely
  // do return rows in different orders, so the guarantee has to be about the *graph*
  // rather than about the array — which means putting the array in a canonical order
  // first. Found by the test that asserts it.
  const nodes = allNodes.filter((n) => keep.has(n.id)).sort((a, b) => a.id.localeCompare(b.id));
  const edges = real
    .filter((e) => keep.has(e.source) && keep.has(e.target))
    .sort((a, b) => a.source.localeCompare(b.source) || a.target.localeCompare(b.target));

  // Start on a circle rather than at random points: a circle has no crossings to undo, so
  // the simulation spends its iterations separating clusters instead of untangling a
  // knot it made itself.
  const placed: Placed[] = nodes.map((n, i) => {
    const angle = (i / Math.max(nodes.length, 1)) * Math.PI * 2 + seeded(n.id) * 0.4;
    const radius = size * 0.35 * (0.75 + seeded(n.id + "r") * 0.25);
    return {
      ...n,
      x: size / 2 + Math.cos(angle) * radius,
      y: size / 2 + Math.sin(angle) * radius,
    };
  });

  if (placed.length < 2) {
    for (const p of placed) {
      p.x = size / 2;
      p.y = size / 2;
    }
    return { nodes: placed, edges, omitted: allNodes.length - nodes.length, omittedComponents };
  }

  const index = new Map(placed.map((p, i) => [p.id, i]));
  // The ideal edge length for this many nodes in this much space.
  const k = Math.sqrt((size * size) / placed.length) * 0.6;
  let temperature = size * 0.1;
  const cooling = temperature / (ITERATIONS + 1);

  const dx = new Float64Array(placed.length);
  const dy = new Float64Array(placed.length);

  for (let step = 0; step < ITERATIONS; step++) {
    dx.fill(0);
    dy.fill(0);

    // Repulsion: every node pushes every other apart. O(n²), which at NODE_BUDGET is
    // 160 000 pairs per iteration — trivial, and the reason the budget is what keeps this
    // honest rather than a quadtree nobody would be able to debug.
    for (let i = 0; i < placed.length; i++) {
      const a = placed[i] as Placed;
      for (let j = i + 1; j < placed.length; j++) {
        const b = placed[j] as Placed;
        let ox = a.x - b.x;
        let oy = a.y - b.y;
        let d2 = ox * ox + oy * oy;
        if (d2 < 0.01) {
          // Two nodes exactly on top of each other have no direction to separate in.
          // Nudged apart by their seeds so the tie is broken the same way every time.
          ox = seeded(a.id) - 0.5;
          oy = seeded(b.id) - 0.5;
          d2 = ox * ox + oy * oy + 0.01;
        }
        const force = (k * k) / d2;
        dx[i] = (dx[i] ?? 0) + ox * force;
        dy[i] = (dy[i] ?? 0) + oy * force;
        dx[j] = (dx[j] ?? 0) - ox * force;
        dy[j] = (dy[j] ?? 0) - oy * force;
      }
    }

    // Attraction along edges.
    for (const e of edges) {
      const a = index.get(e.source);
      const b = index.get(e.target);
      if (a === undefined || b === undefined) continue;
      const ox = (placed[a] as Placed).x - (placed[b] as Placed).x;
      const oy = (placed[a] as Placed).y - (placed[b] as Placed).y;
      const d = Math.sqrt(ox * ox + oy * oy) || 0.01;
      const force = (d * d) / k / d;
      dx[a] = (dx[a] ?? 0) - ox * force;
      dy[a] = (dy[a] ?? 0) - oy * force;
      dx[b] = (dx[b] ?? 0) + ox * force;
      dy[b] = (dy[b] ?? 0) + oy * force;
    }

    for (let i = 0; i < placed.length; i++) {
      const p = placed[i] as Placed;
      const fx = dx[i] ?? 0;
      const fy = dy[i] ?? 0;
      const d = Math.sqrt(fx * fx + fy * fy) || 1;
      // Displacement is capped by the temperature, which falls to zero: that is what
      // makes this converge rather than oscillate.
      const limit = Math.min(d, temperature) / d;
      p.x += fx * limit;
      p.y += fy * limit;
      // Inside the box, with a margin so a node's label is never half off the edge.
      p.x = Math.max(size * 0.04, Math.min(size * 0.96, p.x));
      p.y = Math.max(size * 0.04, Math.min(size * 0.96, p.y));
    }

    temperature -= cooling;
  }

  return { nodes: placed, edges, omitted: allNodes.length - nodes.length, omittedComponents };
}

/** Which resources a node is directly connected to. */
export function neighboursOf(id: string, edges: GraphEdge[]): Set<string> {
  const out = new Set<string>([id]);
  for (const e of edges) {
    if (e.source === id) out.add(e.target);
    if (e.target === id) out.add(e.source);
  }
  return out;
}
