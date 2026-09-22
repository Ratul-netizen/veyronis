/**
 * The fixtures are what they say they are — `docs/UI-3D-DEVICE-EXPLORER.md` §10.
 *
 * A fixture nobody checks is a fixture that quietly stops containing the case it was built
 * for. Each of these asserts the *property the estate exists to exercise*, not its
 * contents: "there is an ARP-only link", not "there are nine edges".
 */

import { describe, expect, it } from "vitest";

import { NODE_BUDGET, depths, layout } from "./graph";
import { MODEL_KINDS, modelFor } from "./devicemodel";
import { ESTATES, largeEstate, mixedEstate, smallCampus } from "./topologyfixtures";

describe("every fixture", () => {
  it("has a node that is not up", () => {
    // A topology of entirely green boxes is the one state an operator never opens this
    // screen in, so it is the one state a fixture must not be in.
    for (const { name, estate } of ESTATES) {
      const unhealthy = estate().nodes.filter((n) => n.status !== "up");
      expect(unhealthy.length, `${name} is entirely healthy`).toBeGreaterThan(0);
    }
  });

  it("has an ARP-only link somewhere, so the weak-evidence style is always exercised", () => {
    for (const { name, estate } of ESTATES) {
      const arp = estate().edges.filter((e) => e.discovered_by === "arp");
      expect(arp.length, `${name} has no ARP edge`).toBeGreaterThan(0);
    }
  });

  it("refers only to nodes it contains", () => {
    // An edge to a node that is not there is the shape of a fixture somebody edited half
    // of, and the layout silently drops it — so the fixture would keep passing while
    // testing less than it says.
    for (const { name, estate } of ESTATES) {
      const { nodes, edges } = estate();
      const ids = new Set(nodes.map((n) => n.id));
      for (const edge of edges) {
        expect(ids.has(edge.source), `${name}: ${edge.source}`).toBe(true);
        expect(ids.has(edge.target), `${name}: ${edge.target}`).toBe(true);
      }
    }
  });

  it("draws with a shape this build knows", () => {
    for (const { estate } of ESTATES) {
      for (const node of estate().nodes) {
        expect(MODEL_KINDS).toContain(modelFor(node));
      }
    }
  });
});

describe("the small campus", () => {
  it("contains every shape the catalogue can draw except the ones it has no kind for", () => {
    // The fixture a reviewer looks at to answer §8's Phase 1 exit criterion — "can a user
    // distinguish these at a glance" — so it has to contain more than one shape.
    const shapes = new Set(smallCampus().nodes.map(modelFor));
    expect(shapes.has("appliance")).toBe(true);
    expect(shapes.has("server")).toBe(true);
    expect(shapes.has("datastore")).toBe(true);
    expect(shapes.size).toBeGreaterThanOrEqual(3);
  });

  it("is one connected component, so hop distance means something in it", () => {
    const { nodes, edges } = smallCampus();
    const depth = depths(nodes, edges);
    expect(depth.size).toBe(nodes.length);
    // And it is more than one layer deep, or the 3D view has nothing to show.
    expect(Math.max(...depth.values())).toBeGreaterThan(1);
  });
});

describe("the mixed estate", () => {
  it("has a component nothing joins to the rest", () => {
    // The case §14.4's omitted-component disclosure is about, and the case a force layout
    // gets wrong by pushing an island out of frame.
    const { nodes, edges } = mixedEstate();
    const reachable = new Set<string>(["r1"]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const e of edges) {
        if (reachable.has(e.source) && !reachable.has(e.target)) {
          reachable.add(e.target);
          grew = true;
        }
        if (reachable.has(e.target) && !reachable.has(e.source)) {
          reachable.add(e.source);
          grew = true;
        }
      }
    }
    expect(reachable.size).toBeLessThan(nodes.length);
  });

  it("puts logical resources beside physical ones", () => {
    const shapes = new Set(mixedEstate().nodes.map(modelFor));
    expect(shapes.has("service")).toBe(true);
    expect(shapes.has("container")).toBe(true);
    expect(shapes.has("unknown")).toBe(true);
  });
});

describe("the large estate", () => {
  it("makes the sizes the performance work measures", () => {
    // §9: 50, 200 and 400. A parameter rather than three hand-written fixtures, so two of
    // the three measurements are not somebody's ad-hoc script.
    for (const size of [50, 200, 400]) {
      expect(largeEstate(size).nodes.length).toBe(size);
    }
  });

  it("goes past the budget, so the disclosure is always reachable", () => {
    const { nodes, edges } = largeEstate(440);
    expect(nodes.length).toBeGreaterThan(NODE_BUDGET);
    const placed = layout(nodes, edges);
    expect(placed.nodes.length).toBeLessThanOrEqual(NODE_BUDGET);
    expect(placed.omitted + placed.omittedComponents).toBeGreaterThan(0);
  });
});
