/**
 * The words beside the scene — `docs/UI-3D-DEVICE-EXPLORER.md` §7, §10.
 *
 * These are the two pure decisions the panel makes. Both are about *evidence*: which
 * protocol saw a link, and how much that is worth. A picture can say "dashed"; only the
 * panel can say why, and it is the only form of the answer a screen reader ever gets.
 */

import { describe, expect, it } from "vitest";

import type { GraphEdge, Placed } from "./graph";
import { evidenceOf, neighboursWithEvidence } from "./scene3d-overlay";

function at(id: string, name: string): Placed {
  return { id, name, kind: "device", status: "up", x: 0, y: 0 };
}

const nodes = [at("a", "core-01"), at("b", "sw-02"), at("c", "ap-03"), at("d", "lonely")];

describe("neighboursWithEvidence", () => {
  it("finds a neighbour whichever end of the edge it is", () => {
    const edges: GraphEdge[] = [
      { source: "a", target: "b", discovered_by: "lldp" },
      { source: "c", target: "a", discovered_by: "cdp" },
    ];
    const found = neighboursWithEvidence("a", nodes, edges).map((n) => n.node.id);
    expect(new Set(found)).toEqual(new Set(["b", "c"]));
  });

  it("lets the stronger evidence win when two protocols saw the same pair", () => {
    // "LLDP and also ARP" is an LLDP link. Reporting ARP would understate what is known
    // and would put a caveat on a link that does not need one.
    const edges: GraphEdge[] = [
      { source: "a", target: "b", discovered_by: "arp" },
      { source: "a", target: "b", discovered_by: "lldp" },
    ];
    const found = neighboursWithEvidence("a", nodes, edges);
    expect(found).toHaveLength(1);
    expect(found[0]?.discoveredBy).toBe("lldp");
  });

  it("does not let weaker evidence overwrite stronger", () => {
    // The same pair in the other order. A naive last-one-wins would report ARP here and
    // LLDP above, which is the same graph described two different ways.
    const edges: GraphEdge[] = [
      { source: "a", target: "b", discovered_by: "lldp" },
      { source: "a", target: "b", discovered_by: "arp" },
    ];
    expect(neighboursWithEvidence("a", nodes, edges)[0]?.discoveredBy).toBe("lldp");
  });

  it("ignores an edge to a node that is not drawn", () => {
    // Past the node budget, an edge can point at a device the layout omitted. A neighbour
    // row for it would be a name with nothing behind it.
    const edges: GraphEdge[] = [{ source: "a", target: "not-here", discovered_by: "lldp" }];
    expect(neighboursWithEvidence("a", nodes, edges)).toEqual([]);
  });

  it("says nothing rather than something about an unlinked device", () => {
    expect(neighboursWithEvidence("d", nodes, [])).toEqual([]);
  });

  it("is sorted by name, so the list does not reshuffle between renders", () => {
    const edges: GraphEdge[] = [
      { source: "a", target: "c", discovered_by: "lldp" },
      { source: "a", target: "b", discovered_by: "lldp" },
    ];
    expect(neighboursWithEvidence("a", nodes, edges).map((n) => n.node.name)).toEqual([
      "ap-03",
      "sw-02",
    ]);
  });
});

describe("evidenceOf", () => {
  it("says out loud that an ARP link is weaker", () => {
    // The dashed line says this to somebody who has learned the convention. This is the
    // form the rule takes for everybody else, and the only form a screen reader gets.
    const said = evidenceOf("arp");
    expect(said).toMatch(/weaker/i);
    expect(said).toMatch(/does not prove/i);
  });

  it("does not put that caveat on a neighbour protocol", () => {
    for (const strong of ["lldp", "cdp"]) {
      expect(evidenceOf(strong)).not.toMatch(/weaker/i);
    }
  });

  it("has something to say about a protocol this build has not heard of", () => {
    // A backend that grows a discovery source must not produce a blank row.
    const said = evidenceOf("bgp-ls");
    expect(said).toContain("bgp-ls");
  });
});
