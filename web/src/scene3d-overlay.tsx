/**
 * The half of the 3D view that is not WebGL — `docs/UI-3D-DEVICE-EXPLORER.md` §7, §9.
 *
 * # Why a canvas is never the only way in
 *
 * §7: *"A user who cannot drag must be able to select, inspect, navigate, and return to 2D
 * without dragging."* A `<canvas>` has no children, so nothing inside the scene can be
 * focused, announced or tabbed to — every device in it is invisible to a screen reader and
 * unreachable from a keyboard.
 *
 * So the facts live here, in HTML, beside the scene rather than inside it: what is
 * selected, what it is, what it is connected to and by what evidence, and buttons for
 * every camera view. The scene shows shape and arrangement; this shows words. That split
 * is the same one the 2D view already makes with its detail panel, and it is why the shape
 * catalogue is allowed to be as reticent as it is — a silhouette that declines to say
 * whether a box is a switch has a sentence next to it saying exactly that.
 *
 * # Nothing here is decorative
 *
 * Every row is either a fact from the backend or a control. There is no legend entry for a
 * colour that is not used and no shape in the catalogue that cannot appear.
 */

import {
  MODEL_KINDS,
  describeModel,
  labelForModel,
  modelFor,
  type DeviceModelKind,
} from "./devicemodel";
import type { GraphEdge, Placed } from "./graph";
import { PRESETS, type CameraPreset } from "./scene3d-interaction";

/** What the scene is doing — §4. */
export type SceneMode = "estate" | "focus";

/** One neighbour of the selected device, with how it was discovered. */
export interface Neighbour {
  node: Placed;
  /** `lldp`, `cdp`, `arp`, `manual`. */
  discoveredBy: string;
}

export interface OverlayProps {
  nodes: Placed[];
  edges: GraphEdge[];
  depths: ReadonlyMap<string, number>;
  selected: string | null;
  hovered: string | null;
  mode: SceneMode;
  onSelect: (id: string | null) => void;
  onMode: (mode: SceneMode) => void;
  onCamera: (preset: CameraPreset) => void;
  /** `Open resource` — absent when the route does not exist yet. */
  onOpen?: ((id: string) => void) | undefined;
}

/**
 * How much to trust a link, in words.
 *
 * The scene draws ARP dashed. That is the whole of what the picture can say, and it says
 * it only to somebody who has learned the convention — so the same thing is said here in a
 * sentence, which is also the only form available to a screen reader.
 */
export function evidenceOf(discoveredBy: string): string {
  switch (discoveredBy) {
    case "lldp":
      return "LLDP — the device named this neighbour";
    case "cdp":
      return "CDP — the device named this neighbour";
    case "arp":
      return "ARP only — both addresses were seen on one segment. This is weaker: it does not prove a direct link.";
    case "manual":
      return "Recorded by hand";
    default:
      return `Reported by ${discoveredBy}`;
  }
}

/** The neighbours of a node, with the evidence for each. */
export function neighboursWithEvidence(
  id: string,
  nodes: Placed[],
  edges: GraphEdge[],
): Neighbour[] {
  const at = new Map(nodes.map((n) => [n.id, n]));
  const found = new Map<string, Neighbour>();
  for (const edge of edges) {
    const other = edge.source === id ? edge.target : edge.target === id ? edge.source : null;
    if (!other) continue;
    const node = at.get(other);
    if (!node) continue;
    // Two devices can be linked by more than one protocol. The stronger evidence wins,
    // because "LLDP and also ARP" is an LLDP link — saying ARP would understate it.
    const existing = found.get(other);
    if (!existing || (existing.discoveredBy === "arp" && edge.discovered_by !== "arp")) {
      found.set(other, { node, discoveredBy: edge.discovered_by });
    }
  }
  return [...found.values()].sort((a, b) => a.node.name.localeCompare(b.node.name));
}

export default function Scene3dOverlay({
  nodes,
  edges,
  depths,
  selected,
  hovered,
  mode,
  onSelect,
  onMode,
  onCamera,
  onOpen,
}: OverlayProps) {
  const chosen = selected ? nodes.find((n) => n.id === selected) : undefined;
  const under = hovered ? nodes.find((n) => n.id === hovered) : undefined;
  const neighbours = chosen ? neighboursWithEvidence(chosen.id, nodes, edges) : [];
  const shape: DeviceModelKind | null = chosen ? modelFor(chosen) : null;
  // Only the shapes actually on screen. A legend listing a silhouette nobody can see is a
  // legend an operator stops reading.
  const present = new Set(nodes.map(modelFor));

  return (
    <div className="scene3d-panel">
      <div className="scene3d-controls">
        <span className="presets" role="group" aria-label="Camera">
          {PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              className="quiet"
              title={preset.hint}
              onClick={() => onCamera(preset.id)}
            >
              {preset.label}
            </button>
          ))}
        </span>
        <span className="presets" role="group" aria-label="Scene">
          <button type="button" aria-pressed={mode === "estate"} onClick={() => onMode("estate")}>
            Estate
          </button>
          <button
            type="button"
            aria-pressed={mode === "focus"}
            disabled={!chosen}
            title={chosen ? "Centre on the selected device" : "Select a device first"}
            onClick={() => onMode("focus")}
          >
            Focus
          </button>
        </span>
      </div>

      {/* Announced when it changes, so a keyboard user who selects from the list below
          hears what happened without looking at the canvas. */}
      <div className="scene3d-readout" aria-live="polite">
        {under && under.id !== selected
          ? `${under.name} — ${under.status}`
          : chosen
            ? `${chosen.name} — ${chosen.status}`
            : "Nothing selected"}
      </div>

      {chosen && shape ? (
        <div className="scene3d-inspect">
          <h3>{chosen.name}</h3>
          <p className="dim">
            {labelForModel(shape)} · {chosen.status}
            {depths.has(chosen.id) && ` · ${depths.get(chosen.id)} hop(s) from the most connected device`}
          </p>
          {/* The sentence that stops the silhouette being read as a claim — §5.1. */}
          <p className="dim">{describeModel(shape)}</p>

          <h4>Links</h4>
          {neighbours.length === 0 ? (
            <p className="dim">Nothing is linked to this device.</p>
          ) : (
            <ul className="scene3d-links">
              {neighbours.map((n) => (
                <li key={n.node.id}>
                  {/* Selecting a neighbour from here is the keyboard path through the
                      graph: no drag, no pick, no canvas. */}
                  <button type="button" className="link" onClick={() => onSelect(n.node.id)}>
                    {n.node.name}
                  </button>
                  <span className="dim"> — {evidenceOf(n.discoveredBy)}</span>
                </li>
              ))}
            </ul>
          )}

          <div className="scene3d-actions">
            {onOpen && (
              <button type="button" onClick={() => onOpen(chosen.id)}>
                Open resource
              </button>
            )}
            <button type="button" className="quiet" onClick={() => onSelect(null)}>
              Clear selection
            </button>
          </div>
        </div>
      ) : (
        <div className="scene3d-inspect">
          <p className="dim">
            Select a device to see what it is linked to. Everything here is also reachable
            from the 2D view, which needs no dragging.
          </p>
          {/* The keyboard way in: a list, before anything has been picked out of the
              canvas. Capped, because four hundred buttons is not a control. */}
          <ul className="scene3d-links">
            {nodes.slice(0, 12).map((n) => (
              <li key={n.id}>
                <button type="button" className="link" onClick={() => onSelect(n.id)}>
                  {n.name}
                </button>
                <span className="dim"> — {n.status}</span>
              </li>
            ))}
          </ul>
          {nodes.length > 12 && (
            <p className="dim">
              …and {nodes.length - 12} more. Use the 2D view or the search box to reach one
              by name.
            </p>
          )}
        </div>
      )}

      <div className="scene3d-legend">
        <h4>What the shapes mean</h4>
        <ul>
          {MODEL_KINDS.filter((kind) => present.has(kind)).map((kind) => (
            <li key={kind}>
              <strong>{labelForModel(kind)}</strong> — {describeModel(kind)}
            </li>
          ))}
        </ul>
        <p className="dim">
          Height is hops from the most connected device in each group — a fact about the
          graph, not a claim about which box is the core. A dashed link was seen by ARP
          only.
        </p>
      </div>
    </div>
  );
}
