/**
 * CSS tokens into WebGL materials — `docs/UI-3D-DEVICE-EXPLORER.md` §6.1, §5.3.
 *
 * # Why the scene reads the stylesheet
 *
 * The semantic five — up, down, degraded, maintenance, unknown — are CSS custom
 * properties, and they are the single source. WebGL cannot read `var(--ok)`, so the values
 * are resolved off the document when the scene is built. Copying them into a constant here
 * would be a second palette to keep in step, and the one that drifts is always the one
 * nobody looks at.
 *
 * Resolved at scene-build time rather than per frame: a theme change lands on the next
 * open of the mode, which is the same behaviour the 2D view has.
 *
 * # One coloured surface per node
 *
 * A node's chassis carries its status and nothing else does. Every other part of a model
 * is drawn in the neutral border token — see `scene3d-models.ts` — so that a shape with
 * more parts does not read as more alarming than one with fewer.
 */

import * as THREE from "three";

/** The tokens the scene needs, resolved once. */
export interface Palette {
  /** By resource status. */
  status: (status: string) => THREE.Color;
  /** Edges, accent parts, and anything that is structure rather than state. */
  neutral: THREE.Color;
  /** Text-coloured, for the selection highlight. */
  ink: THREE.Color;
}

/**
 * Resolve a CSS custom property to something WebGL can use.
 *
 * A token that is missing or unparseable falls back rather than throwing: a scene that
 * refuses to open because a stylesheet moved is worse than one drawn in grey.
 */
function token(name: string, fallback: string): THREE.Color {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  try {
    return new THREE.Color(raw || fallback);
  } catch {
    return new THREE.Color(fallback);
  }
}

/**
 * Which token a status uses.
 *
 * Exported because the legend and the 2D view have to agree with the scene, and a second
 * copy of this switch is how they stop agreeing.
 */
export function tokenForStatus(status: string): string {
  switch (status) {
    case "up":
      return "--ok";
    case "down":
      return "--danger";
    case "degraded":
      return "--warn";
    case "maintenance":
      return "--maintenance";
    default:
      return "--unknown";
  }
}

/** Read the palette off the document. */
export function readPalette(): Palette {
  const cache = new Map<string, THREE.Color>();
  return {
    status: (status: string) => {
      const name = tokenForStatus(status);
      let colour = cache.get(name);
      if (!colour) {
        colour = token(name, "#888888");
        cache.set(name, colour);
      }
      return colour;
    },
    neutral: token("--border-strong", "#333333"),
    ink: token("--text", "#eeeeee"),
  };
}

/**
 * Materials, one per (colour, accent) pair rather than one per node.
 *
 * A material per node would be four hundred of them for six distinct colours, all needing
 * disposal. What is actually per node is *opacity* — dimming is how selection works — so
 * the cache is keyed by colour and the transparent variants are separate entries rather
 * than mutations of a shared one.
 */
export class Materials {
  private readonly made = new Map<string, THREE.MeshBasicMaterial>();

  constructor(private readonly palette: Palette) {}

  /**
   * The material for a node's chassis.
   *
   * `dimmed` is selection's doing: §4.2 says unrelated devices are dimmed rather than
   * hidden, because removing them removes the context that makes the selection mean
   * something.
   */
  chassis(status: string, dimmed: boolean): THREE.MeshBasicMaterial {
    return this.get(`s:${status}:${dimmed}`, this.palette.status(status), dimmed);
  }

  /** The neutral material every non-status part of a model uses. */
  accent(dimmed: boolean): THREE.MeshBasicMaterial {
    return this.get(`a:${dimmed}`, this.palette.neutral, dimmed);
  }

  /**
   * The selected node's chassis: its status colour, lifted towards the text colour.
   *
   * Lifted rather than replaced, so a selected `down` device is still recognisably down.
   * Selection is the one thing §5.3 allows scale to mean, and this is the colour half of
   * the same signal.
   */
  selected(status: string): THREE.MeshBasicMaterial {
    const key = `x:${status}`;
    let material = this.made.get(key);
    if (!material) {
      const colour = this.palette.status(status).clone().lerp(this.palette.ink, 0.35);
      material = new THREE.MeshBasicMaterial({ color: colour });
      this.made.set(key, material);
    }
    return material;
  }

  private get(key: string, colour: THREE.Color, dimmed: boolean): THREE.MeshBasicMaterial {
    let material = this.made.get(key);
    if (!material) {
      material = new THREE.MeshBasicMaterial({
        color: colour,
        transparent: dimmed,
        opacity: dimmed ? 0.15 : 1,
      });
      this.made.set(key, material);
    }
    return material;
  }

  /** How many distinct materials the scene ended up with. For a test, and for profiling. */
  get size(): number {
    return this.made.size;
  }

  dispose(): void {
    for (const material of this.made.values()) material.dispose();
    this.made.clear();
  }
}
