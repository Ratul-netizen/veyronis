/**
 * The shapes themselves — `docs/UI-3D-DEVICE-EXPLORER.md` §5.1, §5.2.
 *
 * # Procedural, not downloaded
 *
 * §3 and §9 both forbid a remote asset, and §5.1 asks for a procedural catalogue. Every
 * shape here is boxes and cylinders written down in about a line each. That buys four
 * things a GLTF file does not: it is deterministic, it is in the bundle, it has no licence
 * attached to somebody else's product design, and it can be reviewed by reading it.
 *
 * # Shared geometry, per-node mesh
 *
 * A model is a list of {@link Part}s, and every node drawn as that model reuses the *same*
 * `BufferGeometry` objects. What is per node is the mesh and its material, because the
 * material carries the status colour. At the 400-node budget that is a few hundred draw
 * calls, which is nothing; §5.2 says to reach for `InstancedMesh` only after profiling
 * says to, and it would complicate picking for a saving that does not exist yet.
 *
 * # Two detail levels, and the reason the low one is not just "smaller"
 *
 * `low` is what four hundred nodes are drawn as: one box, one silhouette, readable across
 * a room. `rich` is the selected node alone. The split is not decoration — §5.2's rule is
 * that a 48-port front face on every node is both slower and *less* legible, because the
 * detail that distinguishes a server from a switch disappears into noise when it is
 * repeated four hundred times.
 *
 * # What an `accent` part is for
 *
 * A chassis carries the status colour, and nothing else does. Port bands, drive bays and
 * the capsule's rings are `accent`: drawn in the neutral border token so that the coloured
 * surface of a node is always the same surface. Without that rule a device with a wide
 * port band reads as "more down" than one without.
 */

import * as THREE from "three";

import type { DeviceModelKind } from "./devicemodel";

/**
 * The size everything is expressed in.
 *
 * Matches the sphere radius the scene used before this existed, so switching to shapes did
 * not silently change how big the graph looks or how far the camera has to be.
 */
export const UNIT = 9;

/** One piece of a model. */
export interface Part {
  geometry: THREE.BufferGeometry;
  /** Where it sits relative to the node's position, in world units. */
  position: [number, number, number];
  /**
   * Drawn in the neutral token rather than the status colour.
   *
   * The chassis is the status surface and it is the only one. See the module docs.
   */
  accent?: boolean;
}

export interface DeviceModel {
  /** Every node. One silhouette. */
  low: Part[];
  /** The selected node, and neighbours in focus mode. */
  rich: Part[];
}

/**
 * Every shape, and the geometries they share.
 *
 * `dispose` must be called when the scene is torn down: a `BufferGeometry` holds a WebGL
 * buffer, and a browser allows only a handful of contexts — the existing scene teardown
 * has the same note on it for the same reason.
 */
export interface Catalogue {
  models: Record<DeviceModelKind, DeviceModel>;
  dispose: () => void;
}

/**
 * Build the catalogue.
 *
 * Called once per scene rather than once per module load: a geometry belongs to the WebGL
 * context that used it, and a module-level one would outlive the renderer that disposed
 * it and come back as an empty buffer on the second visit to the screen.
 */
export function buildCatalogue(): Catalogue {
  const owned: THREE.BufferGeometry[] = [];
  const keep = <T extends THREE.BufferGeometry>(geometry: T): T => {
    owned.push(geometry);
    return geometry;
  };

  const box = (w: number, h: number, d: number) =>
    keep(new THREE.BoxGeometry(w * UNIT, h * UNIT, d * UNIT));
  const cylinder = (r: number, h: number, segments = 18) =>
    keep(new THREE.CylinderGeometry(r * UNIT, r * UNIT, h * UNIT, segments));

  // --- shared pieces ------------------------------------------------------
  // A rack unit, near enough: wide, shallow, and thin enough that a stack of them reads
  // as a stack rather than as a wall.
  const chassis1u = box(2.6, 0.5, 1.5);
  const chassis2u = box(2.6, 0.95, 1.5);
  const portBand = box(2.2, 0.16, 0.1);
  const driveBay = box(0.5, 0.6, 0.12);
  const cube = box(1.1, 1.1, 1.1);
  const smallCube = box(0.75, 0.75, 0.75);
  const drum = cylinder(0.85, 0.95);
  const drumRing = cylinder(0.88, 0.07);
  const capsule = cylinder(0.75, 1.3, 14);
  const capsuleRing = cylinder(0.8, 0.08, 14);
  const neutralBlock = box(1.0, 0.9, 1.0);

  const front = 1.5 / 2 + 0.05;

  const models: Record<DeviceModelKind, DeviceModel> = {
    // A networking box. One rack unit, and deliberately nothing that says *which* kind —
    // see `devicemodel.ts` for why there is no switch, router or firewall here.
    appliance: {
      low: [{ geometry: chassis1u, position: [0, 0, 0] }],
      rich: [
        { geometry: chassis1u, position: [0, 0, 0] },
        // A neutral port band on the front face. §5.4 stage A: slots, not a claim about
        // any physical interface. Nothing is clickable and nothing is counted.
        { geometry: portBand, position: [0, -0.08 * UNIT, front * UNIT], accent: true },
        { geometry: portBand, position: [0, 0.1 * UNIT, front * UNIT], accent: true },
      ],
    },

    // Something that runs workloads: taller, with drive bays rather than ports.
    server: {
      low: [{ geometry: chassis2u, position: [0, 0, 0] }],
      rich: [
        { geometry: chassis2u, position: [0, 0, 0] },
        { geometry: driveBay, position: [-0.8 * UNIT, 0, front * UNIT], accent: true },
        { geometry: driveBay, position: [-0.15 * UNIT, 0, front * UNIT], accent: true },
        { geometry: driveBay, position: [0.5 * UNIT, 0, front * UNIT], accent: true },
      ],
    },

    // A workload inside a host: a cube, because it is the one shape in this catalogue that
    // is obviously not a piece of rack equipment.
    container: {
      low: [{ geometry: smallCube, position: [0, 0, 0] }],
      rich: [
        { geometry: cube, position: [0, 0, 0] },
        { geometry: smallCube, position: [0, 0.85 * UNIT, 0], accent: true },
      ],
    },

    // A database. The drum is the oldest symbol in this business and the only one nobody
    // has to be taught.
    datastore: {
      low: [{ geometry: drum, position: [0, 0, 0] }],
      rich: [
        { geometry: drum, position: [0, 0, 0] },
        { geometry: drumRing, position: [0, 0.5 * UNIT, 0], accent: true },
        { geometry: drumRing, position: [0, -0.5 * UNIT, 0], accent: true },
      ],
    },

    // A logical thing: a capsule standing up, which is not a box and is not a drum, so it
    // does not read as either.
    service: {
      low: [{ geometry: capsule, position: [0, 0, 0] }],
      rich: [
        { geometry: capsule, position: [0, 0, 0] },
        { geometry: capsuleRing, position: [0, 0.7 * UNIT, 0], accent: true },
        { geometry: capsuleRing, position: [0, -0.7 * UNIT, 0], accent: true },
      ],
    },

    // Nothing is claimed. A plain block, and the same one at both detail levels: adding
    // detail to a model that means "we do not know what this is" would be inventing it.
    unknown: {
      low: [{ geometry: neutralBlock, position: [0, 0, 0] }],
      rich: [{ geometry: neutralBlock, position: [0, 0, 0] }],
    },
  };

  return {
    models,
    dispose: () => {
      for (const geometry of owned) geometry.dispose();
      owned.length = 0;
    },
  };
}

/**
 * How far a model reaches from its own centre, in world units.
 *
 * The camera framing and the layout's spacing both need a radius, and the previous scene
 * had one for free because everything was a sphere. Taking the largest half-extent of the
 * largest part keeps a wide chassis from overlapping its neighbour.
 */
export function radiusOf(model: DeviceModel): number {
  let radius = 0;
  for (const part of model.rich) {
    part.geometry.computeBoundingSphere();
    const bound = part.geometry.boundingSphere;
    if (!bound) continue;
    const offset = Math.hypot(part.position[0], part.position[1], part.position[2]);
    radius = Math.max(radius, bound.radius + offset);
  }
  return radius || UNIT;
}
