/**
 * Where the camera is, as arithmetic — `docs/UI-3D-DEVICE-EXPLORER.md` §7, §10.
 *
 * # Why this is a module and not forty lines inside the effect
 *
 * §10 asks for a test that *"camera bounds cannot pass the minimum/maximum distance"*, and
 * a bound that lives inside a `useEffect` beside a `WebGLRenderer` can only be tested by
 * starting a browser. Orbiting is spherical coordinates; there is nothing about it that
 * needs WebGL, so none of it imports `three` and all of it is checkable in milliseconds.
 *
 * # The bounds are the interesting part
 *
 * Two of them, and each exists because of a way a 3D view becomes unusable:
 *
 * * **`phi` short of the poles.** At exactly vertical the up vector is undefined and the
 *   view flips over — the scene appears to invert under the pointer, and the only recovery
 *   a user finds is reloading the page.
 * * **`radius` between a floor and a ceiling derived from the graph's own size.** Without
 *   the ceiling, one scroll gesture on a trackpad puts the estate an invisible distance
 *   away and there is nothing on screen to aim at. Without the floor, zooming passes
 *   through the geometry and shows the inside of a box.
 *
 * Both are derived from the graph's extent rather than fixed, because a two-node pair and
 * a four-hundred-node estate are three orders of magnitude apart in size and any constant
 * is wrong for one of them.
 */

/** Spherical position about the scene centre. */
export interface Orbit {
  /** Around the vertical axis, radians. Unbounded — turning right for ever is fine. */
  theta: number;
  /** Down from the vertical axis, radians. Bounded short of both poles. */
  phi: number;
  /** Distance from the centre. */
  radius: number;
}

export interface Vec3 {
  x: number;
  y: number;
  z: number;
}

/**
 * How close to the pole `phi` may come.
 *
 * Small enough that a user can look from nearly overhead — which is the useful view of a
 * layered graph — and large enough that the up vector never degenerates.
 */
export const POLE_MARGIN = 0.15;

/** The camera's field of view, in degrees. Shared with the scene so framing agrees. */
export const FIELD_OF_VIEW = 45;

/** How far out the ceiling is, as a multiple of the framing distance. */
export const MAX_ZOOM_OUT = 4;

/** How close the floor is, as a multiple of the graph's own radius. */
export const MIN_ZOOM_IN = 0.35;

/**
 * The distance at which a sphere of `spread` fills the frame.
 *
 * `1.15` is margin: a graph that exactly fills the viewport has its outermost nodes on the
 * edge of the screen, which reads as cropped even when it is not.
 */
export function framingDistance(spread: number): number {
  const half = ((FIELD_OF_VIEW * Math.PI) / 180) / 2;
  return (Math.max(spread, 1) / Math.sin(half)) * 1.15;
}

/** Clamp `phi` short of both poles. */
export function clampPhi(phi: number): number {
  return Math.min(Math.PI - POLE_MARGIN, Math.max(POLE_MARGIN, phi));
}

/**
 * Clamp the distance between the floor and the ceiling.
 *
 * `fit` is what {@link framingDistance} returned for this graph; `spread` is the graph's
 * own radius.
 */
export function clampRadius(radius: number, fit: number, spread: number): number {
  return Math.min(fit * MAX_ZOOM_OUT, Math.max(Math.max(spread, 1) * MIN_ZOOM_IN, radius));
}

/** Where the camera sits, given an orbit about a centre. */
export function positionOf(orbit: Orbit, centre: Vec3): Vec3 {
  return {
    x: centre.x + orbit.radius * Math.sin(orbit.phi) * Math.cos(orbit.theta),
    y: centre.y + orbit.radius * Math.cos(orbit.phi),
    z: centre.z + orbit.radius * Math.sin(orbit.phi) * Math.sin(orbit.theta),
  };
}

/**
 * The named views §7 asks for.
 *
 * Semantic buttons with text, not gestures: a user who cannot drag must still be able to
 * look at the graph from above, which is WCAG 2.2's dragging-movement guidance applied to
 * the one control in this product that is a drag by nature.
 *
 * `top` is not exactly overhead — see {@link POLE_MARGIN}.
 */
export type CameraPreset = "reset" | "top" | "front" | "side";

export const PRESETS: ReadonlyArray<{ id: CameraPreset; label: string; hint: string }> = [
  { id: "reset", label: "Reset view", hint: "Frame the whole graph from the default angle" },
  { id: "top", label: "Top", hint: "Look down: layout without the layers" },
  { id: "front", label: "Front", hint: "Look level: the layers without the layout" },
  { id: "side", label: "Side", hint: "Look level from the side" },
];

/**
 * The orbit a preset means.
 *
 * `front` and `side` sit at `phi = π/2` — level with the centre — which is the view that
 * makes hop distance legible, because the layers become horizontal bands. `top` removes
 * the layers entirely and leaves the 2D layout, which is the other half of what the mode
 * is for.
 */
export function orbitFor(preset: CameraPreset, fit: number): Orbit {
  switch (preset) {
    case "top":
      return { theta: Math.PI * 0.25, phi: POLE_MARGIN, radius: fit };
    case "front":
      return { theta: -Math.PI / 2, phi: Math.PI / 2, radius: fit };
    case "side":
      return { theta: 0, phi: Math.PI / 2, radius: fit };
    case "reset":
      return { theta: Math.PI * 0.25, phi: Math.PI * 0.32, radius: fit };
  }
}
