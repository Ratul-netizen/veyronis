/**
 * The camera cannot be lost — `docs/UI-3D-DEVICE-EXPLORER.md` §10.
 *
 * Both of these bounds exist because of a way the view becomes unusable, and both are one
 * removed line away from being gone. Neither is visible in a screenshot, which is why they
 * are asserted rather than reviewed.
 */

import { describe, expect, it } from "vitest";

import {
  MAX_ZOOM_OUT,
  MIN_ZOOM_IN,
  POLE_MARGIN,
  PRESETS,
  clampPhi,
  clampRadius,
  framingDistance,
  orbitFor,
  positionOf,
  type CameraPreset,
} from "./scene3d-interaction";

describe("the vertical bound", () => {
  it("never reaches either pole", () => {
    // At exactly vertical the up vector is undefined and the view flips under the
    // pointer. The only recovery a user finds is reloading the page.
    for (const attempt of [-10, -Math.PI, 0, Math.PI, 10, Number.MAX_SAFE_INTEGER]) {
      const phi = clampPhi(attempt);
      expect(phi).toBeGreaterThanOrEqual(POLE_MARGIN);
      expect(phi).toBeLessThanOrEqual(Math.PI - POLE_MARGIN);
    }
  });

  it("leaves an ordinary angle alone", () => {
    expect(clampPhi(Math.PI / 2)).toBeCloseTo(Math.PI / 2);
  });
});

describe("the distance bound", () => {
  const spread = 500;
  const fit = framingDistance(spread);

  it("frames the graph from outside it", () => {
    // A framing distance inside the graph's own radius means the camera starts within the
    // estate, looking at the inside of a node.
    expect(fit).toBeGreaterThan(spread);
  });

  it("scales with the graph rather than being a constant", () => {
    // A two-node pair and a four-hundred-node estate are orders of magnitude apart, and
    // any fixed distance is wrong for one of them.
    expect(framingDistance(5000)).toBeGreaterThan(framingDistance(50) * 10);
  });

  it("cannot be zoomed out past the ceiling", () => {
    // One trackpad flick otherwise puts the estate an invisible distance away with
    // nothing on screen to aim back at.
    expect(clampRadius(1e9, fit, spread)).toBeCloseTo(fit * MAX_ZOOM_OUT);
  });

  it("cannot be zoomed in through the geometry", () => {
    expect(clampRadius(0, fit, spread)).toBeCloseTo(spread * MIN_ZOOM_IN);
    expect(clampRadius(-100, fit, spread)).toBeGreaterThan(0);
  });

  it("survives a degenerate graph", () => {
    // One node, or every node in the same place: `spread` is zero and a floor of zero
    // would let the camera sit exactly on the centre, where `lookAt` has no direction.
    expect(clampRadius(0, framingDistance(0), 0)).toBeGreaterThan(0);
  });
});

describe("the camera presets", () => {
  const fit = framingDistance(500);
  const centre = { x: 500, y: -300, z: 500 };

  it("offers every named view with a label and a hint", () => {
    // §7: every preset is a semantic button with text. A control with no label is a
    // control a screen reader announces as "button".
    expect(PRESETS.length).toBeGreaterThanOrEqual(4);
    for (const preset of PRESETS) {
      expect(preset.label.length).toBeGreaterThan(0);
      expect(preset.hint.length).toBeGreaterThan(0);
    }
  });

  it("puts every preset inside the bounds it would otherwise break", () => {
    for (const { id } of PRESETS) {
      const orbit = orbitFor(id, fit);
      expect(clampPhi(orbit.phi)).toBeCloseTo(orbit.phi);
      expect(orbit.radius).toBeGreaterThan(0);
    }
  });

  it("looks down from the top and level from the front and the side", () => {
    // What makes the two views worth having: `top` drops the layers and leaves the 2D
    // layout, `front` drops the layout and leaves the layers as horizontal bands.
    const top = positionOf(orbitFor("top", fit), centre);
    expect(top.y).toBeGreaterThan(centre.y);

    for (const level of ["front", "side"] as CameraPreset[]) {
      const at = positionOf(orbitFor(level, fit), centre);
      expect(at.y).toBeCloseTo(centre.y, 5);
    }
  });

  it("puts front and side in different places", () => {
    const front = positionOf(orbitFor("front", fit), centre);
    const side = positionOf(orbitFor("side", fit), centre);
    expect(Math.hypot(front.x - side.x, front.z - side.z)).toBeGreaterThan(fit);
  });

  it("is deterministic", () => {
    // Same graph, same button, same view — an operator comparing this morning against a
    // screenshot needs the two to be comparable.
    expect(positionOf(orbitFor("reset", fit), centre)).toEqual(
      positionOf(orbitFor("reset", fit), centre),
    );
  });
});

describe("positionOf", () => {
  it("stays on the sphere it was given", () => {
    const centre = { x: 10, y: -20, z: 30 };
    for (const phi of [POLE_MARGIN, 0.8, Math.PI / 2, Math.PI - POLE_MARGIN]) {
      const at = positionOf({ theta: 1.1, phi, radius: 250 }, centre);
      const distance = Math.hypot(at.x - centre.x, at.y - centre.y, at.z - centre.z);
      expect(distance).toBeCloseTo(250, 6);
    }
  });
});
