/**
 * The topology in three dimensions — UI-SPEC §14.7, `docs/UI-3D-DEVICE-EXPLORER.md`.
 *
 * # What the third dimension carries
 *
 * Height is hop distance from the most connected device in each component. That is a fact
 * about the graph rather than a claim about the network: §14.0 forbids the UI from
 * inventing backend semantics, and "this is the core layer" is an inference nobody has
 * made. In practice the two usually agree — the box everything is cabled to is the box
 * with the most cables — which is why the view is worth having, and the caption on screen
 * says what is actually measured so an estate that does not follow the pattern is not
 * being described falsely.
 *
 * `x` and `z` are the 2D layout's own coordinates, unchanged. Switching modes therefore
 * lifts the picture you were already looking at rather than rearranging it, which is the
 * difference between a second view of one network and two views that have to be learned
 * separately.
 *
 * # What this file is, after the split
 *
 * Lifecycle and nothing else: build the scene, wire the pointer, draw on demand, dispose.
 * The decisions moved out to where they can be tested without a browser —
 *
 * | | |
 * |---|---|
 * | which shape a resource is | `devicemodel.ts` |
 * | what the shapes are made of | `scene3d-models.ts` |
 * | which colour means what | `scene3d-materials.ts` |
 * | where the camera may go | `scene3d-interaction.ts` |
 * | every fact, in words | `scene3d-overlay.tsx` |
 *
 * That split is not tidiness. A bound on how far the camera may zoom is a one-line rule
 * whose absence makes the view unusable, and inside a `useEffect` beside a
 * `WebGLRenderer` the only way to check it is to start a browser and try.
 *
 * # Why three.js and not a React renderer for it
 *
 * The dependency rule in part 2: a dependency must solve a problem that is materially
 * expensive or unsafe to solve ourselves. WebGL qualifies. React *bindings* for WebGL are
 * convenience — this scene has no per-frame React state — so they do not, and
 * `@react-three/fiber` also pins a React version older than this app's.
 *
 * # Why it is loaded on demand
 *
 * `three` is about half the size of the rest of the application. An operator who never
 * opens the 3D mode should never download it, so this module is behind `React.lazy` and
 * nothing here is imported by the 2D path.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import * as THREE from "three";

import { modelFor } from "./devicemodel";
import type { GraphEdge, Placed } from "./graph";
import { Materials, readPalette } from "./scene3d-materials";
import { buildCatalogue, UNIT, type Part } from "./scene3d-models";
import {
  clampPhi,
  decay,
  pitchFor,
  yawFor,
  zoomFactor,
  clampRadius,
  framingDistance,
  orbitFor,
  positionOf,
  FIELD_OF_VIEW,
  type CameraPreset,
  type Orbit,
} from "./scene3d-interaction";
import Scene3dOverlay, { type SceneMode } from "./scene3d-overlay";

/**
 * Vertical distance between two layers, in world units.
 *
 * Against a layout plane 1 000 units across. At 60 the tiers were technically present and
 * visually nothing — the whole point of the mode is that depth is legible, so the
 * separation has to be a large fraction of the spread, not a rounding error on it.
 */
const LAYER = 170;

export interface Scene3dProps {
  nodes: Placed[];
  edges: GraphEdge[];
  depths: Map<string, number>;
  selected: string | null;
  onSelect: (id: string | null) => void;
  /** `Open resource` from the inspector. Absent until the route exists. */
  onOpen?: (id: string) => void;
}

export default function Scene3d({
  nodes,
  edges,
  depths,
  selected,
  onSelect,
  onOpen,
}: Scene3dProps) {
  const host = useRef<HTMLDivElement>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [mode, setMode] = useState<SceneMode>("estate");

  // Kept in refs as well, so the render loop can read them without re-running the effect
  // and rebuilding the whole scene on every pointer move or selection.
  const hoverRef = useRef<string | null>(null);
  const selectRef = useRef<string | null>(selected);
  selectRef.current = selected;
  const modeRef = useRef<SceneMode>(mode);
  modeRef.current = mode;

  // The scene exposes two imperative hooks to the HTML beside it: move the camera, and
  // redraw. Both are set by the effect and read by the overlay's buttons.
  const cameraTo = useRef<(preset: CameraPreset) => void>(() => {});
  const focusOn = useRef<(id: string | null) => void>(() => {});
  const markDirty = useRef<() => void>(() => {});

  const chooseMode = useCallback((next: SceneMode) => {
    setMode(next);
    modeRef.current = next;
    if (next === "focus") focusOn.current(selectRef.current);
    else cameraTo.current("reset");
    markDirty.current();
  }, []);

  const choose = useCallback(
    (id: string | null) => {
      onSelect(id);
      selectRef.current = id;
      if (id === null && modeRef.current === "focus") {
        setMode("estate");
        modeRef.current = "estate";
        cameraTo.current("reset");
      } else if (modeRef.current === "focus") {
        focusOn.current(id);
      }
      markDirty.current();
    },
    [onSelect],
  );

  useEffect(() => {
    const mount = host.current;
    if (!mount || nodes.length === 0) return;

    const scene = new THREE.Scene();
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mount.appendChild(renderer.domElement);

    const camera = new THREE.PerspectiveCamera(FIELD_OF_VIEW, 1, 1, 12000);

    const palette = readPalette();
    const materials = new Materials(palette);
    const catalogue = buildCatalogue();

    const heightOf = (id: string) => -(depths.get(id) ?? 0) * LAYER;

    // The graph's own extent, so the camera frames whatever it is given rather than a
    // size somebody guessed.
    const maxDepth = Math.max(...nodes.map((n) => depths.get(n.id) ?? 0), 0);
    // Negative, because layers descend: the middle of the stack is below zero. Looking at
    // `+maxDepth/2` aimed the camera above the whole graph.
    const centre = new THREE.Vector3(500, -(maxDepth * LAYER) / 2, 500);

    // --- nodes -------------------------------------------------------------
    // A `Group` per node whose children are meshes over *shared* geometry: at the node
    // budget this is a few hundred draw calls, which is nothing, and it keeps picking and
    // per-node colour simple. Instanced rendering would be the answer at ten thousand, and
    // ten thousand is not legible — §5.2.
    interface Drawn {
      id: string;
      status: string;
      group: THREE.Group;
      /** What is currently built, so a frame that changes nothing rebuilds nothing. */
      detail: "low" | "rich";
      dimmed: boolean;
      chosen: boolean;
    }
    const drawn: Drawn[] = [];
    const pickable: THREE.Object3D[] = [];

    function build(group: THREE.Group, parts: Part[], status: string, dimmed: boolean) {
      for (const part of parts) {
        const material = part.accent
          ? materials.accent(dimmed)
          : dimmed
            ? materials.chassis(status, true)
            : materials.chassis(status, false);
        const mesh = new THREE.Mesh(part.geometry, material);
        mesh.position.set(part.position[0], part.position[1], part.position[2]);
        mesh.userData["id"] = group.userData["id"];
        group.add(mesh);
        pickable.push(mesh);
      }
    }

    function rebuild(node: Drawn, detail: "low" | "rich", dimmed: boolean, chosen: boolean) {
      // Children are disposed of by removal only — the geometry is shared and owned by the
      // catalogue, the materials are shared and owned by `Materials`. Nothing per-mesh is
      // allocated that needs freeing, which is the point of both caches.
      for (const child of [...node.group.children]) {
        node.group.remove(child);
        const at = pickable.indexOf(child);
        if (at >= 0) pickable.splice(at, 1);
      }
      const original = nodes.find((n) => n.id === node.id);
      const model = catalogue.models[modelFor(original ?? { kind: "" })];
      build(node.group, detail === "rich" ? model.rich : model.low, node.status, dimmed);
      if (chosen) {
        // The selected node's chassis takes the lifted colour. Only the chassis: an accent
        // part is structure, and lighting all of it would make selection read as a status.
        const chassis = node.group.children[0] as THREE.Mesh | undefined;
        if (chassis) chassis.material = materials.selected(node.status);
      }
      node.detail = detail;
      node.dimmed = dimmed;
      node.chosen = chosen;
    }

    for (const n of nodes) {
      const group = new THREE.Group();
      group.userData["id"] = n.id;
      group.position.set(n.x, heightOf(n.id), n.y);
      const entry: Drawn = {
        id: n.id,
        status: n.status,
        group,
        detail: "low",
        dimmed: false,
        chosen: false,
      };
      build(group, catalogue.models[modelFor(n)].low, n.status, false);
      scene.add(group);
      drawn.push(entry);
    }

    // --- edges -------------------------------------------------------------
    const at = new Map(nodes.map((n) => [n.id, n]));
    const lines: { line: THREE.Line; a: string; b: string }[] = [];
    const lineMaterials: THREE.Material[] = [];
    // Two materials for the whole graph rather than one per edge: opacity is set per frame
    // on whichever of the two an edge is using, so dimming needs four in total.
    const solidLit = new THREE.LineBasicMaterial({ color: palette.neutral });
    const solidDim = new THREE.LineBasicMaterial({
      color: palette.neutral,
      transparent: true,
      opacity: 0.1,
    });
    const dashLit = new THREE.LineDashedMaterial({
      color: palette.neutral,
      dashSize: 8,
      gapSize: 6,
    });
    const dashDim = new THREE.LineDashedMaterial({
      color: palette.neutral,
      dashSize: 8,
      gapSize: 6,
      transparent: true,
      opacity: 0.1,
    });
    lineMaterials.push(solidLit, solidDim, dashLit, dashDim);

    for (const e of edges) {
      const a = at.get(e.source);
      const b = at.get(e.target);
      if (!a || !b) continue;
      const points = [
        new THREE.Vector3(a.x, heightOf(a.id), a.y),
        new THREE.Vector3(b.x, heightOf(b.id), b.y),
      ];
      // ARP dashed, as in 2D: the same evidence is drawn the same way in both modes, or
      // the two views disagree about how much to trust a link.
      const arp = e.discovered_by === "arp";
      const line = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(points),
        arp ? dashLit : solidLit,
      );
      if (arp) line.computeLineDistances();
      scene.add(line);
      lines.push({ line, a: e.source, b: e.target });
    }

    // --- camera control ----------------------------------------------------
    // Hand-rolled orbit: drag rotates, wheel zooms. Forty lines against a dependency that
    // would also bring a scene-graph helper library with it. Framed from the graph's own
    // bounding sphere rather than a distance somebody guessed.
    const spread = Math.max(
      ...nodes.map((n) => Math.hypot(n.x - centre.x, heightOf(n.id) - centre.y, n.y - centre.z)),
      UNIT,
    );
    const fit = framingDistance(spread);
    let target = centre.clone();
    const orbit: Orbit = orbitFor("reset", fit);
    let dragging = false;
    let lastX = 0;
    let lastY = 0;

    function place() {
      const at = positionOf(orbit, target);
      camera.position.set(at.x, at.y, at.z);
      camera.lookAt(target);
    }

    cameraTo.current = (preset: CameraPreset) => {
      const next = orbitFor(preset, fit);
      orbit.theta = next.theta;
      orbit.phi = next.phi;
      orbit.radius = next.radius;
      if (preset === "reset") target = centre.clone();
      place();
      dirty = true;
    };

    focusOn.current = (id: string | null) => {
      const node = id ? at.get(id) : undefined;
      if (!node) {
        target = centre.clone();
      } else {
        // Centre on the device and come close enough that its neighbours are the scene.
        // Not so close that the rest disappears: §4.2 dims unrelated devices rather than
        // hiding them, because the surrounding graph is what makes the selection mean
        // something.
        target = new THREE.Vector3(node.x, heightOf(node.id), node.y);
        orbit.radius = clampRadius(fit * 0.35, fit, spread);
      }
      place();
      dirty = true;
    };

    // Momentum, so a flick keeps turning and settles. Without it every rotation stops
    // dead on pointer-up and inspecting a graph becomes a series of short strokes — half
    // of why this was reported as tough to use.
    let spinTheta = 0;
    let spinPhi = 0;
    let panning = false;

    const onDown = (event: PointerEvent) => {
      // Right button, middle button or shift pans. Rotating is what the left button does
      // because that is what every 3D view does; panning needs to exist at all, because
      // an orbit with a fixed centre cannot bring an off-centre device into view.
      panning = event.button === 1 || event.button === 2 || event.shiftKey;
      dragging = true;
      spinTheta = 0;
      spinPhi = 0;
      lastX = event.clientX;
      lastY = event.clientY;
      renderer.domElement.setPointerCapture(event.pointerId);
      renderer.domElement.style.cursor = panning ? "move" : "grabbing";
    };
    const onUp = (event: PointerEvent) => {
      dragging = false;
      panning = false;
      renderer.domElement.releasePointerCapture(event.pointerId);
      renderer.domElement.style.cursor = "grab";
      dirty = true;
    };
    const onMove = (event: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.set(
        ((event.clientX - rect.left) / rect.width) * 2 - 1,
        -((event.clientY - rect.top) / rect.height) * 2 + 1,
      );
      if (!dragging) return;
      const dx = event.clientX - lastX;
      const dy = event.clientY - lastY;

      if (panning) {
        // Move the centre in the camera's own plane, scaled by distance so the graph
        // tracks the cursor at any zoom.
        const scale = (orbit.radius * 2) / Math.max(rect.height, 1);
        const right = new THREE.Vector3().setFromMatrixColumn(camera.matrix, 0);
        const up = new THREE.Vector3().setFromMatrixColumn(camera.matrix, 1);
        target.x += (-dx * scale * right.x) + (dy * scale * up.x);
        target.y += (-dx * scale * right.y) + (dy * scale * up.y);
        target.z += (-dx * scale * right.z) + (dy * scale * up.z);
      } else {
        // Viewport-relative: dragging the width of the canvas turns the estate round,
        // whatever the screen. `yawFor`/`pitchFor` carry the reasoning and the tests.
        spinTheta = -yawFor(dx, rect.width);
        spinPhi = -pitchFor(dy, rect.height);
        orbit.theta += spinTheta;
        orbit.phi = clampPhi(orbit.phi + spinPhi);
      }
      lastX = event.clientX;
      lastY = event.clientY;
      place();
    };
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      // Normalised across deltaMode and exponential, so the same notch means the same
      // thing on every machine and zooming out then in returns to where it started.
      orbit.radius = clampRadius(
        orbit.radius * zoomFactor(event.deltaY, event.deltaMode),
        fit,
        spread,
      );
      place();
    };
    // Without this the browser's own menu interrupts a right-drag pan on the first frame.
    const onContextMenu = (event: MouseEvent) => event.preventDefault();

    // --- picking -----------------------------------------------------------
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2(-2, -2);

    const onClick = () => {
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(pickable)[0];
      const id = hit ? (hit.object.userData["id"] as string) : null;
      choose(id === selectRef.current ? null : id);
    };

    // Escape clears, as in 2D, and it is on the canvas rather than the window so it does
    // not steal the key from a dialog somewhere else on the page.
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") choose(null);
    };
    renderer.domElement.tabIndex = 0;

    renderer.domElement.addEventListener("pointerdown", onDown);
    renderer.domElement.addEventListener("pointerup", onUp);
    renderer.domElement.addEventListener("pointermove", onMove);
    renderer.domElement.addEventListener("wheel", onWheel, { passive: false });
    renderer.domElement.addEventListener("click", onClick);
    renderer.domElement.addEventListener("contextmenu", onContextMenu);
    renderer.domElement.style.cursor = "grab";
    renderer.domElement.addEventListener("keydown", onKey);

    // Declared before `resize`, and that is load-bearing rather than tidy.
    //
    // `resize` sets it, `ResizeObserver` calls `resize` **synchronously on observe**, and
    // `let` bindings are in a temporal dead zone until their declaration runs. Declared
    // below with the render loop — where it reads as belonging — the first observation
    // threw `ReferenceError: Cannot access 'dirty' before initialization`, the Suspense
    // boundary had no error boundary above it, and the whole 3D view rendered as
    // "Something went wrong". Found by pointing a browser at it; no test in the suite
    // covers a ResizeObserver firing.
    let dirty = true;
    let frame = 0;

    function resize() {
      const w = mount?.clientWidth ?? 1;
      const h = mount?.clientHeight ?? 1;
      // `updateStyle` left at its default of true: with it false the drawing buffer is
      // sized in device pixels while the element keeps no CSS size of its own, so the
      // canvas lays out at the buffer's dimensions and the view is cropped to a corner.
      renderer.setSize(w, h);
      camera.aspect = w / Math.max(h, 1);
      camera.updateProjectionMatrix();
      place();
      dirty = true;
    }
    const observer = new ResizeObserver(resize);
    observer.observe(mount);
    resize();

    // --- the loop ----------------------------------------------------------
    // It draws on demand rather than continuously: nothing in this scene moves unless
    // somebody moves it, and §14.3's argument against a permanent simulation applies
    // just as much to a permanent render loop on a wall display.
    const setDirty = () => {
      dirty = true;
    };
    markDirty.current = setDirty;
    renderer.domElement.addEventListener("pointermove", setDirty);
    renderer.domElement.addEventListener("wheel", setDirty);

    function tick() {
      frame = requestAnimationFrame(tick);

      // Coast after a flick. Only while the pointer is up, so a spin never fights a drag.
      if (!dragging && (spinTheta !== 0 || spinPhi !== 0)) {
        spinTheta = decay(spinTheta);
        spinPhi = decay(spinPhi);
        orbit.theta += spinTheta;
        orbit.phi = clampPhi(orbit.phi + spinPhi);
        place();
        dirty = true;
      }

      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(pickable)[0];
      const over = hit ? (hit.object.userData["id"] as string) : null;
      if (over !== hoverRef.current) {
        hoverRef.current = over;
        setHovered(over);
        dirty = true;
      }

      if (!dirty) return;
      dirty = false;

      // Selection dims everything not touching it, exactly as in 2D.
      const chosen = selectRef.current;
      const near = new Set<string>();
      if (chosen) {
        near.add(chosen);
        for (const e of edges) {
          if (e.source === chosen) near.add(e.target);
          if (e.target === chosen) near.add(e.source);
        }
      }

      for (const node of drawn) {
        const lit = !chosen || near.has(node.id);
        const emphasised = node.id === chosen || node.id === hoverRef.current;
        // Rich detail for the selected node, and — in focus mode only — its neighbours.
        // §5.2: a fully detailed front face on four hundred nodes is both slower and less
        // legible, because the detail stops distinguishing anything once it is everywhere.
        const wants: "low" | "rich" =
          node.id === chosen || (modeRef.current === "focus" && near.has(node.id))
            ? "rich"
            : "low";
        // Only when something about it actually changed. Rebuilding every node every
        // frame is invisible at four nodes and is the whole frame budget at four hundred —
        // and the render loop is on-demand precisely so that a frame that changes nothing
        // costs nothing.
        if (node.detail !== wants || node.dimmed === lit || node.chosen !== (node.id === chosen)) {
          rebuild(node, wants, !lit, node.id === chosen);
        }
        node.group.scale.setScalar(emphasised ? 1.5 : 1);
      }

      for (const { line, a, b } of lines) {
        const lit = !chosen || (near.has(a) && near.has(b));
        const dashed = (line.material as THREE.Material) === dashLit ||
          (line.material as THREE.Material) === dashDim;
        line.material = dashed ? (lit ? dashLit : dashDim) : lit ? solidLit : solidDim;
      }

      renderer.render(scene, camera);
    }
    tick();

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      renderer.domElement.removeEventListener("pointerdown", onDown);
      renderer.domElement.removeEventListener("pointerup", onUp);
      renderer.domElement.removeEventListener("pointermove", onMove);
      renderer.domElement.removeEventListener("pointermove", setDirty);
      renderer.domElement.removeEventListener("wheel", onWheel);
      renderer.domElement.removeEventListener("contextmenu", onContextMenu);
      renderer.domElement.removeEventListener("wheel", setDirty);
      renderer.domElement.removeEventListener("click", onClick);
      renderer.domElement.removeEventListener("keydown", onKey);
      cameraTo.current = () => {};
      focusOn.current = () => {};
      markDirty.current = () => {};
      // A WebGL context is not garbage collected on its own, and a browser allows only a
      // handful at once — leaking one per visit to this screen means the fifteenth visit
      // renders nothing.
      catalogue.dispose();
      materials.dispose();
      for (const material of lineMaterials) material.dispose();
      for (const { line } of lines) line.geometry.dispose();
      renderer.dispose();
      mount.removeChild(renderer.domElement);
    };
  }, [nodes, edges, depths, choose]);

  return (
    <div className="scene3d-host">
      {/* Names are not drawn in the scene: text in WebGL costs a font atlas and a
          dependency, and §14's split is that 3D carries shape while the panel beside it
          carries the facts. */}
      <div className="scene3d" ref={host} />
      <Scene3dOverlay
        nodes={nodes}
        edges={edges}
        depths={depths}
        selected={selected}
        hovered={hovered}
        mode={mode}
        onSelect={choose}
        onMode={chooseMode}
        onCamera={(preset) => cameraTo.current(preset)}
        onOpen={onOpen}
      />
    </div>
  );
}
