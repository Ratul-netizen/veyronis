/**
 * The topology in three dimensions — UI-SPEC §14.7.
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
 * # Why three.js and not a React renderer for it
 *
 * The dependency rule in part 2: a dependency must solve a problem that is materially
 * expensive or unsafe to solve ourselves. WebGL qualifies. React *bindings* for WebGL are
 * convenience — this scene has no per-frame React state, it is spheres and lines — so
 * they do not, and `@react-three/fiber` also pins a React version older than this app's.
 *
 * # Why it is loaded on demand
 *
 * `three` is about half the size of the rest of the application. An operator who never
 * opens the 3D mode should never download it, so this module is behind `React.lazy` and
 * nothing here is imported by the 2D path.
 */

import { useEffect, useRef, useState } from "react";
import * as THREE from "three";

import type { GraphEdge, Placed } from "./graph";

/**
 * Vertical distance between two layers, in world units.
 *
 * Against a layout plane 1 000 units across. At 60 the tiers were technically present and
 * visually nothing — the whole point of the mode is that depth is legible, so the
 * separation has to be a large fraction of the spread, not a rounding error on it.
 */
const LAYER = 170;
const NODE_SIZE = 9;

/**
 * Resolve a CSS custom property to something WebGL can use.
 *
 * The scene cannot read `var(--ok)`; the tokens are the single source of the semantic
 * five and duplicating their values here would be a second palette to keep in step. So
 * they are read off the document at build time of the scene, which also means the scene
 * follows a theme change on the next open.
 */
function token(name: string, fallback: string): THREE.Color {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  try {
    return new THREE.Color(raw || fallback);
  } catch {
    return new THREE.Color(fallback);
  }
}

function colourOf(status: string): string {
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

export interface Scene3dProps {
  nodes: Placed[];
  edges: GraphEdge[];
  depths: Map<string, number>;
  selected: string | null;
  onSelect: (id: string | null) => void;
}

export default function Scene3d({
  nodes,
  edges,
  depths,
  selected,
  onSelect,
}: Scene3dProps) {
  const host = useRef<HTMLDivElement>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  // Kept in a ref as well, so the render loop can read it without re-running the effect
  // and rebuilding the whole scene on every pointer move.
  const hoverRef = useRef<string | null>(null);
  const selectRef = useRef<string | null>(selected);
  selectRef.current = selected;

  useEffect(() => {
    const mount = host.current;
    if (!mount || nodes.length === 0) return;

    const scene = new THREE.Scene();
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mount.appendChild(renderer.domElement);

    const camera = new THREE.PerspectiveCamera(45, 1, 1, 6000);

    // The graph's own extent, so the camera frames whatever it is given rather than a
    // size somebody guessed.
    const maxDepth = Math.max(...nodes.map((n) => depths.get(n.id) ?? 0), 0);
    // Negative, because layers descend: a node's height is `-depth * LAYER`, so the middle
    // of the stack is below zero. Looking at `+maxDepth/2` aimed the camera above the
    // whole graph and put one node in a corner of an otherwise empty scene.
    const centre = new THREE.Vector3(500, -(maxDepth * LAYER) / 2, 500);

    const nodeColour = new Map<string, THREE.Color>();
    for (const n of nodes) {
      nodeColour.set(n.id, token(colourOf(n.status), "#888888"));
    }
    const dim = token("--border-strong", "#333333");
    const ink = token("--text", "#eeeeee");

    // --- nodes -------------------------------------------------------------
    // One geometry and one mesh per node: at NODE_BUDGET this is a few hundred draw
    // calls, which is nothing, and it keeps picking and per-node colour simple. Instanced
    // rendering would be the answer at ten thousand, and ten thousand is not legible.
    const geometry = new THREE.SphereGeometry(NODE_SIZE, 20, 16);
    const meshes: THREE.Mesh[] = [];
    for (const n of nodes) {
      const material = new THREE.MeshBasicMaterial({
        color: nodeColour.get(n.id) ?? dim,
      });
      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.set(n.x, -(depths.get(n.id) ?? 0) * LAYER, n.y);
      mesh.userData["id"] = n.id;
      scene.add(mesh);
      meshes.push(mesh);
    }

    // --- edges -------------------------------------------------------------
    const at = new Map(nodes.map((n) => [n.id, n]));
    const lines: { line: THREE.Line; a: string; b: string }[] = [];
    for (const e of edges) {
      const a = at.get(e.source);
      const b = at.get(e.target);
      if (!a || !b) continue;
      const points = [
        new THREE.Vector3(a.x, -(depths.get(a.id) ?? 0) * LAYER, a.y),
        new THREE.Vector3(b.x, -(depths.get(b.id) ?? 0) * LAYER, b.y),
      ];
      // ARP dashed, as in 2D: the same evidence is drawn the same way in both modes, or
      // the two views disagree about how much to trust a link.
      const material =
        e.discovered_by === "arp"
          ? new THREE.LineDashedMaterial({ color: dim, dashSize: 8, gapSize: 6 })
          : new THREE.LineBasicMaterial({ color: dim });
      const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), material);
      if (e.discovered_by === "arp") line.computeLineDistances();
      scene.add(line);
      lines.push({ line, a: e.source, b: e.target });
    }

    // --- camera control ----------------------------------------------------
    // Hand-rolled orbit: drag rotates, wheel zooms. Forty lines against a dependency that
    // would also bring a scene-graph helper library with it.
    // Framed from the graph's own bounding sphere rather than a distance somebody guessed:
    // a four-node pair and a four-hundred-node estate need very different camera
    // distances, and a fixed one is wrong for both.
    const spread = Math.max(
      ...nodes.map((n) =>
        Math.hypot(n.x - centre.x, -(depths.get(n.id) ?? 0) * LAYER - centre.y, n.y - centre.z),
      ),
      1,
    );
    const fit = (spread / Math.sin((45 * Math.PI) / 180 / 2)) * 1.15;
    const orbit = { theta: Math.PI * 0.25, phi: Math.PI * 0.32, radius: fit };
    let dragging = false;
    let lastX = 0;
    let lastY = 0;

    function place() {
      const r = orbit.radius;
      camera.position.set(
        centre.x + r * Math.sin(orbit.phi) * Math.cos(orbit.theta),
        centre.y + r * Math.cos(orbit.phi),
        centre.z + r * Math.sin(orbit.phi) * Math.sin(orbit.theta),
      );
      camera.lookAt(centre);
    }

    const onDown = (event: PointerEvent) => {
      dragging = true;
      lastX = event.clientX;
      lastY = event.clientY;
      renderer.domElement.setPointerCapture(event.pointerId);
    };
    const onUp = (event: PointerEvent) => {
      dragging = false;
      renderer.domElement.releasePointerCapture(event.pointerId);
    };
    const onMove = (event: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.set(
        ((event.clientX - rect.left) / rect.width) * 2 - 1,
        -((event.clientY - rect.top) / rect.height) * 2 + 1,
      );
      if (!dragging) return;
      orbit.theta -= (event.clientX - lastX) * 0.006;
      // Clamped short of the poles: at exactly vertical the up vector is undefined and
      // the view flips.
      orbit.phi = Math.min(Math.PI - 0.15, Math.max(0.15, orbit.phi - (event.clientY - lastY) * 0.006));
      lastX = event.clientX;
      lastY = event.clientY;
      place();
    };
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      // Bounded relative to what is on screen, so zooming out cannot lose the graph and
      // zooming in cannot pass through it.
      orbit.radius = Math.min(fit * 4, Math.max(spread * 0.35, orbit.radius * (1 + event.deltaY * 0.001)));
      place();
    };

    // --- picking -----------------------------------------------------------
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2(-2, -2);

    const onClick = () => {
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(meshes)[0];
      const id = hit ? (hit.object.userData["id"] as string) : null;
      onSelect(id === selectRef.current ? null : id);
    };

    renderer.domElement.addEventListener("pointerdown", onDown);
    renderer.domElement.addEventListener("pointerup", onUp);
    renderer.domElement.addEventListener("pointermove", onMove);
    renderer.domElement.addEventListener("wheel", onWheel, { passive: false });
    renderer.domElement.addEventListener("click", onClick);

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
    }
    const observer = new ResizeObserver(resize);
    observer.observe(mount);
    resize();

    // --- the loop ----------------------------------------------------------
    // It draws on demand rather than continuously: nothing in this scene moves unless
    // somebody moves it, and §14.3's argument against a permanent simulation applies
    // just as much to a permanent render loop on a wall display.
    let frame = 0;
    let dirty = true;
    const markDirty = () => {
      dirty = true;
    };
    renderer.domElement.addEventListener("pointermove", markDirty);
    renderer.domElement.addEventListener("wheel", markDirty);

    function tick() {
      frame = requestAnimationFrame(tick);

      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(meshes)[0];
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

      for (const mesh of meshes) {
        const id = mesh.userData["id"] as string;
        const lit = !chosen || near.has(id);
        const material = mesh.material as THREE.MeshBasicMaterial;
        material.color.copy(nodeColour.get(id) ?? dim);
        material.opacity = lit ? 1 : 0.15;
        material.transparent = !lit;
        const emphasised = id === chosen || id === hoverRef.current;
        mesh.scale.setScalar(emphasised ? 1.5 : 1);
        if (id === chosen) material.color.lerp(ink, 0.35);
      }

      for (const { line, a, b } of lines) {
        const lit = !chosen || (near.has(a) && near.has(b));
        const material = line.material as THREE.LineBasicMaterial;
        material.opacity = lit ? 1 : 0.1;
        material.transparent = !lit;
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
      renderer.domElement.removeEventListener("pointermove", markDirty);
      renderer.domElement.removeEventListener("wheel", onWheel);
      renderer.domElement.removeEventListener("wheel", markDirty);
      renderer.domElement.removeEventListener("click", onClick);
      // A WebGL context is not garbage collected on its own, and a browser allows only a
      // handful at once — leaking one per visit to this screen means the fifteenth visit
      // renders nothing.
      geometry.dispose();
      for (const mesh of meshes) (mesh.material as THREE.Material).dispose();
      for (const { line } of lines) {
        line.geometry.dispose();
        (line.material as THREE.Material).dispose();
      }
      renderer.dispose();
      mount.removeChild(renderer.domElement);
    };
  }, [nodes, edges, depths, onSelect]);

  const under = hovered ?? selected;
  const name = under ? nodes.find((n) => n.id === under)?.name : null;

  return (
    <div className="scene3d" ref={host}>
      {/* Names are not drawn in the scene: text in WebGL costs a font atlas and a
          dependency, and §14's split is that 3D carries shape while the panel beside it
          carries the facts. What is under the pointer is named here instead. */}
      {name && <span className="scene3d-readout">{name}</span>}
    </div>
  );
}
