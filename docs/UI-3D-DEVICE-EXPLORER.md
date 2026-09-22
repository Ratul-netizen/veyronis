# UI 3D Device Explorer — implementation plan for Claude

**Status:** proposed implementation specification.  
**Prepared:** 22 September 2026.  
**Scope:** enrich the existing topology screen and `scene3d.tsx`; do not create a separate “3D product.”  
**Prerequisite:** preserve the existing M6 topology evidence model and M7 sampled-flow semantics.

## 1. Product decision

Veyronis already has a 2D topology screen and a lazy-loaded Three.js 3D mode. The current
3D mode is structurally correct: it keeps the 2D layout coordinates, uses height for graph
hop distance, labels weak ARP edges as dashed, selects rather than navigates, has no permanent
render animation, and is not shipped to users who never open it.

This work changes the scene from **coloured spheres and lines** into a useful spatial explorer
with generic device models, without converting the NOC console into a game.

The rule is:

> **2D is the default operational map. 3D is a deliberate exploration mode that explains
> hierarchy, physical placement, and impact. Device models are detailed only when the
> detail tells the operator something.**

The references behind this choice are consistent: serious observability products use a selected
entity plus filters, depth, metrics, and drill-down rather than a permanent global graph. See
[Dynatrace topology](https://docs.dynatrace.com/docs/analyze-explore-automate/smartscape/smartscape-in-context-views/smartscape-view-topology),
[Grafana service graphs](https://grafana.com/docs/tempo/latest/metrics-from-traces/service_graphs/service-graph-view/), and
[New Relic service maps](https://docs.newrelic.com/docs/new-relic-solutions/new-relic-one/ui-data/service-maps/service-maps/).

## 2. Goals

1. Make topology visually memorable **because it answers operational questions faster**.
2. Let an operator select a device and understand its role, state, immediate links, evidence,
   and incident relevance without losing the surrounding graph.
3. Show generic but high-quality 3D models for network and infrastructure devices.
4. Support a “focus / impact” scene for a selected device or incident candidate.
5. Keep the 2D and 3D views semantically identical: same resources, links, status, evidence,
   selection, tenant scope, and truncation disclosures.
6. Remain air-gap safe: no CDN, no runtime asset downloads, no vendor cloud calls.
7. Preserve accessibility, low-power usability, deterministic layout, and the existing
   node-budget principle.

## 3. Non-goals and hard boundaries

- Not a photorealistic digital twin or a CAD/rack-planning product.
- Not a free-form manual diagram editor. Topology remains discovered evidence, not hand-drawn truth.
- Not vendor-branded hardware models in the first release. Do not use vendor logos, product
  photographs, trademarks, or copied front-panel designs without explicit rights.
- Not a physical-location claim when only logical discovery exists.
- Not 3D for dashboards, tables, alerts, logs, traces, or the incident timeline.
- Not animated traffic particles, spinning devices, idle camera motion, bloom, glow effects,
  gradients, or decorative animation.
- Not a new backend truth for topology. The UI only visualizes data the backend has established.
- Not an excuse to move M10 runner/API/screens, M11, or pilot work down the priority list.

## 4. User-facing modes

The topology page retains its existing 2D/3D switch. Inside 3D, use a single mode selector:

### 4.1 Estate mode — default 3D

Shows the selected topology component as a layered scene.

```text
vertical position     graph hop distance from the component root
x/z position          existing deterministic 2D layout
node model            device kind, never a claimed vendor/model unless known
node state             resource status
edge style             discovery confidence / source
```

The screen caption keeps the current honest wording: “Height is hops from the most connected
device.” It must not say “core / distribution / access” unless those roles are derived by a
future explicit backend model.

### 4.2 Focus mode — selected device

Entering focus mode does not reload or rearrange the whole graph. It:

- keeps the selected device at the visual center;
- keeps one-hop neighbours fully visible and dims unrelated devices;
- shows the selected device with the detailed generic model;
- opens an inspect panel with resource facts, link evidence, health, alerts/incidents, and
  direct navigation to resource, incident, flows, logs, and traces when those routes exist;
- offers `Return to estate` and `Open resource` as explicit controls.

### 4.3 Impact mode — future, only after the incident API provides it

This is a visual treatment of M9 evidence, not a new root-cause engine.

- Entry: `Explore impact` from an incident whose `candidate_resource_id` is non-null.
- Center: candidate / **likely origin**, with the existing explanation of why it was chosen.
- Highlight: incident resources and their hop distance from the candidate.
- Dim: non-incident resources; do not hide them completely because they provide context.
- Caption: `Likely origin based on topology direction and alert order.`
- If there is no candidate, do not fabricate one; show a normal focus scene and explain that
  the evidence did not identify a likely origin.

Do not build Impact mode by reconstructing incident logic in TypeScript. It consumes the
incident API's candidate and linked alert/resource set.

## 5. Visual system

### 5.1 Generic device catalogue

Implement a **procedural** catalogue in Three.js code. This is the correct first asset
pipeline: small, deterministic, offline, testable, and free of product-design licensing risk.

| Semantic model | Used for | Geometry language | Detail level |
|---|---|---|---|
| `switch` | `switch`, L2 device | 1U horizontal chassis; optional port band | rich when selected |
| `router` | router / WAN gateway | compact horizontal appliance with fewer large ports | rich when selected |
| `firewall` | firewall / security appliance | 1U appliance with distinct management face | rich when selected |
| `server` | server / VM host | 1U or 2U chassis with drive/port blocks | rich when selected |
| `storage` | storage | wider chassis with drive bays | rich when selected |
| `access-point` | wireless AP | shallow disc / rounded square | medium |
| `cloud-service` | service, database, cloud resource | abstract stacked/capsule shape, not a vendor logo | medium |
| `unknown` | unclassified resource | restrained neutral block | low |
| `rack` | future explicit physical container only | open frame and U markers | future |

> **Amended while building Phase 1.** §12 asks for exactly this: *"Before each phase,
> inspect the relevant current code and update this specification if the repository has
> moved."* It had not moved — the table above was written against kinds this product has
> never had.
>
> `resource_kind`, migration 0002 and unchanged since, is: `device`, `interface`, `host`,
> `vm`, `container`, `service`, `application`, `database`, `cloud_resource`, `site`. There
> is no `switch`, no `router`, no `firewall`, no access point and no storage array. Every
> networking box in an estate is a `device`, and nothing distinguishes them:
> `sysServices` — the standard SNMP signal for "this box does layer 2" versus "layer 3" —
> is asked for by the discovery probe and is not stored, and `TopologyNode` carries only
> `id`, `name`, `display_name`, `kind` and `status`.
>
> A `modelFor` returning `"switch"` would therefore be inventing the one thing this
> section forbids inventing, and it would do it for the **majority of nodes in every
> estate**, which is worse than doing it rarely: an operator who sees four hundred
> confident silhouettes stops reading them as guesses.
>
> So the shipped catalogue is the split the data supports — `appliance`, `server`,
> `container`, `datastore`, `service`, `unknown` — with `appliance` carrying a sentence in
> the inspector that says in words that the product does not know whether it is looking at
> a switch, a router or a firewall. Six silhouettes, each backed by a column.
>
> The rest of the table is not cancelled, it is **blocked on evidence**, and the evidence
> is nameable: a device sub-kind on the resource, derived from `sysServices` or from a
> monitoring profile. When that arrives, `web/src/devicemodel.ts` is the one file that
> changes — everything else in the scene takes a `DeviceModelKind` and does not care where
> it came from.

Mappings must be conservative. A resource with unknown or ambiguous kind uses `unknown`, never a
confidently wrong model. Add a unit-tested pure resolver:

```ts
type DeviceModelKind =
  | "switch" | "router" | "firewall" | "server" | "storage"
  | "access-point" | "cloud-service" | "unknown";

function modelFor(resource: TopologyNode): DeviceModelKind
```

The first version maps **resource kind only**. Vendor/model-specific layouts are a future opt-in
layer, enabled only when identity has high-confidence make/model data and the visual asset is
owned or licensed for use.

### 5.2 Detail budget

Never draw a fully detailed 48-port appliance for all 400 visible nodes.

- **Unselected nodes:** low-detail silhouettes; one chassis plus a small kind cue.
- **Hovered node:** temporarily raises contrast/scale; show name in accessible HTML overlay.
- **Selected node:** rich generic device model, including a port/drive face only where it is
  semantically useful.
- **Neighbour nodes:** medium detail only when inside focus mode.
- **Beyond the existing 400-node legibility cap:** stay omitted with the current explicit warning;
  do not bypass the cap because Three.js can render more.

Use shared `BufferGeometry` and shared materials for each generic model kind. Use
`InstancedMesh` only after profiling proves individual meshes are a bottleneck; it complicates
picking and is not automatically an improvement at the current node budget.

### 5.3 Operational encodings

Every visual channel gets one stable meaning:

| Channel | Meaning |
|---|---|
| model silhouette | resource/device kind |
| height | measured hop distance from component root |
| status band / chassis edge | resource status, using existing semantic tokens |
| model scale | selection/hover only; never “importance” unless an explicit metric exists |
| link style | evidence source: LLDP/CDP solid, ARP dashed |
| link width | future measured utilization, only after an API supplies it |
| link colour | neutral by default; future semantic alert/impact status only |
| detail panel | words, units, source, timestamp, and uncertainty |

State must never be communicated only by colour. The HTML detail panel always says `up`, `down`,
`degraded`, `maintenance`, or `unknown`. This continues the project’s existing accessibility
rule and aligns with WCAG 2.2 focus and target requirements.  
Source: [W3C WCAG 2.2](https://www.w3.org/TR/wcag/)

### 5.4 Device ports

Ports are visually impressive but are also easy to lie with. Implement in three stages:

1. **Stage A — decorative-free generic front face:** selected generic switch/router models show
   neutral port slots only. They are not clickable and do not claim a physical interface mapping.
2. **Stage B — confirmed interface overlay:** only when an API returns an interface-to-link mapping
   for the selected resource. Highlight connected ports and list the source interface name. A port
   without mapping stays neutral.
3. **Stage C — traffic/QoS overlay:** only when M7 flow / later QoS data is linked to that exact
   interface. Show utilization and QoS state in the side panel first; visual port emphasis is
   secondary and must carry a textual equivalent.

Do not make physical port positions a manual configuration field in v1. The first objective is
operational understanding, not a hardware documentation product.

## 6. Architecture and file plan

The existing implementation already uses `three` directly, has no React WebGL binding, and lazy
loads `scene3d.tsx`. Preserve that decision.

### 6.1 Refactor target

Split the current `web/src/scene3d.tsx` by responsibility without changing its public behavior
in the first commit:

```text
web/src/
  scene3d.tsx                 scene lifecycle, camera, selection bridge
  scene3d-models.ts           pure model resolver + shared procedural geometries
  scene3d-materials.ts        CSS-token → Three.js material construction
  scene3d-interaction.ts      camera presets, pointer/keyboard interactions, picking
  scene3d-overlay.tsx         accessible HTML inspector/readout overlay
  scene3d.test.ts             pure model/scene-state tests
```

Do not introduce `@react-three/fiber`, a graph library, a model viewer, a CDN, or a GLTF loader
for the generic-model release. The current code explains why: Three.js solves the WebGL problem;
the bindings do not solve a material problem here and may introduce React compatibility risk.

### 6.2 Extend topology state deliberately

Replace the opaque `solid: boolean` with a named mode:

```ts
type TopologyView = "2d" | "3d";
type ThreeDimensionalMode = "estate" | "focus" | "impact";
```

The 3D component receives a single immutable `SceneInput` object rather than accumulating props:

```ts
interface SceneInput {
  nodes: Placed[];
  edges: GraphEdge[];
  depths: ReadonlyMap<string, number>;
  selectedId: string | null;
  mode: "estate" | "focus" | "impact";
  impact?: {
    candidateId: string | null;
    resourceIds: ReadonlySet<string>;
    explanation: string;
  };
}
```

The scene must not fetch its own data. `TopologyPage` remains responsible for tenant-scoped query
data; this keeps the WebGL layer a rendering layer rather than a second application architecture.

### 6.3 Backend/API additions — staged and evidence-first

**No API change is required for Phase 1 generic models.** `id`, `name`, `kind`, `status`, and
topology edge evidence already exist.

For later port/flow/incident enhancements, add narrowly scoped endpoints or enrich the existing
topology response only after defining the source of each field:

```text
Selected resource visual context
  resource identity: kind, high-confidence make/model only when available
  interfaces: id, name, admin/oper state, exact link mapping when confirmed
  link evidence: source (LLDP/CDP/ARP), observed time
  flow/QoS: interface aggregate, window, sampling marker, unit
  incident: linked resources, candidate, explanation, state
```

Every new response must stay tenant-scoped through the existing `TenantScope` pattern and gain an
adversarial cross-tenant test.

## 7. Interaction design

### Camera

- Keep drag-to-orbit and scroll/pinch-to-zoom.
- Add explicit camera controls: `Reset view`, `Top`, `Front`, `Side`, and `Focus selection`.
- Keep the camera bounded; never permit zooming through devices or losing the scene indefinitely.
- No autorotation and no continuous render loop.
- Switching 2D ↔ 3D preserves selection and uses the same x/z positions.

### Selection and inspect panel

- Click/tap selects. Click again or `Escape` clears.
- Selection does not navigate away.
- The inspector has one primary action: `Open resource`.
- When an incident is relevant, include `Open incident`; do not duplicate the incident timeline in
  the topology scene.
- Include a link-evidence list: neighbour, source protocol, and last observed time where available.

### Keyboard and alternative path

The WebGL canvas cannot be the only way to inspect a topology.

- Keep the existing 2D SVG path, which has keyboard-selectable nodes.
- Provide a keyboard-focusable “selected device” control and directional neighbour list in the
  HTML inspector.
- Every camera preset and scene-mode switch is a semantic button with text.
- A user who cannot drag must be able to select, inspect, navigate, and return to 2D without
  dragging. This is required by WCAG 2.2’s dragging-movement guidance.
- Respect `prefers-reduced-motion`; there is no ambient motion either way, but transitions must
  collapse to immediate changes.

## 8. Delivery phases

### Phase 0 — specification and baseline (small, first)

1. Update `docs/UI-SPEC.md` into a Part 2 or cross-link this document.
2. Record a visual baseline of the current 2D and 3D topology for a small, medium, and maximum
   budget graph.
3. Add a fixture estate with mixed resource kinds, an ARP-only link, an unhealthy node, and a
   disconnected component.
4. Establish performance measurement: initial 3D load, frame time while interacting, memory after
   entering/leaving the scene repeatedly.

**Exit criterion:** current scene behavior is covered before refactoring.

### Phase 1 — generic operational models

1. Extract pure model resolver and shared geometry/material creation.
2. Replace all-node spheres with low-detail generic silhouettes.
3. Render a rich generic model for the selected device only.
4. Preserve current graph layers, colours, ARP dashes, selection dimming, lazy import, and cleanup.
5. Add camera preset controls and accessible HTML scene readout.
6. Verify no branded or downloaded assets enter the build.

**Exit criterion:** a user can distinguish a switch, router, firewall, server, AP, service, and
unknown node at a glance; selected-device detail is useful without claiming unavailable facts.

### Phase 2 — focus mode and operational links

1. Add named `estate` and `focus` modes.
2. Build selected-device inspector with known facts and evidence labels.
3. Add one-hop focus camera framing and explicit reset controls.
4. Add an edge legend and ensure uncertain links are visually/textually distinct.
5. Add links from the inspector to resources, logs/explore, flow, and incidents only where those
   routes and scoped data already exist.

**Exit criterion:** an operator can choose a down device, see its neighbours and evidence, then
reach the relevant investigation route in two interactions or fewer.

### Phase 3 — data-backed interface and flow overlays

Do this only after a design partner confirms need and the backend contract exists.

1. Add confirmed interface/link mapping to the selected-device context.
2. Highlight only mapped ports; retain neutral slots for unmapped/unavailable ports.
3. Add flow/interface summaries, including sampled-data markers.
4. Add QoS overlays only as part of an explicitly approved QoS milestone; no implied QoS control.

**Exit criterion:** no highlighted port or edge claims a relationship that the backend cannot
attribute to a named interface/evidence source.

### Phase 4 — incident impact mode

1. Consume M9 incident candidate and linked-resource data.
2. Add `Explore impact` entry from incident detail.
3. Center/focus the candidate and layer incident resources by hop count.
4. State clearly why the candidate exists and what it is not: a causal proof.

**Exit criterion:** an incident with a candidate produces a comprehensible scene; one without a
candidate never receives an invented origin.

### Phase 5 — optional physical/rack scene

Only pursue this after customers supply reliable site/rack metadata and request it.

- Add physical containers and placement only from explicit backend records.
- Use generic racks and generic chassis initially.
- Treat physical location as a separate selected view, not as a reinterpretation of inferred
  topology coordinates.

## 9. Performance, security, and quality gates

### Performance

- Keep `three` behind `React.lazy`; no 3D bytes on 2D-only navigation.
- Preserve the 400-node legibility budget and current omitted-node disclosure.
- Cap pixel ratio at 2, as current code does.
- Reuse geometry/materials and dispose every geometry, material, texture, renderer, observer, and
  DOM canvas on unmount.
- Render on demand; a camera/pointer/selection change marks the scene dirty, otherwise no redraw.
- Measure Phase 1 against 50, 200, and 400-node fixtures. Do not publish a performance number
  from a four-node demo as if it described a customer estate.

### Security and privacy

- No remote assets or telemetry; this must run in an air-gapped deployment.
- Do not send device make/model, topology, or screen events to an analytics provider.
- Reuse tenant-scoped API paths; add adversarial isolation tests to every new API surface.
- Do not render credentials, management addresses, or sensitive fields merely because a resource
  detail record has them. The scene gets an allowlisted visual context, not the whole resource object.

### Accessibility

- 2D and inspector remain fully usable without WebGL/drag gestures.
- Semantic buttons, visible focus, text labels, and at least 24×24 CSS pixel targets.
- No state by hue alone; legends and inspector text match the scene's semantic colours.
- Test keyboard selection/clear/focus and reduced-motion behavior.

## 10. Tests and acceptance criteria

### Unit tests

- `modelFor()` maps only known kinds and falls back safely to `unknown`.
- Same scene input yields the same model mapping and scene mode.
- ARP edges remain dashed in both 2D and 3D representations.
- Focus mode dims but does not remove unrelated context.
- Impact mode refuses to render a candidate treatment when no candidate is supplied.
- Camera bounds cannot pass the minimum/maximum distance.

### Integration/UI tests

- 3D chunk is not requested when a user stays in 2D.
- Selecting a topology node preserves selection while switching 2D ↔ 3D.
- Clear selection and keyboard alternatives work without a drag action.
- An omitted-component warning remains visible at the node budget.
- Tenant A cannot request selected-device visual context for tenant B.
- The detailed device view cannot render raw credential material or an unallowlisted sensitive field.

### Manual visual QA

Review with three fixture estates:

1. **Small campus:** core router, distribution switches, APs, servers; mixed health.
2. **Mixed estate:** routers, firewall, servers, cloud-service nodes, ARP-only link.
3. **Large graph:** 400 visible nodes plus omitted components.

Check at desktop, NOC distance mode once it exists, laptop, and reduced-motion/keyboard-only paths.

### Definition of done for the first shippable release

- Generic models are helpful at a glance and do not make unsupported vendor/physical claims.
- 3D is optional, lazy, deterministic, and does not degrade 2D use.
- Selected-device exploration has a clear operational purpose and direct next actions.
- Evidence/sampling/status semantics match the rest of Veyronis.
- Tests cover the pure decisions and the browser path; visual QA covers representative estates.
- Documentation explains what 3D height, model shape, edge style, and device ports do—and do not—mean.

## 11. Suggested commit sequence

1. `UI 3D device explorer: fixtures and scene baseline`
2. `UI 3D device explorer: generic model resolver and shared geometry`
3. `UI 3D device explorer: selected-device detail and camera controls`
4. `UI 3D device explorer: focus mode and accessible inspector`
5. `UI 3D device explorer: document semantics and verify performance`

Keep Phase 3+ separate. They require backend contracts and design-partner evidence; they should not
be smuggled into visual polish.

## 12. Claude’s implementation instruction

Implement only Phases 0–2 unless the founder explicitly authorizes a later phase. Preserve the
existing evidence model and topology semantics. Do not add vendor-branded assets, remote downloads,
photorealism, traffic animation, automatic root-cause claims, or QoS-control behavior. Before each
phase, inspect the relevant current code and update this specification if the repository has moved.
