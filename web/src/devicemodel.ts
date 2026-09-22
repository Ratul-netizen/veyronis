/**
 * Which shape a resource is drawn as — `docs/UI-3D-DEVICE-EXPLORER.md` §5.1.
 *
 * # Why this file imports nothing
 *
 * It is the decision, and the decision is the part worth arguing about. The geometry that
 * realises it lives in `scene3d-models.ts`, behind the same lazy import as `three` — so
 * this can be read, tested and reused by the 2D view without pulling half a megabyte of
 * WebGL in with it.
 *
 * # The plan asked for shapes this product cannot honestly draw
 *
 * §5.1's catalogue lists `switch`, `router`, `firewall`, `access-point` and `storage`.
 * None of those is a thing the backend knows. `resource_kind` — migration 0002, unchanged
 * since — is:
 *
 * ```text
 *   device  interface  host  vm  container  service  application  database
 *   cloud_resource  site
 * ```
 *
 * Every switch, router, firewall, load balancer and access point in an estate is a
 * `device`. Nothing distinguishes them: `sysServices`, which is the standard SNMP signal
 * for "this box does layer 2" versus "this box does layer 3", is asked for by the
 * discovery probe and is not stored, and `uops_store_pg::TopologyNode` carries only
 * `id`, `name`, `display_name`, `kind` and `status`.
 *
 * So a `modelFor` that returned `"switch"` would be inventing the one thing §5.1 says
 * must never be invented — *"a resource with unknown or ambiguous kind uses `unknown`,
 * never a confidently wrong model"* — and it would do it for the majority of nodes in
 * every estate this product has seen.
 *
 * What is drawn instead is the split the data actually supports. Six silhouettes, each
 * backed by a column:
 *
 * | shape | from | what it says |
 * |---|---|---|
 * | `appliance` | `device` | a networking box. **Not** which kind of one. |
 * | `server` | `host`, `vm` | something that runs workloads |
 * | `container` | `container` | a workload inside one |
 * | `datastore` | `database` | a database |
 * | `service` | `service`, `application`, `cloud_resource` | a logical thing |
 * | `unknown` | everything else | nothing is claimed |
 *
 * The vendor/model layer §5.1 defers is deferred for the same reason and one further one:
 * it needs identity to hold a high-confidence make and model, which M5 can produce and
 * the topology response does not carry.
 *
 * **When a device sub-kind arrives, this is the one file that changes.**
 */

import type { GraphNode } from "./graph";

/**
 * The shapes the scene can draw.
 *
 * A closed set, and small on purpose. Every value here has to be distinguishable from
 * every other at a glance and across a NOC room, which is a harder constraint than
 * inventing a name for it.
 */
export type DeviceModelKind =
  | "appliance"
  | "server"
  | "container"
  | "datastore"
  | "service"
  | "unknown";

/**
 * The shape for a resource.
 *
 * Total, and deliberately not clever: it maps the `kind` column and nothing else. An
 * unrecognised kind — which is what a backend that grew a value this build has not heard
 * of looks like — is `unknown` rather than a guess.
 */
export function modelFor(node: Pick<GraphNode, "kind">): DeviceModelKind {
  switch (node.kind) {
    case "device":
      return "appliance";
    case "host":
    case "vm":
      return "server";
    case "container":
      return "container";
    case "database":
      return "datastore";
    case "service":
    case "application":
    case "cloud_resource":
      return "service";
    // `interface` and `site` are real kinds that do not appear in a topology: the graph is
    // devices and the links between them. Listed rather than left to the default so that
    // their absence here is a decision somebody made, not an oversight.
    case "interface":
    case "site":
    default:
      return "unknown";
  }
}

/**
 * What the shape means, for the inspector and the legend.
 *
 * Every scene encoding has a text equivalent — §5.3, and the project's standing rule that
 * state is never carried by a visual channel alone. These sentences are also where the
 * product says what it does *not* know, which is the reason `appliance` reads the way it
 * does.
 */
export function describeModel(kind: DeviceModelKind): string {
  switch (kind) {
    case "appliance":
      return "A network device. This product does not know whether it is a switch, a router or a firewall — nothing it collects says so.";
    case "server":
      return "A host or virtual machine.";
    case "container":
      return "A container running on a host.";
    case "datastore":
      return "A database.";
    case "service":
      return "A service, application or cloud resource — something logical rather than a box.";
    case "unknown":
      return "An unclassified resource. No shape is claimed for it.";
  }
}

/**
 * A short label, for a legend row.
 */
export function labelForModel(kind: DeviceModelKind): string {
  switch (kind) {
    case "appliance":
      return "network device";
    case "server":
      return "host or VM";
    case "container":
      return "container";
    case "datastore":
      return "database";
    case "service":
      return "service";
    case "unknown":
      return "unclassified";
  }
}

/** Every shape, in the order a legend lists them. */
export const MODEL_KINDS: readonly DeviceModelKind[] = [
  "appliance",
  "server",
  "container",
  "datastore",
  "service",
  "unknown",
];
