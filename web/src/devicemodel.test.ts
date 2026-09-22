/**
 * What the scene is allowed to claim about a resource — `docs/UI-3D-DEVICE-EXPLORER.md` §10.
 *
 * The plan's first unit test is *"`modelFor()` maps only known kinds and falls back safely
 * to `unknown`"*, and the interesting half is the fallback: a drawing that confidently
 * shows a firewall where the backend said `device` is worse than a neutral block, because
 * an operator believes it.
 */

import { describe, expect, it } from "vitest";

import {
  MODEL_KINDS,
  describeModel,
  labelForModel,
  modelFor,
  type DeviceModelKind,
} from "./devicemodel";

/** Every value of `resource_kind`, from migration 0002. */
const BACKEND_KINDS = [
  "device",
  "interface",
  "host",
  "vm",
  "container",
  "service",
  "application",
  "database",
  "cloud_resource",
  "site",
];

describe("modelFor", () => {
  it("has an answer for every kind the backend can produce", () => {
    // A kind this build has not heard of is what a newer backend looks like, and it must
    // produce a shape rather than `undefined` reaching Three.js.
    for (const kind of BACKEND_KINDS) {
      const model = modelFor({ kind });
      expect(MODEL_KINDS).toContain(model);
    }
  });

  it("maps the kinds the data actually distinguishes", () => {
    expect(modelFor({ kind: "device" })).toBe("appliance");
    expect(modelFor({ kind: "host" })).toBe("server");
    expect(modelFor({ kind: "vm" })).toBe("server");
    expect(modelFor({ kind: "container" })).toBe("container");
    expect(modelFor({ kind: "database" })).toBe("datastore");
    expect(modelFor({ kind: "service" })).toBe("service");
    expect(modelFor({ kind: "application" })).toBe("service");
    expect(modelFor({ kind: "cloud_resource" })).toBe("service");
  });

  it("falls back to unknown rather than guessing", () => {
    // The ones that carry no shape, and the one that matters: a value from a backend this
    // build predates.
    expect(modelFor({ kind: "interface" })).toBe("unknown");
    expect(modelFor({ kind: "site" })).toBe("unknown");
    expect(modelFor({ kind: "quantum_toaster" })).toBe("unknown");
    expect(modelFor({ kind: "" })).toBe("unknown");
  });

  it("never claims a switch, a router or a firewall", () => {
    // The whole reason this file amends §5.1's catalogue. Nothing the backend stores
    // distinguishes them — every one of them is `kind = 'device'` — so no input can
    // produce a shape that says which, and this test is what keeps that true when
    // somebody later adds a mapping that "looks obvious" from a name.
    for (const kind of [...BACKEND_KINDS, "switch", "router", "firewall", "access_point"]) {
      const model: DeviceModelKind = modelFor({ kind });
      expect(["switch", "router", "firewall", "access-point"]).not.toContain(model);
    }
  });

  it("is a function of the kind alone", () => {
    // Same input, same shape — §10: "Same scene input yields the same model mapping". A
    // resolver that consulted a name would draw two identical devices differently because
    // one of them is called `fw-01`.
    const a = modelFor({ kind: "device" });
    const b = modelFor({ kind: "device" });
    expect(a).toBe(b);
  });
});

describe("the text beside the shape", () => {
  it("describes and labels every shape", () => {
    // §5.3: no state by shape alone. A silhouette with no sentence beside it is a picture
    // an operator has to learn by folklore.
    for (const kind of MODEL_KINDS) {
      expect(describeModel(kind).length).toBeGreaterThan(0);
      expect(labelForModel(kind).length).toBeGreaterThan(0);
    }
  });

  it("says out loud that a network device's role is not known", () => {
    // The sentence that stops the shape being read as a claim. If it goes, the shape
    // starts meaning whatever the reader assumes.
    const said = describeModel("appliance");
    expect(said).toMatch(/switch/i);
    expect(said).toMatch(/does not know/i);
  });

  it("does not label an unclassified resource as anything", () => {
    expect(labelForModel("unknown")).toBe("unclassified");
    expect(describeModel("unknown")).toMatch(/no shape is claimed/i);
  });
});
