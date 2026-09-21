/**
 * What the whole application is currently about — UI-SPEC §13.
 *
 * A context narrows every screen at once: the overview's counts, the resource list, the
 * topology's scope. It is one value, it lives in the URL beside the time range, and this
 * file is the only place that knows how it is written down.
 *
 * # Why it is one string rather than three parameters
 *
 * `ctx=site:0193…` is one thing that can only be one thing. Three optional parameters —
 * `site`, `group`, `resource` — would let a pasted link carry two at once, and then every
 * screen would have to decide what a site *and* a group means. §13.1's narrowing is a
 * chain, not a set.
 *
 * # Why the tenant is not in here
 *
 * §13.1: switching tenant is switching customers, and narrowing a view is not. They look
 * similar in a picker and are not the same act, so they are two controls.
 */

/** The four things a context can be, in §13.1's order of narrowing. */
export type Context =
  | { kind: "all" }
  | { kind: "site"; id: string }
  | { kind: "group"; id: string }
  | { kind: "resource"; id: string };

/** No context. The default, and what "All resources" means. */
export const EVERYTHING: Context = { kind: "all" };

const KINDS = ["site", "group", "resource"] as const;

/**
 * Read a context out of the URL.
 *
 * Anything unreadable is `all` rather than an error, for the reason `validateShellSearch`
 * gives: a URL is something people edit and paste, and a page that refuses to render
 * because one parameter is misspelled is worse than one that renders unscoped — provided
 * it *says* it is unscoped, which the bar does.
 */
export function parseContext(value: string | undefined | null): Context {
  if (!value) return EVERYTHING;
  const at = value.indexOf(":");
  if (at < 0) return EVERYTHING;

  const kind = value.slice(0, at);
  const id = value.slice(at + 1);
  if (!id) return EVERYTHING;

  const known = KINDS.find((k) => k === kind);
  return known ? { kind: known, id } : EVERYTHING;
}

/** Write one back. `undefined` for `all`, so the default leaves the URL clean. */
export function formatContext(context: Context): string | undefined {
  return context.kind === "all" ? undefined : `${context.kind}:${context.id}`;
}

/**
 * The resource-list query parameters a context means.
 *
 * One place, because the overview and the resource list both read that endpoint and a
 * context that narrowed one and not the other would be worse than no context at all —
 * the counts would disagree with the list below them.
 *
 * A type alias rather than an interface, deliberately: TypeScript gives an alias an
 * implicit index signature and an interface none, and `api.resources` takes a bag of
 * optional query parameters. The alternative is a cast at every call site.
 */
export type ContextParams = {
  site?: string;
  group?: string;
  only?: string;
};

export function contextParams(context: Context): ContextParams {
  switch (context.kind) {
    case "site":
      return { site: context.id };
    case "group":
      return { group: context.id };
    case "resource":
      return { only: context.id };
    case "all":
      return {};
  }
}

/**
 * Whether a context reaches a given screen, and what to say when it does not.
 *
 * §13.3 is the rule this exists for. A context must not silently hide things, and the
 * other half of that promise is that a context which is *not* being applied must not
 * silently look as if it were: an operator narrowed to one site, reading the discovery
 * run list, needs to know those runs are the whole tenant's.
 *
 * Keyed by path prefix and deliberately explicit — a screen added tomorrow is unscoped
 * and says so, rather than inheriting a promise nobody checked.
 */
const UNSCOPED: { prefix: string; because: string }[] = [
  {
    prefix: "/discovery",
    because: "discovery jobs and their runs are configured per tenant, not per site",
  },
  // The two that are not yet wired rather than deliberately estate-wide. They are here,
  // saying so, because the alternative is a narrowed bar over a full-tenant screen —
  // which is the lie §13.3 exists to prevent, and it does not become less of a lie
  // because the reason for it is that we have not finished.
  { prefix: "/topology", because: "the topology view is still the whole tenant's graph" },
  { prefix: "/flow", because: "flow is grouped by exporter, and narrowing it is not wired yet" },
  // Not "not wired yet": a service runs on many hosts and `service_5m` has no
  // `resource_id` at all, so narrowing by resource would move the query onto raw spans
  // and answer a different question — M8 §2.1.
  { prefix: "/services", because: "a service runs on many hosts, so this is the tenant's" },
  { prefix: "/alerts", because: "the alert list is not yet narrowed by resource" },
  { prefix: "/alerts/rules", because: "a rule's own selector decides what it watches" },
  { prefix: "/alerts/channels", because: "channels belong to the tenant" },
  { prefix: "/dashboards", because: "a dashboard's panels carry their own selectors" },
  { prefix: "/explore", because: "the Explorer's own filter is the one that runs" },
  { prefix: "/map", because: "the map is how you find a site, so it shows all of them" },
];

/**
 * `null` when the context applies here; otherwise the reason it does not.
 *
 * Longest prefix wins, so `/alerts/rules` gives its own reason rather than `/alerts`’s.
 */
export function unscopedBecause(pathname: string): string | null {
  const match = UNSCOPED.filter((u) => pathname.startsWith(u.prefix)).sort(
    (a, b) => b.prefix.length - a.prefix.length,
  )[0];
  return match ? match.because : null;
}
