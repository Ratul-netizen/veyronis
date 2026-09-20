/**
 * The bar under the header naming what the application is currently about — UI-SPEC §13.
 *
 * It is on every screen, which is the whole point: a context you cannot see is a filter
 * you will forget you set, and §13.3 says the product must never hide a device behind one.
 * So the bar states the context in words, says whether this screen is honouring it, and
 * always offers the way out.
 *
 * # Why the picker is three lists rather than a tree
 *
 * §13.1's narrowing — all → site → group → resource — is an order of *breadth*, not a
 * hierarchy: a group crosses sites on purpose, and a resource may be in several groups. A
 * tree would have to pick one parent per leaf and would be lying by the second level.
 * Three labelled lists say the same thing and are searchable with one field.
 */

import { useQuery } from "@tanstack/react-query";
import { useRouterState } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";

import { api, type Group, type Resource, type Site } from "./api";
import { EVERYTHING, unscopedBecause, type Context } from "./context";
import { useShell } from "./shell";

/** How many of each kind the picker lists before it asks for a narrower search. */
const SHOWN = 8;

/** One selectable thing, flattened out of the three lists. */
interface Choice {
  context: Context;
  /** "Site", "Group" or "Resource" — the word the row is filed under. */
  kind: string;
  label: string;
  /** The fact beside the name: a count, a status, whatever the thing knows about itself. */
  detail?: string;
}

const SECTIONS = ["Site", "Group", "Resource"];

/**
 * The name of the current context, for the bar's own label.
 *
 * Falls back to the id when the name is not known — before the lists have been fetched,
 * or when the context names something that has since been deleted. An id is ugly and it
 * is *true*; showing "All resources" instead would tell the operator the view is unscoped
 * when it is not, which is the one thing §13.3 forbids.
 */
function describe(context: Context, choices: Choice[]): string {
  if (context.kind === "all") return "All resources";

  const found = choices.find(
    (c) => c.context.kind === context.kind && "id" in c.context && c.context.id === context.id,
  );
  const word = context.kind[0]?.toUpperCase() + context.kind.slice(1);
  return `${word} — ${found ? found.label : context.id}`;
}

export function ContextBar() {
  const { tenant, context, setContext } = useShell();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const search = useRef<HTMLInputElement>(null);
  const opener = useRef<HTMLButtonElement>(null);

  // Sites and groups are fetched on every page, not only when the picker opens, because
  // the bar's own label needs them: a context narrowed to a site must read "Site — Dhaka
  // DC" rather than "Site — 0193…" on every screen an operator visits. Two small,
  // long-cached lists are the price of the bar telling the truth in words.
  const sites = useQuery({
    queryKey: ["context-sites", tenant.tenant_id],
    queryFn: () => api.sites(tenant.tenant_id),
    retry: false,
    staleTime: 60_000,
  });

  const groups = useQuery({
    queryKey: ["context-groups", tenant.tenant_id],
    queryFn: () => api.groups(tenant.tenant_id),
    retry: false,
    staleTime: 60_000,
  });

  // The inventory is not: it is the long list, and it is only needed to *choose* from.
  // Shares the palette's cache, so opening one after the other costs nothing.
  const resources = useQuery({
    queryKey: ["palette-resources", tenant.tenant_id],
    queryFn: () => api.resources(tenant.tenant_id),
    enabled: open,
    retry: false,
    staleTime: 60_000,
  });

  // Which is why a resource context asks for its one resource by id. One small request,
  // only when the context is a resource and only until it is cached — rather than making
  // every page load the whole estate to render a single name.
  const named = useQuery({
    queryKey: ["context-resource", tenant.tenant_id, context.kind === "resource" ? context.id : ""],
    queryFn: () => api.resource(tenant.tenant_id, (context as { id: string }).id),
    enabled: context.kind === "resource",
    retry: false,
    staleTime: 60_000,
  });

  const choices = useMemo<Choice[]>(() => {
    const out: Choice[] = [];

    for (const s of sites.data ?? ([] as Site[])) {
      const n = s.resources.total;
      out.push({
        context: { kind: "site", id: s.id },
        kind: "Site",
        label: s.name,
        detail: `${n} resource${n === 1 ? "" : "s"}`,
      });
    }

    for (const g of groups.data ?? ([] as Group[])) {
      out.push({
        context: { kind: "group", id: g.id },
        kind: "Group",
        label: g.name,
        detail: `${g.members} member${g.members === 1 ? "" : "s"}`,
      });
    }

    for (const r of resources.data?.items ?? ([] as Resource[])) {
      out.push({
        context: { kind: "resource", id: r.id },
        kind: "Resource",
        label: r.display_name ?? r.name,
        detail: r.status,
      });
    }

    if (named.data) {
      out.push({
        context: { kind: "resource", id: named.data.id },
        kind: "Resource",
        label: named.data.display_name ?? named.data.name,
        detail: named.data.status,
      });
    }

    return out;
  }, [sites.data, groups.data, resources.data, named.data]);

  const matched = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const hit = needle ? choices.filter((c) => c.label.toLowerCase().includes(needle)) : choices;

    // Capped per kind rather than overall, so a tenant with four hundred devices does not
    // push its six sites off the bottom of the list.
    return SECTIONS.map((kind) => {
      // Deduplicated by id: the resource the context already names is fetched on its own
      // and would otherwise appear twice once the full list arrives.
      const seen = new Set<string>();
      const all = hit.filter((c) => {
        if (c.kind !== kind) return false;
        const id = formatKey(c);
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
      });
      return { kind, rows: all.slice(0, SHOWN), more: all.length - Math.min(all.length, SHOWN) };
    });
  }, [choices, text]);

  // Focus moves into the picker when it opens and back to the trigger when it closes —
  // but only if it was open, which `was` is what remembers. Without that the effect fires
  // on mount and the bar takes focus away from the page on every single navigation: the
  // caret lands on a control nobody asked for, and a screen reader announces the context
  // instead of the screen.
  const was = useRef(false);
  useEffect(() => {
    if (open) search.current?.focus();
    else if (was.current) opener.current?.focus();
    was.current = open;
  }, [open]);

  const unscoped = unscopedBecause(pathname);

  function choose(next: Context) {
    setContext(next);
    setOpen(false);
    setText("");
  }

  return (
    <div className={`contextbar${context.kind === "all" ? "" : " narrowed"}`}>
      <span className="contextbar-label">Context</span>

      <button
        type="button"
        ref={opener}
        className="contextbar-pick"
        aria-expanded={open}
        aria-haspopup="dialog"
        onClick={() => setOpen((was) => !was)}
      >
        {describe(context, choices)}
      </button>

      {/* Offered whenever there is something to leave, and not otherwise: a control that
          is permanently present and does nothing four times out of five teaches people to
          stop seeing it. */}
      {context.kind !== "all" && (
        <button type="button" className="quiet" onClick={() => choose(EVERYTHING)}>
          Show everything
        </button>
      )}

      <span className="spacer" />

      {/* §13.3's other half. A narrowed context on a screen that ignores it looks exactly
          like a screen with nothing wrong on it. */}
      {context.kind !== "all" && unscoped && (
        <span className="contextbar-note">Not applied here — {unscoped}.</span>
      )}

      {open && (
        <div
          className="contextpicker"
          role="dialog"
          aria-label="Choose a context"
          onKeyDown={(e) => {
            if (e.key === "Escape") setOpen(false);
          }}
        >
          <input
            ref={search}
            value={text}
            aria-label="Find a site, group or resource"
            placeholder="Find a site, group or resource"
            onChange={(e) => setText(e.target.value)}
          />

          <button type="button" className="contextrow" onClick={() => choose(EVERYTHING)}>
            <span className="contextrow-label">All resources</span>
            <span className="contextrow-detail">Everything in {tenant.name}</span>
          </button>

          {matched.map((section) => (
            <div key={section.kind} className="contextsection">
              <h3>{section.kind}</h3>

              {section.rows.length === 0 && <p className="dim">Nothing matching.</p>}

              {section.rows.map((row) => (
                <button
                  key={formatKey(row)}
                  type="button"
                  className="contextrow"
                  onClick={() => choose(row.context)}
                >
                  <span className="contextrow-label">{row.label}</span>
                  {row.detail && <span className="contextrow-detail">{row.detail}</span>}
                </button>
              ))}

              {section.more > 0 && (
                <p className="dim">{section.more} more — narrow the search.</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Kind and id. Names are not unique across a tenant; ids are. */
function formatKey(choice: Choice): string {
  return "id" in choice.context ? `${choice.context.kind}:${choice.context.id}` : "all";
}
