/**
 * The command palette — UI-SPEC §12. `Ctrl`/`Cmd` + `K`.
 *
 * The fastest path to any resource or screen, and the reason the navigation does not have
 * to grow a search box of its own.
 *
 * # What it is not
 *
 * **Not a query language.** `packet loss > 5%` belongs in the Explorer, which has a
 * compiler, a `Query` AST and an opinion about what is answerable. A palette that accepted
 * half a query language would be a second query language that cannot be saved, alerted on
 * or shared — and this product already refuses to have two of those.
 *
 * So the palette navigates. When what somebody typed looks like a question rather than a
 * destination, it offers to open the Explorer with it rather than pretending to answer.
 *
 * # Why the resources are already in memory
 *
 * It reuses the same `["resources", tenant]` query the rest of the app holds, so opening
 * the palette costs no request and shows the inventory as of whenever the app last read
 * it. An estate too large for that is an estate that needs server-side search, which is a
 * different feature with a different cost — and the honest signal that it is needed is
 * this list being truncated, which it says out loud.
 */

import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";

import { api, type Resource } from "./api";
import { useShell } from "./shell";

/** How many resources the palette will rank before it says it stopped. */
const LIMIT = 8;

type Entry = {
  key: string;
  label: string;
  hint: string;
  go: () => void;
};

/**
 * Screens, and the words somebody would actually type to reach them.
 *
 * "logs" finds Explore because that is where logs are, whatever the screen is called. A
 * palette that only matched the label is a palette that requires you to already know the
 * product's vocabulary — which is the opposite of what it is for.
 */
const SCREENS: { label: string; to: string; words: string[] }[] = [
  { label: "Overview", to: "/", words: ["home", "operations", "start"] },
  { label: "Resources", to: "/resources", words: ["devices", "inventory", "hosts"] },
  { label: "Discovery", to: "/discovery", words: ["scan", "sweep", "find", "snmp"] },
  { label: "Candidates", to: "/discovery/candidates", words: ["unidentified", "found"] },
  { label: "Map", to: "/map", words: ["sites", "geography", "locations"] },
  { label: "Explore", to: "/explore", words: ["logs", "search", "metrics", "query"] },
  { label: "Alerts", to: "/alerts", words: ["firing", "pending", "incidents"] },
  { label: "Rules", to: "/alerts/rules", words: ["thresholds", "conditions"] },
  { label: "Channels", to: "/alerts/channels", words: ["notify", "email", "webhook"] },
  { label: "Dashboards", to: "/dashboards", words: ["panels", "boards"] },
];

/** Whether what was typed looks like a question rather than a destination. */
function looksLikeAQuery(text: string): boolean {
  // An operator or a comparison is the giveaway. Anything else is a name.
  return /[<>=]|\b(above|below|over|under|more than|less than)\b/i.test(text);
}

export function CommandPalette() {
  const { tenant } = useShell();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [cursor, setCursor] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  // Where focus was before the palette took it, so Esc can give it back.
  const opener = useRef<Element | null>(null);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        opener.current = document.activeElement;
        setOpen((was) => !was);
        setText("");
        setCursor(0);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) input.current?.focus();
    else if (opener.current instanceof HTMLElement) opener.current.focus();
  }, [open]);

  // Deliberately unscoped, and deliberately its own cache entry.
  //
  // Unscoped because the palette is how you *find* something, and a finder that only
  // searches what you have already narrowed to cannot get you out of a context you
  // forgot you set — exactly the failure UI-SPEC §13.3 names.
  //
  // Its own key because the resource list is an infinite query under `["resources", …]`
  // and this is not; one key holding two differently shaped caches means whichever
  // fetched last decides what the other reads.
  const resources = useQuery({
    queryKey: ["palette-resources", tenant.tenant_id],
    queryFn: () => api.resources(tenant.tenant_id),
    enabled: open,
    retry: false,
    staleTime: 60_000,
  });

  const entries = useMemo<Entry[]>(() => {
    const needle = text.trim().toLowerCase();
    const out: Entry[] = [];

    // 1. Resources by name — the commonest thing anybody wants, and the one that gets
    //    harder to reach as the estate grows, which is backwards for a console.
    const items: Resource[] = resources.data?.items ?? [];
    const matched = needle
      ? items.filter((r) => (r.display_name ?? r.name).toLowerCase().includes(needle))
      : [];
    for (const r of matched.slice(0, LIMIT)) {
      out.push({
        key: `r:${r.id}`,
        label: r.display_name ?? r.name,
        hint: r.kind,
        go: () => navigate({ to: "/resources/$id", params: { id: r.id } }),
      });
    }
    if (matched.length > LIMIT) {
      out.push({
        key: "r:more",
        label: `${matched.length - LIMIT} more resources match`,
        hint: "open Resources",
        go: () => navigate({ to: "/resources" }),
      });
    }

    // 2. Screens, by label and by the words somebody would use for them.
    for (const s of SCREENS) {
      const hit =
        !needle ||
        s.label.toLowerCase().includes(needle) ||
        s.words.some((w) => w.includes(needle));
      if (hit) {
        out.push({
          key: `s:${s.to}`,
          label: s.label,
          hint: "screen",
          go: () => navigate({ to: s.to }),
        });
      }
    }

    // 3. A question is not a destination. Offer the screen that can actually answer it
    //    rather than inventing a second query language here.
    if (needle && looksLikeAQuery(text)) {
      out.unshift({
        key: "q:explore",
        label: `Ask this in the Explorer: ${text.trim()}`,
        hint: "the palette navigates; the Explorer answers",
        go: () => navigate({ to: "/explore" }),
      });
    }

    return out;
  }, [text, resources.data, navigate]);

  useEffect(() => setCursor(0), [text]);

  if (!open) return null;

  const choose = (entry: Entry | undefined) => {
    if (!entry) return;
    entry.go();
    setOpen(false);
  };

  return (
    <div
      className="palette-scrim"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) setOpen(false);
      }}
    >
      <div className="palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <input
          ref={input}
          className="palette-input"
          value={text}
          placeholder="Search resources and screens"
          aria-label="Search resources and screens"
          aria-controls="palette-results"
          aria-activedescendant={entries[cursor] ? `palette-${cursor}` : undefined}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Escape") setOpen(false);
            if (event.key === "ArrowDown") {
              event.preventDefault();
              setCursor((n) => Math.min(n + 1, entries.length - 1));
            }
            if (event.key === "ArrowUp") {
              event.preventDefault();
              setCursor((n) => Math.max(n - 1, 0));
            }
            if (event.key === "Enter") {
              event.preventDefault();
              choose(entries[cursor]);
            }
          }}
        />

        {entries.length === 0 ? (
          // A sentence saying what it searches, not an empty box.
          <p className="palette-empty">
            Nothing matches. This searches resource names and screens.
          </p>
        ) : (
          <ul className="palette-results" id="palette-results" role="listbox">
            {entries.map((entry, n) => (
              <li
                key={entry.key}
                id={`palette-${n}`}
                role="option"
                aria-selected={n === cursor}
                className={n === cursor ? "on" : undefined}
                onMouseEnter={() => setCursor(n)}
                onMouseDown={(event) => {
                  event.preventDefault();
                  choose(entry);
                }}
              >
                <span className="palette-label">{entry.label}</span>
                <span className="palette-hint">{entry.hint}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
