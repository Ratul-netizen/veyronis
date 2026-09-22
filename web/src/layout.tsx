/**
 * The one layout: left nav, header, content.
 *
 * The header holds the two controls that are not about any particular view — the tenant
 * switcher and the time range — and the context bar sits under it, naming what the whole
 * application is currently about. SPEC calls the range "the single most-used control in the
 * product", which is why it is in the chrome rather than repeated per page: a range that
 * lives on a page is a range that resets when you leave it.
 */

import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import { Fragment, useState } from "react";

import { api } from "./api";
import { Wordmark } from "./brand";
import { ContextBar } from "./contextbar";
import { CommandPalette } from "./palette";
import { PRESETS, describeRange, useShell, type ShellSearch, type TimeRange } from "./shell";

/**
 * The sidebar, grouped by the question each section answers — UI-SPEC §11.2.
 *
 * Only what exists. An entry with no screen behind it, or a screen with no data behind
 * it, is the product telling the operator it is unfinished every time they look at it —
 * and the sidebar is on every page, so it says so more often than anything else. This
 * grows as the product does; it is not a roadmap.
 *
 * Observability holds one item because metrics, logs and traces are all the Explorer with
 * a different `signal`. Three entries pointing at one screen with a preselected dropdown
 * would be three lies about how the product is built.
 */
const NAV: { heading: string; items: { to: string; label: string; exact?: boolean }[] }[] = [
  {
    heading: "Network",
    items: [
      { to: "/resources", label: "Resources" },
      { to: "/topology", label: "Topology" },
      { to: "/discovery", label: "Discovery", exact: true },
      { to: "/flow", label: "Flow" },
      { to: "/map", label: "Map" },
    ],
  },
  {
    heading: "Observability",
    items: [
      { to: "/explore", label: "Explore" },
      { to: "/services", label: "Services" },
    ],
  },
  {
    heading: "Operations",
    items: [
      { to: "/incidents", label: "Incidents" },
      { to: "/alerts", label: "Alerts", exact: true },
      { to: "/alerts/rules", label: "Rules" },
      { to: "/alerts/channels", label: "Channels" },
      // Not under Network, although a collector sits on one. This is the list an
      // operator checks when telemetry has stopped arriving, which is an operations
      // question rather than an inventory one — and the answer is often that a process
      // died rather than that a device did.
      { to: "/collectors", label: "Collectors" },
      // Under Operations, and next to the things it is used during. A runbook is not part
      // of the inventory — it is what somebody does to the inventory at 3 a.m.
      { to: "/runbooks", label: "Runbooks" },
      { to: "/runs", label: "Runs" },
    ],
  },
];

/**
 * Sections that stand alone, below the groups.
 *
 * Dashboards is not a group: a heading reading "Dashboards" above a single item reading
 * "Dashboards" says the word twice and means it once. Observability keeps its heading
 * despite also holding one item, because there the heading says something the item does
 * not — that this is where logs, metrics and traces will live.
 */
const LOOSE: { to: string; label: string }[] = [{ to: "/dashboards", label: "Dashboards" }];

/** Carries the shell's search params through every navigation. */
function keepSearch(old: ShellSearch): ShellSearch {
  return old;
}

function TenantSwitcher() {
  const { me, tenant, setTenant } = useShell();

  // A single-tenant install is the common case on-premise, and a select with one option
  // is a control that looks interactive and is not.
  if (me.tenants.length === 1) {
    return (
      <span className="dim" title={tenant.tenant_id}>
        {tenant.name}
      </span>
    );
  }

  return (
    <select
      aria-label="Tenant"
      value={tenant.tenant_id}
      onChange={(e) => setTenant(e.target.value)}
    >
      {me.tenants.map((t) => (
        <option key={t.tenant_id} value={t.tenant_id}>
          {t.name}
        </option>
      ))}
    </select>
  );
}

function RangePicker() {
  const { range, setRange } = useShell();
  const [editing, setEditing] = useState(false);

  if (editing) {
    return (
      <form
        className="range"
        onSubmit={(e) => {
          e.preventDefault();
          const form = new FormData(e.currentTarget);
          const next: TimeRange = {
            from: String(form.get("from") ?? ""),
            to: String(form.get("to") ?? ""),
          };
          setRange(next);
          setEditing(false);
        }}
      >
        <input name="from" defaultValue={range.from} aria-label="From" size={20} />
        <input name="to" defaultValue={range.to} aria-label="To" size={20} />
        <button type="submit" className="primary">
          Apply
        </button>
        <button type="button" onClick={() => setEditing(false)}>
          Cancel
        </button>
      </form>
    );
  }

  return (
    <div className="range">
      <span className="label">{describeRange(range)}</span>
      {/* One segmented control rather than five separate buttons: the presets are
          alternatives to each other, and drawing them apart said they were five unrelated
          actions sitting next to Sign out. */}
      <span className="presets">
        {PRESETS.map((p) => (
          <button
            key={p.label}
            className="preset"
            aria-pressed={range.from === p.range.from && range.to === p.range.to}
            onClick={() => setRange(p.range)}
          >
            {p.label}
          </button>
        ))}
        <button onClick={() => setEditing(true)} title="Absolute or relative, e.g. now-90m">
          Custom
        </button>
      </span>
    </div>
  );
}

export function Layout() {
  const { me } = useShell();
  const navigate = useNavigate();

  return (
    <div className="shell">
      <Wordmark />

      <header className="header">
        <TenantSwitcher />
        <div className="spacer" />
        <RangePicker />
        <span className="dim" title={me.email}>
          {me.display_name}
        </span>
        <button
          className="quiet"
          onClick={() => {
            // The cookie is cleared by the server; this only stops showing a shell the
            // session behind it no longer supports.
            void api.logout().finally(() => navigate({ to: "/login" }));
          }}
        >
          Sign out
        </button>
      </header>

      {/* Under the header and above everything else, because it says what everything
          else is about. §13. */}
      <ContextBar />

      <nav className="nav" aria-label="Sections">
        {/* Outside every group: the answer to the question you ask before you have one. */}
        <Link
          to="/"
          search={keepSearch}
          activeProps={{ className: "active" }}
          activeOptions={{ exact: true }}
        >
          Overview
        </Link>

        {NAV.map((group) => (
          <Fragment key={group.heading}>
            {/* Not a link. A heading that navigates has to decide which of its children
                it means, and the answer is always arbitrary. */}
            <h2 className="nav-heading">{group.heading}</h2>
            {group.items.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                search={keepSearch}
                activeProps={{ className: "active" }}
                {...(item.exact ? { activeOptions: { exact: true } } : {})}
              >
                {item.label}
              </Link>
            ))}
          </Fragment>
        ))}

        {LOOSE.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            search={keepSearch}
            activeProps={{ className: "active" }}
            className="nav-loose"
          >
            {item.label}
          </Link>
        ))}
      </nav>

      <main className="content">
        <Outlet />
      </main>

      {/* Outside the grid: it covers the page rather than occupying a cell. */}
      <CommandPalette />
    </div>
  );
}
