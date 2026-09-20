# UI/UX specification — part 1: the foundation and the first screen

Status: **specification.** [`UI.md`](./UI.md) §13 requires this document before the
cockpit UI is written — *"without it every page invents its own pattern, and the product
ends up looking like six products."* This is the part of it that the **Operations
Overview** needs, and no more.

| | |
|---|---|
| **Governs** | design tokens · colour semantics · typography · density and the layout grid · the widget contract · live update · animation · accessibility |
| **Defers** | 2D and 3D topology, the investigation workspace, NOC mode, the command palette, incidents, automation, state management beyond what exists, the package split — each one is specified when it is the next thing built |
| **Supersedes** | nothing. `UI.md` stays the direction; where this document is more specific, this document is what gets built |
| **Applies to** | every page, including the six that already exist — see *Migration* at the end |

Written 2026-09-17, against the shell, Explorer, alerts and dashboards as built.

---

## 0. The three rules everything here answers to

From `UI.md`, restated as the tests this specification can be checked against:

1. **2D carries information; 3D carries spatial relationships.** No chart, table, list,
   form or number is 3D. Ever.
2. **Colour is semantic, never decoration.** If a colour means something, it means the
   same thing on every screen; if it means nothing, it is not a colour, it is a grey.
3. **The UI is a layer over the architecture, not a second architecture.** A screen shows
   a `Query` AST's answer, a `resource_id`, a `TenantScope`. It does not invent a second
   model of what a device is.

And one rule this document adds, because it is the one the existing code has already
been following and it should be written down:

4. **Nothing is conveyed by hue alone.** Every state carries a word or a glyph as well.
   Roughly one man in twelve cannot read a red-green distinction, and a NOC wall is read
   from four metres.

---

## 1. Tokens

Every colour, radius and dimension is a custom property on `:root`. There are no colour
literals anywhere else — `web/src/styles.css` already holds this line and it is now a
rule rather than a habit.

### 1.1 Ground and surfaces

`UI.md` §9 asks for "very dark blue / charcoal" ground and near-black cards. The built
palette is charcoal-neutral; this specification moves it onto the blue axis it asks for,
which is a change of about eight points of hue and nothing else.

| Token | Dark | Light | What it is |
|---|---|---|---|
| `--bg` | `#0d1017` | `#fbfbfc` | the ground; the page behind everything |
| `--bg-raised` | `#161a22` | `#ffffff` | cards, panels, popovers — one step up |
| `--bg-sunken` | `#090b10` | `#f2f3f5` | wells: table headers, inputs, the gauge track |
| `--border` | `#252b36` | `#dfe1e6` | one-pixel separation, never a box for its own sake |
| `--text` | `#e6e8ec` | `#16181d` | body |
| `--text-dim` | `#9aa1ae` | `#5c6270` | labels, units, timestamps, anything secondary |

Dark is the default and the one designed first: a NOC wall runs dark for eight hours.
Light exists because the screenshot that goes into a customer's monthly report runs
light, and retrofitting it later is a rewrite of every colour decision.

### 1.2 Semantic state

These five are the product's vocabulary. A screen may not introduce a sixth, and none of
them may be used decoratively.

| Token | Dark | Light | Means | Word used with it |
|---|---|---|---|---|
| `--ok` | `#57d08a` | `#1a7f4b` | up, healthy, resolved, delivered | `up`, `ok`, `resolved` |
| `--warn` | `#e0b054` | `#9a6400` | degraded, pending, rate-limited, slow | `warning`, `pending`, `degraded` |
| `--danger` | `#ff7b7b` | `#b4232b` | down, critical, firing, failed | `critical`, `down`, `firing` |
| `--unknown` | `#8b93a1` | `#6b7280` | never reported, no data, stale | `unknown`, `no data` |
| `--maintenance` | `#9d7bff` | `#6d4ad6` | suppressed by a maintenance window | `maintenance` |

`--unknown` and `--maintenance` are new: the backend has had both states since migration
0002 and 0012 and the UI has had no way to say either. "No data" drawn as zero and
"suppressed" drawn as healthy are the two most consequential lies a monitoring UI can
tell.

### 1.3 Accent — there is not one

**The product has no brand colour on screen.** The only hues in the interface are the
five semantic states in §1.2.

This was a blue, `#2c5fd6`, and rule 2 above is the argument against it: *colour is
semantic, never decoration*. A blue that means "you are here" is decoration by that
rule's own logic — and it created a real collision, because the same blue was also
`--series-1`, so one colour meant both "the page you are on" and "the first line on this
chart".

It also removed an accessibility problem rather than solving one. An accent hue has to
stay distinguishable from five semantic hues under three kinds of colour blindness, on
two backgrounds. The cheapest way to pass that test is not to take it.

So `--accent` is the ink, and selection is drawn by **inversion**:

| Token | Dark | Light |
|---|---|---|
| `--accent` | `#e8ebef` (= `--text`) | `#12151a` (= `--text`) |
| `--accent-text` | `#0c0f13` (= `--bg`) | `#ffffff` |
| `--accent-dim` | `#e8ebef1a` | `#12151a12` | a wash behind an active row |

Consequences, all of them deliberate:

- the current nav item, the current time range and the current tab are **inverted
  blocks**, not tinted ones;
- a link is the ink plus an underline, offset clear of the descenders — links previously
  had no rule at all and fell through to the browser's own blue, which was outside the
  token system entirely;
- the focus ring is `--accent`, which is now the highest-contrast colour available on
  either ground.

### 1.3a The one idea: quiet until something is wrong

When nothing is firing there is **no colour on the screen at all**. When something breaks,
colour arrives — at the left edge of the thing that broke, and in the count that says how
much.

The amount of colour on screen is therefore proportional to how much is wrong, which is
readable from four metres without reading a word. It is also what makes the product
bearable to sit in front of all day: a console that is permanently shouting is one whose
operator stops hearing it.

This is not a mood. It is the reason §8.2's "no zero in a red tile" rule can finally be
kept: the calm state is a sentence, because there is nothing to count.

### 1.4 Series colours

Charts need a categorical palette that is *not* the semantic one, or a line will look
like a status. Six, because a panel with more than six lines is one whose grouping is too
fine to read, and after six they repeat — a visible signal that this has happened.

```
--series-1  #6d9bff   --series-2  #57d08a   --series-3  #e0b054
--series-4  #ff7b7b   --series-5  #a78bfa   --series-6  #2dd4bf
```

They are ordered for distinguishability under the common forms of colour blindness: blue
and amber lead, and the red sits fourth rather than second.

### 1.5 Shape, space and motion

```
--radius      5px     --radius-lg   8px     controls, and panels on a dashboard
--space       4px     the unit; every margin and gap is a multiple
--sidebar     208px   --sidebar-collapsed  56px
--header      48px
--row         28px    one table row at default density
--tap         32px    the smallest interactive target
--rail        3px     the state bar on the left edge of a row
--motion      120ms   the only transition duration
--motion-slow 240ms   panels sliding in, and nothing else
```

One duration, because a product with five easing curves reads as five products. Easing is
`ease-out` on entry and `linear` on anything that repeats.

**Radius belongs to controls.** A region with a radius is a card; a button with one is a
thing you can press. That distinction is load-bearing and replaces the previous rule,
which was that everything had the same radius regardless of what it was.

**Regions are not cards.** A panel used to be a lighter surface with a border, a radius
and its own fill. `--bg-raised` is now the same value as `--bg`, and a section of a page
is bounded by a hairline and held together by its own alignment. Stacked surfaces with
shadows are how a web application looks; equipment you read is ruled, not stacked.

The exception is a **dashboard panel**, which stays a card — because it genuinely is a
discrete object that can be moved, resized and deleted, and drawing it as part of the page
would say otherwise.

### 1.6 The rail

Anything with a state carries it as a `--rail`-wide bar on its **left edge**, tinted with
the semantic colour, set through a `--tone` custom property on the row.

A coloured dot in the third column is legible at arm's length and invisible at four
metres. A column of rails is a single bar of varying colour down the side of the page, and
that is a shape rather than a hue — so it survives both distance and colour blindness.

Rule 4 still applies without exception: every rail sits beside the word for its state.

---

## 2. Typography

| Role | Family | Size | Weight | Use |
|---|---|---|---|---|
| Display | `--font` | 22px | 600 | one per page, the page's name |
| Section | `--font` | 15px | 600 | panel titles, group headings |
| Body | `--font` | 14px | 400 | everything |
| Label | `--font` | 12px | 500 | form labels, column headers, units |
| Stat | `--font` | 34px | 600 | the one number on a stat panel |
| Mono | `--mono` | 13px | 400 | see below |

The decision `UI.md` §9 left open is made: **IBM Plex Sans and IBM Plex Mono**,
self-hosted from `web/public/fonts`. All three of the questions that deferred it are
answered — the files are in the repository, the licence is SIL OFL 1.1 and sits beside
them, and nothing is fetched at runtime. This product is installed on networks with no
route to the internet, and a font that arrives from Google is a font that does not arrive.

Plex rather than Inter because Inter is what a product with no typographic opinion uses.
Plex was drawn for IBM's technical products, it holds up at 13px on a bad monitor, and its
mono is the same superfamily — which matters more here than it usually would, because the
sans/mono distinction in this product is *semantic* rather than stylistic. Two faces from
one family make that read as a change of voice, not a change of typeface.

Four faces, Latin subsets, 82 KB in total: Sans at 400/500/600 and Mono at 400. Loaded
with `font-display: swap`, because a console that shows nothing until a font arrives is
worse than one that reflows.

The scale carries the hierarchy, and has one large step at the top so a screen can have
exactly one loud thing:

```
--t-hero    46px   the count that matters, when something is wrong
--t-display 20px   the page's name
--t-section 13px   a section heading
--t-body    14px
--t-label   12px   column headers, field labels, units
--t-mono   12.5px
```

The previous scale ran 12/14/15/22 — four sizes inside ten points, which is four sizes
that all read the same and no way to make anything matter more than anything else.

**Sentence case, never capitals.** Tracked-out capitals above every column is the
commonest tell of a templated interface, and capitals are measurably slower to read at the
12px a label is always set in.

**Mono is not a style choice, it is a type.** Anything the operator may need to compare
character by character is mono: IP and MAC addresses, timestamps, log bodies, metric
values, identifiers, query text, dedup keys, hostnames in a table. Prose is never mono.

Numbers in tables and stats use `font-variant-numeric: tabular-nums`, so a column of
values does not shift as it updates.

---

## 3. Density and the layout grid

An operations console is read at a glance by somebody who already knows what they are
looking for. It is dense.

- **Twelve columns**, `--space * 3` gutters. Twelve divides by 2, 3, 4 and 6, which is
  every layout anybody asks for. The dashboard grid already works this way.
- **Row height `--row`** at default density, `--row + 8px` at *comfortable*, which is a
  per-user preference and the only density control.
- **Panels are cards**: `--bg-raised`, one-pixel `--border`, `--radius`, 10px 12px
  padding, a header row with the title left and controls right.
- **Below 70rem the grid collapses to one column.** A dashboard read on a phone is a
  list; two columns at that width is two unreadable columns.

### 3.1 The page frame

```
┌────────────────────────────────────────────────────────────────┐
│ header: brand · context · time range · live · alerts · user    │  --header
├──────────┬─────────────────────────────────────────────────────┤
│ sidebar  │ content                                             │
│ --sidebar│   h1 + one line of context                          │
│          │   page body                                         │
└──────────┴─────────────────────────────────────────────────────┘
```

The sidebar is grouped as `UI.md` §1 draws it — Overview, NETWORK, OBSERVABILITY,
OPERATIONS, DASHBOARDS, ADMIN — and collapses to icons at `--sidebar-collapsed`. Items
for pages that do not exist yet are **not shown**: a menu of links to empty pages teaches
an operator the product does not work, which is the same argument §3 makes about empty
panels.

---

## 4. The widget contract

Every panel on every screen — the default dashboard's and a user's — obeys one contract.
This is what stops the built-in dashboards and the builder from being two products.

A widget is:

```ts
{ id, title, query?: Query, viz: Viz, width, height }
```

and it has exactly five states, each of which must be distinguishable at four metres:

| State | What it shows |
|---|---|
| **loading** | the title, and a quiet placeholder. Never a spinner per panel — twenty spinners is a broken page |
| **empty** | "No data in this window." — and *never* a zero |
| **data** | the visualization |
| **error** | the server's own sentence, in the panel's corner, with the rest of the page alive |
| **stale** | data plus a dimmed timestamp: this is what the panel last knew, and it is older than the window claims |

Rules that follow from the backend and are not negotiable in a panel:

1. **The window comes from the header**, always. A panel stores a window as provenance
   and substitutes the current one on read.
2. **The bucket follows the window.** A panel saved at five-minute buckets, viewed over a
   month, asks for wide buckets — otherwise it silently truncates and looks complete.
3. **Null is not zero.** `avg()` over an empty bucket is null; a chart that draws it as
   zero shows an outage as a collapse to the floor.
4. **A panel is one query.** Twenty panels are twenty requests. One slow panel spins
   alone; one failing panel fails alone.

### 4.1 The shipped visualizations

Five, as SPEC §M4 names, and no more until one is needed: **time series**, **single
stat**, **table**, **gauge**, **alert list**. Not heatmap, pie, geo or topology — two are
choices this product does not need and two are §6's, not a panel's.

Charts are **SVG, hand-drawn, no chart library**, as the Explorer histogram, the site map
and the dashboard panels already are. `UI.md` §11 proposes ECharts; that remains open, and
the bar it has to clear is stated here: a chart library enters this product only when a
visualization is needed that is genuinely hard by hand — and it must clear `deny.toml`
first. A line, a bar, a gauge and a sparkline are a scale, a path and two axes.

---

## 5. Live update

The product has three refresh behaviours and they are not the same thing. Getting this
wrong is either a stale console or a bill.

| Surface | Behaviour | Why |
|---|---|---|
| **Alert list, header alert count** | poll every 10s | small indexed reads of the control plane; this is the screen whose whole purpose is to be current |
| **Explorer** | never, unless following | it runs a query somebody typed over a window somebody chose; a timer on it bills the customer for the page being open |
| **Live tail** | poll every 2s, half-open on `ingested_at` | a stream, and the watermark is the server's |
| **Dashboard panels** | on window change; `staleTime` 60s | a wall display is the case; the time range is what changes them |

**The live indicator in the header is a fact, not a decoration.** It is lit only while
something on the page is actually refreshing on a timer, and it carries the word `LIVE`.

No websockets yet. Nothing on these four surfaces needs sub-second push, and a held-open
connection is the thing on-premise proxies close at sixty seconds — the same argument the
live tail already made. When incidents or topology need push, that is when the transport
decision gets made, and it gets written down here.

---

## 6. Animation

Animation means **state change**, and nothing else. `UI.md` §9's micro-interactions,
specified:

| Event | What moves | Duration |
|---|---|---|
| a resource goes down | its status dot pulses twice, then rests | `--motion-slow` ×2 |
| a new alert arrives | the row fades in from `--accent-dim` | `--motion` |
| a panel loads | opacity only, no movement | `--motion` |
| a drilldown opens | slides from the right | `--motion-slow` |
| a value updates | the number changes; nothing animates | — |

Never: rotation, bouncing, parallax, anything looping that does not represent a live
signal, or a full-screen colour change. A screen that flashes red is a screen somebody
turns off.

`prefers-reduced-motion: reduce` removes every one of these. The pulse becomes a static
ring, the slide becomes an appearance. Nothing in the table above is the *only* carrier of
its information, so removing it loses nothing — which is the test for whether an animation
was decoration.

---

## 7. Accessibility

Not a section to revisit later; each item is checkable on every page.

- **Colour plus a word or glyph, always.** A severity is a coloured pill *with the word in
  it*. A status dot has a label beside it.
- **Contrast**: body text ≥ 4.5:1 against its surface, large text and glyphs ≥ 3:1. The
  dark tokens above are chosen to clear this; a new colour must be checked, not assumed.
- **Keyboard**: every interactive element reachable by Tab in visual order, a visible
  focus ring (`--accent`, 2px, never removed), Escape closes any overlay, Enter activates.
- **Screen readers**: every icon-only control has a label; tables have real `<th>`; a
  live region announces "N alerts firing" when that count changes, and nothing else —
  announcing every metric update makes the page unusable.
- **Scalable text**: the layout survives 200% browser zoom and a 16px minimum body size
  preference. No `px` line heights that clip.
- **NOC distance mode**: a per-user setting that raises body to 16px, `--row` to 36px and
  stat to 44px. Not a separate stylesheet — the same tokens with different values.

---

## 8. The Operations Overview

`UI.md` §3's landing page, specified against what the backend can answer **today**.
Panels whose data does not exist yet are not drawn as empty boxes — they are absent, and
the sequencing table says when they arrive.

```
┌───────────────────────────────────────────────────────────────────────┐
│ OPERATIONS OVERVIEW                          Last 30 min ▾   LIVE ●   │
│ Default tenant · all sites                                            │
├───────────┬───────────┬───────────┬───────────────────────────────────┤
│ RESOURCES │  FIRING   │  PENDING  │  REPORTING                        │
│    248    │     5     │     3     │   231 / 248                       │
├───────────┴───────────┴───────────┴───────────────────────────────────┤
│  WHAT IS FIRING                                                       │
│  ● critical  rtr-01   CPU above 90%              4m   [take]          │
│  ● warning   rtr-04   Interface errors           1m   [take]          │
├─────────────────────────────────┬─────────────────────────────────────┤
│  LOG VOLUME BY SEVERITY         │  BUSIEST RESOURCES                  │
│  (stacked bars, 30 min)         │  (name · errors · last seen)        │
└─────────────────────────────────┴─────────────────────────────────────┘
```

### 8.1 Every number on it, and where it comes from

| Tile | Source | Notes |
|---|---|---|
| Resources | `GET /api/v1/resources` count | excludes decommissioned |
| Firing / Pending | `GET /api/v1/alerts` | the two states are separate tiles because one has woken somebody and the other has not |
| Reporting | resources with telemetry in the window ÷ total | the honest availability number this product can compute today. **Not** called "availability": that implies an SLA calculation with maintenance windows excluded, which is M9 |
| What is firing | `GET /api/v1/alerts`, ordered firing-then-pending | the same component as the alerts page; `take` acknowledges in place |
| Log volume | one `Query`: count by `time_bucket` and `severity` | stacked bars, semantic colours, `--unknown` for unparsed |
| Busiest resources | one `Query`: count by `resource_id`, severity ≥ error | links to the resource page |

Six panels, four queries, one control-plane read. Under the twenty-panel budget measured
at p95 0.42s, with room for the topology and flow panels §3 wants when M6 and M7 land.

### 8.2 What it must not do

- **No empty states pretending to be data.** Zero firing alerts is "Nothing is firing",
  not a `0` in a red tile.
- **No health percentage invented from nothing.** §3's mock shows a 97.4% health ring;
  there is no defensible formula for it yet, so it is not drawn. A number nobody can
  explain is worse than an absent one on the screen an operator trusts first.
- **No topology panel until M6.** A placeholder that says "topology coming soon" on the
  landing page is the product telling the operator it is unfinished, every time they open
  it.

---

## 9. Migration: the six pages that already exist

This specification is retrospective for the shell, resources, map, Explorer, alerts and
dashboards. They mostly comply — the tokens, the twelve-column grid, the panel card, the
five widget states and "colour plus a word" all came from building them. Where they do
not:

| Gap | Where | Fix |
|---|---|---|
| ground is charcoal, not blue-dark | `styles.css` `:root` | §1.1 values |
| no `--unknown` or `--maintenance` | everywhere | add; then use them where the backend already reports those states |
| series colours are ad hoc, partly semantic | `panels.tsx` `LINE_COLOURS` | §1.4 |
| no `--space` scale; margins are hand-picked | `styles.css` | §1.5, mechanical |
| sidebar is flat, not grouped | `layout.tsx` | §3.1, when the group has two items in it |
| no focus-ring rule | `styles.css` | §7 |
| no NOC distance mode | — | §7, a later setting |

None of these is a rewrite. They are the difference between six pages that look similar
because one person wrote them in a week and six pages that look the same because they are
built from one set of decisions.

---

## 9a. One product, two ways of running it

The question this answers: ManageEngine ships a web console *and* a native desktop
application, and whether this product should is a real decision rather than a preference.

**The web UI is the product.** One React build, served by the same `uops-server` binary
that serves the API, from the same origin — which is why there is no CORS configuration
anywhere in this tree. It is responsive by §3's rules, so a phone, a tablet and a NOC wall
are the same code at three widths.

**It is installable, and that is the "any device" half.** A web app manifest and PNG icons
at 192, 512 and 180 make it a home-screen app on Android and iOS and a standalone window
on Windows and macOS — the same build, no second codebase, no store review. That is
shipped.

**There is deliberately no service worker.** An installable app is not an offline one, and
a monitoring console that shows cached state from an hour ago is worse than one that says
it cannot reach the server: the first is indistinguishable from an estate that is fine.

**A native shell is a later, small thing — and it is Tauri, not Electron.** What a desktop
shell adds that a browser tab cannot: a system-tray presence, native alert notifications
when the window is closed, and a NOC window with no browser chrome. Tauri is the right
tool for it — it uses the operating system's own webview rather than bundling Chromium, so
the shell is single-digit megabytes against Electron's hundred and fifty, and its licences
(MIT/Apache-2.0) pass `deny.toml` where Electron's tree is a much larger question. It
would load the same build this repo already produces.

**What a native shell must not become** is a second UI. A separate desktop codebase is the
"six products" failure mode of §13 at the application level: two implementations of the
alert list, drifting, with the bug fixed in one of them. The shell is a window and a tray
icon; everything inside it is the web app.

**A true single-host desktop install is not on the table**, and it is worth saying why: the
server needs PostgreSQL and ClickHouse. "Install Veyronis on the ops laptop" means
embedding both, and neither embeds. A single-node `docker compose up` is the small
deployment story, and it already exists.

---

## 10. What this document does not cover

Named so that the next person knows the gap is deliberate: 2D and 3D topology · the
investigation workspace · incidents and their timeline · NOC mode beyond the distance
setting · the command palette · automation · flows and geography · the component and
package architecture · state management beyond TanStack Query as used · websocket and
push · per-page performance budgets beyond the dashboard's measured one.

Each is specified when it is the next thing built, in a part 2 of this document — not
guessed at now, because a specification written a milestone early is a specification that
gets ignored.

---

# Part 2

Written as each thing is built, per §10. What follows is the navigation, the command
palette and the context bar, because those are what is being built now. Incidents,
investigations, flows, traces and automation stay in §10's list: no backend answers them
yet, and specifying a screen over data that does not exist is how a specification becomes
fiction.

## 11. Navigation

### 11.1 The rule that decides what is in it

**Only what exists.** A sidebar entry with no screen behind it, or a screen with no data
behind it, is the product telling the operator it is unfinished — every time they look at
it. That is the same argument §8.2 makes against a "topology coming soon" panel, and it
applies with more force here because the sidebar is on every page.

So the navigation grows as the product does. It is not a roadmap.

### 11.2 Groups

Seven flat links was right at five. It stops being right somewhere around nine, and the
product is there. The groups are by *question asked*, not by subsystem:

```
  Overview                    ← the one thing before you know what you are looking for

  NETWORK                     ← what is out there
    Resources
    Discovery
    Topology
    Map

  OBSERVABILITY               ← what it is doing
    Explore

  OPERATIONS                  ← what is wrong
    Alerts
    Rules
    Channels

  DASHBOARDS                  ← what you decided to keep watching
    Dashboards
```

Group headings are **not links**. A heading that navigates is a heading that has to decide
which of its children it means, and the answer is always arbitrary.

Overview sits outside every group, because it is the answer to the question you ask before
you have one.

**Observability holds one item today.** Metrics, logs and traces are all the Explorer with
a different `signal`, and three sidebar entries pointing at one screen with a preselected
dropdown would be three lies about how the product is built. They become separate entries
when they become separate screens.

### 11.3 Collapsing

Below `--sidebar` the rail collapses to icons with the group headings hidden and a
tooltip per item. NOC wall mode collapses it by default; a wall display has no cursor and
the navigation is not what it is showing.

## 12. The command palette

`Ctrl`/`Cmd` + `K`. The fastest path to any resource or screen, and the reason the
navigation does not have to grow a search box of its own.

### 12.1 What it searches

In order, because the order is the ranking:

1. **Resources by name.** The commonest thing anybody wants, and the one that gets slower
   to reach as the estate grows — which is exactly backwards from what a console should do.
2. **Screens.** By name and by the words somebody would use for them: "logs" finds
   Explore, "topology" finds Topology.
3. **Actions.** Things with a verb: create a dashboard, add a discovery job, sign out.

### 12.2 What it is not

**Not a query language.** `packet loss > 5%` belongs in the Explorer, which has a
compiler, a `Query` AST and an opinion about what is answerable. A palette that accepted
half a query language would be a second query language that cannot be saved, alerted on or
shared — and the product already refuses to have two of those.

The palette's job is *navigation*. When something typed into it looks like a question
rather than a destination, it offers to open the Explorer with it.

### 12.3 Behaviour

- Opens over the page, does not navigate away; `Esc` closes it and returns focus to where
  it was.
- Arrow keys move, `Enter` opens, and the first result is selected so `Ctrl+K` `Enter` on
  an exact name is two keystrokes.
- Results are keyboard-reachable and announced: it is a `listbox`, not a list of divs.
- No results is a sentence saying what it searches, not an empty box.
- It respects `--motion`: it appears, it does not spring.

## 13. Context

> **Built.** `web/src/context.ts` is the model and `web/src/contextbar.tsx` the bar. The
> two decisions below — what may be a context, and that it lives in the URL — were
> written down first precisely so they would not be made accidentally by whichever screen
> implemented it first, and they survived contact with the implementation unchanged.

A bar under the header naming what the whole application is currently about.

```
  Context: All resources ▾        ← everything below is scoped to this
```

Setting a context scopes **every** screen: the overview's counts, the Explorer's default
filter, the alert list, the topology's root, the dashboards' variables. That is the idea
`UI.md` and the research both reach for, and it is only honest to offer it because the
backend already has the thing it scopes on — a `TenantScope`, a `site_id`, a
`resource_id`, a resource group.

### 13.1 What can be a context

Only what the data model already has, and in this order of narrowing:

```
All resources → Site → Resource group → Resource
```

Tenant is deliberately **not** in that list: it is above context, it lives in the header,
and switching it is switching customers rather than narrowing a view. Conflating the two
would put "which customer am I looking at" in the same control as "which rack".

### 13.2 How it is carried

In the URL, beside the time range, in `ShellSearch`. Two reasons and both are practical: a
context that is not in the URL is a context nobody can send to a colleague during an
incident, and one held only in memory is one that resets on reload — at the moment when
reloading is exactly what somebody under pressure will do.

### 13.3 What it must not do

**It must not silently hide things.** A scoped screen says what it is scoped to, in words,
and offers the way out. An operator who cannot find a device because a context they forgot
about is filtering it out will conclude the product has lost the device — and they will be
right to distrust it afterwards.

Three things came out of building it, and all three are this rule read from another side.

**A screen the context does not reach must say so.** The other half of the promise: a
context that is not being applied must not look as if it were. A narrowed bar above a
full-tenant list of discovery runs is a lie of exactly the shape §13.3 forbids.
`unscopedBecause` holds every screen the context does not reach and the sentence saying
why, and the bar prints it. A screen added tomorrow is unscoped and says so, rather than
inheriting a promise nobody checked.

**"Not yet" is one of those reasons, and it is not hidden.** Topology and Alerts are in
that list today because they are not wired, not because they are meant to be estate-wide.
A narrowed bar over a whole-tenant screen is the same lie whether the cause is design or
unfinished work, so it is said out loud either way. Deleting one of those entries is the
*last* step of scoping that screen.

**The way out is a control, not a fact.** "Show everything" sits beside the label, on
every screen, whenever there is something to leave — and is absent when there is not,
because a control that is permanently present and does nothing four times in five teaches
people to stop seeing it.

**A context naming something deleted shows the id.** Ugly, and true. Falling back to "All
resources" would report the view as unscoped at the exact moment it is scoped to nothing,
and the screen underneath says the context is what emptied it.

### 13.4 What is scoped, today

| Screen | |
|---|---|
| Overview, Resources | scoped, through the one resource list both read |
| Topology, Alerts | not yet — the bar says so on both |
| Explore, Dashboards, Rules, Channels, Discovery, Map | never: each carries its own selector, or is the thing you use to *find* a context |

The middle row is the outstanding work, and it is outstanding rather than forgotten. The
command palette is deliberately in the third: a finder that only searches what you have
already narrowed to cannot get you out of a context you forgot you set.

## 14. Topology, 2D

The first screen that draws the relationships rather than listing them. Its data is the
`connected_to` edges M5's neighbour walk writes, and the resources at their ends.

### 14.0 Backend truth

A rule worth stating here because this is the screen most tempted to break it:

> **The UI may visualise backend truth. It may not invent backend semantics.**

The proposal this screen came from wanted animated particles flowing along links to show
traffic direction and volume. There is no flow data — that is M7 — so those particles
would be an animation of nothing, on the screen an operator would most reasonably believe.
They are not drawn. When M7 lands they can be, and they will mean something.

The same rule removes link utilisation colouring, bandwidth labels, and any notion of a
"primary path". What the backend knows about a `connected_to` edge is that two devices
reported each other, and which protocol said so. That is what the edge shows.

### 14.1 What a node is

A resource. It carries:

| | from |
|---|---|
| name | `resource.display_name ?? resource.name` |
| kind | `resource.kind` |
| state | `resource.status` — the semantic five, drawn as the node's fill |

Nothing else, because nothing else is known without another query per node, and a
topology that issues one request per node is a topology that stops working at the size
where it starts being useful.

### 14.2 What an edge is

A `connected_to` relationship: undirected, deduplicated, with `discovered_by` naming the
protocol that last confirmed it. LLDP and CDP are drawn solid; ARP is drawn dashed,
because §2.5 is right that an ARP sighting is much weaker evidence and the picture should
say so without being asked.

`member_of` — an interface inside its device — is **not** drawn. It is containment rather
than adjacency, it would triple the node count, and it is what the resource page is for.

### 14.3 Layout is deterministic

A force simulation, run to a fixed iteration count at load, seeded from each resource's
id. Then it stops.

Two consequences, both deliberate:

- **The same estate always draws the same picture.** An operator comparing this morning's
  topology with a screenshot from last week is comparing two pictures of the same shape,
  not two random arrangements of the same graph. A layout seeded from `Math.random` makes
  that impossible and makes every bug report unreproducible.
- **Nothing moves after load.** A permanently running simulation is a permanently running
  animation frame — on a NOC wall that is a machine that never idles, and §6's rule is
  that motion communicates a change of state. A graph settling is not a change of state.

Dragging a node pins it and re-runs the simulation with that node fixed. That is motion
answering a person's action, which §6 allows.

### 14.4 The hairball, and what is done about it

A force layout of two thousand nodes is a black circle. The rule:

- Under `NODE_BUDGET`, draw every node.
- Over it, draw the **largest connected component** and say, in words, how many nodes and
  components were left out with a control to include them.

Not silent truncation, and not a spinner that never ends. An operator who cannot see a
device must be told it is not being shown — otherwise they conclude the product lost it,
and they are right to distrust it afterwards.

Grouping by site is the better answer and arrives when a meaningful number of
installations set `site_id`; until then it would be a control that does nothing on most
estates.

### 14.5 Controls belong to the screen

Search, layout and filters sit on the topology, not in global settings — the pattern worth
keeping from the research. They apply to what is loaded.

There is no 2D/3D switch until there is a 3D mode. A control that is present and does
nothing is the sidebar problem in miniature.

### 14.6 Selection

Clicking a node selects it: the node and its edges stay at full strength and everything
else drops back, so the question "what is this connected to" is answered by looking rather
than by reading. A second click, or `Esc`, clears it.

Selection is not navigation. The panel that opens offers the ways on — the resource, its
alerts, its logs — and going to one of them is a deliberate act, because losing the
topology you just oriented yourself in is expensive during an incident.

## 14.7 Topology, 3D

A mode on the topology screen, not a screen of its own, and not the default.

### 14.7.1 What the third dimension carries

**Height is hop distance from the most connected device**, computed per connected
component.

That sentence is chosen carefully. It is a fact about the *graph* — a count of hops from a
node with a countable property — and not a claim about the network. "This is the core
layer" would be an inference nobody has made, and §14.0 forbids the UI from making one.
In practice the two usually agree, because the box everything is cabled to is the box with
the most cables, which is why the view is worth having at all. The caption on screen says
what is actually measured, so an operator whose estate does not follow that pattern is not
being told something false about it.

`x` and `z` are the 2D layout's own coordinates, unchanged. Switching modes therefore
**lifts the picture you were already looking at** rather than rearranging it. Two views
that scramble the graph between them are two pictures to learn; one that lifts it is a
second reading of the same one.

### 14.7.2 Why this is a mode and not the product

Rule 1 of this document: *2D carries information; 3D carries spatial relationships.* A flat
adjacency graph of nine devices has no spatial relationship to carry, and 3D would cost
occlusion, a camera to operate and a canvas no screen reader can read, in exchange for
nothing.

It earns its place when the graph has depth — tiers, many nodes, a shape that a plane
flattens into a hairball. So 2D is the default, 3D is deliberate, and the switch only
exists now that there is something to switch to. §14.5's rule about controls that do
nothing applied to this one until the day it worked.

### 14.7.3 Accessibility

A WebGL canvas is not reachable by a keyboard and not readable by a screen reader, and
pretending otherwise with a fake focus ring would be worse than admitting it.

The mitigation is that **2D is the default and is complete**: every node is a focusable
element with a name and a state, every link is in the detail panel as text, and nothing in
3D is reachable only in 3D. The modes show the same graph; one of them is accessible, and
it is the one the product opens with.

### 14.7.4 Motion

Nothing in the scene moves unless somebody moves it, and the renderer draws on demand
rather than in a loop. `prefers-reduced-motion` therefore needs no special case — there is
no ambient animation to reduce — and a wall display left on this screen is not a machine
spinning a GPU all night.

### 14.7.5 The dependency

`three`, and nothing else. The rule stated in part 2 is that a dependency must solve a
problem that is materially expensive or unsafe to solve ourselves: WebGL qualifies, and
React *bindings* for WebGL do not, because this scene has no per-frame React state — it is
spheres and lines. `@react-three/fiber` also pins a React older than this application's,
which is the kind of constraint a convenience dependency has no right to impose.

It is loaded with `React.lazy` and lives in its own chunk. An operator who never opens 3D
never downloads it, and the 2D path's bundle is unchanged by its existence.
