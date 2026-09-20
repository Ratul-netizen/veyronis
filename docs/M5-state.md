# M5 Discovery — where it stands

Last updated: 2026-09-20. Written to be picked up cold.

The specification is [`M5-discovery.md`](./M5-discovery.md); its §4 acceptance criteria
all pass. This file is the *state*, which is a different question: what is built, what
remains, and what a person walking back in needs to know before touching it.

---

## Done

| | Where |
|---|---|
| Specification, decisions closed before building | `docs/M5-discovery.md` |
| Schema — jobs, runs, candidates | `migrations/0017`, `0019` |
| Sweep planning, probe, run driver, credential loop | `crates/uops-discover/src/{sweep,probe,run}.rs` |
| Neighbour decode — LLDP, CDP, ARP | `crates/uops-discover/src/neighbour.rs` |
| Persistence — jobs, runs, candidates | `crates/uops-store-pg/src/discovery_jobs.rs` |
| Sweep → inventory, via identity resolution | `crates/uops-store-pg/src/sweep_ingest.rs` |
| Neighbours → edges and candidates | `crates/uops-store-pg/src/neighbour_ingest.rs` |
| Seven routes, tenant-isolated | `crates/uops-api/src/routes/discovery.rs` |
| Three screens — Jobs, Runs, Candidates | `web/src/discovery.ts`, `web/src/discoverypages.tsx` |
| One run in flight per job, in the schema | `migrations/0020` |
| The scheduler — due, claim, sweep, finish, reap | `crates/uops-sweeper/src/lib.rs` |
| The sweep it runs in production | `crates/uops-sweeper/src/live.rs` |
| Wired into the server behind `UOPS_DISCOVERY` | `crates/uops-server/src/main.rs` |

All twelve acceptance criteria pass. 47 tests in `uops-discover`, 38 across the two store
test files, 12 in `uops-sweeper`, 8 isolation cases, and 1 024 passing across the
workspace — with 37 failures that are all ClickHouse being unreachable on this machine
and none of them in discovery's path.

---

## Not done

**The neighbour walk is not scheduled.** `uops_discover::neighbours` and
`PgStore::record_neighbours` both exist and are tested, and an operator can walk a device
through the API — but a scheduled job sweeps and does not then walk what it found. That is
the next thing to add to `Live::sweep`, after the `record_sweep` call, and it is additive:
the counters it would contribute are already columns on `discovery_run`.

**A scheduled run writes no audit entry.** §2.7 requires one carrying the ranges, and
`routes/discovery.rs` writes it for a manual run. A scheduled run has no `Caller`, so it
needs the system-actor path — which does not exist yet and is the only reason this is
still open.

**There is no `POST /api/v1/discovery/jobs/{id}/run`.** The machinery to serve it now
exists — it is `Live::sweep` with a `Trigger::Manual` — so this is a route to write rather
than a thing to build.

---

## What to know before touching it

**The three caps are chosen against each other.** `IN_FLIGHT`, `PROBES_PER_SECOND` and
`PROBE_TIMEOUT` are not independent: a sweep of empty addresses runs at
`IN_FLIGHT / PROBE_TIMEOUT` probes per second *whatever the rate cap says*. Pick them
separately and the smaller binds silently while the documented one is decoration — which
is what the first version did, promising 5½ minutes for a /16 and delivering 85.
`the_three_caps_agree_with_each_other` is the test that stops it happening again.

**A sweep takes as long as its credential list is long.** A wrong SNMPv2c community is
*silence*, not a refusal, so every credential must be tried against every address that has
not answered. Four credentials over a /16 is twenty-two minutes. This is why
`MAX_CREDENTIALS` is 4 and why it is in the schema too.

**Rediscovery does not work by confidence.** An address and a hostname combine to 0.93,
under `AUTO_MERGE_THRESHOLD` — so a second sweep would send the whole estate to review if
confidence were the test. What saves it is the resolver's *exclusive match*: every
identifier pointing at one resource and nothing else is a repeat sighting. Anything that
changes what a probe observes must not break that.

**Discovery caches the `sysObjectID`; it does not pin a profile.** `resource.profile_id`
is a human's override. Writing it from discovery would make every swept device look like
one somebody had decided about.

**A neighbour is matched by lookup, never by resolution.** Resolution creates, and §2.5
forbids creating the far end of a link.

---

## Running it

Start `uops-server` with a KEK configured and it runs. Every minute it asks each tenant
what is due, sweeps at most one job at a time — the probe caps are per sweep, so running
two at once would double what the customer's network sees — and prints a line when
something happened. `UOPS_DISCOVERY=off` turns it off for a replica that should not have
it; the startup banner says which way it went, and says so explicitly when the reason is a
missing KEK rather than the flag.

Without equipment to point it at, `crates/uops-sweeper/tests/turn.rs` drives the whole
loop against a fake sweep and a real database, and
`crates/uops-store-pg/tests/sweep_ingest.rs` drives a real sweep against a simulated
fleet. Between them every line of the path is exercised except the UDP socket.

The demo instance has a job, a run and three candidates seeded so the screens have
content; the run and candidates were inserted as SQL rather than produced by a sweep.
