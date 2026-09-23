# Where the LLDP walk belongs

**Status:** a decision, closed before building. **Prepared:** 24 September 2026.

The gap is recorded in `docs/lab.md` §4 and in M5's reopened criterion:
`uops_discover::neighbours` reads `lldpRemTable`, `PgStore::record_neighbours` turns what
it read into exactly one `connected_to` edge per adjacency, both are tested, and **nothing
calls either**. On a real estate `GET /api/v1/topology` returns `nodes: 0, edges: 0`.

This document is about *where the caller goes*, which is the only open question — the walk
and the ingest both already exist and neither needs changing.

---

## 1. The three candidates

### 1.1 The discovery sweep — rejected

`uops_discover::run` already reaches devices with credentials, and M5 already has a rule
for a neighbour that matches nothing ("produces a candidate, not a resource"). It looks
like the obvious home and it is the wrong one, for two reasons.

**A sweep probes addresses; topology is about devices.** A sweep walks a range looking for
anything that answers. Walking `lldpRemTable` on every address that answered is a different
job that happens to be adjacent, and bolting it on makes a sweep of a /16 also an LLDP walk
of everything in it.

**A sweep is rare on purpose.** Migration 0017 puts a one-hour floor under the schedule
with the reason written against it — *"a sweep is not a poll: the estate does not change
every minute, and a job scanning more often than hourly is generating traffic a security
team will ask about"*. Topology that only refreshes when somebody sweeps is topology that
is stale between sweeps, and an incident at 03:00 would be suppressed against yesterday's
cabling.

### 1.2 A new scheduled task in the server — rejected

Consistent with how alerts and the sweep scheduler already work, and it would need its own
lease, its own credential access, and its own SNMP transports — all of which the poller
has. That is a second thing to operate for no property the poller does not already have.

### 1.3 The poller — **chosen**

The poller already does this exact thing, which is the argument. On a `Work::Discovery`
task it holds an open transport to the device, and with it:

```rust
self.record_sysobjectid(&task, transport.as_ref()).await;   // a control-plane write
self.record_discovery(&task, kind, &polled.discovered).await; // interfaces + member_of edges
```

Interface discovery is *already* a topology write to `PostgreSQL` from the poller —
`member_of` edges, through `PgStore::record_discovery`. A neighbour walk writing
`connected_to` edges through `PgStore::record_neighbours` is **the same mechanism pointed
at a second table**, on the same cadence, with the same credentials and the same transport.

It also types correctly with nothing adapted: `uops_discover::neighbours` takes a
`uops_snmp::transport::Transport`, which is exactly what the poller holds as
`Arc<dyn uops_snmp::Transport>`.

---

## 2. The decisions that come with it

**It runs on the discovery task, not on every poll.** Interface discovery already has that
cadence and neighbours change at the same rate cabling does — which is to say rarely, and
never between two five-minute metric polls. Walking LLDP every poll would multiply SNMP
traffic against every device in the estate to re-learn a fact that did not change.

**A failed walk does not fail the poll.** The same rule `record_discovery` states: the poll
that produced the metrics succeeded, and losing an adjacency refresh because `PostgreSQL`
blinked must not throw the metrics away. Reported, not fatal.

**A device that speaks no LLDP is not an error.** `neighbours()` already treats an
unreadable protocol as `Neighbours::unreadable` and walks the others — "a device that runs
one protocol and not the others is the normal case". Most of an estate's hosts have no
LLDP at all, and a log line per host per cycle would be noise that trains people to ignore
the log.

**Only a device with a management address is walked.** That is already true of everything
the poller does, and it falls out rather than needing a rule.

**The edge is recorded from whichever end saw it.** `record_neighbours` already sorts the
pair so that walking both ends produces one edge rather than two — a property its tests
assert and the schema's `UNIQUE` alone does not give. Nothing here needs to coordinate
which end walks first.

---

## 3. What this does not do

**Discover a neighbour's address.** `lldpRemManAddrTable` is a separate table many agents
do not populate; a neighbour that matches no known resource becomes a candidate, which is
M5's existing rule and is unchanged.

**Remove an edge that has gone.** A cable pulled today leaves its `connected_to` row until
something ages it out. That is a real gap and it is deliberately not solved here: deciding
when an adjacency is *gone* rather than *not seen this cycle* is its own decision, and
getting it wrong silently deletes topology. `last_seen` is maintained, so the data to
decide with is there when the decision is made.
