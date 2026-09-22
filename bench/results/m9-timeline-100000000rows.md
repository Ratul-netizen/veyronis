# M9 — the timeline, at 100M rows per signal

`docs/M9-incident.md` §4 closed with an obligation rather than a claim: *"The timeline for
a one-hour incident over 100M rows is answered from the sort key, measured rather than
assumed."* This is the run.

- `bench.logs`: `100000000` rows, 3.03 GiB, 12 259 granules
- `bench.spans`: `100000000` rows, 8.26 GiB, 12 268 granules
- tenants: 3 · hosts: 5 000 · range: 7 days
- ClickHouse `26.8.9.10`, 4 cores, 8 GB, in a VM
- harness: `bench/scripts/load.sh` then `bench/scripts/m9.sh`
- the query is `uops_query::timeline::one` verbatim: a one-hour window, two resources,
  `ORDER BY observed_at ASC LIMIT 500`

---

## What was being tested

PLAN §6 named the Investigation Workspace at M0 **because it constrained M0's decisions**:

> every store must answer "all signals for resource R in window W" cheaply — that dictates
> `ORDER BY (tenant_id, resource_id, observed_at)` on every telemetry table, a decision
> that is nearly free now and a full re-ingest later.

Six milestones later, the bill for that decision comes due in one query. The claim is that
a timeline is N *contiguous range reads* rather than N scans — which shows up as **rows
read**, because that is the property of the sort key. The wall clock that follows moves
with the page cache and the host.

## The result

| track | rows read | ms | rows returned |
|---|---:|---:|---:|
| `logs`, by resource | **40 960** | 24 | 87 |
| `spans`, by resource | **65 536** | 34 | 77 |

Forty thousand rows is **five granules out of 12 259**. The two tracks together read
106 496 rows and took 58 ms of server time.

### What the M0 decision bought, priced

The same hour with the resource predicate removed — which is what one track would cost if
the sort key led with time, the design M0 rejected:

| track | rows read | ms |
|---|---:|---:|
| `logs`, whole tenant | 3 735 552 | 216 |
| `spans`, whole tenant | 4 415 488 | 105 |

**77× fewer rows** for the timeline as a whole: 8.15M against 106K. On logs alone the
factor is 91×, on spans 67×.

That is the sort key working exactly as the M0 note said it would, and it is the first
time the number has been put next to the claim.

## Against W1's 9 ms — **not beaten, and the reason is visible**

§4 said *"W1's 9 ms is the number to beat"*, referring to W1's Q05 (*all signals for one
resource*) at 9 ms over 16 380 rows. This run is 24 ms over 40 960 rows for the log track.

It is **slower per query and the same speed per row**, and the difference is that the two
queries are not the same question:

- W1's Q05 read **one** resource; this reads two, which is what an incident's membership
  looks like after a cascade groups a switch with a host.
- This carries `ORDER BY observed_at ASC LIMIT 500`, which W1's did not.
- The window here is a full hour rather than W1's narrower slice.

So the honest statement is: **the architectural claim is proven and the 9 ms target is
not met**. Nothing about the shape changed — it is still a range read of a handful of
granules — there is simply more of it. A screen budget of 58 ms for two full-scale tracks
is comfortable, and it is the number to compare against next time rather than W1's.

## What this run does *not* cover

**Four of the six tracks were empty.** `bench` holds logs and spans; events, states,
metrics and flows ran the same statement against nothing. A full six-signal timeline at
this scale would be roughly three times the work measured here — call it 150–200 ms of
server time — and that extrapolation is stated rather than measured.

It is a fair extrapolation because every one of those tables has the *same* sort key and
the same query shape, which is the whole point of the M0 decision. It is still an
extrapolation.

**Nothing here measures the merge.** Interleaving a few hundred rows by timestamp happens
in the browser; it is a sort of at most 3 000 items and was not worth a harness.

---

## Method notes

**Every query was cold.** The M8 run learned this the expensive way: ClickHouse remembers
which granules matched a predicate, so repeating a query measures that memory rather than
the index — it reported an identical, plausible, wrong number for every configuration
including no index at all. The resource pair and the window here had not been queried
before.

**Statistics come from the `FORMAT JSON` body**, not from `X-ClickHouse-Summary`, which is
sent before the query finishes unless progress headers are configured. That header
produced a believable 40 960 for a full scan during the M8 run.

**The load took 687 s at ~146 000 rows/s** on the 8 GB guest, against ~154 000 rows/s for
spans on the 3.8 GB one. Memory was not the loader's constraint; it was the merges
afterwards that took the smaller guest down.
