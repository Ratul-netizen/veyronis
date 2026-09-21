# M8 — Observability

SPEC §M8, PLAN §385: *OTLP traces · APM · service map · log↔metric↔trace correlation*.

M7 answered *what is the traffic*. M8 answers the question underneath an application
incident: **which service is slow, and what was it waiting for**.

Written before anything is built, the way [`M5-discovery.md`](./M5-discovery.md) and
[`M7-flow.md`](./M7-flow.md) were. The decision that would otherwise be made accidentally
by whichever file was written first is §2.1 — what a span's `resource_id` points at — and
it is the one that cannot be changed afterwards, because it is the sort key.

---

## 1. What M8 is

```text
   instrumented app ──OTLP──▶ uops-collector-otlp ──▶ spans ──▶ service_5m
                                     │                  │
                                     │                  └── logs.trace_id already joins
                                     └── resolve host AND service
```

Three of the four pieces already exist and are doing nothing.

* **`POST /v1/traces` accepts and discards**, with a counter and a partial-success
  message saying so — SPEC §M3 asked for exactly that so instrumented applications would
  not error while the store was missing.
* **`logs.trace_id` and `logs.span_id` are columns**, populated since M3. The join that
  makes correlation possible is already on disk; there is simply nothing on the other end
  of it.
* **`ResourceKind::Service` exists**, declared in M0 and never yet constructed.

So M8 is less "build observability" than "connect four things that were each built
expecting the others".

---

## 2. Decisions

### 2.1 A span belongs to a host *and* a service, and the table stores both.

This is the decision with no second chance, because `resource_id` is in the sort key and
SPEC says changing that is a full re-ingest.

A span has two honest subjects. It ran on a **host**, and it is work done by a
**service** — and one service runs on many hosts while one host runs many services.
Picking either alone loses something real:

* Keyed by host, *"the checkout service's p99"* — the question APM exists to answer —
  becomes a scan across every host that runs it.
* Keyed by service, a span no longer sits beside the logs and metrics of the machine it
  ran on, which breaks SPEC's Investigation Workspace promise that **all signals for
  resource R in window W is one contiguous range read**.

So: **`resource_id` is the host, and `service_id` is a second column.** The sort key stays
`(tenant_id, resource_id, observed_at)`, identical to every other telemetry table, and the
service is reached through the aggregate in §2.4, which is ordered service-first for
exactly the reason `logs_counts_5m` is ordered time-first.

Both are real resources. `uops-otlp` already turns OTel resource attributes into an
`ObservedIdentity`, and it already carries `service.name` — at confidence **0.60 and
deliberately last**, because, as that file says, a service name maps to many resources
rather than one host. That weighting is correct and stays. What changes is that a service
becomes a resource *of its own*, resolved separately, rather than a weak hint about which
host sent the payload.

**What that cost, found while building it.** An identifier belongs to exactly one
resource — `UNIQUE (tenant_id, kind, value)`, which is the constraint the whole resolver
is shaped around. So `service.name` could not stay on the host identity *and* become the
service's: whichever resolved first would claim it, and the other would match it at 0.60,
land under the auto-merge bar, and arrive as a provisional resource with a review item.
Every machine in a fleet, from its own traffic.

So there are now two identities rather than one: `identifiers()` asks which **host** and
offers `host.id` and `host.name`; `service_identifiers()` asks which **service** and
offers exactly one identifier, which is what lets a repeat export match instead of
scoring. The consequences, both tested:

* A payload with **no host keys** — an SDK without `resourcedetection` — offers no host
  identity at all, and an identity with no identifiers must never be resolved, because
  that creates a resource on every call. The rows attribute to the service and both
  columns hold it: one thing was described, and inventing a host to fill a column is
  worse than saying so.
* The service identifier is `namespace/name` when `service.namespace` is set, because two
  teams really do both run a `checkout`.

### 2.2 The sort key cannot answer "show me this trace", and a skip index is the answer.

The commonest trace query is a lookup by `trace_id`, and the sort key leads with the
resource. Nothing about `(tenant, resource, observed_at)` helps find one trace whose spans
are scattered across a dozen services on as many hosts.

The declared DDL already carries `INDEX idx_trace trace_id TYPE bloom_filter GRANULARITY
1`, which is the right mechanism: it prunes granules so a lookup reads a handful rather
than the tenant.

**It must be measured rather than assumed.** W1's method — a populated table and a real
query, not a plan — is the one to copy, and the number to record is granules read for a
single-trace lookup at 100M spans. The alternative if it disappoints is a
`trace_id`-ordered projection, which is the same shape as the `p_by_time` projection W1
already added to `logs` for the tail, and it costs storage the same way.

### 2.3 Traces are sampled, and unlike flow they cannot be scaled up.

M7 §2.4 stored a sampling rate beside the counts and multiplied at read time. **That does
not work here**, and the difference has to be stated or somebody will assume it does.

sFlow tells you it sampled 1 in N. Tracing does not: head sampling happens in the SDK and
tail sampling in a collector, both upstream of us, and the span that was not sampled is
simply *absent* with nothing left behind to say so. OTel's `tracestate` may carry a
sampling probability and frequently does not.

So M8 **stores what arrives and never extrapolates**. A count of traces is a count of
*sampled* traces, and every screen that shows one says so. Where a probability *is*
present it is stored in a column and shown, but it is not applied — the same rule as
flow, reached from the opposite direction: there the rate was reliable and the
multiplication was safe; here it is neither.

The consequence worth writing down: **latency percentiles are trustworthy and counts are
not.** A p99 over sampled spans is a good estimate of the p99 over all spans; a count of
sampled spans is a fraction of the truth with an unknown denominator. Screens may present
the first as a measurement and must present the second as a sample.

### 2.4 Raw spans keep days; the service aggregate keeps the long window.

The `flows` lesson, unchanged and for the same reason. `ch-migrations/deferred/traces.sql`
declares a 30-day TTL, and that file's own header now warns that its retention and its
column list were declared before anything filled them — which is how `flows` ended up
without a sampling column.

Raw spans answer *"show me this trace"*, which is an investigation and therefore recent.
The aggregate answers *"is checkout slower than last week"*, which needs the long window
and does not need individual spans.

**The aggregate is by `(tenant, service, operation)` into five-minute buckets**, holding
request count, error count, and latency as an *aggregate state* rather than a number.
Percentiles cannot be summed or averaged — a p99 of p99s is not a p99 — so this is
`AggregateFunction(quantilesTDigest, …)`, merged at read time, exactly as `metrics_5m`
stores `avgState` rather than an average.

### 2.5 Correlation is the point, and half of it already works.

`logs.trace_id` has been populated since M3. The moment spans exist, *"the logs emitted
during this trace"* is a query against a column that is already there, and *"the trace
this log line belongs to"* is the same join read backwards.

What M8 must not do is build a second, parallel way to relate them. There is one identity
model and one query AST, and a trace is a signal in that AST — `SignalType::Trace` already
exists and already compiles to a refusal, the same state `SignalType::Flow` was in before
M7.

### 2.5b What the planner turned up: a trace id is shaped exactly like a UUID.

Found by the first golden fixture that looked a trace up by id, and worth writing down
because it had been wrong since M3 without anyone being able to hit it.

A trace id is 32 hex characters. A UUID with its dashes removed is 32 hex characters. The
query AST's `Value` is `#[serde(untagged)]`, so `"4b4b4b4b…"` off the wire deserialises
into `Value::Uuid` and compiles to `{p:UUID}` — against `trace_id`, which is a `String`
column on `spans` *and* on `logs`. The statement is a type error at the server.

So the compiler binds by the **column** rather than by what JSON happened to parse: a
comparison against `trace_id`, `span_id` or `parent_span_id` binds a `Value::Uuid` as its
32-character hex form. `logs.trace_id` has been a `String` since M3, so §2.5's join was
mistypeable for as long as the column has existed; nothing hit it because there were no
spans to look up.

### 2.6 A service map is derived, never configured.

A service map is what the spans already say: a parent span in service A with a child in
service B *is* an edge, and there is no second source of truth to reconcile. It is
computed from the aggregate and never stored as its own configured topology.

That also keeps it honest in the way M6's topology is: the edges are evidence, not
assertion, and an edge disappears when the calls stop rather than when somebody remembers
to delete it.

---

## 3. Schema

Promoted from `ch-migrations/deferred/traces.sql`, and read with the suspicion its own
header now asks for.

```sql
spans        -- one row per span, raw, short retention
service_5m   -- request count, error count, latency states, per service per operation
```

**The table is `spans`, not `traces`.** The deferred file calls it `traces`, and a row in
it is one span — a trace is the set of them sharing a `trace_id`, and is never a row
anywhere. SPEC already has the distinction right in the trait it declared in M0:
`TraceStore` stores `SpanRow`. Renaming the table to match costs nothing now, because
nothing has been created, and a table whose name disagrees with its rows is a name that
will mislead every reader of every query for as long as it exists.

Sort key `(tenant_id, resource_id, observed_at)` on `spans` — §2.1, and not negotiable.
`service_5m` is ordered service-first, because every question it answers starts with a
service.

The declared table is missing at least `service_id` (§2.1), a column for a sampling
probability when one is present (§2.3), and `duration_ns` is there but `status_code` will
need a companion for the error *count* the aggregate needs. Expect to find more; that is
what promoting a deferred file is for.

---

## 4. Acceptance criteria

- [x] An OTLP trace export produces one row per span, with the host resolved to a resource
      and the service resolved to a *separate* resource
- [x] Two hosts running one service resolve to two host resources and one service resource
      — and raise nothing for review, which is the assertion that makes §2.1 load-bearing
- [x] `POST /v1/traces` stops reporting partial success, because the spans are now stored
- [~] A trace is retrievable by `trace_id` — through the AST, against the live server.
      The granules that lookup reads are **not** measured yet; that needs a populated
      table and W1's method, and §2.2 is explicit that assuming is not enough
- [ ] The logs emitted during a trace are retrievable by joining on `trace_id`, using the
      column that has been populated since M3
- [x] A p99 read from `service_5m` over a week agrees with the same p99 computed from raw
      spans over an hour of that week, within the tolerance a t-digest allows
      — `a_percentile_survives_the_aggregate`, against the live server
- [ ] A span count is never presented as a total; the screen says it is a sample — §2.3
- [ ] A service map edge appears because a parent span in one service has a child in
      another, and disappears when the calls stop
- [x] Spans from tenant A are unreachable from tenant B, by the same adversarial test M7
      used
- [ ] The suite runs against the live ClickHouse, on a server whose timezone is not UTC

---

## 5. What M8 does not do

**Profiling.** No continuous profiler, no flame graphs from sampled stacks. That is a
fourth signal with its own storage shape, and OTel's profiling signal was still moving as
this was written.

**Instrumentation.** The product receives OTLP; it does not ship agents or
auto-instrumentation. An application is instrumented by its own team with the vendor's SDK,
and a monitoring product that insists on its own agent is one that gets refused at the
first security review.

**Trace-based alerting.** M9 territory. Alerting on a p99 from `service_5m` is an ordinary
metric rule once the aggregate exists, and that is where it belongs.
