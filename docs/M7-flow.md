# M7 — Flow

SPEC §M7, PLAN §384: *NetFlow v9 · IPFIX · sFlow (hand-written) · traffic analytics ·
GeoIP*.

Discovery answered *what is on the network*. Topology answered *what is cabled to what*.
Flow answers the question an operator actually asks during an incident, which neither of
those can: **what is the traffic, where is it going, and what changed**.

This file closes the decisions before anything is written, the way
[`M5-discovery.md`](./M5-discovery.md) did. The ones that would otherwise be made
accidentally by whichever decoder was implemented first are §2.2 (templates are state),
§2.4 (sampling is not a detail) and §2.6 (a UDP packet has no tenant).

---

## 1. What M7 is

Three protocols, one table, and an exporter that is already a resource.

```text
   router/switch                    uops-collector-flow              ClickHouse
   ─────────────                    ───────────────────              ──────────
   NetFlow v5   ──┐
   NetFlow v9   ──┼── UDP ──▶  decode ── template cache              flows
   IPFIX        ──┤                 └──── resolve exporter   ──▶     flows_5m
   sFlow v5     ──┘                 └──── resolve endpoints
```

`uops-flow` is the decoding, with no I/O in it. `uops-collector-flow` is the binary that
binds sockets and writes rows. The same split as `uops-syslog` / `uops-collector-syslog`,
for the same reason: a parser that needs a socket is a parser nobody fuzzes.

---

## 2. Decisions

### 2.1 Four protocols, not three. NetFlow v5 is included.

PLAN names v9, IPFIX and sFlow. v5 is added because it is a fixed 48-byte record with no
templates, it is perhaps two hundred lines, and it is still what a great deal of installed
equipment emits. Leaving it out to save those two hundred lines means telling an operator
their router is unsupported when the reason is that we preferred the newer protocol.

It also earns its place as the control: v5 exercises the whole path — socket, exporter
resolution, endpoint lookup, insert — with none of §2.2's template machinery. When a v9
flow is wrong, v5 passing is what says the problem is in the templates rather than
everywhere else.

### 2.2 Templates are state, and that state is the hard part of M7.

A NetFlow v9 (RFC 3954) or IPFIX (RFC 7011) data record is **undecodable on its own**. It
carries a template ID; the template that gives each field an identity and a length arrives
in a different packet, periodically. Everything awkward about M7 follows from that.

**The cache is keyed by `(exporter address, observation domain, template ID)`** — never by
template ID alone. Template IDs start at 256 on every exporter, so two routers pointed at
one collector will both use 256 for different layouts, and a cache keyed on the ID alone
decodes one of them as the other. Silently: the fields are the right *width*, so it
produces plausible addresses and byte counts that are wrong.

**A data record that arrives before its template is dropped and counted.** Not buffered.
Buffering is the obvious alternative and it is a memory exhaustion bug with a public UDP
port in front of it — at flow volumes a template refresh interval is gigabytes, and an
attacker who never sends a template can make that happen on purpose. The counter is
exposed, because "we are dropping flow from 10.0.0.1" is a thing an operator must be able
to see rather than infer from a thin graph.

**Restarting the collector loses the cache, and there is a gap until templates re-arrive.**
That is real, it is inherent to the protocol, and it is stated here rather than discovered.
Exporters refresh on a timer — commonly 30 seconds to 10 minutes, and configurable to far
worse. The collector logs the gap as it closes, per exporter, so the hole in the data has
a line in the log next to it.

**A redefined template is a race nobody can win.** UDP is unordered, so a data record sent
before a redefinition can arrive after it, and it is not distinguishable from one sent
after. It will be decoded with the new layout and be wrong. Nothing in the protocol carries
the generation. This is accepted, not solved, and it is bounded: redefinition happens at
reconfiguration, not continuously.

**The cache is bounded** — a maximum number of exporters, and of templates per exporter.
Reached, it refuses new templates and counts the refusal rather than evicting a live one,
because evicting under memory pressure means dropping the flow of whichever exporter is
quietest.

### 2.3 The exporter is a resource. The endpoints are not.

`flows.resource_id` is the device that sent the packet, resolved from its source address.
That is a resource the operator already has, because something had to be configured to
export.

`src_resource_id` and `dst_resource_id` are filled **by lookup only, and are null when the
lookup fails**. This is M5 §2.5's rule, unchanged and for the same reason: a flow saying
`10.0.0.7 → 8.8.8.8` is not evidence that a resource `10.0.0.7` exists, and a product that
invents inventory from traffic produces an asset list nobody can trust. Most flows have a
null on at least one end — every flow to the internet does — and that is the correct
answer, not a gap to fill.

### 2.4 Sampling is stored, never pre-multiplied.

sFlow is sampled by definition: 1 packet in N. NetFlow and IPFIX can be. If 1-in-1000
sampling is in force, a flow's byte count is roughly a thousandth of the traffic it stands
for, and a sum over the table is off by three orders of magnitude.

**Both the observed counts and the sampling rate are columns, and the multiplication
happens at query time.** Two reasons, and the second is the one that matters.

Pre-multiplying is lossy: `bytes × rate` cannot be taken apart again, so the number of
packets actually seen — the thing that says how much to trust the estimate — is gone.

And it launders an estimate into a fact. A stored `bytes` that is really `bytes × 1000` is
indistinguishable from a measurement, and every screen downstream will present it as one.
UI-SPEC's rule is that the product may visualise backend truth and may not invent it; an
extrapolation written into the storage layer is an invention that no screen can see past.

**The declared DDL in `ch-migrations/deferred/traces_flows.sql` has no sampling column and
must gain one** before it is promoted. That file was written in M0 to settle the sort key
and the tenant column, and this is the thing it got wrong — recorded here rather than
quietly fixed, because the DDL is the artefact the rest of the codebase was written
against.

### 2.5 Flow is not logs, and its retention cannot be.

Flow is the highest-volume signal this product ingests, by a wide margin: a busy edge
router emits tens of thousands of records a second, none of which is interesting on its
own. The declared DDL gives `flows` and `traces` the same 30-day TTL. For flow that is
wrong in the expensive direction.

**Raw flow is kept for days; the aggregate is kept for the long window**, the same shape
`metrics`/`metrics_5m`/`metrics_1h` already has and for the same reason. The aggregate is
by `(tenant, exporter, src, dst, port, protocol)` into five-minute buckets, because that is
what every question on the screen is: top talkers, what changed, who is this host speaking
to. The raw table answers "show me the actual conversations in this minute", which is an
investigation, and investigations are recent.

The exact retentions are a number to pick with a measurement rather than an opinion, and
W1's method is the one to copy.

### 2.6 A UDP packet has no tenant, so the port decides.

This is the same problem syslog has, and it gets the same answer, deliberately: **one
listener per tenant, named in a configuration file**. A datagram's tenant is decided by the
socket it arrived on, not by anything inside it.

The alternative — resolve the exporter address to a resource, and take that resource's
tenant — is rejected. It means an unauthenticated packet selects its own tenant by
choosing a source address, so a forged packet writes into whichever customer the attacker
names. For an MSP that is a cross-tenant write triggered by a spoofed UDP datagram, which
is the worst class of bug this architecture exists to make impossible. Tenancy in this
product is a type (`TenantScope`) and a composite foreign key precisely so that it is never
decided by attacker-controlled input.

**An exporter that is not in inventory is not dropped.** It is resolved like any other
sender: `uops_pipeline::Pipeline::attribute` matches it, or creates a provisional resource
and a review item, and the flow is stored against whatever came back.

This paragraph used to say the opposite — that an unresolved exporter was dropped and
counted, because "the port says which tenant; the inventory says whether this device is
allowed to speak into it". That was written without checking what the collector it claims
to copy actually does, and it is wrong twice over.

It contradicts **SPEC §M0.2 rule 1, *never block ingestion***, which is a product-wide rule
and not a syslog one. And `uops-collector-syslog`'s own configuration file records the
argument, having already had it: an allow-list posture "loses the logs of every device
somebody forgot to register — which are disproportionately the devices involved in an
incident, because an unregistered device is one nobody is watching." Flow makes that
sharper rather than softer. An exporter nobody registered is precisely the one whose
traffic gets asked about at 3 a.m.

The security concern behind the original wording is real and is answered where syslog
answers it: at the firewall, where it is one rule rather than a second identity system
inside the product. What the port decides — which tenant — is not weakened by any of this,
and that is the decision this section exists to record.

### 2.7 GeoIP is optional and never bundled.

PLAN names GeoIP. MaxMind's GeoLite2 needs an account and a licence key, and its terms
restrict redistribution — so it cannot ship in the image, cannot be vendored, and cannot be
a build dependency without dragging the whole `deny.toml` discipline somewhere it should
not go.

So: the database is **operator-supplied, by path, and absent by default**. Every screen
works without it, showing an address where it would have shown a country. A feature that
degrades to "slightly less annotated" is one an air-gapped customer can simply not have;
one that degrades to a blank panel is a support ticket.

### 2.8 The decoders are hand-written, and fuzzed.

Hand-written, consistent with `uops-snmp`, `uops-syslog` and `uops-otlp`. These are
binary parsers reading attacker-reachable input off an unauthenticated UDP port, which is
the highest-risk code in the product. Every one of them takes a length from the packet and
uses it to slice a buffer.

The workspace forbids `unsafe`, so the failure mode of a bad length is a panic rather than
a read out of bounds. A panic in a collector is still a denial of service, so the decode
path returns `Result` and the receive loop treats a malformed packet as one dropped packet,
never as a reason to stop.

**Fuzzing would be new.** There is no `cargo fuzz` setup in this repository today, and the
existing decoders do not have one — so this is a thing M7 introduces, not a convention it
follows. It is worth introducing here because IPFIX is the first format in the product
with attacker-controlled *field lengths* driving the parse, which is the shape that
historically breaks. If it earns its keep, the other three decoders should get it too; that
is a separate piece of work and is not smuggled into M7's acceptance.

---

## 3. Schema

Promoted from `ch-migrations/deferred/traces_flows.sql`, amended per §2.4 and §2.5.

```sql
flows          -- one row per flow record, raw, short retention
flows_5m       -- the aggregate every screen actually reads
```

Sort key `(tenant_id, resource_id, observed_at)`, unchanged and not negotiable — SPEC's
Investigation Workspace decision, and changing it is a full re-ingest.

`src_address`/`dst_address` stay `IPv6`, with IPv4 stored mapped. One column, both
families, one set of predicates: the alternative is every query having to know which of two
column pairs to read.

---

## 4. Acceptance criteria

- [x] A NetFlow v5 export from a simulated exporter produces one row per record, with the
      exporter resolved to its resource
- [x] A NetFlow v9 export whose template arrives **after** its first data packet decodes
      the later records and counts the dropped ones — and the count is visible, not just
      logged
- [x] Two exporters both using template ID 256 for different layouts are decoded
      correctly, which is the cache-key decision in §2.2 stated as a test
- [x] An IPFIX export with a variable-length field decodes, and one whose declared length
      runs past the end of the packet is one dropped packet rather than a panic
- [x] An sFlow v5 sample carries its sampling rate into the row, and a query that sums
      bytes multiplies by it — asserted against a known rate, because this is the one that
      is wrong by a factor of a thousand when it is wrong
- [x] A flow whose endpoints are not in inventory is stored with null endpoint ids and
      creates no resource
- [x] A packet from an exporter that is not in inventory produces a provisional resource
      and a review item rather than a dropped packet — SPEC §M0.2 rule 1
- [ ] A packet arriving on tenant A's listener cannot produce a row in tenant B, whatever
      it claims — the isolation test, as an adversarial case
- [ ] Each decoder survives a fuzzing run without a panic
- [x] The suite runs against the live ClickHouse and the flow queries return correct rows
      on a server whose timezone is not UTC — see `docs/dev-environment.md`

---

## 5. What M7 does not do

**Packet capture.** Flow is a summary of conversations. Full packet capture is a different
product with a different storage cost and a very different legal posture: payloads carry
personal data in a way that a record of "this address spoke to that one" largely does not,
and Bangladesh's Personal Data Protection Act 2026 makes that distinction expensive to get
wrong.

**Deep packet inspection.** No application identification by payload signature. A port and
a protocol are what a flow record contains, and claiming more than that from it would be
inventing backend truth.

**Blocking.** Flow tells you what is happening. Acting on it is M9.x Response, behind an
incident and an authorization, and deliberately not a button that appears next to a graph.
