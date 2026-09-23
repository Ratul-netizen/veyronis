# Address management, and the three tables it does not need

**Status:** decisions, closed before building — the practice every milestone document here
follows. Scoped as `docs/PRODUCT-STRATEGY.md` **Stage 1b**.

**Prepared:** 23 September 2026.

---

## 1. Why this is small

IPAM is a separately-licensed add-on in the product family this one is measured against:
ManageEngine sells it beside NCM, NetFlow Analyzer, Firewall Analyzer and APM, and
OpManager Nexus exists to bundle the five. Three of those five are already core here. This
is one of the two that are not.

It is also, in this codebase, **mostly a view over data that is already collected**:

| What IPAM needs | Where it already is |
|---|---|
| Which ranges an estate uses | `discovery_job.ranges cidr[]`, declared by an operator |
| Which addresses answered | `discovery_candidate.address inet` |
| Which addresses belong to a known device | `resource_identifier` where `kind = 'mgmt_ip'` |
| Which MAC is behind an address | ARP, already walked by `uops-discover` |
| When each was last seen | `resource_identifier.last_seen`, `discovery_candidate` |

**So the work is not collection. It is one declaration the product cannot infer, and a set
of queries over what it already knows.** That is the whole reason this is Stage 1b and
cheap, and it is the reason to write the decisions down: a module that looks this cheap is
one somebody will be tempted to build as a screen with four ad-hoc queries behind it.

---

## 2. The decisions

### 2.1 A subnet is declared, not discovered

**Decided: one small table, `subnet`, holding what an operator says.**

The tempting alternative is to derive the subnet list from `discovery_job.ranges` — the
data is there and it needs no schema at all. It is wrong twice:

* **A sweep range is not a subnet.** A job that scans `10.0.0.0/16` scans two hundred and
  fifty-six /24s. Utilisation over the /16 is a number nobody can act on.
* **A subnet an operator cares about is not always one they sweep.** A DHCP scope, a
  point-to-point link, a range reserved for a project that has not been built — all are
  address space to manage and none is a sweep target.

Deriving would also make the *discovery* configuration load-bearing for an unrelated
feature, so editing a sweep would silently change the address inventory.

**What the table holds is only what cannot be computed**: the range, what it is called, who
it belongs to, and optionally which site. Everything else on the screen is derived, because
a stored utilisation figure is a figure that is wrong between refreshes.

### 2.2 IPv4 only, and the schema says so

The same decision migration 0017 made for sweeps, for the same reason, written the same
way: on a /64 the arithmetic returns a number with no meaning. `masklen` capacity maths is
IPv4 maths.

**IPv6 is not "later, maybe".** It is a different feature — address space that cannot be
enumerated, where the questions are *which prefixes are delegated* and *what is actually
in use*, not *how full is this*. Pretending a /64 has a utilisation percentage would be
the product stating something false, which §2.6 below refuses in general.

A `CHECK (family(range) = 4)` makes it a schema fact rather than a handler's good
intentions.

### 2.3 Utilisation is computed at read time, from two sources that are not equal

An address in a subnet is **known** if either:

1. a resource claims it — `resource_identifier`, `kind = 'mgmt_ip'`; or
2. a discovery candidate answered on it — `discovery_candidate.address`.

**These are deliberately not merged into one number.** They answer different questions:

* *assigned* — this address belongs to something in the inventory;
* *responding* — something answered here and the product does not know what it is.

An address that is responding and not assigned is the interesting one: it is either a
device nobody inventoried or a device somebody plugged in. Collapsing both into "used"
would throw that away, and it is the finding IPAM is bought for.

**Capacity** is `2^(32 - masklen)`, with the network and broadcast addresses excluded for
prefixes shorter than /31. A /31 is a point-to-point link with two usable addresses and a
/32 is one host — RFC 3021 — and the ordinary formula returns zero and a negative number
respectively. Both are common in a routed estate, so the arithmetic handles them rather
than the screen apologising for them.

### 2.4 A conflict is two resources claiming one address, and it is not an error

The schema already refuses two identifiers with the same `(tenant, kind, value)` — that
constraint is the identity mechanism, and a violation goes to the review queue. So a
conflict *within* `resource_identifier` cannot exist by construction.

What can exist, and what this reports, is **an address claimed by a resource and also
answering as an unclassified candidate whose identity does not match**. That is a real
operational finding — a re-IP that half-completed, a DHCP lease handed to a device with a
static neighbour — and it is a *report*, never an alert. The product does not know which of
the two is right.

### 2.5 Reclaim is a suggestion with its evidence attached

An address that was assigned and has not been seen for a long time is a **candidate** for
reclaim. The product says how long, and never releases anything: releasing an address is a
change to somebody else's network, and M10's whole safety model exists because this product
writes to estates only through an approved, dry-runnable, audited path. An IPAM screen with
a "free this address" button would be that path reinvented with none of the guards.

### 2.6 What this will not claim

* **That a subnet is full.** It reports assigned, responding and capacity, and lets a
  reader divide. "97% full" hides whether the other 3% is reserved.
* **That an unassigned address is available.** The product sees what answered. A device
  that is switched off answers nothing and still owns its address.
* **A DHCP scope's contents.** The product does not speak to DHCP servers. A range the
  operator marks as DHCP is labelled so its utilisation is read correctly, and that label
  is a declaration, not an integration.

> **The honest limit, stated once:** without a DHCP or DNS integration this is an inventory
> of *what the estate said*, not an authoritative address registry. For the on-premise,
> multi-vendor, network-first buyer this is the common case and is most of the value —
> they currently keep it in a spreadsheet. It is not a replacement for an authoritative
> IPAM in an estate that already runs one, and the screen should not imply it is.

---

## 3. What is built

* Migration **0028** — the `subnet` table, tenant-scoped, IPv4-checked, with the capacity
  function beside it so the arithmetic lives in one place.
* `uops_store_pg::ipam` — subnet CRUD and the two derived reads: utilisation and the
  address list for one subnet.
* Routes under `/api/v1/subnets`, in `isolation.rs` like every other surface.
* A screen under **Network**, beside Discovery, because address space is inventory.

## 4. What building it taught

Added after the fact, in the practice the milestone documents use: a decision document that
turned out to be wrong somewhere is worth more with the correction attached than without.

**§1 was right that this is small and wrong about where the difficulty is.** "Mostly a view
over data that is already collected" held — one table, no collection, no new protocol. But
three of the queries are plausible and wrong when written the obvious way, and each wrong
version returns a believable number:

1. **A join instead of correlated subqueries double-counts.** An address that is both
   assigned and responding is the *ordinary* case, not the exception: a device that was
   discovered and then classified keeps its candidate row. A joined count reports a /24
   with two devices in it as having four.
2. **An inner join drops the finding.** The addresses worth surfacing are the ones present
   in one source and absent from the other — which is exactly what an inner join removes.
   It has to be a full join, and the test that catches this is the one asserting a
   never-classified address is still listed.
3. **The textbook capacity formula is wrong for two ordinary prefixes.**
   `2^(32-masklen) - 2` gives **0** for a /31 and **−1** for a /32. A routed estate is full
   of both: every point-to-point link and every loopback. The function in 0028 handles them
   and the test pins all five prefix lengths.

**None of these is a schema problem and none fails loudly.** The lesson worth carrying into
NCM — the other Stage 1 module — is that high substrate reuse predicts how *big* a module
is and says nothing about where its defects will be.

**The isolation test earned its keep immediately.** `GET /api/v1/subnets/{id}/addresses`
answered `200 []` for a range belonging to another tenant, rather than 404. Nothing leaked,
and that is why it is worth writing down: the bug was not a disclosure, it was that the
owner of a genuinely empty range and somebody probing another tenant's ids received the
same answer. `subnet_addresses` now returns `None` for a range that is not the caller's,
and the decision lives in the store because that is where the scope is.

---

## 5. What is not

Reservations, DHCP and DNS integration, IPv6, and any form of assignment. Each is a
decision of its own and none is needed to answer *"what is in this range and what is
responding that should not be"*, which is the question this exists for.
