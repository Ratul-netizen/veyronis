# Guessing what a device is, and saying that it is a guess

**Status:** a decision, closed before building. **Prepared:** 24 September 2026.

---

## 1. The gap this closes

IPAM's headline number is *unaccounted*: an address answered and nothing in the inventory
claims it (`docs/ipam.md` §2.3). Today the product can say **that** and nothing about
**what**. An operator gets a list of addresses and a shrug, which turns a finding into
homework.

The same hole sits under discovery. `discovery_candidate` is *"everything a run found and
could not turn into a resource by itself"* — the residue that keeps the feature honest —
and the reason a candidate is a candidate is usually that it does not speak SNMP. So the
one class of device the product cannot identify is exactly the class it most needs help
with.

The idea comes from a scanner of the founder's own, which shows a **Device Type (guess)**
column built from vendor, hostname and ping TTL, labelled in the UI as
*"a best-effort guess … not a guarantee"*. That labelling is the part worth copying.

## 2. What evidence exists, without collecting anything new

Checked rather than assumed — all of this is already stored on `discovery_candidate`:

| evidence | where it comes from | strength |
|---|---|---|
| `sys_descr` | the SNMP probe, when it answered at all | **strong** — usually names the OS and often the model |
| `mac` | the ARP table, as `macaddr` | **good** — `uops_oui::vendor_of` resolves it, including the MA-M and MA-S blocks a 3-byte lookup misses |
| `hostname` | rDNS | weak, and conventional — `printer-3`, `ap-lobby`, `esx01` |
| TTL | **not collected** | see §5 |

That is enough to be useful now. Three independent weak signals that agree are worth more
than any of them alone, which is the whole design.

## 3. The decisions

### 3.1 A guess is a separate thing from an identity, and the types must say so

`uops-identity` decides *which resource this is*, and it is the highest-leverage component
in the system — SPEC §M0.2. It resolves on identifiers that are unique by specification and
sends anything ambiguous to a review queue. **Nothing here may feed that.**

So this is its own crate returning its own type. A `Guess` cannot be assigned to a
`ResourceKind` field by accident, because it is not one. The only way a guess becomes a
fact is a person agreeing with it.

### 3.2 Every guess carries the evidence that produced it

Not a confidence number on its own. A bare *"73% printer"* is unarguable — the reader
cannot tell whether to believe it. `Guess` carries the reasons:

> **printer** — the MAC is assigned to Zebra Technologies; the hostname contains "print"

An operator can dismiss that in a second when it is wrong, which is what makes it safe to
show. This is the same rule M11 §2.8 applies to severity and `UI-SPEC` applies generally:
the product may visualise what it knows and may not invent.

### 3.3 Agreement raises confidence; a single weak signal does not

Three tiers, and they are about *how much it would take to be wrong*:

* **Likely** — a strong signal, or two independent weak ones that agree.
* **Possible** — one weak signal.
* **Unknown** — nothing, and the product says so rather than guessing anyway.

A hostname alone never gets past *possible*. `ap-lobby` is a decent hint and it is also
what somebody calls the laptop they take to the lobby.

### 3.4 It guesses a *role*, not a `ResourceKind`

`ResourceKind` is the schema's vocabulary — `Device`, `Host`, `Service`. It answers a
different question and it is already set correctly by discovery. What an operator wants to
know about an unaccounted address is nearer to *"printer"*, *"access point"*, *"camera"*,
*"phone"* — a role. Reusing `ResourceKind` would both lose that and risk §3.1.

### 3.5 The vendor table is data, not a detection library

M11 §1's line — a detection library is a content business — applies here in miniature. The
mapping from vendor to role is a short table of the manufacturers whose whole business is
one kind of device (Zebra prints, Axis makes cameras, Polycom makes phones). It is
deliberately small and deliberately not exhaustive: a vendor that makes five kinds of thing
tells you nothing, and pretending otherwise is how a guess becomes noise.

## 4. What it will not do

**Feed identity resolution or profile selection.** §3.1.

**Be stored as though it were discovered.** A guess is computed when read. Storing it
would make a stale guess indistinguishable from a fresh fact, and the input is three
columns and a lookup table — it costs nothing to recompute.

**Claim a model.** Vendor is knowable from a MAC. Model is not, and `sys_descr` strings
that look like models are vendor-formatted prose.

## 5. TTL, and why it is not here yet

The scanner this comes from uses ping TTL, and it is a genuinely good signal: initial TTL
is 64 on Linux and most embedded stacks, 128 on Windows, 255 on a lot of network gear, so
the observed value rounds up to an OS family and the difference is the hop count.

**The product does not capture it.** Adding it means changing what the ICMP check records,
and that check does not run on the development host at all (`docs/lab.md` §5 — it needs a
Linux or macOS datagram socket). Building it blind and untested is how a signal that is
subtly wrong gets shipped.

So `Evidence` has the field, nothing populates it, and the classifier already uses it when
it is there. That is the smallest honest way to leave the door open.
