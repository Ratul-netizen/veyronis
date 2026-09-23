# The path to a device

**Status:** a decision, closed before building. **Prepared:** 24 September 2026.

---

## 1. The gap

The product knows *adjacency* and not *path*. Topology is `connected_to` edges from LLDP —
layer 2, and only between devices that both speak it and that the product polls. When an
operator asks **"why can't I reach this"**, there is nothing to answer with.

That is a real hole in the investigation spine. An incident now pivots to a resource, to its
signals, to the topology — and stops at the point where the question becomes *where does the
traffic actually go, and where does it stop going*.

The idea and several of the details come from a scanner of the founder's own, which draws a
hop-by-hop graph, plots latency per hop with loss markers, and — importantly — never plots a
private address on a map, because there is no such place.

## 2. How the probe is made

**By running the operating system's own `traceroute`, as a child process.**

This is the decision M10 §2.10 already made for SSH, for the same reasons and with the same
discomfort. The alternatives:

* **Raw sockets.** The correct way, and it needs privileges the product deliberately does
  not take. `docs/lab.md` §5 records that even the *unprivileged* ICMP datagram socket the
  poller uses is a Linux and macOS facility with no Windows equivalent — so a hand-rolled
  tracer would not run at all on a Windows host, and could not be tested on the machine
  this was built on.
* **A crate.** The maintained ones want raw sockets, which is the same problem with an
  added dependency.

`tracert` on Windows and `traceroute` on Unix are present, unprivileged for the caller, and
already trusted by every operator who has ever debugged a path. What they cost is a parser
per platform, and parsing another program's prose is a genuine liability — §3 is about
containing it.

## 3. The parser is the risky part, so it is the tested part

`tracert` output is *prose*, and prose changes with version and locale. The mitigations:

**The parser is pure and exhaustively tested against captured real output**, including the
cases seen within five minutes of looking: `<1 ms` for a sub-millisecond hop, `*` for a
timeout, and a line reading `192.168.1.171 reports: Destination host unreachable.` which is
**not a hop at all** and which a naive line-per-hop reader would record as one.

**A line that does not parse is skipped, never guessed at.** A hop invented from a
misparsed line is worse than a missing one: it puts an address on a path it was never on.

**The raw output is kept and returned.** Whatever the parser made of it, the operator can
read what the command actually said — the same instinct behind M10 keeping a run transcript.

## 4. What the product says about a hop

**Where it is, in one of four scopes** — and this is taken directly from the founder's
scanner, which is right about it:

| scope | meaning |
|---|---|
| `private` | RFC 1918. Inside the estate. |
| `carrier_grade` | RFC 6598 `100.64.0.0/10`. The ISP's own space — outside the estate, and **not** the public internet. |
| `link_local` | RFC 3927 `169.254.0.0/16`. A link with no address assignment. |
| `public` | Everything else. |

The distinction earns its place immediately: the first real trace taken on this machine
crossed `10.153.77.1` and then `100.64.170.170`. A two-way inside/outside split would call
the second one "outside" and imply it is on the internet, which it is not — it is the
carrier's. An operator chasing a path needs to know where their responsibility ends, and
that boundary is exactly where CGNAT begins.

**Never a geographic location for a private or carrier-grade hop.** There is no such place.
Geolocation is not built here at all (§6), and this rule is written down now so that when it
is, the rule is already the product's rather than something remembered later.

## 5. Where it runs and who may ask

**An operator, not a viewer.** A traceroute sends packets from the product to a target an
operator names. That is an outbound action against an address the product was not
necessarily configured to touch, and it is audited for the same reason a runbook run is.

**Rate-limited and bounded.** A maximum of 30 hops and a hard timeout, because the failure
mode of an unbounded trace is a request that never returns and a process holding a child
forever. `uops-runner` learned this about SSH and the lesson transfers.

**The target is validated before anything is spawned.** Only a literal IPv4 address or a
hostname of the shape a resolver accepts — never a shell metacharacter, and never passed
through a shell. The argument vector is built directly, exactly as `uops_runner::ssh` does,
and for the same reason.

## 6. What this does not do

**Geolocation.** The founder's scanner plots public hops on a world map from a local
GeoLite2 database, and it is genuinely useful — for flow endpoints as much as for hops.
It is not here because MaxMind's terms mean the product cannot ship the database, only read
one an operator supplies, and that is a distribution and configuration decision of its own.
§4's scope rule is the half that belongs in this change.

**A hop graph drawn as a diagram.** The first version is a table with a latency bar per
hop, which answers "where does it stop" without a layout engine. The graph is worth having
and is not worth blocking this on.

**Storing traces.** A traceroute is a question asked now. Keeping a history of them is a
different feature with a retention decision attached, and nothing yet asks for it.
