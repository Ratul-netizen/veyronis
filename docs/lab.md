# The lab the product is tested against

**Written:** 24 September 2026, after the first end-to-end run against it.

Every test in this workspace before this one replaced at least one end: a scripted SNMP
agent, a fixture of LLDP rows, a `Scripted` transport. That is the right way to test
orchestration, and it cannot find the class of defect where a component is correct,
tested, and **never called**. This estate exists to find those, and it found one on the
first run — see §4.

---

## 1. What it is

Four Debian nodes under EVE-NG, cabled into a tree rather than a segment:

```text
                Mgmt — bridged to the real LAN, eth0 on every node
                 │
   edge-fw ── core-sw-01 ── lb-01
                    └────── app-01
```

The shape is deliberate. `core-sw-01` is upstream of both leaves, so taking it down should
produce **one incident with two suppressed symptoms** — which is the only way to exercise
M9's topology-aware suppression against discovered adjacency rather than a fixture.

**Every node speaks what the product actually reads**, and nothing more:

| | why it is there |
|---|---|
| `snmpd`, v2c | MIB-2 `system` and `interfaces` — polling, and `sysObjectID` for identity |
| `lldpd` with `-x` (AgentX) | hands LLDP-MIB to snmpd. **Without AgentX there is no LLDP in SNMP at all** |
| `rsyslog`, RFC 5424 | the log collector's input |
| ICMP | availability — though see §3 |

## 2. Why these images and not vendor ones

Cisco, Palo Alto, F5 and Fortinet images require an entitlement, and the usual way people
obtain them is not a way this project will. Debian with `snmpd` and `lldpd` produces
*genuine* SNMP and *genuine* LLDP — the protocols are the same ones a switch speaks, and
they are what the product consumes. A licensed image, if one is available, drops into
`/opt/unetlab/addons/qemu/` and joins the same topology.

## 3. Three things building it taught, all of them about cloning

Recorded because each one cost a boot cycle and each will recur for anyone building a
golden image.

1. **A cloud image has no networking without a datasource.** `debian-genericcloud`
   delegates its network configuration to cloud-init, and an EVE-NG node has no cloud-init
   datasource, so the first four nodes booted with no addresses at all. Fixed with a
   `systemd-networkd` wildcard unit, which also brings the data-plane links up with
   link-local addressing — LLDP has to run on the links that form the topology, not only
   on the one the product polls over.

2. **Clones share `/etc/machine-id`, and systemd-networkd derives its DHCP client
   identifier from it.** All four nodes were handed the *same lease*, `192.168.1.237`.
   Fixed with `ClientIdentifier=mac` **and** an emptied machine-id: either alone leaves the
   trap for the next image.

3. **`unattended-upgrades` holds the dpkg lock**, so an `apt-get install` in a provisioning
   script fails silently and the tool you thought you installed is not there. Which turns
   into a diagnostic that reports "command not found" where you expected a device answer.

**A fourth, about the host rather than the lab:** this machine has 16 GB and was running
EVE-NG, a second VM for `ClickHouse`, the product, and a desktop. Committed memory reached
22.5 GB, and all four nodes were killed once with no OOM entry inside the guest. A lab this
small is not free.

## 4. What it found immediately

**Nothing walks LLDP.** `uops_discover::neighbours` reads `lldpRemTable`,
`PgStore::record_neighbours` turns that into exactly one `connected_to` edge per adjacency,
and both are tested. **No running process calls either.** `record_neighbours` appears only
in tests; `uops_discover::run` sweeps and never walks.

Everything around it works, which is what makes the finding precise rather than a shrug:

* `snmpwalk` against the nodes returns the adjacency correctly — `core-sw-01` reports both
  `edge-fw` and `lb-01` as neighbours, each leaf reports only `core-sw-01`;
* a sweep of `192.168.1.0/24` probed 254 addresses, **4 answered, 4 resources created, 0
  sent for review**;
* the poller picked all four up and collected CPU, memory, uptime and per-interface
  counters;
* and `GET /api/v1/topology` returned `nodes: 0, edges: 0`.

M5's criterion was reopened to `[~]` with this written against it. The criterion was not
wrong — an LLDP walk really does produce one edge — it simply never said that anything
walks, and a reader would assume it.

**A second find, 24 September: no incident ever went quiet.** M9 §2.1 says an incident
whose alerts have all resolved becomes *quiet*, `PgStore::quiet_settled_incidents` does
exactly that, and its test has always passed. Nothing in production called it — the call
was in `Engine::evaluate_tenant`, reachable only from `Engine::cycle`, which the run loop
does not use. Found by restarting `core-sw-01` here and watching the incident stay `open`
with every alert resolved. Fixed in the run loop, with a test that drives the real loop
rather than the function.

**Fixed the same day**, and verified here rather than in a fixture: `docs/topology-walk.md`
puts the walk on the poller's discovery task, and the same four devices now return

```text
nodes: 4  edges: 3
  core-sw-01 <-> edge-fw   via lldp
  core-sw-01 <-> lb-01     via lldp
  core-sw-01 <-> app-01    via lldp
```

which is the cabling in §1. The walk reported **6 adjacencies** and the graph holds
**3 edges** — both ends were walked and the sorted pair collapsed them, which is exactly
the property the ingest's tests assert and which a real estate exercises for free.

## 5. What it cannot test here

**Availability.** The poller uses an unprivileged ICMP datagram socket, which is a Linux
and macOS facility; on Windows it reports
*"unprivileged ICMP needs a Linux or macOS datagram socket; this platform has none"* and
the availability jobs fail. That is a correct message about a deliberate design — polling
needs no elevated privileges — and it means **a Windows development host cannot exercise
the availability path**. The deployment target is Linux, so this is a development
inconvenience rather than a product gap, but it is worth knowing before reading a poller
log full of failures.

## 6. Running it

The image is built by the scripts recorded in `docs/dev-environment.md`; the lab is
`uops-estate` in EVE-NG and is driven through its REST API. Node addresses are DHCP, and
the reliable way to map a node to its address is EVE-NG's own MAC scheme — node *N*'s first
interface is `00:50:00:00:0N:00` — rather than boot order.
