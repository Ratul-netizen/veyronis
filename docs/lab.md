# The lab the product is tested against

**Written:** 24 September 2026, after the first end-to-end run against it.

Every test in this workspace before this one replaced at least one end: a scripted SNMP
agent, a fixture of LLDP rows, a `Scripted` transport. That is the right way to test
orchestration, and it cannot find the class of defect where a component is correct,
tested, and **never called**. This estate exists to find those, and it found one on the
first run — see §4.

---

## 1. What it is

Nine nodes under EVE-NG, cabled as a small datacenter and **routed**, not flat:

```text
   Mgmt — bridged to the real LAN (pnet0). Out-of-band: every fabric device by DHCP.
     │
  core-rtr-01 ── edge-fw ── spine-01 ─┬─ leaf-01 ──┬─ lb-01     10.10.6.10
                                      │            └─ app-01    10.10.6.11
                                      └─ leaf-02 ──┬─ app-02    10.10.7.10
                                                   └─ db-01     10.10.7.11
```

| | address | why |
|---|---|---|
| fabric — `core-rtr-01`, `edge-fw`, `spine-01`, `leaf-01`, `leaf-02` | DHCP on Mgmt | out-of-band management, which is how a datacenter is run: losing a switch's forwarding must not lose the ability to *see* the switch |
| workloads — `lb-01`, `app-01`, `app-02`, `db-01` | `10.10.<leaf>.0/24` only | reachable **only through their leaf**, which is what makes the dependency real |

**The routing is the point.** A flat /24 where the product can reach every node directly
makes M9's topology-aware suppression cosmetic — the graph says one thing and reachability
says another, so a suppression test passes whether or not suppression works. Here, stopping
`leaf-01` genuinely removes `lb-01` and `app-01`, and demonstrably leaves `leaf-02`'s servers
alone:

```text
before      leaf-01 up    lb-01 up    app-01 up    app-02 up
stop leaf-01
after       leaf-01 DOWN  lb-01 DOWN  app-01 DOWN  app-02 up
```

That is one root cause, two downstream symptoms, and a blast radius that stops at the right
place — verified 24 September 2026, and the reason the estate is worth running.

**Every node speaks what the product actually reads**, and nothing more:

| | why it is there |
|---|---|
| `snmpd`, v2c, community `uopslab` | MIB-2 `system` and `interfaces` — polling, and `sysObjectID` for identity |
| `lldpd` with `-x` (AgentX) | hands LLDP-MIB to `snmpd`. **Without AgentX there is no LLDP in SNMP at all** |
| `rsyslog`, RFC 5424 | the log collector's input |
| `haproxy` | on `lb-01`, so a load balancer is a load balancer |
| ICMP | availability — though see §5 |

## 2. Why these images and not vendor ones

Cisco, Palo Alto, F5 and Fortinet images require an entitlement, and the usual way people
obtain them is not a way this project will. Debian with `snmpd` and `lldpd` produces
*genuine* SNMP and *genuine* LLDP — the protocols are the same ones a switch speaks, and
they are what the product consumes. A licensed image, if one is available, drops into
`/opt/unetlab/addons/qemu/` and joins the same topology.

One image, `linux-uopsnode`, is cloned nine times. A node's role comes from its **EVE-NG node
number**, which it reads out of its own MAC — EVE-NG assigns `00:50:00:00:0N:00` to node *N*'s
first interface, and that is the only thing a plain Linux node can observe about its place in
a topology. There is no cloud-init datasource and no metadata service.

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

**A fourth and a fifth, from growing it from four nodes to nine on 24 September 2026.**

4. **The naming table was a hardcoded list of four, and its fallback lied.** The provisioning
   script mapped node numbers `02`, `03` and `04` to names and fell through to
   `NAME=edge-fw`. Adding five nodes therefore produced five devices that told the product,
   over SNMP, that they were all `edge-fw` — `core-rtr-01` reported `edge-fw-000500`. The
   product was not wrong; it was faithfully reporting what the estate claimed. The fallback is
   now `node-NN`, which is still wrong and is *visibly* wrong rather than plausible. Exactly
   the shape of the Dockerfile's stale binary list in `docs/packaging.md` §2: a hardcoded list
   beside a comment warning against hardcoded lists.

5. **Spare interfaces can be detached through the API after all.** The previous script carried
   a workaround — `90-unused.network` holding `ens4`–`ens6` down — with the note *"EVE-NG would
   not let the spare interfaces be unlinked through its API, so they sit on the same segment as
   ens3."* The API rejects `network_id: 0` with *"invalid network_id (20033)"* and accepts an
   **empty string**, which detaches cleanly. The workaround is no longer needed, and the
   topology now has no interface on a segment the diagram does not show.

**A sixth, about the host rather than the lab:** this machine has 16 GB and was running
EVE-NG, a second VM for `ClickHouse`, the product, and a desktop. Committed memory reached
22.5 GB, and all four nodes were killed once with no OOM entry inside the guest. A lab this
small is not free.

> **And at nine nodes the binding constraint turned out not to be memory.** It is the CPU: an
> i5-7300HQ with **four logical processors**, of which EVE-NG has two and the `ClickHouse`
> guest had four — six vCPUs on four threads, with nine nested QEMU nodes booting. Nine nodes
> at 4 096 MB fit comfortably in EVE-NG's 6 144 MB (59% used); what did not fit was the
> scheduling. Trimming the `ClickHouse` guest to 2 vCPU and 2 048 MB was worth more than any
> memory change. Boots take minutes, and an address that has not appeared yet is usually a
> node still waiting for CPU rather than a node that failed.

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

## 5b. What the product makes of it

`crates/uops-poller/tests/live_lab.rs` walks the estate with the product's own code and
asserts the graph. **PostgreSQL only** — a neighbour walk is SNMP in and
`resource_relationship` out, so it runs when `ClickHouse` is down, which is how it came to be
written. Skipped, loudly, when `UOPS_LAB` is unset.

The run of 24 September 2026, nine nodes:

```text
  192.168.1.237   edge-fw-000100      lldp=4 -> edges 0  candidates 4
  192.168.1.64    spine-01-000200     lldp=6 -> edges 1  candidates 5
  192.168.1.49    core-rtr-01-000500  lldp=2 -> edges 2  candidates 0
  192.168.1.128   leaf-01-000600      lldp=6 -> edges 1  candidates 5
  192.168.1.207   leaf-02-000700      lldp=6 -> edges 1  candidates 5
  10.10.6.10      lb-01-000300        lldp=2 -> edges 2  candidates 0
  10.10.6.11      app-01-000400       lldp=2 -> edges 2  candidates 0
  10.10.7.10      app-02-000800       lldp=2 -> edges 2  candidates 0
  10.10.7.11      db-01-000900        lldp=2 -> edges 2  candidates 0

  nodes: 9  edges: 8
    core-rtr-01 — edge-fw        spine-01 — leaf-01     leaf-01 — lb-01    leaf-02 — app-02
    edge-fw — spine-01           spine-01 — leaf-02     leaf-01 — app-01   leaf-02 — db-01
```

Eight edges, and they are the eight cabled links — nothing else. **32 adjacencies reported,
8 distinct links stored**, which is the dedup the sorted pair gives and the schema's `UNIQUE`
does not: both ends of every link walk it.

**A second pass records all 32 again and changes nothing**, which the test asserts rather than
observes. A poller walks every cycle, so an upsert that was not idempotent would grow the graph
forever — and the failure would look like a topology that slowly filled with duplicates rather
than like a bug.

**A `mgmt_ip` is not enough to match a neighbour, and finding that out cost the first run.**
`neighbour_ingest::identifiers_of` matches on chassis id, management address or `sysName`.
`lldpd` here advertises a chassis id and a system name and *no* management address, so a
resource known only by the address the poller dials matches nothing: the first run reported 32
adjacencies and built **zero** edges, every one of them filed as a discovery candidate. The
test now asks each device for `sysName.0` and records it, which is what identity resolution
does on a real sweep. Worth keeping in the document because the symptom — a full neighbour
walk and an empty graph — looks exactly like the M5 defect in §4 and is a different cause.

## 6. Running it

The lab is `uops-estate` in EVE-NG and is driven through its REST API. Fabric addresses are
DHCP, and the reliable way to map a node to its address is EVE-NG's own MAC scheme — node *N*'s
first interface is `00:50:00:00:0N:00` — rather than boot order.

**The provisioning is `scripts/lab-firstboot.sh`.** This section used to say the image was
"built by the scripts recorded in `docs/dev-environment.md`". It was not recorded anywhere: it
existed only inside `linux-uopsnode`'s qcow2 on the EVE-NG guest, so the lab could not be
rebuilt, inspected or reasoned about without extracting a file from a disk image — which is
what had to be done to grow it to nine nodes. Installing it into the image is one command on
the EVE-NG host:

```bash
IMG=/opt/unetlab/addons/qemu/linux-uopsnode/virtioa.qcow2
cp -a "$IMG" "$IMG.bak"                      # the image is 730 MB; the copy is cheap insurance
virt-customize -a "$IMG" \
  --upload lab-firstboot.sh:/usr/local/sbin/uops-firstboot.sh \
  --chmod 0755:/usr/local/sbin/uops-firstboot.sh
```

A node marks firstboot done in `/var/lib/uops-firstboot.done`, so changing the script needs the
node overlays discarded — `GET /api/labs/uops-estate.unl/nodes/wipe` after a stop — or the old
configuration simply persists and nothing says why.

**The workload subnets need a route on the monitoring host**, because the servers are
deliberately not on Mgmt. On Windows:

```
route add 10.10.6.0 mask 255.255.255.0 <leaf-01 Mgmt address>
route add 10.10.7.0 mask 255.255.255.0 <leaf-02 Mgmt address>
```

Without these the four servers are unreachable and look like a broken lab rather than a
missing route. They are not persistent; `-p` makes them so, at the cost of a stale route when
a leaf's lease moves.

**What the estate is reached with:** EVE-NG's API and shell are `admin`/`eve` and `root`/`eve`;
SNMP is v2c, community `uopslab`, read-only. All of it is a lab on a private segment and all of
it is written down here on purpose — the previous state of affairs was that none of it was, and
a lab nobody can log into is a lab that cannot be repaired.
