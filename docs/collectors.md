# Collectors

Putting a collector in the inventory, and what that changes.

M12 §2.3 records *why* it is built this way; this file is for somebody running one.

---

## What enrolling changes

A collector that has not enrolled keeps working exactly as it always has: it reads its
own listener file and serves what that names. Enrolling changes three things.

**It appears in an inventory.** Collectors → the list of every collector this
organization has, what version it runs, what it is bound to, and how much it has taken in
and written out.

**Its silence is noticed.** A collector reports in every 30 seconds. Three missed
reports and the screen says so. Before this, a syslog daemon that died three days ago
looked exactly like a quiet network.

**Which customers it may carry is decided here, not there.** A listener naming a tenant
the collector was not assigned refuses to start, and says which tenant. Before this, any
collector with database credentials could carry any tenant by editing its own YAML.

### What it does not change

The token is **not** a credential for the databases. A collector already holds those — it
has to, because that is where it writes — and they are strictly more powerful than any
enrolment token. This is an operational control, not a security boundary: it stops a box
brought up with a copied config from quietly serving a customer. It is not what stops a
hostile collector, and M12 §2.3 says what would.

---

## Enrolling one

**1. Issue a token.** Collectors → *Issue a token*. Give it a label somebody will
recognise in six months — `site-berlin`, `rollout-2026-q4`. Leave *Uses* empty for a
token that can bring up any number of collectors, which is what a token living in
configuration management wants; set it to 1 for a one-off.

The token is shown **once**. Only its hash is stored, so if you lose it you mint another.

**2. Set it on the collector** and restart:

```bash
UOPS_COLLECTOR_TOKEN=<the token>
# Optional. Defaults to the hostname, which is what makes a restart claim the same row
# rather than creating a second one. Two collectors of the *same kind* on one host need
# distinct names; two of different kinds do not.
UOPS_COLLECTOR_NAME=berlin-01
```

**3. Assign its tenants.** A freshly enrolled collector serves **nothing** — that is the
point. Until somebody assigns a tenant, a listener naming one refuses to start:

```
uops-collector-syslog: this collector is not assigned this tenant: acme.
Assign it in the collector inventory, or remove the listener
```

Assign it in Collectors → *Assign a tenant*, then restart the collector.

There is no identity file. Enrolment is idempotent on `(organization, kind, name)`, so a
restart claims the row it already had and spends no use. The alternative — writing an id
to disk — produces a second collector with the same job the day somebody loses the file,
and forty collectors that all believe they are the same one the day somebody bakes it
into an image.

---

## Reading the list

| State | What it means | Who should look |
|---|---|---|
| **Reporting** | Heard from within the last few minutes | Nobody |
| **Quiet** | Reported and then stopped | Whoever owns the box — is the process running? |
| **Never reported** | Enrolled and has never sent a heartbeat | Whoever wrote its configuration |
| **Retired** | Somebody retired it | Nobody. If it reports again it comes back by itself |

The difference between **Quiet** and **Never reported** is the one worth knowing. Quiet is
an outage; never reported is a misconfiguration — usually a database it cannot reach, or
a process that died on its first tick. They need different people.

The three counters are **Received**, **Written** and **Lost**. Lost is the one that means
data loss: a full queue and a full disk are different failures and this adds them up,
because the question is *did we lose anything*. It is marked when it is not zero.

The counters are **per process**, so they reset when a collector restarts. *Last heard*
and the start time beside it are what make a reset legible rather than looking like a
collapse in traffic.

---

## Revoking a token

Collectors → *Revoke*. **Collectors it already brought up keep working** — enrolment is a
bootstrap, and a revocation that silently stopped forty running collectors is a
revocation nobody dares perform. What it stops is new ones.

A token can also stop working on its own, and the list distinguishes the three:

* **revoked** — somebody did that
* **expired** — a clock did that
* **spent** — a count did that

---

## Retiring a collector

Collectors → *Retire*. It stays in the list, marked, with the tenants it was carrying
still recorded: the row is what answers *what used to be at that site*.

If it starts reporting again it **un-retires itself**. That is the honest outcome — the
alternative is an inventory that hides a running collector.

---

## What this does not do yet

**Apply an assignment change while running.** A collector logs that its assignment
changed and keeps serving what it started with; restart it to apply. Starting and
stopping listeners underneath a live ingest path is a larger change than the registry,
with its own failure modes.

**Require enrolment.** A collector with no token stays out of the registry and serves
what its file names. That is deliberate — making it mandatory would have been a flag day
for every existing deployment — and it means the server-side assignment is authoritative
only for collectors that enrolled. Once an estate has enrolled everything it has,
requiring the token is the next step, and it is a deployment decision rather than a code
change.

**Route telemetry through the server.** A collector writes to ClickHouse directly, which
is why it needs those credentials and why the token is not a security boundary. Changing
that is what would let a customer-hosted collector talk to a hosted control plane over
nothing but an HTTPS egress, and it is a throughput question first: W1 measured ~100 000
msg/s straight to ClickHouse.
