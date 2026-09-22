# Restore drill — 2026-09-22

M12 §2.4: *a restore that has not been performed is not a backup.* This is the record of
one that was performed on **8c1999f**, against real PostgreSQL 17.2 and real ClickHouse
26.8.9.10 — not a container fixture and not a description of what would happen.

It is written the way a drill should be: including the thing it got wrong the first time,
because that is the only part of a drill that could not have been written in advance.

---

## What was restored

| | Source | Restored | |
|---|---|---|---|
| **Control plane** | `uops` (PostgreSQL 17.2) | `uops_restored` | |
| users | 573 | 573 | ✓ |
| tenants | 1 716 | 1 714 | +2 written after the backup started |
| organizations | 1 577 | 1 575 | +2 written after the backup started |
| resources | 1 185 | 1 185 | ✓ |
| sealed credentials | 26 | 24 | +2 written after the backup started |
| roles (`user_tenant_role`) | 533 | 533 | ✓ |
| alert rules | 193 | 193 | ✓ |
| dashboards | 10 | 10 | ✓ |
| saved searches | 39 | 39 | ✓ |
| collectors | 112 | 112 | ✓ |
| identity providers | 123 | 123 | ✓ |
| audit log | 1 713 | 1 713 | ✓ |
| resource identifiers | 480 | 480 | ✓ |

| | Source | Restored | |
|---|---|---|---|
| **Telemetry** | `uops` (ClickHouse 26.8.9.10) | `uops_restored` | |
| `logs` | 1 471 | 1 471 | ✓ |
| `logs_counts_5m` | 1 301 | 1 301 | ✓ |
| `metrics` | 3 677 | 3 677 | ✓ |
| `metrics_5m` | 1 407 | 1 407 | ✓ |
| `metrics_1h` | 588 | 588 | ✓ |
| `events` | 0 | 0 | ✓ |
| `states` | 0 | 0 | ✓ |
| `flows` | 382 | 382 | ✓ |
| `flows_5m` | 344 | 344 | ✓ |
| `spans` | 7 401 | 7 401 | ✓ |
| `service_5m` | 870 | 870 | ✓ |

**Every telemetry table matched exactly.** The three control-plane differences are not
loss: the source is a live database, and each one is explained precisely. The backup
started at `11:50:08Z`; the two extra credentials were created at `11:54:17Z`, and the two
extra tenants are named `restore-no-kek` and `restore-with-kek` — fixtures written by the
drill's own tests, four minutes after the snapshot. A backup is consistent as of when it
was taken, and this one is.

A password hash was compared byte for byte across the two databases and is identical, so
the restored deployment authenticates whoever could authenticate before.

---

## How long it took

| | Time | Size |
|---|---|---|
| Backup, control plane | **1 s** | 1 450 531 bytes (`pg_dump -Fc`) |
| Backup, telemetry | **6 s** | 2 052 497 bytes (11 tables, ClickHouse Native) |
| Backup, total | **8 s** | |
| Restore, control plane | **2 s** | |
| Restore, telemetry | **6 s** | including re-applying 9 ClickHouse migrations |
| Restore, total | **8 s** | |

**Recovery time on this data: 8 seconds.** That number is honest about what it measures
and nothing more — it is 17 441 telemetry rows and a 1.4 MB control plane on one
developer machine with ClickHouse across a LAN. It says the procedure works; it says
nothing about a production estate, where the control plane is still small and the
telemetry is not. The shape to expect is that the control plane stays seconds and the
telemetry scales with its bytes.

What this drill has **not** established is a restore of a large ClickHouse. At 100 M
spans — the size W1 and M8 measured against — a logical `SELECT … FORMAT Native` export is
the wrong tool and ClickHouse's own `BACKUP TABLE … TO Disk(…)` is the right one. That is
named in `scripts/backup.sh` and is the next drill rather than this one.

---

## What the drill found

**The first attempt silently doubled every aggregate.**

The backup contains the raw tables and the aggregate tables they feed. Loading the raw
rows with the materialized views attached made each view fire, writing into an aggregate
table that *already held* the rows restored from the backup:

| | Source | First attempt | |
|---|---|---|---|
| `logs_counts_5m` | 1 301 | 2 602 | 2× |
| `flows_5m` | 344 | 688 | 2× |
| `metrics_5m` | 1 407 | 2 814 | 2× |
| `service_5m` | 870 | 1 740 | 2× |
| `metrics_1h` | 588 | 1 764 | **3×** — two of its inputs were restored |

Nothing complained. The restore reported success. The raw tables — `logs`, `metrics`,
`spans`, `flows` — were all exactly right, which is what makes this the dangerous shape:
somebody spot-checking a restore checks the raw counts. Every dashboard and every alert
rule built on a five-minute rollup would have read **twice the traffic that existed**,
and the restored deployment would have looked healthy while lying about its own history.

A backup verified by *did the restore command succeed* ships that. This is the entire
argument for §2.4 asking for a drill rather than a procedure.

**The fix** is to detach every materialized view for the duration of the load and
re-attach it afterwards — `scripts/restore.sh` does that now and says why. The obvious
alternative, dropping the aggregates from the backup and letting the views rebuild them
from the restored raw rows, is wrong in a quieter way: an aggregate outlives the raw rows
it came from, which is what it is *for*, so everything older than the raw retention would
have vanished without a number changing anywhere to say so.

**A second, smaller thing.** The first attempt printed `curl: (3) URL rejected` once per
table and carried on, because the load put the query in the request body and the rows in
the URL. A fallback caught it, so the restore worked — which is exactly how a broken
primary path survives review. Both are now one correct call.

---

## Credentials: what a restore cannot do

The key-encryption key never enters the database — SPEC §M0.4 — so it is not in any
backup this product produces.

A control plane restored onto a machine that does not have the original KEK comes back
**complete except for the ability to open a single device credential**. The rows are
there. The names are there. The inventory lists them and says which resource uses which.
Nothing can be polled.

That is the correct behaviour, and it is checked rather than asserted:
`crates/uops-store-pg/tests/restore.rs` seals a credential, swaps the key ring for a
different one under the same key id — which is exactly what a restore onto a host with a
freshly generated `UOPS_KEK_ID` is — and requires the open to fail while `describe` and
`list` still work. The paired test does the same with the *right* key material and
requires the plaintext back, because a negative test written on its own passes just as
well against something that can never open anything.

**So: a rehearsal that does not also rehearse the key material has rehearsed the easy
half.** `scripts/restore.sh` prints that sentence at the end of every control-plane
restore, where somebody will read it before they need it.

---

## Does the product run on it?

Yes. `uops-server` was started against both restored databases and answered:

```json
{"ok":true,"control_plane":{"reachable":true},"telemetry":{"reachable":true,"version":"26.8.9.10"}}
```

It came up reporting `credentials=off (no KEK configured)`, which is the restored-without-
the-key case above, stated by the product itself in its own startup line.

---

## Reproducing it

```bash
export DATABASE_URL=postgres://uops@127.0.0.1:5432/uops
export CLICKHOUSE_URL=http://<clickhouse>:8123 CLICKHOUSE_DB=uops
export CLICKHOUSE_USER=uops CLICKHOUSE_PASSWORD=uops

bash scripts/backup.sh /tmp/drill

# The destination has no default, on purpose. See the header of restore.sh.
createdb uops_restored
curl -sS "$CLICKHOUSE_URL/?user=uops&password=uops" --data-binary "CREATE DATABASE uops_restored"

export RESTORE_DATABASE_URL=postgres://uops@127.0.0.1:5432/uops_restored
export RESTORE_CLICKHOUSE_DB=uops_restored
bash scripts/restore.sh /tmp/drill
```

Then compare, which is the step that is not optional:

```bash
for t in logs logs_counts_5m metrics metrics_5m metrics_1h events states \
         flows flows_5m spans service_5m; do
  a=$(curl -sS "$CLICKHOUSE_URL/?user=uops&password=uops" --data-binary "SELECT count() FROM uops.$t")
  b=$(curl -sS "$CLICKHOUSE_URL/?user=uops&password=uops" --data-binary "SELECT count() FROM uops_restored.$t")
  [ "$a" = "$b" ] && echo "$t ok" || echo "$t MISMATCH $a vs $b"
done
```

The aggregate tables are the ones to look at. They are the ones that were wrong.

---

## Next drill

* **A large ClickHouse.** `BACKUP TABLE … TO Disk(…)` against something on the order of
  100 M rows, with a recovery time somebody can plan a maintenance window around.
* **A KEK restored from wherever it lives**, so the credential half of the rehearsal is
  rehearsed rather than only described.
* **A restore onto a different machine**, which is what a real one is, and which would
  catch anything this drill got for free by staying on one host.
