# Running the stack without Docker

`deploy/docker-compose.yml` is the supported way to bring up PostgreSQL and ClickHouse,
and `scripts/linux-test.sh` runs the suite against it. This file is for the case where
Docker is not available — which on the machine this was written on is permanent, because
WSL and the Windows hypervisor are switched off so that VMware can run Proxmox.

The goal is a suite that runs green, not a production deployment. Nothing here is a
deployment topology.

---

## Before you push

Added 2026-09-24, after the `web` job sat red on `main` across two commits. The check that
caught it — `scripts/css-classes.mjs` — already existed and had simply never been run
against those commits, so the failure was discovered a push too late and by accident. Four
of the five commands below take seconds; only the Rust suite is slow.

```bash
# Rust. The long one. Both stores have to be reachable, or tests skip or fail for reasons
# that have nothing to do with the change -- see the two sections below for the URLs.
export DATABASE_URL=... CLICKHOUSE_URL=... SQLX_OFFLINE=true
cargo clippy --workspace --all-targets     # CI denies warnings
cargo test --workspace

# The web app. Seconds, and the guards are the part that gets forgotten.
cd web
npx tsc -b --noEmit && npx eslint src && npx vitest run && npm run build
node scripts/no-remote-assets.mjs          # no third-party host in the built bundle
node scripts/css-classes.mjs               # every class in the markup is defined
cd ..

# The artefact guards. Fast, no build needed.
python scripts/no-phone-home.py --self-test && python scripts/no-phone-home.py
```

`scripts/csp-browser-check.py` is not in that list because it needs a browser and takes
longer. Run it after changing the Content-Security-Policy in
`crates/uops-server/src/headers.rs`, or after adding a web dependency that touches fonts,
images, workers or wasm.

**`cargo fmt --check` is not in the list either**, deliberately: it reports around 170
pre-existing differences on this machine, which is toolchain skew rather than dirty code.
Running it produces noise that hides anything real.

---

## PostgreSQL — a portable install

No container needed: PostgreSQL has a Windows build that runs from a directory.

On the machine this was written on the directory sits **beside** the repository rather
than inside it — `../pgtmp` — so that a `cargo clean` or a fresh clone cannot take the
database with it. The paths below are relative to wherever it was unpacked.

```bash
PG=pgtmp/x/pgsql/bin
"$PG/pg_ctl.exe" -D pgtmp/data -o "-p 5432 -c listen_addresses=127.0.0.1" -l pgtmp/pg.log start
export DATABASE_URL="postgres://uops@127.0.0.1:5432/uops"
bash scripts/db.sh migrate
```

Trust auth, loopback only, user `uops`. Development defaults, deliberately obvious — the
same argument `deploy/docker-compose.yml` makes about its own.

### The schema tests need `psql` directly

`bash scripts/db.sh test` runs `migrations/tests/invariants.sql` through
`docker compose exec`, so it cannot work here. The portable install ships the client:

```bash
PSQL=pgtmp/x/pgsql/bin/psql.exe
"$PSQL" "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/tests/invariants.sql
```

**Run it against a scratch database, not the dev one.** Two of the invariants insert
fixtures and assert on what comes back, so they fail against a database that has
accumulated rows from interrupted integration tests — which is the contamination item
STATUS.md has been carrying since M2. A clean run is three commands:

```bash
"$PSQL" "postgres://uops@127.0.0.1:5432/postgres" -tAc "CREATE DATABASE uops_inv OWNER uops"
DATABASE_URL="postgres://uops@127.0.0.1:5432/uops_inv" sqlx migrate run --source migrations
"$PSQL" "postgres://uops@127.0.0.1:5432/uops_inv" -v ON_ERROR_STOP=1 -f migrations/tests/invariants.sql
```

It caught a real defect in migration 0021 that way: a composite `ON DELETE SET NULL` that
would have nulled `tenant_id`.

---

## ClickHouse — a Linux VM

### Two things that will bite you after a restart

**The guest's IP changes.** It is DHCP on a bridged adapter, so a restart can move it —
and it moved across an entire subnet once, from `192.168.1.219` to `172.31.38.250`. The
failure is confusing rather than obvious: `ping` still answered, because a different
device on the old network had taken the old address, while every TCP connection to 8123
timed out. Read the address back rather than assuming it:

```bash
vmrun -T ws getGuestIPAddress "<the vmx>" -wait
export CLICKHOUSE_URL="http://<that>:8123"
```

STATUS.md's housekeeping already carries the same lesson for Docker — *"re-read the
container IPs, Docker reassigns them"*. It is the same mistake with a different
hypervisor.

**ClickHouse does not auto-start.** It is a standalone binary, not a package:

```bash
cd ~/clickhouse && nohup ./clickhouse server --config-file=./config.xml > /tmp/ch.out 2>&1 &
```

### Running commands in the guest

`vmrun`'s guest operations work, but **invoke them from PowerShell, not from bash**. The
same `runScriptInGuest` call that returns `Error: A file was not found` through the bash
tool succeeds unchanged from PowerShell — the VMX path has a space in it and the bash
wrapper mangles the quoting into an argument vmrun reads as a missing file. The error
names the wrong thing entirely, which is what makes it expensive.

```powershell
$vmx = "C:\...\kali-linux-2026.2-vmware-amd64.vmx"
$vmrun = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
& $vmrun -T ws -gu kali -gp kali runScriptInGuest $vmx "/bin/bash" "free -m > /tmp/x.txt 2>&1"
& $vmrun -T ws -gu kali -gp kali CopyFileFromGuestToHost $vmx /tmp/x.txt C:\Temp\x.txt
```

Output comes back through a file, because `runScriptInGuest` does not return stdout.

### The guest's memory, and the benchmark that did not fit in it

**It has 8 GB now.** It had 3.8 GB when the M8 benchmark was run, and `config.xml` caps
ClickHouse at half of whatever is there — which was right for the test suite and **not
enough for a benchmark load**. Loading 100M spans — 8.26 GiB compressed, 20.5 GiB raw —
plus a `MATERIALIZE INDEX` mutation across thirty parts took the guest out of memory: the
process stayed alive and kept its pid, dropped its listener, and left the kernel unable to
fork, so that not even `/bin/true` would run. From the host it looked like a hung test
suite.

The measurement in [`bench/results/m8-spans-100000000rows.md`](../bench/results/m8-spans-100000000rows.md)
was worth having and worth the outage once. Before running another one:

* **The memory was doubled after this happened**, which is the first half of the fix. The
  second half stands: an 8 GiB load on the instance every integration test depends on
  turns a benchmark into an outage for everything else, and more headroom moves that
  threshold rather than removing it.
* **Watch `free -m` in the guest during a load**, rather than concluding afterwards. The
  failure mode is not a crash: the process keeps its pid, drops its listener, and the
  kernel stops being able to fork.
* **The data is regenerable** from seed 42 and is never committed, so dropping it costs
  eleven minutes and nothing else: `DROP DATABASE bench`.
* **Merges settle.** Once the load and any mutation have finished, the table sits there
  costing disk and nothing else. `system.merges` and `system.mutations` are the two tables
  to check before concluding it is still the problem.


ClickHouse has **no native Windows build**, so this one needs a Linux somewhere. Any
Linux reachable over the network will do; here it is a VMware guest.

### Which version

**26.8, and the version matters.** `0001_logs.sql` declares

```sql
INDEX idx_body body TYPE text(tokenizer = 'splitByNonAlpha') GRANULARITY 1
```

and that syntax moved during the 26.x beta — 26.7 is not a safe substitute.
`deploy/docker-compose.yml` pins `26.8-alpine` for the same reason. Note that **26.8 is
the LTS line**: GitHub tags it `v26.8.x.y-lts`, not `-stable`, which is easy to miss when
scanning release names.

### Installing it

The `clickhouse-common-static` tarball, not the apt repository: it is one binary in one
directory, so the whole thing comes off again with `rm -rf ~/clickhouse`. That matters
when the Linux box is somebody's working VM rather than a server.

```bash
V=26.8.9.10
B=https://github.com/ClickHouse/ClickHouse/releases/download/v$V-lts
F=clickhouse-common-static-$V-amd64.tgz

mkdir -p ~/clickhouse && cd ~/clickhouse
curl -sSL -O $B/$F -O $B/$F.sha512
sha512sum -c $F.sha512          # a binary about to be run gets verified
tar -xzf $F
install -m 0755 clickhouse-common-static-$V/usr/bin/clickhouse ./clickhouse
mkdir -p data logs tmp user_files format_schemas
```

`config.xml` needs `<listen_host>0.0.0.0</listen_host>` so the development machine can
reach it, `<path>` and friends pointed inside `~/clickhouse`, and
`<max_server_memory_usage_to_ram_ratio>0.5</max_server_memory_usage_to_ram_ratio>` on a
small guest — ClickHouse sizes its caches off total RAM and will otherwise take most of
it.

`users.xml` pins `default` to loopback and gives `uops`/`uops` network access. The listen
host is open, so the access rules are what closes it: a VM bridged onto a home LAN with an
unauthenticated ClickHouse on it is not a thing to leave running.

```bash
setsid nohup ./clickhouse server --config-file=./config.xml > logs/stdout.log 2>&1 &
curl -s http://127.0.0.1:8123/ping     # Ok.
```

### Pointing the suite at it

```bash
export CLICKHOUSE_URL="http://<guest-ip>:8123"
export CLICKHOUSE_DB=uops CLICKHOUSE_USER=uops CLICKHOUSE_PASSWORD=uops
curl -sS -f "$CLICKHOUSE_URL/?user=uops&password=uops" --data-binary "CREATE DATABASE IF NOT EXISTS uops"
bash scripts/ch.sh apply
bash scripts/ch.sh verify     # uops-query's golden SQL against the live schema
bash scripts/ch.sh smoke
```

`ChConfig::from_env` reads all four variables, so the tests need nothing else — no port
forwarding, and the guest's address is the only thing that changes.

---

## Leave the server's timezone alone

The guest here runs `America/New_York`, and **that is deliberate**.

The Docker image runs UTC. Every telemetry column is `DateTime64(3, 'UTC')`, and for a
long time the query compiler bound its window parameters as a timezone-less
`DateTime64(3)` — which ClickHouse parses in the *server's* timezone. On UTC the two
happen to agree, so the whole suite passed and nothing was wrong that anyone could see.

The first run against a non-UTC server failed thirteen tests, and the cause was a real
defect: a window of 15:00–18:00 UTC was read as 19:00–22:00 and matched nothing. Not an
error — an empty graph, during an incident, on any customer whose ClickHouse is not UTC.

The compiler now binds `DateTime64(3, 'UTC')` and
`no_timestamp_parameter_is_left_without_a_timezone` checks the recorded SQL for a
regression. Keeping the development server on a non-UTC timezone is the other half of
that: it is the only thing that would catch the same mistake made somewhere the golden
files do not reach. Setting it to UTC would make the environment quieter and strictly
worse at its job.

## The live SSH fixture, for M10's last criterion

`uops-runner/tests/live_ssh.rs` is the only test in the workspace that drives a runbook
step through `ssh(1)` into a real `sshd`. It closes the criterion that stayed open through
all of M10 — *"verified against a real SSH server, not a mock"* — and it needs a server
that will accept a key.

The same Kali guest that runs ClickHouse already has `openssh-server` installed. Bring it
up and authorise a key:

```bash
# in the guest
echo kali | sudo -S systemctl start ssh
ssh-keygen -t ed25519 -N '' -C uops-runner-live -f ~/uopskey
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat ~/uopskey.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
```

Copy the **private** key to the host — `vmrun CopyFileFromGuestToHost` does it — and point
the test at it:

```bash
UOPS_SSH_HOST=<guest ip> UOPS_SSH_USER=kali UOPS_SSH_KEY=<path on host> \
  cargo test -p uops-runner --test live_ssh
```

**Without those variables the test skips and says so**, so a full workspace run on a
machine with no fixture stays green. The skip line is deliberately loud: a silently-passing
live test is worse than an absent one.

Two notes worth keeping:

* **The key must have no passphrase.** The transport refuses one by design — `ssh(1)`
  cannot be handed a passphrase without a helper program whose job is to print a secret,
  and M10 §2.10 records why that is not a trade this product makes.
* **The test writes to `/tmp` on the guest** and removes what it wrote. It also checks the
  *absence* of that file after a dry run by asking the device directly over a separate
  `ssh`, rather than trusting the run's own transcript — which is the assertion a scripted
  transport cannot make.
