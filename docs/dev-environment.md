# Running the stack without Docker

`deploy/docker-compose.yml` is the supported way to bring up PostgreSQL and ClickHouse,
and `scripts/linux-test.sh` runs the suite against it. This file is for the case where
Docker is not available — which on the machine this was written on is permanent, because
WSL and the Windows hypervisor are switched off so that VMware can run Proxmox.

The goal is a suite that runs green, not a production deployment. Nothing here is a
deployment topology.

---

## PostgreSQL — a portable install

No container needed: PostgreSQL has a Windows build that runs from a directory.

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
