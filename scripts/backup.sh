#!/usr/bin/env bash
# Back up both planes — M12 §2.4, `docs/M12-enterprise.md`.
#
#   bash scripts/backup.sh <directory>
#
# Writes one directory holding both planes and a manifest describing what is in it.
#
# # Two planes, two commands, and they are not interchangeable
#
# **PostgreSQL** is small, mutable and irreplaceable. It holds identity, roles, sealed
# credentials, alert rules, dashboards and every decision anybody has made. Losing it
# loses the product; there is nothing to regenerate it from.
#
# **ClickHouse** is large, append-only and *partially* regenerable. Telemetry that has
# aged out is gone. Telemetry that has not can often be re-sent — a syslog sender retries,
# an OTLP collector has its own queue, and a poller will simply poll again. What cannot be
# re-sent is history: nobody re-sends last quarter.
#
# Treating them as one "backup story" is how somebody restores a control plane and
# discovers the telemetry retention was the part that mattered. So this script does both
# and reports them separately, and the restore script can do either alone.
#
# # What is NOT in here
#
# **The key-encryption key.** SPEC §M0.4: it never enters the database, so it is not in
# the dump. A restored control plane without its KEK holds sealed credentials nobody can
# open — every other thing works, and every device credential is a locked box.
#
# That is the correct behaviour and it is not a bug to be worked around. It does mean the
# KEK has to be backed up *somewhere else*, by whatever holds the rest of your secrets,
# and that a restore rehearsal which does not also rehearse the key material has rehearsed
# the easy half. `restore.sh` says so at the end of every run, where somebody will read it.
#
# # The ClickHouse export is logical, not a snapshot
#
# One `SELECT … FORMAT Native` per table. Native preserves every type exactly and is far
# cheaper to parse back than CSV, but the tables are read one after another, so rows
# written *during* the backup may be in one file and not another. For append-only
# telemetry that is a boundary in time rather than a corruption: the restored database is
# consistent as of somewhere inside the backup window, and the manifest records both ends
# of it.
#
# ClickHouse's own `BACKUP TABLE … TO Disk(…)` is the right tool for a large deployment
# and needs a backup disk configured on the server. This works against any reachable
# ClickHouse with no server-side setup, which is what makes it the one a drill can
# actually use.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${DATABASE_URL:=postgres://uops:uops@localhost:5432/uops}"
: "${CLICKHOUSE_URL:=http://localhost:8123}"
: "${CLICKHOUSE_DB:=uops}"
: "${CLICKHOUSE_USER:=uops}"
: "${CLICKHOUSE_PASSWORD:=uops}"

DEST="${1:-}"
if [ -z "$DEST" ]; then
  echo "usage: bash scripts/backup.sh <directory>" >&2
  exit 2
fi

# Every table the product writes. Listed rather than discovered, and the reason is what a
# discovered list would include: `system.*`, and the materialized views whose *targets*
# are already here — restoring both would double every aggregate.
#
# A table added to ch-migrations and not added here is telemetry that silently is not
# backed up, so `verify` below counts what it found against this list.
CH_TABLES=(
  logs
  logs_counts_5m
  metrics
  metrics_5m
  metrics_1h
  events
  states
  flows
  flows_5m
  spans
  service_5m
)

# Deliberately not backed up: `schema_migrations` and `schema_migration_steps`. They are
# the migration runner's own bookkeeping, and the restore rebuilds the schema by applying
# migrations — so restoring a six-month-old record of which ones had run would tell the
# runner it had nothing to do.
CH_NOT_DATA=(schema_migrations schema_migration_steps)

mkdir -p "$DEST"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_EPOCH="$(date +%s)"

ch() {
  curl -sS -f \
    "${CLICKHOUSE_URL}/?user=${CLICKHOUSE_USER}&password=${CLICKHOUSE_PASSWORD}&database=${CLICKHOUSE_DB}" \
    --data-binary @-
}

echo "backup: into $DEST"
echo "backup: started $STARTED"

# ---------------------------------------------------------------- control plane

echo
echo "-- PostgreSQL (control plane) --"
PG_START="$(date +%s)"

# `-Fc` rather than plain SQL: it is compressed, it can be restored selectively, and
# `pg_restore --list` can say what is in it without restoring anything — which is how
# somebody checks a backup without a scratch database to put it in.
#
# The dump carries `_sqlx_migrations`, so a restored database knows exactly which
# migrations it has. That matters more than it sounds: restoring data into a schema built
# by re-running migrations would work right up until the day the two disagreed.
pg_dump --format=custom --no-owner --no-privileges \
  --file="$DEST/control-plane.dump" "$DATABASE_URL"

PG_SECONDS=$(( $(date +%s) - PG_START ))
PG_BYTES="$(wc -c < "$DEST/control-plane.dump" | tr -d ' ')"
echo "backup: control plane ${PG_BYTES} bytes in ${PG_SECONDS}s"

# ---------------------------------------------------------------- telemetry

echo
echo "-- ClickHouse (telemetry plane) --"
CH_START="$(date +%s)"
mkdir -p "$DEST/telemetry"

CH_ROWS_TOTAL=0
CH_BYTES_TOTAL=0
{
  echo "table,rows,bytes"
  for table in "${CH_TABLES[@]}"; do
    # Existence first. A table named here and absent from the server is a list that has
    # drifted from ch-migrations, and it should say so rather than write an empty file
    # that restores as silence.
    exists="$(echo "SELECT count() FROM system.tables WHERE database = '${CLICKHOUSE_DB}' AND name = '${table}'" | ch)"
    if [ "$exists" != "1" ]; then
      echo "backup: WARNING ${table} is not in ${CLICKHOUSE_DB}; skipping" >&2
      continue
    fi

    echo "SELECT * FROM ${table} FORMAT Native" | ch > "$DEST/telemetry/${table}.native"

    rows="$(echo "SELECT count() FROM ${table}" | ch)"
    bytes="$(wc -c < "$DEST/telemetry/${table}.native" | tr -d ' ')"
    CH_ROWS_TOTAL=$(( CH_ROWS_TOTAL + rows ))
    CH_BYTES_TOTAL=$(( CH_BYTES_TOTAL + bytes ))
    printf '%s,%s,%s\n' "$table" "$rows" "$bytes"
    echo "backup: ${table} ${rows} rows, ${bytes} bytes" >&2
  done
} > "$DEST/telemetry/manifest.csv"

CH_SECONDS=$(( $(date +%s) - CH_START ))
echo "backup: telemetry ${CH_ROWS_TOTAL} rows, ${CH_BYTES_TOTAL} bytes in ${CH_SECONDS}s"

# The drift check that actually matters, and it runs the other way round from the one
# above: a table on the server that nobody listed is telemetry this backup silently does
# not contain. Nothing else would ever notice — the backup succeeds, the restore
# succeeds, and one signal is missing.
known="$( { printf "%s
" "${CH_TABLES[@]}"; printf "%s
" "${CH_NOT_DATA[@]}"; } | sort )"
on_server="$(echo "SELECT name FROM system.tables WHERE database = '${CLICKHOUSE_DB}' AND engine NOT LIKE '%View%' ORDER BY name" | ch)"
missed="$(comm -13 <(echo "$known") <(echo "$on_server" | sort) || true)"
if [ -n "$missed" ]; then
  echo "backup: WARNING these tables exist and are NOT backed up:" >&2
  echo "$missed" | sed 's/^/backup:   /' >&2
  echo "backup:   add them to CH_TABLES in this script, or to CH_NOT_DATA if they are bookkeeping" >&2
fi

# ---------------------------------------------------------------- manifest

FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TOTAL_SECONDS=$(( $(date +%s) - START_EPOCH ))

# Both ends of the window, because the telemetry export is logical: the restored database
# is consistent as of somewhere between these two instants and the manifest is the only
# place that says where.
cat > "$DEST/manifest.json" <<JSON
{
  "started_at": "${STARTED}",
  "finished_at": "${FINISHED}",
  "seconds": ${TOTAL_SECONDS},
  "control_plane": {
    "format": "pg_dump custom",
    "bytes": ${PG_BYTES},
    "seconds": ${PG_SECONDS}
  },
  "telemetry": {
    "format": "ClickHouse Native, one file per table",
    "database": "${CLICKHOUSE_DB}",
    "rows": ${CH_ROWS_TOTAL},
    "bytes": ${CH_BYTES_TOTAL},
    "seconds": ${CH_SECONDS}
  },
  "excluded": [
    "the key-encryption key: SPEC M0.4, it never enters the database. Back it up with whatever holds your other secrets, or the credentials in this dump are locked boxes"
  ],
  "commit": "$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
}
JSON

echo
echo "backup: done in ${TOTAL_SECONDS}s — $DEST"
echo "backup: the KEK is NOT in here. Without it a restore cannot open any device credential."
