#!/usr/bin/env bash
# Restore either plane, or both — M12 §2.4, `docs/M12-enterprise.md`.
#
#   bash scripts/restore.sh <directory> [--control-plane-only|--telemetry-only]
#
# The destination comes from the environment, never from the backup. A restore script
# that remembered where it was taken from is a restore script that one day writes over
# production because somebody ran a rehearsal with the wrong variables unset:
#
#   RESTORE_DATABASE_URL=postgres://uops@127.0.0.1:5432/uops_restored
#   RESTORE_CLICKHOUSE_DB=uops_restored
#
# Both are **required**. There is no default, and the defaults that suggest themselves are
# exactly the two databases you do not want to overwrite.
#
# # Why the two planes can be restored separately
#
# Because the failures are separate. A control plane lost to a bad migration needs the
# control plane back and nothing else — the telemetry is fine and re-loading it would be
# hours of avoidable downtime. A ClickHouse node lost to a disk needs telemetry back and
# must not touch identity, roles or credentials, which have moved on since the backup.
#
# # The order inside each plane
#
# PostgreSQL restores schema **and** data from the dump, including `_sqlx_migrations`, so
# the restored database knows exactly where it is. Re-running migrations onto restored
# data instead would work right up until the day the dump and the migration directory
# disagreed, and then it would fail halfway through with the data already in.
#
# ClickHouse is the other way round: the schema comes from `ch-migrations` and only the
# rows come from the backup. That is not an inconsistency, it is what the two engines are.
# The Native files hold rows and nothing else; a ClickHouse table's definition — its sort
# key, its codecs, its projections and its bloom filters — is the product's, not the
# backup's, and restoring a six-month-old table definition would quietly undo every
# storage decision made since.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SRC="${1:-}"
MODE="${2:-both}"
if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
  echo "usage: bash scripts/restore.sh <directory> [--control-plane-only|--telemetry-only]" >&2
  exit 2
fi

: "${CLICKHOUSE_URL:=http://localhost:8123}"
: "${CLICKHOUSE_USER:=uops}"
: "${CLICKHOUSE_PASSWORD:=uops}"

want_pg=1
want_ch=1
case "$MODE" in
  --control-plane-only) want_ch=0 ;;
  --telemetry-only) want_pg=0 ;;
  both) ;;
  *) echo "restore: unknown option $MODE" >&2; exit 2 ;;
esac

START_EPOCH="$(date +%s)"
echo "restore: from $SRC"
[ -f "$SRC/manifest.json" ] && echo "restore: backup taken $(grep -o '"started_at": "[^"]*"' "$SRC/manifest.json" | cut -d'"' -f4)"

# ---------------------------------------------------------------- control plane

if [ "$want_pg" = 1 ]; then
  if [ -z "${RESTORE_DATABASE_URL:-}" ]; then
    echo "restore: RESTORE_DATABASE_URL is not set. It has no default on purpose — see the header." >&2
    exit 2
  fi

  echo
  echo "-- PostgreSQL (control plane) -> ${RESTORE_DATABASE_URL##*/} --"
  PG_START="$(date +%s)"

  # `--clean --if-exists` so a rehearsal can be run twice into the same scratch database
  # without a pile of "already exists" errors hiding a real one.
  #
  # Not `--exit-on-error`: a dump restored into a database whose roles do not exist
  # produces harmless GRANT failures, and stopping on the first one would leave a
  # half-restored database while reporting a problem nobody needs to fix. The row counts
  # at the end are what says whether it worked.
  pg_restore --clean --if-exists --no-owner --no-privileges \
    --dbname="$RESTORE_DATABASE_URL" "$SRC/control-plane.dump" 2>&1 \
    | grep -v "^pg_restore: warning: errors ignored on restore" || true

  PG_SECONDS=$(( $(date +%s) - PG_START ))

  # What actually landed. A restore that reported success and restored nothing is the
  # failure this line exists to catch.
  pg_counts="$(psql "$RESTORE_DATABASE_URL" -tAc "
    SELECT format('%s users, %s tenants, %s resources, %s sealed credentials, %s collectors',
      (SELECT count(*) FROM app_user),
      (SELECT count(*) FROM tenant),
      (SELECT count(*) FROM resource),
      (SELECT count(*) FROM credential),
      (SELECT count(*) FROM collector))")"
  migrations="$(psql "$RESTORE_DATABASE_URL" -tAc "SELECT max(version) FROM _sqlx_migrations")"

  echo "restore: control plane in ${PG_SECONDS}s — ${pg_counts}"
  echo "restore: schema is at migration ${migrations}"
fi

# ---------------------------------------------------------------- telemetry

if [ "$want_ch" = 1 ]; then
  if [ -z "${RESTORE_CLICKHOUSE_DB:-}" ]; then
    echo "restore: RESTORE_CLICKHOUSE_DB is not set. It has no default on purpose — see the header." >&2
    exit 2
  fi

  echo
  echo "-- ClickHouse (telemetry plane) -> ${RESTORE_CLICKHOUSE_DB} --"
  CH_START="$(date +%s)"

  ch_into() {
    curl -sS -f \
      "${CLICKHOUSE_URL}/?user=${CLICKHOUSE_USER}&password=${CLICKHOUSE_PASSWORD}&database=${RESTORE_CLICKHOUSE_DB}" \
      "$@"
  }

  # The schema first, from the migrations rather than from the backup. See the header.
  echo "restore: applying ch-migrations to ${RESTORE_CLICKHOUSE_DB}"
  (
    cd "$ROOT"
    CLICKHOUSE_DB="$RESTORE_CLICKHOUSE_DB" \
    CLICKHOUSE_URL="$CLICKHOUSE_URL" \
    CLICKHOUSE_USER="$CLICKHOUSE_USER" \
    CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" \
      cargo run --quiet -p uops-ch-migrate -- apply
  )

  ch_sql() {
    curl -sS -f \
      "${CLICKHOUSE_URL}/?user=${CLICKHOUSE_USER}&password=${CLICKHOUSE_PASSWORD}&database=${RESTORE_CLICKHOUSE_DB}" \
      --data-binary @-
  }

  # ------------------------------------------------------------------------
  # Detach every materialized view for the duration of the load.
  #
  # **This is what the first drill got wrong**, and it is the reason §2.4 asks for a
  # drill rather than a procedure. The backup holds the raw tables *and* the aggregates
  # they feed. Load the raw rows with the views attached and every view fires, writing
  # into an aggregate table that already holds the rows restored from the backup — so
  # every aggregate doubles, and `metrics_1h` tripled, because two of its inputs were
  # restored.
  #
  # Nothing complains. The restore reports success, the raw counts are exactly right, and
  # every dashboard built on a five-minute rollup reads twice the traffic that existed. A
  # backup verified by "did the restore command succeed" would ship that.
  #
  # Rebuilding the aggregates from the restored raw data instead would be wrong in a
  # different way: an aggregate outlives the raw rows it came from — that is what it is
  # for — so everything older than the raw retention would silently vanish.
  views="$(echo "SELECT name FROM system.tables WHERE database = '${RESTORE_CLICKHOUSE_DB}' AND engine = 'MaterializedView' ORDER BY name" | ch_sql)"
  if [ -n "$views" ]; then
    echo "restore: detaching $(echo "$views" | tr -d '\r' | grep -c .) materialized view(s) for the load"
    for view in $views; do
      echo "DETACH TABLE ${view}" | ch_sql
    done
  fi


  CH_ROWS=0
  while IFS=, read -r table rows _bytes; do
    [ "$table" = "table" ] && continue
    file="$SRC/telemetry/${table}.native"
    [ -f "$file" ] || continue

    # Empty files are legitimate — a deployment with no flows has an empty flows table —
    # and posting one is a request ClickHouse rejects for having no data.
    if [ ! -s "$file" ]; then
      echo "restore: ${table} was empty at backup time"
      continue
    fi

    # The query goes in the URL and the rows go in the body. It cannot be the other way
    # round: `--data-urlencode` would put a megabyte of Native-format binary into the
    # request line, which curl rejects before the server ever sees it. The first drill
    # tried that, fell through to a fallback, and printed a `curl: (3)` per table while
    # appearing to succeed.
    ch_into --data-binary "@${file}" \
      --url-query "query=INSERT INTO ${table} FORMAT Native" >/dev/null

    echo "restore: ${table} ${rows} rows"
    CH_ROWS=$(( CH_ROWS + rows ))
  done < "$SRC/telemetry/manifest.csv"

  # Back on, so the restored database keeps aggregating whatever arrives next. A restore
  # that left them detached would produce a deployment whose rollups stopped on the day of
  # the incident — noticed weeks later, as a dashboard that goes flat.
  if [ -n "$views" ]; then
    for view in $views; do
      echo "ATTACH TABLE ${view}" | ch_sql
    done
    echo "restore: materialized views re-attached"
  fi

  CH_SECONDS=$(( $(date +%s) - CH_START ))
  echo "restore: telemetry ${CH_ROWS} rows in ${CH_SECONDS}s"
fi

TOTAL=$(( $(date +%s) - START_EPOCH ))
echo
echo "restore: done in ${TOTAL}s"

if [ "$want_pg" = 1 ]; then
  cat <<'NOTE'

restore: the key-encryption key is not in a backup and never was.
         Point this deployment at the SAME UOPS_KEK_FILE / UOPS_KEK_HEX it had before,
         or every device credential in the restored control plane is a locked box:
         the inventory, the users, the roles, the rules and the dashboards all work,
         and nothing can be polled.

         A rehearsal that did not also rehearse the key material rehearsed the easy half.
NOTE
fi
