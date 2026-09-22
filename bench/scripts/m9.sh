#!/usr/bin/env bash
# M9's last open acceptance criterion, measured.
#
# `docs/M9-incident.md` §4:
#
#   "The timeline for a one-hour incident over 100M rows is answered from the sort key,
#    measured rather than assumed — W1's method, and W1's 9 ms is the number to beat."
#
# WHAT IS ACTUALLY BEING TESTED
#
# PLAN §6 named the Investigation Workspace at M0 **because it constrained M0's
# decisions**: every store had to answer "all signals for resource R in window W" cheaply,
# and that is why every telemetry table is `ORDER BY (tenant_id, resource_id,
# observed_at)`. The claim is that the timeline is therefore N contiguous range reads
# rather than N scans.
#
# A range read at this scale shows up as **rows read**, not as milliseconds. Two granules
# out of twelve thousand is the property of the sort key; the wall clock that follows from
# it moves with the page cache and the host. So the number to look at first is how much of
# the table each track touched.
#
# The comparison is the same query with the resource predicate removed, which is what the
# timeline would cost if the sort key led with time instead — the design that was rejected
# in M0 and can now be priced.
#
# EVERY QUERY IS COLD
#
# The M8 run learned this the expensive way: ClickHouse remembers which granules matched a
# predicate, so repeating a query measures that memory rather than the index. Each
# measurement below uses a resource and a window nothing has asked about before.
#
# Usage:
#   CH_URL=http://host:8123 CH_USER=u CH_PASSWORD=p bash bench/scripts/m9.sh

set -euo pipefail

CH="${CH_URL:-http://localhost:8123}/?user=${CH_USER:-bench}&password=${CH_PASSWORD:-bench}"

qs() { printf '%s' "$1" | curl -sS --data-binary @- "$CH"; }

# Run a statement as JSON and print "<rows_read> <elapsed_ms> <result_rows>".
#
# From the response body: `X-ClickHouse-Summary` is sent before the query finishes unless
# progress headers are on, which in the M8 run produced a plausible and wrong number.
stat() {
  printf '%s' "$1 FORMAT JSON" | curl -sS --data-binary @- "$CH" | python -c '
import json, sys
d = json.load(sys.stdin)
s = d["statistics"]
print(s["rows_read"], round(s["elapsed"] * 1000), len(d["data"]))
'
}

echo "== M9: the timeline, against bench =="
echo "version: $(qs "SELECT version() FORMAT TSV")"

for table in logs spans; do
  rows=$(qs "SELECT count() FROM bench.$table FORMAT TSV" 2>/dev/null || echo 0)
  printf '%-6s %s rows\n' "$table" "${rows:-0}"
done
echo

# One tenant and two resources that nothing has queried, to stand in for an incident's
# membership. Read once; the cost of finding them is setup, not measurement.
TENANT=$(qs "SELECT toString(tenant_id) FROM bench.logs LIMIT 1 FORMAT TSV")
RESOURCES=$(qs "SELECT toString(resource_id) FROM bench.logs
                WHERE tenant_id = toUUID('$TENANT') AND observed_at > '2026-08-25 04:00:00'
                LIMIT 2 BY resource_id LIMIT 2 FORMAT TSV" | tr '\n' ' ')
IN_LIST=$(printf "toUUID('%s')," $RESOURCES | sed 's/,$//')
echo "tenant:    $TENANT"
echo "resources: $RESOURCES"

# An hour nothing has looked at, in the middle of the range.
START=$(qs "SELECT toString(min(observed_at) + INTERVAL 4 DAY + INTERVAL 7 HOUR) FROM bench.logs FORMAT TSV")
END=$(qs "SELECT toString(min(observed_at) + INTERVAL 4 DAY + INTERVAL 8 HOUR) FROM bench.logs FORMAT TSV")
echo "window:    $START .. $END"
echo

# The timeline's actual query shape — `uops_query::timeline::one`: this window, these
# resources, oldest first, five hundred rows.
track() {
  local table="$1" cols="$2"
  echo "SELECT $cols FROM bench.$table
        WHERE tenant_id = toUUID('$TENANT')
          AND resource_id IN ($IN_LIST)
          AND observed_at >= toDateTime64('$START', 3, 'UTC')
          AND observed_at <  toDateTime64('$END', 3, 'UTC')
        ORDER BY observed_at ASC LIMIT 500"
}

# The same window and columns with no resource predicate: what one track costs when the
# sort key cannot narrow it. This is the number the M0 decision bought.
scan() {
  local table="$1" cols="$2"
  echo "SELECT $cols FROM bench.$table
        WHERE tenant_id = toUUID('$TENANT')
          AND observed_at >= toDateTime64('$START', 3, 'UTC')
          AND observed_at <  toDateTime64('$END', 3, 'UTC')
        ORDER BY observed_at ASC LIMIT 500"
}

printf '%-28s %12s %8s %8s\n' "track" "rows read" "ms" "returned"

TOTAL_ROWS=0
TOTAL_MS=0
for pair in "logs:observed_at, severity, body" "spans:observed_at, name, status_code"; do
  table="${pair%%:*}"
  cols="${pair#*:}"
  out=$(stat "$(track "$table" "$cols")")
  read -r rows ms returned <<<"$out"
  printf '%-28s %12s %8s %8s\n' "$table (sort key)" "$rows" "$ms" "$returned"
  TOTAL_ROWS=$((TOTAL_ROWS + rows))
  TOTAL_MS=$((TOTAL_MS + ms))
done

echo
printf 'six-signal timeline: %s rows read, %s ms of server time for the two tracks that hold 100M rows each\n' \
  "$TOTAL_ROWS" "$TOTAL_MS"
echo "(the other four tracks are the same statement against empty tables here)"

echo
echo "-- the same hour without the resource predicate, which is what a time-first sort key would cost --"
printf '%-28s %12s %8s %8s\n' "track" "rows read" "ms" "returned"
for pair in "logs:observed_at, severity, body" "spans:observed_at, name, status_code"; do
  table="${pair%%:*}"
  cols="${pair#*:}"
  out=$(stat "$(scan "$table" "$cols")")
  read -r rows ms returned <<<"$out"
  printf '%-28s %12s %8s %8s\n' "$table (whole tenant)" "$rows" "$ms" "$returned"
done

echo
echo "-- storage --"
qs "SELECT table, formatReadableSize(sum(data_compressed_bytes)) AS compressed,
      sum(marks) AS granules, sum(rows) AS rows
    FROM system.parts WHERE database = 'bench' AND active
    GROUP BY table ORDER BY table FORMAT PrettyCompact"
