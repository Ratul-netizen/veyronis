#!/usr/bin/env bash
# M8's two open acceptance criteria, measured.
#
# `docs/M8-observability.md` §2.2 and §2.6 each make a bet, and each was written with the
# obligation to measure it attached, because the alternative to measuring is assuming:
#
#   §2.2  "It must be measured rather than assumed. The number to record is granules read
#          for a single-trace lookup at 100M spans."
#   §2.6  "The cost is not measured. A hash join over the window."
#
# ────────────────────────────────────────────────────────────────────────────────────
# THE TRAP THIS SCRIPT EXISTS TO AVOID: EVERY TRACE ID IS USED EXACTLY ONCE
# ────────────────────────────────────────────────────────────────────────────────────
#
# The first version of this script did what a benchmark normally does — ran each query
# five times and took the median. Every configuration then reported the same number:
# 40 960 rows in 9 ms, whether the skip index was on, off, or ignored. Which is
# impossible, and was the measurement measuring itself.
#
# ClickHouse remembers which granules matched a predicate. The second run of a lookup
# reads only the granules the first one found, so a repeated benchmark query measures
# that memory rather than the index. Turning `use_skip_indexes` off does not help,
# because the pruning has already happened and been recorded.
#
# So: **one trace id per configuration, never queried before.** That makes each number a
# single cold observation rather than a median, which is the honest trade — a median of
# warm runs is precise about the wrong thing. Ids are taken from different days of the
# range, because a lookup near the start of a sorted table is not evidence about one in
# the middle.
#
# Usage:
#   CH_URL=http://host:8123 CH_USER=u CH_PASSWORD=p bash bench/scripts/m8.sh

set -euo pipefail

CH="${CH_URL:-http://localhost:8123}/?user=${CH_USER:-bench}&password=${CH_PASSWORD:-bench}"
TABLE="bench.spans"

qs() { printf '%s' "$1" | curl -sS --data-binary @- "$CH"; }

# Run a statement as JSON and print "<rows_read> <elapsed_ms> <result_rows>".
#
# From the response body, not from a header: `X-ClickHouse-Summary` is sent before the
# query finishes unless progress headers are configured, so reading it gives whatever had
# been counted at flush time. That produced a plausible, wrong 40 960 for a full scan.
stat() {
  printf '%s' "$1 FORMAT JSON" | curl -sS --data-binary @- "$CH" | python -c '
import json, sys
d = json.load(sys.stdin)
s = d["statistics"]
print(s["rows_read"], round(s["elapsed"] * 1000), len(d["data"]))
'
}

echo "== M8 measurements against $TABLE =="
ROWS=$(qs "SELECT count() FROM $TABLE FORMAT TSV")
[ "${ROWS:-0}" -gt 0 ] || { echo "the table is empty; run bench/scripts/load.sh spans first" >&2; exit 1; }
echo "rows:    $ROWS"
echo "range:   $(qs "SELECT concat(toString(min(observed_at)), ' .. ', toString(max(observed_at))) FROM $TABLE FORMAT TSV")"
echo "version: $(qs "SELECT version() FORMAT TSV")"
TENANT=$(qs "SELECT toString(tenant_id) FROM $TABLE LIMIT 1 FORMAT TSV")
echo "tenant:  $TENANT ($(qs "SELECT count() FROM $TABLE WHERE tenant_id = toUUID('$TENANT') FORMAT TSV") spans)"

# A trace id from day N of the range that nothing has looked at yet.
fresh_trace() {
  qs "SELECT trace_id FROM $TABLE
      WHERE tenant_id = toUUID('$TENANT') AND observed_at > '2026-08-2$1 0$1:00:00'
      LIMIT 1 OFFSET $(( $1 * 4211 )) FORMAT TSV"
}

echo
echo "-- §2.2  one trace by trace_id, at $ROWS spans, each id cold --"
printf '%-34s %12s %8s %8s\n' "index configuration" "rows read" "ms" "spans"

run_lookup() {
  local label="$1" settings="$2" trace="$3"
  local out
  out=$(stat "SELECT count() FROM $TABLE WHERE tenant_id = toUUID('$TENANT') AND trace_id = '$trace' SETTINGS $settings")
  printf '%-34s %12s %8s %8s\n' "$label" "$(echo "$out" | cut -d' ' -f1)" "$(echo "$out" | cut -d' ' -f2)" \
    "$(qs "SELECT count() FROM $TABLE WHERE tenant_id = toUUID('$TENANT') AND trace_id = '$trace' FORMAT TSV")"
}

run_lookup "no skip index"           "use_skip_indexes = 0"            "$(fresh_trace 2)"
run_lookup "bloom_filter, as declared" "use_skip_indexes = 1"          "$(fresh_trace 4)"

echo
echo "-- §2.6  the service map over one hour --"

START="$(qs "SELECT toString(min(observed_at) + INTERVAL 3 DAY) FROM $TABLE FORMAT TSV")"
END="$(qs "SELECT toString(min(observed_at) + INTERVAL 3 DAY + INTERVAL 1 HOUR) FROM $TABLE FORMAT TSV")"
IN_WINDOW=$(qs "SELECT count() FROM $TABLE WHERE tenant_id = toUUID('$TENANT')
                AND observed_at >= toDateTime64('$START',3,'UTC')
                AND observed_at <  toDateTime64('$END',3,'UTC') FORMAT TSV")
echo "window: $START .. $END  ($IN_WINDOW spans)"

MAP="SELECT parent.service_id AS from_service, child.service_id AS to_service,
      count() AS calls, countIf(child.status_code = 'error') AS errors,
      toUInt64(quantileTDigest(0.95)(child.duration_ns)) AS p95
    FROM $TABLE AS child
    INNER JOIN (SELECT span_id, service_id FROM $TABLE
                WHERE tenant_id = toUUID('$TENANT')
                  AND observed_at >= toDateTime64('$START', 3, 'UTC')
                  AND observed_at <  toDateTime64('$END', 3, 'UTC')
                  AND service_id != toUUID('00000000-0000-0000-0000-000000000000')) AS parent
      ON child.parent_span_id = parent.span_id
    WHERE child.tenant_id = toUUID('$TENANT')
      AND child.observed_at >= toDateTime64('$START', 3, 'UTC')
      AND child.observed_at <  toDateTime64('$END', 3, 'UTC')
      AND child.parent_span_id != ''
      AND child.service_id != toUUID('00000000-0000-0000-0000-000000000000')
      AND child.service_id != parent.service_id
    GROUP BY from_service, to_service ORDER BY calls DESC LIMIT 500"

OUT=$(stat "$MAP")
printf 'edges %s · rows read %s · %s ms\n' \
  "$(echo "$OUT" | cut -d' ' -f3)" "$(echo "$OUT" | cut -d' ' -f1)" "$(echo "$OUT" | cut -d' ' -f2)"

echo
echo "-- storage --"
qs "SELECT table, formatReadableSize(sum(data_compressed_bytes)) AS compressed,
      formatReadableSize(sum(data_uncompressed_bytes)) AS uncompressed,
      round(sum(data_uncompressed_bytes) / sum(data_compressed_bytes), 2) AS ratio,
      formatReadableSize(sum(secondary_indices_compressed_bytes)) AS skip_index,
      sum(marks) AS granules, sum(rows) AS rows
    FROM system.parts WHERE database = 'bench' AND table = 'spans' AND active
    GROUP BY table FORMAT PrettyCompact"
