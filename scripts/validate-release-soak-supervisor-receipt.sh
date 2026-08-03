#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: validate-release-soak-supervisor-receipt.sh RECEIPT.json REPORT.json" >&2
}

if [[ $# -ne 2 ]]; then
  usage
  exit 64
fi

receipt=$1
report=$2
for command in basename jq sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-soak receipt command is unavailable: $command" >&2
    exit 69
  }
done
if [[ -L $receipt || ! -f $receipt || -L $report || ! -f $report \
  || -e $report.failure.json || -L $report.failure.json ]]; then
  echo "release-soak receipt/report boundary is incomplete" >&2
  exit 65
fi
receipt_bytes=$(stat -c '%s' -- "$receipt")
report_bytes=$(stat -c '%s' -- "$report")
if (( receipt_bytes < 2 || receipt_bytes > 64 * 1024 \
  || report_bytes < 2 || report_bytes > 16 * 1024 * 1024 )); then
  echo "release-soak receipt/report exceeds its evidence bound" >&2
  exit 65
fi
report_sha256=$(sha256sum "$report")
report_sha256=${report_sha256%% *}
report_revision=$(jq -er '
  select(
    .schemaVersion == "mealy.soak-report.v2"
    and .sourceState == "clean_revision"
    and (.revision | type == "string" and test("^[0-9a-f]{40}$"))
  )
  | .revision
' "$report") || {
  echo "release-soak report identity is invalid" >&2
  exit 65
}
if ! jq -e \
  --arg report_name "$(basename -- "$report")" \
  --arg report_sha256 "$report_sha256" \
  --argjson report_bytes "$report_bytes" \
  --arg report_revision "$report_revision" '
  select(
    .schemaVersion == "mealy.soak-supervisor-receipt.v1"
    and .result == "success"
    and .commandExitStatus == 0
    and (.startedAtUnixMs | type == "number" and . >= 0)
    and (.finishedAtUnixMs | type == "number")
    and .finishedAtUnixMs >= .startedAtUnixMs
    and .reportName == $report_name
    and .reportSha256 == $report_sha256
    and .reportBytes == $report_bytes
    and .reportRevision == $report_revision
    and (keys | sort) == ([
      "commandExitStatus",
      "finishedAtUnixMs",
      "reportBytes",
      "reportName",
      "reportRevision",
      "reportSha256",
      "result",
      "schemaVersion",
      "startedAtUnixMs"
    ] | sort)
  )
' "$receipt" >/dev/null; then
  echo "release-soak supervisor receipt does not bind a successful command and exact report" >&2
  exit 65
fi
printf 'release soak supervisor receipt: ok (%s, %s)\n' \
  "$report_revision" "$report_sha256"
