#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: supervise-release-soak.sh REPORT.json RECEIPT.json -- COMMAND [ARG ...]" >&2
}

if [[ $# -lt 4 || $3 != -- ]]; then
  usage
  exit 64
fi

report=$1
receipt=$2
shift 3

for command in basename chmod date dirname jq mktemp mv rm sha256sum stat sync; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-soak supervisor command is unavailable: $command" >&2
    exit 69
  }
done

normalize_new_path() {
  local candidate=$1
  local label=$2
  local parent name
  parent=$(dirname -- "$candidate")
  name=$(basename -- "$candidate")
  if [[ $name == . || $name == .. || $name == / \
    || -L $parent || ! -d $parent ]]; then
    echo "$label parent must be an existing non-symlink directory" >&2
    return 64
  fi
  parent=$(cd "$parent" && pwd -P)
  candidate="$parent/$name"
  if [[ -e $candidate || -L $candidate ]]; then
    echo "$label destination must not already exist: $candidate" >&2
    return 73
  fi
  printf '%s\n' "$candidate"
}

report=$(normalize_new_path "$report" "release-soak report") || exit $?
receipt=$(normalize_new_path "$receipt" "release-soak supervisor receipt") || exit $?
if [[ $report == "$receipt" ]]; then
  echo "release-soak report and supervisor receipt must be distinct" >&2
  exit 64
fi
failure_report=$report.failure.json
if [[ -e $failure_report || -L $failure_report ]]; then
  echo "release-soak failure destination must not already exist: $failure_report" >&2
  exit 73
fi

started_at_unix_ms=$(( $(date +%s) * 1000 ))
set +e
"$@"
command_status=$?
set -e
finished_at_unix_ms=$(( $(date +%s) * 1000 ))

result=failure
report_sha256=null
report_bytes=null
report_revision=null
effective_status=$command_status
if [[ $command_status -eq 0 \
  && ! -L $report && -f $report && -s $report \
  && ! -e $failure_report && ! -L $failure_report ]]; then
  candidate_report_bytes=$(stat -c '%s' -- "$report")
  if (( candidate_report_bytes >= 2 && candidate_report_bytes <= 16 * 1024 * 1024 )) \
    && report_revision_value=$(jq -er '
    select(
      .schemaVersion == "mealy.soak-report.v2"
      and .sourceState == "clean_revision"
      and (.revision | type == "string" and test("^[0-9a-f]{40}$"))
    )
    | .revision
  ' "$report"); then
    result=success
    report_sha256_value=$(sha256sum "$report")
    report_sha256_value=${report_sha256_value%% *}
    report_sha256=$(jq -Rn --arg value "$report_sha256_value" '$value')
    report_bytes=$candidate_report_bytes
    report_revision=$(jq -Rn --arg value "$report_revision_value" '$value')
  else
    effective_status=65
  fi
elif [[ $command_status -eq 0 ]]; then
  effective_status=65
fi

receipt_parent=$(dirname -- "$receipt")
receipt_name=$(basename -- "$receipt")
temporary=$(mktemp "$receipt_parent/.${receipt_name}.XXXXXX")
# shellcheck disable=SC2317,SC2329 # Invoked by the EXIT trap.
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT
jq -n \
  --arg result "$result" \
  --argjson command_exit_status "$effective_status" \
  --argjson started_at_unix_ms "$started_at_unix_ms" \
  --argjson finished_at_unix_ms "$finished_at_unix_ms" \
  --arg report_name "$(basename -- "$report")" \
  --argjson report_sha256 "$report_sha256" \
  --argjson report_bytes "$report_bytes" \
  --argjson report_revision "$report_revision" '
  {
    schemaVersion: "mealy.soak-supervisor-receipt.v1",
    result: $result,
    commandExitStatus: $command_exit_status,
    startedAtUnixMs: $started_at_unix_ms,
    finishedAtUnixMs: $finished_at_unix_ms,
    reportName: $report_name,
    reportSha256: $report_sha256,
    reportBytes: $report_bytes,
    reportRevision: $report_revision
  }
' >"$temporary"
chmod 0600 "$temporary"
sync -f "$temporary"
mv -fT -- "$temporary" "$receipt"
temporary=
sync -f "$receipt_parent"

if [[ $result == success ]]; then
  printf 'release soak supervisor: success receipt published (%s)\n' "$receipt"
else
  printf 'release soak supervisor: failure receipt published (status %s)\n' \
    "$effective_status" >&2
fi
exit "$effective_status"
