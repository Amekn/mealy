#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
supervisor=$repository_root/scripts/supervise-release-soak.sh
validator=$repository_root/scripts/validate-release-soak-supervisor-receipt.sh
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-soak-supervisor-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

revision=0123456789abcdef0123456789abcdef01234567
payload='{"schemaVersion":"mealy.soak-report.v2","sourceState":"clean_revision","revision":"'"$revision"'"}'
report=$temporary/success.json
receipt=$temporary/success-receipt.json
# shellcheck disable=SC2016 # Positional parameters expand inside the child shell.
"$supervisor" "$report" "$receipt" -- \
  bash -c 'printf "%s" "$1" >"$2"' _ "$payload" "$report" >/dev/null
"$validator" "$receipt" "$report" >/dev/null
test "$(jq -r .result "$receipt")" = success
test "$(jq -r .commandExitStatus "$receipt")" -eq 0
test "$(stat -c '%a' "$receipt")" = 600

failed_report=$temporary/failed.json
failed_receipt=$temporary/failed-receipt.json
set +e
"$supervisor" "$failed_report" "$failed_receipt" -- bash -c 'exit 42' >/dev/null 2>&1
status=$?
set -e
test "$status" -eq 42
test "$(jq -r .result "$failed_receipt")" = failure
test "$(jq -r .commandExitStatus "$failed_receipt")" -eq 42
if "$validator" "$failed_receipt" "$failed_report" >/dev/null 2>&1; then
  echo "failed release-soak receipt was accepted" >&2
  exit 1
fi

missing_report=$temporary/missing.json
missing_receipt=$temporary/missing-receipt.json
set +e
"$supervisor" "$missing_report" "$missing_receipt" -- true >/dev/null 2>&1
status=$?
set -e
test "$status" -eq 65
test "$(jq -r .result "$missing_receipt")" = failure
test "$(jq -r .commandExitStatus "$missing_receipt")" -eq 65

printf ' ' >>"$report"
if "$validator" "$receipt" "$report" >/dev/null 2>&1; then
  echo "tampered supervised release-soak report was accepted" >&2
  exit 1
fi

printf 'release soak supervisor tests: ok\n'
