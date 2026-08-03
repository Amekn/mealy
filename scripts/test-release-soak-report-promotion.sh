#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
promoter=$repository_root/scripts/promote-release-soak-report.sh
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-soak-promotion-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

revision=0123456789abcdef0123456789abcdef01234567
source_report=$temporary/source.json
destination=$temporary/destination.json
printf '%s' '{"schemaVersion":"mealy.soak-report.v2","sourceState":"clean_revision","revision":"'"$revision"'"}' \
  >"$source_report"
printf 'stale\n' >"$destination"
"$promoter" "$source_report" "$destination" >/dev/null
cmp -s "$source_report" "$destination"
test "$(stat -c '%a' "$destination")" = 644
test "$(stat -c '%s' "$source_report")" -eq "$(stat -c '%s' "$destination")"

malformed=$temporary/malformed.json
printf '%s' '{}' >"$malformed"
if "$promoter" "$malformed" "$temporary/rejected.json" >/dev/null 2>&1; then
  echo "malformed release-soak report was accepted" >&2
  exit 1
fi

source_link=$temporary/source-link.json
ln -s "$source_report" "$source_link"
if "$promoter" "$source_link" "$temporary/rejected-link.json" >/dev/null 2>&1; then
  echo "symlinked release-soak source was accepted" >&2
  exit 1
fi

destination_link=$temporary/destination-link.json
ln -s "$destination" "$destination_link"
if "$promoter" "$source_report" "$destination_link" >/dev/null 2>&1; then
  echo "symlinked release-soak destination was accepted" >&2
  exit 1
fi

printf 'release soak report promotion tests: ok\n'
