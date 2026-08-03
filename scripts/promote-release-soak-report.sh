#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: promote-release-soak-report.sh SOURCE.json DESTINATION.json" >&2
}

if [[ $# -ne 2 ]]; then
  usage
  exit 64
fi

source_report=$1
destination=$2

for command in basename chmod cmp dirname install jq mktemp mv readlink rm sha256sum stat sync; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-soak promotion command is unavailable: $command" >&2
    exit 69
  }
done

if [[ -L $source_report || ! -f $source_report ]]; then
  echo "release-soak source must be a regular non-symlink file" >&2
  exit 66
fi
source_report=$(readlink -f -- "$source_report")
source_bytes=$(stat -c '%s' -- "$source_report")
if (( source_bytes < 2 || source_bytes > 16 * 1024 * 1024 )); then
  echo "release-soak source is empty or exceeds its 16 MiB evidence bound" >&2
  exit 65
fi
if ! jq -e '
  select(
    .schemaVersion == "mealy.soak-report.v2"
    and .sourceState == "clean_revision"
    and (.revision | type == "string" and test("^[0-9a-f]{40}$"))
  )
' "$source_report" >/dev/null; then
  echo "release-soak source does not identify a clean canonical observation" >&2
  exit 65
fi

destination_parent=$(dirname -- "$destination")
destination_name=$(basename -- "$destination")
if [[ $destination_name == . || $destination_name == .. || $destination_name == / \
  || -L $destination_parent || ! -d $destination_parent ]]; then
  usage
  exit 64
fi
destination_parent=$(cd "$destination_parent" && pwd -P)
destination="$destination_parent/$destination_name"
if [[ $destination == "$source_report" ]]; then
  echo "release-soak source and destination must be distinct" >&2
  exit 64
fi
if [[ -L $destination || (-e $destination && ! -f $destination) ]]; then
  echo "release-soak destination must be absent or a regular non-symlink file" >&2
  exit 73
fi

temporary=$(mktemp "$destination_parent/.mealy-release-soak.XXXXXX")
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT

install -m 0644 -- "$source_report" "$temporary"
if ! cmp -s -- "$source_report" "$temporary"; then
  echo "release-soak temporary copy is not byte-identical" >&2
  exit 74
fi
source_sha256=$(sha256sum "$source_report")
source_sha256=${source_sha256%% *}
sync -f "$temporary"
mv -fT -- "$temporary" "$destination"
temporary=
sync -f "$destination_parent"

destination_sha256=$(sha256sum "$destination")
destination_sha256=${destination_sha256%% *}
if [[ $destination_sha256 != "$source_sha256" \
  || $(stat -c '%s' -- "$destination") -ne $source_bytes ]] \
  || ! cmp -s -- "$source_report" "$destination"; then
  echo "promoted release-soak report is not byte-identical" >&2
  exit 74
fi
chmod 0644 "$destination"
printf 'release soak report promotion: ok (%s, %s bytes)\n' \
  "$source_sha256" "$source_bytes"
