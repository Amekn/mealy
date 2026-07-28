#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 || -L $1 || ! -f $1 || -z $2 || ! $3 =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: validate-release-upgrade-baseline.sh MANIFEST RELEASE_VERSION RELEASE_SCHEMA" >&2
  exit 64
fi
for command in jq stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "release upgrade-baseline validation requires $command" >&2
    exit 69
  fi
done
manifest=$1
release_version=$2
release_schema=$3
if [[ $(stat -c '%s' "$manifest") -gt 4096 ]]; then
  echo "release upgrade-baseline manifest exceeds 4 KiB" >&2
  exit 65
fi

jq -e \
  --arg release_version "$release_version" \
  --argjson release_schema "$release_schema" '
    type == "object"
    and (keys == [
      "baselineStateSchemaVersion",
      "baselineTag",
      "baselineVersion",
      "releaseStateSchemaVersion",
      "releaseVersion",
      "schemaVersion"
    ])
    and .schemaVersion == "mealy.release-upgrade-baseline.v1"
    and .releaseVersion == $release_version
    and .releaseStateSchemaVersion == $release_schema
    and (.releaseVersion | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
    and (.baselineVersion | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
    and .baselineTag == ("v" + .baselineVersion)
    and .baselineVersion != .releaseVersion
    and (.baselineStateSchemaVersion
      | type == "number" and floor == . and . >= 1 and . <= 9999)
    and .baselineStateSchemaVersion < .releaseStateSchemaVersion
  ' "$manifest" >/dev/null || {
    echo "release upgrade-baseline manifest does not match this candidate" >&2
    exit 65
  }

jq -c . "$manifest"
