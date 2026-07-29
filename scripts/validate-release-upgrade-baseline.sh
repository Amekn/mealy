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

jq -e -c \
  --arg release_version "$release_version" \
  --argjson release_schema "$release_schema" '
    if type != "object" then
      error("manifest type")
    elif .schemaVersion == "mealy.release-upgrade-baseline.v1" then
      if keys != [
        "baselineStateSchemaVersion",
        "baselineTag",
        "baselineVersion",
        "releaseStateSchemaVersion",
        "releaseVersion",
        "schemaVersion"
      ] then error("v1 fields") else
        {
          schemaVersion: "mealy.release-upgrade-baselines.v2",
          releaseVersion,
          releaseStateSchemaVersion,
          baselines: [{
            tag: .baselineTag,
            version: .baselineVersion,
            stateSchemaVersion: .baselineStateSchemaVersion
          }]
        }
      end
    elif .schemaVersion == "mealy.release-upgrade-baselines.v2" then
      if keys != [
        "baselines",
        "releaseStateSchemaVersion",
        "releaseVersion",
        "schemaVersion"
      ] then error("v2 fields") else . end
    else
      error("schema")
    end as $normalized
    | if
        $normalized.schemaVersion == "mealy.release-upgrade-baselines.v2"
        and $normalized.releaseVersion == $release_version
        and $normalized.releaseStateSchemaVersion == $release_schema
        and ($normalized.releaseVersion
          | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
        and ($normalized.releaseStateSchemaVersion
          | type == "number" and floor == . and . >= 1 and . <= 9999)
        and ($normalized.baselines
          | type == "array" and length >= 1 and length <= 4)
        and all($normalized.baselines[];
          type == "object"
          and keys == ["stateSchemaVersion", "tag", "version"]
          and (.version
            | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
          and .tag == ("v" + .version)
          and .version != $normalized.releaseVersion
          and (.stateSchemaVersion
            | type == "number" and floor == . and . >= 1 and . <= 9999)
          and .stateSchemaVersion < $normalized.releaseStateSchemaVersion)
        and ([$normalized.baselines[].version] | unique | length)
          == ($normalized.baselines | length)
        and all(range(1; ($normalized.baselines | length));
          $normalized.baselines[. - 1].stateSchemaVersion
            > $normalized.baselines[.].stateSchemaVersion)
      then $normalized
      else error("candidate mismatch")
      end
  ' "$manifest" || {
    echo "release upgrade-baseline manifest does not match this candidate" >&2
    exit 65
  }
