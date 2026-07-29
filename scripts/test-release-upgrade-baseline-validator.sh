#!/usr/bin/env bash
set -euo pipefail
umask 077

scripts_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
validator="$scripts_root/validate-release-upgrade-baseline.sh"
temporary=$(mktemp -d)
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

valid="$temporary/valid.json"
jq -n '{
  schemaVersion: "mealy.release-upgrade-baseline.v1",
  releaseVersion: "0.3.0",
  releaseStateSchemaVersion: 18,
  baselineTag: "v0.2.1",
  baselineVersion: "0.2.1",
  baselineStateSchemaVersion: 16
}' >"$valid"
normalized=$("$validator" "$valid" 0.3.0 18)
jq -e '
  .schemaVersion == "mealy.release-upgrade-baselines.v2"
  and .releaseVersion == "0.3.0"
  and .releaseStateSchemaVersion == 18
  and .baselines == [{
    tag: "v0.2.1",
    version: "0.2.1",
    stateSchemaVersion: 16
  }]
' <<<"$normalized" >/dev/null

for mutation in wrong-release same-version wrong-tag future-schema extra-field; do
  invalid="$temporary/$mutation.json"
  case $mutation in
    wrong-release) jq '.releaseVersion = "0.3.1"' "$valid" >"$invalid" ;;
    same-version)
      jq '.baselineVersion = "0.3.0" | .baselineTag = "v0.3.0"' \
        "$valid" >"$invalid"
      ;;
    wrong-tag) jq '.baselineTag = "v0.2.0"' "$valid" >"$invalid" ;;
    future-schema) jq '.baselineStateSchemaVersion = 19' "$valid" >"$invalid" ;;
    extra-field) jq '.unexpected = true' "$valid" >"$invalid" ;;
  esac
  if "$validator" "$invalid" 0.3.0 18 >/dev/null 2>&1; then
    echo "upgrade-baseline validator accepted $mutation" >&2
    exit 70
  fi
done

valid_v2="$temporary/valid-v2.json"
jq -n '{
  schemaVersion: "mealy.release-upgrade-baselines.v2",
  releaseVersion: "0.5.0",
  releaseStateSchemaVersion: 30,
  baselines: [
    {tag: "v0.4.0", version: "0.4.0", stateSchemaVersion: 23},
    {tag: "v0.3.0", version: "0.3.0", stateSchemaVersion: 18}
  ]
}' >"$valid_v2"
normalized=$("$validator" "$valid_v2" 0.5.0 30)
jq -e '
  .schemaVersion == "mealy.release-upgrade-baselines.v2"
  and .baselines == [
    {tag: "v0.4.0", version: "0.4.0", stateSchemaVersion: 23},
    {tag: "v0.3.0", version: "0.3.0", stateSchemaVersion: 18}
  ]
' <<<"$normalized" >/dev/null

for mutation in empty duplicate reversed version-order future-version \
  extra-baseline-field future-schema too-many; do
  invalid="$temporary/v2-$mutation.json"
  case $mutation in
    empty) jq '.baselines = []' "$valid_v2" >"$invalid" ;;
    duplicate) jq '.baselines[1] = .baselines[0]' "$valid_v2" >"$invalid" ;;
    reversed) jq '.baselines |= reverse' "$valid_v2" >"$invalid" ;;
    version-order)
      jq '
        .baselines[0].tag = "v0.3.0"
        | .baselines[0].version = "0.3.0"
        | .baselines[1].tag = "v0.4.0"
        | .baselines[1].version = "0.4.0"
      ' "$valid_v2" >"$invalid"
      ;;
    future-version)
      jq '
        .baselines[0].tag = "v0.6.0"
        | .baselines[0].version = "0.6.0"
      ' "$valid_v2" >"$invalid"
      ;;
    extra-baseline-field) jq '.baselines[0].unexpected = true' "$valid_v2" >"$invalid" ;;
    future-schema)
      jq '.baselines[0].stateSchemaVersion = 30' "$valid_v2" >"$invalid"
      ;;
    too-many)
      jq '.baselines = [
        {tag: "v0.4.0", version: "0.4.0", stateSchemaVersion: 23},
        {tag: "v0.3.0", version: "0.3.0", stateSchemaVersion: 18},
        {tag: "v0.2.1", version: "0.2.1", stateSchemaVersion: 16},
        {tag: "v0.2.0", version: "0.2.0", stateSchemaVersion: 15},
        {tag: "v0.1.0", version: "0.1.0", stateSchemaVersion: 14}
      ]' "$valid_v2" >"$invalid"
      ;;
  esac
  if "$validator" "$invalid" 0.5.0 30 >/dev/null 2>&1; then
    echo "upgrade-baseline validator accepted v2 $mutation" >&2
    exit 70
  fi
done

echo "release upgrade-baseline validator tests: ok"
