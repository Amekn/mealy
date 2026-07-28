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
"$validator" "$valid" 0.3.0 18 >/dev/null

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

echo "release upgrade-baseline validator tests: ok"
