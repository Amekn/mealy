#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: validate-release-soak-candidate.sh REPORT.json MEALYD EXPECTED_COMMIT LINEAGE.json" >&2
}

if [[ $# -ne 4 ]]; then
  usage
  exit 64
fi
if [[ -z $4 ]]; then
  usage
  exit 64
fi

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
validator=$repository_root/scripts/validate-release-soak.sh
report=$1
mealyd=$2
expected_commit=$3
lineage=$4

# A GitHub rebase merge rewrites the observed commit even when its tree is unchanged.
# Pass the checked proof whenever any filesystem object occupies the canonical evidence
# path so malformed files and symlinks are rejected by the underlying validator rather
# than being mistaken for an absent, unnecessary proof.
if [[ -e $lineage || -L $lineage ]]; then
  exec "$validator" "$report" "$mealyd" "$expected_commit" "$lineage"
fi
exec "$validator" "$report" "$mealyd" "$expected_commit"
