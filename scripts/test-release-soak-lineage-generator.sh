#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
generator=$repository_root/scripts/generate-release-soak-lineage.sh

for command in cmp git jq mktemp sha256sum; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-soak lineage test command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-soak-lineage-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

repository=$temporary/repository
mkdir -p "$repository/apps/mealyd/src"
git -C "$repository" init -q
git -C "$repository" config user.name Mealy
git -C "$repository" config user.email mealy@example.invalid
printf '[workspace]\nmembers = ["apps/mealyd"]\n' >"$repository/Cargo.toml"
printf 'fn main() {}\n' >"$repository/apps/mealyd/src/main.rs"
git -C "$repository" add Cargo.toml apps/mealyd/src/main.rs
git -C "$repository" commit -qm 'observed release source'
observed=$(git -C "$repository" rev-parse HEAD)
observed_tree=$(git -C "$repository" rev-parse "${observed}^{tree}")
observed_payload=$temporary/observed-commit.txt
git -C "$repository" cat-file commit "$observed" >"$observed_payload"

report=$temporary/report.json
jq -n --arg revision "$observed" '{
  schemaVersion: "mealy.soak-report.v2",
  sourceState: "clean_revision",
  revision: $revision
}' >"$report"
report_sha256=$(sha256sum "$report")
report_sha256=${report_sha256%% *}

release_lineage=$(
  printf 'GitHub rebase copy of observed release source\n' \
    | git -C "$repository" commit-tree "$observed_tree"
)
git -C "$repository" update-ref refs/heads/release "$release_lineage"
git -C "$repository" symbolic-ref HEAD refs/heads/release
mkdir -p "$repository/docs"
printf 'release evidence\n' >"$repository/docs/release.md"
git -C "$repository" add docs/release.md
git -C "$repository" commit -qm 'record release evidence'
expected=$(git -C "$repository" rev-parse HEAD)

first=$temporary/first.json
second=$temporary/second.json
(cd "$repository" \
  && "$generator" "$report" "$release_lineage" "$expected" "$first") >/dev/null
(cd "$repository" \
  && "$generator" "$report" "$release_lineage" "$expected" "$second") >/dev/null
cmp "$first" "$second"
jq -e \
  --arg report_sha256 "$report_sha256" \
  --arg observed "$observed" \
  --arg tree "$observed_tree" \
  --rawfile payload "$observed_payload" \
  --arg release_lineage "$release_lineage" '
  (keys | sort) == [
    "observedCommitPayload",
    "observedGitTree",
    "observedRevision",
    "releaseLineageGitTree",
    "releaseLineageRevision",
    "reportSha256",
    "schemaVersion",
    "transformation"
  ]
  and .schemaVersion == "mealy.soak-lineage.v1"
  and .reportSha256 == $report_sha256
  and .observedRevision == $observed
  and .observedGitTree == $tree
  and .observedCommitPayload == $payload
  and .releaseLineageRevision == $release_lineage
  and .releaseLineageGitTree == $tree
  and .transformation == "github_rebase_merge"
' "$first" >/dev/null

expect_rejection() {
  local name=$1
  local candidate_report=$2
  local candidate_lineage=$3
  local candidate_expected=$4
  local candidate_output=$temporary/$name.json
  if (cd "$repository" \
    && "$generator" "$candidate_report" "$candidate_lineage" \
      "$candidate_expected" "$candidate_output") \
    >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "release-soak lineage generator accepted invalid $name input" >&2
    exit 1
  fi
}

expect_rejection wrong-tree "$report" "$expected" "$expected"
unrelated=$(
  printf 'unrelated identical tree\n' \
    | git -C "$repository" commit-tree "$observed_tree"
)
expect_rejection nonancestor-lineage "$report" "$unrelated" "$expected"
direct_report=$temporary/direct-report.json
jq --arg revision "$release_lineage" '.revision = $revision' \
  "$report" >"$direct_report"
expect_rejection unnecessary-direct-proof \
  "$direct_report" "$release_lineage" "$expected"
malformed_report=$temporary/malformed-report.json
jq 'del(.sourceState)' "$report" >"$malformed_report"
expect_rejection malformed-report "$malformed_report" "$release_lineage" "$expected"
expect_rejection absent-expected "$report" "$release_lineage" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

symlink_output=$temporary/symlink-output.json
ln -s "$temporary/symlink-target.json" "$symlink_output"
if (cd "$repository" \
  && "$generator" "$report" "$release_lineage" "$expected" "$symlink_output") \
  >"$temporary/symlink.stdout" 2>"$temporary/symlink.stderr"; then
  echo "release-soak lineage generator followed a symlink output" >&2
  exit 1
fi

echo "release-soak lineage generator: ok"
