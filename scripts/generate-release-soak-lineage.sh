#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: generate-release-soak-lineage.sh REPORT.json RELEASE_LINEAGE_COMMIT EXPECTED_COMMIT OUTPUT.json" >&2
}

if [[ $# -ne 4 ]]; then
  usage
  exit 64
fi

report=$1
release_lineage_commit=$2
expected_commit=$3
output=$4

for command in chmod dirname git jq mktemp mv rm sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required release-soak lineage command is unavailable: $command" >&2
    exit 69
  }
done

output_parent=$(dirname "$output")
if [[ -L $report || ! -f $report \
  || ! $release_lineage_commit =~ ^[0-9a-f]{40}$ \
  || ! $expected_commit =~ ^[0-9a-f]{40}$ \
  || -L $output_parent || ! -d $output_parent \
  || -L $output || (-e $output && ! -f $output) ]]; then
  usage
  exit 64
fi

report_bytes=$(stat -c '%s' "$report")
if (( report_bytes < 2 || report_bytes > 16 * 1024 * 1024 )); then
  echo "release soak report is empty or exceeds its 16 MiB evidence bound" >&2
  exit 65
fi

if ! observed_revision=$(jq -er '
  select(
    .schemaVersion == "mealy.soak-report.v2"
    and .sourceState == "clean_revision"
    and (.revision | type == "string" and test("^[0-9a-f]{40}$"))
  )
  | .revision
' "$report"); then
  echo "release soak report does not identify a clean canonical observed revision" >&2
  exit 65
fi

resolved_observed=$(git rev-parse --verify "${observed_revision}^{commit}" 2>/dev/null || true)
resolved_lineage=$(
  git rev-parse --verify "${release_lineage_commit}^{commit}" 2>/dev/null || true
)
resolved_expected=$(git rev-parse --verify "${expected_commit}^{commit}" 2>/dev/null || true)
if [[ $resolved_observed != "$observed_revision" \
  || $resolved_lineage != "$release_lineage_commit" \
  || $resolved_expected != "$expected_commit" ]]; then
  echo "release soak lineage names an absent or noncanonical commit" >&2
  exit 65
fi
if git merge-base --is-ancestor "$observed_revision" "$expected_commit"; then
  echo "release soak revision is already an ancestor; no lineage proof is required" >&2
  exit 65
fi
if ! git merge-base --is-ancestor "$release_lineage_commit" "$expected_commit"; then
  echo "release lineage commit is not an ancestor of the expected release commit" >&2
  exit 65
fi

observed_tree=$(git rev-parse "${observed_revision}^{tree}")
release_lineage_tree=$(git rev-parse "${release_lineage_commit}^{tree}")
if [[ $observed_tree != "$release_lineage_tree" ]]; then
  echo "release lineage commit does not preserve the exact observed Git tree" >&2
  exit 65
fi

payload=$(mktemp "${output_parent}/.mealy-soak-observed-commit.XXXXXX")
temporary=$(mktemp "${output_parent}/.mealy-soak-lineage.XXXXXX")
cleanup() {
  rm -f -- "$payload" "$temporary"
}
trap cleanup EXIT

git cat-file commit "$observed_revision" >"$payload"
payload_bytes=$(stat -c '%s' "$payload")
if (( payload_bytes < 1 || payload_bytes > 4096 )) \
  || [[ $(git hash-object -t commit --stdin <"$payload") != "$observed_revision" ]]; then
  echo "observed commit payload is oversized or does not rehash to the report revision" >&2
  exit 65
fi

report_sha256=$(sha256sum "$report")
report_sha256=${report_sha256%% *}
jq -n \
  --arg report_sha256 "$report_sha256" \
  --arg observed_revision "$observed_revision" \
  --arg observed_tree "$observed_tree" \
  --rawfile observed_payload "$payload" \
  --arg release_revision "$release_lineage_commit" \
  --arg release_tree "$release_lineage_tree" '
  {
    schemaVersion: "mealy.soak-lineage.v1",
    reportSha256: $report_sha256,
    observedRevision: $observed_revision,
    observedGitTree: $observed_tree,
    observedCommitPayload: $observed_payload,
    releaseLineageRevision: $release_revision,
    releaseLineageGitTree: $release_tree,
    transformation: "github_rebase_merge"
  }
' >"$temporary"

chmod 0644 "$temporary"
mv -fT -- "$temporary" "$output"
temporary=
printf 'release soak lineage evidence: ok (%s -> %s -> %s)\n' \
  "$observed_revision" "$release_lineage_commit" "$expected_commit"
