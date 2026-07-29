#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
normalizer=$repository_root/scripts/normalize-stacked-release-candidate.sh

for command in cmp git grep mkdir mktemp sed sha256sum; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required stacked-release normalization test command is unavailable: $command" >&2
    exit 69
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-stacked-release-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

repository=$temporary/repository
mkdir -p "$repository"
git -C "$repository" init -q
git -C "$repository" config user.name Mealy
git -C "$repository" config user.email mealy@example.invalid

mkdir -p "$repository/docs"
printf '[workspace]\n\n[workspace.package]\nversion = "0.3.0"\n' \
  >"$repository/Cargo.toml"
printf 'stable predecessor\n' >"$repository/runtime.txt"
git -C "$repository" add Cargo.toml runtime.txt
git -C "$repository" commit -qm 'initial predecessor'
initial=$(git -C "$repository" rev-parse HEAD)

git -C "$repository" switch -qc predecessor
printf 'candidate release runbook\n' >"$repository/docs/runbook.md"
git -C "$repository" add docs/runbook.md
git -C "$repository" commit -qm 'finish predecessor candidate'
old_predecessor=$(git -C "$repository" rev-parse HEAD)
old_tree=$(git -C "$repository" rev-parse "${old_predecessor}^{tree}")

git -C "$repository" switch -qc candidate "$initial"
sed -i 's/version = "0.3.0"/version = "0.4.0"/' "$repository/Cargo.toml"
printf 'governed capability\n' >"$repository/capability.txt"
git -C "$repository" add Cargo.toml capability.txt
git -C "$repository" commit -qm 'build successor capability'
git -C "$repository" merge -q --no-ff predecessor -m 'synchronize predecessor'
candidate=$(git -C "$repository" rev-parse HEAD)

public_lineage=$(
  printf 'public rebase copy of predecessor\n' \
    | git -C "$repository" commit-tree "$old_tree" -p "$initial"
)
git -C "$repository" switch -qC public-predecessor "$public_lineage"
printf 'attested predecessor evidence\n' >"$repository/docs/release-evidence.json"
git -C "$repository" add docs/release-evidence.json
git -C "$repository" commit -qm 'publish predecessor evidence'
public_predecessor=$(git -C "$repository" rev-parse HEAD)

refs_before=$(git -C "$repository" show-ref | sha256sum)
normalized=$(
  cd "$repository"
  "$normalizer" \
    "$old_predecessor" \
    "$public_lineage" \
    "$public_predecessor" \
    "$candidate" \
    0.4.0
)
refs_after=$(git -C "$repository" show-ref | sha256sum)
if [[ $refs_before != "$refs_after" ]]; then
  echo "stacked-release normalizer mutated a Git reference" >&2
  exit 1
fi

if [[ $(git -C "$repository" rev-parse "${normalized}^") != "$public_predecessor" \
  || $(git -C "$repository" cat-file -p "$normalized" \
    | sed -n 's/^parent //p' | wc -l) -ne 1 ]]; then
  echo "normalized candidate is not a single-parent public-predecessor child" >&2
  exit 1
fi
test "$(git -C "$repository" show "${normalized}:capability.txt")" \
  = "governed capability"
test "$(git -C "$repository" show "${normalized}:docs/release-evidence.json")" \
  = "attested predecessor evidence"
git -C "$repository" cat-file -p "$normalized" >"$temporary/normalized-commit.txt"
grep -Fxq "Normalized-From: ${candidate}" "$temporary/normalized-commit.txt"
grep -Fxq "Predecessor-Source: ${old_predecessor}" "$temporary/normalized-commit.txt"
grep -Fxq "Predecessor-Lineage: ${public_lineage}" "$temporary/normalized-commit.txt"
grep -Fxq "Predecessor-Release: ${public_predecessor}" \
  "$temporary/normalized-commit.txt"

git -C "$repository" diff --binary --full-index \
  "$old_predecessor" "$candidate" >"$temporary/candidate.patch"
git -C "$repository" diff --binary --full-index \
  "$public_predecessor" "$normalized" >"$temporary/normalized.patch"
cmp "$temporary/candidate.patch" "$temporary/normalized.patch"

expect_rejection() {
  local name=$1
  shift
  if (cd "$repository" && "$normalizer" "$@") \
    >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "stacked-release normalizer accepted invalid $name input" >&2
    exit 1
  fi
}

expect_rejection wrong-version \
  "$old_predecessor" "$public_lineage" "$public_predecessor" "$candidate" 0.5.0
expect_rejection empty-delta \
  "$old_predecessor" "$public_lineage" "$public_predecessor" \
  "$old_predecessor" 0.3.0
expect_rejection wrong-lineage-tree \
  "$old_predecessor" "$public_predecessor" "$public_predecessor" \
  "$candidate" 0.4.0
unrelated_lineage=$(
  printf 'unrelated public lineage\n' \
    | git -C "$repository" commit-tree "$old_tree"
)
expect_rejection unrelated-lineage \
  "$old_predecessor" "$unrelated_lineage" "$public_predecessor" \
  "$candidate" 0.4.0
expect_rejection candidate-already-public \
  "$old_predecessor" "$public_lineage" "$public_predecessor" \
  "$normalized" 0.4.0
expect_rejection malformed-version \
  "$old_predecessor" "$public_lineage" "$public_predecessor" \
  "$candidate" 00.4.0
expect_rejection absent-commit \
  "$old_predecessor" "$public_lineage" "$public_predecessor" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0.4.0

git -C "$repository" switch -qC next-candidate "$candidate"
sed -i 's/version = "0.4.0"/version = "0.5.0"/' "$repository/Cargo.toml"
printf 'ecosystem maturity\n' >"$repository/ecosystem.txt"
git -C "$repository" add Cargo.toml ecosystem.txt
git -C "$repository" commit -qm 'build next successor'
next_candidate=$(git -C "$repository" rev-parse HEAD)

normalized_message=$(git -C "$repository" show -s --format=%B "$normalized")
normalized_lineage=$(
  printf '%s\n' "$normalized_message" \
    | git -C "$repository" commit-tree \
      "$(git -C "$repository" rev-parse "${normalized}^{tree}")" \
      -p "$public_predecessor"
)
git -C "$repository" switch -qC normalized-public-predecessor "$normalized_lineage"
printf 'attested normalized predecessor evidence\n' \
  >"$repository/docs/normalized-release-evidence.json"
git -C "$repository" add docs/normalized-release-evidence.json
git -C "$repository" commit -qm 'publish normalized predecessor evidence'
normalized_public_predecessor=$(git -C "$repository" rev-parse HEAD)

next_normalized=$(
  cd "$repository"
  "$normalizer" \
    "$candidate" \
    "$normalized_lineage" \
    "$normalized_public_predecessor" \
    "$next_candidate" \
    0.5.0
)
test "$(git -C "$repository" show "${next_normalized}:ecosystem.txt")" \
  = "ecosystem maturity"
test "$(
  git -C "$repository" show \
    "${next_normalized}:docs/normalized-release-evidence.json"
)" = "attested normalized predecessor evidence"
test "$(
  git -C "$repository" show "${next_normalized}:docs/release-evidence.json"
)" = "attested predecessor evidence"

forged_lineage=$(
  printf 'forged normalization\n\nNormalized-From: %040d\n' 0 \
    | git -C "$repository" commit-tree \
      "$(git -C "$repository" rev-parse "${normalized}^{tree}")" \
      -p "$public_predecessor"
)
expect_rejection forged-normalization-link \
  "$candidate" "$forged_lineage" "$forged_lineage" \
  "$next_candidate" 0.5.0

git -C "$repository" switch -qC conflict-candidate "$candidate"
printf 'candidate runtime\n' >"$repository/runtime.txt"
git -C "$repository" add runtime.txt
git -C "$repository" commit -qm 'change candidate runtime'
conflict_candidate=$(git -C "$repository" rev-parse HEAD)
git -C "$repository" switch -qC conflict-public "$public_lineage"
printf 'public runtime\n' >"$repository/runtime.txt"
git -C "$repository" add runtime.txt
git -C "$repository" commit -qm 'change public runtime'
conflict_public=$(git -C "$repository" rev-parse HEAD)
expect_rejection conflicting-delta \
  "$old_predecessor" "$public_lineage" "$conflict_public" \
  "$conflict_candidate" 0.4.0

if "$normalizer" >/dev/null 2>&1 \
  || "$normalizer" "$old_predecessor" >/dev/null 2>&1; then
  echo "stacked-release normalizer accepted an invalid argument count" >&2
  exit 1
fi

echo "stacked-release normalization: ok"
