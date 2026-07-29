#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: normalize-stacked-release-candidate.sh OLD_PREDECESSOR PUBLIC_LINEAGE PUBLIC_PREDECESSOR CANDIDATE EXPECTED_VERSION" >&2
}

if [[ $# -ne 5 ]]; then
  usage
  exit 64
fi

old_predecessor=$1
public_lineage=$2
public_predecessor=$3
candidate=$4
expected_version=$5

for command in git sed wc; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required stacked-release normalization command is unavailable: $command" >&2
    exit 69
  }
done

if [[ ! $old_predecessor =~ ^[0-9a-f]{40}$ \
  || ! $public_lineage =~ ^[0-9a-f]{40}$ \
  || ! $public_predecessor =~ ^[0-9a-f]{40}$ \
  || ! $candidate =~ ^[0-9a-f]{40}$ \
  || ! $expected_version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  usage
  exit 64
fi

if [[ $(git rev-parse --is-inside-work-tree 2>/dev/null || true) != true ]]; then
  echo "stacked-release normalization requires a Git worktree" >&2
  exit 65
fi

for revision in \
  "$old_predecessor" \
  "$public_lineage" \
  "$public_predecessor" \
  "$candidate"; do
  resolved=$(git rev-parse --verify "${revision}^{commit}" 2>/dev/null || true)
  if [[ $resolved != "$revision" ]]; then
    echo "stacked-release normalization names an absent or noncanonical commit" >&2
    exit 65
  fi
done

if ! git merge-base --is-ancestor "$old_predecessor" "$candidate"; then
  echo "candidate does not descend from the recorded predecessor candidate" >&2
  exit 65
fi
if ! git merge-base --is-ancestor "$public_lineage" "$public_predecessor"; then
  echo "public predecessor does not descend from its mapped candidate lineage" >&2
  exit 65
fi
if git merge-base --is-ancestor "$public_predecessor" "$candidate"; then
  echo "candidate already descends from the public predecessor" >&2
  exit 65
fi

old_tree=$(git rev-parse "${old_predecessor}^{tree}")
lineage_tree=$(git rev-parse "${public_lineage}^{tree}")
candidate_tree=$(git rev-parse "${candidate}^{tree}")
if [[ $old_tree != "$lineage_tree" ]]; then
  mapfile -t normalized_from < <(
    git show -s --format=%B "$public_lineage" \
      | git interpret-trailers --parse \
      | sed -n 's/^Normalized-From: //p'
  )
  lineage_parent_count=$(
    git cat-file -p "$public_lineage" | sed -n 's/^parent //p' | wc -l
  )
  if [[ ${#normalized_from[@]} -ne 1 \
    || ${normalized_from[0]} != "$old_predecessor" \
    || $lineage_parent_count -ne 1 ]]; then
    echo "public predecessor lineage neither preserves nor names the candidate-base tree" >&2
    exit 65
  fi
fi
if [[ $candidate_tree == "$old_tree" ]]; then
  echo "stacked release candidate has no change from its predecessor" >&2
  exit 65
fi

mapfile -t candidate_versions < <(
  git show "${candidate}:Cargo.toml" 2>/dev/null \
    | sed -n 's/^version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p'
)
if [[ ${#candidate_versions[@]} -ne 1 \
  || ${candidate_versions[0]} != "$expected_version" ]]; then
  echo "stacked release candidate has the wrong or ambiguous workspace version" >&2
  exit 65
fi

merge_output=
if ! merge_output=$(
  git merge-tree --write-tree --no-messages \
    --merge-base "$old_predecessor" \
    "$public_predecessor" "$candidate" 2>&1
); then
  echo "stacked release candidate conflicts with public predecessor evidence" >&2
  printf '%s\n' "$merge_output" >&2
  exit 65
fi
normalized_tree=${merge_output%%$'\n'*}
if [[ ! $normalized_tree =~ ^[0-9a-f]{40}$ \
  || $(git cat-file -t "$normalized_tree" 2>/dev/null || true) != tree ]]; then
  echo "stacked-release merge did not produce a canonical Git tree" >&2
  exit 65
fi
if [[ $normalized_tree == "$(git rev-parse "${public_predecessor}^{tree}")" ]]; then
  echo "stacked-release merge lost the candidate delta" >&2
  exit 65
fi

mapfile -t normalized_versions < <(
  git show "${normalized_tree}:Cargo.toml" 2>/dev/null \
    | sed -n 's/^version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p'
)
if [[ ${#normalized_versions[@]} -ne 1 \
  || ${normalized_versions[0]} != "$expected_version" ]]; then
  echo "normalized release tree has the wrong or ambiguous workspace version" >&2
  exit 65
fi

git var GIT_AUTHOR_IDENT >/dev/null
git var GIT_COMMITTER_IDENT >/dev/null
normalized=$(
  printf '%s\n\n%s\n%s\n%s\n%s\n' \
    "release(v${expected_version}): normalize candidate onto public predecessor" \
    "Normalized-From: ${candidate}" \
    "Predecessor-Source: ${old_predecessor}" \
    "Predecessor-Lineage: ${public_lineage}" \
    "Predecessor-Release: ${public_predecessor}" \
    | git commit-tree "$normalized_tree" -p "$public_predecessor"
)

if [[ ! $normalized =~ ^[0-9a-f]{40}$ \
  || $(git rev-parse "${normalized}^{tree}") != "$normalized_tree" \
  || $(git rev-parse "${normalized}^") != "$public_predecessor" \
  || $(git cat-file -p "$normalized" | sed -n 's/^parent //p' | wc -l) -ne 1 ]]; then
  echo "normalized stacked-release commit failed its postcondition" >&2
  exit 65
fi

printf 'normalized stacked release candidate: %s -> %s\n' \
  "$candidate" "$normalized" >&2
printf '%s\n' "$normalized"
