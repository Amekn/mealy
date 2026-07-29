#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
validator=$repository_root/scripts/validate-public-release-record.sh
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-public-release-record.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

tag=v0.3.0
repository=Amekn/mealy
required=SHA256SUMS-linux-x86_64-gnu
second=mealy-v0.3.0-linux-x86_64-gnu.tar.gz

jq -n \
  --arg tag "$tag" \
  --arg repository "$repository" \
  --arg required "$required" \
  --arg second "$second" '{
  tagName: $tag,
  isDraft: false,
  isImmutable: true,
  isPrerelease: false,
  url: ("https://github.com/" + $repository + "/releases/tag/" + $tag),
  assets: [
    {
      name: $required,
      digest: ("sha256:" + ("a" * 64)),
      size: 4096,
      state: "uploaded",
      url: ("https://github.com/" + $repository + "/releases/download/"
        + $tag + "/" + $required)
    },
    {
      name: $second,
      digest: ("sha256:" + ("b" * 64)),
      size: 8192,
      state: "uploaded",
      url: ("https://github.com/" + $repository + "/releases/download/"
        + $tag + "/" + $second)
    }
  ]
}' >"$temporary/valid.json"

"$validator" "$temporary/valid.json" "$tag" "$repository" \
  "$required" "$second" >"$temporary/valid.stdout"
grep -Fq 'public release record: ok' "$temporary/valid.stdout"

expect_rejection() {
  local name=$1
  local filter=$2
  jq "$filter" "$temporary/valid.json" >"$temporary/$name.json"
  if "$validator" "$temporary/$name.json" "$tag" "$repository" \
    "$required" "$second" >/dev/null 2>&1; then
    echo "public-release record validator accepted $name" >&2
    exit 1
  fi
}

expect_rejection mutable '.isImmutable = false'
expect_rejection draft '.isDraft = true'
expect_rejection prerelease '.isPrerelease = true'
expect_rejection wrong-tag '.tagName = "v0.3.1"'
expect_rejection wrong-release-url '.url = "https://example.invalid/release"'
expect_rejection missing-digest 'del(.assets[0].digest)'
expect_rejection malformed-digest '.assets[0].digest = "sha256:abcd"'
expect_rejection empty-asset '.assets[0].size = 0'
expect_rejection unuploaded-asset '.assets[0].state = "open"'
expect_rejection wrong-asset-url '.assets[0].url = "https://example.invalid/asset"'
expect_rejection duplicate-asset '.assets += [.assets[0]]'
expect_rejection foreign-field '.mutable = true'

if "$validator" "$temporary/valid.json" "$tag" "$repository" \
  missing.tar.gz >/dev/null 2>&1; then
  echo "public-release record validator accepted a missing required asset" >&2
  exit 1
fi

ln -s valid.json "$temporary/symlink.json"
if "$validator" "$temporary/symlink.json" "$tag" "$repository" \
  "$required" >/dev/null 2>&1; then
  echo "public-release record validator accepted a symbolic-link record" >&2
  exit 1
fi

if "$validator" "$temporary/valid.json" v0.03.0 "$repository" \
  "$required" >/dev/null 2>&1; then
  echo "public-release record validator accepted a noncanonical tag" >&2
  exit 1
fi

echo "public-release record validator tests: ok"
