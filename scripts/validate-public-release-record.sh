#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: validate-public-release-record.sh [--exact] RELEASE.json TAG OWNER/REPOSITORY REQUIRED_ASSET..." >&2
}

exact_inventory=false
if [[ ${1-} == --exact ]]; then
  exact_inventory=true
  shift
fi
if [[ $# -lt 4 ]]; then
  usage
  exit 64
fi

release=$1
expected_tag=$2
repository=$3
shift 3
required_assets=("$@")

for command in grep jq sort stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "public-release record validation requires $command" >&2
    exit 69
  }
done

if [[ -L $release || ! -f $release \
  || ! $expected_tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ \
  || ! $repository =~ ^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$ ]]; then
  usage
  exit 64
fi

release_bytes=$(stat -c '%s' "$release")
if ((release_bytes < 2 || release_bytes > 8 * 1024 * 1024)); then
  echo "public-release record is empty or exceeds its 8 MiB evidence bound" >&2
  exit 65
fi

for asset in "${required_assets[@]}"; do
  if [[ ! $asset =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$ ]]; then
    echo "required public-release asset name is unsafe" >&2
    exit 64
  fi
done
required_inventory=$(printf '%s\n' "${required_assets[@]}" | sort)
if [[ $(printf '%s\n' "${required_assets[@]}" | sort -u) != "$required_inventory" ]]; then
  echo "required public-release asset inventory contains duplicates" >&2
  exit 64
fi

if ! jq -e \
  --arg tag "$expected_tag" \
  --arg repository "$repository" '
  def uint:
    type == "number" and . >= 0 and floor == .;
  def asset_name:
    type == "string"
    and test("^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$");
  (keys | sort) == [
    "assets",
    "isDraft",
    "isImmutable",
    "isPrerelease",
    "tagName",
    "url"
  ]
  and .tagName == $tag
  and .isDraft == false
  and .isImmutable == true
  and .isPrerelease == false
  and .url == ("https://github.com/" + $repository + "/releases/tag/" + $tag)
  and (.assets | type == "array" and length >= 1 and length <= 128)
  and ([.assets[].name] | length == (unique | length))
  and all(.assets[];
    (.name | asset_name)
    and (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$"))
    and (.size | uint and . > 0 and . <= 2147483648)
    and .state == "uploaded"
    and .url == ("https://github.com/" + $repository + "/releases/download/"
      + $tag + "/" + .name))
  ' "$release" >/dev/null 2>&1; then
  # Keep the actual inventory comparison outside jq's input stream so required names can be
  # validated without accepting a second, attacker-controlled JSON document.
  actual_inventory=$(jq -er '.assets | map(.name) | .[]' "$release" | sort) || true
  for asset in "${required_assets[@]}"; do
    if ! grep -Fqx -- "$asset" <<<"$actual_inventory"; then
      echo "public release is missing required asset: $asset" >&2
      exit 65
    fi
  done
  echo "public-release record is mutable, malformed, incomplete, or not canonical" >&2
  exit 65
fi

actual_inventory=$(jq -er '.assets | map(.name) | .[]' "$release" | sort)
if [[ $exact_inventory == true && $actual_inventory != "$required_inventory" ]]; then
  echo "public release asset inventory does not exactly match the publisher inventory" >&2
  exit 65
fi
for asset in "${required_assets[@]}"; do
  if ! grep -Fqx -- "$asset" <<<"$actual_inventory"; then
    echo "public release is missing required asset: $asset" >&2
    exit 65
  fi
done

asset_count=$(jq -er '.assets | length' "$release")
printf 'public release record: ok (%s, %s uploaded digest-bearing assets)\n' \
  "$expected_tag" "$asset_count"
