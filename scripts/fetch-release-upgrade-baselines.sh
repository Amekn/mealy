#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  echo "usage: fetch-release-upgrade-baselines.sh MANIFEST RELEASE_VERSION RELEASE_SCHEMA TARGET SCOPE DESTINATION OWNER/REPOSITORY" >&2
}

if [[ $# -ne 7 || -L $1 || ! -f $1 \
  || ! $2 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ \
  || ! $3 =~ ^[1-9][0-9]{0,3}$ \
  || ! $7 =~ ^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$ ]]; then
  usage
  exit 64
fi

manifest=$1
release_version=$2
release_schema=$3
target=$4
scope=$5
destination=$6
repository=$7
scripts_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

for command in awk basename find gh jq mkdir sha256sum sort; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "release upgrade-baseline fetch requires $command" >&2
    exit 69
  }
done
if [[ -e $destination || -L $destination ]]; then
  echo "release upgrade-baseline destination must not already exist" >&2
  exit 65
fi
case $target in
  linux-x86_64-gnu)
    deb_architecture=amd64
    rpm_architecture=x86_64
    arch_supported=true
    ;;
  linux-aarch64-gnu)
    deb_architecture=arm64
    rpm_architecture=aarch64
    arch_supported=false
    ;;
  *)
    echo "unsupported release upgrade-baseline target: $target" >&2
    exit 64
    ;;
esac
case $scope in
  all|deb|rpm) ;;
  arch)
    if [[ $arch_supported != true ]]; then
      echo "the release upgrade-baseline Arch scope requires x86-64" >&2
      exit 64
    fi
    ;;
  *)
    echo "unsupported release upgrade-baseline scope: $scope" >&2
    exit 64
    ;;
esac

validated=$(
  "$scripts_root/validate-release-upgrade-baseline.sh" \
    "$manifest" "$release_version" "$release_schema"
)
mkdir -m 0700 "$destination"
checksums="SHA256SUMS-$target"
index_entries=()

while IFS= read -r baseline; do
  baseline_tag=$(jq -er '.tag' <<<"$baseline")
  baseline_version=$(jq -er '.version' <<<"$baseline")
  baseline_schema=$(jq -er '.stateSchemaVersion' <<<"$baseline")
  deb=
  rpm=
  arch=
  assets=("$checksums")
  if [[ $scope == all || $scope == deb ]]; then
    deb="mealy_${baseline_version}_${deb_architecture}.deb"
    assets+=("$deb")
  fi
  if [[ $scope == all || $scope == rpm ]]; then
    rpm="mealy-${baseline_version}-1.${rpm_architecture}.rpm"
    assets+=("$rpm")
  fi
  if [[ $scope == arch || ( $scope == all && $arch_supported == true ) ]]; then
    arch="mealy-${baseline_version}-1-x86_64.pkg.tar.zst"
    assets+=("$arch")
  fi

  directory="$destination/$baseline_version"
  mkdir -m 0700 "$directory"
  arguments=()
  for asset in "${assets[@]}"; do
    arguments+=(--pattern "$asset")
  done
  gh release download "$baseline_tag" \
    --repo "$repository" --dir "$directory" "${arguments[@]}"

  expected=$(printf '%s\n' "${assets[@]}" | sort)
  actual=$(
    find "$directory" -mindepth 1 -maxdepth 1 -type f \
      -exec basename {} \; | sort
  )
  if [[ $actual != "$expected" \
    || -n $(find "$directory" -mindepth 1 -maxdepth 1 \
      ! -type f -print -quit) ]]; then
    echo "release upgrade-baseline download inventory is not exact" >&2
    exit 65
  fi
  for asset in "${assets[@]}"; do
    gh release verify-asset "$baseline_tag" "$directory/$asset" \
      --repo "$repository" >/dev/null
  done

  package_checksums="$directory/PACKAGE-SHA256SUMS"
  : >"$package_checksums"
  for asset in "${assets[@]:1}"; do
    mapfile -t matching_checksums < <(
      awk -v asset="$asset" '$2 == asset {print}' "$directory/$checksums"
    )
    if [[ ${#matching_checksums[@]} -ne 1 ]]; then
      echo "release upgrade-baseline checksum inventory is not exact" >&2
      exit 65
    fi
    printf '%s\n' "${matching_checksums[0]}" >>"$package_checksums"
  done
  (cd "$directory" && sha256sum --check --strict PACKAGE-SHA256SUMS >/dev/null)

  index_entries+=("$(
    jq -cn \
      --arg tag "$baseline_tag" \
      --arg version "$baseline_version" \
      --argjson state_schema_version "$baseline_schema" \
      --arg deb "$deb" --arg rpm "$rpm" --arg arch "$arch" '{
        tag: $tag,
        version: $version,
        stateSchemaVersion: $state_schema_version,
        packages: {deb: $deb, rpm: $rpm, arch: $arch}
      }'
  )")
done < <(jq -c '.baselines[]' <<<"$validated")

expected_count=$(jq -er '.baselines | length' <<<"$validated")
if [[ ${#index_entries[@]} -ne $expected_count ]]; then
  echo "release upgrade-baseline index is incomplete" >&2
  exit 65
fi
baselines=$(printf '%s\n' "${index_entries[@]}" | jq -cs .)
jq -n \
  --arg release_version "$release_version" \
  --argjson release_schema "$release_schema" \
  --arg target "$target" \
  --arg scope "$scope" \
  --argjson baselines "$baselines" '{
    schemaVersion: "mealy.release-upgrade-baseline-index.v1",
    releaseVersion: $release_version,
    releaseStateSchemaVersion: $release_schema,
    target: $target,
    scope: $scope,
    baselines: $baselines
  }' >"$destination/index.json"

printf '%s\n' "$destination/index.json"
