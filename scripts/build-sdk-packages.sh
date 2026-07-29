#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

if [[ $# -ne 1 ]]; then
  echo "usage: build-sdk-packages.sh OUTPUT_DIRECTORY" >&2
  exit 64
fi

output_directory=$1
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$repository_root"

for command in cargo cmp find git install jq sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "SDK package build requires $command" >&2
    exit 69
  }
done

if [[ -e $output_directory ]]; then
  if [[ -L $output_directory || ! -d $output_directory ]]; then
    echo "SDK package output must be a real directory" >&2
    exit 65
  fi
  if [[ -n $(find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "SDK package output directory must be empty" >&2
    exit 65
  fi
fi

allow_dirty=${MEALY_SDK_PACKAGE_ALLOW_DIRTY:-false}
if [[ $allow_dirty != true && $allow_dirty != false ]]; then
  echo "MEALY_SDK_PACKAGE_ALLOW_DIRTY must be true or false" >&2
  exit 64
fi
if [[ $allow_dirty != true ]] \
  && { ! git diff --quiet --ignore-submodules -- \
    || ! git diff --cached --quiet --ignore-submodules -- \
    || [[ -n $(git ls-files --others --exclude-standard) ]]; }; then
  echo "SDK release packages require a clean source tree" >&2
  exit 65
fi

mkdir -p "$output_directory"
output_directory=$(cd "$output_directory" && pwd -P)

version=$(cargo metadata --locked --format-version 1 --no-deps |
  jq -er '
    [.packages[] | select(.name == "mealy-client") | .version]
    | select(length == 1) | .[0]
  ')
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "SDK package version must be stable semantic version" >&2
  exit 65
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-sdk-package.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

package_arguments=(--locked --no-verify)
if [[ $allow_dirty == true ]]; then
  package_arguments+=(--allow-dirty)
fi
crates=(mealy-domain mealy-protocol mealy-client)
assets=()
package_selection=()
for crate in "${crates[@]}"; do
  package_selection+=(-p "$crate")
  archive="${crate}-${version}.crate"
  assets+=("$archive")
done
cargo package "${package_arguments[@]}" "${package_selection[@]}" >/dev/null
for archive in "${assets[@]}"; do
  test ! -L "target/package/$archive" && test -f "target/package/$archive"
  install -m 0644 "target/package/$archive" "$temporary/first-$archive"
  rm -f "target/package/$archive"
done
cargo package "${package_arguments[@]}" "${package_selection[@]}" >/dev/null
for archive in "${assets[@]}"; do
  cmp "$temporary/first-$archive" "target/package/$archive"
  install -m 0644 "target/package/$archive" "$output_directory/$archive"
done

lockfile="mealy-sdk-${version}-Cargo.lock"
mkdir -p "$temporary/lock-unpacked" "$temporary/lock-consumer/src"
for archive in "${assets[@]}"; do
  tar -xzf "$output_directory/$archive" --no-same-owner --no-same-permissions \
    -C "$temporary/lock-unpacked"
done
cat >"$temporary/lock-consumer/Cargo.toml" <<EOF
[package]
name = "mealy-sdk-downstream-smoke"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
mealy-client = { path = "$temporary/lock-unpacked/mealy-client-${version}" }

[patch.crates-io]
mealy-domain = { path = "$temporary/lock-unpacked/mealy-domain-${version}" }
mealy-protocol = { path = "$temporary/lock-unpacked/mealy-protocol-${version}" }
EOF
cat >"$temporary/lock-consumer/src/main.rs" <<'EOF'
fn main() {}
EOF
install -m 0644 Cargo.lock "$temporary/lock-consumer/Cargo.lock"
target_directory=${MEALY_SDK_VERIFY_TARGET_DIR:-"$repository_root/target/sdk-smoke"}
CARGO_TARGET_DIR="$target_directory" \
  cargo check --manifest-path "$temporary/lock-consumer/Cargo.toml" --all-targets
install -m 0644 "$temporary/lock-consumer/Cargo.lock" "$output_directory/$lockfile"
assets+=("$lockfile")
(cd "$output_directory" && sha256sum "${assets[@]}" | sort -k 2 >SHA256SUMS-sdk)

"$repository_root/scripts/verify-sdk-packages.sh" "$output_directory" "$version"
printf '%s\n' "$output_directory"
