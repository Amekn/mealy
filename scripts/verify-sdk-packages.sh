#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

if [[ $# -ne 2 ]]; then
  echo "usage: verify-sdk-packages.sh PACKAGE_DIRECTORY VERSION" >&2
  exit 64
fi

package_directory=$1
version=$2
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "SDK package version must be stable semantic version" >&2
  exit 64
fi
if [[ -L $package_directory || ! -d $package_directory ]]; then
  echo "SDK package input must be a real directory" >&2
  exit 66
fi
package_directory=$(cd "$package_directory" && pwd -P)

for command in cargo find grep sha256sum stat tar; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "SDK package verification requires $command" >&2
    exit 69
  }
done

crates=(mealy-domain mealy-protocol mealy-client)
assets=()
for crate in "${crates[@]}"; do
  assets+=("${crate}-${version}.crate")
done
lockfile="mealy-sdk-${version}-Cargo.lock"
assets+=("$lockfile")
for asset in "${assets[@]}" SHA256SUMS-sdk; do
  if [[ -L $package_directory/$asset || ! -f $package_directory/$asset ]]; then
    echo "SDK package asset is absent or unsafe: $asset" >&2
    exit 65
  fi
done

expected_paths=$(printf '%s\n' "${assets[@]}" | sort)
actual_paths=$(awk '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ {exit 1}
  {print $2}
' "$package_directory/SHA256SUMS-sdk" | sort) || {
  echo "SDK checksum manifest is malformed" >&2
  exit 65
}
if [[ $actual_paths != "$expected_paths" ]]; then
  echo "SDK checksum manifest inventory is not exact" >&2
  exit 65
fi
(cd "$package_directory" && sha256sum --check --strict SHA256SUMS-sdk >/dev/null)

for asset in "${assets[@]}"; do
  size=$(stat -c '%s' "$package_directory/$asset")
  if ((size <= 0 || size > 16 * 1024 * 1024)); then
    echo "SDK package asset violates its size bound: $asset" >&2
    exit 65
  fi
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-sdk-verify.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT
mkdir "$temporary/unpacked"

for crate in "${crates[@]}"; do
  archive="${crate}-${version}.crate"
  root="${crate}-${version}"
  entries=$(tar -tzf "$package_directory/$archive")
  if [[ -z $entries ]] || grep -Ev "^${root}/([^/]+/?)*$" <<<"$entries" >/dev/null \
    || grep -E '(^|/)\.\.?(/|$)' <<<"$entries" >/dev/null \
    || grep -F "\\" <<<"$entries" >/dev/null; then
    echo "SDK package archive inventory is unsafe: $archive" >&2
    exit 65
  fi
  if tar -tvzf "$package_directory/$archive" | awk '
      {
        kind = substr($1, 1, 1)
        if (kind != "-" && kind != "d") {
          unsafe = 1
        }
      }
      END {exit unsafe ? 0 : 1}
    '; then
    echo "SDK package archive contains a link or special file: $archive" >&2
    exit 65
  fi
  tar -xzf "$package_directory/$archive" --no-same-owner --no-same-permissions \
    -C "$temporary/unpacked"
  extracted="$temporary/unpacked/$root"
  if [[ -L $extracted || ! -d $extracted ]] \
    || [[ -n $(find "$extracted" \( -type l -o ! -type f ! -type d \) -print -quit) ]]; then
    echo "SDK package extracted an unsafe filesystem object: $archive" >&2
    exit 65
  fi
  for required in Cargo.toml Cargo.toml.orig LICENSE README.md src/lib.rs; do
    if [[ -L $extracted/$required || ! -f $extracted/$required ]]; then
      echo "SDK package lacks required source: $archive: $required" >&2
      exit 65
    fi
  done
  grep -Eq "^name = \"${crate}\"$" "$extracted/Cargo.toml"
  grep -Eq "^version = \"${version}\"$" "$extracted/Cargo.toml"
  grep -Eq '^publish = true$' "$extracted/Cargo.toml"
done

consumer="$temporary/consumer"
mkdir -p "$consumer/src"
cat >"$consumer/Cargo.toml" <<EOF
[package]
name = "mealy-sdk-downstream-smoke"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
mealy-client = { path = "$temporary/unpacked/mealy-client-${version}" }

[patch.crates-io]
mealy-domain = { path = "$temporary/unpacked/mealy-domain-${version}" }
mealy-protocol = { path = "$temporary/unpacked/mealy-protocol-${version}" }
EOF
cat >"$consumer/src/main.rs" <<'EOF'
use mealy_client::{
    MealyClient,
    protocol::{API_VERSION, CreateSessionRequest},
};

fn main() {
    let request = CreateSessionRequest {
        api_version: API_VERSION.to_owned(),
        provider_selection: None,
    };
    assert_eq!(request.api_version, API_VERSION);
    let client = MealyClient::new("http://127.0.0.1:37281", "downstream-smoke-token")
        .expect("construct packaged client");
    drop(client);
}
EOF
install -m 0644 "$package_directory/$lockfile" "$consumer/Cargo.lock"
target_directory=${MEALY_SDK_VERIFY_TARGET_DIR:-"$temporary/target"}
CARGO_TARGET_DIR="$target_directory" \
  cargo check --manifest-path "$consumer/Cargo.toml" --locked --all-targets

printf 'verified SDK package set %s\n' "$version"
