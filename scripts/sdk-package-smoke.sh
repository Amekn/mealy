#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
for command in cp find ln sed sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "SDK package smoke requires $command" >&2
    exit 69
  }
done
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-sdk-smoke.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

MEALY_SDK_PACKAGE_ALLOW_DIRTY=${MEALY_SDK_PACKAGE_ALLOW_DIRTY:-false} \
MEALY_SDK_VERIFY_TARGET_DIR=${MEALY_SDK_VERIFY_TARGET_DIR:-"$repository_root/target/sdk-smoke"} \
  "$repository_root/scripts/build-sdk-packages.sh" "$temporary/packages" >/dev/null

version=$(find "$temporary/packages" -maxdepth 1 -type f \
  -name 'mealy-client-*.crate' -printf '%f\n')
version=${version#mealy-client-}
version=${version%.crate}
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "SDK package smoke could not derive the stable version" >&2
  exit 65
fi

expect_rejection() {
  local name=$1
  local directory=$2
  if "$repository_root/scripts/verify-sdk-packages.sh" \
    "$directory" "$version" >/dev/null 2>&1; then
    echo "SDK package verifier accepted $name" >&2
    exit 1
  fi
}

cp -a "$temporary/packages" "$temporary/tampered-bytes"
printf 'tamper' >>"$temporary/tampered-bytes/mealy-client-${version}.crate"
expect_rejection "tampered package bytes" "$temporary/tampered-bytes"

cp -a "$temporary/packages" "$temporary/foreign-inventory"
printf 'unexpected\n' >"$temporary/foreign-inventory/unexpected"
(cd "$temporary/foreign-inventory" &&
  sha256sum unexpected >>SHA256SUMS-sdk)
expect_rejection "a foreign checksum entry" "$temporary/foreign-inventory"

cp -a "$temporary/packages" "$temporary/nonpublishable"
mkdir "$temporary/nonpublishable-unpacked"
tar -xzf "$temporary/nonpublishable/mealy-client-${version}.crate" \
  -C "$temporary/nonpublishable-unpacked"
manifest="$temporary/nonpublishable-unpacked/mealy-client-${version}/Cargo.toml"
sed -i 's/^publish = true$/publish = false/' "$manifest"
grep -Fxq 'publish = false' "$manifest"
rm "$temporary/nonpublishable/mealy-client-${version}.crate"
tar -czf "$temporary/nonpublishable/mealy-client-${version}.crate" \
  -C "$temporary/nonpublishable-unpacked" "mealy-client-${version}"
(cd "$temporary/nonpublishable" &&
  sha256sum "mealy-client-${version}.crate" "mealy-domain-${version}.crate" \
    "mealy-protocol-${version}.crate" "mealy-sdk-${version}-Cargo.lock" |
    sort -k 2 >SHA256SUMS-sdk)
expect_rejection "a non-publishable client manifest" "$temporary/nonpublishable"

cp -a "$temporary/packages" "$temporary/link-archive"
mkdir "$temporary/link-unpacked"
tar -xzf "$temporary/link-archive/mealy-client-${version}.crate" \
  -C "$temporary/link-unpacked"
ln -s ../../outside \
  "$temporary/link-unpacked/mealy-client-${version}/unexpected-link"
rm "$temporary/link-archive/mealy-client-${version}.crate"
tar -czf "$temporary/link-archive/mealy-client-${version}.crate" \
  -C "$temporary/link-unpacked" "mealy-client-${version}"
(cd "$temporary/link-archive" &&
  sha256sum "mealy-client-${version}.crate" "mealy-domain-${version}.crate" \
    "mealy-protocol-${version}.crate" "mealy-sdk-${version}-Cargo.lock" |
    sort -k 2 >SHA256SUMS-sdk)
expect_rejection "a package archive containing a symbolic link" "$temporary/link-archive"
