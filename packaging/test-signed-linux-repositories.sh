#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
builder=$repository_root/packaging/build-signed-linux-repositories.sh
validator=$repository_root/packaging/validate-signed-linux-repositories.sh
ubuntu_image=${MEALY_UBUNTU_IMAGE:-ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90}
fedora_image=${MEALY_FEDORA_IMAGE:-fedora:44@sha256:6c75d5bf57cb0fa5aa4b92c6a83c86c791644496d9ac230de7711f5b8ec3b898}
arch_image=${MEALY_ARCH_IMAGE:-archlinux:base-devel@sha256:412efebb0eeef0ef322ff24ad73f82b1ba2d3b12377db4c5fbe3074c7e7e8678}

for command in cp date docker gpg grep jq mkdir mktemp readlink rm sed stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required signed-repository test command is unavailable: $command" >&2
    exit 69
  fi
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-signed-repositories-test.XXXXXX")
cleanup() {
  chmod -R u+rwX -- "$temporary" 2>/dev/null || true
  rm -rf -- "$temporary"
}
trap cleanup EXIT

version=9.8.7
epoch=1784786400
assets=$temporary/assets
key_home=$temporary/gnupg
private_key=$temporary/repository-private-key.asc
repository=$temporary/repository
mkdir -m 0700 "$key_home"
mkdir -m 0755 "$assets"

# RPM 6 evaluates a signing subkey's binding at the package-signature time.
# Backdate the ephemeral fixture certificate enough to make that ordering
# deterministic across host/container clock rounding without weakening the
# production verifier or its key-policy checks.
key_epoch=$(($(date --utc +%s) - 300))
gpg --batch --homedir "$key_home" --passphrase '' \
  --faked-system-time "$key_epoch" \
  --quick-generate-key \
  'Mealy repository acceptance fixture <repository-fixture@mealy.invalid>' \
  ed25519 cert 2d >/dev/null 2>&1
fingerprint=$(
  gpg --batch --homedir "$key_home" --with-colons --list-secret-keys |
    awk -F: '
      $1 == "sec" {want_fingerprint = 1; next}
      want_fingerprint && $1 == "fpr" {print toupper($10); exit}
    '
)
if [[ ! $fingerprint =~ ^[0-9A-F]{40}$ ]]; then
  echo "fixture signing key did not produce one v4 fingerprint" >&2
  exit 70
fi
gpg --batch --homedir "$key_home" --passphrase '' \
  --faked-system-time "$key_epoch" \
  --quick-add-key "$fingerprint" ed25519 sign 2d >/dev/null 2>&1
gpg --batch --homedir "$key_home" --armor \
  --export-secret-subkeys "$fingerprint" >"$private_key"

docker run --rm \
  --env HOST_GID="$(id -g)" \
  --env HOST_UID="$(id -u)" \
  --env VERSION="$version" \
  --volume "$assets:/assets" \
  "$ubuntu_image" bash -lc '
    set -euo pipefail
    if ! command -v dpkg-deb >/dev/null 2>&1; then
      apt-get update >/dev/null
      apt-get install --yes dpkg-dev >/dev/null
    fi
    for architecture in amd64 arm64; do
      root="/tmp/mealy-deb-$architecture"
      mkdir -p "$root/DEBIAN" "$root/usr/bin"
      cat >"$root/DEBIAN/control" <<EOF
Package: mealy
Version: $VERSION
Architecture: $architecture
Maintainer: Mealy repository fixture <repository-fixture@mealy.invalid>
Description: Mealy signed repository acceptance fixture
EOF
      printf "#!/bin/sh\nprintf \"mealy repository fixture %s\\n\"\n" "$VERSION" \
        >"$root/usr/bin/mealy-repository-fixture"
      chmod 0755 "$root/usr/bin/mealy-repository-fixture"
      dpkg-deb --root-owner-group --build "$root" \
        "/assets/mealy_${VERSION}_${architecture}.deb" >/dev/null
    done
    chown "$HOST_UID:$HOST_GID" /assets/*.deb
  '

docker run --rm \
  --env HOST_GID="$(id -g)" \
  --env HOST_UID="$(id -u)" \
  --env VERSION="$version" \
  --volume "$assets:/assets" \
  "$fedora_image" bash -lc '
    set -euo pipefail
    if ! command -v rpmbuild >/dev/null 2>&1; then
      dnf install --assumeyes rpm-build >/dev/null
    fi
    for architecture in x86_64 aarch64; do
      topdir="/tmp/rpmbuild-$architecture"
      mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
      cat >"$topdir/SPECS/mealy.spec" <<EOF
Name: mealy
Version: $VERSION
Release: 1
Summary: Mealy signed repository acceptance fixture
License: Apache-2.0
AutoReqProv: no

%description
Mealy signed repository acceptance fixture.

%install
install -d -m 0755 %{buildroot}/usr/bin
printf "#!/bin/sh\\nprintf \"mealy repository fixture $VERSION\\\\n\"\\n" \
  >%{buildroot}/usr/bin/mealy-repository-fixture
chmod 0755 %{buildroot}/usr/bin/mealy-repository-fixture

%files
/usr/bin/mealy-repository-fixture
EOF
      rpmbuild -bb "$topdir/SPECS/mealy.spec" \
        --target "${architecture}-linux" \
        --define "_topdir $topdir" \
        --define "_build_id_links none" \
        --define "_enable_debug_packages 0" \
        --define "debug_package %{nil}" >/dev/null
      package=$(find "$topdir/RPMS" -type f -name "*.rpm" -print)
      install -m 0644 "$package" \
        "/assets/mealy-${VERSION}-1.${architecture}.rpm"
    done
    chown "$HOST_UID:$HOST_GID" /assets/*.rpm
  '

docker run --rm \
  --env HOST_GID="$(id -g)" \
  --env HOST_UID="$(id -u)" \
  --env SOURCE_DATE_EPOCH="$epoch" \
  --env VERSION="$version" \
  --volume "$assets:/assets" \
  "$arch_image" bash -lc '
    set -euo pipefail
    trap "chown -R \"$HOST_UID:$HOST_GID\" /assets 2>/dev/null || true" EXIT
    package_root=/tmp/mealy-arch-package
    definition=/tmp/mealy-arch-fixture-definition
    package="/assets/mealy-${VERSION}-1-x86_64.pkg.tar.zst"
    install -d -m 0755 "$package_root/usr/bin"
    cat >"$definition" <<EOF
pkgname=mealy
pkgver=$VERSION-1
pkgarch=x86_64
payload=usr/bin/mealy-repository-fixture
EOF
    printf "#!/bin/sh\nprintf \"mealy repository fixture $VERSION\\n\"\n" \
      >"$package_root/usr/bin/mealy-repository-fixture"
    chmod 0755 "$package_root/usr/bin/mealy-repository-fixture"
    payload_size=$(stat -c %s "$package_root/usr/bin/mealy-repository-fixture")
    definition_digest=$(sha256sum "$definition" | awk "{print \$1}")
    cat >"$package_root/.PKGINFO" <<EOF
pkgname = mealy
pkgbase = mealy
xdata = pkgtype=pkg
pkgver = $VERSION-1
pkgdesc = Signed repository acceptance fixture
url = https://github.com/Amekn/mealy
builddate = $SOURCE_DATE_EPOCH
packager = Mealy repository fixture <repository-fixture@mealy.invalid>
size = $payload_size
arch = x86_64
license = Apache-2.0
EOF
    cat >"$package_root/.BUILDINFO" <<EOF
format = 2
pkgname = mealy
pkgbase = mealy
pkgver = $VERSION-1
pkgarch = x86_64
pkgbuild_sha256sum = $definition_digest
packager = Mealy repository fixture <repository-fixture@mealy.invalid>
builddate = $SOURCE_DATE_EPOCH
builddir = /tmp/mealy-arch-package
startdir = /tmp
buildtool = mealy-repository-fixture
buildtoolver = 1.0.0
options = !debug
options = !strip
EOF
    find "$package_root" -exec \
      touch --no-dereference --date="@$SOURCE_DATE_EPOCH" {} +
    (
      cd "$package_root"
      find . -mindepth 1 ! -name .MTREE -printf "%P\0" |
        sort -z |
        bsdtar -cnf - --format=mtree \
          --options="!all,use-set,type,uid,gid,mode,time,size,sha256,link" \
          --null --files-from - |
        gzip -c -f -n >.MTREE
      touch --date="@$SOURCE_DATE_EPOCH" .MTREE
      find . -mindepth 1 -printf "%P\0" |
        sort -z |
        bsdtar --no-fflags --no-read-sparse -cnf - \
          --null --files-from - |
        zstd --compress --quiet --stdout >"$package"
    )
    test "$(bsdtar -xOf "$package" .PKGINFO |
      awk -F " = " '"'"'$1 == "pkgname" {print $2}'"'"')" = mealy
    test "$(bsdtar -xOf "$package" .PKGINFO |
      awk -F " = " '"'"'$1 == "pkgver" {print $2}'"'"')" = "$VERSION-1"
    test "$(bsdtar -xOf "$package" .PKGINFO |
      awk -F " = " '"'"'$1 == "arch" {print $2}'"'"')" = x86_64
    pacman --query --info --file "$package" >/dev/null
  '

expected_assets=$(
  printf '%s\n' \
    "mealy_${version}_amd64.deb" \
    "mealy_${version}_arm64.deb" \
    "mealy-${version}-1.x86_64.rpm" \
    "mealy-${version}-1.aarch64.rpm" \
    "mealy-${version}-1-x86_64.pkg.tar.zst" |
    sort
)
actual_assets=$(find "$assets" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
if [[ $actual_assets != "$expected_assets" ]]; then
  echo "fixture package inventory is not exact" >&2
  exit 70
fi

if MEALY_REPOSITORY_ALLOW_TEST_URL=false "$builder" \
  "$version" "$assets" "$temporary/rejected-url" file:///repository \
  "$epoch" "$private_key" "$fingerprint" \
  >"$temporary/rejected-url.stdout" 2>"$temporary/rejected-url.stderr"; then
  echo "repository builder accepted a non-HTTPS production URL" >&2
  exit 1
fi
grep -Fq 'must be an absolute HTTPS URL' "$temporary/rejected-url.stderr"

replacement=0
if [[ ${fingerprint:0:1} == 0 ]]; then
  replacement=1
fi
wrong_fingerprint=$replacement${fingerprint:1}
if [[ ! $wrong_fingerprint =~ ^[0-9A-F]{40}$ ||
  $wrong_fingerprint == "$fingerprint" ]]; then
  echo "fixture could not construct a distinct signing fingerprint" >&2
  exit 70
fi
if MEALY_REPOSITORY_ALLOW_TEST_URL=true "$builder" \
  "$version" "$assets" "$temporary/rejected-key" file:///repository \
  "$epoch" "$private_key" "$wrong_fingerprint" \
  >"$temporary/rejected-key.stdout" 2>"$temporary/rejected-key.stderr"; then
  echo "repository builder accepted the wrong signing fingerprint" >&2
  exit 1
fi
grep -Fq 'does not contain exactly the expected primary key' \
  "$temporary/rejected-key.stderr"

MEALY_REPOSITORY_ALLOW_TEST_URL=true "$builder" \
  "$version" "$assets" "$repository" file:///repository \
  "$epoch" "$private_key" "$fingerprint" >/dev/null
"$validator" "$repository" file:///repository "$fingerprint"

if grep -RIl -- 'PRIVATE KEY' "$repository" | grep -q .; then
  echo "published fixture repository leaked its private key" >&2
  exit 1
fi
repository_index="$repository/index.html"
if [[ ! -f $repository_index || $(stat -c '%s' "$repository_index") -gt 65536 ]]; then
  echo "repository install page is missing or exceeds its 64 KiB bound" >&2
  exit 1
fi
# These are literal browser-visible command strings; the test must not expand its own home.
# shellcheck disable=SC2016
for expected in \
  '<title>Install Mealy on Linux</title>' \
  '<span class="badge">Stable 9.8.7</span>' \
  'file:///repository/mealy.sources' \
  'sudo apt install mealy' \
  'file:///repository/mealy.repo' \
  'sudo dnf install mealy' \
  'file:///repository/repository-signing-key.asc' \
  'sudo pacman -Syu mealy' \
  'mealyctl</code></pre>' \
  'ChatGPT subscription through the official Codex client' \
  'mealyctl chat --continue' \
  'mealyctl update' \
  'href="REPOSITORY-MANIFEST.json"' \
  'href="REPOSITORY-MANIFEST.json.asc"' \
  'href="repository-signing-key.asc"' \
  'href="REPOSITORY-KEY-FINGERPRINT"' \
  "$fingerprint"; do
  if ! grep -Fq -- "$expected" "$repository_index"; then
    echo "repository install page omitted required content: $expected" >&2
    exit 1
  fi
done
if grep -Fq 'mealyctl onboard</code></pre>' "$repository_index"; then
  echo "repository install page bypasses the canonical bare-command journey" >&2
  exit 1
fi
if grep -Eq '<script|@@(VERSION|BASE_URL|FINGERPRINT)@@' "$repository_index"; then
  echo "repository install page contains JavaScript or an unresolved template field" >&2
  exit 1
fi
if grep -Fq 'Claude subscription' "$repository_index"; then
  echo "repository install page advertises prohibited third-party Claude subscription routing" >&2
  exit 1
fi

docker run --rm \
  --env DEBIAN_FRONTEND=noninteractive \
  --volume "$repository:/repository:ro" \
  "$ubuntu_image" bash -lc '
    set -euo pipefail
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
    install -m 0644 /repository/mealy.sources \
      /etc/apt/sources.list.d/mealy.sources
    apt-get update >/dev/null
    apt-get install --yes mealy >/dev/null
    test "$(mealy-repository-fixture)" = "mealy repository fixture 9.8.7"
  '

docker run --rm \
  --volume "$repository:/repository:ro" \
  "$fedora_image" bash -lc '
    set -euo pipefail
    install -m 0644 /repository/mealy.repo /etc/yum.repos.d/mealy.repo
    dnf --assumeyes --disablerepo="*" --enablerepo=mealy \
      install mealy >/dev/null
    test "$(mealy-repository-fixture)" = "mealy repository fixture 9.8.7"
  '

docker run --rm \
  --env EXPECTED_FINGERPRINT="$fingerprint" \
  --volume "$repository:/repository:ro" \
  "$arch_image" bash -lc '
    set -euo pipefail
    pacman-key --init >/dev/null
    pacman-key --add /repository/repository-signing-key.asc
    pacman-key --lsign-key "$EXPECTED_FINGERPRINT" >/dev/null
    cat /repository/mealy.pacman.conf >>/etc/pacman.conf
    pacman --sync --refresh --noconfirm mealy >/dev/null
    test "$(mealy-repository-fixture)" = "mealy repository fixture 9.8.7"
  '

cp -a "$repository" "$temporary/tampered"
printf '\n# tampered\n' >>"$temporary/tampered/mealy.repo"
if "$validator" "$temporary/tampered" file:///repository "$fingerprint" \
  >"$temporary/tampered.stdout" 2>"$temporary/tampered.stderr"; then
  echo "repository validator accepted a changed published file" >&2
  exit 1
fi
grep -Eq 'signed-manifest verification|inventory differs' "$temporary/tampered.stderr"

cp -a "$repository" "$temporary/symlinked"
ln -s mealy.repo "$temporary/symlinked/untrusted.repo"
if "$validator" "$temporary/symlinked" file:///repository "$fingerprint" \
  >"$temporary/symlinked.stdout" 2>"$temporary/symlinked.stderr"; then
  echo "repository validator accepted a symbolic link" >&2
  exit 1
fi
grep -Fq 'contains a symlink or unsupported file type' \
  "$temporary/symlinked.stderr"

echo "signed Linux repository build and clean-install acceptance: ok"
