#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: install-public-linux-repository.sh FAMILY IMAGE BASE_URL SIGNING_FINGERPRINT VERSION VERIFIED_CONTROL_DIRECTORY" >&2
}

if [[ $# -ne 6 ]]; then
  usage
  exit 64
fi

family=$1
image=$2
base_url=${3%/}
signing_fingerprint=${4^^}
version=$5
verified_control_directory=$6

if [[ ! $image || $image == *[[:space:]]* \
  || ! $base_url =~ ^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~!$&()+,;=:@%/-]*)?$ \
  || ! $signing_fingerprint =~ ^[0-9A-F]{40}$ \
  || ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ \
  || -L $verified_control_directory || ! -d $verified_control_directory ]]; then
  echo "public repository installation identity is invalid" >&2
  exit 64
fi

for command in docker jq readlink sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required public repository installation command is unavailable: $command" >&2
    exit 69
  }
done
verified_control_directory=$(readlink -f "$verified_control_directory")
if [[ $verified_control_directory == *:* || $verified_control_directory == *$'\n'* ]]; then
  echo "verified repository-control path cannot be mounted safely" >&2
  exit 64
fi
manifest=$verified_control_directory/REPOSITORY-MANIFEST.json
if [[ -L $manifest || ! -f $manifest ]] \
  || ! jq -e \
    --arg base_url "$base_url" \
    --arg fingerprint "$signing_fingerprint" \
    --arg version "$version" '
      .schemaVersion == "mealy.linux-repositories.v1"
      and .baseUrl == $base_url
      and .signingFingerprint == $fingerprint
      and .version == $version
      and (.files | type == "array")
    ' "$manifest" >/dev/null; then
  echo "verified repository-control manifest has the wrong identity" >&2
  exit 65
fi
for name in repository-signing-key.asc mealy.sources mealy.repo mealy.pacman.conf; do
  candidate=$verified_control_directory/$name
  metadata=$(jq -er --arg path "$name" '
    [.files[] | select(.path == $path)]
    | select(length == 1)
    | .[0]
    | [.sha256, (.bytes | tostring)]
    | @tsv
  ' "$manifest")
  IFS=$'\t' read -r expected_sha256 expected_bytes <<<"$metadata"
  if [[ -L $candidate || ! -f $candidate \
    || $(stat -c '%s' "$candidate") != "$expected_bytes" \
    || $(sha256sum "$candidate" | awk '{print $1}') != "$expected_sha256" ]]; then
    echo "verified repository control failed its manifest digest: $name" >&2
    exit 65
  fi
done

export MEALY_REPOSITORY_BASE_URL=$base_url
export MEALY_REPOSITORY_FINGERPRINT=$signing_fingerprint
export MEALY_EXPECTED_VERSION=$version

case $family in
  deb)
    docker run --rm --interactive \
      --volume "$verified_control_directory:/verified:ro" \
      --env MEALY_REPOSITORY_BASE_URL \
      --env MEALY_EXPECTED_VERSION \
      "$image" bash -s <<'DEBIAN'
set -euo pipefail
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install --yes ca-certificates
install -m 0644 /verified/mealy.sources /etc/apt/sources.list.d/mealy.sources
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install --yes mealy
test "$(mealyctl --version)" = "mealyctl $MEALY_EXPECTED_VERSION"
DEBIAN
    ;;
  rpm)
    docker run --rm --interactive \
      --volume "$verified_control_directory:/verified:ro" \
      --env MEALY_REPOSITORY_BASE_URL \
      --env MEALY_EXPECTED_VERSION \
      "$image" bash -s <<'FEDORA'
set -euo pipefail
dnf install --assumeyes ca-certificates
install -m 0644 /verified/repository-signing-key.asc \
  /etc/pki/rpm-gpg/RPM-GPG-KEY-mealy
awk \
  -v expected="gpgkey=$MEALY_REPOSITORY_BASE_URL/repository-signing-key.asc" \
  -v replacement="gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-mealy" '
    $0 == expected {
      print replacement
      replacements += 1
      next
    }
    { print }
    END {
      if (replacements != 1) {
        exit 65
      }
    }
  ' /verified/mealy.repo >/etc/yum.repos.d/mealy.repo
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-mealy
dnf --assumeyes install mealy
test "$(mealyctl --version)" = "mealyctl $MEALY_EXPECTED_VERSION"
FEDORA
    ;;
  arch)
    docker run --rm --interactive \
      --volume "$verified_control_directory:/verified:ro" \
      --env MEALY_REPOSITORY_BASE_URL \
      --env MEALY_REPOSITORY_FINGERPRINT \
      --env MEALY_EXPECTED_VERSION \
      "$image" bash -s <<'ARCH'
set -euo pipefail
pacman -Syu --noconfirm ca-certificates gnupg
actual=$(
  gpg --batch --show-keys --with-colons \
    /verified/repository-signing-key.asc |
    awk -F: '
      $1 == "pub" {want = 1; next}
      want && $1 == "fpr" {print toupper($10); exit}
    '
)
test "$actual" = "$MEALY_REPOSITORY_FINGERPRINT"
pacman-key --init
pacman-key --add /verified/repository-signing-key.asc
pacman-key --lsign-key "$MEALY_REPOSITORY_FINGERPRINT"
cat /verified/mealy.pacman.conf >>/etc/pacman.conf
pacman --sync --refresh --noconfirm mealy
test "$(mealyctl --version)" = "mealyctl $MEALY_EXPECTED_VERSION"
ARCH
    ;;
  *)
    echo "unsupported repository family: $family" >&2
    exit 64
    ;;
esac
