#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: install-public-linux-repository.sh FAMILY IMAGE BASE_URL SIGNING_FINGERPRINT VERSION" >&2
}

if [[ $# -ne 5 ]]; then
  usage
  exit 64
fi

family=$1
image=$2
base_url=${3%/}
signing_fingerprint=${4^^}
version=$5

if [[ ! $image || $image == *[[:space:]]* \
  || ! $base_url =~ ^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~!$&()+,;=:@%/-]*)?$ \
  || ! $signing_fingerprint =~ ^[0-9A-F]{40}$ \
  || ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "public repository installation identity is invalid" >&2
  exit 64
fi

export MEALY_REPOSITORY_BASE_URL=$base_url
export MEALY_REPOSITORY_FINGERPRINT=$signing_fingerprint
export MEALY_EXPECTED_VERSION=$version

case $family in
  deb)
    docker run --rm --interactive \
      --env MEALY_REPOSITORY_BASE_URL \
      --env MEALY_EXPECTED_VERSION \
      "$image" bash -s <<'DEBIAN'
set -euo pipefail
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install --yes ca-certificates curl
curl --fail --location --silent --show-error \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  "$MEALY_REPOSITORY_BASE_URL/mealy.sources" \
  --output /etc/apt/sources.list.d/mealy.sources
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install --yes mealy
test "$(mealyctl --version)" = "mealyctl $MEALY_EXPECTED_VERSION"
DEBIAN
    ;;
  rpm)
    docker run --rm --interactive \
      --env MEALY_REPOSITORY_BASE_URL \
      --env MEALY_EXPECTED_VERSION \
      "$image" bash -s <<'FEDORA'
set -euo pipefail
dnf install --assumeyes ca-certificates curl
curl --fail --location --silent --show-error \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  "$MEALY_REPOSITORY_BASE_URL/mealy.repo" \
  --output /etc/yum.repos.d/mealy.repo
dnf --assumeyes install mealy
test "$(mealyctl --version)" = "mealyctl $MEALY_EXPECTED_VERSION"
FEDORA
    ;;
  arch)
    docker run --rm --interactive \
      --env MEALY_REPOSITORY_BASE_URL \
      --env MEALY_REPOSITORY_FINGERPRINT \
      --env MEALY_EXPECTED_VERSION \
      "$image" bash -s <<'ARCH'
set -euo pipefail
pacman -Syu --noconfirm ca-certificates curl gnupg
curl --fail --location --silent --show-error \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  "$MEALY_REPOSITORY_BASE_URL/repository-signing-key.asc" \
  --output /tmp/mealy-repository-signing-key.asc
curl --fail --location --silent --show-error \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  "$MEALY_REPOSITORY_BASE_URL/mealy.pacman.conf" \
  --output /tmp/mealy.pacman.conf
actual=$(
  gpg --batch --show-keys --with-colons \
    /tmp/mealy-repository-signing-key.asc |
    awk -F: '
      $1 == "pub" {want = 1; next}
      want && $1 == "fpr" {print toupper($10); exit}
    '
)
test "$actual" = "$MEALY_REPOSITORY_FINGERPRINT"
pacman-key --init
pacman-key --add /tmp/mealy-repository-signing-key.asc
pacman-key --lsign-key "$MEALY_REPOSITORY_FINGERPRINT"
cat /tmp/mealy.pacman.conf >>/etc/pacman.conf
pacman --sync --refresh --noconfirm mealy
test "$(mealyctl --version)" = "mealyctl $MEALY_EXPECTED_VERSION"
ARCH
    ;;
  *)
    echo "unsupported repository family: $family" >&2
    exit 64
    ;;
esac
