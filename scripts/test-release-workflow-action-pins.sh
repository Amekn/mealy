#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
validator=$repository_root/scripts/validate-workflow-action-pins.sh
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-workflow-action-pins.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

valid=$temporary/valid
mkdir "$valid"
cat >"$valid/release.yml" <<'EOF'
jobs:
  release:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
      - uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1
      - uses: actions/configure-pages@45bfe0192ca1faeb007ade9deae92b16b8254a0d # v6.0.0
      - uses: actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9 # v5.0.0
      - uses: actions/deploy-pages@cd2ce8fcbc39b97be8ca5fce6e763baed58fa128 # v5.0.0
      - uses: anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0
EOF
"$validator" "$valid" >/dev/null

expect_rejection() {
  local name=$1
  local directory=$temporary/$name
  shift
  cp -a "$valid" "$directory"
  "$@" "$directory/release.yml"
  if "$validator" "$directory" >"$temporary/$name.stdout" \
    2>"$temporary/$name.stderr"; then
    echo "workflow action-pin validator accepted $name" >&2
    exit 1
  fi
}

mixed_attest() {
  printf '%s\n' \
    '      - uses: actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4.2.0' \
    >>"$1"
}
unknown_action() {
  printf '%s\n' \
    '      - uses: example/action@0000000000000000000000000000000000000000' \
    >>"$1"
}
missing_action() {
  sed -i '/anchore\/sbom-action/d' "$1"
}
abbreviated_sha() {
  sed -i \
    's/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/actions\/checkout@3d3c42e5/' \
    "$1"
}
quoted_use() {
  sed -i \
    's|uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1|uses: "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"|' \
    "$1"
}

expect_rejection mixed-attest mixed_attest
expect_rejection unknown-action unknown_action
expect_rejection missing-action missing_action
expect_rejection abbreviated-sha abbreviated_sha
expect_rejection quoted-use quoted_use

symlinked=$temporary/symlinked
mkdir "$symlinked"
ln -s "$valid/release.yml" "$symlinked/release.yml"
if "$validator" "$symlinked" >/dev/null 2>&1; then
  echo "workflow action-pin validator accepted a symbolic-link workflow" >&2
  exit 1
fi
empty=$temporary/empty
mkdir "$empty"
if "$validator" "$empty" >/dev/null 2>&1; then
  echo "workflow action-pin validator accepted an empty workflow directory" >&2
  exit 1
fi
if "$validator" >/dev/null 2>&1 \
  || "$validator" "$valid" unexpected >/dev/null 2>&1; then
  echo "workflow action-pin validator accepted an invalid argument count" >&2
  exit 1
fi

echo "release workflow action-pin tests: ok"
