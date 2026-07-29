#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
fetcher=$repository_root/scripts/fetch-release-upgrade-baselines.sh
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-upgrade-baseline-fetch.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

mkdir "$temporary/bin"
cat >"$temporary/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$MOCK_GH_LOG"
printf '\n' >>"$MOCK_GH_LOG"

if [[ $1 == release && $2 == download ]]; then
  shift 2
  tag=$1
  shift
  repository=
  directory=
  patterns=()
  while (($#)); do
    case $1 in
      --repo)
        repository=$2
        shift 2
        ;;
      --dir)
        directory=$2
        shift 2
        ;;
      --pattern)
        patterns+=("$2")
        shift 2
        ;;
      *)
        echo "unexpected gh release download argument: $1" >&2
        exit 64
        ;;
    esac
  done
  test "$repository" = Amekn/mealy
  case $tag in v0.4.0|v0.3.0) ;; *) exit 64 ;; esac
  checksum_name=
  packages=()
  for pattern in "${patterns[@]}"; do
    case $pattern in
      SHA256SUMS-*) checksum_name=$pattern ;;
      *) packages+=("$pattern") ;;
    esac
  done
  test -n "$checksum_name"
  : >"$directory/$checksum_name"
  for package in "${packages[@]}"; do
    printf '%s fixture %s\n' "$tag" "$package" >"$directory/$package"
    digest=$(sha256sum "$directory/$package" | awk '{print $1}')
    if [[ ${MOCK_GH_BAD_CHECKSUM:-false} == true ]]; then
      digest=$(printf '0%.0s' {1..64})
    fi
    printf '%s  %s\n' "$digest" "$package" >>"$directory/$checksum_name"
  done
  if [[ ${MOCK_GH_EXTRA_ASSET:-false} == true ]]; then
    : >"$directory/unexpected"
  fi
elif [[ $1 == release && $2 == verify-asset ]]; then
  case $3 in v0.4.0|v0.3.0) ;; *) exit 64 ;; esac
  test -f "$4"
  test "$5" = --repo
  test "$6" = Amekn/mealy
else
  echo "unexpected gh call: $*" >&2
  exit 64
fi
EOF
chmod 0755 "$temporary/bin/gh"

manifest="$temporary/baselines.json"
jq -n '{
  schemaVersion: "mealy.release-upgrade-baselines.v2",
  releaseVersion: "0.5.0",
  releaseStateSchemaVersion: 30,
  baselines: [
    {tag: "v0.4.0", version: "0.4.0", stateSchemaVersion: 23},
    {tag: "v0.3.0", version: "0.3.0", stateSchemaVersion: 18}
  ]
}' >"$manifest"

PATH="$temporary/bin:$PATH" MOCK_GH_LOG="$temporary/gh.log" \
  "$fetcher" "$manifest" 0.5.0 30 linux-x86_64-gnu all \
  "$temporary/all" Amekn/mealy >/dev/null
jq -e '
  .schemaVersion == "mealy.release-upgrade-baseline-index.v1"
  and .releaseVersion == "0.5.0"
  and .releaseStateSchemaVersion == 30
  and .target == "linux-x86_64-gnu"
  and .scope == "all"
  and .baselines == [
    {
      tag: "v0.4.0",
      version: "0.4.0",
      stateSchemaVersion: 23,
      packages: {
        deb: "mealy_0.4.0_amd64.deb",
        rpm: "mealy-0.4.0-1.x86_64.rpm",
        arch: "mealy-0.4.0-1-x86_64.pkg.tar.zst"
      }
    },
    {
      tag: "v0.3.0",
      version: "0.3.0",
      stateSchemaVersion: 18,
      packages: {
        deb: "mealy_0.3.0_amd64.deb",
        rpm: "mealy-0.3.0-1.x86_64.rpm",
        arch: "mealy-0.3.0-1-x86_64.pkg.tar.zst"
      }
    }
  ]
' "$temporary/all/index.json" >/dev/null
for version in 0.4.0 0.3.0; do
  test "$(find "$temporary/all/$version" -maxdepth 1 -type f | wc -l)" -eq 5
  (cd "$temporary/all/$version" \
    && sha256sum --check --strict PACKAGE-SHA256SUMS >/dev/null)
done

PATH="$temporary/bin:$PATH" MOCK_GH_LOG="$temporary/gh.log" \
  "$fetcher" "$manifest" 0.5.0 30 linux-aarch64-gnu deb \
  "$temporary/deb" Amekn/mealy >/dev/null
jq -e '
  .target == "linux-aarch64-gnu"
  and .scope == "deb"
  and [.baselines[] | {
    version,
    packages
  }] == [
    {
      version: "0.4.0",
      packages: {
        deb: "mealy_0.4.0_arm64.deb",
        rpm: "",
        arch: ""
      }
    },
    {
      version: "0.3.0",
      packages: {
        deb: "mealy_0.3.0_arm64.deb",
        rpm: "",
        arch: ""
      }
    }
  ]
' "$temporary/deb/index.json" >/dev/null
for version in 0.4.0 0.3.0; do
  test "$(find "$temporary/deb/$version" -maxdepth 1 -type f | wc -l)" -eq 3
done

if PATH="$temporary/bin:$PATH" MOCK_GH_LOG="$temporary/gh.log" \
  "$fetcher" "$manifest" 0.5.0 30 linux-aarch64-gnu arch \
  "$temporary/rejected-arch" Amekn/mealy >/dev/null 2>&1; then
  echo "upgrade-baseline fetch accepted Arch on ARM64" >&2
  exit 70
fi
if PATH="$temporary/bin:$PATH" MOCK_GH_LOG="$temporary/gh.log" \
  MOCK_GH_BAD_CHECKSUM=true \
  "$fetcher" "$manifest" 0.5.0 30 linux-x86_64-gnu deb \
  "$temporary/rejected-checksum" Amekn/mealy >/dev/null 2>&1; then
  echo "upgrade-baseline fetch accepted a checksum-mismatched package" >&2
  exit 70
fi
if PATH="$temporary/bin:$PATH" MOCK_GH_LOG="$temporary/gh.log" \
  MOCK_GH_EXTRA_ASSET=true \
  "$fetcher" "$manifest" 0.5.0 30 linux-x86_64-gnu deb \
  "$temporary/rejected-inventory" Amekn/mealy >/dev/null 2>&1; then
  echo "upgrade-baseline fetch accepted an extra downloaded asset" >&2
  exit 70
fi
if PATH="$temporary/bin:$PATH" MOCK_GH_LOG="$temporary/gh.log" \
  "$fetcher" "$manifest" 0.5.1 30 linux-x86_64-gnu deb \
  "$temporary/rejected-release" Amekn/mealy >/dev/null 2>&1; then
  echo "upgrade-baseline fetch accepted a mismatched release identity" >&2
  exit 70
fi

test "$(grep -c '^release download ' "$temporary/gh.log")" -eq 6
test "$(grep -c '^release verify-asset ' "$temporary/gh.log")" -eq 14
echo "release upgrade-baseline fetch tests: ok"
