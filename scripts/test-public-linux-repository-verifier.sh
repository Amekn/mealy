#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
verifier=$repository_root/scripts/verify-public-linux-repository.sh
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-public-repository-verifier.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/no-repository"

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
  pattern=
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
        pattern=$2
        shift 2
        ;;
      *)
        echo "unexpected gh release download argument: $1" >&2
        exit 64
        ;;
    esac
  done
  test "$tag" = v0.2.1
  test "$repository" = Amekn/mealy
  test "$pattern" = ATTESTATION-linux-repositories.sigstore.json
  printf 'offline attestation fixture\n' \
    >"$directory/ATTESTATION-linux-repositories.sigstore.json"
elif [[ $1 == attestation && $2 == verify ]]; then
  test "$*" = "attestation verify $MOCK_OUTPUT/REPOSITORY-MANIFEST.json --repo Amekn/mealy --signer-workflow Amekn/mealy/.github/workflows/release.yml --source-ref refs/tags/v0.2.1 --source-digest b8e9d8576f228fd43a523ad38704a86b4630b115 --bundle $MOCK_OUTPUT/ATTESTATION-linux-repositories.sigstore.json --deny-self-hosted-runners"
else
  echo "unexpected gh call: $*" >&2
  exit 64
fi
EOF

cat >"$temporary/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
url=
output=
while (($#)); do
  case $1 in
    --output)
      output=$2
      shift 2
      ;;
    https://*)
      url=$1
      shift
      ;;
    *)
      shift
      ;;
  esac
done
case ${url##*/} in
  repository-signing-key.asc)
    printf 'public key fixture\n' >"$output"
    ;;
  REPOSITORY-MANIFEST.json)
    jq -n '{
      schemaVersion: "mealy.linux-repositories.v1",
      version: "0.2.1",
      baseUrl: "https://amekn.github.io/mealy",
      publicationEpoch: 1785192800,
      signingFingerprint: "F8CB2DA307288C92757D731FFC798D3063749EA6",
      files: [{path: "mealy.sources", sha256: ("a" * 64), bytes: 1}]
    }' >"$output"
    ;;
  REPOSITORY-MANIFEST.json.asc)
    printf 'signature fixture\n' >"$output"
    ;;
  *)
    echo "unexpected curl URL: $url" >&2
    exit 64
    ;;
esac
EOF

cat >"$temporary/bin/gpg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" --list-keys "* ]]; then
  printf '%s\n' \
    'pub:-:255:22:0123456789ABCDEF:1785192800::::::scSC:::::ed25519:::0:' \
    'fpr:::::::::F8CB2DA307288C92757D731FFC798D3063749EA6:'
fi
EOF

chmod 0755 "$temporary/bin/gh" "$temporary/bin/curl" "$temporary/bin/gpg"
if (cd "$temporary/no-repository" && git rev-parse --git-dir >/dev/null 2>&1); then
  echo "public repository verifier regression fixture unexpectedly has Git metadata" >&2
  exit 1
fi

output=$temporary/output
(
  cd "$temporary/no-repository"
  PATH="$temporary/bin:$PATH" \
    MOCK_GH_LOG="$temporary/gh.log" \
    MOCK_OUTPUT="$output" \
    MEALY_PUBLIC_REPOSITORY_ATTEMPTS=1 \
    "$verifier" \
      Amekn/mealy v0.2.1 b8e9d8576f228fd43a523ad38704a86b4630b115 \
      https://amekn.github.io/mealy \
      F8CB2DA307288C92757D731FFC798D3063749EA6 \
      "$output"
)

grep -Fq \
  'release download v0.2.1 --repo Amekn/mealy --pattern ATTESTATION-linux-repositories.sigstore.json' \
  "$temporary/gh.log"
grep -Fq \
  'attestation verify' \
  "$temporary/gh.log"

if "$verifier" invalid v0.2.1 \
  b8e9d8576f228fd43a523ad38704a86b4630b115 \
  https://amekn.github.io/mealy \
  F8CB2DA307288C92757D731FFC798D3063749EA6 \
  "$temporary/rejected" >/dev/null 2>&1; then
  echo "public repository verifier accepted an invalid repository identity" >&2
  exit 1
fi

echo "public Linux repository verifier tests: ok"
