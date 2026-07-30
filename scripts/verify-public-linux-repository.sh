#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  cat >&2 <<'EOF'
usage: verify-public-linux-repository.sh \
  OWNER/REPOSITORY RELEASE_TAG SOURCE_COMMIT BASE_URL SIGNING_FINGERPRINT OUTPUT_DIRECTORY
EOF
}

if [[ $# -ne 6 ]]; then
  usage
  exit 64
fi

repository=$1
release_tag=$2
source_commit=$3
base_url=${4%/}
signing_fingerprint=${5^^}
output_directory=$6

if [[ ! $repository =~ ^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$ \
  || ! $release_tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ \
  || ! $source_commit =~ ^[0-9a-f]{40}$ \
  || ! $base_url =~ ^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~!$&()+,;=:@%/-]*)?$ \
  || ! $signing_fingerprint =~ ^[0-9A-F]{40}$ ]]; then
  echo "public repository verification identity is invalid" >&2
  exit 64
fi

attempts=${MEALY_PUBLIC_REPOSITORY_ATTEMPTS:-60}
retry_delay=${MEALY_PUBLIC_REPOSITORY_RETRY_DELAY_SECONDS:-10}
if [[ ! $attempts =~ ^[1-9][0-9]*$ || ! $retry_delay =~ ^[0-9]+$ ]]; then
  echo "public repository retry policy is invalid" >&2
  exit 64
fi

for command in curl gh gpg jq sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required public repository verification command is unavailable: $command" >&2
    exit 69
  }
done

mkdir -p -- "$output_directory"
if [[ -n $(find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
  echo "public repository verification output directory must be empty" >&2
  exit 65
fi

gh release download "$release_tag" \
  --repo "$repository" \
  --pattern ATTESTATION-linux-repositories.sigstore.json \
  --dir "$output_directory"

download_public_file() {
  local name=$1
  curl --fail --location --silent --show-error \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 20 --max-time 120 \
    "$base_url/$name" --output "$output_directory/$name"
}

verify_manifest_file() {
  local name=$1
  local candidate=$output_directory/$name
  local metadata expected_sha256 expected_bytes
  if ! metadata=$(jq -er --arg path "$name" '
    [.files[] | select(.path == $path)]
    | select(length == 1)
    | .[0]
    | [.sha256, (.bytes | tostring)]
    | @tsv
  ' "$output_directory/REPOSITORY-MANIFEST.json"); then
    return 1
  fi
  IFS=$'\t' read -r expected_sha256 expected_bytes <<<"$metadata"
  [[ ! -L $candidate && -f $candidate \
    && $(stat -c '%s' "$candidate") == "$expected_bytes" \
    && $(sha256sum "$candidate" | awk '{print $1}') == "$expected_sha256" ]]
}

version=${release_tag#v}
verified=false
for ((attempt = 1; attempt <= attempts; attempt++)); do
  rm -rf -- "$output_directory/gnupg"
  mkdir -m 0700 "$output_directory/gnupg"
  if download_public_file repository-signing-key.asc \
    && download_public_file REPOSITORY-MANIFEST.json \
    && download_public_file REPOSITORY-MANIFEST.json.asc \
    && gpg --batch --homedir "$output_directory/gnupg" \
      --import "$output_directory/repository-signing-key.asc" >/dev/null 2>&1 \
    && gpg --batch --homedir "$output_directory/gnupg" \
      --verify "$output_directory/REPOSITORY-MANIFEST.json.asc" \
      "$output_directory/REPOSITORY-MANIFEST.json" >/dev/null 2>&1 \
    && jq -e \
      --arg base_url "$base_url" \
      --arg fingerprint "$signing_fingerprint" \
      --arg version "$version" '
        (keys | sort) == [
          "baseUrl",
          "files",
          "publicationEpoch",
          "schemaVersion",
          "signingFingerprint",
          "version"
        ]
        and .schemaVersion == "mealy.linux-repositories.v1"
        and .baseUrl == $base_url
        and .signingFingerprint == $fingerprint
        and .version == $version
        and (.publicationEpoch | type == "number" and floor == . and . >= 1)
        and (.files | type == "array" and length >= 1 and length <= 512)
        and ([.files[].path] | length == (unique | length))
        and all(.files[];
          (.path | type == "string"
            and test("^[A-Za-z0-9][A-Za-z0-9._/+~-]*$")
            and (contains("..") | not))
          and (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
          and (.bytes | type == "number" and floor == . and . > 0
            and . <= 536870912))
      ' "$output_directory/REPOSITORY-MANIFEST.json" >/dev/null \
    && verify_manifest_file repository-signing-key.asc \
    && download_public_file mealy.sources \
    && verify_manifest_file mealy.sources \
    && download_public_file mealy.repo \
    && verify_manifest_file mealy.repo \
    && download_public_file mealy.pacman.conf \
    && verify_manifest_file mealy.pacman.conf; then
    verified=true
    break
  fi
  if ((attempt < attempts)); then
    sleep "$retry_delay"
  fi
done

if [[ $verified != true ]]; then
  echo "public signed repository did not converge on release $release_tag" >&2
  exit 69
fi

actual_fingerprint=$(
  gpg --batch --homedir "$output_directory/gnupg" --with-colons --list-keys |
    awk -F: '
      $1 == "pub" {want = 1; next}
      want && $1 == "fpr" {print toupper($10); exit}
    '
)
if [[ $actual_fingerprint != "$signing_fingerprint" ]]; then
  echo "public repository signing certificate has the wrong primary fingerprint" >&2
  exit 65
fi

gh attestation verify "$output_directory/REPOSITORY-MANIFEST.json" \
  --repo "$repository" \
  --signer-workflow "$repository/.github/workflows/release.yml" \
  --source-ref "refs/tags/$release_tag" \
  --source-digest "$source_commit" \
  --bundle "$output_directory/ATTESTATION-linux-repositories.sigstore.json" \
  --deny-self-hosted-runners >/dev/null

printf 'public Linux repository verification: ok (%s, %s, %s)\n' \
  "$repository" "$release_tag" "$source_commit"
