#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
installer=$repository_root/scripts/install-public-linux-repository.sh
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-public-repository-installer.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

mkdir -p "$temporary/bin"
printf '0\n' >"$temporary/count"
cat >"$temporary/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=$(<"$MOCK_DOCKER_COUNT")
count=$((count + 1))
printf '%s\n' "$count" >"$MOCK_DOCKER_COUNT"
printf '%q ' "$@" >"$MOCK_DOCKER_LOG/arguments-$count"
printf '\n' >>"$MOCK_DOCKER_LOG/arguments-$count"
if [[ " $* " != *" --interactive "* ]]; then
  echo "repository installer did not attach its checked program to container stdin" >&2
  exit 65
fi
cat >"$MOCK_DOCKER_LOG/program-$count"
test -s "$MOCK_DOCKER_LOG/program-$count"
EOF
chmod 0755 "$temporary/bin/docker"

run_installer() {
  PATH="$temporary/bin:$PATH" \
    MOCK_DOCKER_COUNT="$temporary/count" \
    MOCK_DOCKER_LOG="$temporary" \
    "$installer" "$@"
}

base_url=https://amekn.github.io/mealy
fingerprint=F8CB2DA307288C92757D731FFC798D3063749EA6
controls=$temporary/verified-controls
mkdir "$controls"
printf 'public key fixture\n' >"$controls/repository-signing-key.asc"
printf 'Types: deb\nSigned-By: fixture\n' >"$controls/mealy.sources"
printf '[mealy]\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=%s/repository-signing-key.asc\n' \
  "$base_url" >"$controls/mealy.repo"
printf '[mealy]\nSigLevel = Required DatabaseRequired\n' >"$controls/mealy.pacman.conf"
jq -n \
  --arg base_url "$base_url" \
  --arg fingerprint "$fingerprint" \
  --arg key_sha "$(sha256sum "$controls/repository-signing-key.asc" | awk '{print $1}')" \
  --argjson key_bytes "$(stat -c '%s' "$controls/repository-signing-key.asc")" \
  --arg sources_sha "$(sha256sum "$controls/mealy.sources" | awk '{print $1}')" \
  --argjson sources_bytes "$(stat -c '%s' "$controls/mealy.sources")" \
  --arg repo_sha "$(sha256sum "$controls/mealy.repo" | awk '{print $1}')" \
  --argjson repo_bytes "$(stat -c '%s' "$controls/mealy.repo")" \
  --arg pacman_sha "$(sha256sum "$controls/mealy.pacman.conf" | awk '{print $1}')" \
  --argjson pacman_bytes "$(stat -c '%s' "$controls/mealy.pacman.conf")" '{
    schemaVersion: "mealy.linux-repositories.v1",
    version: "0.2.1",
    baseUrl: $base_url,
    publicationEpoch: 1785192800,
    signingFingerprint: $fingerprint,
    files: [
      {path: "repository-signing-key.asc", sha256: $key_sha, bytes: $key_bytes},
      {path: "mealy.sources", sha256: $sources_sha, bytes: $sources_bytes},
      {path: "mealy.repo", sha256: $repo_sha, bytes: $repo_bytes},
      {path: "mealy.pacman.conf", sha256: $pacman_sha, bytes: $pacman_bytes}
    ]
  }' >"$controls/REPOSITORY-MANIFEST.json"

run_installer deb ubuntu-fixture "$base_url" "$fingerprint" 0.2.1 "$controls"
run_installer rpm fedora-fixture "$base_url" "$fingerprint" 0.2.1 "$controls"
run_installer arch arch-fixture "$base_url" "$fingerprint" 0.2.1 "$controls"

test "$(<"$temporary/count")" -eq 3
grep -Fq 'apt-get install --yes mealy' "$temporary/program-1"
grep -Fq 'gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-mealy' \
  "$temporary/program-2"
grep -Fq 'rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-mealy' \
  "$temporary/program-2"
grep -Fq 'install mealy' "$temporary/program-2"
grep -Fq 'pacman --sync --refresh --noconfirm mealy' "$temporary/program-3"
for arguments in "$temporary"/arguments-*; do
  grep -Fq "$controls:/verified:ro" "$arguments"
done
for program in "$temporary"/program-*; do
  # The container program must retain this expression for expansion inside the container.
  # shellcheck disable=SC2016
  grep -Fq \
    'test "$(mealyctl --version)" = "mealyctl $MEALY_EXPECTED_VERSION"' \
    "$program"
  if grep -Fq 'curl ' "$program"; then
    echo "public repository installer re-downloaded a verified control file" >&2
    exit 1
  fi
done

for workflow in \
  "$repository_root/.github/workflows/release.yml" \
  "$repository_root/.github/workflows/public-repository-acceptance.yml"; do
  if ! grep -A6 -F 'scripts/install-public-linux-repository.sh' "$workflow" |
    grep -Fq "\"\$RUNNER_TEMP/mealy-public-repository\""; then
    echo "release workflow omitted the verified repository-control handoff: $workflow" >&2
    exit 1
  fi
done

tampered=$temporary/tampered-controls
cp -a "$controls" "$tampered"
printf 'gpgcheck=0\n' >>"$tampered/mealy.repo"
if run_installer rpm fedora-fixture "$base_url" "$fingerprint" 0.2.1 \
  "$tampered" >/dev/null 2>&1; then
  echo "public repository installer accepted a changed verified control file" >&2
  exit 1
fi

if run_installer unsupported fixture "$base_url" "$fingerprint" 0.2.1 "$controls" \
  >/dev/null 2>&1; then
  echo "public repository installer accepted an unsupported package family" >&2
  exit 1
fi

echo "public Linux repository installer tests: ok"
