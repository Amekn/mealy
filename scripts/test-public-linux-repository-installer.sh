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
run_installer deb ubuntu-fixture "$base_url" "$fingerprint" 0.2.1
run_installer rpm fedora-fixture "$base_url" "$fingerprint" 0.2.1
run_installer arch arch-fixture "$base_url" "$fingerprint" 0.2.1

test "$(<"$temporary/count")" -eq 3
grep -Fq 'apt-get install --yes mealy' "$temporary/program-1"
grep -Fq 'dnf --assumeyes install mealy' "$temporary/program-2"
grep -Fq 'pacman --sync --refresh --noconfirm mealy' "$temporary/program-3"
for program in "$temporary"/program-*; do
  # The container program must retain this expression for expansion inside the container.
  # shellcheck disable=SC2016
  grep -Fq \
    'test "$(mealyctl --version)" = "mealyctl $MEALY_EXPECTED_VERSION"' \
    "$program"
done

if run_installer unsupported fixture "$base_url" "$fingerprint" 0.2.1 \
  >/dev/null 2>&1; then
  echo "public repository installer accepted an unsupported package family" >&2
  exit 1
fi

echo "public Linux repository installer tests: ok"
