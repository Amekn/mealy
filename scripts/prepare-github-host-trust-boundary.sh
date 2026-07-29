#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'prepare-github-host-trust-boundary: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die 'this command does not accept arguments'
[[ ${GITHUB_ACTIONS:-} == true ]] || die 'this repair is limited to GitHub Actions'
[[ ${RUNNER_ENVIRONMENT:-} == github-hosted ]] ||
  die 'this repair is limited to GitHub-hosted runners'
[[ ${EUID} -ne 0 ]] || die 'run as the unprivileged GitHub Actions account'

for path in / /usr /usr/bin; do
  [[ -d $path && ! -L $path ]] || die "expected a non-symlink directory: $path"
done
[[ -f /usr/bin/bwrap && ! -L /usr/bin/bwrap ]] ||
  die 'expected a non-symlink Bubblewrap executable'

readonly ROOT_IDENTITY='0:0:755'
root_identity=$(stat --format='%u:%g:%a' -- /)
bin_identity=$(stat --format='%u:%g:%a' -- /usr/bin)
bwrap_identity=$(stat --format='%u:%g:%a' -- /usr/bin/bwrap)
usr_identity=$(stat --format='%u:%g:%a' -- /usr)
[[ $root_identity == "$ROOT_IDENTITY" ]] ||
  die "refusing unexpected root-directory identity: $root_identity"
[[ $bin_identity == "$ROOT_IDENTITY" ]] ||
  die "refusing unexpected /usr/bin identity: $bin_identity"
[[ $bwrap_identity == "$ROOT_IDENTITY" ]] ||
  die "refusing unexpected Bubblewrap identity: $bwrap_identity"

if [[ $usr_identity == "$ROOT_IDENTITY" ]]; then
  printf 'GitHub-hosted /usr trust boundary already protected\n'
  exit 0
fi

runner_gid=$(id -g)
readonly RUNNER_OWNED_IDENTITY="${EUID}:${runner_gid}:755"
[[ $usr_identity == "$RUNNER_OWNED_IDENTITY" ]] ||
  die "refusing unexpected /usr identity: $usr_identity"

# GitHub's ubuntu-24.04 image 20260726.254.1 shipped /usr owned by the
# unprivileged runner account. Restore the production invariant instead of
# teaching Mealy to trust a system tree that the workload account can replace.
sudo chown --no-dereference 0:0 -- /usr
[[ $(stat --format='%u:%g:%a' -- /usr) == "$ROOT_IDENTITY" ]] ||
  die 'the repaired /usr identity did not remain protected'
printf 'GitHub-hosted /usr trust boundary restored to root ownership\n'
