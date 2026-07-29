#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'diagnose-system-executable-trust: %s\n' "$*" >&2
  exit 64
}

[[ $# -eq 1 ]] || die 'usage: diagnose-system-executable-trust.sh ABSOLUTE_EXECUTABLE'
[[ $1 == /* ]] || die 'the executable path must be absolute'
[[ -e $1 ]] || die "the executable does not exist: $1"

canonical=$(readlink -f -- "$1")
printf 'Executable canonical path: %s\n' "$canonical"
current=$canonical
while [[ $current != / ]]; do
  stat --format='%n uid=%u gid=%g mode=%a type=%F' -- "$current"
  current=${current%/*}
  [[ -n $current ]] || current=/
done
stat --format='%n uid=%u gid=%g mode=%a type=%F' -- /
printf 'UID map:\n'
sed 's/^/  /' /proc/self/uid_map
printf 'GID map:\n'
sed 's/^/  /' /proc/self/gid_map
grep --extended-regexp '^(Uid|Gid):' /proc/self/status
printf 'Overflow UID: '
cat /proc/sys/kernel/overflowuid
findmnt --target "$canonical" --output TARGET,FSTYPE,OPTIONS
