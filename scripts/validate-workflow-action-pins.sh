#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: validate-workflow-action-pins.sh WORKFLOW_DIRECTORY" >&2
}

if [[ $# -ne 1 || -L $1 || ! -d $1 ]]; then
  usage
  exit 64
fi
for command in find sed sort; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "workflow action-pin validation requires $command" >&2
    exit 69
  }
done

workflow_root=$(cd "$1" && pwd -P)
if [[ -n $(find "$workflow_root" -maxdepth 1 -type l \
  \( -name '*.yml' -o -name '*.yaml' \) -print -quit) ]]; then
  echo "workflow action-pin validation refuses symbolic-link workflows" >&2
  exit 65
fi
mapfile -d '' workflow_files < <(
  find "$workflow_root" -maxdepth 1 -type f \
    \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z
)
if [[ ${#workflow_files[@]} -eq 0 ]]; then
  echo "workflow action-pin validation found no workflow files" >&2
  exit 65
fi

declare -A expected=(
  [actions/checkout]=3d3c42e5aac5ba805825da76410c181273ba90b1
  [actions/upload-artifact]=043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
  [actions/download-artifact]=3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
  [actions/attest]=508db95dd578ae2727ebd6217d5ba78e4fbda05d
  [actions/configure-pages]=45bfe0192ca1faeb007ade9deae92b16b8254a0d
  [actions/upload-pages-artifact]=fc324d3547104276b827a68afc52ff2a11cc49c9
  [actions/deploy-pages]=cd2ce8fcbc39b97be8ca5fce6e763baed58fa128
  [anchore/sbom-action]=e22c389904149dbc22b58101806040fa8d37a610
)
declare -A seen=()
use_count=0

for workflow in "${workflow_files[@]}"; do
  mapfile -t raw_uses < <(
    sed -n -E '/^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*/p' "$workflow"
  )
  mapfile -t parsed_uses < <(
    sed -n -E \
      's|^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})([[:space:]]+#.*)?$|\2@\3|p' \
      "$workflow"
  )
  if [[ ${#raw_uses[@]} -ne ${#parsed_uses[@]} ]]; then
    echo "workflow contains a malformed, quoted, local, or non-SHA action use: $workflow" >&2
    exit 65
  fi
  for use in "${parsed_uses[@]}"; do
    action=${use%@*}
    revision=${use#*@}
    if [[ -z ${expected[$action]+present} ]]; then
      echo "workflow uses an action outside the reviewed allowlist: $action" >&2
      exit 65
    fi
    if [[ $revision != "${expected[$action]}" ]]; then
      echo "workflow action is not pinned to its reviewed commit: $action" >&2
      exit 65
    fi
    seen[$action]=$(( ${seen[$action]:-0} + 1 ))
    use_count=$((use_count + 1))
  done
done

if (( use_count == 0 )); then
  echo "workflow action-pin validation found no action uses" >&2
  exit 65
fi
for action in "${!expected[@]}"; do
  if (( ${seen[$action]:-0} == 0 )); then
    echo "reviewed workflow action is absent from the complete workflow set: $action" >&2
    exit 65
  fi
done

printf 'workflow action pins: ok (%d uses, %d reviewed actions)\n' \
  "$use_count" "${#expected[@]}"
