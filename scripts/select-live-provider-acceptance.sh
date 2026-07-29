#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: select-live-provider-acceptance.sh RUNS.json EXPECTED_SHA REPOSITORY SERVER_URL" >&2
}

if [[ $# -ne 4 ]]; then
  usage
  exit 64
fi

runs=$1
expected_sha=$2
repository=$3
server_url=${4%/}

for command in jq stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required live-acceptance selector command is unavailable: $command" >&2
    exit 69
  }
done

if [[ -L $runs || ! -f $runs \
  || ! $expected_sha =~ ^[0-9a-f]{40}$ \
  || ! $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ \
  || ! $server_url =~ ^https://[A-Za-z0-9.-]+$ ]]; then
  usage
  exit 64
fi

runs_bytes=$(stat -c '%s' "$runs")
if (( runs_bytes < 2 || runs_bytes > 8 * 1024 * 1024 )); then
  echo "live-provider run response is empty or exceeds its 8 MiB evidence bound" >&2
  exit 65
fi

required_openrouter_title="Mealy live acceptance: openrouter-free @ $expected_sha"
required_private_title="Mealy live acceptance: private-responses @ $expected_sha"
# Stable output contract: strict-free OpenRouter first, then the pinned private provider.
if ! selected_urls=$(jq -er \
  --arg sha "$expected_sha" \
  --arg repository "$repository" \
  --arg server_url "$server_url" \
  --arg required_openrouter_title "$required_openrouter_title" \
  --arg required_private_title "$required_private_title" '
  .workflow_runs as $runs
  | select($runs | type == "array")
  | def selected($required_title):
      [$runs[] | select(
        (.id | type == "number" and . > 0 and floor == .)
        and .head_sha == $sha
        and .event == "workflow_dispatch"
        and .status == "completed"
        and .conclusion == "success"
        and .path == ".github/workflows/live-smoke.yml"
        and .name == $required_title
        and .display_title == $required_title
        and .html_url == ($server_url + "/" + $repository
          + "/actions/runs/" + (.id | tostring))
      )]
      | sort_by(.id)
      | last;
  (selected($required_openrouter_title)) as $openrouter
  | (selected($required_private_title)) as $private
  | select($openrouter != null and $private != null)
  | [$openrouter.html_url, $private.html_url]
  | .[]
  ' "$runs"); then
  echo "successful reviewed openrouter-free and private-responses acceptances are both required for the exact release commit" >&2
  exit 65
fi

printf '%s\n' "$selected_urls"
