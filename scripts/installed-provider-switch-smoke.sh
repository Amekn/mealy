#!/usr/bin/env bash

# Prove that a verified production package can promote an already-configured provider through the
# real user-service manager, survive the daemon restart, and retain inspectable transaction evidence.

set -euo pipefail
umask 077

if [[ $# -ne 2 ]]; then
  echo "usage: $0 PATH_TO_INSTALLED_MEALYD PATH_TO_INSTALLED_MEALYCTL" >&2
  exit 64
fi
if [[ $(uname -s) != Linux ]]; then
  echo "the installed provider-switch smoke is Linux-only" >&2
  exit 69
fi
for command in dirname jq mktemp python3 readlink realpath seq sha256sum sleep stat systemctl timeout; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "installed provider-switch smoke requires $command" >&2
    exit 69
  fi
done
if [[ ! -d /run/systemd/system ]]; then
  echo "the host system manager is not systemd" >&2
  exit 69
fi

isolated_environment=false
if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
  isolated_environment=true
elif command -v systemd-detect-virt >/dev/null 2>&1 \
  && systemd-detect-virt --quiet --container; then
  isolated_environment=true
fi
if [[ $isolated_environment != true \
  && ${MEALY_PROVIDER_SWITCH_SMOKE_ALLOW_HOST-} != true ]]; then
  echo "refusing to mutate a non-isolated systemd user manager" >&2
  echo "run this proof in a disposable container, or explicitly allow the reviewed temporary service lifecycle" >&2
  exit 73
fi

systemctl_user() {
  timeout --foreground --signal=TERM --kill-after=5 30 systemctl --user "$@"
}
if ! systemctl_user show-environment >/dev/null 2>&1; then
  echo "the current user has no reachable systemd user manager" >&2
  exit 69
fi
if systemctl_user cat mealy.service >/dev/null 2>&1; then
  echo "refusing to replace an existing mealy.service in this user manager" >&2
  exit 73
fi

mealyd=$(realpath -- "$1")
mealyctl=$(realpath -- "$2")
mealyd_directory=$(dirname -- "$mealyd")
mealyctl_directory=$(dirname -- "$mealyctl")
if [[ ! -x $mealyd || ! -x $mealyctl || $mealyd_directory != "$mealyctl_directory" ]]; then
  echo "installed mealyd and mealyctl must be executable and installed side by side" >&2
  exit 66
fi
install_status=$("$mealyctl" install-status)
jq -e '
  .integrity == "verified"
  and (
    .installationKind == "managed-archive"
    or .installationKind == "debian-package"
    or .installationKind == "rpm-package"
    or .installationKind == "arch-package"
  )
' <<<"$install_status" >/dev/null

temporary=$(mktemp -d "$HOME/.mealy-provider-switch-smoke.XXXXXX")
home="$temporary/home"
fixture_directory="$temporary/fixture"
port_file="$fixture_directory/port"
default_unit="$HOME/.config/systemd/user/mealy.service"
mkdir -m 0700 -- "$home" "$fixture_directory"
daemon_pid=
fixture_pid=
service_installed=false

cleanup() {
  status=$?
  set +e
  if [[ $service_installed == true ]]; then
    systemctl_user disable --now mealy.service >/dev/null 2>&1
    if [[ -f $default_unit ]] \
      && grep -Fq "ExecStart=\"$mealyd\" --home \"$home\"" "$default_unit"; then
      rm -f -- "$default_unit"
    fi
    systemctl_user daemon-reload >/dev/null 2>&1
    systemctl_user reset-failed mealy.service >/dev/null 2>&1
  fi
  if [[ -n $daemon_pid ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null
    wait "$daemon_pid" 2>/dev/null
  fi
  if [[ -n $fixture_pid ]] && kill -0 "$fixture_pid" 2>/dev/null; then
    kill "$fixture_pid" 2>/dev/null
    wait "$fixture_pid" 2>/dev/null
  fi
  if [[ $status -ne 0 && ${MEALY_PROVIDER_SWITCH_SMOKE_RETAIN_ON_FAILURE-} == true ]]; then
    echo "retained failed provider-switch smoke evidence at $temporary" >&2
  else
    rm -rf -- "$temporary"
  fi
  exit "$status"
}
trap cleanup EXIT

python3 - "$port_file" >"$fixture_directory/server.stdout" \
  2>"$fixture_directory/server.stderr" <<'PY' &
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port_file = sys.argv[1]

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def do_POST(self):
        if self.path != "/v1/responses":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0"))
        if length < 1 or length > 65536:
            self.send_error(400)
            return
        request = json.loads(self.rfile.read(length))
        model = request.get("model")
        if model not in ("primary-model", "fallback-model"):
            self.send_error(400)
            return
        body = json.dumps({
            "id": "resp_mealy_installed_switch_fixture",
            "object": "response",
            "model": model,
            "status": "completed",
            "error": None,
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "OK"}]
            }],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
        }, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "x", encoding="ascii") as handle:
    os.chmod(port_file, 0o600)
    handle.write(str(server.server_address[1]))
server.serve_forever()
PY
fixture_pid=$!
for _ in $(seq 1 200); do
  if [[ -s $port_file ]]; then
    break
  fi
  if ! kill -0 "$fixture_pid" 2>/dev/null; then
    echo "the local provider fixture exited before publishing its port" >&2
    exit 70
  fi
  sleep 0.05
done
if [[ ! -s $port_file ]]; then
  echo "the local provider fixture did not become ready" >&2
  exit 70
fi
port=$(<"$port_file")
if [[ ! $port =~ ^[1-9][0-9]{0,4}$ ]] || ((port > 65535)); then
  echo "the local provider fixture published an invalid port" >&2
  exit 70
fi
base_url="http://127.0.0.1:$port/v1"

"$mealyd" \
  --home "$home" \
  --promotion-interval-ms 10 \
  --outbox-delay-ms 0 \
  --agent-delay-ms 10 \
  --fake-provider-delay-ms 10 \
  >"$temporary/direct.stdout" 2>"$temporary/direct.stderr" &
daemon_pid=$!
for _ in $(seq 1 400); do
  if "$mealyctl" --home "$home" health >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "the installed daemon exited before initializing the switch home" >&2
    exit 70
  fi
  sleep 0.05
done
"$mealyctl" --home "$home" health >/dev/null
"$mealyctl" --home "$home" drain >/dev/null
wait "$daemon_pid"
daemon_pid=

"$mealyctl" --home "$home" config provider-local \
  --provider-id local.primary \
  --base-url "$base_url" \
  --model primary-model \
  --context-tokens 32768 \
  --maximum-output-tokens 64 \
  --disable-streaming \
  --skip-connectivity-test \
  --estimated-latency-ms 1000 \
  --approve >/dev/null
"$mealyctl" --home "$home" config provider-fallback-local \
  --provider-id local.fallback \
  --base-url "$base_url" \
  --model fallback-model \
  --residency local \
  --context-tokens 32768 \
  --maximum-output-tokens 64 \
  --disable-streaming \
  --skip-connectivity-test \
  --estimated-latency-ms 1000 \
  --approve >/dev/null

service=$("$mealyctl" --home "$home" service install)
jq -e --arg daemon "$mealyd" --arg home "$home" --arg unit "$default_unit" '
  .platform == "linux-systemd-user"
  and .daemonPath == $daemon
  and .home == $home
  and .serviceDefinition == $unit
' <<<"$service" >/dev/null
service_installed=true
systemctl_user daemon-reload
systemctl_user enable --now mealy.service >/dev/null
for _ in $(seq 1 400); do
  if "$mealyctl" --home "$home" health >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
"$mealyctl" --home "$home" health >/dev/null
pid_before=$(systemctl_user show mealy.service --property=MainPID --value)
if [[ ! $pid_before =~ ^[1-9][0-9]*$ \
  || ! -e /proc/$pid_before/exe \
  || $(readlink -f -- "/proc/$pid_before/exe") != "$mealyd" ]]; then
  echo "the installed owner service did not start the exact daemon" >&2
  exit 70
fi

catalog_before=$("$mealyctl" --home "$home" provider catalog)
jq -e '
  .catalogScope == "configured_route"
  and (.routes | length) == 2
  and .routes[0].providerId == "local.primary"
  and .routes[0].modelId == "primary-model"
  and .routes[0].routeRole == "primary"
  and .routes[1].providerId == "local.fallback"
  and .routes[1].modelId == "fallback-model"
  and .routes[1].routeRole == "fallback"
' <<<"$catalog_before" >/dev/null
config_sha256_before=$(sha256sum "$home/config.json" | cut -d ' ' -f 1)
plan=$("$mealyctl" --home "$home" provider switch \
  --provider-id local.fallback --model-id fallback-model)
jq -e '
  .schemaVersion == "mealy.provider-switch-plan.v1"
  and .providerId == "local.fallback"
  and .modelId == "fallback-model"
  and .previousProviderId == "local.primary"
  and .previousModelId == "primary-model"
  and .configuredRouteCount == 2
  and .actionRequired == true
  and .applySupported == true
  and .probeRequired == true
  and .drainRequired == true
  and .restartRequired == true
  and .exactRollbackAvailable == true
  and .unsupportedReason == null
' <<<"$plan" >/dev/null
[[ $(sha256sum "$home/config.json" | cut -d ' ' -f 1) == "$config_sha256_before" ]]
[[ ! -e $home/provider-switch-transactions ]]

transaction=$(timeout --foreground --signal=TERM --kill-after=5 180 \
  "$mealyctl" --home "$home" provider switch \
    --provider-id local.fallback --model-id fallback-model --approve)
jq -e '
  .schemaVersion == "mealy.provider-switch-transaction.v1"
  and .phase == "committed"
  and .previousProviderId == "local.primary"
  and .previousModelId == "primary-model"
  and .candidateProviderId == "local.fallback"
  and .candidateModelId == "fallback-model"
  and .configuredRouteCount == 2
  and (.committedConfigDigest | test("^[0-9a-f]{64}$"))
  and .failure == null
  and .rollbackAttempted == false
' <<<"$transaction" >/dev/null
transaction_id=$(jq -er '.transactionId' <<<"$transaction")
committed_config_digest=$(jq -er '.committedConfigDigest' <<<"$transaction")
previous_config_sha256=$(jq -er '.previousConfigSha256' <<<"$transaction")
candidate_config_sha256=$(jq -er '.candidateConfigSha256' <<<"$transaction")
transaction_status=$("$mealyctl" --home "$home" provider switch-status "$transaction_id")
jq -e --arg transaction_id "$transaction_id" '
  .transactionId == $transaction_id
  and .phase == "committed"
  and .candidateProviderId == "local.fallback"
  and .rollbackAttempted == false
' <<<"$transaction_status" >/dev/null
helper=$(jq -er '.helperExecutable' <<<"$transaction_status")
record="$home/provider-switch-transactions/$transaction_id.json"
previous_snapshot="$home/provider-switch-transactions/$transaction_id.previous.json"
candidate_snapshot="$home/provider-switch-transactions/$transaction_id.candidate.json"
archived_config=$(jq -er '.archivedConfig' <<<"$transaction_status")
[[ ! -e $helper ]]
[[ $(stat -c '%a' "$home/provider-switch-transactions") == 700 ]]
[[ $(stat -c '%a' "$record") == 600 ]]
[[ $(stat -c '%a' "$previous_snapshot") == 600 ]]
[[ $(stat -c '%a' "$candidate_snapshot") == 600 ]]
[[ $archived_config == "$home/config-history/pre-provider-switch-$transaction_id.json" ]]
[[ $(stat -c '%a' "$archived_config") == 600 ]]
[[ $(sha256sum "$previous_snapshot" | cut -d ' ' -f 1) == "$previous_config_sha256" ]]
[[ $(sha256sum "$candidate_snapshot" | cut -d ' ' -f 1) == "$candidate_config_sha256" ]]
[[ $(sha256sum "$archived_config" | cut -d ' ' -f 1) == "$previous_config_sha256" ]]
[[ $(sha256sum "$home/config.json" | cut -d ' ' -f 1) == "$candidate_config_sha256" ]]

catalog_after=$("$mealyctl" --home "$home" provider catalog)
jq -e --arg committed_config_digest "$committed_config_digest" '
  .catalogScope == "configured_route"
  and .configDigest == $committed_config_digest
  and (.routes | length) == 2
  and .routes[0].providerId == "local.fallback"
  and .routes[0].modelId == "fallback-model"
  and .routes[0].routeRole == "primary"
  and .routes[1].providerId == "local.primary"
  and .routes[1].modelId == "primary-model"
  and .routes[1].routeRole == "fallback"
' <<<"$catalog_after" >/dev/null
jq -e '
  .provider.providerId == "local.fallback"
  and .provider.model == "fallback-model"
  and (.providerFallbacks | length) == 1
  and .providerFallbacks[0].providerId == "local.primary"
  and .providerFallbacks[0].model == "primary-model"
' "$home/config.json" >/dev/null
pid_after=$(systemctl_user show mealy.service --property=MainPID --value)
if [[ ! $pid_after =~ ^[1-9][0-9]*$ \
  || $pid_after == "$pid_before" \
  || ! -e /proc/$pid_after/exe \
  || $(readlink -f -- "/proc/$pid_after/exe") != "$mealyd" ]]; then
  echo "the provider switch did not restart into the exact installed daemon" >&2
  exit 70
fi
"$mealyctl" --home "$home" health >/dev/null
"$mealyctl" --home "$home" doctor | jq -e '
  .controlPlaneReady == true
  and .sandboxAvailable == true
  and (.checks.sqlite | startswith("ok:"))
' >/dev/null

"$mealyctl" --home "$home" drain >/dev/null
for _ in $(seq 1 400); do
  state=$(systemctl_user show mealy.service --property=ActiveState --value)
  if [[ $state != active && $state != deactivating ]]; then
    break
  fi
  sleep 0.05
done
systemctl_user disable --now mealy.service >/dev/null
"$mealyctl" --home "$home" service remove --approve >/dev/null
service_installed=false
systemctl_user daemon-reload

jq -n \
  --arg transaction_id "$transaction_id" \
  --arg previous_pid "$pid_before" \
  --arg committed_pid "$pid_after" \
  '{
    installedProviderSwitchPassed: true,
    transactionId: $transaction_id,
    previousDaemonPid: ($previous_pid | tonumber),
    committedDaemonPid: ($committed_pid | tonumber),
    primaryProviderId: "local.fallback",
    primaryModelId: "fallback-model"
  }'
