#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 7 || -z $1 || -L $2 || ! -f $2 || -L $3 || ! -f $3 \
  || -z $4 || ! $5 =~ ^[1-9][0-9]*$ || -z $6 || ! $7 =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: installed-native-upgrade-smoke.sh FAMILY OLD_PACKAGE NEW_PACKAGE OLD_VERSION OLD_SCHEMA NEW_VERSION NEW_SCHEMA" >&2
  exit 64
fi

family=$1
old_package=$(readlink -f "$2")
new_package=$(readlink -f "$3")
old_version=$4
old_schema=$5
new_version=$6
new_schema=$7
if [[ $old_package == "$new_package" || $old_version == "$new_version" \
  || $old_schema -ge $new_schema ]]; then
  echo "native upgrade smoke requires distinct packages and a forward schema transition" >&2
  exit 64
fi
for package in "$old_package" "$new_package"; do
  if [[ $(stat -c '%s' "$package") -gt 268435456 ]]; then
    echo "native package exceeds the 256 MiB smoke bound: $package" >&2
    exit 65
  fi
done
for command in find jq mktemp readlink seq sha256sum sleep sort stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "installed native upgrade smoke requires $command" >&2
    exit 69
  fi
done

case $(uname -m) in
  x86_64 | amd64)
    deb_architecture=amd64
    rpm_architecture=x86_64
    arch_architecture=x86_64
    ;;
  aarch64 | arm64)
    deb_architecture=arm64
    rpm_architecture=aarch64
    arch_architecture=aarch64
    ;;
  *)
    echo "unsupported native upgrade smoke architecture" >&2
    exit 69
    ;;
esac

installation_kind=
update_mode=
case $family in
  deb)
    for command in dpkg dpkg-deb dpkg-query tar; do
      command -v "$command" >/dev/null 2>&1 || {
        echo "Debian native upgrade smoke requires $command" >&2
        exit 69
      }
    done
    installation_kind=debian-package
    update_mode=apt
    for package in "$old_package" "$new_package"; do
      if [[ $(dpkg-deb --field "$package" Package) != mealy \
        || $(dpkg-deb --field "$package" Architecture) != "$deb_architecture" ]]; then
        echo "Debian package identity does not match this host" >&2
        exit 65
      fi
      control_inventory=$(dpkg-deb --ctrl-tarfile "$package" | tar -tf - | sort)
      if [[ $control_inventory != $'./\n./control\n./md5sums' ]]; then
        echo "Debian package contains unexpected maintainer control files" >&2
        exit 65
      fi
    done
    if [[ $(dpkg-deb --field "$old_package" Version) != "${old_version/-/~}" \
      || $(dpkg-deb --field "$new_package" Version) != "${new_version/-/~}" ]]; then
      echo "Debian package version does not match the requested upgrade boundary" >&2
      exit 65
    fi
    if dpkg-query --show mealy >/dev/null 2>&1; then
      echo "a Mealy Debian package is already registered" >&2
      exit 73
    fi
    ;;
  rpm)
    command -v rpm >/dev/null 2>&1 || {
      echo "RPM native upgrade smoke requires rpm" >&2
      exit 69
    }
    installation_kind=rpm-package
    update_mode=dnf
    for package in "$old_package" "$new_package"; do
      if [[ $(rpm -qp --queryformat '%{NAME} %{ARCH}\n' "$package") \
          != "mealy $rpm_architecture" \
        || -n $(rpm -qp --scripts "$package") ]]; then
        echo "RPM identity does not match this host or package contains scriptlets" >&2
        exit 65
      fi
    done
    if [[ $(rpm -qp --queryformat '%{VERSION}\n' "$old_package") != "$old_version" \
      || $(rpm -qp --queryformat '%{VERSION}\n' "$new_package") != "$new_version" ]]; then
      echo "RPM version does not match the requested upgrade boundary" >&2
      exit 65
    fi
    if rpm -q mealy >/dev/null 2>&1; then
      echo "a Mealy RPM is already registered" >&2
      exit 73
    fi
    ;;
  arch)
    for command in awk bsdtar pacman; do
      command -v "$command" >/dev/null 2>&1 || {
        echo "Arch native upgrade smoke requires $command" >&2
        exit 69
      }
    done
    if [[ $arch_architecture != x86_64 ]]; then
      echo "the supported Arch package lane is x86_64" >&2
      exit 69
    fi
    installation_kind=arch-package
    update_mode=pacman
    for package in "$old_package" "$new_package"; do
      package_info=$(bsdtar -xOf "$package" .PKGINFO)
      if [[ $(awk -F ' = ' '$1 == "pkgname" {print $2}' <<<"$package_info") != mealy \
        || $(awk -F ' = ' '$1 == "arch" {print $2}' <<<"$package_info") \
          != "$arch_architecture" \
        || $(bsdtar -tf "$package" | grep -Ec '(^|/)\.INSTALL$') -ne 0 ]]; then
        echo "Arch package identity does not match this host or package contains an install hook" >&2
        exit 65
      fi
    done
    if [[ $(bsdtar -xOf "$old_package" .PKGINFO \
        | awk -F ' = ' '$1 == "pkgver" {print $2}') != "$old_version-1" \
      || $(bsdtar -xOf "$new_package" .PKGINFO \
        | awk -F ' = ' '$1 == "pkgver" {print $2}') != "$new_version-1" ]]; then
      echo "Arch package version does not match the requested upgrade boundary" >&2
      exit 65
    fi
    if pacman -Q mealy >/dev/null 2>&1; then
      echo "a Mealy Arch package is already registered" >&2
      exit 73
    fi
    ;;
  *)
    echo "unsupported native package family: $family" >&2
    exit 64
    ;;
esac

if [[ -e /usr/bin/mealyd || -e /usr/bin/mealyctl || -e /usr/lib/mealy \
  || -e /usr/share/doc/mealy ]]; then
  echo "an unmanaged Mealy target path already exists" >&2
  exit 73
fi
if [[ $EUID -eq 0 ]]; then
  root_command=()
else
  if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true; then
    echo "passwordless sudo is required for the isolated native upgrade smoke" >&2
    exit 77
  fi
  root_command=(sudo -n)
fi

temporary_root=${MEALY_INSTALLED_SMOKE_ROOT:-${HOME-}}
if [[ -z $temporary_root || -L $temporary_root || ! -d $temporary_root \
  || ! -w $temporary_root ]]; then
  echo "native upgrade smoke requires a writable real HOME or MEALY_INSTALLED_SMOKE_ROOT" >&2
  exit 69
fi
temporary=$(mktemp -d "$temporary_root/.mealy-native-upgrade-smoke.XXXXXX")
home="$temporary/home"
mkdir -m 0700 "$home"
daemon_pid=
package_installed=false

remove_package() {
  case $family in
    deb)
      "${root_command[@]}" dpkg --remove mealy >/dev/null 2>&1 || true
      "${root_command[@]}" dpkg --purge mealy >/dev/null 2>&1 || true
      ;;
    rpm) "${root_command[@]}" rpm -e mealy >/dev/null 2>&1 || true ;;
    arch) "${root_command[@]}" pacman -R --noconfirm mealy >/dev/null 2>&1 || true ;;
  esac
}
cleanup() {
  if [[ -n $daemon_pid ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  if [[ $package_installed == true ]]; then
    remove_package
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT

install_old_package() {
  case $family in
    deb) "${root_command[@]}" dpkg --install "$old_package" >/dev/null ;;
    rpm) "${root_command[@]}" rpm --install --nosignature "$old_package" >/dev/null ;;
    arch) "${root_command[@]}" pacman -U --noconfirm "$old_package" >/dev/null ;;
  esac
}
upgrade_package() {
  case $family in
    deb) "${root_command[@]}" dpkg --install "$new_package" >/dev/null ;;
    rpm) "${root_command[@]}" rpm --upgrade --nosignature "$new_package" >/dev/null ;;
    arch) "${root_command[@]}" pacman -U --noconfirm "$new_package" >/dev/null ;;
  esac
}

verify_installed_release() {
  local expected_version=$1
  local expected_schema=$2
  local manifest=/usr/lib/mealy/release/BUILD-MANIFEST.json
  if [[ ! -x /usr/bin/mealyd || ! -x /usr/bin/mealyctl \
    || ! -f $manifest || ! -f /usr/lib/mealy/release/PAYLOAD-SHA256SUMS ]]; then
    echo "native package is not installed at the canonical paths" >&2
    exit 70
  fi
  (cd /usr/lib/mealy/release \
    && sha256sum --check --strict PAYLOAD-SHA256SUMS >/dev/null)
  jq -e --arg version "$expected_version" --argjson schema "$expected_schema" '
    .version == $version and .stateSchemaVersion == $schema
  ' "$manifest" >/dev/null
  [[ $(/usr/bin/mealyd --version) == "mealyd $expected_version" ]]
  [[ $(/usr/bin/mealyctl --version) == "mealyctl $expected_version" ]]
  [[ $(/usr/bin/mealyd --print-supported-schema-version) == "$expected_schema" ]]
  local install_status
  install_status=$(/usr/bin/mealyctl install-status)
  jq -e \
    --arg kind "$installation_kind" \
    --arg mode "$update_mode" \
    --arg version "$expected_version" \
    --argjson schema "$expected_schema" '
      .schemaVersion == "mealy.install-status.v1"
      and .installationKind == $kind
      and .integrity == "verified"
      and .currentVersion == $version
      and .stateSchemaVersion == $schema
      and .updateMode == $mode
      and .rollbackAvailable == false
      and (.nativeUpdateCommand | type == "string" and length > 0)
      and .issues == []
    ' <<<"$install_status" >/dev/null
}

start_daemon() {
  local phase=$1
  /usr/bin/mealyd \
    --home "$home" \
    --promotion-interval-ms 10 \
    --outbox-delay-ms 0 \
    --agent-delay-ms 10 \
    --fake-provider-delay-ms 10 \
    >"$temporary/$phase-daemon.stdout" 2>"$temporary/$phase-daemon.stderr" &
  daemon_pid=$!
  for _ in $(seq 1 600); do
    if [[ -s $home/connection.json ]] \
      && /usr/bin/mealyctl --home "$home" health \
        >"$temporary/$phase-health.json" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      echo "$phase daemon exited before becoming live" >&2
      sed -n '1,120p' "$temporary/$phase-daemon.stderr" >&2
      exit 70
    fi
    sleep 0.05
  done
  jq -e '.apiVersion == "v1" and .live == true' \
    "$temporary/$phase-health.json" >/dev/null
}

stop_daemon() {
  local phase=$1
  /usr/bin/mealyctl --home "$home" drain >/dev/null
  for _ in $(seq 1 600); do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  if kill -0 "$daemon_pid" 2>/dev/null; then
    echo "$phase daemon did not complete its bounded drain" >&2
    exit 70
  fi
  wait "$daemon_pid"
  daemon_pid=
}

package_installed=true
install_old_package
verify_installed_release "$old_version" "$old_schema"
start_daemon old
/usr/bin/mealyctl --home "$home" doctor >"$temporary/old-doctor.json"
jq -e --arg schema "$old_schema" '
  .apiVersion == "v1"
  and .controlPlaneReady == true
  and (.checks.sqlite | contains("schema " + $schema + " "))
' "$temporary/old-doctor.json" >/dev/null
if [[ -d $home/migration-backups \
  && -n $(find "$home/migration-backups" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
  echo "fresh old-version home unexpectedly contains a migration backup" >&2
  exit 70
fi

session=$(/usr/bin/mealyctl --home "$home" session create)
session_id=$(jq -er '.sessionId' <<<"$session")
marker="native-upgrade-$family-$old_version-to-$new_version-$session_id"
/usr/bin/mealyctl --home "$home" session send "$session_id" "$marker" \
  --idempotency-key installed-native-upgrade-smoke-1 >/dev/null
task_id=
for _ in $(seq 1 800); do
  search=$(/usr/bin/mealyctl --home "$home" session search --limit 1 "$marker")
  task_id=$(jq -r '.hits[0].taskId // empty' <<<"$search")
  if [[ -n $task_id ]]; then
    task=$(/usr/bin/mealyctl --home "$home" task status "$task_id")
    status=$(jq -r '.status' <<<"$task")
    if [[ $status == succeeded || $status == failed || $status == cancelled ]]; then
      break
    fi
  fi
  sleep 0.05
done
if [[ -z $task_id ]]; then
  echo "old package did not publish a canonical task" >&2
  exit 70
fi
jq -e '.status == "succeeded"' <<<"$task" >/dev/null
old_replay=$(/usr/bin/mealyctl --home "$home" task replay "$task_id")
jq -e '
  .mode == "recorded_only"
  and .evidenceComplete == true
  and .liveProviderCalls == 0
  and .liveToolCalls == 0
' <<<"$old_replay" >/dev/null
identity_digest=$(sha256sum "$home/identity.json" | awk '{print $1}')
stop_daemon old

upgrade_package
verify_installed_release "$new_version" "$new_schema"
start_daemon new
/usr/bin/mealyctl --home "$home" doctor >"$temporary/new-doctor.json"
jq -e --arg schema "$new_schema" '
  .apiVersion == "v1"
  and .controlPlaneReady == true
  and (.checks.sqlite | contains("schema " + $schema + " "))
' "$temporary/new-doctor.json" >/dev/null
[[ $(sha256sum "$home/identity.json" | awk '{print $1}') == "$identity_digest" ]]

mapfile -t migration_backups < <(
  find "$home/migration-backups" -mindepth 1 -maxdepth 1 -type d -printf '%p\n' | sort
)
if [[ ${#migration_backups[@]} -ne 1 ]]; then
  echo "upgrade did not publish exactly one immutable pre-migration snapshot" >&2
  exit 70
fi
migration_manifest=${migration_backups[0]}/manifest.json
jq -e --argjson old "$old_schema" --argjson new "$new_schema" '
  .formatVersion == 1
  and .fromSchemaVersion == $old
  and .toSchemaVersion == $new
  and (.createdAtMs | type == "number")
  and ([.files[].relativePath] | sort == ["config.json", "state.sqlite3"])
  and (.rollback | type == "string" and length > 0)
' "$migration_manifest" >/dev/null
migration_manifest_digest=$(sha256sum "$migration_manifest" | awk '{print $1}')

new_search=$(/usr/bin/mealyctl --home "$home" session search --limit 1 "$marker")
jq -e --arg session "$session_id" --arg task "$task_id" '
  .hits[0].sessionId == $session and .hits[0].taskId == $task
' <<<"$new_search" >/dev/null
new_task=$(/usr/bin/mealyctl --home "$home" task status "$task_id")
jq -e '.status == "succeeded"' <<<"$new_task" >/dev/null
new_replay=$(/usr/bin/mealyctl --home "$home" task replay "$task_id")
jq -e '
  .mode == "recorded_only"
  and .evidenceComplete == true
  and .liveProviderCalls == 0
  and .liveToolCalls == 0
' <<<"$new_replay" >/dev/null
sessions=$(/usr/bin/mealyctl --home "$home" session list --limit 100)
jq -e --arg session "$session_id" \
  'any(.sessions[]; .sessionId == $session)' <<<"$sessions" >/dev/null

title="Upgraded $family conversation"
/usr/bin/mealyctl --home "$home" session rename "$session_id" "$title" \
  >"$temporary/rename.json"
sessions=$(/usr/bin/mealyctl --home "$home" session list --limit 100)
jq -e --arg session "$session_id" --arg title "$title" '
  any(.sessions[]; .sessionId == $session and .title == $title)
' <<<"$sessions" >/dev/null
checkpoint=$(/usr/bin/mealyctl --home "$home" session checkpoint create "$session_id" \
  --label "After native upgrade")
checkpoint_id=$(jq -er '.checkpointId' <<<"$checkpoint")
checkpoints=$(/usr/bin/mealyctl --home "$home" session checkpoint list "$session_id" --limit 20)
jq -e --arg checkpoint "$checkpoint_id" \
  'any(.checkpoints[]; .checkpointId == $checkpoint)' <<<"$checkpoints" >/dev/null
stop_daemon new

remove_package
package_installed=false
if [[ -e /usr/bin/mealyd || -e /usr/bin/mealyctl || -e /usr/lib/mealy \
  || ! -f $home/mealy.sqlite3 || ! -f $migration_manifest \
  || $(sha256sum "$migration_manifest" | awk '{print $1}') \
    != "$migration_manifest_digest" ]]; then
  echo "native uninstall did not remove program files while preserving migrated owner state" >&2
  exit 70
fi

jq -n \
  --arg family "$family" \
  --arg oldVersion "$old_version" \
  --argjson oldSchema "$old_schema" \
  --arg newVersion "$new_version" \
  --argjson newSchema "$new_schema" \
  --arg sessionId "$session_id" \
  --arg taskId "$task_id" \
  --arg checkpointId "$checkpoint_id" \
  --arg migrationManifestDigest "$migration_manifest_digest" '{
    schemaVersion: "mealy.installed-native-upgrade-smoke.v1",
    family: $family,
    oldVersion: $oldVersion,
    oldSchema: $oldSchema,
    newVersion: $newVersion,
    newSchema: $newSchema,
    sessionId: $sessionId,
    taskId: $taskId,
    checkpointId: $checkpointId,
    migrationManifestDigest: $migrationManifestDigest,
    result: "ok"
  }'
