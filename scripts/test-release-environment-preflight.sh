#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
preflight=$repository_root/scripts/preflight-release-environments.sh
temporary=$(mktemp -d "${TMPDIR:-/tmp}/mealy-release-environment-test.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/fixtures"

jq -n '{
  full_name: "Amekn/mealy",
  private: false,
  archived: false,
  disabled: false
}' >"$temporary/fixtures/repository.json"
jq -n '{
  enforce_admins: {enabled: true},
  required_status_checks: {
    strict: true,
    contexts: [
      "Strict workspace gate",
      "Linux sandbox conformance",
      "Linux rendered-browser conformance",
      "Control plane (ubuntu-24.04-arm)",
      "Control plane (ubuntu-24.04)",
      "Linux distribution compatibility"
    ],
    checks: [
      {context: "Strict workspace gate", app_id: 15368},
      {context: "Linux sandbox conformance", app_id: 15368},
      {context: "Linux rendered-browser conformance", app_id: 15368},
      {context: "Control plane (ubuntu-24.04-arm)", app_id: 15368},
      {context: "Control plane (ubuntu-24.04)", app_id: 15368},
      {context: "Linux distribution compatibility", app_id: 15368}
    ]
  },
  required_pull_request_reviews: {
    dismiss_stale_reviews: true,
    required_approving_review_count: 0
  },
  required_linear_history: {enabled: true},
  required_conversation_resolution: {enabled: true},
  allow_force_pushes: {enabled: false},
  allow_deletions: {enabled: false}
}' >"$temporary/fixtures/main_protection.json"
touch "$temporary/fixtures/vulnerability_alerts_enabled"
jq -n '{
  enabled: true,
  paused: false
}' >"$temporary/fixtures/automated_security_fixes.json"
jq -n '{
  enabled: true,
  enforced_by_owner: false
}' >"$temporary/fixtures/immutable_releases.json"
jq -n '{
  enabled: true,
  allowed_actions: "selected",
  sha_pinning_required: true
}' >"$temporary/fixtures/actions_permissions.json"
jq -n '{
  github_owned_allowed: true,
  verified_allowed: false,
  patterns_allowed: ["anchore/sbom-action@*"]
}' >"$temporary/fixtures/selected_actions.json"
jq -n '{
  build_type: "workflow",
  public: true,
  https_enforced: true,
  html_url: "https://amekn.github.io/mealy/"
}' >"$temporary/fixtures/pages.json"
jq -n '{
  protection_rules: [
    {type: "required_reviewers", reviewers: [{type: "User"}]},
    {type: "branch_policy"}
  ],
  deployment_branch_policy: {
    protected_branches: false,
    custom_branch_policies: true
  }
}' >"$temporary/fixtures/signing_environment.json"
jq -n '{
  branch_policies: [{type: "tag", name: "v*.*.*"}]
}' >"$temporary/fixtures/signing_policies.json"
jq -n '[
  {name: "MEALY_REPOSITORY_BASE_URL", value: "https://amekn.github.io/mealy"},
  {name: "MEALY_REPOSITORY_GPG_FINGERPRINT", value: ("A" * 40)}
]' >"$temporary/fixtures/signing_variables.json"
jq -n '[
  {name: "MEALY_REPOSITORY_GPG_PRIVATE_KEY_BASE64"}
]' >"$temporary/fixtures/signing_secrets.json"
jq -n '{
  protection_rules: [{type: "branch_policy"}],
  deployment_branch_policy: {
    protected_branches: false,
    custom_branch_policies: true
  }
}' >"$temporary/fixtures/pages_environment.json"
cp "$temporary/fixtures/signing_policies.json" \
  "$temporary/fixtures/pages_policies.json"
jq -n '{
  protection_rules: [
    {type: "required_reviewers", reviewers: [{type: "User"}]},
    {type: "branch_policy"}
  ],
  deployment_branch_policy: {
    protected_branches: true,
    custom_branch_policies: false
  }
}' >"$temporary/fixtures/live_environment.json"
jq -n '[
  {name: "OPENROUTER_API_KEY"},
  {name: "LOCAL_API_KEY"}
]' >"$temporary/fixtures/live_secrets.json"

cat >"$temporary/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  "api repos/Amekn/mealy")
    cat "$MOCK_FIXTURES/repository.json"
    ;;
  "api repos/Amekn/mealy/branches/main/protection")
    cat "$MOCK_FIXTURES/main_protection.json"
    ;;
  "api repos/Amekn/mealy/vulnerability-alerts")
    test -e "$MOCK_FIXTURES/vulnerability_alerts_enabled"
    ;;
  "api repos/Amekn/mealy/automated-security-fixes")
    cat "$MOCK_FIXTURES/automated_security_fixes.json"
    ;;
  "api repos/Amekn/mealy/immutable-releases")
    cat "$MOCK_FIXTURES/immutable_releases.json"
    ;;
  "api repos/Amekn/mealy/actions/permissions")
    cat "$MOCK_FIXTURES/actions_permissions.json"
    ;;
  "api repos/Amekn/mealy/actions/permissions/selected-actions")
    cat "$MOCK_FIXTURES/selected_actions.json"
    ;;
  "api repos/Amekn/mealy/pages")
    cat "$MOCK_FIXTURES/pages.json"
    ;;
  "api repos/Amekn/mealy/environments/linux-repository-signing")
    cat "$MOCK_FIXTURES/signing_environment.json"
    ;;
  "api repos/Amekn/mealy/environments/linux-repository-signing/deployment-branch-policies")
    cat "$MOCK_FIXTURES/signing_policies.json"
    ;;
  "variable list --repo Amekn/mealy --env linux-repository-signing --json name,value")
    cat "$MOCK_FIXTURES/signing_variables.json"
    ;;
  "secret list --repo Amekn/mealy --env linux-repository-signing --json name")
    cat "$MOCK_FIXTURES/signing_secrets.json"
    ;;
  "api repos/Amekn/mealy/environments/github-pages")
    cat "$MOCK_FIXTURES/pages_environment.json"
    ;;
  "api repos/Amekn/mealy/environments/github-pages/deployment-branch-policies")
    cat "$MOCK_FIXTURES/pages_policies.json"
    ;;
  "api repos/Amekn/mealy/environments/live-provider-smoke")
    cat "$MOCK_FIXTURES/live_environment.json"
    ;;
  "secret list --repo Amekn/mealy --env live-provider-smoke --json name")
    cat "$MOCK_FIXTURES/live_secrets.json"
    ;;
  *)
    echo "unexpected gh call: $*" >&2
    exit 64
    ;;
esac
EOF
chmod 0755 "$temporary/bin/gh"

run_preflight() {
  PATH="$temporary/bin:$PATH" \
    MOCK_FIXTURES="$temporary/fixtures" \
    "$preflight" Amekn/mealy
}

run_preflight >"$temporary/valid.stdout"
grep -Fq 'release environment preflight: ok' "$temporary/valid.stdout"
cp -a "$temporary/fixtures" "$temporary/valid"

expect_rejection() {
  local name=$1
  local fixture=$2
  local filter=$3
  rm -rf -- "$temporary/fixtures"
  cp -a "$temporary/valid" "$temporary/fixtures"
  jq "$filter" "$temporary/fixtures/$fixture.json" \
    >"$temporary/fixtures/$fixture.changed.json"
  mv "$temporary/fixtures/$fixture.changed.json" \
    "$temporary/fixtures/$fixture.json"
  if run_preflight >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "release-environment preflight accepted invalid $name configuration" >&2
    exit 1
  fi
}

expect_rejection renamed-repository repository '.full_name = "Amekn/project_mealy"'
expect_rejection private-repository repository '.private = true'
expect_rejection missing-required-context main_protection \
  '.required_status_checks.contexts |= map(select(. != "Strict workspace gate"))'
expect_rejection extra-required-context main_protection \
  '.required_status_checks.contexts += ["unreviewed"]'
expect_rejection non-strict-status-checks main_protection \
  '.required_status_checks.strict = false'
expect_rejection spoofable-status-check main_protection \
  '.required_status_checks.checks[0].app_id = null'
expect_rejection missing-pull-request-gate main_protection \
  '.required_pull_request_reviews = null'
expect_rejection bypassable-administrator main_protection \
  '.enforce_admins.enabled = false'
expect_rejection nonlinear-history main_protection \
  '.required_linear_history.enabled = false'
expect_rejection unresolved-conversations main_protection \
  '.required_conversation_resolution.enabled = false'
expect_rejection force-push-enabled main_protection \
  '.allow_force_pushes.enabled = true'
expect_rejection deletion-enabled main_protection \
  '.allow_deletions.enabled = true'
expect_rejection disabled-security-updates automated_security_fixes \
  '.enabled = false'
expect_rejection paused-security-updates automated_security_fixes \
  '.paused = true'
expect_rejection mutable-releases immutable_releases '.enabled = false'
expect_rejection disabled-actions actions_permissions '.enabled = false'
expect_rejection unrestricted-actions actions_permissions '.allowed_actions = "all"'
expect_rejection mutable-action-tags actions_permissions '.sha_pinning_required = false'
expect_rejection broad-verified-actions selected_actions '.verified_allowed = true'
expect_rejection missing-github-actions selected_actions '.github_owned_allowed = false'
expect_rejection extra-third-party-action selected_actions \
  '.patterns_allowed += ["unreviewed/action@*"]'
expect_rejection non-workflow-pages pages '.build_type = "legacy"'
expect_rejection insecure-pages pages '.https_enforced = false'
expect_rejection missing-signing-review signing_environment \
  '.protection_rules |= map(select(.type != "required_reviewers"))'
expect_rejection broad-signing-policy signing_policies \
  '.branch_policies[0] = {type: "branch", name: "main"}'
expect_rejection wrong-base-url signing_variables \
  'map(if .name == "MEALY_REPOSITORY_BASE_URL" then .value = "https://example.invalid" else . end)'
expect_rejection lowercase-fingerprint signing_variables \
  'map(if .name == "MEALY_REPOSITORY_GPG_FINGERPRINT" then .value = ("a" * 40) else . end)'
expect_rejection missing-signing-secret signing_secrets 'map(select(false))'
expect_rejection broad-pages-policy pages_policies \
  '.branch_policies[0] = {type: "branch", name: "main"}'
expect_rejection missing-live-review live_environment \
  '.protection_rules |= map(select(.type != "required_reviewers"))'
expect_rejection broad-live-policy live_environment \
  '.deployment_branch_policy = {
    protected_branches: false,
    custom_branch_policies: true
  }'
expect_rejection missing-openrouter-secret live_secrets \
  'map(select(.name != "OPENROUTER_API_KEY"))'
expect_rejection missing-private-endpoint-secret live_secrets \
  'map(select(.name != "LOCAL_API_KEY"))'

rm -rf -- "$temporary/fixtures"
cp -a "$temporary/valid" "$temporary/fixtures"
rm "$temporary/fixtures/vulnerability_alerts_enabled"
if run_preflight >"$temporary/disabled-vulnerability-alerts.stdout" \
  2>"$temporary/disabled-vulnerability-alerts.stderr"; then
  echo "release-environment preflight accepted disabled vulnerability alerts" >&2
  exit 1
fi

if "$preflight" invalid >/dev/null 2>&1; then
  echo "release-environment preflight accepted an invalid repository argument" >&2
  exit 1
fi

echo "release environment preflight tests: ok"
