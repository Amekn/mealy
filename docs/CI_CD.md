# Development and production delivery

This runbook defines Mealy's source-to-production promotion path. A build is production evidence
only when the exact commit moves through every gate below; a successful local build, pull-request
artifact, soak report, or live-provider run is not independently a release.

## Promotion model

```text
developer branch
  -> protected pull request CI
  -> protected main
  -> reviewed live-provider acceptance for that exact commit
  -> immutable semantic-version tag on that commit
  -> native build, test, package, SBOM, and provenance jobs
  -> one published GitHub release
  -> public clean-host acceptance on every published platform
```

There is no mutable staging deployment or alternate production build. The reviewed
`live-provider-smoke` GitHub environment is the external staging gate, and the tag workflow builds
production assets from the same Git commit. The checked release-soak report binds the long-running
runtime candidate to an identical release daemon. The release workflow refuses a tag that is not
on `main`, lacks exact-commit live acceptance, has stale/invalid soak evidence, or disagrees with
the workspace version.

## Developer setup and fast feedback

Install the host prerequisites in [QUICKSTART.md](QUICKSTART.md), use the repository-pinned Rust
toolchain, and keep `Cargo.lock` authoritative:

```sh
rustup show
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Before opening a pull request, run the checks affected by the change. For a release-bound or
cross-cutting change, reproduce the strict documentation and packaging gates too. The Debian
fixture requires `dpkg-deb` and `lintian`; protected CI installs both and treats every Lintian
warning or error as a failure:

```sh
cargo test --locked --workspace --doc --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
scripts/validate-documentation.py --cli target/debug/mealyctl
bash -n packaging/*.sh scripts/*.sh
shellcheck packaging/*.sh scripts/*.sh
scripts/test-public-license-validator.sh
scripts/test-release-soak-validator.sh
scripts/test-release-notes.sh
packaging/test-packaging.sh
packaging/test-deb-packaging.sh
packaging/test-rpm-packaging.sh
packaging/test-arch-packaging.sh
packaging/test-signed-linux-repositories.sh
```

Linux sandbox, systemd, and rendered-browser tests need the operating-system prerequisites and
explicitly isolated test setup documented in [TESTING.md](TESTING.md). Do not weaken or skip those
boundaries to make a workstation pass.

## Code and API documentation contract

All workspace crates enable the `missing_docs` lint. Protected CI builds workspace rustdoc with
warnings denied, and tests documentation examples. It also runs the real `mealyctl --help` surface
through `scripts/validate-documentation.py`, compares every registered Axum method/path pair with
`API.md`, and resolves every tracked repository-local Markdown target and fragment. Missing or
stale API routes, undocumented public top-level commands, broken local links, empty required
documents, symlink substitutions, and repository escapes fail the same protected gate. Every
public item must explain its invariant, units, authority, error behavior, and safety boundary where
relevant. Do not use comments to promise behavior that is not enforced by an implementation or
test.

The validator's bounded `--mode package` does not require Git metadata. Release jobs run it against
each extracted Linux archive with the archive's own `mealyctl`, both immediately after the native
build and again after downloading the immutable public asset. The source-mode router
comparison remains authoritative for completeness; package mode independently proves the shipped
core/API/usage documents, local links, endpoint inventory, and CLI command table are usable from
the distribution itself.

A public transport change must update all of the following in one pull request:

1. framework-neutral DTO rustdoc in `mealy-protocol`;
2. adapter/backend contract rustdoc in `mealy-api`;
3. [API.md](API.md), including endpoint, version, retry, or cursor behavior;
4. public-API and compatibility tests;
5. usage/operations documentation when an operator-visible command or lifecycle changes.

Architecture or invariant changes additionally require the relevant ADR, `ARCHITECTURE.md`, threat
model, and requirements-coverage update. New files below `docs/` must be deliberately added to the
fail-closed release-document inventories in `packaging/build-release.sh`,
`packaging/build-deb.sh`, and `packaging/install.sh`.

## Pull request and protected-main gate

Use a short-lived branch, keep unrelated changes separate, and open a pull request against `main`.
The repository must enforce strict up-to-date status checks, linear history, resolved review
conversations, admin enforcement, and disabled force-push/deletion. These six contexts are the
required Linux production set:

- `Strict workspace gate`;
- `Linux sandbox conformance`;
- `Linux rendered-browser conformance`;
- `Control plane (ubuntu-24.04)`;
- `Control plane (ubuntu-24.04-arm)`;
- `Linux distribution compatibility`.

`.github/workflows/ci.yml` is the executable definition. The strict lane checks formatting,
workflow policy, dependency policy, dashboard JavaScript, clippy, all targets/features, doc tests,
rustdoc, checked Markdown/API/CLI documentation consistency, RustSec, generated third-party
notices, shell entry points, release evidence, and all package formats. Dedicated lanes exercise
Linux Bubblewrap/systemd and the content-pinned browser; native jobs compile Linux x86-64/ARM64,
and the distribution aggregate covers clean Ubuntu, Debian, Fedora, and Arch package builds plus
a disposable-key signed APT/DNF/Pacman repository, clean installs through every manager, and
tamper rejection.

GitHub vulnerability alerts and Dependabot security updates must remain enabled. The checked
`.github/dependabot.yml` opens bounded weekly Cargo and GitHub Actions update pull requests; those
changes receive the same protected checks and are never auto-merged around release policy.

Repository Actions policy is also fail closed: Actions must remain enabled with the `selected`
allowlist and full-length commit-SHA pinning required. The selected set admits GitHub-owned actions
and exactly `anchore/sbom-action@*`; verified Marketplace status alone grants no authority. Source
policy still requires every invocation, including the SBOM action, to name a reviewed 40-hex
commit. Repository-level immutable releases, vulnerability alerts, and unpaused Dependabot
security updates must also remain enabled. The authenticated release-environment preflight
revalidates those settings and the exact protected-`main` contract, including all six
GitHub-Actions-bound status checks, before tagging. Disabled protection or security features,
mutable action references, or a broadened third-party allowlist therefore block publication even
if a stale source checkout still looks correct.

`scripts/validate-workflow-action-pins.sh` adds a repository-wide reviewed-version fence on top of
the syntax, security, allowlist, and immutable-SHA checks. Every external `uses:` entry must be an
unquoted 40-character commit from the complete checked allowlist, every reviewed action must remain
present, and every occurrence of one action—including successor-only release jobs—must use the
same reviewed commit. Hermetic negative fixtures reject a stale mixed pin, an unknown action, a
missing reviewed action, an abbreviated SHA, quoted syntax, symlinked workflow input, and an empty
workflow set.

Never merge around a red or missing context. Diagnose the first failing command from the job log,
add a regression when behavior was wrong, rerun the same command locally when practical, and let
the protected pull request rerun all contexts. A green PR is merged linearly; direct pushes to
`main` are not a release procedure.

## Main and release-candidate evidence

After merge, record the exact protected commit and require its push CI to remain green:

```sh
git fetch origin main --tags
candidate=$(git rev-parse origin/main)
git status --short
printf '%s\n' "$candidate"
gh run list --workflow ci.yml --branch main --commit "$candidate"
scripts/preflight-release-environments.sh Amekn/mealy
```

Run the preflight from the canonical source checkout before creating any release tag. It reads only
public repository/branch-protection/Actions/Pages/environment policy plus GitHub's variable and
secret-name metadata; it cannot retrieve secret values. The authenticated caller needs repository
administration read access. The check fails unless the canonical repository is public and enabled;
`main` is administrator-enforced, pull-request-only, strictly current, linear, conversation-clean,
non-force-pushable, non-deletable, and protected by the exact six GitHub Actions contexts;
vulnerability alerts, unpaused Dependabot security updates, and repository-level immutable
releases are enabled; Actions are restricted to the exact allowlist with full-SHA pinning; Pages
is a public HTTPS workflow deployment; both signing and Pages environments admit only stable
version tags; signing requires owner review; the Pages URL and uppercase primary fingerprint are
exact; the signing-subkey secret name exists; and the reviewed free-OpenRouter environment remains
restricted to protected branches with both the strict-free OpenRouter and pinned private-endpoint
secret names present. This catches a weakened source, trust-root, or provider-acceptance ceremony
before an immutable tag exists.

The release report at `docs/benchmarks/release-soak.json` must pass
`scripts/validate-release-soak.sh`. For release one it must represent a clean, retained-disk,
external-release-binary run of at least 86,400 seconds with complete accounting, successful
recovery/replay, SQLite integrity `ok`, clean drain, and zero residual work. If code changes alter
the release binaries or runtime/storage semantics after the soak, treat the report as stale and
repeat the required candidate validation rather than editing its measurements. The validator
enforces this boundary: Cargo manifests, the lockfile/toolchain configuration, compiled application
and library sources/assets/migrations, schemas, and the release-binary build entry point must be
unchanged between the observed revision (or its identical-tree lineage commit) and the proposed
release commit. Evidence, packaging, workflow, and documentation follow-ups remain eligible but
still receive protected CI.

For an external soak, the exact x86-64 `mealyd` subject must also be available through the checked
`docs/benchmarks/release-soak-subject.json` promotion manifest. The source is a private draft
release bound by numeric release ID under a dedicated `soak-subject-<revision>` tag, not an
unpinned URL or a pull-request artifact. Before tagging, run
`scripts/test-release-soak-subject-fetch.sh`; the real tag workflow's isolated promotion job is
the only build-side job granted an ephemeral `contents: write` token, because private drafts
require push-level visibility. It selects exactly one owner-uploaded asset, checks GitHub's
asset digest and byte count against the manifest, checks the manifest against the full soak report,
downloads it, recomputes the SHA-256, verifies `mealyd --version`, and transfers it through a
one-day artifact scoped to the same workflow run. The read-only x86 package job rechecks byte
count and SHA-256 before installation. It subsequently audits, service-tests, packages, SBOMs,
attests, publishes, and clean-host tests that exact daemon. A
hosted-runner rebuild is still required as a source/audit check, but it cannot replace the observed
binary because native link environments are not assumed byte-reproducible across distributions.
The fetcher rejects an ordinary stable release tag or a `soak-subject-*` tag whose encoded commit
does not exactly equal the report revision, even when the remote tag happens to resolve to that
commit.

### Stage the exact soak subject

After the terminal report passes against the candidate, merge the candidate before staging. This
repository requires linear history. When the report names a commit that exists only on the
candidate branch, use an explicit GitHub **rebase merge**, not a squash merge: the rebased sequence
retains a main-line commit with the observed commit's exact Git tree, while a squash would collapse
that intermediate tree and make the checked lineage proof impossible. GitHub documents that its
[rebase merge adds each commit individually while creating new commit
SHAs](https://docs.github.com/en/pull-requests/reference/pull-request-merges#rebase-and-merge-your-commits).
Record the protected-main head before merging, then locate the unique rebased commit with the
observed tree:

```bash
repository=Amekn/mealy
pr_number=PR_NUMBER
report=/absolute/path/to/release-soak.json
mealyd=/absolute/path/to/the/exact/soaked/mealyd
candidate=$(gh pr view "$pr_number" --repo "$repository" --json headRefOid --jq .headRefOid)
scripts/validate-release-soak.sh "$report" "$mealyd" "$candidate"
git fetch origin main
pre_merge_main=$(git rev-parse origin/main)
gh pr ready "$pr_number" --repo "$repository"
gh pr merge "$pr_number" --repo "$repository" --rebase
git fetch origin main
release_head=$(git rev-parse origin/main)
observed=$(jq -er '.revision | select(test("^[0-9a-f]{40}$"))' "$report")
observed_tree=$(git rev-parse "${observed}^{tree}")
mapfile -t lineage_matches < <(
  git rev-list "$release_head" "^$pre_merge_main" |
    while read -r candidate; do
      test "$(git rev-parse "${candidate}^{tree}")" = "$observed_tree" &&
        printf '%s\n' "$candidate"
    done
)
test "${#lineage_matches[@]}" -eq 1
release_lineage=${lineage_matches[0]}
scripts/generate-release-soak-lineage.sh \
  "$report" "$release_lineage" "$release_head" \
  docs/benchmarks/release-soak-lineage.json
scripts/validate-release-soak.sh \
  "$report" "$mealyd" "$release_head" \
  docs/benchmarks/release-soak-lineage.json
```

Require the exact `release_head` protected-main CI run to finish successfully before creating the
private staging tag or release.

If the observed revision is already an ancestor of `release_head`, do not create a lineage proof;
validate it directly. The generator rejects an unnecessary proof, a non-ancestor mapped commit,
tree drift, malformed report identity, an absent commit, an oversized/unrehashable commit payload,
or a symlink destination. The validator then rehashes the embedded original commit payload and
binds the unedited report digest, both Git trees, the mapped main-line commit, and the final
release ancestry.

After that validation, stage the observed daemon as a private draft transport asset before opening
the evidence PR. This is not the public production release. Run from the canonical repository on
the Linux soak host, with an authenticated `gh` session that can create a draft release:

```sh
repository=Amekn/mealy
report=/absolute/path/to/release-soak.json
mealyd=/absolute/path/to/the/exact/soaked/mealyd
observed=$(jq -er '.revision | select(test("^[0-9a-f]{40}$"))' "$report")
staging_tag="soak-subject-$observed"
asset_name="mealy-soak-${observed}-linux-x86_64-gnu-mealyd"
test "$(git rev-parse --verify "${observed}^{commit}")" = "$observed"
expected=$(git rev-parse origin/main)
if git merge-base --is-ancestor "$observed" "$expected"; then
  scripts/validate-release-soak.sh "$report" "$mealyd" "$expected"
else
  scripts/validate-release-soak.sh \
    "$report" "$mealyd" "$expected" \
    docs/benchmarks/release-soak-lineage.json
fi

git tag -a "$staging_tag" "$observed" -m "Mealy release soak subject $observed"
git push origin "refs/tags/$staging_tag"
staging=$(mktemp -d)
install -m 0755 "$mealyd" "$staging/$asset_name"
gh release create "$staging_tag" "$staging/$asset_name" --draft --verify-tag \
  --title "Mealy release soak subject $observed" \
  --notes "Private exact-binary transport for the validated release soak."
rm -rf -- "$staging"
```

Derive the checked manifest from GitHub's current authenticated release-list and asset metadata;
never type its ID, size, or digest from memory. Drafts do not have a stable public tag URL, so
select exactly one matching draft from the owner-visible list rather than using the public
release-by-tag endpoint:

```sh
releases=$(gh api --method GET "repos/$repository/releases" -F per_page=100)
release=$(jq -cer --arg tag "$staging_tag" '
  [.[] | select(.tag_name == $tag)]
  | if length == 1 then .[0] else error("release identity") end
  ' <<<"$releases")
release_id=$(jq -er '.id' <<<"$release")
asset=$(jq -er --arg name "$asset_name" \
  '[.assets[] | select(.name == $name)] | if length == 1 then .[0] else error("asset identity") end' \
  <<<"$release")
asset_bytes=$(jq -er '.size' <<<"$asset")
asset_digest=$(jq -er '.digest | select(test("^sha256:[0-9a-f]{64}$"))' <<<"$asset")
asset_sha256=${asset_digest#sha256:}
jq -n --arg repository "$repository" --argjson release_id "$release_id" \
  --arg release_tag "$staging_tag" --arg asset_name "$asset_name" \
  --arg asset_sha256 "$asset_sha256" --argjson asset_bytes "$asset_bytes" \
  --arg revision "$observed" '
  {
    schemaVersion: "mealy.soak-subject.v1",
    repository: $repository,
    releaseId: $release_id,
    releaseTag: $release_tag,
    assetName: $asset_name,
    assetSha256: $asset_sha256,
    assetBytes: $asset_bytes,
    revision: $revision,
    target: {os: "linux", architecture: "x86_64"}
  }
  ' >docs/benchmarks/release-soak-subject.json
```

Copy the terminal report without editing its measurements, then verify a fresh authenticated
download before committing either JSON file. The fetcher deliberately requires an explicit
`GH_TOKEN` even when the maintainer already has a valid GitHub CLI session, matching the narrower
workflow credential boundary instead of silently selecting ambient authentication:

```sh
verified=$(mktemp -d)
GH_TOKEN="$(gh auth token)" \
  scripts/fetch-release-soak-subject.sh \
  docs/benchmarks/release-soak-subject.json \
  "$report" \
  "$verified/mealyd" \
  "$repository"
if git merge-base --is-ancestor "$observed" "$expected"; then
  scripts/validate-release-soak.sh \
    "$report" "$verified/mealyd" "$expected"
else
  scripts/validate-release-soak.sh \
    "$report" "$verified/mealyd" "$expected" \
    docs/benchmarks/release-soak-lineage.json
fi
rm -rf -- "$verified"
```

Do not enable shell tracing around the token assignment. Keep prior draft subjects for audit; their
unique tags, release IDs, and asset names prevent them from qualifying a newer manifest.

## Reviewed live-provider acceptance

The exact final commit needs a successful protected `main` push run of `.github/workflows/ci.yml`
and two successful manual runs of `.github/workflows/live-smoke.yml` in the protected
`live-provider-smoke` environment. First run `openrouter-free` without forcing a model:

```sh
gh workflow run live-smoke.yml --ref main \
  -f provider=openrouter-free \
  -f run_brave_search=false
```

Then dispatch the separately reviewed pinned-private-endpoint acceptance against the same final
`main` commit. The model and context below are the most recently verified non-secret server
identity; recheck them deliberately if the server changes:

```sh
gh workflow run live-smoke.yml --ref main \
  -f provider=private-responses \
  -f model=Qwen3.6-27B \
  -f context_tokens=32768 \
  -f run_brave_search=false
```

The environment must require an owner review, admit protected branches only, and expose
`OPENROUTER_API_KEY` and `LOCAL_API_KEY` only as environment secrets; the release-environment
preflight requires both so strict-free and pinned private-endpoint acceptance remain runnable.
The workflow discovers the account-visible
catalog, selects an exact `:free` tool-capable model, requires complete zero input/output pricing
and usable token limits, and then proves setup, credential containment, a real governed read,
durable usage settlement, recorded-only replay, and clean drain. Activation keeps its no-tools
connectivity probe bounded to 256 output tokens, while live agent turns receive a 1,024-token
runtime allowance so a tool call and its post-tool final response can both become terminal. The
catalog-selected model must advertise at least that runtime output capacity. The workflow never
sends the key to a pull-request job or stores it in Mealy configuration.

After approval and completion, verify that both successful runs' `headSha` values are exactly the
candidate commit. The workflow-controlled run name binds each selected provider and SHA. Both the
x86 package gate and final publication gate use the checked selector to require exact canonical
names, workflow paths, successful `workflow_dispatch` results, and repository run URLs for both
`openrouter-free` and `private-responses`. A success on an earlier commit does not qualify a later
tag, and neither provider can substitute for the other. Direct paid API keys and the owner-local
ChatGPT subscription bridge remain separately reviewed additional acceptance and should not be
used for frequent CI traffic. Claude Free, Pro,
and Max subscription credentials are not a supported Mealy route under Anthropic's current
third-party terms; exercise the direct Anthropic API only with separately approved paid credentials.

## Tag and publish

The workspace version and proposed tag must match. Confirm protected CI and live acceptance first,
then create one annotated stable `vMAJOR.MINOR.PATCH` tag on the exact candidate and push only that
tag. The production workflow rejects prerelease/build metadata, leading-zero components, and any
workspace-version mismatch rather than publishing them as a normal stable GitHub release:

```sh
test "$(git rev-parse origin/main)" = "$candidate"
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
tag="v$version"
git tag -a "$tag" "$candidate" -m "Mealy $tag"
git push origin "refs/tags/$tag"
```

Do not move or reuse a published version tag. A correction uses a new semantic version.

`.github/workflows/release.yml` then performs these production gates:

- revalidates license, tag ancestry/identity, soak evidence, exact protected-main CI, and both
  exact-commit strict-free OpenRouter and pinned private-provider live acceptances;
- isolates private-draft access in one ephemeral promotion job and rehashes its current-run handoff;
- repeats strict tests, sandbox/browser/service proofs, RustSec, and auditable binary inspection;
- builds native Linux x86-64 and ARM64 archives, Debian packages, and RPMs plus an x86-64 Arch
  package;
- generates per-platform CycloneDX SBOMs and third-party license notices;
- verifies reproducibility, checksums, installed archive/package behavior, upgrade/rollback, and
  state preservation;
- creates GitHub artifact attestations plus retained offline Sigstore bundles;
- creates package-manager-native signed APT, DNF, and Pacman repositories with an owner-reviewed
  signing key, attests their complete manifest, and stages the exact Pages artifact;
- assembles one exact release inventory and publishes deterministic evidence-bound notes;
- waits for the published record to report `isImmutable: true`, validates every uploaded asset
  name/digest/size/URL, and verifies GitHub's signed release attestation before any dependent
  repository deployment or public acceptance can start;
- deploys the signed repositories only after the immutable GitHub release exists;
- downloads the public release on native Linux runners, verifies release/asset integrity and
  provenance, uses the public tokenless rootless bootstrap without a repository override, and
  repeats guided onboarding, first chat, enabled-service restart, `doctor`, durable continuation,
  and clean removal against those exact downloaded binaries;
- repeats clean-host installed acceptance on Ubuntu, Debian, Fedora, and Arch and installs the
  tagged version through each public HTTPS repository before the workflow can pass.

The tag workflow and `.github/workflows/public-repository-acceptance.yml` share checked manifest
verification and package-manager installation scripts. Every GitHub release command supplies an
explicit `OWNER/REPOSITORY`, so the verifier is independent of checkout discovery. The manual
workflow is a non-publishing recovery path for an already published immutable tag when only the
dependent verification harness was defective. It runs only from protected `main`, resolves the
annotated tag to its exact commit, requires that commit in `main`, verifies the original release
workflow attestation, and aggregates all five public repository lanes.

The one-time Pages, signing Environment, offline-key, and rotation controls are in
[LINUX_REPOSITORIES.md](LINUX_REPOSITORIES.md#maintainer-activation). A missing Pages site,
unapproved signing Environment, empty key secret, base-URL mismatch, wrong fingerprint, unusable
signing subkey, invalid package identity, or failed public package-manager install blocks the tag;
there is no unsigned publication fallback.

Linux x86-64 and ARM64 are the production worker targets. Arch Linux is x86-64-only upstream;
Arch Linux ARM remains a derivative rather than an official target. macOS and Windows are outside
the active production, packaging, and CI contract.

## Verification and promotion decision

Monitor every tag job and do not announce production readiness until the workflow is fully green,
or until a verifier-only post-publication failure has a green protected revalidation run:

```sh
gh run list --repo Amekn/mealy --workflow release.yml --commit "$candidate"
gh release verify "$tag" --repo Amekn/mealy --format json
gh release view "$tag" --repo Amekn/mealy \
  --json tagName,targetCommitish,url,assets
gh workflow run public-repository-acceptance.yml \
  --repo Amekn/mealy --ref main -f release_tag="$tag"
```

For each downloaded asset, run `gh release verify-asset`. For archives, packages, installers, and
SBOMs, also verify the matching checksum manifest and provenance with `gh attestation verify`, the
repository, the release workflow identity, the exact tag source ref, and the retained offline
bundle. [RELEASE.md](RELEASE.md) contains the complete end-user commands.

The production decision is fail closed:

- PR or protected-main failure: fix in a new commit and repeat protected CI;
- soak invalidation: build the exact new candidate and repeat the formal soak;
- live-provider failure or SHA mismatch: do not tag; fix and rerun the reviewed gate;
- tag workflow failure before publication: do not create assets manually; fix and publish a new
  version if the tag cannot be safely removed before any release exists;
- public acceptance harness failure after publication: retain the failed run, correct the harness
  through protected `main`, and require the non-publishing post-publication workflow to pass against
  the unchanged immutable tag;
- public artifact, package, repository-content, signature, provenance, or runtime failure after
  publication: do not call that version production-ready or replace assets; publish a corrected
  version through every applicable gate.

## Roll forward, rollback, and incident evidence

Normal production change is roll-forward through the same pipeline with a new version. The managed
Linux installer retains the prior release metadata and supports `install-mealy.sh rollback`.
Schema-changing rollback requires the separately approved migration-backup activation documented
in [RELEASE.md](RELEASE.md). Uninstall preserves the owner database. Back up and verify durable
state before upgrading, and use [OPERATIONS.md](OPERATIONS.md) for drain, safe mode, diagnosis,
backup/restore, retention, and incident recovery.

Retain the pull request, protected-main run, reviewed live-provider run, release run, generated
release notes, checksums, SBOMs, attestations, and clean-host job URLs as the audit chain for each
version. Never use a local dirty build or unreviewed provider probe as a substitute.
