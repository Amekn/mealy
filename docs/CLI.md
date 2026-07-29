# Command-line reference

`mealyctl` is the supported owner-facing client for Mealy's local authenticated API and
stopped-home configuration boundaries. The global form is:

```sh
mealyctl COMMAND [OPTIONS]
```

The default home is the stable private `$HOME/.mealy` directory, independent of the current
working directory. `--home` or `MEALY_HOME` overrides it for intentional alternative layouts; an
implicit home is rejected when `HOME` is absent, empty, or relative. Keep the selected location on
owner-private durable storage. Do not place the local bearer token or a provider credential
directly on a command line. Interactive onboarding securely prompts with terminal echo disabled
when its named provider variable is absent; automation and the lower-level `setup` command import
that variable. Both paths broker the value once and store only its opaque reference.

Run `mealyctl --help` for the current public surface and `mealyctl COMMAND --help` for the exact
arguments of one command. Protected CI compares that real help output with the table below, so a
public command cannot be added or removed without updating this reference.

## Public commands

| Command | Purpose |
| --- | --- |
| *(no subcommand)* | On an interactive terminal, onboard an unconfigured home or open a new chat for a configured home. |
| `onboard` | Configure one provider route, install/start the Linux owner service, and verify health and doctor. |
| `setup` | Initialize a clean stopped home and activate one bounded provider configuration. |
| `chat` | Start or resume the interactive durable conversation client. |
| `tui` | Open the full-screen canonical session workbench. |
| `session` | Create, submit to, inspect, search, or watch durable sessions. |
| `provider` | Inspect the active provider/model catalog and metadata provenance. |
| `task` | Inspect, cancel, pause, resume, or replay durable agent tasks. |
| `eval` | Validate or run versioned public-API scenario suites. |
| `delegation` | Inspect durable parent-to-child agent delegations. |
| `approval` | Inspect and resolve authenticated approval subjects. |
| `effect` | Inspect governed effects, dispatch attempts, and reconciliation evidence. |
| `memory` | Manage governed long-term memory, retrieval, export, and index rebuilding. |
| `compaction` | Create or inspect cited derived session compactions. |
| `extension` | Install, grant, invoke, upgrade, disable, or revoke isolated extensions. |
| `skill` | Inspect and manage stopped-home data-only skill bundles. |
| `registry` | Inspect and advance signed inert registry trust metadata while stopped. |
| `channel` | Configure and inspect webhook, Telegram, Discord, Slack, and exact-thread Slack continuation bindings. |
| `schedule` | Create, inspect, pause, resume, cancel, or audit recurring schedules. |
| `automation` | Create, edit, inspect, pause, resume, cancel, or audit one-shot and future-event automations. |
| `health` | Check daemon liveness. |
| `status` | Inspect queues, leases, providers, approvals, effects, channels, automations, and storage. |
| `metrics` | Emit stable machine-readable operational gauges. |
| `usage` | Emit exact settled terminal-run usage for a bounded trailing day range. |
| `doctor` | Diagnose control-plane, permission, and sandbox conformance. |
| `install-status` | Inspect install provenance, complete release integrity, rollback availability, and update ownership. |
| `update` | Verify a stable release target and optionally apply a same-schema archive update. |
| `update-status` | Inspect one durable disconnect-resistant update transaction. |
| `repair` | Verify and optionally restore owner-local installation-management evidence. |
| `rollback` | Verify and optionally exchange same-schema owner-local release slots. |
| `uninstall` | Verify and optionally remove program files while preserving durable state. |
| `completion` | Generate native Bash, Zsh, or Fish completion. |
| `dashboard` | Serve a temporary least-authority loopback dashboard. |
| `drain` | Close admission and begin bounded graceful daemon shutdown. |
| `backup` | Create an immutable complete online backup. |
| `restore-verify` | Restore into an isolated fresh home and verify without replacement. |
| `restore-activate` | Activate one exact verified encrypted backup while stopped. |
| `garbage-collect` | Erase only eligible unreferenced artifact files. |
| `export` | Publish an immutable owner-scoped evidence bundle. |
| `service` | Render/install or plan/remove an owner-level systemd user unit on Linux. |
| `config` | Inspect or change governed stopped-home configuration. |
| `media` | Explicitly activate or disable bounded stopped-home media capabilities. |
| `browser` | Explicitly activate or disable separately governed one-shot browser transactions. |
| `mcp-http` | Inspect and govern remote Streamable HTTP MCP catalogs, explicit read-only/idempotent/non-idempotent tool classes, OAuth login/activation/local revocation, and lifecycle. |

## Scenario evaluations

Validate a strict suite without a daemon, then run it through fresh authenticated public sessions:

```sh
mealyctl eval validate ./evaluation-suite.json
mealyctl --home "$HOME/.mealy" eval run ./evaluation-suite.json
```

`eval run` emits the complete digest-bearing report and exits nonzero after output when any case
fails. It never resolves approvals or exposes prompt/response bodies in the report. See the
[evaluation guide](EVALUATIONS.md) for the contract, safety/recovery composition, privacy limits,
and CI workflow.

## Optional semantic memory

Semantic retrieval is disabled until the owner stops the daemon and approves an exact
OpenAI-compatible embedding policy:

```sh
systemctl --user stop mealy.service
mealyctl --home "$HOME/.mealy" config memory-embedding \
  --base-url http://127.0.0.1:8080/v1 \
  --model nomic-embed-text \
  --dimensions 768 \
  --residency owner-host \
  --document-prefix 'search_document: ' \
  --query-prefix 'search_query: ' \
  --approve
systemctl --user start mealy.service
```

Non-loopback endpoints require HTTPS and paired `--secret-id` / `--credential-env` arguments; the
environment value is probed and imported once into the private broker. The command preserves the
replaced configuration, prints the non-secret policy digest, and requires explicit `--approve`.
Its compatibility probe is enabled by default. `--skip-connectivity-test` stages an unproved
policy rather than making it production-ready.

Build the complete derived set and request hybrid retrieval:

```sh
mealyctl --home "$HOME/.mealy" memory rebuild-index --semantic
mealyctl --home "$HOME/.mealy" memory search \
  --workspace WORKSPACE_IDENTITY --hybrid 'related meaning'
```

The response distinguishes actual hybrid retrieval from safe lexical fallback. Correction,
expiry, rejection, deletion, or active-revision drift marks the complete semantic set stale until
another approved rebuild. Stop the daemon and run
`mealyctl config memory-embedding-disable --approve` to disable future embedding calls while
retaining canonical memory and the separately managed broker credential. See
[the semantic-memory guide](SEMANTIC_MEMORY.md) for the privacy and recovery contract.

## Signed registry trust metadata

The v0.5 registry trust-bootstrap surface is deliberately local-file-only. First obtain an initial
root through an independently authenticated out-of-band path, retain its expected digest outside
the registry, and inspect the exact file without changing the Mealy home:

```sh
mealyctl registry root-inspect --root ./mealy-registry-root.json
```

Review `registryId`, `rootVersion`, `rootDigest`, `threshold`, every `keyId`, and the expiry. Mealy
can verify the root's internal structure but cannot decide whether the first key set belongs to
the registry you intended. After the matching Mealy daemon has initialized the current canonical
schema and is stopped, make that explicit trust decision:

```sh
mealyctl --home "$HOME/.mealy" registry root-add \
  --root ./mealy-registry-root.json --approve

mealyctl --home "$HOME/.mealy" registry status dev.mealy.registry
```

`root-add` refuses to initialize or migrate the canonical database. A prior release must first run
its normal backup-protected daemon migration. All state-dependent registry commands acquire the
same stopped-home lock as the daemon, so they fail while `mealyd` owns the home.

Root rotation accepts only an exact next-version envelope that independently satisfies the active
old threshold and the candidate new threshold:

```sh
mealyctl --home "$HOME/.mealy" registry root-rotate dev.mealy.registry \
  --envelope ./mealy-registry-root-rotation.json --approve
```

Inspect a threshold-signed snapshot against the active root and durable anti-rollback fence before
accepting that same no-follow file:

```sh
mealyctl --home "$HOME/.mealy" registry snapshot-inspect dev.mealy.registry \
  --envelope ./mealy-registry-snapshot.json

mealyctl --home "$HOME/.mealy" registry snapshot-accept dev.mealy.registry \
  --envelope ./mealy-registry-snapshot.json --approve
```

Exact root-rotation and snapshot replays are idempotent. Lower snapshot versions, different bytes
at an accepted version, expired metadata, wrong registry identities, missing signature thresholds,
and post-rotation root regression fail closed. Root files are capped at 128 KiB, rotation
envelopes at 256 KiB, and snapshot envelopes at 4 MiB; all are opened as nonempty no-follow regular
files. Output includes only key IDs and summary counts, not public-key bodies or signed metadata
payloads.

Root and file-based snapshot commands perform no DNS lookup or HTTP request. To retrieve the fixed
current snapshot from an owner-selected mirror and verify it without mutation:

```sh
mealyctl --home "$HOME/.mealy" registry snapshot-fetch dev.mealy.registry \
  --mirror https://registry.example.org/mealy/v1/
```

Review the same snapshot summary, then repeat through the approved atomic acceptance boundary:

```sh
mealyctl --home "$HOME/.mealy" registry snapshot-refresh dev.mealy.registry \
  --mirror https://registry.example.org/mealy/v1/ \
  --expected-envelope-digest DIGEST_FROM_SNAPSHOT_FETCH \
  --approve
```

`snapshot-fetch` prints the signed envelope identity as `state.envelopeDigest`. Refresh requires
that exact lowercase SHA-256, so a mirror update between review and apply fails without advancing
state; fetch and review the new summary before trying again.

The base must be a canonical HTTPS directory URL ending in `/`; credentials, query strings,
fragments, encoded/empty path segments, HTTP, loopback, private, link-local, documentation,
reserved, multicast, and otherwise non-public destinations fail closed. Mealy resolves once,
rejects the entire DNS answer if any address is non-public, pins that answer into TLS connection
establishment, and verifies the connected peer is in the pinned set. The client uses no proxy,
redirect, referrer, cookie, content decoding, or ambient credential path. It requests only
`metadata/snapshot.json`, accepts exactly HTTP 200 and the registry snapshot-envelope media type,
and retains at most 4 MiB under a five-second DNS deadline and five-minute HTTP deadline. The
shared resolver permits at most eight concurrent outstanding lookups, so a stuck operating-system
resolver cannot create unbounded threads. Signature, expiry, registry-identity, rollback, and
equivocation verification still run against the locally trusted root before output or acceptance.
The stopped-home lock remains held across retrieval and any commit, so the daemon cannot race the
reviewed state.

After accepting a snapshot, inspect one exact publisher release selected by that snapshot:

```sh
mealyctl --home "$HOME/.mealy" registry release-fetch dev.mealy.registry \
  dev.mealy.extension.clock 1.0.0 \
  --mirror https://registry.example.org/mealy/v1/
```

Review the publisher, host compatibility, exact dependencies, and manifest/archive descriptors,
then retain the same release as immutable inert evidence:

```sh
mealyctl --home "$HOME/.mealy" registry release-accept dev.mealy.registry \
  dev.mealy.extension.clock 1.0.0 \
  --mirror https://registry.example.org/mealy/v1/ \
  --expected-envelope-digest DIGEST_FROM_RELEASE_FETCH \
  --approve

mealyctl --home "$HOME/.mealy" registry release-status dev.mealy.registry \
  dev.mealy.extension.clock 1.0.0
```

Release fetch derives the immutable object path solely from the active signed snapshot. Both
review and acceptance require an unexpired snapshot under the active root; a root rotation
therefore requires a newly authorized snapshot before any release can be admitted. Acceptance
repeats snapshot, publisher threshold, withdrawal, dependency closure, host API, and exact
envelope verification inside an immediate schema 25 SQLite transaction. An exact replay is
idempotent, while the same registry/package/version can never alias different bytes.
`release-status` is offline and remains available for historical evidence after a later
withdrawal; that withdrawal blocks new acceptance.

Once release evidence is accepted, fetch and strictly inspect its exact manifest and package:

```sh
mealyctl --home "$HOME/.mealy" registry package-fetch dev.mealy.registry \
  dev.mealy.extension.clock 1.0.0 \
  --mirror https://registry.example.org/mealy/v1/
```

`package-fetch` requires the release to remain selected and unwithdrawn by the current unexpired
snapshot under the active root. It retrieves only the manifest and archive objects addressed by
that release's signed SHA-256 descriptors. Output presents the exact manifest/archive digests,
complete file inventory, executable flags, and requested extension authority or separately
governed skill/tool references. It writes no package bytes and creates no grant. After reviewing
that output, retain those exact inert bytes with a second digest-fenced decision:

```sh
mealyctl --home "$HOME/.mealy" registry package-stage dev.mealy.registry \
  dev.mealy.extension.clock 1.0.0 \
  --mirror https://registry.example.org/mealy/v1/ \
  --expected-archive-digest DIGEST_FROM_PACKAGE_FETCH \
  --approve
```

`package-stage` repeats the complete fetch and inspection path, then rechecks the active root,
current unexpired snapshot, selected publisher release, withdrawal state, host compatibility,
manifest/archive identities, and exact byte counts inside schema 26's immediate transaction. The
manifest and archive are published atomically into Mealy's private content-addressed artifact
store before their immutable evidence row is committed. An exact replay is idempotent. If the
database commit loses a race or fails, the unreferenced content remains inert and is eligible for
the existing age-gated artifact garbage collector; it cannot become installed authority.
Content-addressed package blobs are included in the established backup, restore, migration-copy,
integrity, and orphan-accounting paths.

For a staged skill or extension, compare its exact content and requested authority with the
currently installed revision:

```sh
mealyctl --home "$HOME/.mealy" registry package-plan dev.mealy.registry \
  dev.mealy.skill.review 1.0.0
```

The offline plan rereads and verifies both staged blobs, requires the release to remain authorized
and unwithdrawn, and reports install/update/evidence-adoption intent, prior status and digest,
instruction/resource changes, exact added/removed governed-tool references, whether authority
widens, and whether applying an update will remove active authority. Extension plans include the
analogous capability, filesystem, network, secret, process, executable, and runtime-file diff.
The canonical plan material is returned as `planDigest`; it binds the staged publisher evidence
and the exact current installation.

Apply one unchanged reviewed skill plan:

```sh
mealyctl --home "$HOME/.mealy" registry package-install dev.mealy.registry \
  dev.mealy.skill.review 1.0.0 \
  --expected-plan-digest DIGEST_FROM_PACKAGE_PLAN \
  --approve
```

Apply repeats the active-root/snapshot/release/withdrawal checks, staged-blob integrity inspection,
and complete install-plan calculation under the stopped-home lock. A digest mismatch changes
nothing. A new skill is published through the existing immutable skill store and configured
disabled. An update or rollback retains prior immutable revisions, replaces the configured
revision, and removes prior instruction authority by leaving the candidate disabled. If identical
locally installed bytes lack registry provenance, evidence adoption preserves their current
enabled/disabled state. The signed registry, release, and archive identities are retained in
non-secret skill configuration. Skill enablement remains the separate existing
`skill enable --expected-manifest-digest ... --approve` decision, and required tools remain
references rather than grants.

Extensions use the same command with the extension package ID and version. Mealy atomically
publishes only the authenticated manifest and executable beneath the private
`extensions/registry/MANIFEST_DIGEST` directory, re-inspects the result through the established
extension-host boundary, and executes nothing. Schema 27 binds the exact registry, release,
manifest, archive, and extension-revision identities. A new extension is installed without a
grant. An update, rollback, or identical-byte evidence adoption creates a retained revision,
switches to the registry-published root, removes any prior grant, and leaves the extension
disabled. Start the daemon, inspect the resulting extension, and use the existing digest/revision
fenced `extension enable` command with an explicit least-authority grant when ready.

The application transport also derives immutable release/manifest/archive paths only as
`objects/sha256/DIGEST` from already signed descriptors and checks exact media type, length, and
SHA-256 before parsing. The package inspector accepts only uncompressed deterministic USTAR with
two exact zero trailer blocks, regular files, canonical UTF-8 relative paths, zero owner/group/time,
mode `0644` for data and `0755` only for the declared extension executable, zero padding, and an
inventory exactly equal to `manifest.json` plus declared content. It rejects links, devices,
FIFOs, sparse/PAX/GNU extensions, duplicates, undeclared files, traversal, non-canonical metadata,
and trailing content. It parses and retains bytes in memory rather than invoking a tar extraction
API, so inspection cannot create filesystem paths or race an extraction destination.

No registry command activates an extension or skill, automatically discovers a mirror, or grants
a tool or requested permission. `package-install` supports both package classes and always uses
the existing disabled-by-default lifecycle for new or changed bytes. `skill status` and `skill list` include
`registryPolicy` for provenance-bound revisions and distinguish configured `enabled` from actual
`instructionAuthorityActive`. The projection compares the exact accepted
release and staged manifest/archive identities with the newest accepted snapshot. Explicit
withdrawal, target removal, package/version substitution, or missing/mismatched evidence blocks
`skill enable`; an already configured revision is suppressed from runtime instruction context on
the next daemon start. The same projection runs before every registry extension enable and
invocation, so an enabled extension cannot resume after restart under a withdrawn, removed,
substituted, or evidence-incomplete revision. Mealy retains immutable installed bytes and registry
history so the owner can inspect, install a reviewed replacement, or use the same exact-version
rollback flow. Snapshot expiry still blocks new admission but does not alone deactivate an offline
installation. Registry publication tooling remains a later v0.5 boundary.

For everyday conversation, plain `chat` creates a new durable session, `chat --continue` (or
`chat -c`) resumes the most recently updated session for the exact local binding, `chat --pick`
interactively selects one of the 20 newest exact-binding sessions, and `chat --session-id
SESSION_ID` selects a specific older session for scripts. The picker shows the bounded owner title
when one exists and otherwise a deterministic title derived from the first canonical owner input,
plus status, relative recency, queued input count, and active-turn state without creating a
session. An empty session is titled `New conversation`. Derived titles make no provider call.
`--continue` and `--pick` never silently create a session when there is no history.

For the full-screen interface, run:

```sh
mealyctl --home "$HOME/.mealy" tui
mealyctl --home "$HOME/.mealy" tui --new
mealyctl --home "$HOME/.mealy" tui --session-id SESSION_ID
```

Plain `tui` selects the newest exact-binding session and creates one only when no session exists.
`--new` and `--session-id` are mutually exclusive. The workbench is a bounded thin client: the
daemon remains authoritative for sessions, transcripts, timelines, approvals, checkpoints, forks,
and admission. It shows the verified canonical transcript, provider/model/context/price status,
queued and active work, structured recent event/tool evidence, and exact pending approvals.

Use `Tab`/`Shift-Tab` to move among panes, arrow keys or `j`/`k` to navigate, `/` from the session
pane to search canonical user/final-assistant text, and `Enter` to admit the composer content.
`F2` renames, `F3` checkpoints, `F4` creates a checkpoint and forks it, `F5` refreshes, `F6`
creates a verified private JSON transcript, `Shift-F6` creates inert HTML, and `F7` reviews an
exact approval subject before `a` approves or `d` denies. `F1` displays the complete in-product
key map. `F8` opens the active model catalog: `Enter` changes this conversation's default for
future turns, while `t` pins only the next submitted turn. `Ctrl-C` cancels a stalled foreground
request, restores the terminal, and exits.

The workbench requires terminal stdin, stdout, and stderr and fails before session creation when
that boundary is absent. Input is capped at the daemon's 1 MiB admission limit; remote text and
structured previews are bounded and control-safe. Normal exit, Ctrl-C, persistent daemon loss,
resize, initialization failure, and panic all use terminal restoration. `mealyctl chat` remains
the accessible line interface, while `session` commands remain the automation interface.

Rename a conversation or capture/list immutable resumable boundaries with:

```sh
mealyctl --home "$HOME/.mealy" session rename SESSION_ID "Release planning"
mealyctl --home "$HOME/.mealy" session checkpoint create SESSION_ID --label "Before refactor"
mealyctl --home "$HOME/.mealy" session checkpoint list SESSION_ID --limit 20
mealyctl --home "$HOME/.mealy" session fork SESSION_ID CHECKPOINT_ID
mealyctl --home "$HOME/.mealy" session export SESSION_ID --format json \
  --output ./release-planning.json
mealyctl --home "$HOME/.mealy" session export SESSION_ID --format html \
  --output ./release-planning.html
```

When `--expected-revision` is omitted, the client fetches current session status immediately
before the mutation. Automation can pass the exact revision explicitly. A concurrent change then
fails with a conflict rather than overwriting newer state. Checkpoint creation requires no pending
input or active turn and rejects a failed/cancelled latest canonical turn. Owner titles and labels
are trimmed, terminal-safe, at most 72 characters and 160 UTF-8 bytes.

`session fork` prints the generated idempotency key before dispatch so an ambiguous request can be
retried exactly. The returned session starts with fresh operational state and references only
bounded, immutable source conversation evidence that passes current context and authority checks.
It never reuses source approvals, effects, leases, reservations, schedules, or child state.

`session export` defaults to JSON and otherwise writes inert self-contained HTML. It verifies the
daemon-provided digest and transcript structure before creating a new owner-only file, refuses to
overwrite an existing path or follow a symlink, and prints a bounded JSON receipt. Transcript text
is verbatim owner-visible evidence, so protect the file if the conversation contains a pasted
secret. The dashboard exposes the same title, checkpoint, fork, and verified export operations
through its fixed loopback allowlist without exposing the daemon bearer. It also exposes the same
catalog and provider-selection contracts for new sessions, conversation defaults, and one-turn
overrides.

Inspect and select only routes already present in the daemon's active configuration:

```sh
mealyctl --home "$HOME/.mealy" provider catalog

mealyctl --home "$HOME/.mealy" session create \
  --provider-id openrouter.responses --model-id vendor/model:free

mealyctl --home "$HOME/.mealy" session provider set SESSION_ID \
  --provider-id local.responses --model-id local-model

mealyctl --home "$HOME/.mealy" session provider set SESSION_ID --automatic

mealyctl --home "$HOME/.mealy" session send SESSION_ID "Compare the evidence." \
  --provider-id openrouter.responses --model-id vendor/model:free

# Review only: promote one already-configured compatible route to primary.
mealyctl --home "$HOME/.mealy" provider switch \
  --provider-id local.responses --model-id local-model

# Apply the exact reviewed plan through the independent Linux service helper.
mealyctl --home "$HOME/.mealy" provider switch \
  --provider-id local.responses --model-id local-model --approve

mealyctl --home "$HOME/.mealy" provider switch-status TRANSACTION_ID
```

`session provider get SESSION_ID` returns the canonical default and revision. Omitting a selection
from `session send` inherits that default; `--automatic` explicitly overrides an exact default for
that turn. Admission durably pins the resolved identity before queue acknowledgement. Exact
selection disables implicit fallback for that turn, although a classified retry may reuse that
same exact endpoint. Selection changes affect only future new turns and never rewrite queued,
active, or completed work.

The initial v0.4 image-input surface is scriptable API/CLI only. Stop the daemon, review that every
primary/fallback route is a direct OpenAI Responses or Anthropic Messages route, and activate it
explicitly:

```sh
mealyctl --home "$HOME/.mealy" media image-input --enable --approve

# Restart the daemon, then submit one to four exact local images.
mealyctl --home "$HOME/.mealy" session send-image SESSION_ID ./screen.png ./detail.webp \
  --prompt "Compare these screenshots." \
  --provider-id local.responses --model-id local-vision-model

# Disable while the daemon is stopped.
mealyctl --home "$HOME/.mealy" media image-input --disable --approve
```

`session send-image` requires an exact activated provider/model route. It opens only no-follow
regular `.png`, `.jpg`, `.jpeg`, or `.webp` files outside the Mealy home, rejects empty or
unsupported input, caps each source at 2 MiB and the ordered source set at 4 MiB, and sends bytes
only to the daemon's isolated normalizer. It does not send a filename or host path to the model.
One to four source images are normalized to canonical owner-private artifacts and returned in
`imageArtifactIds`.

When the command generates its delivery key and UUIDv7 artifact IDs, it prints
`MEALY_IDEMPOTENCY_KEY` and one `MEALY_IMAGE_ARTIFACT_ID` line per image before the request. After
an ambiguous client failure, retry with the exact printed values using `--idempotency-key` and one
`--artifact-id` per path in the original order. Reusing a key or artifact ID with different
evidence fails closed. TUI, dashboard, chat-native, and channel image attachment/rendering are not
enabled by this command.

Image generation is a separate high-risk capability. While the daemon is stopped, enable one exact
adapter and optionally import its credential from a one-shot environment variable into the private
broker:

```sh
export OPENROUTER_API_KEY='replace-with-your-key'
mealyctl --home "$HOME/.mealy" media image-generation --enable \
  --protocol open-router-images \
  --provider-id openrouter.images \
  --base-url https://openrouter.ai/api/v1 \
  --model 'OWNER_VERIFIED_IMAGE_MODEL:free' \
  --residency openrouter \
  --secret-id openrouter-images \
  --credential-env OPENROUTER_API_KEY \
  --size 1024x1024 \
  --quality low \
  --maximum-cost-microunits 50000 \
  --maximum-output-bytes 2097152 \
  --timeout-ms 120000 \
  --approve
unset OPENROUTER_API_KEY

# Disable while stopped; the brokered key remains until explicitly unreferenced and revoked.
mealyctl --home "$HOME/.mealy" media image-generation --disable --approve
```

Use `open-ai-images` with an OpenAI-compatible `/v1` base, including a credential-free literal
loopback server. Reuse an existing broker entry by supplying `--secret-id` without
`--credential-env`. The command validates and archives the complete prior configuration but
deliberately performs no generation probe: probing is itself potentially billable and
non-idempotent. For OpenRouter under a free-only policy, independently verify that the exact
image-output model ends in `:free` and still reports zero prices immediately before activation;
do not substitute a moving paid alias.

The agent sees only `image.generate` with one prompt. Every invocation parks for exact local owner
approval after reserving the configured cost/output ceilings. Denial makes no provider request.
An interrupted dispatch is never retried and becomes `outcome_unknown`; inspect it with
`effect status` and reconcile only from external evidence. A confirmed output is normalized to a
private canonical JPEG and identified by an artifact ID in the tool observation. Retrieve it
through the authenticated artifact metadata/content API. TUI/dashboard/channel previews and image
edits are not enabled by this backend command.

Transactional browser authority is separate from installing or enabling the default read-only
browser. With the daemon stopped, activate or remove it explicitly:

```sh
mealyctl --home "$HOME/.mealy" browser --enable-transactions --approve
mealyctl --home "$HOME/.mealy" browser --disable-transactions --approve
```

Exactly one of `--enable-transactions` or `--disable-transactions` is required, and `--approve` is
mandatory. Enabling fails unless the content-pinned read browser and its governed web authority are
already valid. It publishes no broad origin approval: every `browser.transact` proposal still
parks for exact authenticated owner review. Disable retains the installed read browser and its
immutable bundle. Read-browser disable is rejected until the separate transaction switch is
disabled; terminal browser revoke removes both authorities. Read-browser re-enable does not
silently restore transactions.

`provider switch` is different from scoped selection: it changes which compatible configured
route automatic routing prefers. Without `--approve`, it emits a non-mutating
`mealy.provider-switch-plan.v1`. Approved apply is supported only for a verified production Linux
installation whose active `mealy.service` exactly binds this home and daemon. A private,
digest-bound helper probes the selected route, drains the daemon, atomically promotes it, restarts
the service, and requires liveness, readiness, `doctor`, config-digest, route-count, and exact
primary-identity agreement. Failure before activation aborts; failure after activation restores
the exact prior configuration and requalifies it. `switch-status` reads the durable transaction
after terminal or client disconnection. Transactional switching accepts brokered credentials,
credential-free literal-loopback endpoints, and the official subscription client; it rejects
environment-only credential references because an independent recovery helper cannot safely
inherit the caller's shell secret.

The switch only reorders the complete existing validated route chain. Adding/removing a route or
changing an endpoint, model, credential, price, locality, or residency remains a stopped-daemon
`config` operation. Chain validation may also reject a promotion that would leave a weaker-trust
fallback behind the new primary.

Most non-interactive commands emit one bounded JSON value on standard output and diagnostics on
standard error. Scripts should validate `apiVersion`, named fields, and the process exit status;
they must not infer success from human-readable text. `chat`, `tui`, `dashboard`, setup approval prompts,
and selected pairing flows are intentionally interactive unless their documented explicit flags
choose a bounded non-interactive path.

## Common workflows

- Follow [getting started](GETTING_STARTED.md) for verified installation, one-command onboarding,
  and the first chat.
- Follow the [quickstart](QUICKSTART.md) for detailed provider activation, first
  conversation, skills, tools, channels, schedules, and delegation.
- Follow [durable automation](AUTOMATION.md) for one-shot prompts, future-event notifications,
  revision-fenced edits, crash recovery, and delivery boundaries.
- Follow [exact-thread remote continuation](REMOTE_CONTINUATION.md) to pin, inspect, use, expire,
  or revoke proactive Slack notification routes.
- Use the [operations guide](OPERATIONS.md) for health, metrics, drain, backup/restore, retention,
  service management, upgrades, and incidents.
- Use the [local API reference](API.md) when building a direct client rather than invoking
  `mealyctl`.
- Use the [release guide](RELEASE.md) for attestation verification, installation, rollback, and
  uninstall of published packages.

Commands that mutate stopped-home configuration require the daemon lock to be free and normally
require exact explicit approval. Commands against a running daemon authenticate through the
owner-only `connection.json`. Safe mode and drain intentionally reject ordinary mutations; consult
the command's JSON error and retryability contract instead of bypassing those states.

## Interactive chat status

Bare `mealyctl` is the ordinary terminal entry point: it selects `onboard` only when
`config.json` is absent and otherwise selects a new `chat`. It requires interactive stdin,
stdout, and stderr; non-terminal callers fail without mutation and must name `onboard`, `chat`, or
another exact subcommand. It never follows a `config.json` symlink while deciding the journey.

`mealyctl chat` prints a concise status block before the first prompt.
`/status` refreshes the same authenticated projection without leaving the conversation. It shows
the effective provider and model, process-lifetime health, locality/residency, context and maximum
response tokens, conservative provider-owned input overhead, exact configured input/output prices,
admission/safe-mode state, queue pressure, and every primary/fallback route's concurrency and
current-minute pressure.

Prices and settled task cost remain provider-neutral integer microunits; Mealy does not infer an
invoice or silently label an owner-configured currency. After every terminal task, chat prints the
recorded input/output tokens, cost microunits, model calls, tool calls, and retries. These values
come from durable task evidence and are not estimates of the model's remaining context window.
Changing the configured route set or credentials still uses the stopped-daemon configuration
transaction. Scoped session/turn selection never changes the configured primary. Promoting one
already-configured compatible automatic route uses `provider switch`; its drain/restart boundary
preserves immutable identity for every in-flight turn.

## Installation status and completion

`mealyctl install-status` is offline and emits `mealy.install-status.v1`. A published installation
is reported as healthy only after every checksum-declared file—including both binaries, the stable
manager inputs, the release bootstrap, documentation, SBOM, and license notices—has been read as a
bounded no-follow regular file and matched its release digest. It distinguishes owner-local archive
slots from Debian, RPM, and Arch package ownership. Source builds and unknown layouts never acquire
a mutating update backend.

`mealyctl update` performs a no-mutation check by default. The bundled,
release-digest-bound bootstrap downloads the selected stable release, verifies its exact hosted
GitHub Actions provenance from the tag, verifies the complete outer checksum inventory, and reads
the target manifest from the attested archive. The resulting `mealy.update-plan.v1` identifies the
current and target versions and state schemas.

An owner-local archive update may be applied with `--approve` only when the target is strictly
newer, uses the exact active state schema, and the running `mealy.service` definition exactly owns
the verified binary and home. The foreground command records a `mealy.update-transaction.v1`
request, prints its UUID, and launches a separate restart-on-failure user-service helper. That
helper is a private digest-pinned copy of the qualified old client, so restart cannot resolve
through an unqualified candidate. It independently re-verifies the candidate, creates an immutable
backup, drains the daemon,
activates the retained-slot update, starts the service, and requires liveness, readiness,
`doctor`, target version/commit, and complete installed integrity before commit. Failed
qualification automatically restores and verifies the prior same-schema slot. Terminal
disconnect does not cancel the helper; inspect its durable phase with:

```sh
mealyctl update-status TRANSACTION_UUID
```

`aborted` means verification failed before program mutation and the prior service still qualified;
`rolled-back` means the prior slot was restored and qualified after mutation began;
`recovery-failed` leaves evidence and the safest established slot in place for inspection.

A target with a different state schema is deliberately refused by this convenience path and must
use the staged migration procedure in the [release guide](RELEASE.md). Debian, RPM, and Arch
installations always retain native package ownership; the plan reports the exact `apt`, `dnf`, or
`pacman` handoff and never writes `/usr`.

`repair`, `rollback`, and `uninstall` also plan without mutation unless `--approve` is present.
Repair can reconstruct a missing or modified stable archive manager only from the checksum-verified
active metadata copy; it cannot repair around a changed binary or manifest. Rollback delegates only
when both complete archive slots verify, and the stable manager independently refuses a backward
state-schema transition. Uninstall removes managed program files only and always preserves the
complete Mealy home. Drain and stop the owner service before rollback or uninstall. Native packages
return the exact `apt`, `dnf`, or `pacman` repair/uninstall command so `/usr` remains under the
distribution package database.

Generate completion without starting the daemon or reading private state:

```sh
# Bash
mealyctl completion bash >"$HOME/.local/share/bash-completion/completions/mealyctl"

# Zsh
mealyctl completion zsh >"$HOME/.local/share/zsh/site-functions/_mealyctl"

# Fish
mealyctl completion fish >"$HOME/.config/fish/completions/mealyctl.fish"
```

## Onboarding routes

`mealyctl onboard` is the ordinary clean-install path. It prompts for one of
six explicit routes: `openrouter-free`, `custom`, `local`, `chatgpt-subscription`,
`openai-api`, or `anthropic-api`.

The OpenRouter route fetches the live account catalog and admits only tool-capable text models
whose exact ID ends in `:free`, whose context/output limits are complete, and whose posted
input/output plus auxiliary prices are exactly zero. Custom and official API routes import a
credential from the named environment variable when present. When it is absent and stdin/stderr
are terminals, onboarding reads the credential once through an echo-disabled bounded prompt,
restores the terminal before continuing, and brokers the value without printing it. Non-terminal
automation fails before mutation unless the variable is set. The local route requires a
literal-loopback endpoint and no credential. The ChatGPT subscription route pins and live-probes
the installed official Codex executable without extracting its subscription credential. Through
the documented Codex app-server protocol it reads only coarse account state, asks for separate
terminal consent before a required sign-in, and displays either the official browser challenge or
the headless `--chatgpt-login device-code` challenge. Non-terminal signed-out use fails before
login or home mutation. The route selects the unique account-catalog default; `--model` must name
an exact visible or hidden account-catalog entry. Its Mealy context ceiling remains a conservative
128,000 tokens unless `--context-tokens` is explicit.

The lower-level stopped-home `config provider-subscription-openai` command does not manage login
or query the catalog. It requires an existing official Codex ChatGPT session and retains the
maintained `gpt-5.6` model alias and conservative 128,000-token defaults unless explicitly
overridden. If Codex is absent or cannot be inspected safely, both paths fail before mutation and
point to the [official Codex CLI installation guide](https://learn.chatgpt.com/docs/codex/cli);
Mealy does not download or execute that external installer.

The retired `claude-subscription` alias and `config provider-subscription-claude` command remain
recognizable only to give existing scripts an actionable error. They fail before home mutation or
client invocation because Anthropic prohibits third-party routing of Free, Pro, and Max
subscription credentials. Supported alternatives are `anthropic-api`, `openrouter-free`, a
`custom` endpoint, or Claude Code itself.

Before mutation, onboarding prints a non-secret provider digest and its service action, then
requires the exact word `APPROVE` unless `--approve` was given. A pre-existing configuration is
rejected unless `--reconfigure` explicitly acknowledges replacement while the daemon is stopped.
The normal Linux path installs and starts `mealy.service`, waits up to 30 seconds, and requires
liveness, control-plane readiness, and an available sandbox. On an interactive terminal it then
opens a new durable chat by default. `--chat` forces that transition, while `--no-chat` retains
machine-readable onboarding output and prints the exact chat command. `--configure-only`
deliberately stops after provider activation and reports the exact service-install command as the
next step; it cannot be combined with `--chat`.
`--skip-connectivity-test` requires that configure-only mode, preventing a staged provider from
being reported as a verified running onboarding result.

`mealyctl --home "$HOME/.mealy" service remove` emits a no-mutation
`mealy.service-removal.v1` plan for the loaded or default unit. `--approve` is accepted only when
the exact generated definition still binds its recorded daemon and this home. For a custom linked
unit, the plan records both the canonical definition and systemd's loader-visible link. Apply
disables and stops the unit, proves the home lock is free, re-verifies both identities and the
definition bytes, removes the loader link and definition, and reloads the user manager without
deleting the home. An approved owner-local archive `uninstall` composes this exact cleanup before
removing program files. Native package handoffs leave it as an explicit owner step.
