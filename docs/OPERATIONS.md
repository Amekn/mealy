# Operations

Mealy's release-one control plane is a single owner-private home, one `mealyd` process, an
authenticated loopback API, and `mealyctl`. Operational commands use the same authorization and
bounded blocking pool as normal clients; they do not bypass canonical state.

An owner can admit a local text file without copying its host path into durable state:

```sh
mealyctl --home "$HOME/.mealy" session send-file SESSION_ID ./report.md \
  --prompt "Review this untrusted report."
```

The interactive equivalent is `/attach ./report.md` at the `mealyctl chat` prompt. It uses a fixed
safe prompt and queues normal work; the complete remainder is the path, so spaces are accepted.

The CLI opens a no-follow regular file, caps exact UTF-8 bytes at 256 KiB, allowlists text/source
extensions, records basename/media/size/SHA-256 in an untrusted frame, and then uses normal durable
input/idempotency/delivery behavior. Treat the bytes as prompt-visible durable data; never select a
credential file. Host paths, symlinks, arbitrary binary data, images, audio, and video are not
admitted by either text-attachment form.

The separate v0.4 image API/CLI surface defaults off. It may be changed only while the daemon is
stopped and only when every configured route is direct OpenAI Responses or Anthropic Messages:

```sh
mealyctl --home "$HOME/.mealy" media image-input --enable --approve
mealyctl --home "$HOME/.mealy" session send-image SESSION_ID ./screen.png \
  --provider-id local.responses --model-id local-vision-model
```

Restart the service after changing the setting. Image turns require an exact image-capable route.
The CLI accepts one to four no-follow PNG/JPEG/WebP files outside the Mealy home, bounded to 2 MiB
each and 4 MiB total. Preserve the generated delivery/artifact IDs until receipt so an ambiguous
admission can be retried exactly. The daemon normalizes in a fresh no-network worker, stores only
canonical owner-private artifacts, and exports path-free metadata. Chat/TUI/dashboard/channel
image upload/rendering remains unavailable. See the
[CLI reference](CLI.md) for the complete retry contract.

The separate `media image-generation` transaction enables or disables one exact OpenAI Images or
OpenRouter Images backend while the daemon is stopped. Enablement pins the provider/model,
protocol/origin, broker secret reference when remote, residency, JPEG/size/quality, maximum
cost/output, and deadline, archives the prior complete configuration, and requires `--approve`.
It performs no connectivity probe because generation can be billable and non-idempotent. Restart
the service and run `doctor` after the change.

Every generated image requires a new exact local approval and immutable cost/output reservation.
Denial sends nothing. A crash or transport ambiguity after dispatch is never retried; it appears as
`outcome_unknown`, is conservatively charged to the full approved maximum, and requires external
provider evidence plus the normal revision-fenced `effect reconcile` workflow. Confirmed output is
isolated-normalized to a canonical private JPEG before atomic artifact/effect/usage settlement.
Use the authenticated artifact API for retrieval. Client previews, edits, masks, reference inputs,
multiple outputs, and provider fallback remain disabled in this slice. The complete setup command,
including a free-only OpenRouter warning, is in the [quickstart](QUICKSTART.md).

For an owner-local interactive overview, run `mealyctl --home "$HOME/.mealy" dashboard` and open the
printed `127.0.0.1` URL. The foreground command must remain running. It preflights status, doctor,
recent sessions, pending approvals, schedules, and a bounded 30-day usage report, then exposes only fixed typed routes for that
snapshot, session creation/input, a 200-event timeline page, exact approval resolution, and
cooperative task cancellation. Exact effect and attempt queries are also available, and one fixed
command reconciles a linked `outcome_unknown` pair only from the inspected effect revision, an
explicit `succeeded`/`failed` conclusion, and a non-empty external-evidence object capped at the
canonical 32 KiB bound. Input is limited to 16 KiB; input, approval, cancellation, and
reconciliation use stable idempotency keys. Fixed schedule routes additionally expose keyed
creation, an exact definition, 1–100 newest occurrence rows, and revision-fenced
pause/resume/cancel. The browser proposes a canonical UUIDv7 schedule identity and retains the
exact identity/immutable definition across an ambiguous manual retry. Canonical storage returns an
existing exact definition without a second creation event and conflicts on different semantics.
Schedule lifecycle commands are not automatically retried: the page re-reads status after
ambiguity, and a response is accepted only for the same schedule, requested terminal status, and
revision +1. Governed-memory routes separately provide exact namespace
list/search/detail, digest-bound proposal, explicit exact-revision owner-approved activation,
correction, pin/unpin, expire, reject, and delete/scrub. Existing-record changes are optimistic
revision transitions. Proposal and correction derive a stable hashed owner provenance locator from
the browser command key and pair it with the exact content digest; a manual retry reconciles that
locator before any write. Proposal never implies activation. The UI accepts at most 48 KiB of
memory content and never accepts caller-selected provenance locators. There is no arbitrary proxy or general
configuration/credential route.

The read-only 30-day report is exact-owner scoped and includes root, delegated, and validation
runs through durable root lineage. It accepts at most 31 days, groups only terminal runs by UTC
completion day, attributes a run's complete settled usage to that day, omits empty days, and fails
closed if any terminal run retains an active reservation. It reports runs, calls, delegation,
retries, tokens, output bytes, and configured-price cost microunits. The first UTC bucket may begin
before a mid-day lower bound, but contains only runs whose completion time lies inside the exact
inclusive/exclusive request range.

For scripts or a terminal-only host, request the same canonical report without exposing or copying
the daemon bearer:

```sh
mealyctl --home "$HOME/.mealy" usage --days 30
```

`--days` accepts 1 through 31. Output is the versioned JSON report with exact `fromMs`, `toMs`, and
ordered non-empty UTC buckets.

An Origin-checked task-usage route fetches one exact owner-authorized task and renders its canonical
budget ledger: used and reserved provider/tool/delegation calls, retries, input/output tokens,
output bytes, and provider-neutral cost microunits. Numeric values are rejected above JavaScript's
exact-integer ceiling, final-response content is digest checked, criteria/validation identity is
validated, and a terminal task must have zero active reservations. These values are Mealy's durable
configured price snapshot, not a provider invoice; operators must not infer unsupported charge,
tax, credit, media, cache, search, or reasoning axes from them.

Fixed extension routes expose at most 1,000 owner extensions and 1,024 manifest-history entries per
extension, with complete data-only manifest, health, and active-grant projections. Inventory and
detail are strict Origin-checked POSTs. Enable prefetches the exact extension/revision, proves each
selected capability, filesystem mapping, network destination, opaque secret reference, and process
flag is a subset of the current manifest, and accepts only an enabled revision +1 response carrying
that exact grant after a successful health check. Disable and terminal revoke are also revision
fenced. An identical already-completed transition is returned without another mutation; other
ambiguity requires a re-read. Package install/stage, installation roots, upgrades, and arbitrary
invocation remain CLI-only. Secret references are names, never values.

Reconciliation evidence is durable operational state. Record only the minimum secret-free receipt,
digest, timestamp, and operator observation needed to justify the conclusion; never paste a
credential, bearer token, private key, or unrelated file content into the dashboard evidence box.
Governed-memory content is also durable owner state: use credential references, never raw secrets,
and review namespace, category, sensitivity, retention, content digest, sources, and revision before
typing an activation or deletion confirmation.

The dashboard re-reads the owner-private connection descriptor for every request so it can follow
an orderly daemon restart. A malformed descriptor or invalid backend response returns a generic
unavailable state without browser-visible paths, bearer credentials, or daemon error bodies. Exact
numeric Host, a separate 256-bit browser capability, exact Origin on mutations, a 64 KiB body cap,
strict response headers, canonical UUID parsing, separate bounded detail reads, and one concurrent
write fail closed. Daemon JSON and error bodies are streamed under an 8 MiB ceiling before decode.
Ctrl-C
destroys the random listener and browser capability. Do not bind, tunnel, or reverse-proxy it beyond
the owner-local loopback boundary.

## Install and start

Follow [`QUICKSTART.md`](QUICKSTART.md) to install the pinned Rust toolchain, Linux Bubblewrap
prerequisite, and stable release binaries before using the commands below. Tagged package
verification, clean install, upgrade, and binary/schema rollback boundaries are in
[`RELEASE.md`](RELEASE.md).
The owner-local archive provides active/previous rollback slots; the root-owned Debian, RPM, and
Arch packages provide ordinary system-package-manager install/upgrade/remove without maintainer
scripts, install hooks, or home mutation. No package form starts the daemon or creates a service
during installation.

On a clean home, activate one provider before starting the service:

```sh
export OPENAI_API_KEY='replace-with-your-api-key'
mealyctl --home "$HOME/.mealy" setup
unset OPENAI_API_KEY
```

The wizard holds the stopped-home lock, writes the shared typed default configuration atomically,
reviews a non-secret provider-config digest, requires exact approval, runs the normal bounded
provider probe, brokers the credential, and prints the next start/doctor/chat commands. A denied
review creates no config or broker state. Probe failure can leave only the safe builtin default
home so setup is retryable; it never publishes the proposed provider or credential. Never use
`--skip-connectivity-test` as production connectivity evidence.

Personal ChatGPT subscriptions never use the API-key broker. The ordinary
`onboard --route chatgpt-subscription` journey asks the official Codex app-server for coarse
account state and the account-visible model catalog. If Codex is signed out or uses another login
mode, an interactive terminal discloses the shared-account change and requires separate consent
before starting an official browser flow; `--chatgpt-login device-code` selects the headless flow.
The login wait is bounded to five minutes. A non-terminal caller cannot start login, and declining
starts no login and changes no Mealy home. Mealy retains no email, account ID, OAuth/session
material, challenge, or broker identity.

Onboarding selects the unique account-catalog default; explicit `--model` must exactly match a
catalog entry. The lower-level stopped-home `config provider-subscription-openai` command assumes
an already ChatGPT-authenticated Codex client and retains the maintained `gpt-5.6` default for
automation. Activation pins the canonical executable path and SHA-256 and runs a bounded no-tools
connectivity probe. Mealy never passes provider API-key variables to Codex. A client upgrade or
expired login requires owner-local reactivation. This bridge is suitable only for the owner's
signed-in machine; use a brokered API key or private endpoint for unattended service accounts and
release acceptance.
Activation expands the per-call deadline only to the declared subscription routing estimate and
only within the existing total run wall-time. Official-client-added input tokens are represented by
a conservative capability allowance and included in the durable reservation and replay evidence.

The legacy Claude subscription provider is retired and fails validation before process dispatch.
Anthropic prohibits third-party products from routing Free, Pro, or Max subscription credentials.
To migrate an old stopped home, activate `provider-anthropic`, strict-free OpenRouter, or a custom
endpoint before restarting the service. Claude Code remains available as its own official product.

Run directly:

```sh
mealyd --home "$HOME/.mealy"
```

Or install an owner-level service definition:

```sh
mealyctl --home "$HOME/.mealy" service install
mealyctl --home "$HOME/.mealy" service remove
mealyctl --home "$HOME/.mealy" service remove --approve
```

The installer atomically writes an owner-private systemd user unit on Linux and prints the explicit
activation command. Reinstalling first preserves a `.previous`
rollback copy. Unsupported service-manager platforms fail explicitly instead of emitting a weaker
unit. The daemon itself remains portable; arbitrary worker execution is separately fail-closed by
the sandbox profile reported by `doctor`.

On Linux, service installation requires the canonical Mealy home to remain outside host `/tmp` and
`/var/tmp` and on a non-`tmpfs`, non-`ramfs` filesystem. This prevents volatile state from being
mistaken for a durable service home. Configured workspaces are canonicalized and checked for
private-state overlap, but can reside on any filesystem the owner deliberately configured. A
custom unit output must be named `mealy.service`; its printed command links the exact absolute path
before enablement.

Service removal is plan-first. Omit `--destination` to inspect the loaded/default unit, or repeat
the exact custom destination used at installation. Apply disables and stops only a loaded fragment
whose canonical definition matches the reviewed path, obtains the stopped-home lock, rechecks the
loader link and generated bytes, removes both a custom loader link and its definition, and reloads
the user manager. The verifier recognizes an exact Mealy-generated unit even when it points to a
previous or explicitly selected daemon path. It always preserves the complete Mealy home.

The Linux unit also bounds the daemon's complete child cgroup with `MemoryHigh=1G`,
`MemoryMax=1536M`, `MemorySwapMax=0`, `TasksMax=384`, and `LimitNOFILE=1024`, with a three-start
burst limit. This is required for the supported browser deployment because V8 reserves a very
large virtual address range and cannot run under a useful `RLIMIT_AS`; direct launches need an
equivalent operator-managed cgroup to obtain the same physical-memory containment. `UMask=0077`
keeps daemon-created state private, and exit status 2 from a recorded forced bounded drain is
explicitly restart-inhibited so the service manager cannot undo an operator's drain request. The
unit limits socket creation to Unix, IPv4, IPv6, and netlink, denies realtime scheduling, permits
only the native syscall ABI, and sets `NoNewPrivileges=true`. It executes the exact daemon directly
because an outer Bubblewrap is incompatible with Ubuntu's reviewed profile: that profile removes
capabilities from the outer sandbox's children and therefore prevents the per-tool Bubblewrap from
creating its required namespace. The unit is supervision and resource containment, not a
whole-daemon filesystem sandbox. Governed effects, MCP, extensions, and browser calls retain their
fresh fail-closed Bubblewrap boundaries; writable-executable memory and Internet socket families
remain available to V8, providers, and channels.

## Health, diagnostics, and traces

```sh
mealyctl --home "$HOME/.mealy" health
mealyctl --home "$HOME/.mealy" status
mealyctl --home "$HOME/.mealy" metrics
mealyctl --home "$HOME/.mealy" doctor
```

`status` exposes queue depth, non-terminal runs, active leases, pending approvals, unknown effects,
outbox state, active/paused schedules and claimed/failed/skipped occurrences, aggregate provider
health plus every primary/fallback endpoint's identity, streaming mode, health, latency estimate,
durable cumulative dispatch count, current/max concurrency and minute-rate pressure, and durable
last success/failure time. Each endpoint also reports `protocol` as `openai_responses`,
`anthropic_messages`, or `builtin_fixture`. Status additionally exposes extension health,
channels, storage usage, schema version, the effective configuration/
policy digests, and recent durable failures. `metrics` is the stable JSON gauge view.
It additionally exposes `sqlite_writer_waits`, `sqlite_writer_maximum_wait_us`,
`sqlite_reader_waits`, and `sqlite_reader_maximum_wait_us`. These counters cover the current daemon
process only. A rising writer maximum means canonical transitions are queueing behind another
mutation; a rising reader maximum means the bounded snapshot pool is saturated. Investigate the
corresponding request/agent spans and database/WAL growth before increasing run or provider
deadlines. Normal history reads must use the snapshot pool, and new code must not reintroduce one
process-wide store mutex.
Every HTTP request receives an `x-request-id`; request spans log method, URI, status, and latency.
Agent/provider/tool spans and durable events retain task/run/attempt, correlation, causation, and
policy identities. `enabledReadTools` lists ordinary evidence tools; `enabledActionTools` lists
separately configured effect tools that still require an explicit action task and per-effect
approval. `doctor` also executes the configured routing contract with an explicit
same-trust fallback and rejects a lower-trust candidate.
Live health deliberately returns to `configured_unprobed` after restart, while cumulative counts
and timestamps remain available from canonical attempts; historical success is not treated as
proof of current connectivity. The configured-provider doctor check ends with a concrete repair
action and never prints credentials or provider response bodies.

### Optional private OTLP export

OpenTelemetry export is disabled by default. For an owner-operated local Collector using the
standard OTLP/HTTP receiver, start the daemon with its literal loopback origin:

```sh
mealyd --home "$HOME/.mealy" \
  --otlp-endpoint http://127.0.0.1:4318 \
  --otlp-export-interval-ms 30000 \
  --otlp-request-timeout-ms 3000
```

The endpoint is a collector origin, not a signal URL; Mealy derives exact `/v1/traces` and
`/v1/metrics` paths. The export interval accepts 1,000 through 300,000 milliseconds and the
request timeout accepts 100 through 30,000 milliseconds. Remote collectors require HTTPS.
Clear-text HTTP accepts only a literal loopback IPv4 or IPv6 address and an explicit port, not
`localhost`. URL credentials, base paths, query strings, fragments, proxy use, redirects,
compression, retries, and arbitrary headers are rejected or unavailable. This first slice does
not support authenticated vendor collectors; terminate authentication at an owner-controlled
local Collector or leave export disabled. Never place a collector credential in the URL.

Only the fixed `mealyd` service name/version/schema, claimed-run task/run/turn/session/correlation
IDs, a fixed outcome, and duration can cross this boundary. Metrics group by the three fixed
outcomes only; IDs occur on traces and are locators, not prompt content. Prompts, responses, tool
arguments, memory, file paths, search terms, provider bodies, arbitrary errors, general log
fields, host/user/process attributes, environment variables, and credentials have no recording
API. The daemon does not read `OTEL_*`, proxy, or exporter-header environment variables for this
pipeline.

The queue holds at most 1,024 spans, batches at most 128, an encoded request at most 2 MiB, and a
collector response at most 64 KiB. A full queue drops new telemetry rather than blocking agent
work. Collector failure or a bounded final-flush failure is logged with a generic local error and
does not rewrite canonical task state, durable events, or clean-drain evidence. The Collector is
therefore an optional derived view, never Mealy's audit authority. For a supervised deployment,
add these exact arguments to an operator-reviewed direct `mealyd` unit; the current generated
`mealyctl service install` unit intentionally does not acquire optional network-export authority.

### Scenario evaluation operations

Preflight a checked suite without requiring a running service:

```sh
mealyctl eval validate ./evaluation-suite.json
```

Then run it against the selected private home:

```sh
mealyctl --home "$HOME/.mealy" eval run ./evaluation-suite.json \
  > ./evaluation-report.json
```

The run creates fresh sessions and can make normal provider requests, so choose a deterministic
local provider for protected CI and apply ordinary live-provider cost/rate policy to manual
runs. Cases execute sequentially with explicit time/call/token/cost ceilings. A task that requires
approval parks; the evaluator never approves it. The report is emitted before the command returns
a failed status for a regression. Preserve both stdout and the exit status.

Reports contain no prompt/response/tool/validation/timeline bodies, but do contain stable
canonical IDs and unsalted SHA-256 commitments that may reveal equality or permit guessing
low-entropy text. Store them with workload-appropriate access controls. The report digest detects
modification but is not a signature. Release evidence must retain it inside the protected CI or
attestation chain. See [`EVALUATIONS.md`](EVALUATIONS.md) for the complete contract and
crash-harness composition.

External providers configured with `streaming: true` request `text/event-stream`. Text deltas are
untrusted, non-authoritative progress: each attempt retains no more than 64 KiB across 256 events,
each event is at most 4 KiB, and correlation IDs keep adjacent turns separate. Responses requires
the final `response.completed` object, usage, and streamed text to agree. Anthropic Messages
requires its ordered message/content-block/delta/stop sequence, cumulative usage, and exactly one
unambiguous text or tool decision; unexpected prompt-cache usage is rejected because Mealy does
not enable or price caching. Replay validates the progress sequence, cumulative bytes, event
ordering, and terminal boundary; changing a delta makes evidence incomplete. Provider HTTP
dispatch and JSON/SSE reads are async and polled against durable cancellation every 50 ms;
cancellation drops the active
request even when the peer has stalled and records post-dispatch uncertainty conservatively. The
immutable provider deadline remains the outer bound. Use the relevant provider command's
`--disable-streaming` only for a terminal-only compatible endpoint.

Provider-key rotation uses a new broker identity and a tested config activation before old material
is removed. With the daemon stopped, `config provider-secret-revoke SECRET_ID --approve` scans the
active config recursively and refuses any current model, fallback, or web-search reference. It
removes only the broker file, reports absence idempotently, and does not edit archived config or
encrypted backups. Revoke or rotate the upstream key independently.

Before the runtime opens its reader pool or starts background workers, startup runs full SQLite,
FTS5, and foreign-key integrity checks on the quiescent canonical writer. Live `health` and
`doctor` calls then check online schema/connection invariants without rerunning SQLite deep
diagnostics against concurrent FTS writes; `doctor` also inspects artifact storage and private
permissions and reports each sandbox profile as `enforceable` or `denied` with a reason. Backup,
restore, stopped-soak, and release validation repeat the deep checks on consistent copies or a
stopped database. Release one currently enforces `observe` and `workspace_write` through
Bubblewrap on a conforming Linux host. `networked`, `service_operator`, and `full_trust` are denied.
macOS and Windows are outside the active source, CI, packaging, and production support contract.
On Ubuntu 24.04, a denied profile paired with `RTM_NEWADDR` or user-namespace audit messages should
be repaired through the reviewed distro `bwrap-userns-restrict` activation and probe in
[`QUICKSTART.md`](QUICKSTART.md), not by making Bubblewrap setuid or disabling the host-wide
AppArmor mitigation.

Provider requests and independent-validation context are transparently compressed at rest only
when a canonical JSON object is at least 4 KiB and the bounded zlib/base64url envelope is smaller.
The recorded digest still identifies the original uncompressed canonical JSON, and historical raw
rows need no migration. Dispatch and replay cap decompression at the field's original 64/256-KiB
logical limit and fail closed on corruption, length mismatch, invalid UTF-8/JSON, or digest drift.
There is no operator toggle: if `doctor`, a task replay, or startup recovery reports incomplete or
corrupt evidence, preserve forensics and restore a verified backup rather than editing the row.

## Safe mode and drain

Start query-only recovery mode with:

```sh
mealyd --home "$HOME/.mealy" --safe-mode
```

Safe mode does not start promotion, provider, effect, lease-reaper, or outbox workers. It rejects
canonical mutations and signed ingress while retaining queries, diagnostics, complete backup,
restore verification, export, and drain.

Begin bounded graceful drain with:

```sh
mealyctl --home "$HOME/.mealy" drain
```

Admission closes before the server and workers drain. A clean path classifies interrupted work,
records terminal process evidence, checkpoints SQLite, removes `connection.json`, and exits zero.
The configured deadline (100 ms through five minutes) or a second signal exits with status 2. A
private forced-shutdown marker is synced before exit and reconciled into `daemon_run_record` if the
canonical writer lane was unavailable.

## Task control ordering

All controls require the exact current task revision:

```sh
mealyctl --home "$HOME/.mealy" task pause TASK_ID --expected-revision REVISION
mealyctl --home "$HOME/.mealy" task resume TASK_ID --expected-revision REVISION
mealyctl --home "$HOME/.mealy" task cancel TASK_ID "owner requested stop"
```

`queue` preserves FIFO order behind the active turn. `steer-at-boundary` attaches the accepted
input to the active run's next durable safe boundary. `interrupt-then-queue` records cancellation
before leaving the accepted input at the queue head. Pause fences any active lease and classifies
its provider/tool/effect boundary in the same transaction before the task becomes `paused`;
resume derives `queued`, `running`, or `waiting` from that durable run boundary. Cancellation is
cooperative at boundaries and becomes forceful only after the configured drain/grace deadline.
Stale revisions and stale worker fences are rejected.

When a parent is parked on `agent.delegate`, use the same task controls plus the owner-scoped
delegation projection:

```sh
mealyctl --home "$HOME/.mealy" delegation list --limit 20
mealyctl --home "$HOME/.mealy" delegation status DELEGATION_ID
mealyctl --home "$HOME/.mealy" task status CHILD_TASK_ID
```

The projection shows exact parent/child run linkage, the child's intersected read-only authority,
its separate budget, state, and structured result. Cancelling the parent atomically marks its
queued or running child for cancellation, leaves the parent parked until the child boundary is
settled, then requeues and terminally cancels the parent with zero reserved child/tool budget.
Child completion always records `delegation.succeeded`, `delegation.failed`, or
`delegation.cancelled`; a stale child fence cannot resume the parent. Use `task replay` separately
on the root and child task when auditing successful execution evidence.

`mealyctl chat` exposes those three delivery modes without serializing terminal input behind the
active task. It tracks at most 64 local admission workflows, backs idle promotion polling off to one
request per second per queued input, reloads the private connection descriptor across daemon
restart, and filters progress by the task's immutable correlation ID. Approval prompts are
non-blocking: copy the rendered exact subject into `/approve APPROVAL_ID SUBJECT_DIGEST` or
`/deny APPROVAL_ID SUBJECT_DIGEST`. Exiting the client aborts only its local watchers and never
withdraws an already committed input.

`chat --continue` (or `chat -c`) resumes the most recently updated session belonging to the exact
authenticated principal and channel binding. It reuses the ordinary bounded history scan before
accepting input, and it fails with a direct new-chat instruction instead of creating a session when
no prior local conversation exists.

`chat --pick` provides the owner-facing older-session path. It requires interactive stdin, stdout,
and stderr, fetches at most 20 newest exact-binding summaries, shows the bounded deterministic
first-input title plus status/relative recency and queued or active work, and resumes only the
selected exact session. Empty sessions use `New conversation`; deriving a title performs no model
call or mutation. Cancellation and invalid selection create nothing. Automation should continue
using `--continue` or `--session-id`.

`session list --limit N` (1 through 100) discovers older sessions for that same binding, including
their derived titles, pending-input, and active-turn state. Transcript-search hits return the same
session title. Use a selected ID with `chat --session-id`. Cross-channel sessions are deliberately
not merged; inspect Telegram bindings through their channel administration view.

Create a checkpoint only after the session is quiescent, then fork it with an exact
caller-generated idempotency boundary:

```sh
mealyctl --home "$HOME/.mealy" session checkpoint create SESSION_ID \
  --label "Before provider comparison"
mealyctl --home "$HOME/.mealy" session fork SESSION_ID CHECKPOINT_ID
```

An exact retry returns the original fork receipt. The child session has fresh operational state and
only immutable, bounded conversation references; context compilation rechecks the current
owner/configuration/policy/workspace-authority boundary before using them. Inspect the receipt and
new session before admitting work.

For a portable owner-readable transcript rather than an administrative evidence bundle:

```sh
mealyctl --home "$HOME/.mealy" session export SESSION_ID --format json \
  --output ./session.json
mealyctl --home "$HOME/.mealy" session export SESSION_ID --format html \
  --output ./session.html
```

The client verifies the response digest and format and creates a new mode-`0600` file without
following symlinks or replacing an existing path. The export is a bounded read-only projection,
not replay or recovery material. It deliberately preserves owner-visible message text verbatim,
so a secret pasted into chat remains in the export. Use the separate immutable administrative
`export` command for complete/scoped evidence publication.

## Backup and restore verification

Create a complete immutable backup:

```sh
mealyctl --home "$HOME/.mealy" backup nightly-2026-07-11
mealyctl --home "$HOME/.mealy" restore-verify nightly-2026-07-11
```

The online SQLite backup covers canonical state, journal, extension manifests, memory, and artifact
metadata. Every referenced content-addressed artifact, every config-referenced immutable data-only
skill package file, and the validated non-secret configuration is copied and covered by
`manifest.json` with exact size and SHA-256 evidence. Restored skill packages are re-inspected
against their manifests before verification succeeds. Publication is an atomic directory rename;
an existing backup name is never replaced.

Secrets are excluded by default. To opt in, pass the encryption passphrase through an environment
variable rather than the process argument list:

```sh
export MEALY_BACKUP_PASSPHRASE='a long owner-chosen passphrase'
mealyctl --home "$HOME/.mealy" backup nightly-secret --include-secrets
mealyctl --home "$HOME/.mealy" restore-verify nightly-secret \
  --passphrase-env MEALY_BACKUP_PASSPHRASE
```

The secret archive contains `identity.json`, active brokered channel keys, brokered model-provider
credentials, and validated MCP OAuth token families under Argon2id-derived XChaCha20-Poly1305
authenticated encryption. The passphrase is never persisted. Format-v2 secret-free manifests name
`mcp-oauth-tokens/` among the exclusions, while restore remains compatible with format v1.
Verification first checks every manifest file, copies the archive into a new isolated temporary
home, authenticates and decrypts secrets when present, opens the copied database, runs full
integrity/foreign-key/schema checks, validates all canonical artifact files and OAuth records, and
proves that decrypted identity is active in the restored registry. It never replaces the active
home.

Only a secret-complete backup can become an operable active home. Record the exact
`manifestDigest` returned by `restore-verify`, drain Mealy, and explicitly bind activation to that
digest:

```sh
mealyctl --home "$HOME/.mealy" drain
export MEALY_BACKUP_PASSPHRASE='a long owner-chosen passphrase'
mealyctl --home "$HOME/.mealy" restore-activate nightly-secret \
  --expected-manifest-digest MANIFEST_SHA256 \
  --passphrase-env MEALY_BACKUP_PASSPHRASE \
  --approve
unset MEALY_BACKUP_PASSPHRASE
```

This is an offline operation: it takes the actual daemon-home lock, re-verifies and decrypts the
backup into a private sibling directory, opens the copied database, checks schema/foreign keys,
artifacts, configuration, and active identity, removes the encrypted transport envelope, and
creates a new locked home. On Linux it then uses one same-filesystem atomic directory
exchange, so observers see either the complete old home or the complete restored home—never a
partially copied one. The exact old home is retained beside it as
`HOME.pre-restore-TIMESTAMP-DIGEST`, and `restore-activation.json` records the activation evidence.

Wrong approval, digest, passphrase, non-secret backup, live daemon lock, corrupt evidence, or a
filesystem without atomic exchange support leaves the active home unchanged. Do not remove the
preserved home until the restored daemon passes `health`, `status`, and `doctor` and a new encrypted
backup has been created and verified. Backup/export history not covered by the selected manifest
remains in the preserved home rather than being silently merged into restored state.

## Complete and scoped export

A secret-free complete archive and owner-scoped portable JSON bundles are available:

```sh
mealyctl --home "$HOME/.mealy" export complete-2026-07-11 complete
mealyctl --home "$HOME/.mealy" export audit-2026-07-11 audit
mealyctl --home "$HOME/.mealy" export task-case task --selector TASK_ID
mealyctl --home "$HOME/.mealy" export artifact-case artifact --selector ARTIFACT_ID
mealyctl --home "$HOME/.mealy" export memory-case memory --selector WORKSPACE_IDENTITY
```

Complete export is an atomic directory containing an online canonical SQLite snapshot, validated
non-secret configuration, every referenced artifact, and an exact digest manifest. Audit export
deduplicates all owner-visible session timelines by global cursor and includes the operational
snapshot. Task export is a validated recorded-only replay graph. Artifact export carries authorized
metadata plus base64url content. Memory export includes every revision and tombstone in the exact
workspace. Bundles are private, immutable, atomically published, and returned with byte size and
SHA-256 evidence.

## Retention, deletion, and garbage collection

`config.json` is schema-versioned and includes minimum ages by data class and sensitivity plus
principal, task, channel-binding, and legal-hold selectors. Memory records additionally carry their
own governed retention state. Release one never physically erases canonical journal/history through
the garbage collector.

The same configuration carries enforceable agent-loop budgets, per-session pending-input capacity,
and concurrency ceilings for daemon, principal, session, provider, extension, agent role, and
resource class. New tasks receive an immutable copy of the effective budget. Lease claims enforce
principal/session/role capacity transactionally; worker, provider, extension, and resource guards
enforce the remaining dimensions. Values outside their bounded schema fail startup validation.

```sh
mealyctl --home "$HOME/.mealy" garbage-collect
```

GC holds the canonical store while collecting its referenced artifact digests. It preserves every
referenced blob regardless of age and erases only configured-age temporary or unreferenced files.
User-visible memory deletion remains an immutable tombstone; backups and audit history retain what
their manifest/retention constraints require.

## Semantic memory operations

Optional semantic retrieval is an explicitly configured derived cache, not canonical state. It is
off when `memoryEmbedding` is absent. Configure or disable it only while the daemon is stopped;
each command archives the replaced configuration and reports that restart is required. Remote
endpoints require HTTPS and a credential imported from a named environment variable into the
private provider-secret broker. Literal-loopback HTTP may be credentialless.

After activation, run:

```sh
mealyctl --home "$HOME/.mealy" memory rebuild-index --semantic
```

This first rebuild snapshots all active governed-memory revisions for the authenticated principal,
sends them to the exact configured endpoint in batches of at most 32, and atomically publishes the
complete derived set only when every revision and content digest still matches. The initial exact
cosine implementation caps the principal at 10,000 active revisions and vectors at 8,192
dimensions. Rebuild networking occurs outside the SQLite writer lane.

Inspect the JSON receipt before treating hybrid search as active:

- `healthy` means the complete current policy/dimension set was committed;
- `degraded` means the explicit endpoint rebuild failed and no partial set is searchable;
- a changed policy digest or dimension is incompatible until a complete rebuild; and
- zero active memories may produce a healthy empty set.

Correction, activation-status drift, expiry, rejection, and deletion remove affected vector rows
and mark the principal's set stale in the same transaction. That stale state survives restart.
Hybrid queries then return `lexical_fallback`/`stale`; ordinary governed memory remains available.
Run another explicit semantic rebuild after reviewing the lifecycle change. Temporary query
endpoint failure reports `embedding_unavailable` without changing canonical memory.

Do not copy derived-vector tables into another service as authoritative memory. Clean
reconstruction from canonical active revisions is the recovery procedure. Changing the endpoint,
model, prefixes, dimensions, residency, or credential policy requires an approved stopped-home
configuration update and complete rebuild. Disabling the policy prevents future calls but retains
canonical memory and the separately managed broker credential for rollback. See
[the semantic-memory guide](SEMANTIC_MEMORY.md) for setup and response examples.

## Configuration activation and rollback

Only validated non-secret `config.json` is activated, and its canonical digest is recorded on every
daemon start. Release one has no runtime reload path: high-risk settings change only while the
daemon is stopped and take effect after restart. `mealyctl config provider` validates an `OpenAI`
Responses-compatible provider; `config provider-anthropic` validates the independently implemented
Anthropic Messages contract. Each imports a credential into the owner-private broker, writes only
its opaque identity to configuration, and preserves the replaced document.
`provider-subscription-openai` instead persists no secret reference: it retains the selected
official-client kind, exact canonical executable path/digest, model, residency, and bounded limits.
The runtime re-hashes the Codex client before every dispatch,
clears its environment to a small owner/authentication allowlist, excludes all API-key variables,
disables client tools/connectors/project instructions/session persistence, and accepts only bounded
schema-valid decisions plus complete usage. Client-reported output above the configured acceptance
ceiling fails closed; the official clients do not expose a direct-API-equivalent upstream maximum
output setting. Legacy Claude subscription configuration fails validation before the executable is
opened. The corresponding
`provider-fallback` and `provider-fallback-anthropic` commands append a uniquely identified
endpoint only when its residency and local/remote boundary exactly match the primary. A chain may
mix protocols, and each fallback credential is brokered separately. Definite
transient failures use a durable delayed retry and advance through that ordered chain, while
outcome-unknown transport failures never auto-retry. Every successful effective configuration is
archived as `config-history/<DIGEST>.json`, so the prior successful value remains available.

Remove one exact fallback without rebuilding or silently reordering the rest:

```sh
mealyctl --home "$HOME/.mealy" config provider-list
mealyctl --home "$HOME/.mealy" config provider-fallback-remove PROVIDER_ID --approve
```

The credential is deliberately retained until a separate unreferenced
`provider-secret-revoke`. A primary replacement preserves the existing fallback array only when
the complete replacement chain still satisfies unique identity and exact residency/locality
validation; an incompatible primary change fails before config or broker mutation.
The list response validates the complete chain and exposes only non-secret settings and opaque
credential references; it never resolves broker values.

Read-only workspace grants use the same stopped-daemon and explicit-approval boundary:

```sh
mealyctl --home "$HOME/.mealy" config workspace-grant project /canonical/project --approve
mealyctl --home "$HOME/.mealy" config workspace-revoke project --approve
```

Grant publication canonicalizes the existing directory, rejects duplicate identities or roots,
and preserves the replaced configuration. On Linux, startup opens each root once and probes
`openat2` beneath-root enforcement before publishing readiness. A revoked or changed grant rotates
the session context epoch at the next turn, so no stale workspace schema survives restart. Safe
mode intentionally opens no workspace adapters.
Every root must be disjoint from the canonical Mealy home. A root equal to the home, below it, or
containing it is rejected at configuration time and independently at startup so workspace,
extension-mount, or attachment authority cannot expose bearer, broker, backup, or configuration
state.

Workspace-mutation authority is an additional writable subset, never inferred from read access:

```sh
mealyctl --home "$HOME/.mealy" config workspace-write-enable project --approve
mealyctl --home "$HOME/.mealy" config workspace-write-disable project --approve
```

Each workspace response sets `restartRequired` and leaves `serviceReinstallRequired=false` because
the generated service does not embed workspace paths. Restart the daemon after a workspace change;
there is no separate service-regeneration step. The stopped-home command and daemon startup both
validate private-state overlap, while every governed operation gives its fresh Bubblewrap process
only the selected request-specific workspace mount.

After restart, `workspace.create_file`, `workspace.manage_path`, and `workspace.replace_file`
appear in `enabledActionTools`, but only explicit `/act TEXT`, `/manage TEXT`, and `/edit TEXT`
tasks respectively receive one in their immutable run ceilings. The model-facing target remains
`workspace://<id>/<relative-path>`; the host root is retained only in policy/executor evidence and
is not sent to the model or exposed in the approval target. Each proposal requires a current exact
owner approval and a medium-risk fresh validation. Bubblewrap mounts only the selected root
writable, supplies no network/secrets/environment/process-spawn authority, and invokes a digest-
pinned worker under time/output/memory/process limits. Create requires existing parents and refuses
an existing target. Replace requires an existing regular file of at most 128 KiB, an exact
approval-bound current SHA-256, and exactly one of bounded complete new UTF-8 content or one to 16
ordered exact-text replacements. Each exact replacement binds non-empty old text, new text, and an
expected non-overlapping occurrence count from 1 to 32. The worker applies the edits in order and
then uses an atomic mode-`0600` staging-file rename followed by directory synchronization. Stale
content, occurrence mismatch, invalid UTF-8, output overflow, missing targets, symlinks, traversal,
and non-regular files fail closed without changing the original. Neither operation can delete,
rename to a different logical path, apply fuzzy patches, chmod, or create directories.

`workspace.manage_path` is a separate exact contract for one `create_directory`, `move_file`,
`remove_file`, or `remove_empty_directory`. Directory creation/removal is non-recursive and requires
an existing safe parent; removal accepts only an empty directory. File move/removal accepts only a
bounded regular file whose complete current SHA-256 matches the approval-bound precondition. Moves
bind both logical paths and use no-overwrite rename semantics. Removal moves the entry to an
effect/attempt-specific root-level `.mealy-remove-*.quarantine`, synchronizes, verifies its digest,
then unlinks and synchronizes again. Safe-parent `openat2` resolution rejects traversal, symlinks,
magic links, and mount crossing. Every manage operation is conservatively non-idempotent with
reconcile-only recovery; no ambiguous post-dispatch attempt is retried.

For an `outcome_unknown` lifecycle effect, inspect the exact evidence and filesystem before
resolving it:

```sh
mealyctl --home "$HOME/.mealy" effect status EFFECT_ID
mealyctl --home "$HOME/.mealy" effect attempt ATTEMPT_ID
mealyctl --home "$HOME/.mealy" effect reconcile EFFECT_ID ATTEMPT_ID succeeded \
  --revision EFFECT_REVISION \
  --evidence-json '{"operatorObservation":"approved source absent and destination digest matched"}'
```

Use `failed` only when external evidence proves the approved mutation did not occur. For a removal,
also inspect the original logical path and the exact quarantine name derived from the effect and
attempt IDs; do not delete a quarantine entry until its digest and ownership have been reconciled.
The effect ledger preserves preparation/dispatch/outcome/observation boundaries, and recorded
replay performs no model, worker, or filesystem call. Disabling write leaves read authority intact;
revoking the workspace removes both after restart.

High-risk direct-process authority is separately configured while stopped:

```sh
mealyctl --home "$HOME/.mealy" config process-grant mkdir /usr/bin/mkdir --approve
mealyctl --home "$HOME/.mealy" config process-revoke mkdir --approve
```

The grant requires a root-owned executable and root-controlled non-writable directory chain,
stores its SHA-256 identity, and requires an existing writable workspace. `/run TEXT` is the only
normal admission prefix that exposes `process.run`. The approval preview verifies and displays the
exact normalized command ID, workspace, working directory, and argv together with the immutable
subject. Dispatch re-hashes the selected executable and mounts only that command identity—not
other configured commands—alongside its required loader libraries. The worker performs direct
execution with null stdin, an empty environment, no network or secrets, one writable workspace,
and hard argument/time/output/memory/process bounds.

Treat every command as having its program-defined authority over the entire selected writable
workspace. Do not grant a shell/interpreter casually. `process.run` is non-idempotent and uses
never-retry recovery: if the external boundary may have been crossed without a terminal outcome,
the task parks until the owner inspects `effect status`/`effect attempt` and submits an explicit
`effect reconcile` decision. Recorded replay never re-executes the command.

Bounded web authority follows the same activation boundary:

```sh
mealyctl --home "$HOME/.mealy" config web-enable \
  --allow-domain example.com --brave-secret-id brave-search --approve
mealyctl --home "$HOME/.mealy" config web-disable --approve
```

Configuration distinguishes broad public HTTPS, exact DNS suffixes, and exact origins. Search
credentials are imported through the private broker. Runtime resolution rejects private/reserved
or mixed DNS answers, pins accepted addresses, verifies the peer, disables proxies and redirects,
and applies content/status/size/time/result bounds. Disable removes all web schemas after restart
but retains the token for rollback; revoke it at the provider when immediate invalidation is
needed. The immutable run capability ceiling records exact tool IDs, logical workspace roots, the
exact writable-workspace subset, network destinations, and opaque secret references at promotion,
then the runtime and SQLite
prepare boundary independently intersect and enforce that ceiling.

Native MCP stdio authority is also stopped-daemon configuration. Inspecting does execute the
candidate, but only inside the same empty-environment, no-network Bubblewrap boundary and without
publishing authority:

```sh
mealyctl --home "$HOME/.mealy" config mcp-inspect SERVER_ID /canonical/native-server
mealyctl --home "$HOME/.mealy" config mcp-add SERVER_ID /canonical/native-server \
  --allow-tool REMOTE_TOOL --approve
mealyctl --home "$HOME/.mealy" config mcp-list
```

The supported profile accepts only native ELF servers and MCP revision `2025-11-25`. It
stores no server credential and supplies no environment, network, home, workspace, host writable
filesystem, shell, `PATH`, or child-process authority. Direct `--argument` values are persisted and
must be non-secret. The installed executable, complete paginated advertised tool set, and every
selected full definition/schema are digest-pinned. Startup and each fresh per-call session repeat
initialization and full discovery before dispatch; any executable or tool-set drift prevents use.
Per-tool time and normalized-output ceilings combine with protocol message/count/stdout/stderr and
sandbox CPU/address-space/file/descriptor/process limits. Cancellation is propagated and the
process is then terminated. Successful evidence uses `mcp://SERVER_ID/REMOTE_TOOL`; recorded replay
does not launch a process.

Classify every selected operation with exactly one repeated argument: `--allow-tool REMOTE_TOOL`
for read-only, `--allow-tool idempotent:REMOTE_TOOL` for an effect whose downstream contract
accepts a stable-key retry, or `--allow-tool non-idempotent:REMOTE_TOOL` for reconcile-only
recovery. Server annotations never choose this class. Effect proposals require exact owner
approval and bind the immutable run ceiling,
executable/catalog/definition/schema, normalized arguments, logical target, and policy. After a
dispatch crash, idempotent work may create a new fenced attempt; non-idempotent work becomes
`outcome_unknown` and must not be retried before authenticated external-evidence reconciliation.

If MCP verification prevents startup, keep the daemon stopped and remove authority without
executing the server:

```sh
mealyctl --home "$HOME/.mealy" config mcp-disable SERVER_ID --approve
# or permanently remove the active entry while retaining immutable rollback bytes:
mealyctl --home "$HOME/.mealy" config mcp-revoke SERVER_ID --approve
```

Re-enable only with `config mcp-enable SERVER_ID --approve`; that path launches a fresh isolated
discovery and accepts only the exact retained pins. Server upgrades have no in-place trust carry:
revoke, inspect the replacement bytes, and add the identity again. Safe mode launches no MCP
server. Complete export/backup and migration rollback copy configured executables, restore owner-
executable permissions, and re-verify ELF type, path, size, and digest before the reconstructed home
is accepted.

Remote Streamable HTTP MCP catalog operations use separate commands and grants:

```sh
mealyctl --home "$HOME/.mealy" mcp-http inspect \
  SERVER_ID https://mcp.example.com/mcp
mealyctl --home "$HOME/.mealy" mcp-http add \
  SERVER_ID https://mcp.example.com/mcp \
  --allow-tool REMOTE_TOOL \
  --allow-resource EXACT_RESOURCE_URI \
  --allow-prompt REMOTE_PROMPT \
  --approve
mealyctl --home "$HOME/.mealy" config mcp-list
```

For bearer authentication, set `MCP_HTTP_BEARER_TOKEN` and add `--bearer-secret-id SECRET_ID` to
both inspect and add. Add imports the token into the existing owner-private broker and persists
only the opaque reference. Production endpoints require HTTPS; literal-loopback HTTP is accepted
for local testing. DNS is checked and pinned, proxies and redirects are disabled, session IDs stay
in zeroizing memory, and every call uses a fresh session plus complete
tool/resource/resource-template/prompt catalog revalidation. Exact resource reads take no dynamic
URI argument. Prompt arguments are limited to advertised string fields, and returned prompt
messages remain cited untrusted tool evidence rather than becoming system instructions. The
endpoint destination and credential reference are bound to the durable descriptor and immutable
task ceiling. A changed endpoint, credential reference, protocol, inventory, definition, schema,
or structured result fails closed.

HTTP and OAuth-backed `add` accept the same `--allow-tool idempotent:REMOTE_TOOL` and
`--allow-tool non-idempotent:REMOTE_TOOL` forms. Effectful calls use a fresh revalidated session and the
ordinary durable approval/effect/attempt ledger. A definite pre-dispatch failure is terminal; a
post-dispatch transport ambiguity is retryable only for the owner-classified idempotent contract.
Non-idempotent ambiguity parks for exact revision-fenced owner reconciliation. Replay opens no
session, performs no refresh, and repeats no effect.

Before authorizing an OAuth-protected server, inspect its public metadata without mutation:

```sh
mealyctl --home "$HOME/.mealy" mcp-http oauth-inspect \
  SERVER_ID https://mcp.example.com/mcp
```

The inspection proves the bounded `401` challenge, protected-resource metadata, exact resource
audience, selected issuer, OAuth/OIDC metadata, authorization-code flow, and PKCE S256. Redirects,
proxies, private destinations, mismatched resources/issuers, malformed metadata, and missing PKCE
fail closed. Multiple advertised issuers require `--authorization-server EXACT_ISSUER`. This
operation writes neither the Mealy home nor a credential broker.

For a reviewed pre-registered public client, stage an initial token family only while the daemon is
stopped:

```sh
mealyctl --home "$HOME/.mealy" drain
mealyctl --home "$HOME/.mealy" mcp-http oauth-login \
  SERVER_ID https://mcp.example.com/mcp \
  --oauth-client-id REVIEWED_PUBLIC_CLIENT_ID \
  --oauth-token-set-id mcp.SERVER_ID.oauth \
  --oauth-timeout-seconds 300 \
  --approve
```

The client prints one owner-only authorization URL and listens only on an ephemeral literal
`127.0.0.1` callback. It validates exact Host/path/state, PKCE S256, the MCP resource parameter,
token response cache controls, Bearer type, bounds, and non-broadened scope before creating a
generation-one record under `mcp-oauth-tokens/`. The record is owner-only and never enters
configuration, stdout, evidence, or model context. Login changes no MCP authority. Existing token
identities, confidential clients, missing public-client metadata, malformed callbacks, unsafe token
paths, and persistence failures fail closed.

After reviewing the live catalog, bind the staged family to only the selected operations:

```sh
mealyctl --home "$HOME/.mealy" mcp-http oauth-add \
  SERVER_ID https://mcp.example.com/mcp \
  --oauth-token-set-id mcp.SERVER_ID.oauth \
  --allow-tool REMOTE_TOOL \
  --allow-resource EXACT_RESOURCE_URI \
  --allow-prompt REMOTE_PROMPT \
  --approve
```

This approved stopped-home transaction revalidates the complete OAuth metadata and catalog before
publishing authority. Startup and re-enable revalidate the same non-secret grant. Runtime access
refreshes before expiry; concurrent processes serialize on the token family, exact scope cannot
change, public-client refresh tokens must rotate, and a rejected access generation permits only one
refresh plus one retry. Every replacement is an atomic, durable generation advance.

Use `mcp-http disable`, `mcp-http enable`, or `mcp-http revoke` with `--approve` while stopped.
After revoking every server that references a family, remove its local tokens:

```sh
mealyctl --home "$HOME/.mealy" mcp-http oauth-revoke \
  mcp.SERVER_ID.oauth --approve
```

Local revocation fails closed while any configuration reference remains and does not call an
issuer revocation endpoint; remove the authorization at the issuer separately when required.
Encrypted secret backups and migration rollback carry only validated token records. Secret-free
backups explicitly omit `mcp-oauth-tokens/`. Dynamic registration/CIMD, issuer-side revocation,
resource-template expansion/subscriptions, resumable GET, and long-lived session health remain
unavailable until their separate v0.4 contracts and recovery tests land.

The optional rendered browser is a separate stopped-daemon authority and currently has release
evidence on Linux x86_64. Fetch only the release-pinned Headless Shell archive with the managed
helper, inspect it, then install it after web destinations have been configured:

```sh
BROWSER_BUNDLE="$("$HOME/.local/share/mealy/fetch-browser-runtime.sh" \
  "$HOME/.cache/mealy/browser-runtimes")"
mealyctl config browser-inspect "$BROWSER_BUNDLE"
mealyctl --home "$HOME/.mealy" config browser-add "$BROWSER_BUNDLE" --approve
mealyctl --home "$HOME/.mealy" config browser-list
```

Inspection runs `--version` inside a no-network/no-home namespace. Add then copies the complete
no-symlink inventory into `browser-runtimes/<digest>` and requires a real CDP/navigation/rendering
self-test before configuration publication. Startup and each call re-verify the content identity.
Each call uses a fresh profile and private network namespace; only a scoped Unix-socket host proxy
can resolve/connect, and it applies the configured web destinations, public/loopback IP rules,
GET/HEAD, a 32-concurrent/256-total connection ceiling at both relay layers, aggregate byte/time
limits, prompt completed-handler reaping, and peer pins. It further fixes all traffic for one call to
the initial URL's exact origin, so cross-origin redirects, subresources, and followed or activated links fail
closed even when separately configured; investigate a partially rendered page with that limitation
in mind. CDP 1.3 independently rejects non-read
methods and authentication, denies ambient downloads, blocks WebSocket/WebTransport/direct sockets, and
normalizes only accessibility evidence plus an optional bounded PNG. A call may follow one exact
accessible same-origin GET link or activate one exact enabled native form-free
`<button type="button">`; submit/form buttons fail closed and all resulting network still crosses
GET/HEAD interception. It may instead fill one exact enabled native non-password textbox/searchbox
through a value setter captured before page code. No input/change/submit event is dispatched. An
optional form step accepts only GET plus same-origin action plus empty/`_self` target and constructs
the destination from only the selected non-empty field name/value; hidden and sibling fields never
cross the proxy. There is no host CDP port, arbitrary keyboard/form event authority, personal
profile, cookie persistence, or upload authority in this default read tool. One exact accessible
same-origin `downloadLink` is the only read-tool download exception: Chrome writes a CDP GUID-
named file under the per-call ephemeral profile, progress and total bytes are capped, the worker
opens it with `NOFOLLOW`, and the result carries at most 512 KiB as base64 plus SHA-256/size/URL.
No configured workspace or owner-selected path is mounted or written.

One-shot POST authority is an independent stopped-daemon switch and remains disabled after browser
installation or read-browser re-enable:

```sh
mealyctl --home "$HOME/.mealy" browser --enable-transactions --approve
mealyctl --home "$HOME/.mealy" browser --disable-transactions --approve
```

With it enabled, `browser.snapshot` may report inert POST-form catalog entries and
`browser.transact` may propose one exact digest-matched same-origin form. Every invocation requires
authenticated local approval binding the canonical initial URL, form digest, public values,
submitter, private upload artifact identities/digests, runtime identity, ceilings, and deadline.
Dispatch reloads and revalidates the form in a fresh profile, closes the hostile source target,
reconstructs the approved controls in a controlled blank target, and arms one POST only after the
durable running boundary. Uploads are digest-rechecked owner-private artifacts, never host paths.
The proxy rejects any second state-changing request, cross-origin redirect, popup, background
fetch/XHR/beacon, or service worker.

`browser.transact` is `NeverRetry`. If the daemon or worker disappears after dispatch, status parks
at `outcome_unknown`; inspect the external system and the exact effect/attempt evidence, then use
the ordinary revision-fenced `effect reconcile` command. Never “fix” a parked transaction by
restarting it or editing SQLite. Recorded replay validates the intent, approval, attempt,
observation, artifacts, and event chain without Chrome or network. The boundary intentionally has
no ambient login cookies, personal profile, payments, WebAuthn, wallet extensions, cross-origin
identity flow, arbitrary JavaScript/clicking, or unattended batching.

Disable before removing web authority; `web-disable` deliberately refuses to orphan an enabled
browser:

```sh
mealyctl --home "$HOME/.mealy" browser --disable-transactions --approve
mealyctl --home "$HOME/.mealy" config browser-disable --approve
mealyctl --home "$HOME/.mealy" config web-disable --approve
# Re-enable performs complete bundle/product/CDP/render verification:
mealyctl --home "$HOME/.mealy" config browser-enable --approve
# Revoke removes active configuration but retains rollback bytes:
mealyctl --home "$HOME/.mealy" config browser-revoke --approve
```

Safe mode never launches Chrome. Recorded replay reads durable evidence without Chrome or network.
Complete backups and migration reconstruction copy every referenced bundle file, restore its exact
executable-mode inventory, and re-verify the aggregate and executable digests.

Rollback requires the daemon to be stopped, an exact archived digest, and explicit approval:

```sh
mealyctl --home "$HOME/.mealy" config rollback CONFIG_DIGEST --approve
```

The command refuses a live home, preserves the replaced configuration, atomically restores the
digest-pinned archive, and requires a restart. The subsequent daemon start validates and records the
restored digest.

## Telegram channel operations

Prefer `channel telegram-pair`: it verifies `getMe`, generates 128 bits of operating-system
randomness for an expiring one-time command, polls only bounded `message` updates, and accepts only
the exact command from a non-bot sender whose positive user ID equals a one-to-one private-chat ID.
The accepted binding starts after every update inspected through the challenge, preventing old
setup traffic from becoming agent input. The default window is 120 seconds and the allowed range
is 30–300 seconds. A timeout or failed Bot API response creates no binding and does not broker the
token. Remove an existing webhook first, do not run another `getUpdates` consumer for that token,
and do not send ordinary prompts until the pairing response is printed.

`channel telegram-list` and `channel telegram-status BINDING_ID` expose the exact user/chat/bot
identity, dedicated session, durable `nextUpdateId`, lifecycle revision, last successful and failed
poll times, consecutive failures, and a stable secret-free error code. The token itself is stored
under `provider-secrets/telegram.<BINDING_ID>.key` with owner-only permissions and is included only
in explicitly encrypted secret backups. Do not copy it into service environment files.

The main remediation codes are:

- `telegram_webhook_conflict`: remove the bot's webhook before using `getUpdates` polling;
- `telegram_unauthorized` or `telegram_credential_mismatch`: terminally revoke, rotate the token
  with BotFather, and create a new binding;
- `telegram_credential_unavailable`: verify owner-private broker storage and restore the matching
  encrypted secret backup if appropriate;
- `telegram_transport_unavailable`, `telegram_rate_limited`, or `telegram_server_error`: retain the
  durable cursor and investigate connectivity/rate limits before restarting;
- `telegram_response_oversized` or `telegram_response_malformed`: retain evidence and investigate
  the Bot API endpoint or any unsupported local Bot API implementation.

`degradedChannels` counts active Telegram bindings with consecutive poll failures, and
`reservedChannelUpdates` exposes updates reserved before a crash but not yet terminally completed.
The driver recovers those reservations, and advances the poll cursor only in the same transaction
as the terminal admitted/ignored receipt. A nonzero reserved count lasting longer than a poll
cycle merits inspection; do not edit the cursor or receipt tables.

Definite `sendMessage` failures use bounded durable retry. A transport failure or malformed 2xx
acknowledgement after Telegram may have accepted the message is marked terminal outcome-unknown so
automatic retry cannot duplicate it. Inspect failed outbox and recent-failure evidence, then use
the canonical session timeline as the full record. Telegram supports only one `getUpdates`
consumer per token; Mealy also permanently prevents one token digest from owning multiple cursors.
If guided pairing reports a webhook conflict, remove the webhook and retry with a new challenge. If
it expires, simply rerun the command; challenges are never stored as credentials. For a custom Bot
API origin, pass the same origin to both daemon and CLI. HTTPS is mandatory except for literal
loopback HTTP used by local test servers.

Revocation removes the credential first and then commits revision-fenced terminal binding evidence;
retrying after a transient SQLite failure is safe because credential removal is idempotent. Once
revoked, inbound polling and outbound routing cease, but the dedicated session, update receipts,
and audit history remain. Safe mode never resolves Telegram tokens or starts polling/outbox work.

## Discord DM channel operations

Use `channel discord-pair --channel-id DM_CHANNEL_ID` for the least-authority profile. The CLI
authenticates with `Authorization: Bot`, verifies `/users/@me`, requires Discord channel type `1`
with exactly one non-bot recipient, establishes a current-message fence, and accepts only the
128-bit one-time `/pair` text from that recipient. The token is brokered as
`provider-secrets/discord.<BINDING_ID>.key`; SQLite and operator projections contain only its
opaque identity and SHA-256 pin. Production accepts only `https://discord.com/api/v10`; literal
loopback HTTP exists solely for fixtures. Arbitrary alternate HTTPS endpoints, proxies, redirects,
guild channels, and group DMs fail closed.

`channel discord-list` and `channel discord-status BINDING_ID` expose the exact human, DM, and bot
snowflakes as decimal strings, the dedicated session, `afterMessageId`, lifecycle revision, poll
times, consecutive failures, and stable last error. Do not coerce snowflakes through a signed
integer in scripts. The main repair codes are:

- `discord_unauthorized` or `discord_credential_mismatch`: revoke, reset the Developer Portal
  token, and pair a replacement;
- `discord_forbidden` or `discord_channel_not_found`: verify the bot still shares and can access
  that exact one-to-one DM, then replace the binding if its identity changed;
- `discord_credential_unavailable`: repair owner-private broker storage or restore an explicitly
  encrypted secret backup;
- `discord_transport_unavailable`, `discord_rate_limited`, or `discord_server_error`: preserve the
  cursor and investigate connectivity or Discord status; the shared gate honors the server's
  `Retry-After` before polling or sending again;
- `discord_response_oversized` or `discord_response_malformed`: investigate the endpoint without
  editing canonical receipt/cursor state;
- `discord_backlog_exceeded`: the lossless backward scan exceeded 10,000 messages or 16 MiB and
  deliberately did not advance the cursor. Preserve the home for diagnosis instead of resetting
  the cursor by hand.

Every inbound message is reserved before interpretation. Saturated 100-message pages are walked
backward to the durable floor, then sorted and duplicate-checked before the oldest message is
processed; each admitted or ignored receipt advances the cursor transactionally. Attachments,
webhooks, system message types, bot output, and wrong sender/channel messages are retained only as
ignored evidence. The DM accepts text plus the same queue/steer/interrupt and exact-subject
approval commands as Telegram.

Outbound delivery caps text at 2,000 characters, disables mention parsing and embeds, and binds a
stable 25-character nonce to the durable outbox ID with `enforce_nonce`. A definite 429 retries
after the platform delay. Transport errors, server errors, or a 2xx body that does not prove the
exact channel, bot, nonce, and new message ID are parked terminally to avoid duplicate user-visible
effects. Inspect the local timeline when a notification is truncated or parked. Revocation is
revision-fenced, removes the brokered token, stops active target discovery, and preserves session,
message-receipt, health, and journal evidence. Safe mode resolves no Discord credential and runs
neither polling nor external delivery.

## Slack Socket Mode operations

`channel slack-create` reads `SLACK_APP_TOKEN` and `SLACK_BOT_TOKEN` once, live-verifies the exact
app/workspace/bot/member/conversation relationship, and brokers both credentials outside SQLite.
Use `channel slack-list` and `channel slack-status BINDING_ID` to inspect identity pins, lifecycle,
revision, last success/failure, consecutive failures, and a secret-free failure code. The daemon
groups exact routes sharing one installation behind one Socket Mode connection because Slack may
distribute events unpredictably across multiple connections.

Operational error codes are intentionally stable and secret-free:

- `credential_unavailable`, `credential_mismatch`, or `unauthorized`: rotate/reinstall the Slack
  app, revoke the affected binding, and create a replacement with both current tokens;
- `app_identity_mismatch`: the app token opened a socket for a different application than the
  verified bot token; revoke immediately and correct the token pair;
- `unsafe_socket_url`: Slack returned a Socket Mode origin outside the fixed production policy;
- `rate_limited` or `transport`: inspect Slack service/network health and allow bounded backoff;
- `malformed`, `malformed_hello`, or `oversized`: preserve logs and receipt evidence and treat the
  upstream/protocol exchange as suspect;
- `store`, `session`, or `invariant`: stop mutation, preserve the home, and run local integrity and
  migration diagnostics before retrying.

Routine Slack `disconnect` refresh envelopes cause an immediate fresh `apps.connections.open` and
do not degrade channel health. Each other failure is recorded for every route sharing that
installation. A connection success clears the consecutive-failure counter. Pending reserved
envelopes are completed before new traffic after reconnect/restart.

Outbound delivery uses the exact originating Slack thread. One per-channel send slot per second is
reserved before dispatch; definite `429` responses defer the route by bounded `Retry-After`.
Retries retain `client_msg_id`. Rich-text interpretation and link/media unfurls are disabled.
Approval notifications are informational only: Slack text cannot resolve an effect approval.

Revoke with the current revision. A route sharing the same app installation leaves the shared
credentials intact; revoking its final active route removes both broker entries. The revocation
transaction restores credential files if the canonical database transition fails. Safe mode
resolves neither Slack credential and starts no Socket Mode or Slack outbox worker.

## Scheduled automation operations

`schedule list`, `schedule status`, and `schedule runs` expose the canonical definition, next due
instant, revision, and newest-first occurrence history. Lifecycle changes are revision fenced:

```sh
mealyctl --home "$HOME/.mealy" schedule pause SCHEDULE_ID --expected-revision REVISION
mealyctl --home "$HOME/.mealy" schedule resume SCHEDULE_ID --expected-revision REVISION
mealyctl --home "$HOME/.mealy" schedule cancel SCHEDULE_ID --expected-revision REVISION
```

Both `mealyctl schedule create` and the dashboard generate a canonical UUIDv7 before dispatch. The
versioned create request requires that client-proposed identity; it is also the durable creation
key. An exact replay returns the existing schedule without inserting another journal event, even
if its lifecycle has subsequently advanced. The same identity with a different owner, destination,
name, prompt, cron/time-zone, missed/overlap policy, grace, or action opt-in conflicts. Retain the
identity and exact definition when recovering an ambiguous low-level API call; never generate a
new identity as a retry for the same intended schedule.

The driver leases a due occurrence for 30 seconds and admits it with a deterministic idempotency
key. A crash before terminal schedule evidence may reclaim the lease, but session admission is not
duplicated. `latest` and `skip` coalesce downtime to one selected occurrence; there is no unbounded
catch-up mode. `skip-if-running` checks prior admitted work from that schedule before claiming.
Session backpressure and permanent authorization/invariant failures become terminal failed
run-history rows; transient SQLite unavailability leaves the claim recoverable.

Pause stops future claims while retaining the cursor. Resume computes the next future cron instant,
so paused time is not replayed. Cancel is terminal. Do not alter schedule tables directly. Review
nonzero `claimedScheduleRuns` that persist beyond a lease interval and any increase in
`failedScheduleRuns`; inspect exact reasons with `schedule runs`. Safe mode deliberately starts no
schedule driver.

## Installed-program lifecycle

Inspect the program separately from daemon health:

```sh
mealyctl install-status
mealyctl --home "$HOME/.mealy" update
mealyctl --home "$HOME/.mealy" update-status TRANSACTION_UUID
mealyctl repair
mealyctl --home "$HOME/.mealy" rollback
mealyctl --home "$HOME/.mealy" uninstall
```

These commands emit versioned plans and do not mutate by default. Archive status hashes every file
in the release inventory and separately verifies the stable manager against the active or complete
previous slot. `update` downloads and verifies an exact stable release plus its hosted-workflow
attestation before comparing versions and state schemas. Only a strictly newer, same-schema
owner-local target can use `update --approve`. Apply requires the active exact owner service and
delegates to a separate restart-on-failure user-service helper copied and digest-pinned from the
qualified old client. It durably records the target,
creates and verifies an immutable backup, drains to a free home lock, re-verifies and activates the
candidate, restarts, and requires liveness, readiness, `doctor`, exact version/commit, and complete
installed integrity. Failed qualification restores the prior same-schema slot, restarts it, and
still returns a failed update result with rollback evidence. A failure before program mutation is
recorded as `aborted` only after the prior service qualifies; damaged service identity restores the
prior slot when necessary but leaves it stopped as `recovery-failed`. `update-status` reads the mode-`0600`
transaction document after a client or terminal disconnect. Native installs return an `apt`,
`dnf`, or `pacman` handoff and retain root package ownership.

`repair --approve` is intentionally limited to replacing the stable archive manager from its
verified active metadata copy. `rollback --approve` delegates only with two complete slots and
still refuses a lower state schema. `uninstall --approve` removes archive program files while
preserving the entire home and first removes an installed exact generated owner service. Native
uninstall uses the plan's package-manager command, so run the separately reviewed `service remove`
step before handing program files back to the package manager. Preserve a verified backup.

## Migrations, downgrade, and corrupt storage

Before any supported forward migration, startup read-only inspects the old schema and publishes an
online database/config snapshot under `migration-backups/`. Migrations and version markers run in
one immediate SQLite transaction, preserve canonical history, and have forward tests from each
phase snapshot. The public v0.2.1 release schema is 16; the v0.3 development schema is 18.
Schema 15 added the partial
terminal-completion index used by bounded usage reports; migration tests preserve schema-14 state
and assert the query plan uses that index. Schema 16 adds bounded, digest-bound compressed context
manifest bundles plus sparse artifact/compaction/memory provenance. It leaves legacy row-per-item
manifests in place and replayable instead of performing an eager multi-gigabyte rewrite. Provider
requests and validation JSON continue to use compatibility-preserving envelope compression.
Schema 17 adds the reconstructible owner-title projection, immutable exact-bound session
checkpoints, immutable root/parent lineage, duplicate-safe fork command receipts, and bounded
fork-context references. Migration creates root-lineage rows for existing sessions but no owner
title; their deterministic derived titles remain unchanged until the owner renames them. Transcript
exports require no canonical export table: they are bounded coherent read-only projections from
the existing session, turn, attempt, artifact, lineage, and timeline evidence.
Schema 18 adds the canonical revision-fenced session provider-selection projection and immutable
provider/model selection plus resolution source on admitted inputs and promoted turns. It
backfills existing sessions and work as `automatic`, while triggers require complete provider/model
pairs, bind selection events to the exact owner session, prevent later mutation, and require every
promoted turn to match its admitted input. The active provider catalog is a runtime projection and
does not create a second configuration authority. Provider and model identities share the
existing durable attempt/checkpoint bound of 128 UTF-8 bytes, so a configuration cannot activate
an identity that storage would later reject.

## Transactional primary-route promotion

Inspect the active catalog, then review a no-mutation plan:

```sh
mealyctl provider catalog
mealyctl provider switch \
  --provider-id local.responses --model-id local-model
```

The target must be one exact already-configured route. The plan compares the complete config chain
with the authenticated active catalog, stages a full reordered candidate, and reports whether the
verified active Linux owner service can apply it. It never resolves or prints a credential.

Approve only the same exact target:

```sh
mealyctl provider switch \
  --provider-id local.responses --model-id local-model --approve
mealyctl provider switch-status TRANSACTION_ID
```

The client copies its already-verified executable into an owner-private transaction directory and
asks the user service manager to supervise that digest-bound helper. The helper serializes against
program updates, resolves only a brokered credential (or uses a credential-free loopback or
official subscription route), performs the bounded exact-model probe, closes admission, waits for
drain, acquires the stopped-home lock, archives the prior configuration, and atomically installs
the candidate. After restart it requires liveness, readiness, `doctor`, active service identity,
candidate file digest, catalog/status config-digest agreement, unchanged route count, and exact
primary provider/model.

Every phase and immutable snapshot digest is mode-`0600` evidence below
`provider-switch-transactions/`. A crash after file activation but before phase persistence is
recognized from the exact candidate digest when the service manager restarts the helper. Failure
before activation returns `aborted` only after the prior route qualifies. Failure after activation
stops the candidate, restores the exact previous snapshot, restarts, and returns `rolled-back`
only after the old catalog digest and primary identity qualify. `recovery-failed` preserves the
record and journal for manual incident work.

This transaction intentionally reorders rather than edits the active route set, so persisted exact
session defaults cannot become dangling. Chain validation rejects a promotion that would weaken a
fallback trust boundary. Add/remove, endpoint/model, credential, price, locality, and residency
changes remain stopped-daemon configuration operations. Environment-only credential references
are not eligible because the independent helper does not inherit a caller's shell secret.

There is no in-place downgrade and an older binary must never open the newer database. For a
package-managed rollback, inspect the exact automatic snapshot and compare its manifest SHA-256
with the `manifest_digest` recorded by the startup migration event. Then use the installed
manager's explicit cross-schema path:

```sh
SNAPSHOT='v16-to-v18-TIMESTAMP-SEQUENCE'
MANIFEST="$HOME/.mealy/migration-backups/$SNAPSHOT/manifest.json"
DIGEST=$(sha256sum "$MANIFEST" | awk '{print $1}')
jq '{fromSchemaVersion,toSchemaVersion,createdAtMs,files}' "$MANIFEST"

"$HOME/.local/share/mealy-manager.sh" rollback-migration \
  --migration-backup "$SNAPSHOT" \
  --expected-manifest-digest "$DIGEST" \
  --approve --prefix "$HOME/.local" --home "$HOME/.mealy"
```

This stopped-home operation binds the previous/active release schema identities to the snapshot,
holds both installer and daemon locks, and hands the already-held home lock to the verified newer
client over standard input. Before replacement, that client verifies the exact immutable manifest
and files, full older-database integrity and foreign keys, active owner identity, brokered secrets,
and every referenced content-addressed artifact. It reconstructs a complete private sibling home,
locks it, syncs it, and atomically exchanges the two home directories. The complete migrated home
is retained beside the active home, and `migration-rollback-activation.json` records the exact
transition. A failure before exchange leaves the home unchanged and restores the original release
slots. Keep the preserved migrated home until the older daemon passes `health`, `status`, and
`doctor`, and a fresh encrypted backup has been created and verified. For destructive future
changes, use an explicit export/transform/import plan.

The stable manager durably records the verified original slots and request under
`$HOME/.local/share/mealy-rollback-transaction` before exchanging binaries. A hard interruption
releases its file-backed locks without leaving a stale ownership directory. Keep the daemon stopped
and rerun `$HOME/.local/share/mealy-manager.sh` with the same command: it first validates that
record, finalizes a matching completed home exchange, or restores the exact original slots before
retrying. Do not manually remove the transaction directory.

If read-only inspection or normal open detects corrupt SQLite storage, startup copies the original
database plus every existing WAL/SHM sidecar into a timestamped owner-private `forensics/` directory
with a digest manifest. It does not truncate, rebuild, replace, or publish readiness. Repair or
restore begins only after that evidence exists.
