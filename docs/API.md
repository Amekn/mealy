# Local API reference

Mealy exposes a versioned HTTP/JSON and Server-Sent Events API for owner-local integrations. The
supported release-one API version is `v1`. `mealyctl` is the preferred interactive client; direct
API clients are appropriate when they preserve the authentication, versioning, idempotency, and
cursor rules described here.

The transport DTOs are defined and documented in `crates/mealy-protocol/src/lib.rs`. Build the
complete Rust API documentation with:

```sh
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
```

Open `target/doc/mealy_protocol/index.html` for request/response fields and
`target/doc/mealy_api/index.html` for the adapter contract. JSON field names are `camelCase` unless
a documented enum uses `snake_case`. Mutation bodies reject unsupported `apiVersion` values, and
most command DTOs reject unknown fields.

Before changing a public route, run
`scripts/validate-documentation.py --cli target/debug/mealyctl`. The protected documentation gate
compares this reference with every registered Axum method/path pair, so both an undocumented route
and a stale documented route fail CI.

## Connection and authentication

`mealyd` binds only to a loopback address. On startup it writes an owner-only connection descriptor
to `$MEALY_HOME/connection.json` (default `~/.mealy/connection.json`):

```json
{
  "apiVersion": "v1",
  "baseUrl": "http://127.0.0.1:37281",
  "bearerToken": "base64url-encoded-32-byte-token",
  "principalId": "opaque-principal-id",
  "channelBindingId": "opaque-binding-id"
}
```

Treat the entire file as a secret. Do not copy it into logs, command history, bug reports, URLs, or
browser storage. All routes except signed webhook delivery require exactly one header of the form
`Authorization: Bearer TOKEN`. An absent or malformed credential returns `401`; a valid credential
that does not own a resource returns a safe `403` response. Browser-origin requests are rejected
unless that exact origin is configured. Requests without an `Origin` header are permitted.

This example reads the protected readiness endpoint without placing the token itself in the shell
command line:

```sh
connection=${MEALY_HOME:-$HOME/.mealy}/connection.json
base_url=$(jq -er '.baseUrl' "$connection")
token=$(jq -er '.bearerToken' "$connection")
curl --fail-with-body --silent --show-error --config - <<EOF
url = "$base_url/health/ready"
header = "Authorization: Bearer $token"
EOF
unset token
```

The default maximum request body is 1 MiB. The daemon bounds concurrent commands and timeline
subscribers; excess work fails quickly with `429` instead of accumulating an unbounded queue.
Artifact-content responses are binary, use the committed media type, and set `Cache-Control:
no-store`, `X-Content-Type-Options: nosniff`, and attachment disposition.

## Common request flow

Create a session, submit an idempotent input, and read its durable timeline:

```sh
connection=${MEALY_HOME:-$HOME/.mealy}/connection.json
base_url=$(jq -er '.baseUrl' "$connection")
token=$(jq -er '.bearerToken' "$connection")

session=$(curl --fail-with-body --silent --show-error --config - <<EOF
url = "$base_url/v1/sessions"
request = "POST"
header = "Authorization: Bearer $token"
header = "Content-Type: application/json"
data = "{\"apiVersion\":\"v1\"}"
EOF
)
session_id=$(jq -er '.sessionId' <<EOF
$session
EOF
)

curl --fail-with-body --silent --show-error --config - <<EOF
url = "$base_url/v1/sessions/$session_id/inputs"
request = "POST"
header = "Authorization: Bearer $token"
header = "Content-Type: application/json"
data = "{\"apiVersion\":\"v1\",\"idempotencyKey\":\"example-001\",\"deliveryMode\":\"queue\",\"content\":\"Summarize my granted workspace.\"}"
EOF

curl --fail-with-body --silent --show-error --config - <<EOF
url = "$base_url/v1/sessions/$session_id/timeline?after=0&limit=100"
header = "Authorization: Bearer $token"
EOF
unset token
```

Retry a mutation only with the same idempotency key and identical semantic payload. Use a new key
for a new command. The delivery modes are `queue`, `steer_at_boundary`, and
`interrupt_then_queue`.

`ProviderSelectionCommand` is a tagged object: `{"mode":"automatic"}` or
`{"mode":"exact","providerId":"…","modelId":"…"}`. Create-session and input requests may omit it.
An omitted input choice inherits the canonical session default; explicit `automatic` overrides an
exact default for that turn. The admission receipt always returns the resolved choice and its
stable `inherited`, `automatic`, or `exact` source. Resolution is committed with admission and is
immutable across queueing, promotion, duplicate retry, and restart.

The catalog exposes only routes in the active reviewed configuration. It reports capability,
locality, health, pressure, configured limits/prices, and provenance; unverified configured values
remain explicitly unverified. An exact choice must match one selectable catalog route and disables
implicit fallback for that turn, though bounded classified retry may reuse that same endpoint.
Changing a session default requires its exact current revision and applies only to future new
turns. Catalog or selection routes never change endpoints, credentials, prices, locality, or
residency.

## Endpoints

Request and response names below refer to public types in `mealy_protocol`. `-` means there is no
JSON request body. Path IDs are opaque and must not be parsed for policy decisions.

### Health, sessions, tasks, and evidence

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/health/live` | - | `HealthResponse` |
| `GET` | `/health/ready` | - | `ReadinessResponse` |
| `GET` | `/v1/providers/catalog` | - | `ProviderCatalogResponse` |
| `GET` | `/v1/sessions` | `limit` (default 20, 1–100) | `SessionsResponse` |
| `POST` | `/v1/sessions` | `CreateSessionRequest` | `CreateSessionResponse` |
| `GET` | `/v1/sessions/search` | `query`, optional `limit` (default 20, 1–100) | `SessionSearchResponse` |
| `PATCH` | `/v1/sessions/{session_id}` | `UpdateSessionTitleRequest` | `SessionTitleResponse` |
| `GET` | `/v1/sessions/{session_id}/checkpoints` | optional `limit` (default 20, 1–100) | `SessionCheckpointsResponse` |
| `POST` | `/v1/sessions/{session_id}/checkpoints` | `CreateSessionCheckpointRequest` | `SessionCheckpointResponse` |
| `POST` | `/v1/sessions/{session_id}/forks` | `ForkSessionRequest` | `SessionForkResponse` |
| `GET` | `/v1/sessions/{session_id}/exports/json` | - | JSON transcript attachment |
| `GET` | `/v1/sessions/{session_id}/exports/html` | - | inert HTML transcript attachment |
| `POST` | `/v1/sessions/{session_id}/inputs` | `SubmitInputRequest` | `InputAdmissionResponse` |
| `POST` | `/v1/sessions/{session_id}/image-inputs` | `SubmitImageInputRequest` | `InputAdmissionResponse` |
| `GET` | `/v1/sessions/{session_id}/provider-selection` | - | `SessionProviderSelectionResponse` |
| `PATCH` | `/v1/sessions/{session_id}/provider-selection` | `UpdateSessionProviderSelectionRequest` | `SessionProviderSelectionResponse` |
| `GET` | `/v1/sessions/{session_id}/status` | - | `SessionStatusResponse` |
| `GET` | `/v1/sessions/{session_id}/timeline` | optional `after`, optional `limit` | `TimelinePageResponse` |
| `GET` | `/v1/sessions/{session_id}/events` | optional `after`, optional `limit`; SSE | timeline events |
| `POST` | `/v1/sessions/{session_id}/compactions` | `CreateCompactionRequest` | `CompactionResponse` |
| `GET` | `/v1/compactions/{compaction_id}` | - | `CompactionResponse` |
| `GET` | `/v1/tasks/{task_id}` | - | `TaskResponse` |
| `POST` | `/v1/tasks/{task_id}/cancel` | `CancelTaskRequest` | `TaskCancellationReceipt` |
| `POST` | `/v1/tasks/{task_id}/pause` | `ControlTaskRequest` | `TaskControlReceipt` |
| `POST` | `/v1/tasks/{task_id}/resume` | `ControlTaskRequest` | `TaskControlReceipt` |
| `GET` | `/v1/tasks/{task_id}/replay` | - | `TaskReplayResponse` |
| `GET` | `/v1/delegations` | optional `limit` (default 20, 1–100) | `DelegationsResponse` |
| `GET` | `/v1/delegations/{delegation_id}` | - | `DelegationResponse` |
| `GET` | `/v1/context-manifests/{manifest_id}` | - | `ContextManifestEvidenceResponse` |
| `GET` | `/v1/artifacts/{artifact_id}` | - | `ArtifactMetadataResponse` |
| `GET` | `/v1/artifacts/{artifact_id}/content` | - | bounded artifact bytes |

The optional v0.4 `image.generate` tool has no unauthenticated or direct “generate now” HTTP
shortcut. An ordinary agent turn may propose it, then the existing approval/effect endpoints expose
the exact subject and lifecycle. A confirmed result is an owner-private canonical JPEG artifact
whose ID appears in the recorded tool observation. The two artifact routes above return its
path-free metadata and bounded digest-verified bytes under the same owner/channel authorization.
Recorded replay reads that evidence only and never contacts the image provider.

`SessionsResponse` includes one bounded `title` and a `titleSource` of `owner` or `derived` for
each exact-binding session. Before an owner title exists, this is a deterministic, control-free
projection of the first canonical owner input and is `New conversation` before the first input.
Search hits include the same values as `sessionTitle` and `sessionTitleSource`; deriving a fallback
makes no provider request and creates no canonical mutation.

An owner title update supplies the exact observed `expectedRevision`. It atomically commits the
bounded title, advances the session revision, and appends `session.title_updated`; a stale
revision returns `409` without changing the projection. Titles are 1–160 UTF-8 bytes, at most 72
Unicode scalar values, trimmed, and reject terminal controls, bidirectional overrides, and
zero-width direction controls.

A checkpoint request also supplies `expectedRevision` and an optional title-safe label.
Checkpoint creation is accepted only when the durable inbox is empty, no turn is active, and the
newest canonical turn—if any—completed successfully. The immutable response binds the timeline
high watermark before the checkpoint event, source turn, context epoch, configuration and policy
digests, workspace identity and authority digest, latest provider/model identity, source session
revision, creation event, and time. A checkpoint never copies or grants authority. List responses
are newest first.

A fork request binds the source session, exact retained checkpoint, a caller-generated UUIDv7
idempotency key, and an optional title. An exact retry returns the original receipt; reuse with
different semantics conflicts. The new session begins with an empty inbox and no active task,
lease, reservation, approval, effect, outbox delivery, schedule, child run, or mutable memory. Its
immutable lineage references only the newest contiguous eligible source evidence under the
checkpoint and current compaction boundary, capped at 32 turns and 512 KiB. Context construction
rechecks the fork's current owner, context epoch, configuration, policy, workspace identity, and
workspace-authority digest before using those references. A mismatch drops the referenced
conversation instead of inheriting stale authority.

Transcript exports are exact-owner, read-only projections of successful completed canonical turns.
They return the newest contiguous tail under 1,000 turns and 4 MiB of combined user/assistant
content, with explicit eligible, included, and omitted counts. JSON uses
`mealy.session-transcript.v2`; readers may continue to accept the text-only v1 schema. Each
image-bearing user message carries only ordered path-free canonical evidence: artifact ID, media
type, SHA-256, byte count, width, and height. Image bytes and host paths are never embedded. HTML is
rendered from the same model with strict escaping, no active content or remote resources, and a
deny-all content security policy. Both attachments include an exact SHA-256 in
`x-mealy-content-sha256` and use `Cache-Control: no-store`. Exported conversation messages are
owner-visible verbatim evidence and can contain secrets the owner pasted into chat; the export
excludes daemon credentials, bearer tokens, private artifact paths, provider request envelopes,
image bytes, and effect/tool operational state. Reading an export never replays a model call or
effect.

Image input is a separately activated v0.4 surface. `SubmitImageInputRequest` contains the normal
`apiVersion`, stable `idempotencyKey`, `deliveryMode`, and bounded UTF-8 `content`, plus an exact
`providerSelection` (`mode: "exact"`, `providerId`, and `modelId`) and one to four ordered
`images`. Each image supplies a retry-stable client UUIDv7 `artifactId`, a claimed source
`mediaType` (`image/png`, `image/jpeg`, or `image/webp`), and standard padded `dataBase64`. Remote
URLs and provider file IDs are unsupported. The route has a 6 MiB transport limit; source images
are capped at 2 MiB each and 4 MiB in aggregate before isolated decode/re-encode. Success returns
the canonical normalized artifact identities in `imageArtifactIds`. An exact retry returns those
same identities with `duplicate: true`; changing any input evidence under the same delivery key
conflicts.

The daemon admits this request only when `imageInputEnabled` was explicitly activated while
stopped, every configured route uses direct OpenAI Responses or Anthropic Messages, and the exact
selected route advertises image input. Normalization happens in a fresh no-network Bubblewrap
worker before durable admission. The TUI and dashboard are bounded adapters over this exact
endpoint: neither creates alternate media state, and dashboard preview revalidates the canonical
artifact metadata/content endpoints before rendering. Line chat and channel upload are not part of
this surface.

### Schedules, automations, and governed memory

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/schedules` | - | `SchedulesResponse` |
| `POST` | `/v1/schedules` | `CreateScheduleRequest` | `ScheduleResponse` |
| `GET` | `/v1/schedules/{schedule_id}` | - | `ScheduleResponse` |
| `POST` | `/v1/schedules/{schedule_id}/pause` | `ScheduleLifecycleRequest` | `ScheduleResponse` |
| `POST` | `/v1/schedules/{schedule_id}/resume` | `ScheduleLifecycleRequest` | `ScheduleResponse` |
| `POST` | `/v1/schedules/{schedule_id}/cancel` | `ScheduleLifecycleRequest` | `ScheduleResponse` |
| `GET` | `/v1/schedules/{schedule_id}/runs` | optional `limit` (default 100) | `ScheduleRunsResponse` |
| `GET` | `/v1/automations` | - | `AutomationsResponse` |
| `POST` | `/v1/automations` | `CreateAutomationRequest` | `AutomationResponse` |
| `GET` | `/v1/automations/{automation_id}` | - | `AutomationResponse` |
| `PATCH` | `/v1/automations/{automation_id}` | `EditAutomationRequest` | `AutomationResponse` |
| `POST` | `/v1/automations/{automation_id}/pause` | `AutomationLifecycleRequest` | `AutomationResponse` |
| `POST` | `/v1/automations/{automation_id}/resume` | `AutomationLifecycleRequest` | `AutomationResponse` |
| `POST` | `/v1/automations/{automation_id}/cancel` | `AutomationLifecycleRequest` | `AutomationResponse` |
| `GET` | `/v1/automations/{automation_id}/runs` | optional `limit` (default 100) | `AutomationRunsResponse` |
| `GET` | `/v1/memories` | `workspaceIdentity`, optional `includeDeleted` | `MemoriesResponse` |
| `POST` | `/v1/memories` | `ProposeMemoryRequest` | `MemoryResponse` |
| `GET` | `/v1/memories/search` | `workspaceIdentity`, `query`, optional `maximumSensitivity`, optional `limit`, optional `retrievalMode` | `MemorySearchResponse` |
| `GET` | `/v1/memories/{memory_id}` | `workspaceIdentity` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/activate` | `PromoteMemoryRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/correct` | `CorrectMemoryRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/pin` | `SetMemoryPinRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/expire` | `MemoryLifecycleRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/reject` | `MemoryLifecycleRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/delete` | `MemoryLifecycleRequest` | `MemoryResponse` |
| `POST` | `/v1/memory-index/rebuild` | `RebuildMemoryIndexRequest` | `MemoryIndexRebuildResponse` |

`CreateAutomationRequest.automationId` is a canonical client-proposed UUIDv7 and durable creation
key. Exact retries return the current projection even after the due time, event-cursor movement, or
lifecycle advancement; a semantic mismatch conflicts. One-shot times are UTC epoch milliseconds.
Event triggers observe one exact future direct-session event type after an exclusive cursor and
accept only a static notification action. Edit and lifecycle requests carry the exact current
revision. See [the automation contract](AUTOMATION.md).

`retrievalMode` defaults to `lexical`. `hybrid` requests an explicitly configured semantic path
and never silently claims it was used: the response returns actual `retrievalMode` as `hybrid` or
`lexical_fallback`, plus `semanticStatus` as one of `healthy`, `disabled`, `not_built`, `stale`,
`degraded`, `embedding_unavailable`, or `incompatible`. Hits retain the complete cited canonical
`memory` projection and may include `lexicalRank`, `semanticSimilarity`, and deterministic
`fusedRankScore`. Namespace, ownership, active status, sensitivity, and content-digest checks run
before either rank contributes.

`RebuildMemoryIndexRequest` accepts `{ "apiVersion": "v1", "semantic": true }`. Lexical rebuild
always occurs first. Semantic rebuild is accepted only when the daemon has an explicit embedding
privacy policy; it snapshots every active revision for that authenticated principal, embeds
bounded batches outside the writer, and atomically replaces the complete derived set under exact
revision/content/configuration fences. Its optional `semanticIndex` receipt reports the fixed
status, non-secret policy digest, dimensions, active-revision count, last successful rebuild, and
safe error code. Endpoint failure can yield a degraded semantic receipt while canonical lexical
memory remains usable. See [the semantic-memory guide](SEMANTIC_MEMORY.md).

### Approvals, effects, and extensions

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/approvals` | - | `PendingApprovalsResponse` |
| `POST` | `/v1/approvals/{approval_id}/resolve` | `ResolveApprovalRequest` | `ApprovalResolutionReceipt` |
| `GET` | `/v1/effects/{effect_id}` | - | `EffectResponse` |
| `GET` | `/v1/effect-attempts/{attempt_id}` | - | `EffectAttemptResponse` |
| `POST` | `/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile` | `ReconcileEffectRequest` | `EffectReconciliationReceipt` |
| `GET` | `/v1/extensions` | - | `ExtensionsResponse` |
| `POST` | `/v1/extensions` | `InstallExtensionRequest` | `ExtensionResponse` |
| `GET` | `/v1/extensions/{extension_id}` | - | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/stage` | `StageExtensionManifestRequest` | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/enable` | `EnableExtensionRequest` | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/disable` | `ExtensionLifecycleRequest` | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/revoke` | `ExtensionLifecycleRequest` | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/invoke` | `InvokeExtensionRequest` | `ExtensionInvocationResponse` |

Each `ExtensionManifestRevisionResponse` may include a `registry` object containing the exact
`registryId`, `packageId`, `version`, `releaseEnvelopeDigest`, and `archiveDigest` retained for a
signed-registry installation. Internal package paths remain omitted. Registry policy is enforced
server-side before enablement and invocation; non-authorized evidence returns the normal conflict
boundary without executing extension code.

### Channel administration

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/channels/webhooks` | - | `WebhookChannelsResponse` |
| `POST` | `/v1/channels/webhooks` | `CreateWebhookChannelRequest` | `CreateWebhookChannelResponse` |
| `GET` | `/v1/channels/webhooks/{binding_id}` | - | `WebhookChannelResponse` |
| `POST` | `/v1/channels/webhooks/{binding_id}/revoke` | `RevokeWebhookChannelRequest` | `WebhookChannelResponse` |
| `GET` | `/v1/channels/telegram` | - | `TelegramChannelsResponse` |
| `POST` | `/v1/channels/telegram` | `CreateTelegramChannelRequest` | `TelegramChannelResponse` |
| `GET` | `/v1/channels/telegram/{binding_id}` | - | `TelegramChannelResponse` |
| `POST` | `/v1/channels/telegram/{binding_id}/revoke` | `RevokeTelegramChannelRequest` | `TelegramChannelResponse` |
| `GET` | `/v1/channels/discord` | - | `DiscordChannelsResponse` |
| `POST` | `/v1/channels/discord` | `CreateDiscordChannelRequest` | `DiscordChannelResponse` |
| `GET` | `/v1/channels/discord/{binding_id}` | - | `DiscordChannelResponse` |
| `POST` | `/v1/channels/discord/{binding_id}/revoke` | `RevokeDiscordChannelRequest` | `DiscordChannelResponse` |
| `GET` | `/v1/channels/slack` | - | `SlackChannelsResponse` |
| `POST` | `/v1/channels/slack` | `CreateSlackChannelRequest` | `SlackChannelResponse` |
| `GET` | `/v1/channels/slack/{binding_id}` | - | `SlackChannelResponse` |
| `POST` | `/v1/channels/slack/{binding_id}/revoke` | `RevokeSlackChannelRequest` | `SlackChannelResponse` |
| `GET` | `/v1/channels/slack/{binding_id}/remote-continuations` | - | `SlackRemoteContinuationsResponse` |
| `POST` | `/v1/channels/slack/{binding_id}/remote-continuations` | `CreateSlackRemoteContinuationRequest` | `SlackRemoteContinuationResponse` |
| `GET` | `/v1/channels/slack/{binding_id}/remote-continuations/{remote_continuation_id}` | - | `SlackRemoteContinuationResponse` |
| `POST` | `/v1/channels/slack/{binding_id}/remote-continuations/{remote_continuation_id}/revoke` | `RevokeSlackRemoteContinuationRequest` | `SlackRemoteContinuationResponse` |

The ingress-only `POST /v1/channels/webhooks/{binding_id}/deliveries` route does not accept the
local bearer. It requires exactly one `X-Mealy-Timestamp`, `X-Mealy-Nonce`, and
`X-Mealy-Signature` header. The signature is lower-case HMAC-SHA256 over the exact configured
framing and raw body. Use the binding-time client contract; do not reconstruct the framing from
this summary. Authentication and replay checks occur before JSON parsing.

Slack administration is local-bearer authenticated. Creation accepts Socket Mode `xapp-` and bot
`xoxb-` credentials only over the loopback API, live-verifies the bot, workspace, app, member, and
conversation, proves the app token can open Socket Mode, then brokers both token values outside
SQLite. Responses expose only identity pins, lifecycle, revision, and secret-free health. Socket
Mode itself is an outbound daemon connection: no public Slack webhook route is opened.

A Slack remote-continuation creation carries a canonical client-proposed UUIDv7, an exact
previously admitted thread root, and an exclusive expiry between one minute and 30 days after
creation. The route captures a no-replay timeline cursor, permits only proactive static
`automation.notification` output, and is terminally revision-fenced on revoke. Slack automation
requests must include the exact active `remoteContinuationId`; it is invalid for non-Slack targets
or prompt actions. Delivery revalidates the declared route and never selects a newer thread. See
[the remote-continuation contract](REMOTE_CONTINUATION.md).

### Administration

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/admin/status` | - | `AdminStatusResponse` |
| `GET` | `/v1/admin/metrics` | - | `AdminMetricsResponse` |
| `GET` | `/v1/admin/usage` | `fromMs`, `toMs` | `AdminUsageReportResponse` |
| `GET` | `/v1/admin/doctor` | - | `DoctorResponse` |
| `POST` | `/v1/admin/drain` | `DrainDaemonRequest` | `DrainDaemonResponse` |
| `POST` | `/v1/admin/backups` | `CreateBackupRequest` | `BackupResponse` |
| `POST` | `/v1/admin/backup-verifications` | `VerifyBackupRequest` | `BackupVerificationResponse` |
| `POST` | `/v1/admin/artifact-gc` | `RunGarbageCollectionRequest` | `GarbageCollectionResponse` |
| `POST` | `/v1/admin/exports` | `CreateExportRequest` | `ExportResponse` |

`AdminStatusResponse` includes the effective provider/model and route health plus the effective
context limit, maximum output limit, provider-owned input-token overhead, and configured
input/output microunit prices. These secret-free capability fields let first-party clients explain
the active model boundary without reopening private configuration or guessing from a provider
catalog.

During safe mode or graceful drain, non-GET commands fail with retryable `503` except the bounded
maintenance commands for drain, backup, backup verification, and export.

## Timeline SSE and resumption

`GET /v1/sessions/{session_id}/events` returns `text/event-stream`. Supply the last durable cursor
as either `after=N` or `Last-Event-ID: N`; the query value takes precedence. Each event has:

- `id`: the decimal durable cursor;
- `event`: the stable timeline event type;
- `data`: one JSON `TimelineEvent`.

The server sends a keep-alive comment every 15 seconds. Persist a cursor only after the event has
been processed. Reconnect with that cursor; consumers must tolerate exact redelivery. A cursor
ahead of canonical state or older than retained history returns a conflict (`timeline_cursor_ahead`
or `timeline_gap`). SSE error events carry the same `ApiErrorResponse` JSON envelope and terminate
the stream.

## Errors and retry policy

JSON errors have this stable shape:

```json
{
  "apiVersion": "v1",
  "code": "invalid_request",
  "message": "safe bounded detail",
  "retryable": false
}
```

| HTTP | Typical code | Meaning |
| --- | --- | --- |
| `400` | `invalid_request` | Malformed query/body, unsupported version, or failed command validation |
| `401` | `invalid_credential` | Local bearer missing or invalid |
| `403` | `origin_forbidden`, `unauthorized` | Origin denied or authenticated identity lacks ownership |
| `404` | `not_found` | Route or owned resource not found |
| `405` | `method_not_allowed` | Wrong HTTP method |
| `409` | `conflict`, `timeline_gap`, `timeline_cursor_ahead` | Revision, state, or cursor conflict |
| `413` | `payload_too_large` | Request exceeds the configured body limit |
| `429` | `busy` | Bounded concurrency is exhausted; retryable |
| `503` | `unavailable`, `admission_closed` | Dependency unavailable, safe mode, or drain; retryable where marked |
| `500` | `internal` | Safe internal failure |

Use the response's `retryable` value, bounded exponential backoff, and a retry ceiling. Never
blindly retry a mutation with a new idempotency key. Do not infer authorization state from the
difference between `403` and `404`.

## Typed Rust client

`crates/mealy-client` provides the first stable SDK over these exact DTOs. `MealyClient` is a
blocking client intended for owner-local integrations and later HTTPS-protected single-owner
continuation. It covers health/status, providers, session workbench, approvals, complete
automation lifecycle/history, extensions, and webhook, Telegram, Discord, and Slack
administration. Session workbench includes text/image admission plus task status, pause, resume,
cancellation, recorded replay, and read-only list/detail inspection of durable child delegations.
Import DTOs through `mealy_client::protocol` so client and wire-contract versions remain
coordinated.

The SDK accepts clear-text HTTP only for literal `127.0.0.0/8` or `::1` addresses and requires
HTTPS elsewhere. URL credentials, base paths, queries, and fragments are invalid. Ambient proxies
and redirects are disabled, bearer headers and debug output are redacted, request and response
versions are checked, typed JSON commands have a fixed 8 MiB pre-dispatch ceiling and zeroizing
source buffer, and JSON responses are streamed into an 8 MiB default ceiling rather than trusted
from `Content-Length`. The response ceiling can be lowered or raised to at most 64 MiB through the
builder. `MealyClient::from_connection` accepts an already trusted `LocalConnectionInfo`; it does
not open `connection.json`, so an embedding application must retain Mealy's owner-private,
no-symlink file boundary when loading that descriptor.

See [`../crates/mealy-client/README.md`](../crates/mealy-client/README.md) and generated Rustdoc for
the operation, packaged-release, and error contracts. Timeline SSE is not part of this blocking
SDK; use bounded timeline pages or the documented raw SSE contract.

## Compatibility contract

Clients must send `apiVersion: "v1"` on mutation DTOs and require `apiVersion == "v1"` in JSON
responses. Additive response fields may appear within `v1`; tolerant readers should ignore fields
they do not use. Field removal, semantic reinterpretation, or incompatible enum changes require a
new API version. The authoritative compatibility tests live in `mealy-api`, `mealy-protocol`, the
frozen v0.2.1/v0.3/v0.4/v0.5 `mealy-client` daemon fixtures, the clean packaged-consumer proof,
and the real-daemon public-API scenario suites described in [TESTING.md](TESTING.md).
