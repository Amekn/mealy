# Threat Model

- Status: baseline for release-one design
Related requirements: `SEC-*`, `AUTH-*`, `TOOL-*`, `EXT-*`

## Security objective

Mealy should let one owner grant useful machine and service capabilities to an unreliable, externally influenced model without silently granting the model the full authority of the owner's OS account.

This is risk reduction, not a claim that arbitrary native code can be perfectly contained on every host. When a profile cannot be enforced, Mealy fails closed or labels an explicit full-trust downgrade.

## Assets

- owner files, repositories, devices, and local services;
- provider, channel, and service credentials, including official-client subscription sessions;
- private conversations, context manifests, memories, and artifacts;
- task/effect/approval integrity;
- daemon configuration, policy, skill/extension manifests, and audit history;
- availability, provider spend, and external service quotas;
- identity mappings between channel users and Mealy principals.

## Actors

| Actor | Default trust |
|---|---|
| Local owner principal | Trusted to administer Mealy; still subject to explicit high-risk confirmation UX |
| Model | Untrusted decision proposer |
| Remote/channel sender | Untrusted until platform verification and binding; then limited to principal grants |
| Retrieved web/file/message content | Untrusted data, even when it comes from an authorized principal |
| Installed skill | Owner-reviewed instructions/passive data; never executable or authority-bearing by itself |
| Delegated child model run | Untrusted bounded computation with explicit isolated context and an intersected read-only grant |
| Built-in compiled adapter | Trusted code, reviewed with the daemon |
| Third-party extension | Untrusted native code confined to its host process and grants |
| Local MCP stdio server | Untrusted owner-selected native code confined to a fresh sandbox and exact schema/tool-set/effect-class grant |
| Remote MCP HTTP server | Untrusted external service confined to an exact endpoint/credential/catalog-item/effect-class grant and bounded fresh session |
| Chrome Headless Shell and rendered page | Untrusted browser/runtime content confined to a fresh agent-only profile, private network namespace, and exact GET/HEAD destination grant |
| Provider/service | External dependency; responses untrusted, credential scope limited |
| Image-generation provider and output | External billable effect; response metadata and binary bytes are untrusted |
| Official subscription client | Trusted owner-installed authentication/transport broker; executable identity pinned, model decision untrusted |
| Sandbox worker | Disposable, lower-trust process |

## Trust boundaries

1. Channel/network to API: signature/token verification, replay protection, size/rate limits.
2. API to application: principal authorization and command validation.
3. Application to provider: privacy routing, secret broker, or exact-digest official subscription client.
4. Application to executor: capability token, sandbox profile, effect ID, fencing token.
5. Application to extension host: manifest grant and versioned RPC.
6. Skill package to context/resource tool: exact inventory/digest verification, separate activation, and bounded reads.
7. MCP server to tool evidence: executable or endpoint/credential authority plus
   full-toolset/schema pinning, exact protocol lifecycle, fresh isolated process or HTTP session,
   bounded arguments/results, cancellation, and cited replay.
8. Parent run to delegated child: explicit work package, read-only capability intersection,
   separate budget, depth zero, durable result fence, and cancellation propagation.
9. Browser/page to evidence: complete runtime pin, private profile/network namespace, scoped
   Unix-socket proxy, GET/HEAD plus upgrade denial, CDP filtering, output normalization, and cleanup.
10. Image-generation provider to artifact: exact approved adapter authority, non-idempotent effect
    fencing, cost/output reservation, bounded response parsing, isolated media normalization, and
    atomic content-addressed settlement.
11. SQLite/artifacts to presentation: authorization and redaction.

Session IDs, task IDs, continuation tokens, and shared gateway secrets are never principal boundaries by themselves.

## Primary threats and controls

### Prompt injection causes a dangerous tool call

Controls: model is untrusted; typed tool schema; default-deny policy; exact approval binding; sandbox enforcement; no ambient credentials; risk-based validation. Prompt filtering may improve UX but is not credited as a boundary.

### Duplicate external effect after crash

Controls: durable intent-before-dispatch; stable idempotency key where supported; effect outcome state; stale-lease fencing; `outcome_unknown` reconciliation; no automatic non-idempotent retry.

### Image generation duplicates spend or publishes hostile output

Controls: image generation is absent by default and exposed only as the exact high-risk
`image.generate` effect. Stopped-home configuration pins one OpenAI Images or OpenRouter Images
protocol, canonical HTTPS origin or literal-loopback HTTP origin, provider/model, opaque
credential reference, residency, JPEG output, size, quality, maximum cost/output bytes, and
deadline. Proxies, redirects, URL-only results, multiple outputs, fallback, edits, masks, and
streaming are disabled. The model supplies only a bounded prompt; trusted normalization injects
the remaining authority, and the durable origin trigger proves both separately.

The immutable run ceiling, policy, and exact owner approval bind the adapter/descriptor digests,
target, network/secret authority, prompt, injected constraints, non-idempotent class, and
never-retry recovery. A complete cost/output reservation exists before the run parks. Denial
settles it at zero and performs no HTTP call. Dispatch records a fenced running attempt first. A
5xx, transport ambiguity, or crash after dispatch parks `outcome_unknown`, conservatively charges
the full approved cost ceiling, and can proceed only through authenticated revision-fenced
external-evidence reconciliation; restart never redispatches.

A confirmed response must contain one bounded base64 body and an in-budget nonnegative reported
cost. The bytes are not decoded in the daemon. A fresh empty-environment, no-network media worker
applies decode/pixel/resource limits and metadata-stripping canonical JPEG re-encoding; the daemon
then rechecks signature, dimensions, digest, media type, and byte ceilings. Outcome, charge,
artifact metadata/reference, and event settle atomically after content-addressed blob publication.
Artifact access is exact-owner authenticated. Recorded replay resolves no credential and makes no
network or approval call; changed/missing prompt, authority, charge, metadata, reference, event, or
blob evidence fails closed. Safe backend storage does not authorize a client to render the bytes.

### Forged approval through a chat message or client history

Controls: approval is an authenticated API command, not model-visible text; it binds the exact effect digest, principal, expiry, and policy version; argument changes invalidate it.

### Channel impersonation

Controls: verify raw request signatures in constant time; derive identity only from verified platform claims; bind platform identity to a principal; reject unbound or revoked identities.

Telegram pairing accepts only a random expiring command from a non-bot sender whose ID and private
chat are exact. Discord pairing independently verifies the bot token, API v10 current-user object,
type-1 DM, and sole non-bot recipient, then accepts the random command only from that recipient and
channel. Runtime Discord messages must repeat the exact channel/author claims, default message
type, and non-webhook/non-bot classification. Platform IDs are canonical decimal strings, not
authorization by possession. Setup and runtime cursors fence old traffic; reservations make crash
replay idempotent; revocation removes future target discovery while retaining evidence.

Slack setup verifies the `xoxb-` bot against `auth.test`, the exact human through `users.info`, the
exact conversation and membership through `conversations.info`, and proves the `xapp-` token can
call `apps.connections.open`. The Socket Mode `hello.connection_info.app_id` must then equal the
bot-token app identity before events are accepted. Routes may share a connection only when owner,
workspace, app, bot, and both secret identities/digests agree. Runtime input repeats the exact
workspace/conversation/member claims and rejects bot, subtype, malformed, or unmentioned shared
messages. Token possession alone is not a local principal boundary.

### Channel backlog, rate, mention, and duplicate-message abuse

Controls: bounded response bytes and record counts; Telegram long-poll limits; Discord full-page
backward traversal to a durable floor; no cursor advance on malformed, oversized, or over-ceiling
history; shared parsing of platform `Retry-After`; long cooldown after invalid Discord authority;
durable queue backpressure; output truncation; Discord `allowed_mentions.parse=[]` and embed
suppression; stable outbox-derived nonce with `enforce_nonce`; exact channel/bot/nonce/message
acknowledgement; and terminal parking when remote acceptance is ambiguous. Attachments in the
Discord DM profile are ignored rather than fetched. Token bytes are header-only and the production
base is the exact official API v10 endpoint, preventing credential exfiltration through an
operator-supplied alternate HTTPS origin.

Slack Web API and Socket Mode use fixed production origins, no proxy, no redirect, bounded HTTP
bodies, and a one-MiB WebSocket message/frame ceiling. The complete normalized admit/ignore
disposition is committed before the Socket Mode acknowledgement; a crash after remote
acknowledgement therefore leaves recoverable local work. Envelope/body drift conflicts rather than
reinterpreting evidence. Outbound messages are control-text escaped, rich parsing/unfurls are
disabled, an exact originating thread is mandatory, per-channel sends are paced, `429 Retry-After`
is bounded, and retries retain the outbox-derived `client_msg_id`. Slack messages are never an
approval authority; approval-looking commands are durably ignored.

### Session-ID authorization bypass

Controls: authorize every query/command using principal/resource grants. IDs are locators only.

### Malicious extension

Controls: data-only manifest inspection; digest/signature pin; out-of-process host; no inherited environment; capability-scoped RPC; resource limits; brokered secrets; kill/revoke without daemon restart.

### Ambient executable or loader environment replaces a trusted sandbox helper

Controls: Bubblewrap and dynamic-linker inspection use exact absolute system paths whose complete
file and directory chains must remain root-controlled. Dynamic runtime discovery invokes only
`/usr/bin/ldd`, clears the inherited environment, sets a deterministic locale, and places `--`
before the already-canonical worker or configured root-controlled command. The daemon does not
search the owner's `PATH` or pass `LD_*` state into this trusted setup step. Missing or unsafe
helpers make the affected tool profile unavailable; they never select an alternate executable or
fall back to unsandboxed dispatch.

### Workspace, extension mount, or local attachment exposes daemon secrets

Controls: the canonical Mealy home and every candidate host root/file are resolved before
authority is published or content is framed. A workspace or extension mount is rejected when it
equals the home, is below it, contains it, is redirected, or is unavailable; daemon startup and
every extension enable/invocation repeat the relevant check. Local text attachments bind the
opened file identity to its canonical path and reject any file below the home before API
admission. Secret access remains a separate broker/reference boundary. The generated Linux unit
does not convert workspace declarations into daemon-level filesystem authority; each governed
worker still receives only its request-specific mounts.

### Malformed image exhausts parsing resources or bypasses durable authority

Controls: the provider-neutral envelope accepts only bounded PNG/JPEG/WebP bytes, binds the
artifact identity, media type, size, and SHA-256 digest, permits images only on authenticated user
messages, caps count and aggregate bytes, charges a conservative per-image token reservation, and
revalidates every field before provider serialization. Text-only routes reject image content
before dispatch. Capability defaults off. An approved stopped-daemon transaction can enable it
only when every configured route is a direct OpenAI Responses or Anthropic Messages route; each
admission still requires an exact provider/model whose capability contract contains image input.
The public API has a separate 6 MiB transport ceiling, accepts only canonical padded base64 and
retry-stable UUIDv7 artifact IDs, and bounds source bytes before decode. The CLI opens only
no-follow regular allowlisted images outside the Mealy home and never submits a host path.

Public ingress delegates every decode to a fresh identity-pinned, empty-environment, no-network
Bubblewrap worker with no home/workspace/secret mount and hard process/protocol limits. The worker
performs dimension/pixel enforcement and metadata-stripping re-encode; the daemon independently
validates the complete returned evidence. This process boundary remains mandatory because
supported decoder release notes acknowledge hostile inputs that can panic decoders.
Content-addressed
commit-before-link admission is now enforced: the private blob is atomically published first and
schema 21 links only contiguous ordered artifacts whose owner, session, inbox origin, producer,
media type, bounds, and access policy match. Admission idempotency binds the exact ordered image
evidence; SQLite triggers reject later media/artifact/content-metadata/reference mutation; and a
late acknowledgement failure rolls every canonical link back while age-gated collection retains a
fresh orphan for recovery.

Context-manifest v3 binds each selected image through a sparse artifact link and reserves 8,192
tokens before dispatch. Trusted hydration rechecks authorization, metadata, digest, and canonical
bytes; missing, dangling, cross-owner, or corrupt evidence fails the turn rather than silently
dropping an image. Recorded-only replay compares the exact normalized request and performs no live
provider or decoder call. Transcript v2 discloses ordered path-free metadata but embeds neither
private paths nor image bytes. TUI, dashboard, chat-native, and channel visual surfaces stay
disabled until they have independent hostile-rendering and retry/recovery evidence. A magic prefix
alone is never accepted as public-ingress proof.

Remote image URLs and provider file IDs are outside the contract, preventing mutable fetches,
ambient network authority, and provider-retention dependence. See
[ADR 0017](decisions/0017-content-addressed-bounded-image-input.md).

### Service supervision hides state or breaks governed workers

Controls: Linux service generation holds the stopped-home lock, canonicalizes every path, and
rejects a home beneath host `/tmp` or `/var/tmp` or on `tmpfs`/`ramfs`, and validates the current
workspace inventory before writing the unit. A custom path must retain the exact `mealy.service`
name and is linked explicitly. `UMask=0077`, socket-family/syscall-ABI/realtime restrictions, and
physical-memory/swap/task/file-descriptor cgroup limits apply without asking the user manager to
create a namespace. The intentional status-2 forced-drain exit is restart-inhibited. The unit
executes the exact configured daemon directly: Ubuntu's reviewed Bubblewrap AppArmor profile
removes capabilities from children of an outer Bubblewrap, so wrapping the daemon would prevent
the required per-request Bubblewrap from constructing its stronger tool boundary. Consequently,
the unit is not a whole-daemon filesystem sandbox; the trusted daemon retains the owner's ambient
read access. Model-selected shell, mutation, MCP, extension, and browser work remains outside the
daemon in fresh fail-closed sandboxes with request-specific mounts and authority.

### Malicious or changed skill package widens authority

Controls: complete no-symlink inventory and exact manifest/asset digest/size checks without code
execution; immutable private publication; install/update disabled; manifest-digest-fenced activation;
startup re-verification; bounded lower-precedence instruction context; passive resources loaded only
through a bounded cited read tool. Required tool contracts are inspection references and never add
tools, workspaces, network, processes, secrets, extensions, or delegation to the capability ceiling.

### Malicious or changed MCP server gains ambient authority

Controls: all transports require explicit selected authority. Native stdio inspection and
activation require an exact canonical ELF and installation publishes owner-private
content-addressed bytes. The negotiated protocol,
complete paginated advertised tool set, each selected full definition, self-contained input/output
schema, direct non-secret arguments, timeout, and output ceiling are pinned. Startup and every call
re-hash and re-discover before dispatch, so missing, extra, or changed tools remove authority.
Annotations are retained as untrusted evidence and never authorize effects. Each discovery/call
uses a fresh Bubblewrap namespace with an empty environment, no network, Mealy home, workspace,
secrets, shell, `PATH`, persistent writable mount, or child-process budget; only the exact server,
launcher, runtime libraries, private `/proc`/`dev`, and ephemeral `/tmp` exist. Hard protocol,
CPU, memory, file, descriptor, process, output, and wall-clock bounds contain failure; cancellation
is signalled and followed by termination. Output is untrusted, schema-checked when declared, cited,
persisted, and replayed without execution. The server still sees arguments deliberately sent to
it, and the host kernel remains the native-code isolation boundary.

Streamable HTTP grants instead pin one canonical HTTPS endpoint (or literal-loopback HTTP), the
exact opaque credential reference, protocol, negotiated capability declarations, complete
tool/resource/resource-template/prompt inventory, and definitions. The owner selects exact tools,
static resource URIs, and prompt names. Resource reads accept no dynamic URI; prompt inputs are
restricted to the advertised string arguments and returned messages are tagged/cited as untrusted
tool evidence, never hidden or system instructions. The destination
and credential reference are cryptographically bound into the durable descriptor and immutable run
ceiling. Resolution rejects mixed/private/reserved answers and pins accepted addresses; proxies and
redirects are disabled. Required Origin/media/protocol/session headers are bounded, bearer and
session values are sensitive zeroizing memory only, and every startup verification or call uses a
fresh session. JSON/SSE parsers reject unsolicited server requests, inventory-change notifications,
invalid correlation, unbounded events, catalog drift, and malformed results. OAuth metadata
inspection sends an unauthenticated bounded probe and validates an advertised protected-resource
metadata URL or both required well-known fallbacks. Metadata fetches reuse the same redirect-free,
proxy-free, SSRF-resistant DNS-pinned boundary; the advertised resource must exactly match the MCP
endpoint, multiple issuers require owner selection, issuer metadata must match that selection, and
authorization-code plus PKCE S256 support is mandatory. Inspection creates no client, state,
verifier, code, token, broker entry, configuration, or authority. A separate approved stopped-home
login accepts only pre-registered public clients advertising token authentication method `none`.
It creates fresh high-entropy state and verifier material, uses only PKCE S256, requests the exact
resource, and accepts only one exact literal-loopback callback with bounded GET headers, Host,
path, unique state/code fields, and no body. Code exchange reuses the pinned network boundary and
accepts only bounded JSON Bearer material with required cache controls and non-broadened scope.
Tokens are zeroized in process memory; the owner-private broker rejects symlink roots/records,
unsafe modes, collisions, oversized records, and non-generation-one creation. The immutable
non-secret grant binds resource, issuer, token endpoint, public client, scope, and metadata digest.
Login changes no configuration or model authority. Separately approved activation revalidates that
grant plus the complete catalog before publishing selected authority. Runtime refresh is
cross-process serialized and generation-fenced; it repeats the exact resource/client, rejects
scope changes and refresh-token reuse, and allows at most one `401`-triggered refresh/retry.
Reference-safe local revocation cannot delete a token used by active configuration. Encrypted
backups and migration recovery validate every record before restoration.

Effect authority is selected by the owner as read-only, idempotent, or non-idempotent; server
annotations remain untrusted hints. Effectful grants require the exact `service_operator` profile
and bind the immutable run ceiling, executable or endpoint identity, credential reference, catalog,
definition/schema, arguments, target, class, recovery, and policy into the descriptor and approval.
The runtime and SQLite prepare boundary recheck that intersection, rediscover immediately before
dispatch, and record a fenced running attempt before the external call. A definite pre-dispatch
failure is terminal. Interrupted idempotent work may create a bounded new fenced attempt with the
same stable key. Non-idempotent transport ambiguity or crash becomes `outcome_unknown`, parks the
task, and requires authenticated revision-fenced owner reconciliation with external evidence.
Replay performs no process, network, token refresh, approval, retry, or effect call. Adversarial
real-process tests prove both crash branches and exact one-dispatch reconciliation.

Issuer-side revocation, dynamic registration/CIMD, scope-challenge parking, resource-template
expansion/subscriptions, resumable GET, and long-lived session health are not yet implemented.

### Parent model delegates hidden context or excess authority

Controls: `agent.delegate` accepts only bounded objective/instructions/criteria and optional object
context; the child receives no implicit parent conversation, memory, approvals, or effect history.
Effective child tools are a fresh read-only intersection of the parent's immutable ceiling and
current runtime policy; mutation/process tools, writable roots, executable identities, and further
delegation are removed. Child limits are separately enforced, launch and parent parking are atomic,
terminal results are fencing-token bound, and parent cancellation propagates before either budget
settles. Owner list/status and root/child recorded replay make the boundary independently auditable.

### Malicious page turns a read-only browser into ambient network or personal-profile authority

Controls: Mealy accepts only a completely inventoried, content-addressed Chrome Headless Shell
bundle whose executable banner and CDP product/protocol identity are pinned. It never launches the
owner's normal browser or profile. Every call uses a new private writable profile inside a fresh
Bubblewrap user/PID/mount/network namespace with an empty environment and no home, workspace,
secret, host browser, or host CDP mount. Chrome can reach only a loopback relay whose Unix socket
terminates at a host policy proxy; the proxy independently applies the persisted web destination
claims, rejects private/mixed DNS except an exact HTTP loopback origin, pins peer addresses, admits
only GET/HEAD or an authorized HTTPS tunnel, and bounds headers, aggregate bytes, time, 32
concurrent connections, and 256 accepted connections per call at both proxy layers. Completed
connection threads are joined during the call rather than retained until shutdown, and a lease
releases the concurrency slot even if a handler unwinds. It intersects those claims with the
initial URL's exact origin for the whole call; a page
cannot pivot through a configured cross-origin redirect, subresource, or accessible link. Fetch
interception rejects every non-GET/HEAD request and authentication. Ambient downloads are denied;
one exact accessible same-origin link may instead use CDP `allowAndName` in a per-call ephemeral
directory. Mealy validates the GUID, caps progress/total/file bytes at 512 KiB, opens with
`NOFOLLOW`, returns digest/base64 evidence, and destroys the profile without mounting an owner
path. Progress counters must be non-negative integral JSON numbers within exact IEEE-754 range;
fractions, negatives, inexact values, and over-limit bytes fail closed. WebSocket, WebTransport,
QUIC, direct sockets, service workers, beacon/native form
submission, and non-read Fetch/XHR are blocked or make the call fail. Exact text filling accepts
only native non-password text controls and uses value setters captured before page code without
dispatching page events. Optional GET submission is reconstructed in Rust from only the selected
named control after same-origin/method/target validation, so hidden/sibling fields and page submit
handlers cannot widen it. HTTPS tunnel contents cannot be classified by
the host proxy alone, so the independent CDP/network/API blocks are part of the browser boundary;
future effectful interaction must not reuse the read-only classification.

Only bounded accessibility text and role/name/occurrence records, final URL/title, exact fill
target/value byte count/digest, optional submitted GET URL, one optional bounded attachment's
URL/size/digest/base64, and an optional validated PNG enter
durable evidence. A submitted URL necessarily contains the selected encoded value; hidden/sibling
control values do not. Raw DOM, CDP, cookies, profile files, and browser stderr do not enter
evidence. The process/profile/socket are destroyed after success, failure, cancellation, or
deadline; recorded replay launches neither Chrome nor network. CPU/process/file/descriptor/output
limits apply per call. Because V8 requires a large virtual address reservation, the supported
systemd deployment applies a physical-memory/task/swap cgroup ceiling to `mealyd` and all children;
a direct launch without an equivalent cgroup is not the fully contained browser deployment. The
native browser and host kernel remain trusted-computing-base risks, so pinned-browser security
updates and the x86_64 conformance job are release requirements.

### Sandbox escape or unsupported policy downgrade

Controls: platform backend tests; deny unsupported profiles; record backend and effective policy; make full-trust explicit; permit optional VM/container backends for stronger isolation.

### Browser page or DNS rebinding steals local operational authority

Controls: the optional operations dashboard is a foreground `mealyctl` adapter on a random numeric
`127.0.0.1` port, never the daemon API itself. It embeds a separate 256-bit lifetime capability in
a no-store page; the daemon bearer is retained only by the CLI process and is never returned in
HTML, JSON, URLs, logs, or browser storage. Every request requires the exact numeric Host, API
access additionally uses constant-time capability validation, and every mutation requires the
exact loopback Origin rather than accepting an Origin-less request. A restrictive CSP,
`frame-ancestors 'none'`, same-origin resource/opener policies, no CORS allowance, 64 KiB request
bodies, canonical UUID route parsing, bounded timelines/evidence, and separate one-at-a-time
snapshot, timeline, detail, and command permits limit compromise. Every ordinary daemon body is
streamed under an 8 MiB ceiling before decode; transcript attachments have a separate 32 MiB
ceiling and are verified before browser download. The adapter exposes only a hard-coded snapshot,
session create/title/checkpoint/fork/input, transcript export, timeline, exact approval-resolution,
cooperative task-cancellation, exact bounded 30-day terminal usage and per-task usage/cost
inspection, effect/attempt inspection,
unknown-effect reconciliation, and exact
schedule-create/detail/run-history/pause/resume/cancel plus fixed governed-memory
namespace/search/detail/propose/activate/correct/pin/expire/reject/delete and bounded extension
inventory/detail/enable/disable/revoke routes; it has no arbitrary proxy, configuration,
credential-value, extension-install/stage/invoke, or
general recovery route. Memory content is capped at 48 KiB, search at 100 results, and list/history
at 1,000 logical records/1,024 immutable revisions. Browser callers cannot supply provenance:
proposal/correction derive a stable hashed owner locator and exact content digest, reconcile it
before manual retry, and activation always records exact-revision owner approval. Schedule
creation accepts only a canonical client-proposed UUIDv7 plus a validated exact definition. The
page retains both after ambiguity; canonical storage returns an identical existing schedule without
another event and rejects same-ID semantic drift. Action-authorized creation requires typed exact
identity confirmation. Schedule history is capped at 100 rows. Extension inventory/history is capped at 1,000/1,024; enable
authority is accepted only when the complete current data-only manifest validates, the required
health capability is present, every selected axis is a subset, and the returned revision +1 grant
matches exactly. Identical completed extension transitions reconcile before dispatch. Lifecycle
mutations bind the exact rendered revision and expected
revision +1 response; cancellation and action-enabled resume require typed identity confirmation,
and ambiguity triggers an evidence re-read rather than a blind retry.
Reconciliation requires two canonical linked IDs, the exact inspected revision, an explicit
terminal conclusion, non-empty bounded external evidence, and exact mutation Origin; the browser
cannot retry the effect itself. Command DTOs reject unknown fields and
input/approval/cancellation/reconciliation retries retain stable idempotency keys. Operators must
not tunnel or expose the port; Ctrl-C destroys the listener and capability.

Usage/cost evidence is copied only from the canonical owner-authorized budget ledger. The aggregate
query binds every child through durable root lineage, accepts at most 31 days, groups terminal runs
by UTC completion day, and rejects residual reservations, unbalanced status totals, malformed UTC
buckets, or non-exact browser integers. The per-task adapter distinguishes used from reserved
microunits. Neither view labels configured provider-neutral microunits as an invoice or infers
unsupported upstream billing axes. Financial reconciliation still requires the provider's records.

### Session metadata, fork, or export is used to smuggle control or inherited authority

Controls: fallback titles are local deterministic projections and never provider output. Owner
titles and checkpoint labels are exact-binding, revision-fenced commands capped at 160 UTF-8 bytes
and 72 Unicode scalar values; controls, bidirectional overrides, zero-width direction controls,
padding, and malformed stored values fail closed before terminal or web rendering. Every accepted
rename appends private journal evidence atomically with the projection.

A checkpoint is created only with an empty durable inbox, no active turn, and no newer
failed/cancelled canonical turn. Its source cursor is captured before its own event and binds the
source session revision, completed turn, immutable context epoch, configuration/policy digests,
workspace identity and owner/channel/workspace authority digest, and provider/model evidence.
Rows are immutable and exact-owner queries are bounded. They contain no bearer, credential,
approval grant, effect permission, lease, reservation, mutable run, pending input, or child state.

A fork command is exact-owner, UUIDv7-keyed, duplicate-safe, and bound to one retained checkpoint.
The new session has empty operational state. It references only the newest contiguous successful
canonical source turns beneath the checkpoint and compaction boundary, capped at 32 turns and
512 KiB. Before any reference enters a model context, compilation requires the fork's current
owner/channel binding and exact context epoch, configuration, policy, workspace identity, and
workspace-authority digest to match the checkpoint. Otherwise all inherited references are
dropped. No source approval, effect permission, lease, reservation, pending input, task, run,
schedule, child state, mutable memory, or channel delivery is cloned.

Transcript export is exact-owner and reads one coherent high-watermark snapshot. It includes only
successful completed canonical turns, capped at the newest contiguous 1,000 turns and 4 MiB of
message content, and reports omissions explicitly. Artifact-backed content is size/digest verified
before hydration. JSON and HTML carry an exact response digest; the CLI and dashboard adapter
verify it before creating or downloading a file. HTML is strict-escaped, scriptless, resource-free,
and served with a deny-all content security policy. The export excludes daemon credentials,
bearers, private artifact paths, provider request envelopes, and tool/effect operational state, but
conversation text is deliberately verbatim and the format says that owner-pasted secrets remain.
Opening an export cannot execute a provider, tool, approval, or effect.

### Full-screen terminal content injects controls or leaves the owner terminal unusable

Controls: `mealyctl tui` requires terminal stdin, stdout, and stderr before any session creation.
Remote titles, provider/model labels, timeline types, payload previews, transcript text, approval
targets, notices, and identifiers pass through bounded control-character-safe rendering; structured
payload previews are capped independently and transcript content is capped by the verified export
schema. Composer input is UTF-8-boundary aware and cannot exceed the daemon's 1 MiB admission
ceiling. Search and rename retain their stricter canonical bounds.

The workbench enters raw alternate-screen mode only through a lifecycle guard, enables bracketed
paste explicitly, and disables paste plus restores the normal screen/raw/cursor state on normal
exit, Ctrl-C, initialization or event failure, persistent daemon loss, and stack unwinding. The
terminal library installs restoration ahead of the prior panic hook. While a local API mutation is
pending, the event loop continues to accept Ctrl-C and drops the request future; the canonical
daemon command remains idempotent/revision-fenced and its state is rediscovered on reopening.
Resize below 60×18 renders a bounded recovery message rather than indexing invalid layout.
Pseudo-terminal process tests exercise non-terminal denial, normal cleanup, stalled-admission
cancellation, bearer absence, and daemon-loss cleanup.

### Provider selection silently changes route, trust, price, or fallback behavior

Controls: the authenticated catalog contains only exact routes in the daemon's active reviewed
configuration. Provider/model labels are bounded and control-free. Limits and prices disclose
their source as `active_configuration`; neither is marked operator-verified without independent
evidence. Health and pressure are process-lifetime observations, not promises.

An exact new-session or per-turn choice must match one active provider/model pair. Session defaults
are exact-owner and revision-fenced. Admission resolves inherited, automatic, or exact scope in the
same transaction as the durable receipt and records the source; promotion must copy the immutable
pair to the turn. Duplicate admission returns the original selection even if the session default
later changes. Restart cannot reinterpret prior work. Exact routing filters candidates to that one
endpoint and disables implicit fallback, while bounded classified retries may reuse the same
endpoint. A changed default applies only to future new turns and cannot rewrite queued, active, or
completed work.

The TUI, dashboard, and scoped-selection CLI are thin clients of these canonical contracts. They
do not edit configuration, broker credentials, or maintain a private routing preference.

Promoting one already-configured compatible automatic route uses a separate plan-first service
transaction. The non-mutating plan requires exact agreement between config and the authenticated
catalog. Approved apply binds immutable prior/candidate snapshots plus daemon/helper digests,
probes the exact model before drain, serializes against program updates, activates only under the
stopped-home lock, and verifies the restarted service, `doctor`, readiness, route count, config
digest, and primary identity. Its service-manager-supervised helper resumes across disconnect or
crash. Pre-activation failure requalifies the original route; post-activation failure restores the
exact prior bytes and original catalog digest before reporting rollback. Environment-only secrets
are rejected because the helper does not inherit caller shell state.

The transient provider-switch and archive-update helpers keep `NoNewPrivileges`, a private umask,
and resource bounds, but create no temporary files and deliberately omit `PrivateTmp`. On some user
managers that setting creates a one-entry user namespace and exposes root-owned `systemctl` through
an overflow identity on a writable root filesystem, causing the helper's trusted-executable check
to reject recovery. Both helpers instead re-verify the canonical root-protected system manager
executable before every service action.

The transaction reorders the complete validated chain and removes no route, so persisted exact
session defaults remain resolvable. Trust-boundary validation rejects unsafe reorderings. Changing
the route set, endpoint, model, credential, configured price, locality, or residency remains a
stopped-daemon operation.

### Subscription bridge steals a session or exposes ambient client tools

Controls: Mealy does not parse, copy, refresh, export, or persist OAuth/session material. The owner
first signs in with the official Codex or Claude client; Mealy invokes only the canonical absolute
client path whose SHA-256 was approved and rechecks that identity before every request. The client
process necessarily retains access to its own owner authentication home and is therefore trusted
code, not a sandbox worker. Its environment is otherwise cleared to a small locale/runtime/auth-home
allowlist; OpenAI, Anthropic, OpenRouter, and private-endpoint API-key variables are never inherited.

Each invocation starts at `/`, loads no project rules, receives the normalized bounded conversation
and Mealy tool descriptions through stdin only, and disables host shell, filesystem, browser,
computer, image, app/connector, subagent, skill-dependency, and session-persistence facilities.
Output must match a fixed structured decision envelope; tool identity must be one Mealy-supplied ID,
JSON arguments must decode to one bounded object, final text and complete usage remain bounded, and
the process is deadline/cancellation/concurrency/rate limited. The configured output-token limit is
an acceptance check over reported usage because these clients do not expose the direct API's exact
upstream maximum-output control. Invalid login, executable drift, nonzero exit, malformed output,
missing usage, or over-limit usage fails closed. Client updates require explicit stopped-home
reactivation. This owner-local convenience is not credited as a service-account, CI, multi-user, or
general API authentication boundary; upstream subscription terms and limits still apply.

### Secret disclosure in prompts or logs

Controls: opaque secret references; broker resolution at invocation; structured redaction before
persistence/presentation; tests over provider payloads, journal, logs, artifacts, and child
environments. Guided setup accepts only an environment-variable name in argv/prompts, reads its
value once after exact approval, uses the normal bounded probe/broker path, and process-tests that
the credential is absent from stdout, stderr, configuration, and rollback history.
The CLI reads `connection.json` only from a canonical, non-symlinked owner-private home, opens the
descriptor itself with no-follow semantics, validates the metadata on that exact file descriptor,
caps it at 64 KiB, and accepts only a 32-byte bearer plus a literal loopback HTTP origin. This
prevents a permissive or redirected parent directory from turning an otherwise private descriptor
check into bearer disclosure.
Dashboard memory explicitly warns that credential-category content is a reference only. The
adapter never accepts arbitrary source locators, but it cannot determine whether owner-entered
content is itself a secret; typed review, sensitivity/category metadata, owner-local exposure, and
documentation remain required controls. The owner-explicit chat `/attach` and `session send-file` paths are also
prompt-visible durable input: it opens a no-follow regular file, enforces a 256-KiB
UTF-8/text-extension ceiling, rejects NUL and symlinks, hashes the exact selected bytes, and sends
only basename/media/size/digest plus content in an untrusted frame. It never transmits the host
path, but cannot determine whether the owner selected a file that contains a secret;
documentation and the local command error boundary warn against credential files.

### Stale worker overwrites newer state

Controls: lease fencing token checked in every result transaction; monotonic revisions; expired
workers cannot commit. Existing-file edits additionally bind the complete approved arguments to
the expected current-content SHA-256 and recheck it through an `openat2`-confined regular-file
descriptor immediately before an atomic replacement. Structured edits also bind the ordered exact
old/new strings and expected non-overlapping occurrence counts; the worker verifies every count in
order and all UTF-8/size bounds before rename. Stale or ambiguous evidence fails without changing
the original.

Path lifecycle operations use a distinct non-idempotent descriptor. File moves/removals bind a
complete-content SHA-256 and every logical target; create/removal of directories is one level and
non-recursive. The worker opens parents beneath the selected root without symlink/mount crossing,
uses no-overwrite rename, and rechecks moved/quarantined bytes after the namespace transition.
Removal quarantines before unlink. A crash after the external boundary is never interpreted as
failure or retried: the effect parks as `outcome_unknown`, the task stops, and only authenticated
owner reconciliation with external evidence can settle it. A preserved quarantine is evidence,
not permission for automatic cleanup.

### Unbounded cost or resource exhaustion

Controls: durable queue caps, rate limits, concurrency limits, provider budgets, step/tool/output
limits, bounded retries, sandbox memory/CPU/time, and backpressure responses. Provider wire bodies
stop at 8 MiB, but that larger transport allowance cannot become canonical agent output: final text
is capped at 64 KiB across the complete response (including every Anthropic content block), and
normalized provider tool arguments stop at 256 KiB. The aggregate streaming counter is updated
before progress emission, so splitting a response into individually valid deltas or blocks cannot
bypass the durable-output boundary. Ordinary `mealyctl` JSON/error decoding also streams into an
8-MiB ceiling instead of trusting `Content-Length` or buffering an arbitrary local response.
Successful client envelopes must carry the exact semantic API version, and structured daemon
errors must carry that version plus bounded canonical codes and single-line terminal-safe
messages. Timeline watching applies the same 8-MiB ceiling to each complete SSE wire event before
the parser can accumulate it, requires strictly increasing matching cursor/type/body identity,
deserializes the typed event, and reserializes terminal-safe JSON instead of printing daemon bytes.
Ordinary local requests have a 30-second whole-request deadline; explicitly long drain, backup,
verification, garbage-collection, and export operations have a ten-minute ceiling, while the
resumable SSE stream reconnects from its durable cursor rather than using a whole-stream deadline.
Provider response metadata is treated as untrusted input too: retained body and header request IDs
must be bounded, trim-clean, and control-free; Responses terminal envelopes must identify the
`response` object and exact configured model; and Anthropic terminal and `message_start` envelopes
must name that same exact configured model. Provider-supplied incomplete reasons and unknown error
metadata are classified into fixed Mealy errors rather than reflected into durable records or
operator output.

### Context or memory crosses principal/workspace boundary

Controls: namespace and authorization filters before relevance scoring; context manifest records inclusion; memory provenance and sensitivity; validator gets separately compiled context.

### Journal/artifact tampering

Controls: OS-user-only storage permissions; immutable journal API; content digests; foreign keys;
backup/restore verification; bounded at-rest compression whose declared and actual decompressed
sizes, UTF-8/JSON shape, and logical digest are rechecked before dispatch/replay; optional encryption
and future hash-chain checkpoints.

### A staging asset substitutes a different release daemon

Controls: the x86-64 soak subject is never selected by a mutable URL, display name alone, or a
workflow artifact from an unrelated run. A checked manifest binds the repository, numeric draft
release ID, dedicated staging tag, exact asset name, observed revision, Linux/x86-64 target, byte count, and SHA-256. The
authenticated release API must report one uploaded asset with that exact name, owner uploader,
size, and digest on a non-prerelease private draft; the downloaded bytes are independently sized
and hashed. Because draft visibility requires push-level access, only a short promotion job has
the ephemeral `contents: write` token. It validates the subject before handing it through a
one-day artifact that can only be downloaded from the same workflow run; downstream build jobs
retain `contents: read` and independently recheck file type, size, and digest before atomic
executable installation. The full soak validator then binds that same
binary's digest and version to the report. RustSec binary audit, real service execution, SBOM,
package checksums, GitHub provenance attestations, immutable release creation, and public
clean-host install tests all occur after promotion. The draft asset and current-run artifact are
transport, not authority: mutating or replacing either cannot satisfy the committed digest.

## Explicit non-boundaries

- prompt instructions;
- model self-critique;
- regex command classifiers;
- a human-readable warning without enforced policy;
- a tool allowlist when arbitrary unsandboxed shell remains available;
- a plugin manifest if plugin code still runs with daemon authority;
- a continuation token without principal authentication;
- output redaction as protection against a malicious process that already holds the secret.

## Release-one security gates

- No model-proposed mutation runs inside `mealyd`.
- Unsupported sandbox profiles fail closed in integration tests on each platform lane.
- Approval mutation/tampering tests cover every bound field.
- Duplicate delivery and stale lease tests prove no unauthorized transition.
- Provider payload and child environment tests prove secret minimization.
- Extension-host crash and malicious-request fixtures cannot stop or bypass the daemon.
- MCP fixtures prove stdio network/filesystem/environment/process isolation plus HTTP
  SSRF/redirect/credential/session confinement, framing and output bounds, complete-catalog
  executable/endpoint drift denial, cancellation, daemon survival, and zero-execution replay.
  OAuth fixtures additionally prove bounded challenge parsing, path/root and OAuth/OIDC discovery
  order, exact resource/issuer binding, explicit multi-issuer selection, PKCE S256 enforcement, and
  metadata inspection without home or broker mutation.
- Image-generation process tests prove approval and immutable budget reservation before one
  dispatch, denial without dispatch, exact pinned provider requests, bounded isolated JPEG
  normalization, atomic private artifact settlement, crash-after-dispatch with zero retry and
  conservative full-cost accounting, explicit reconciliation, recorded-only replay, and
  missing-blob corruption denial.
- The pinned real Headless Shell gate proves fresh-profile/CDP identity, rendering, safe exact-link
  same-origin navigation, exact form-free button activation plus submit-button denial, native
  text-control fill plus selected-field-only GET and POST/password/hidden-field denial, one bounded
  GUID-confined attachment plus oversized/ambient-download denial, screenshot
  bounds, non-read/WebSocket denial, model-visible citation,
  complete bundle backup/recovery, and replay after runtime deletion.
- API binds loopback only and rejects missing credentials and disallowed Origins.
- The dashboard process test proves exact Host/Origin/token enforcement, DNS-rebinding rejection,
  no daemon-bearer disclosure, fixed snapshot/timeline aggregation, exact typed command forwarding,
  stable idempotency, subject-digest binding, exact schedule identity/revision/status validation,
  malformed/oversized/arbitrary-route denial before daemon access, CSP/no-store headers, and
  lifetime cleanup.

## Deferred risks

Multi-tenant adversarial hosting needs stronger tenant encryption, resource fairness, administrative separation, and probably separate OS identities or machines. This architecture preserves principal namespaces but does not claim release-one is a hostile multi-tenant boundary.
