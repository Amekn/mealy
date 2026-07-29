# Mealy v0.3–v0.5 production roadmap

Status: active
Baseline: public v0.2.1 Linux production release
Primary product: single-owner, provider-neutral, local-first Linux agent

## Outcome

Mealy will progress through three independently releasable production milestones:

- **v0.3 — daily-use parity:** make ordinary conversation, navigation, review, and
  provider selection as approachable as the strongest terminal-first agents.
- **v0.4 — governed capability breadth:** add broader delegation, MCP, media,
  browser, and work-channel capabilities without creating alternate authority or
  recovery paths.
- **v0.5 — ecosystem maturity:** make extensions, memory, automation, SDK use,
  observability, evaluation, and remote continuation safe to adopt and maintain.

Each version remains useful and supportable on its own. Later milestones may
consume earlier APIs, but publication of one version does not depend on unfinished
features from a later version.

## Non-negotiable invariants

Every slice must preserve the v0.2.1 production contract:

1. Canonical state remains in the daemon and SQLite journal/projections. A TUI,
   dashboard, SDK, remote client, channel, or extension must not become an
   alternate source of truth.
2. An external effect is durably prepared before dispatch, carries exact owner
   authority, and settles as succeeded, failed, or outcome-unknown before
   dependent work proceeds.
3. Replays use recorded evidence and do not repeat provider, tool, channel,
   browser, MCP, or extension effects.
4. Host access is least-authority, bounded, sandboxed, cancellable, and
   inspectable. Convenience cannot silently widen workspace, network, secret,
   process, browser, or channel authority.
5. Configuration and credentials remain reviewable, secret-safe, recoverable,
   and rollback-capable.
6. New derived indexes and presentation projections are reconstructible from
   canonical evidence.
7. Linux remains the production OS contract. Ubuntu, Debian, Fedora, and Arch
   packages and repositories remain qualified; derivatives remain
   compatibility-expected rather than falsely certified.
8. Public documentation describes only behavior exercised by the exact release
   artifacts.

## v0.3 — daily-use parity

Status update (2026-07-28): the canonical title/search/checkpoint/fork/export workbench and
provider-selection boundaries are implemented across schema 18, daemon API, scriptable CLI,
full-screen terminal client, and the thin dashboard adapter. The TUI includes session/search
navigation, verified conversation rendering, bounded composition, provider/context/cost status,
recent structured activity/tool evidence, exact approval review, checkpoint/fork/export controls,
and an active-route model picker with separate conversation and next-turn scope. Pseudo-terminal
proofs cover terminal enforcement, alternate-screen cleanup, Ctrl-C during stalled admission, and
persistent daemon loss. Focused storage, API, process, real-provider, artifact-integrity,
exact-owner, terminal, and browser-boundary tests are green. Plan-first transactional route-set
switching and its installed-package service-manager acceptance are implemented; final package,
upgrade, soak, protected-CI, live-provider, and publication gates remain in progress. The native
upgrade gate now verifies the attested public v0.2.1 baseline, preserves one completed durable task
through schema 16-to-18 migration, checks the immutable rollback snapshot, then exercises v0.3
titles/checkpoints and state-preserving uninstall. Local Ubuntu, Fedora, and Arch executions pass;
the protected tag workflow and post-publication matrix must repeat it on every supported
architecture/distribution before the gate is complete.

### Session workbench

- Add deterministic conversation titles immediately, derived from the first
  canonical owner input and bounded for terminal/web rendering.
- Add owner-renamed titles with optimistic concurrency, immutable journal
  evidence, history, and exact-binding authorization.
- Provide one searchable session workbench shared by the full-screen TUI and
  dashboard.
- Add explicit checkpoints that bind the session, source cursor, context epoch,
  canonical turn boundary, provider/config identity, and workspace authority.
- Add conversation fork from a retained checkpoint. Forking references eligible immutable
  conversation evidence from a new context lineage; it does not copy approvals,
  active work, effects, leases, mutable child state, or revoked authority.
- Add bounded JSON and self-contained HTML transcript exports with digests,
  citations, redaction metadata, and no bearer credentials or owner filesystem
  paths.

### Full-screen terminal interface

- [x] Add a full-screen terminal mode while retaining the line REPL and scriptable
  commands.
- [x] Include a session rail, searchable titles, verified conversation timeline, composer,
  provider/context/cost status, active/queued work, exact approvals, structured recent tool/event
  results, and bounded evidence previews.
- [ ] Add richer dedicated subagent cards and media/artifact/diff viewers as the corresponding v0.4
  delegation and multimodal projections mature; current canonical delegation/tool facts remain
  visible in the structured activity preview.
- [x] Restore terminal state after normal exit, cancellation, panic, daemon loss,
  resize, and unsupported-terminal detection.
- [x] Keep terminal input and rendered remote text bounded and control-character
  safe.

### Provider and model experience

- [x] Add an authenticated provider/model catalog projection with locality,
  protocol, tool/media capabilities, limits, verified pricing state, health,
  and route pressure.
- [x] Permit per-new-session and per-new-turn model selection within a compatible
  configured route.
- [x] Add plan-first provider switching that stages and probes a complete candidate,
  drains incompatible in-flight work, activates atomically, verifies health,
  rotates affected context epochs, and automatically rolls back on failure.
- Never label unverified prices or provider-advertised limits as operator
  verified.

### Dashboard

- Use the same canonical session/workbench APIs as the TUI.
- Add session titles/search, checkpoint/fork/export, provider/model selection,
  structured tool/approval cards, artifact previews, and recovery guidance.
- Retain the loopback capability boundary, strict origin/host/CSP policy,
  response bounds, and absence of the daemon bearer from browser content.

### v0.3 release gate

Publication requires:

- schema migration and rollback reconstruction tests for every new canonical
  record;
- exact-binding authorization, terminal-safety, malformed-data, concurrency,
  crash/restart, cancellation, and replay tests;
- full-screen TUI pseudo-terminal tests and dashboard browser tests;
- provider-switch failure and rollback tests;
- clean v0.2.1-to-v0.3 package upgrade and same-version rollback on all
  qualified distributions;
- protected green CI, required live-provider acceptance, rebuilt package
  validation, release-policy soak evidence, SBOM/provenance, and attested
  publication.

## v0.4 — governed capability breadth

### Durable delegation

- Generalize the current serial child into bounded parallel child runs with
  explicit depth, fan-out, token/tool/time/cost budgets, resource claims,
  cancellation propagation, deterministic ordering, handoffs, and owner
  steering.
- Preserve isolated contexts and authority intersection. Shared task state is
  typed canonical evidence, not a writable prompt scratchpad.

### MCP

- Add Streamable HTTP transport, resources, prompts, bounded OAuth/credential
  delegation, and long-lived health.
- Route every effectful MCP invocation through the existing approval, effect,
  attempt, reconciliation, and replay contracts.
- Keep server discovery metadata separate from granted authority.

The first two MCP slices and the public-client OAuth runtime slice are implemented on the
v0.4 branch: owner-facing inspect/add/list/
enable/disable/revoke; exact endpoint and bearer-reference authority; redirect-free DNS-pinned
connections; fresh sessions; JSON/SSE bounds; complete tool/resource/resource-template/prompt
catalog revalidation before every selected read; exact static-resource reads; prompts with
advertised string arguments normalized as untrusted evidence; execution-free replay; and
non-mutating protected-resource plus OAuth/OIDC metadata inspection with exact resource binding,
explicit multi-issuer selection, authorization-code validation, and PKCE S256 enforcement. A
separately approved stopped-daemon login supports pre-registered public clients, fresh state and
PKCE, an exact loopback callback, bounded token exchange, narrowed scopes, and a private
generation-one token-family record without changing configuration or exposing model authority.
A distinct `oauth-add` transaction revalidates metadata/catalog evidence before activation.
Runtime resolution supports proactive refresh, cross-process serialized refresh-token rotation,
exact-scope enforcement, atomic generation fencing, and one `401`-triggered refresh/retry.
Reference-safe local revocation, encrypted-backup restore, and migration rollback are covered.
Owner-classified effectful invocation is also implemented for both transports: mutually exclusive
read-only/idempotent/non-idempotent grants, exact approval and immutable-ceiling binding, fresh
pre-dispatch inventory validation, fenced attempts, retry-only idempotent crash recovery,
reconcile-only non-idempotent ambiguity, and execution-free replay are process-tested. Dynamic
client registration/CIMD, issuer-side revocation, resource-template expansion/subscriptions,
resumable GET, and long-lived health remain explicit later slices.

### Media

- Add bounded image input first, followed by explicitly supported audio/video
  inputs.
- Add provider modality negotiation, content-addressed binary artifacts,
  metadata stripping policy, safe previews, and separately permissioned image
  generation.
- Reject unsupported media before provider reservation or dispatch.

The provider-neutral image envelope, both direct adapter translations, and the first public
API/scriptable-CLI ingress are implemented. The envelope accepts only digest-bound PNG/JPEG/WebP
bytes, limits one request to four images and 4 MiB total, permits images only on authenticated user
messages, reserves 8,192 input tokens per included image, and fails unsupported text-only routes
before reservation or HTTP dispatch. OpenAI-compatible requests use low detail for a portable
accounting ceiling; Anthropic requests use image-first base64 blocks.

Strict isolated decode/re-encode metadata stripping and schema-21 content-addressed inbox linkage
bind exact ordered owner-private image evidence to inbox/journal/acknowledgement state after blob
publication. Context-manifest v3 adds sparse artifact provenance, trusted hydration rechecks bytes,
transcript v2 exports path-free metadata, and recorded-only replay reconstructs the exact request
without redispatch. Stopped-daemon activation is explicit and limited to all-direct
OpenAI/Anthropic route chains; individual admissions require an exact image-capable route. The API
has a 6 MiB transport boundary and `session send-image` uses no-follow local files plus
retry-stable delivery/artifact IDs.

The separately permissioned image-generation backend is also implemented. One exact stopped-home
OpenAI Images or OpenRouter Images adapter pins provider/model, origin, credential reference,
JPEG/size/quality, maximum cost/output bytes, and deadline. `image.generate` is a high-risk
non-idempotent effect: the model supplies only the prompt, the owner approves the complete injected
authority, cost/output are reserved before parking, denial makes no provider call, and a dispatch
crash never retries. Confirmed output passes through the isolated normalizer before one atomic
effect/artifact/usage settlement; recorded replay verifies the graph and blob without live calls.
Schema 22 and real-process happy/denied/crash/reconcile/corruption tests cover the boundary.
[ADR 0018](decisions/0018-governed-image-generation-effect.md) records the contract.

The full-screen TUI now admits up to four no-follow local images through `F9` only after an exact
route is selected, and renders path-free canonical image/artifact evidence in the transcript. The
dashboard uses browser-selected bytes with retry-stable UUIDv7 identities, the same admission
ceilings, and an owner-scoped PNG/JPEG viewer that rechecks immutable metadata, length, media type,
and SHA-256 before an in-memory preview or download. Public-process tests cover both adapters.
Line-chat/channel image upload, terminal pixel protocols, fork-lineage image projection,
reference/edit workflows, and audio/video remain incomplete.
[ADR 0017](decisions/0017-content-addressed-bounded-image-input.md) defines the input and rendering
boundaries.

### Channels and browser

- Define a reusable channel adapter contract and ship Slack as the next
  production work channel.
- Add an explicitly approved transactional browser profile for bounded POST
  forms, uploads, and downloads. Keep the current research profile as the safe
  default; persistent/personal profiles remain a separate higher-trust choice.

The reusable channel contract and first Slack production slice are implemented on the v0.4
branch. The pure adapter enforces exact workspace/member/conversation/bot/mention bounds and
bounded control-safe output. Setup live-verifies both Slack token roles and the app/workspace/bot/
human/conversation identities, while the Socket Mode hello independently binds the app token to
the bot app. Routes with identical installation pins share one connection. A complete normalized
admit/ignore disposition is persisted before acknowledgement, acknowledged-but-unfinished input
recovers after restart, duplicates are body-bound, and output resolves the exact originating
thread with stable `client_msg_id` plus per-channel rate control. Both tokens remain broker-only;
final-route revocation removes them. Slack chat deliberately cannot grant effect approval.
Migration/storage tests and a real HTTP/WebSocket public-process proof cover crash-after-ack
recovery, exact allowlists, duplicate acknowledgement, thread routing, 429 retry, stable
downstream identity, secret exclusion/deletion, and revocation. Package/upgrade matrices and the
complete v0.4 release gate remain pending.

The first transactional-browser effect is also implemented. A stopped-home flag, separate from
the safer read browser, exposes `browser.transact` only when the pinned runtime and web authority
remain valid. `browser.snapshot` emits bounded inert POST-form catalogs with hidden-value digests.
Each transaction proposal binds one canonical URL/origin/form digest, exact fields/submitter,
ordered digest-verified private upload artifacts, runtime identity, ceilings, and deadline; policy
always parks for exact authenticated owner approval. After approval a fresh worker revalidates the
source form, closes the hostile target, reconstructs only approved controls in a clean target, and
permits one same-origin POST plus at most one bounded response download. The effect is
non-idempotent and `NeverRetry`.

Schema 23 preserves the bounded raw-model-to-normalized-intent proof and denies noncanonical URLs,
unknown fields, or form/value drift. Low-level real Chrome tests exercise controlled submission and
denial boundaries. A daemon process test proves approval, exactly one POST, crash after durable
dispatch, restart without resubmission, authenticated reconciliation, terminal continuation, and
complete recorded-only replay after the browser bundle is removed. Persistent/personal profiles,
ambient login, arbitrary clicking/JavaScript, payments, cross-origin transactions, and unattended
batches remain separate future contracts. [ADR 0019](decisions/0019-one-shot-transactional-browser-effects.md)
records the boundary.

### v0.4 release gate

In addition to the standard release gates, v0.4 requires adversarial
cross-agent resource tests, MCP OAuth/revocation/ambiguous-effect tests,
media-parser and artifact tests, Slack rate/retry/restart acceptance, and
browser transaction reconciliation evidence.

## v0.5 — ecosystem maturity

### Registry and lifecycle

- Publish a signed registry format for skills and extensions with publisher
  identity, immutable artifacts, compatibility ranges, dependency locking,
  permission diffs, staged activation, withdrawal, upgrade, and rollback.
- Registry discovery never executes package content and never grants requested
  authority automatically.

### Memory and automation

- Add optional hybrid semantic retrieval as a rebuildable derived index with
  local embedding support, provider/privacy policy, citations, deletion
  propagation, and literal-search fallback.
- Add one-shot and event-driven automation, safe sub-minute scheduling where
  justified, schedule editing, webhooks, completion/approval notifications,
  and durable deduplication.

### SDK, observability, evaluation, and remote continuation

- Publish stable typed clients for the daemon, timeline, approvals, extensions,
  and channels.
- Export bounded OpenTelemetry traces/metrics without prompts, secrets, or
  private content by default.
- Add versioned scenario/evaluation contracts for task success, safety,
  recovery, latency, and cost regression.
- Add outbound-only, authenticated, revocable, single-owner remote
  continuation with synchronized timeline cursors and completion/approval
  notifications. Multi-user hosting remains outside this milestone.

### v0.5 release gate

In addition to the standard release gates, v0.5 requires registry
signature/withdrawal tests, semantic-index reconstruction and deletion tests,
automation duplicate/restart tests, SDK compatibility fixtures, telemetry
privacy tests, remote-session expiry/revocation tests, and end-to-end upgrade
evidence from both v0.3 and v0.4.

## Implementation sequence

The intended critical path is:

1. derived session titles and presentation;
2. canonical title/checkpoint/fork/export contracts and migration;
3. shared session-workbench API;
4. full-screen TUI;
5. dashboard workbench;
6. model catalog and safe switching;
7. v0.3 qualification and publication;
8. parallel delegation, HTTP MCP, media, Slack, and transactional browser;
9. v0.4 qualification and publication;
10. registry, semantic memory, event automation, SDK/telemetry/evals, and
    remote continuation;
11. v0.5 qualification and publication.

Security, authorization, durability, recovery, migration, or release-identity
regressions stop breadth work until resolved.
