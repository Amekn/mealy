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

### Session workbench

- Add deterministic conversation titles immediately, derived from the first
  canonical owner input and bounded for terminal/web rendering.
- Add owner-renamed titles with optimistic concurrency, immutable journal
  evidence, history, and exact-binding authorization.
- Provide one searchable session workbench shared by the full-screen TUI and
  dashboard.
- Add explicit checkpoints that bind the session, source cursor, context epoch,
  canonical turn boundary, provider/config identity, and workspace authority.
- Add conversation fork from a retained checkpoint. Forking copies referenced
  conversation evidence into a new context lineage; it does not copy approvals,
  active work, effects, leases, mutable child state, or revoked authority.
- Add bounded JSON and self-contained HTML transcript exports with digests,
  citations, redaction metadata, and no bearer credentials or owner filesystem
  paths.

### Full-screen terminal interface

- Add a full-screen terminal mode while retaining the line REPL and scriptable
  commands.
- Include a session rail, searchable titles, conversation timeline, composer,
  provider/context/cost status, active/queued work, subagent progress, exact
  approvals, structured tool results, and artifact/diff previews.
- Restore terminal state after normal exit, cancellation, panic, daemon loss,
  resize, and unsupported-terminal detection.
- Keep terminal input and rendered remote text bounded and control-character
  safe.

### Provider and model experience

- Add an authenticated provider/model catalog projection with locality,
  protocol, tool/media capabilities, limits, verified pricing state, health,
  and route pressure.
- Permit per-new-session and per-new-turn model selection within a compatible
  configured route.
- Add plan-first provider switching that stages and probes a complete candidate,
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

### Media

- Add bounded image input first, followed by explicitly supported audio/video
  inputs.
- Add provider modality negotiation, content-addressed binary artifacts,
  metadata stripping policy, safe previews, and separately permissioned image
  generation.
- Reject unsupported media before provider reservation or dispatch.

### Channels and browser

- Define a reusable channel adapter contract and ship Slack as the next
  production work channel.
- Add an explicitly approved transactional browser profile for bounded POST
  forms, uploads, and downloads. Keep the current research profile as the safe
  default; persistent/personal profiles remain a separate higher-trust choice.

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
