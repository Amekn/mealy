# Mealy v0.3–v0.5 completion audit

Observed: 2026-07-30 (Pacific/Auckland)

Scope: the three production milestones in
[`V0_3_TO_V0_5_ROADMAP.md`](../V0_3_TO_V0_5_ROADMAP.md), preserving the
normative requirements, accepted architecture, threat model, Linux support
contract, and protected release policy.

This audit separates four states that must not be conflated:

1. **Implemented** means the authoritative daemon/client source contains the
   bounded capability.
2. **Qualified source** means adversarial, process, migration, package, and
   protected pull-request checks passed the exact candidate.
3. **Release-qualified** means the normalized public-lineage candidate also
   passed its exact-package soak, protected `main` checks, live providers, and
   predecessor upgrades.
4. **Publicly complete** means immutable signed and attested artifacts passed
   checkout-free post-publication acceptance on the supported Linux matrix.

As of this observation, the named v0.3, v0.4, and v0.5 feature slices are
implemented and protected-PR qualified. The three-version objective is **not
complete**: v0.3 is still inside its fresh 24-hour exact-binary soak, while
v0.4 and v0.5 must be normalized and requalified sequentially after their
predecessors become immutable public releases.

## Preserved system invariants

| Invariant | Authoritative evidence | Finding |
| --- | --- | --- |
| Canonical authority remains in the daemon journal and projections. | [`ARCHITECTURE.md`](../../ARCHITECTURE.md), [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md), and ADRs [`0011`](../decisions/0011-session-lineage-and-thin-workbench-clients.md), [`0013`](../decisions/0013-atomic-parallel-delegation-groups.md), [`0021`](../decisions/0021-derived-semantic-memory-index.md), and [`0023`](../decisions/0023-exact-thread-slack-remote-continuation.md). | **Covered.** TUI, dashboard, SDK, vectors, evaluation reports, registry data, channels, and continuation routes remain adapters or derived evidence rather than alternate state authorities. |
| Effects are prepared durably before dispatch and never silently repeated. | ADR [`0003`](../decisions/0003-effect-recovery.md), `crates/mealy-application/src/effect_ledger.rs`, `crates/mealy-infrastructure/src/sqlite/effects.rs`, and `apps/mealyd/tests/real_provider.rs`. | **Covered.** Exact approval, idempotent retry, non-idempotent reconciliation, image generation, transactional browsing, replay, and outcome-unknown paths use one effect/attempt ledger. |
| Replay does not redispatch providers, tools, MCP, browser, channel, or extension effects. | `apps/mealyd/tests/real_provider.rs`, `apps/mealyd/tests/slack_channel.rs`, `apps/mealyd/tests/phase4_validation.rs`, and `apps/mealyd/tests/phase5_memory_context.rs`. | **Covered.** Public-process tests remove or count live dependencies and require recorded-only replay. |
| Host access remains least-authority and sandboxed. | [`THREAT_MODEL.md`](../THREAT_MODEL.md), ADR [`0004`](../decisions/0004-security-boundaries.md), `crates/mealy-infrastructure/src/sandbox.rs`, and `crates/mealy-infrastructure/tests/sandbox_executor.rs`. | **Covered.** Workspace, process, browser, MCP, registry, and media boundaries retain exact executable/content/network/resource pins and fail closed. |
| Provider choice does not create provider-specific canonical state. | `crates/mealy-application/src/provider.rs`, `crates/mealy-application/src/provider_selection.rs`, both direct provider adapters, and the provider/process tests in `apps/mealyd/tests/real_provider.rs`. | **Covered.** OpenAI-compatible, Anthropic, OpenRouter, private compatible endpoints, local endpoints, and the authorized official subscription bridge share canonical task/effect/usage contracts. |
| Public delivery is attributable and independently verifiable. | [`CI_CD.md`](../CI_CD.md), [`RELEASE.md`](../RELEASE.md), `.github/workflows/release.yml`, and the release validator/fetcher/attestation scripts. | **Implemented, publication pending.** Exact subject promotion, SBOMs, offline Sigstore bundles, signed APT/DNF/Pacman repositories, immutable-release checks, and checkout-free public acceptance are mandatory tag gates. |

## v0.3 daily-use parity

| Requirement | Backend and frontend evidence | Direct verification | Finding |
| --- | --- | --- | --- |
| Searchable titled sessions, checkpoints, forks, and verified exports. | `crates/mealy-application/src/session_workbench.rs`, `session_export.rs`, the SQLite workbench/transcript projections, `crates/mealy-api/src/lib.rs`, `apps/mealyctl/src/main.rs`, `tui.rs`, and `assets/dashboard.html`. | `crates/mealy-infrastructure/tests/session_workbench.rs`; `apps/mealyctl/tests/chat_pty.rs::tui_drives_search_rename_checkpoint_verified_export_and_fork`; the authenticated dashboard process test. | **Source-complete.** Optimistic revisions, exact owner binding, quiescent checkpoint boundaries, duplicate-safe fresh forks, digest verification, bounds, and redaction are exercised. |
| Competitor-grade full-screen terminal workbench. | `apps/mealyctl/src/tui.rs` consumes only authenticated daemon projections and retains bounded view caches. | PTY tests cover non-terminal denial, terminal restoration, Ctrl-C during stalled admission, persistent daemon loss, search, rename, checkpoint/fork/export, exact model selection, and image attachment. | **Source-complete.** The line REPL and scriptable commands remain available. |
| Polished thin dashboard over canonical daemon state. | `apps/mealyctl/src/dashboard.rs` and `assets/dashboard.html`. | `apps/mealyctl/tests/dashboard.rs::dashboard_is_interactive_idempotent_origin_bound_and_never_exposes_daemon_bearer`. | **Source-complete.** Origin/host/CSP controls, bearer exclusion, idempotent commands, bounded projections, media, delegation, memory, automation, and extension views share daemon APIs. |
| Integrated provider/model catalog and safe transactional switching. | `crates/mealy-application/src/provider_selection.rs`, ADR [`0012`](../decisions/0012-transactional-provider-primary-switch.md), CLI/TUI/dashboard selectors, and installed service-manager switching. | Catalog/scoped-selection restart proof in `apps/mealyd/tests/real_provider.rs`; CLI plan and installed provider-switch tests; protected sandbox/update lanes. | **Source-complete.** Selection is revision-fenced; primary switching stages, probes, drains, rotates affected context, verifies, and rolls back. |

The v0.3 release gate is still open. Completion requires the active corrected
86,400-second exact-binary soak to finish and validate, followed by the
candidate/evidence protected merges, exact protected-`main` CI, strict-free
OpenRouter and pinned private-endpoint acceptance, final package/repository
qualification, signed attestations, immutable publication, public v0.2.1
upgrades, and checkout-free distro acceptance.

## v0.4 governed capability breadth

| Requirement | Backend and frontend evidence | Direct verification | Finding |
| --- | --- | --- | --- |
| Bounded parallel durable delegation. | `crates/mealy-application/src/delegation.rs`, domain/SQLite delegation projections, owner CLI, TUI child cards, and dashboard exact-child inspection. | Real-daemon tests cover atomic ordering, abrupt restart, budget rollback, parent cancellation, sibling cancellation, settlement, and zero-provider replay. | **Source-complete.** Depth, fan-out, token/tool/time/cost budgets, authority intersections, resource claims, ordering, cancellation, steering, and handoff evidence are canonical. |
| Streamable HTTP/OAuth MCP resources, prompts, tools, and governed effects. | `crates/mealy-application/src/mcp.rs`, `mcp_oauth.rs`, infrastructure HTTP/OAuth/token adapters, CLI lifecycle, and the shared effect runtime. | Configuration/process fixtures plus real-provider tests cover read-only tools, exact resources/prompts, PKCE login, refresh rotation, revocation, exact approvals, idempotent retry, non-idempotent reconciliation, and replay. | **Source-complete for the scoped v0.4 contract.** Discovery metadata remains separate from granted authority. |
| Bounded image input and separately governed image generation. | Provider-neutral image envelopes, isolated media normalizer, content-addressed private artifacts, API/CLI/TUI/dashboard admission and viewing, and `image.generate` effect runtime. | Media-normalizer, dashboard/PTY, direct-provider, generation approval/denial/crash/reconcile/corruption, usage, and recorded-replay tests. | **Source-complete.** Unsupported modality fails before reservation/dispatch; generated output is normalized before atomic effect/artifact settlement. |
| Reusable channel boundary with Slack. | `crates/mealy-application/src/channel_adapter.rs`, `slack_channel.rs`, secret broker, Socket Mode adapter, SQLite channel/slack projections, and CLI lifecycle. | `apps/mealyd/tests/slack_channel.rs::slack_socket_ack_is_crash_safe_threaded_rate_limited_and_revocable`. | **Source-complete.** Reserve-before-ack, exact workspace/member/conversation/thread routing, stable downstream identity, retry/rate bounds, recovery, revocation, and secret exclusion are exercised; Slack cannot approve effects. |
| Separately approved transactional browser effects. | `crates/mealy-application/src/browser_transaction.rs`, isolated browser runtime, exact form snapshots, uploads/downloads, and the common effect ledger. | Real Chrome one-shot same-origin test plus daemon crash/reconciliation/replay proof in `apps/mealyd/tests/real_provider.rs`. | **Source-complete.** Fresh profiles, source-form revalidation, exact controls, `NeverRetry`, one POST, bounded response download, and execution-free replay are enforced. |

These are pre-normalization results. v0.4 cannot inherit a production claim
from its stacked branch. After v0.3 is public, the candidate must be normalized
onto the exact immutable v0.3 lineage, rebuilt, package-tested against public
v0.3 assets, soaked, live-tested, attested, published, and independently
accepted.

## v0.5 ecosystem maturity

| Requirement | Backend and frontend evidence | Direct verification | Finding |
| --- | --- | --- | --- |
| Threshold-signed skill/extension registry with permission-diff install, update, withdrawal, and rollback. | `crates/mealy-application/src/registry.rs`, mirror/package adapters, schema 24–27 SQLite evidence, skill and extension lifecycle bridges, and `mealyctl registry`. | Threshold signature/tamper/expiry/rollback/equivocation/withdrawal/dependency/permission tests; `apps/mealyctl/tests/registry_configuration.rs`; migration/restore tests. | **Source-complete.** Fetch/stage are inert, install is disabled by default, activation requires separate grants, and runtime policy is revalidated. |
| Optional privacy-preserving semantic memory. | `crates/mealy-application/src/memory.rs`, derived SQLite index, bounded embedding adapter, CLI/API/dashboard lifecycle, and [`SEMANTIC_MEMORY.md`](../SEMANTIC_MEMORY.md). | `semantic_memory_rebuild_falls_back_when_stale_and_recovers_after_restart` and deletion/restart/replay coverage in `apps/mealyd/tests/phase5_memory_context.rs`. | **Source-complete.** Canonical sensitivity/scope filters precede retrieval; stale/degraded/unavailable vectors fall back to literal evidence. |
| Richer one-shot/event automation and notifications. | `crates/mealy-application/src/automation.rs`, leased SQLite scheduler/outbox, CLI/API/dashboard lifecycle, and [`AUTOMATION.md`](../AUTOMATION.md). | `automation_api_drives_one_shot_and_future_event_actions_without_replay`, unit contract tests, migration/restore, observability, drain, and hard-restart coverage. | **Source-complete.** Definition revisions, exclusive cursors, deterministic deduplication, leased recovery, static event notifications, and content-minimized history are durable. |
| Stable typed SDK. | `crates/mealy-client`, protocol DTOs, frozen fixtures, reproducible package builder, downstream-consumer lock, and dedicated release attestation. | Client socket tests, `crates/mealy-client/tests/compatibility.rs`, reproducible crate archives, and clean locked downstream compilation in protected CI. | **Source-complete for the scoped stable blocking Rust SDK.** It covers workbench, timeline, approvals, delegation, automation, extensions, and all channel lifecycles without ambient proxy/credential behavior. |
| Privacy-preserving OpenTelemetry and evaluation tooling. | `crates/mealy-observability`, `crates/mealy-evaluation`, `mealyctl eval`, [`EVALUATIONS.md`](../EVALUATIONS.md), and the versioned suite fixture. | Real OTLP socket test proves the exact signal inventory and content canary absence; evaluation tests prove public-client operation, deterministic assertions, content-free reports, approval parking, and zero unauthorized dispatch. | **Source-complete for the scoped claimed-run signals and deterministic evaluator.** Neither surface becomes canonical authority. |
| Secure single-owner remote continuation. | Exact-thread Slack continuation routes in application/API/client/SQLite layers and [`REMOTE_CONTINUATION.md`](../REMOTE_CONTINUATION.md). | Slack public-process proof covers create/list/read, restart recovery, proactive exact-thread delivery, expiry/revoke behavior, and post-revoke rejection; migration/restore and typed-client tests cover persistence/compatibility. | **Source-complete.** Routes are outbound-only, expiring, revision-fenced, bound to an already admitted exact thread, and have no ambient latest-thread fallback. |

v0.5 remains pre-normalization. It must follow immutable v0.4, independently
rebuild and qualify both public v0.4→v0.5 and v0.3→v0.5 native upgrades,
complete its required exact-package soak, run live acceptance, publish the
stable SDK and all release attestations, and pass public repository/distro
acceptance.

## Real sequential-normalization rehearsal

On 2026-07-30 a disposable object-only rehearsal used exact protected-green
candidate heads `0d2bd8a82c09bc81db41e205ae323258c9bb0094` (v0.3),
`cd7e2099cf50500fd8e4fbdfe63336a6df35d282` (v0.4), and
`c4e88329a3be8436c46a2f7c110fe337d2849049` (v0.5).

The rehearsal created an identical-tree v0.3 public-lineage surrogate plus a
child that replaced all three canonical soak evidence files, normalized the
real v0.4 candidate, simulated its protected public lineage/evidence, and then
normalized the real v0.5 candidate. Both resulting binary/full-index successor
patches were byte-for-byte identical to their original candidate deltas. Each
normalized result had exactly one immutable-public predecessor, preserved the
new public evidence, and moved no Git ref. The v0.5 result retained the stable
SDK and ordered `v0.4.0` plus `v0.3.0` upgrade baselines.

This proves the current stacked deltas are normalization-clean. It does not
substitute synthetic commits for the eventual immutable public tags; the final
sequence must repeat the normalizer and every qualification gate with the
actual published identities.

## Explicitly later scope

The following items are recorded future breadth, not hidden claims of the
v0.3–v0.5 production milestones: a client-owned diff viewer before a canonical
bounded diff-artifact projection exists; audio/video and image edit/reference
flows; dynamic MCP client registration, subscriptions, and resumable GET;
registry publication hosting; async or non-Rust SDKs; arbitrary telemetry
attributes or private collector credentials; model-judge plugins; general
remote interactive prompts; public inbound continuation listeners; and
multi-user hosting.

They must not be inferred from the implemented slices. Adding any of them
requires its own requirements, threat-model update, authority/recovery
contract, migrations where applicable, adversarial tests, package
qualification, and release evidence.

## Completion finding

The feature implementation portion of the v0.3–v0.5 objective is covered by
authoritative source plus direct adversarial/process evidence. The overall
objective is **not achieved** until all three versions are sequentially
normalized where required, exactly qualified, signed, attested, immutable,
publicly downloadable, and independently accepted on the supported Linux
matrix. The release order and evidence requirements in
[`RELEASE.md`](../RELEASE.md) remain controlling.
