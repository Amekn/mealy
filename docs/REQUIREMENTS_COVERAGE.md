# Requirements Coverage

This is the release-one implementation review for [`REQUIREMENTS.md`](../REQUIREMENTS.md). A row is
`covered` only when the behavior exists at a real enforcement or persistence boundary and has
repeatable evidence. A green compiler or unrelated test is not treated as requirement evidence.

## Normative requirement groups

| Requirements | Status | Implementation and verification evidence |
|---|---|---|
| DUR-001..002, API-001 | covered | `sessions`, `promotion`, journal/outbox transactions, and the single authenticated API; `durable_admission`, `phase1_runtime`, and `phase1_recovery` prove acknowledgement-before-processing and atomic transitions. |
| SEC-001..003, AUTH-001 | covered | Model/context content is data only; effects cross typed policy/executor ports; Bubblewrap is the only claimed mutation boundary. API and signed-channel tests prove IDs/body claims grant no authority. |
| AUTH-010..013, CHAN-010..013 | covered | Local bearer identity and raw-body HMAC verification resolve registered principal/binding records. Binding and extension grants are terminally revocable without history deletion. Durable webhook reservations, Telegram update receipts, Discord message/cursor receipts, and Slack reserve-before-ack envelope receipts all cross the same inbox/outbox boundary. Slack additionally binds live-verified app/bot/member/conversation identities, requires the Socket Mode `app_id`, shares one connection only across identical owner/installation/token pins, recovers acknowledged unfinished input, and keeps approvals owner-local. `phase6_channel_boundary`, `telegram_channel`, `discord_channel`, `slack_channel`, `sqlite::channel`, `sqlite::telegram`, `sqlite::discord`, `sqlite::slack`, and `outbox_delivery` prove signature/challenge identity, replay/dedupe, exact allowlists, restart, retry, thread routing, and revocation. |
| TASK-010..019 | covered | Typed UUIDv7 IDs, explicit lifecycle states, FIFO delivery modes, one canonical session turn at a time, bounded same-epoch conversation projection, durable pause/resume fencing, cancellation, lineage, and agent-facing bounded delegation are implemented. `agent.delegate` atomically parks the parent, creates an isolated depth-zero read-only child with a separate budget, propagates parent cancellation, resumes through a fenced structured result, and exposes owner-scoped inspection; root and child recorded replay are independently verified. Exact-binding transcript search returns newest canonical turns with digest-linked, UTF-8-safe bounded excerpts and filters transport identity before matching. Deterministic safe fallback titles require no provider or mutation; canonical owner titles are exact-binding, revision-fenced, and journaled. Immutable checkpoints capture the pre-event timeline cursor plus session/context/configuration/policy/workspace-authority/provider identity only at quiescent successful boundaries. UUIDv7-keyed forks create empty operational state, retain immutable root/parent lineage, reference only bounded eligible source turns, and recheck the complete current context/authority boundary before projection. Coherent transcript snapshots expose only successful canonical turns under fixed turn/content limits; JSON and inert HTML carry citations, omission/redaction metadata, and exact digests, while artifact-backed content is verified before hydration. `lifecycle_properties`, `phase1_runtime`, `session_workbench`, `real_provider`, `telegram_channel`, `discord_channel`, `phase2_cancellation`, `phase4_validation`, and `phase7_operations` cover transitions, metadata concurrency, checkpoint/fork safety, export integrity, authority isolation, and search isolation. |
| SCHED-010..015, OPS-001 | covered | Expiring leases, heartbeat, fencing, transactional per-principal/session/role ceilings, configured daemon/provider/extension/resource ceilings, atomic inbox backpressure, persisted due times, bounded attempts, and exponential outbox retry with deterministic jitter. `phase1_runtime`, recovery tests, outbox tests, and session-capacity tests cover the boundaries. |
| AGENT-010..016 | covered | The explicit context → model → validation → tool/effect → observation → final loop persists every dependency boundary. Schema-versioned daemon configuration supplies run budgets. OpenAI Responses, Anthropic Messages, credentialless local Responses, and the explicit OpenRouter stateless Responses-beta preset have bounded activation/catalog proofs. The first image-input slice requires an exact activated direct route, reserves a conservative 8,192 input tokens per selected image, and independently revalidates canonical image evidence before OpenAI/Anthropic serialization. Separately configured `image.generate` supplies the model only a prompt while trusted normalization injects and binds exact provider/model/JPEG/size/quality/cost authority. Phase 2–4 and image-bearing/generating `real_provider` process suites cover normalization, limits, repair/failure boundaries, deterministic tool order, profiles, independent validation, duplicate admission, approval/denial, crash/reconciliation, and zero-redispatch replay. |
| TOOL-010..018, REC-001 | covered | Immutable tool descriptors, exact approval subjects, intent-before-dispatch, stable effect keys, terminal/unknown outcomes, reconciliation, output limits/artifacts, and sandbox obligations. `workspace.replace_file` v2 binds a current SHA-256 plus either complete content or bounded ordered exact-text edits and occurrence counts; mismatch leaves the original unchanged. `workspace.manage_path` v1 adds exact non-recursive directory creation/removal, digest-bound no-overwrite bounded-file move/removal, safe-parent confinement, quarantine-before-unlink, and conservative non-idempotent/reconcile-only recovery. `image.generate` is high-risk, exact-approved, non-idempotent, and never retried; one immutable cost/output reservation precedes approval parking, denial dispatches nothing, and an interrupted running attempt parks unknown with conservative full-cost settlement until owner reconciliation. Provider-process evidence proves exact approval, fresh validation, and execution-free replay. The Linux x86_64 rendered-browser subset adds a content/CDP-pinned fresh profile, private network namespace, destination-pinned GET/HEAD proxy, non-read/upgrade/ambient-download denial, bounded accessibility/PNG evidence, exact form-free activation, native no-event text/search fill, selected-field-only same-origin GET, one GUID-confined 512-KiB attachment capture, cleanup, and execution-free replay. Domain properties, tool/policy units, `sandbox_executor`, `browser_runtime`, the real-provider browser/edit/manage/image-generation proofs, and `phase3_effect_approval` cover read/mutation/crash boundaries. |
| SEC-010..017 | covered | Default-deny typed policy evaluates identity, role/risk, exact arguments/resources/workspace/time/capability, records version/explanation, and emits sandbox/secret obligations. Five profiles exist; unsupported guarantees are explicitly denied by `doctor`. Security and process tests cover argument drift, ambient authority, secret canaries, traversal, and fail-closed profiles. |
| CTX-001, CTX-010..015 | covered | Context epochs/manifests persist ordered included/excluded/redacted evidence, digests, reasons, sensitivity, tokens, transformations, policy and residency. Conversation discovery is owner/session/epoch scoped, bounded to 32 recent successful turns and 512 KiB, compaction-aware, and token allocation reserves the latest authenticated input. Context-manifest v3 adds ordered user-only image evidence as sparse artifact-linked items; trusted hydration rechecks owner, media, dimensions, digest, byte count, and canonical bytes, while dangling or corrupt links fail closed. Epoch rotation discards prior-session-derived candidates before dispatch. Compaction retains canonical sources and typed goals/constraints/approvals/effects. Conversation storage/compiler units plus Phase 2, Phase 5, image-bearing real-provider continuity/replay, and workspace-revocation process tests verify isolation, inspection, and replay integrity. |
| MEM-001, MEM-010..015 | covered | Governed proposal/activation/rejection/supersession/expiry/deletion, provenance/namespace/confidence/sensitivity/retention, deterministic FTS5 plus fallback, untrusted citations, correction/pin/export/index rebuild. The chat-native and scriptable `remember` workflows preserve distinct proposal/owner-approval commits, generated exact-content provenance, optimistic revision fences, and recoverable partial-failure IDs. `phase5_memory_context`, `memory_workflow`, PTY/parser, and memory store tests include cross-scope denial, lifecycle UX, and tombstones. |
| PROV-010..014 | covered | The versioned capability contract includes modalities, tools, structured output, reasoning, streaming, context/output limits, pricing, residency, concurrency/rate ceilings, and retry hints. Live attempt preparation uses deterministic routing across capability/privacy/locality/health/cost/latency/policy; fallback is explicit and cannot reduce trust. Independent Responses and Anthropic Messages adapters normalize their distinct request/tool/terminal/SSE/error/usage contracts. `mealyctl setup` initializes a clean home, reviews bounded non-secret provider/model/limit/price inputs, imports a standard-environment credential into the broker, and reuses the exact bounded live probe before atomic activation. `mealyctl onboard` composes that stopped-home boundary with named free/custom/local/ChatGPT-subscription/API routes, bounded model selection, explicit no-replacement behavior, Linux service activation, and authenticated health/doctor verification. Its OpenRouter-free policy requires an exact `:free` ID, complete tool/text/token-limit metadata, and zero input/output/auxiliary prices from the live account catalog. Credential-scoped remote and credentialless literal-loopback model-list/activation commands enforce protocol-specific discovery/probing and distinguish provider-advertised limits from operator-verified values. The owner-local ChatGPT subscription command invokes only an existing official Codex client session: the canonical executable and SHA-256 are pinned and rechecked, API-key variables and host-client tools/connectors are excluded, stdin/stdout/stderr/time/token/concurrency/rate bounds are enforced, and malformed or unauthenticated client results fail closed. Legacy Claude subscription commands/configuration are rejected before mutation or dispatch because Anthropic prohibits third-party Free/Pro/Max credential routing; the independently implemented Anthropic Messages API adapter remains supported. Exact stopped-home fallback removal preserves remaining order/history and broker material; compatible primary rotation retains the chain, while incompatible identity/residency/locality fails before mutation. Provider units, client process tests, the public `doctor` scenario, and a mixed-protocol retry/replay process proof exercise interactive/flagged onboarding, discovery, local no-auth setup, subscription envelopes, fallback exclusion, and exact settlement. Credentials never enter argv, config, output, or normalized context. |
| EXT-001, EXT-010..016 | covered | Data-only skills have strict full-inventory inspection without execution, immutable digest publication, inert installation/update, separate revision-fenced enable/disable, bounded context provenance, on-demand cited passive-resource reads, backup/rollback coverage, and tool references that grant no authority. Extensions use digest-pinned manifests, inspection without execution, explicit immutable grants, compatibility/migration/rollback metadata, bounded out-of-process RPC, failure isolation, upgrade and revocation. MCP supports explicit selected read-only and effectful tools over exact-version native stdio and governed Streamable HTTP tools/resources/prompts. Stdio retains executable/complete-toolset/full-definition/schema pins and fresh no-network Bubblewrap sessions. HTTP adds a canonical endpoint and opaque bearer reference, SSRF-resistant pinned resolution, no proxy/redirect, fresh zeroizing sessions, JSON/SSE bounds, per-call complete tool/resource/resource-template/prompt catalog revalidation, exact static-resource and prompt grants, authority-bound descriptors, cited untrusted prompt/resource evidence, revocation, and execution-free replay. Non-mutating OAuth inspection validates protected-resource challenges/metadata, exact resource audience, explicit issuer selection, OAuth/OIDC metadata, authorization-code flow, and PKCE S256 without creating credentials or authority. Separately approved stopped-home login for a pre-registered public client adds fresh state/PKCE, strict loopback callback parsing, exact-resource code exchange, scope narrowing, redacted/zeroizing secrets, and no-follow owner-private generation-one token storage while still creating no MCP authority. A separate approved `oauth-add` revalidates metadata/catalog evidence before activation; runtime access adds proactive refresh, exact-scope and rotated-refresh-token enforcement, cross-process generation fencing, one `401` refresh/retry, reference-safe local revocation, and encrypted-backup/migration recovery. Owner-classified effects reuse the built-in exact approval/effect/attempt/reconciliation/validation/replay ledger for both transports. Mutually exclusive read-only/idempotent/non-idempotent selections bind the complete definition, transport/executable/endpoint/credential authority, immutable run ceiling, normalized arguments, target, recovery, and policy; annotations remain untrusted. Idempotent dispatch interruption permits only a bounded new fenced attempt with the stable key, while non-idempotent ambiguity parks after one dispatch for authenticated evidence-bound reconciliation. Real-provider happy, crash/restart, reconcile, and execution-free replay proofs cover those contracts. Dynamic registration/CIMD, issuer-side revocation, scope-challenge parking, resource-template invocation/subscriptions, and resumable GET remain open v0.4 work. Domain/infrastructure units, `skill_configuration`, `mcp_configuration`, live HTTP/OAuth catalog/login/activation/refresh/revocation fixture proofs, the real-provider skill/MCP process proofs, `extension_host`, `mcp_stdio`, and `phase6_extension_boundary` cover the implemented contracts. |
| REC-010..017 | covered | SQLite state/journal/outbox atomicity, content-addressed artifacts, startup classification, unknown-effect honesty, forensic preservation, backup-aware transactional migrations, and effect-free recorded replay. Schema 21 publishes normalized input-image blobs before atomically linking ordered owner/session evidence to the inbox; failed linkage leaves no canonical reference and only an age-gated orphan. Schema 22 publishes a normalized generated-image blob before atomically settling its exact effect outcome, cost/output usage, private artifact, immutable effect reference, and event. Input and generation replay validate exact recorded evidence and make zero live provider/decoder calls; missing generated bytes make replay incomplete. Large provider-request and validation-context objects use bounded backward-compatible at-rest compression only when smaller; logical canonical digests, legacy rows, strict decompression ceilings, and corruption rejection remain part of dispatch/replay evidence. Phase 1–7 crash suites, migration snapshots, image/replay-corruption cases, soak storage attribution, and maintenance tests provide evidence. Live replay is intentionally absent; the MAY requirement does not weaken recorded replay. |
| OBS-010..013, ART-010..011 | covered | The timeline spans all lifecycle/effect/context/validation/artifact/recovery facts with resumable gap-aware cursors. Artifact metadata and atomic blob publication are enforced. Generated images are canonical private JPEG artifacts attributed to the exact effect attempt and retrievable only through authenticated metadata/content endpoints; outcome settlement binds their digest, size, reference, event, and charged usage. Admin status/metrics expose queues, leases, approvals, unknown effects, health, storage, schema and failures; the authenticated usage endpoint adds exact-owner, at-most-31-day zero-reservation terminal settlement grouped by UTC completion day across root/delegated/validation lineage. HTTP and agent spans carry request/task/run/attempt/correlation/causation identity. The first optional external OpenTelemetry slice adds a typed allowlist rather than a general log bridge: claimed agent-run traces carry bounded task/run/turn/session/correlation IDs, while fixed-outcome counters and duration histograms avoid high-cardinality IDs. Its environment-independent OTLP/HTTP protobuf transport bounds queue/batch/body/response/interval/timeout behavior, and a real socket fixture proves exact resource/span/metric inventories with no general-tracing canary or authorization header. Provider/tool/effect external signal expansion remains explicit later v0.5 work and does not replace the already-covered durable events/admin metrics. The full-screen TUI consumes the same bounded status, verified transcript, recent timeline, session, and exact-approval projections for provider/context/cost state plus structured tool/event previews; it retains only view caches. The ephemeral dashboard adds session title/checkpoint/fork and digest-verified transcript export commands, exact trailing-30-day and per-task settled/reserved usage/cost, effect/attempt evidence reads, revision/evidence-bound owner reconciliation, UUIDv7-keyed duplicate-safe schedule creation, definition/run inspection plus revision-fenced lifecycle, bounded governed-memory administration, and bounded extension manifest/grant inspection plus manifest-derived health-gated enable/disable/revoke. Both remain adapters rather than alternate state authorities and never expose the daemon bearer. |
| VAL-010..016 | covered | Every admitted task stores objective criteria/risk. Deterministic checks are preferred; medium-risk mutation requires a separately authorized fresh-context validator and durable outcome/evidence. `phase4_validation` and replay tests use the public API and deterministic provider. The v0.5 `mealy.evaluation-suite.v1` runner adds strict local/CI scenario contracts that create fresh sessions only through the stable typed public client, then assert canonical task/validation/replay/timeline/usage evidence for success, safety, recovery events, duration, tokens, calls, and cost. Its real-daemon proof includes validated success plus a mutation proposal that parks without evaluator approval or effect dispatch; private prompt, response, timeline-payload, rubric, and tool content are absent from digest-bearing reports. Crash injection/restart is intentionally composed by the outer process harness rather than granted to scenario input. |
| CFG-010..012, DATA-010..013 | covered | Non-secret schema-versioned config, a shared clean-home default, exact-digest guided setup approval, effective digests/history, explicit approved offline rollback, exact-transition automatic migration snapshots with atomic complete-home activation, class/sensitivity/principal/task/channel/legal retention selectors, encrypted opt-in secret backup, isolated restore verification, complete archive plus scoped exports, memory tombstones, and reference-safe GC. Image generation uses an approved stopped-home enable/replace/disable command that validates one exact adapter, imports or reuses only a broker secret reference, performs no billable probe, archives prior bytes to UUIDv7 create-new files, and preserves reference-safe credential revocation. Encrypted backup format v2 and migration reconstruction preserve validated owner-private MCP OAuth token families; secret-free backups explicitly declare their omission, and v1 backups remain readable. Schema 15 adds only a partial terminal-completion reporting index; v14 forward migration preserves canonical rows and query-plan tests require its use. Configured skill packages, MCP executables, and complete browser bundle files/executable modes are content-pinned, backup-covered, and reconstruction-verified. Phase 7, setup/config, image-generation configuration, browser configuration, maintenance, process, packaging, and artifact tests cover these paths. |
| NFR-REL-001..004, NFR-PERF-002, NFR-PERF-004 | covered | Startup recovery is automatic/queryable; acknowledged input survives provider/extension/sandbox/process failures; every retry/timeout is bounded; cursors resume and detect gaps; all ingress/provider/tool/extension/artifact frames have byte/item limits. Owner-explicit chat `/attach` and scriptable local text-file admission open no-follow regular files, cap exact UTF-8 bytes at 256 KiB, allowlist text/source extensions, withhold host paths, and reuse the durable idempotent input boundary. Scriptable image admission independently caps route body, per-image/aggregate source and canonical bytes, count, dimensions, pixels, base64, context slots, and token reservation; it preserves retry-stable IDs and withholds filename/path metadata. Image generation separately caps prompt/request/response/base64/canonical bytes, cost, time, and one output; it disables fallback and automatic retry and makes crash ambiguity owner-visible. |
| NFR-PERF-001, NFR-PERF-003 | measurement target | Accepted-input p95 latency and idle resident memory are SHOULD-level hardware-sensitive targets, not release blockers. The runtime avoids synchronous provider work on admission and keeps optional workers/models outside the idle baseline; repeatable benchmark baselines remain release-engineering measurements rather than functional enforcement claims. |
| NFR-PORT-001..002, NFR-OPS-001..002 | covered | Linux is the sole production OS contract. Ubuntu 24.04/26.04, Debian 13, and Fedora 44 receive clean x86-64/ARM64 package gates; Arch Linux receives a clean x86-64 gate. Native `.deb`, `.rpm`, and `.pkg.tar.zst` packages plus generic glibc archives cover the supported families, while derivatives are conditional on the documented Linux compatibility boundary. macOS and Windows are archived or out of scope. Native service installation is systemd-user Linux; unsupported platforms deny explicitly. CLI exposes doctor/status/backup/restore verification/safe mode/drain, forced termination evidence, and a temporary least-authority loopback dashboard. The dashboard aggregates canonical projections and exposes only typed session input, bounded timeline, exact approval, exact 30-day/per-task usage, cooperative cancellation, unknown-effect reconciliation, durable keyed schedule creation plus revision-fenced lifecycle, bounded governed-memory administration, and manifest-bounded extension lifecycle. Exact Host/Origin/capability checks, an 8 MiB daemon-response ceiling, and strict DTO limits protect the adapter without exposing the daemon bearer, creating alternate state, or providing an arbitrary proxy. |
| NFR-QUAL-001..004 | covered | Domain property tests, policy/recovery/effect/migration units, real SQLite integration tests, real process crash scenarios, public API workflows, fallback doctor scenario, extension/channel failures, migration snapshots, and sandbox/authorization/secret security cases run locally and in CI. |

The first v0.5 registry verifier extends the EXT/NFR-QUAL evidence without yet changing the
release-one lifecycle claim. An out-of-band root verifies threshold-signed exact snapshot bytes;
expiring monotonic state rejects signature drift, rollback, and same-version equivocation.
Snapshots authorize separate threshold publisher keys, immutable media-type/size/SHA-256 release
descriptors, and withdrawals. Publisher releases bind host compatibility and complete exact
dependency locks. Deterministic extension/skill diffs enumerate every requested capability,
filesystem, network, secret, process, and governed-tool change before a later staging transaction.
Unit fixtures cover tampering, missing thresholds, expiry, rollback, equivocation, target
substitution, withdrawal, incompatibility, missing dependencies, and authority widening. Root
bootstrap accepts only exact owner-supplied out-of-band JSON; rotation requires the exact next
version under both old and new key thresholds. Schema 24 retains immutable exact root/snapshot
bytes and monotonic heads, repeats verification inside the SQLite write transaction, rejects stale
writers, and survives reopen, migration, integrity, backup, and rollback tests. The stopped-home
`registry` CLI now provides no-mutation root/snapshot inspection, explicit-approved root
bootstrap/rotation and snapshot acceptance, and durable status. It accepts only bounded no-follow
files, excludes a running daemon, refuses database initialization or implicit schema migration,
and keeps exact replays idempotent. Fixed-path `snapshot-fetch` and approved `snapshot-refresh`
add canonical HTTPS-only, proxy/redirect-free, DNS-pinned, public-address-only reads with connected
peer verification, exact media type, hard body/time bounds, and the same local signature and
anti-rollback checks. Refresh also requires the exact envelope SHA-256 returned by the reviewed
fetch. Immutable mirror content requests derive paths only from signed SHA-256
descriptors and verify exact type/length/digest. Unit and process tests cover unsafe mirror URLs,
loopback/private denial, shared special-address policy, digest drift, approval ordering, and no
state advancement on transport failure. These boundaries still confer no package authority.
Schema 25 and `release-fetch`/`release-accept`/`release-status` now retain exact publisher-signed
release evidence under the active root/snapshot fence. Transactional reverification covers
publisher threshold, withdrawal, exact dependency closure, descriptors, and host compatibility;
root rotation requires a newly authorized snapshot. Evidence is immutable and restart-durable,
exact replay is idempotent, aliasing conflicts, and later withdrawal blocks new acceptance while
preserving audit history. `package-fetch` now requires that durable evidence and current
root/snapshot authorization, retrieves only the signed manifest/archive objects, binds manifest
identity, and performs extraction-free exact USTAR inventory/content inspection. Adversarial tests
cover traversal, links, duplicates, extra files, metadata, checksums, padding/trailers, manifest
substitution, and instruction controls. It reports authority but persists and grants nothing.
Explicitly approved `package-stage` repeats that review under a digest fence, persists exact
manifest/archive bytes through the existing content-addressed artifact store, and commits schema
26 immutable evidence only after transactional root/snapshot/release/withdrawal reverification.
Restart, exact replay, mutation rejection, backup enumeration, and v25-to-v26 migration are
covered. Offline `package-plan` covers complete extension permission and skill governed-tool
reference diffs, content/executable changes, current status, widening, authority reset, and one
review digest without mutation. Approved `package-install` covers skill and extension install,
update, rollback, and exact-evidence adoption. Skill changes use the existing immutable publisher
and remain disabled. Extension changes publish only authenticated manifest/executable bytes,
execute nothing, create a retained schema 27 provenance-bound revision, and remove old grants.
Exact-plan mismatch, invalid approval/digest ordering, extraction-free conversion, inert
publication, substituted destination bytes, migration, atomic evidence failure, and provenance
projection are tested. Installed-withdrawal handling is now covered: status and runtime boundaries
project the newest accepted snapshot over exact release/staged provenance; explicit withdrawal,
removal, substitution, or evidence mismatch blocks skill instruction activation and extension
enable/invocation without deleting audit evidence. Snapshot expiry alone does not deactivate an
offline install.

The first v0.5 stable SDK slice extends API/AUTH/NFR-REL/NFR-QUAL evidence without adding a second
state authority. `mealy-client` reuses `mealy-protocol` DTOs and exposes typed health/status,
provider, session-workbench/input, task-control/replay, approval, extension, and channel
operations. It rejects ambiguous origins and identifiers, disallows remote clear-text transport,
ambient proxies, and redirects, redacts bearer material, bounds request/response bytes, validates
request/response/error versions, and preserves structured retry evidence. Real loopback unit
fixtures cover exact headers, paths, queries, bodies, receipts, size/version failures,
private-descriptor validation, and debug redaction. Async/SSE, non-Rust bindings, and frozen
downstream compatibility qualification remain explicit v0.5 work rather than current release-one
claims.

Schema 16 extends the REC/DATA/OBS/NFR-REL evidence above: one canonical writer is separated from
bounded query-only WAL snapshots; wait metrics make both lanes observable; and new context
manifests use one bounded, compressed, digest-verified item bundle with sparse foreign-key
artifact/compaction/memory provenance. Legacy row-per-item manifests remain replayable. Migration,
governed-memory deletion/restart, crash recovery, replay, soak-attribution, and retained 3.1 GB
diagnostics cover the compatibility and contention boundaries.

Schema 18 extends the PROV/REC/DATA/OBS evidence above: the daemon publishes a truthful
authenticated catalog of only its active configured routes, and session defaults are
reconstructible revision-fenced projections. New-session and per-turn choices are validated
against that catalog. Admitted input records contain an immutable automatic/exact selection and
resolution source, and promotion must copy that exact identity to the turn. Migration backfills
legacy sessions and work as `automatic`. Exact selection filters routing to one endpoint and
disables implicit fallback while retaining bounded classified same-endpoint retry. Foreign keys
and triggers reject partial pairs, cross-session events, post-admission mutation, and inbox/turn
disagreement. The CLI, TUI, and dashboard consume the same contracts and retain no private routing
authority. Focused storage, restart, duplicate-admission, API, browser-boundary, terminal, CLI, and
real-provider tests cover the boundary.

Schema 21 extends the DUR/AUTH/REC/ART/NFR-REL evidence above for the disabled v0.4 image-input
foundation. Canonical decoder output is published to the owner-private SHA-256 store before an
atomic inbox transaction creates exact-owner artifact metadata, a contiguous ordered media link,
an immutable reference, versioned journal evidence, and the acknowledgement. Four-image,
per-image, aggregate-byte, canonical-media, dimension, artifact-identity, and access-policy bounds
are enforced in both application code and SQLite. Duplicate delivery binds order, digest, size,
media type, and dimensions; evidence drift conflicts. Triggers reject mutation, late failure rolls
all metadata links back, v20 upgrades in place, and a real normalizer/blob/file-database reopen test
proves referenced retention plus safe young-orphan recovery. Public ingress and provider dispatch
are now active only through the separately qualified API/scriptable-CLI exact-route slice; other
client rendering surfaces remain outside that claim.

Schema 22 extends the TOOL/REC/ART/AGENT/NFR-REL evidence for governed image generation. One
reservation immutably binds the exact approved maximum cost and output bytes before approval
parking and can settle only once. The origin trigger preserves the model's prompt-only proposal
while proving all trusted injected dispatch constraints. Confirmed output becomes a metadata-free
canonical JPEG in the owner-private content-addressed store before one transaction settles the
effect, reservation, artifact/reference, event, and charged usage. Interrupted running work
settles at the full reserved cost, parks unknown, and cannot be retried. Real-process success,
denial, crash/restart, reconciliation, recorded replay, and blob-corruption proofs make zero or one
provider dispatch observable. Exact v21 upgrade plus schema-13 package rollback and encrypted
restore tests cover forward/backward operational compatibility.

## Release-one acceptance path

The eleven acceptance steps are crossed by the process suites rather than mocked at the storage
boundary:

1. `phase1_recovery` authenticates the local principal and durably admits input before reply.
2. `phase2_read_only_loop` claims a fenced run and persists the exact context manifest.
3. The built-in normalized provider proposes `fixture.read`; the bounded tool result becomes an
   artifact and then a final response.
4. `phase3_effect_approval` proposes the sandboxed fixture write, persists exact approval evidence,
   and parks the run.
5. Hard restart preserves queue, approval, cursor, manifest, budgets, and completed boundaries.
6. Approval resumes without repeating completed work; the effect crash matrix proves at-most-once
   mutation or explicit `outcome_unknown`.
7. `phase4_validation` records deterministic/fresh independent evidence before task success.
8. Final delivery crosses the durable outbox, and `task replay` validates the recorded graph with
   zero provider, tool, extension, or effect calls.

## Deliberate release boundary

The deferred items in the requirements—multi-tenant hosting, distributed scheduling, public
internet exposure, mobile clients—and the plan's personal/persistent browser interaction,
guild/group Discord, vector, and marketplace work remain outside release one. The supported
one-human Discord DM does not imply arbitrary guild or multi-user channel authority. The read-only
rendered-browser subset permits only an exact same-origin GET link, exact native form-free button
activation, or exact native non-password text/search fill with an optional selected-field-only GET.
Separately enabled v0.4 `browser.transact` permits one exact digest-matched same-origin POST form
after authenticated owner approval, with digest-verified owner-private artifact uploads, a bounded
response/download, a clean reconstructed target, and `NeverRetry` recovery through explicit
unknown-outcome reconciliation. Neither browser contract implies arbitrary clicking/keyboard
events, origin-wide or unattended POST authority, owner-path uploads/downloads, payments,
cross-origin transactions, persistence, or a personal-profile attachment.
Additional live provider and tool adapters can be added behind the covered
contracts; they must pass the same provider, sandbox, effect, recovery, and traceability suites
before being advertised as supported.

The final local gate is:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc
# Large pinned-browser gates used by CI/release:
MEALY_BROWSER_BUNDLE=/reviewed/chrome-headless-shell-linux64 \
  cargo test -p mealy-infrastructure --test browser_runtime -- --ignored
```
