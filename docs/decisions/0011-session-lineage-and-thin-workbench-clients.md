# ADR 0011: Canonical session lineage and thin workbench clients

Status: Proposed

## Context

Mealy v0.2.1 has durable sessions, exact-binding transcript search, resumable
timelines, a concurrent line REPL, and a temporary loopback dashboard. It does
not have owner titles, checkpoints, conversation forks, a full-screen terminal
workbench, or an ordinary transcript export.

Adding these features independently to each client would create several risks:

- the terminal and dashboard could disagree about session state or fork
  semantics;
- a client-side copy of a transcript could accidentally copy prior approvals,
  effects, mutable work, or authority into a new conversation;
- a model-generated title could add cost, latency, untrusted text, and provider
  dependence to session discovery;
- a checkpoint that only records a message index could resume under a different
  context epoch, provider/config identity, or workspace authority; and
- a richer interface could become a second scheduler or mutation authority.

## Proposed decision

### Canonical session lineage

The daemon owns a versioned session-lineage graph.

- A session has one immutable lineage identity and may have one parent
  checkpoint.
- A checkpoint binds an exact session, retained timeline cursor, canonical turn
  boundary, context epoch, effective configuration/provider identity, workspace
  authority digest, and creation actor/time.
- A fork creates a new session and context lineage from one retained checkpoint.
  It references immutable eligible conversation evidence; it does not copy
  inbox records, active turns, tasks, runs, leases, reservations, approvals,
  effects, outbox records, schedules, child runs, mutable memory, or channel
  delivery state.
- Context construction re-authorizes every referenced item under the fork's
  current ownership and policy. A prior grant or approval is evidence, never
  inherited authority.
- Checkpoint and fork transitions are journaled atomically with their canonical
  rows and presentation events.

### Titles

- Before an owner title exists, the display title is a deterministic,
  control-free, bounded projection of the first canonical owner input.
- Derivation makes no provider call and creates no canonical mutation.
- An owner rename is a revision-fenced canonical metadata transition with
  exact-binding authorization and immutable journal history.
- Presentation projections always expose one bounded effective title and its
  source.

### Exports

- JSON export contains versioned canonical conversation evidence, lineage,
  digests, timestamps, citation metadata, and explicit redaction metadata.
- HTML export is generated from the same bounded export model and is inert:
  strict escaping, no remote resources, no scripts, and no embedded bearer or
  secret values.
- Export never implies that replaying the document will re-execute a provider
  or effect.

### Thin workbench clients

- The full-screen TUI and dashboard consume the same authenticated session,
  search, lineage, checkpoint, fork, export, provider, timeline, approval, task,
  and artifact APIs.
- Clients may keep bounded view caches and cursor state. They do not own
  canonical task state, scheduling, effect recovery, provider routing, or
  permission decisions.
- Every mutation uses the same versioned daemon command and idempotency or
  revision boundary regardless of client.
- The line REPL and scriptable CLI remain supported accessibility, recovery,
  and automation surfaces.

## Alternatives considered

### Client-local transcript copies

Rejected. They cannot reliably preserve journal identity, context epochs,
revocation, compaction provenance, or current authority, and would give each
interface different fork behavior.

### Clone the session's relational rows

Rejected. A relational clone would duplicate mutable work and could inherit
approval/effect authority. Forking must reference eligible immutable evidence
and start with empty operational state.

### Ask the active provider to title every conversation

Rejected as the required default. It adds an avoidable external call and makes
basic navigation depend on provider availability, price, language behavior,
and untrusted generated text. A future optional title suggestion may be
reviewed as owner-editable input.

### Put TUI state directly in SQLite

Rejected. Pane selection, scroll position, filters, and terminal dimensions are
presentation preferences, not canonical agent state. Only user-meaningful
metadata and commands belong in the daemon contract.

## Expected consequences

- The first title slice can ship without a migration because its fallback is a
  deterministic projection.
- Owner titles, checkpoints, and forks should share one reviewed migration so
  their lineage and concurrency constraints are introduced together.
- Every client can add richer navigation without reimplementing recovery or
  authorization.
- Forking is intentionally more conservative than copying a chat transcript:
  prior text can inform a new context, but prior authority cannot.
- Checkpoint retention must be included in garbage collection, backup,
  restore, export, migrations, and evidence-deletion policy.
- The ADR remains proposed until the schema, transition contracts, and
  crash/authorization tests are accepted.
