# ADR 0012: Transactional promotion of an already-configured provider route

Status: Accepted (2026-07-28)

## Context

Mealy resolves provider identity at admission and retains that exact identity
through queueing, retries, restart, settlement, and replay. The v0.3 catalog and
scoped-selection work lets an owner pin an active route for one conversation or
turn, but automatic routing still follows the immutable provider order loaded
at daemon startup.

Mutating the provider vector in a live process would weaken several invariants:

- the startup configuration digest would stop describing the running daemon;
- already-admitted and in-flight work could observe a different preference
  order;
- a terminal disconnect between config write and runtime mutation could leave
  disk and memory disagreeing;
- a newly selected endpoint could become primary without an exact live probe;
  and
- a failed restart could leave the service stopped or an unqualified candidate
  active.

Removing a route during switching would also make persisted exact session
defaults point at an identity that no longer exists.

## Decision

Provider-primary switching is a restartable user-service transaction and the
first version only promotes one exact route already present in the complete
active configuration.

1. The foreground client fetches the authenticated active catalog, reads the
   no-follow configuration, validates the complete provider/fallback chain,
   and requires exact route-order and provider/model agreement.
2. Review mode emits `mealy.provider-switch-plan.v1` and performs no probe,
   drain, secret resolution, file creation, or mutation.
3. Approved apply requires a verified production Linux installation and the
   exact active generated `mealy.service` for this home and daemon. It copies
   the already-verified client into a mode-`0700` transaction directory,
   records the helper and daemon SHA-256 identities, and stores immutable
   mode-`0600` previous/candidate configuration snapshots.
4. A transient user service supervises that exact helper outside the invoking
   terminal. A home-scoped service-mutation lock serializes it with program
   updates.
5. The helper resolves only a brokered credential, a credential-free
   literal-loopback route, or the official subscription client and performs
   the existing bounded exact-model connectivity probe before closing
   admission. Environment-only credential references are rejected because the
   helper does not inherit caller shell secrets.
6. Drain and process exit establish the stopped-home boundary. Under the daemon
   lock, the helper archives the exact previous bytes and atomically activates
   the full reordered candidate.
7. Restart qualification requires liveness, readiness, `doctor`, exact service
   and daemon identity, candidate file digest, status/catalog config-digest
   agreement, unchanged route count, and the exact new primary provider/model.
8. A monotonic transaction record uses `scheduled`, `prepared`, `draining`,
   `stopped`, `activated`, `starting`, `verifying`, `committed`, `aborted`,
   `rolling-back`, `rolled-back`, and `recovery-failed`. On restart, the helper
   compares the live config digest with both snapshots, so a crash after rename
   but before phase persistence is not mistaken for untouched state.
9. Pre-activation failure reports `aborted` only after the old service and
   catalog requalify. Post-activation failure stops the candidate, restores the
   exact previous snapshot, restarts, and reports `rolled-back` only after the
   original config digest and primary identity requalify.
10. Reordering must still satisfy the fallback trust-boundary invariant. The
    transaction removes no route, so exact session defaults remain resolvable
    and the changed ordered capability/config digest rotates context on the
    next turn.

Route addition/removal and endpoint, model, credential, price, locality, or
residency edits remain explicit stopped-daemon configuration operations.

## Alternatives considered

### Mutate the live provider vector

Rejected. It makes daemon-lifetime configuration evidence false and creates a
memory/disk split-brain recovery problem.

### Rewrite config and ask the owner to restart manually

Rejected for the routine compatible promotion. It has no independent recovery
owner, health commit condition, or automatic rollback after terminal loss.

### Permit a switch to introduce a new route

Deferred. It combines route publication, secret import, trust-boundary review,
session-default reconciliation, and primary promotion in one operation. Those
changes retain the stopped-daemon configuration path until a separately
specified transaction can prove each boundary.

### Drop routes that become invalid fallbacks after promotion

Rejected. Silent removal could strand exact session defaults and change
availability or cost behavior beyond the reviewed primary promotion.

## Expected consequences

- Automatic primary preference can change without weakening per-turn immutable
  identity or startup configuration evidence.
- Terminal disconnect and helper crash have one inspectable recovery cursor.
- A provider call is part of approved apply, never plan generation.
- Some seemingly reasonable promotions fail because preserving every route
  would violate the trust-boundary ordering. The owner must review a separate
  stopped configuration change.
- Installed-package qualification must exercise the complete supervised path
  before v0.3 publication.
