# Domain Model

This document gives implementation names to the normative concepts in `REQUIREMENTS.md`. Domain types live in `mealy-domain`; transport DTOs do not define these invariants.

## ID policy

All externally visible objects use UUIDv7 newtypes. IDs are opaque and never convey authorization. Journal aggregate sequences and inbox sequences are monotonic integers scoped to their aggregate/session.

Required newtypes:

```text
PrincipalId  ChannelBindingId  SessionId  InboxEntryId  TurnId
TaskId       RunId              AttemptId  ToolCallId    EffectId
ApprovalId   ArtifactId         ContextManifestId       MemoryId
ValidationId LeaseId            CorrelationId           EventId
```

Stringly typed IDs are forbidden across domain/application boundaries.

## Aggregate boundaries

### Session

Owns conversational ordering, inbox promotion, context epoch pointer, and active turn pointer. It does not own principal authorization or arbitrary task state.

Invariants:

- inbox sequence is unique and increasing;
- no more than one promoted mutating turn;
- a dedupe key maps to one admission result;
- a context epoch changes only at a turn boundary.

### Task

Owns objective, criteria, risk, budget, lifecycle, parent task, and final outcome. A task may have multiple runs and validations.

Invariants:

- terminal states cannot return to active states;
- success requires policy-required validation;
- cancellation does not erase unknown effects;
- revisions increase on every transition.

### Run

Owns agent role, delegated work order, capability ceiling, budget, lineage, and attempt list. Child capabilities are an intersection, never an implicit copy.

### Effect

Owns the exact normalized intent, subject digest, policy decision, approval, dispatch metadata, idempotency key, recovery class, and outcome.

Invariants:

- dispatch requires an active authorization for the current subject digest;
- only one current dispatch lease/fencing token may commit;
- non-idempotent unknown outcomes cannot transition back to dispatch automatically;
- reconciliation creates evidence and an explicit transition.

### Memory

Owns a logical memory and versioned revisions. Source links remain immutable even when a corrected revision supersedes content.

### Automation

Owns one owner-authored name, trigger, action, lifecycle, current revision, and event cursor. Each
trigger occurrence owns a separate durable run and claim.

Invariants:

- a client-proposed UUIDv7 maps to one semantic definition even after its lifecycle advances;
- one-shot time and event-cursor keys identify at most one occurrence;
- event observation begins strictly after create/edit/resume and never copies event payload;
- event triggers may notify but cannot submit model prompts;
- prompt admission uses the existing session inbox and approval/effect boundaries;
- only an unexpired claim owner may commit a terminal run;
- notification completion, outbox creation, cursor/status transition, and journal fact are atomic.

## Commands versus facts

Commands are authenticated requests that may fail preconditions:

```text
SubmitInput  PromoteInput  PauseTask  ResumeTask  CancelTask
StartRun     RecordModelResult  ProposeEffect  ResolveApproval
RecordEffectOutcome  ReconcileEffect  ProposeMemory  AcceptMemory
RecordValidation  CreateAutomation  EditAutomation  PauseAutomation
ResumeAutomation  CancelAutomation  ClaimAutomationRun  CompleteAutomationRun
```

Journal events are past-tense facts produced only after a committed transition:

```text
input.accepted  input.promoted  task.started  task.waiting
model.attempt_completed  effect.proposed  approval.requested
effect.outcome_unknown  effect.reconciled  context.compiled
memory.activated  validation.completed  task.succeeded
automation.created  automation.edited  automation.paused  automation.resumed  automation.cancelled
automation.admitted  automation.notified  automation.failed
```

An event handler never mutates canonical state outside an application transaction. Outbox consumers perform delivery and report results through commands.

## Error taxonomy

- `InvalidTransition`: domain lifecycle forbids the command.
- `Conflict`: expected revision, lease, or resource claim is stale.
- `Unauthorized`: authenticated principal lacks access.
- `PolicyDenied`: capability was evaluated and denied.
- `ApprovalRequired`: durable waiting state was created.
- `ResourceBusy`: bounded scheduling conflict.
- `RetryableDependency`: classified external transient failure.
- `OutcomeUnknown`: dispatch may have taken effect and needs reconciliation.
- `InvariantViolation`: bug or corrupt canonical state; fail closed and alert.

Errors exposed by the API use stable codes and safe details. Internal causes become sensitive artifacts when needed.
