# ADR 0013: Atomic, ordered groups for parallel delegation

Status: Accepted (2026-07-29)

## Context

Mealy v0.3 can park one parent run while one isolated child run completes. The
child has its own task, run, success criteria, context package, capability
intersection, execution budget, lineage edge, lease, and resource claims. The
parent's delegated-run reservation and provider tool call settle atomically
with the child result.

Running several useful investigations concurrently cannot be implemented by
simply accepting several provider tool decisions:

- provider `parallel_tool_calls` would weaken the existing one-decision
  validation and replay boundary;
- independently parking the same parent once per child would release one lease
  and settle one tool call multiple times;
- resuming on the first terminal child would make later results race with the
  parent's next model request;
- completion order would make prompt evidence nondeterministic;
- cancellation could leave unobserved siblings running; and
- sharing the parent's prompt, authority, or writable scratch state would let
  one child widen or corrupt another child's work.

The durable unit therefore needs to be the complete provider-requested group,
not an accidental collection of unrelated child rows.

## Decision

Mealy retains the serial `agent.delegate` contract and adds
`agent.delegate_parallel` as one provider function call containing an ordered
array of two to eight child work orders.

1. The parent tool-call identity is the immutable provider-origin boundary. A
   fresh canonical delegation-group row binds that tool call, parent run,
   parent fence, requested child count, completion policy, and creation time.
2. Group creation is one immediate writer transaction. It verifies the exact
   prepared tool call, validates every work order before writing, reserves the
   complete fan-out against the parent budget, creates all child
   tasks/runs/turns/lineage edges in request order, then releases and parks the
   parent exactly once. Any failure rolls back the complete group.
3. Provider-side parallel tool calls remain disabled. Scheduler concurrency
   comes only from the already-committed child rows and remains bounded by
   per-principal, per-session, per-role, and global lease limits.
4. Each child receives a unique canonical `childKey`, a one-based group
   ordinal, explicit success criteria, a bounded context package, an
   independently derived budget, and the strict intersection of parent,
   request, and current policy authority. Hidden parent context, approvals,
   mutable prompt scratchpads, and sibling context are not inherited.
5. Lineage depth and total delegated-run budgets are separate controls.
   Fan-out is charged by child count, not by group count. Descendants can only
   delegate when both their remaining depth and independently granted
   delegated-run budget permit it.
6. Exclusive resource claims retain the existing conflict-key transaction.
   Siblings may run concurrently only when their claims do not conflict.
   Waiting for a conflicting claim consumes no extra authority.
7. A child terminal transition stores its fenced result and settles one child
   reservation. It does not resume the parent while any sibling is queued or
   running.
8. The fixed initial completion policy is `all_terminal`. The final child
   terminal transition constructs one bounded result array ordered by group
   ordinal, commits it as the parent tool output, settles the group and parent
   tool reservation, advances the parent checkpoint, and makes the parent
   runnable exactly once.
9. Parent cancellation propagates in the same transaction to every queued or
   running child. Queued children become terminal without dispatch; running
   children observe the durable cancellation request. The parent resumes only
   after all child outcomes are terminal, and then follows its cancellation
   path.
10. Owner steering is a separate authenticated command that appends typed
    evidence to one non-terminal child. It cannot edit the original work
    order, capability grant, budget, success criteria, sibling state, or
    already-assembled parent result.
11. Serial delegations migrate as one-child groups. Their original identifiers,
    ordinals, results, journal events, and replay behavior remain unchanged.

## Alternatives considered

### Enable provider parallel tool decisions

Rejected. Provider response shape would become an execution scheduler and
would bypass Mealy's atomic group admission, complete fan-out budget check, and
one-tool-call replay invariant.

### Launch children through repeated serial calls

Rejected as the primary interface. It makes concurrency dependent on model
turns, repeatedly parks and resumes the parent, and cannot provide an atomic
all-or-nothing fan-out.

### Resume after the first successful child

Rejected for the initial contract. It introduces timing-dependent evidence,
orphan cancellation rules, and ambiguous charging. Later completion policies
require their own versioned semantics.

### Give siblings a shared writable task document

Rejected. Shared mutable prompt state has no authority boundary or deterministic
replay. Cross-child handoffs use typed, append-only canonical evidence instead.

## Expected consequences

- Parallel work preserves one provider decision and one parent wait boundary.
- Parent results are stable across scheduling order, restart, and machine
  speed.
- A wide group can be rejected even when each individual child would fit,
  because admission reserves the complete fan-out.
- Resource conflicts reduce concurrency without weakening correctness.
- Schema, cancellation, scheduler settlement, and recovery tests must treat
  one group as a multi-row atomic state machine.
- Supporting additional completion policies or shared collaborative state
  requires a new contract version rather than reinterpretation of stored
  groups.
