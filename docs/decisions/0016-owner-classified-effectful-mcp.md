# ADR 0016: Owner-classified effectful MCP through the durable effect ledger

Status: Accepted (2026-07-29)

## Context

Mealy already supports owner-selected read-only MCP tools over isolated native stdio and governed
Streamable HTTP transports. Treating every remote tool as read-only is insufficient for practical
MCP interoperability: servers commonly expose operations that create, update, send, purchase, or
otherwise change external state.

MCP `ToolAnnotations` are explicitly hints. The stable `2025-11-25` schema defaults an absent
`readOnlyHint` to false, `destructiveHint` to true, `idempotentHint` to false, and `openWorldHint`
to true, but a malicious or mistaken server controls all of those values. They cannot be an
authorization boundary. The protocol also distinguishes cancellation from proof that a dispatched
operation did not occur, and its optional tasks facility does not make an arbitrary tool safely
retryable.

Mealy therefore needs effectful MCP without creating a second, weaker action system or allowing a
model/server to choose its own risk and recovery policy.

## Decision

1. Every selected MCP tool has an explicit owner classification stored in the grant:
   `read_only`, `idempotent`, or `non_idempotent`. Existing grants without the field decode as
   `read_only`; no migration or authority widening occurs.
2. Inspection reports server annotations as untrusted evidence only. The owner selects a class
   with `--allow-tool NAME`, `--allow-tool idempotent:NAME`, or
   `--allow-tool non-idempotent:NAME`. A remote name may appear in exactly one class.
3. Read-only tools keep the read-tool ledger. Both effect classes use the existing durable effect
   proposal, deterministic policy, exact approval, attempt, outcome, reconciliation, validation,
   and replay contracts.
4. Effect descriptors bind the complete reviewed tool definition and schema, transport authority,
   executable or endpoint identity, credential reference, protocol revision, inventory digest,
   target locator, effect class, idempotency contract, risk, recovery strategy, time limit, and
   output limit. Any drift fails before dispatch.
5. Effectful MCP requires the `service_operator` policy profile. Idempotent tools are medium risk
   with retry recovery; non-idempotent tools are high risk with reconcile-only recovery. Both
   require a fresh, authenticated, unexpired owner approval bound to the exact normalized
   arguments, owner, task/run, descriptor, target, executable identity, network/secret authority,
   and policy version.
6. The immutable run capability ceiling must contain the exact tool ID, effect class,
   `service_operator` profile, executable identity, and any endpoint or credential reference.
   Promotion, runtime proposal, SQLite preparation, restart recovery, and replay independently
   recheck that intersection.
7. Immediately before a call, Mealy revalidates the complete live catalog and selected definition.
   It durably marks a fenced attempt `running` before crossing the external dispatch boundary.
8. A definite local failure before dispatch is terminally failed. A confirmed MCP success is
   terminal evidence. An application-level `isError` is terminal failure for an idempotent
   operation; for a non-idempotent operation it does not prove that no partial external effect
   occurred and therefore requires reconciliation.
9. An interrupted idempotent attempt may be retried after restart as a new fenced attempt using
   the same stable idempotency key. Retry is bounded by the run budget and remains visible in the
   timeline. Owners must classify only operations whose downstream semantics really tolerate
   repetition.
10. A non-idempotent timeout, transport loss, malformed terminal response, or daemon crash after
    dispatch becomes `outcome_unknown`. The task parks, no automatic tool or model call proceeds,
    and only an authenticated revision-fenced owner reconciliation with non-empty external
    evidence can establish success or failure.
11. Model-visible observations contain only normalized durable result or reconciliation evidence.
    Executable paths, bearer/OAuth values, MCP session IDs, and other secrets never enter prompts,
    timelines, exports, or replay bundles.
12. Recorded replay never starts an MCP process, opens a network connection, refreshes a token,
    asks for approval, retries an attempt, or repeats an effect.

The implementation follows the stable MCP
[tool schema](https://modelcontextprotocol.io/specification/2025-11-25/schema),
[tool contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools),
[task utility](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks), and
[cancellation contract](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation)
without treating optional server claims as local policy.

## Consequences

- Native and remote MCP actions inherit the same approval, crash honesty, reconciliation, and
  execution-free replay guarantees as built-in Mealy effects.
- Setup is deliberately more explicit: the owner, not the model or server, accepts the
  idempotency consequences of each selected operation.
- Idempotent recovery can produce more than one externally received request after a crash; its
  stable key and fenced attempt history make that fact auditable.
- Non-idempotent recovery favors honesty over liveness. A lost response requires owner evidence
  and cannot be silently converted into success, failure, or a second external action.
- Existing read-only configurations remain byte-compatible and do not gain effect authority.
- This decision does not add MCP task polling, resource-template invocation, subscriptions,
  resumable GET, dynamic client registration, issuer-side revocation, or arbitrary server-originated
  sampling/elicitation.

## Rejected alternatives

### Trust `ToolAnnotations`

Rejected because the server controls them and the MCP specification describes them as hints rather
than a security or authorization contract.

### Treat every selected tool as non-idempotent

Rejected because it would unnecessarily park genuinely keyed operations after every ambiguous
crash and would discard Mealy's existing safe fenced-retry machinery.

### Treat every transport error as failure

Rejected because a request may have changed remote state before its response was lost.

### Retry an effect in place

Rejected because it would erase the distinction between the interrupted attempt and the new
external request. Recovery creates a separately identified fenced attempt.

### Let the model reconcile an unknown outcome

Rejected because model text is not independently authenticated external evidence and cannot
exercise owner authority.
