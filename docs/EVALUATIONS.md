# Scenario evaluations

Mealy's v0.5 evaluation boundary runs strict, versioned scenarios against a real daemon through
the same authenticated public API used by other clients. It does not read SQLite, call a hidden
provider fixture endpoint, bypass policy, grant tools, or resolve approvals.

The first contract is `mealy.evaluation-suite.v1`; reports use
`mealy.evaluation-report.v1`. The Rust source of truth is `mealy-evaluation`, and
[`evaluation-suite-v1.json`](evaluation-suite-v1.json) is a checked, release-packaged example.

## Validate and run

Validation is offline and makes no daemon request:

```sh
mealyctl eval validate ./evaluation-suite.json
```

It opens one nonempty regular file without following a final symlink, reads at most 2 MiB, rejects
unknown JSON fields, applies every semantic/resource bound, and prints the typed suite identity,
digest, and case count.

Run the same suite against the authenticated owner daemon:

```sh
mealyctl --home "$HOME/.mealy" eval run ./evaluation-suite.json
```

Each case:

1. creates a fresh session;
2. admits one idempotent input through `/v1/sessions/{session_id}/inputs`;
3. finds the root task from the canonical timeline after the admission cursor;
4. waits for the explicitly expected settled state or an earlier terminal state;
5. reads task, success-criteria, validation, usage, timeline, and optional recorded replay
   projections through the public API; and
6. emits fixed deterministic assertions plus content-free evidence.

Cases run sequentially. The command prints the complete report to standard output, then returns a
nonzero status if any assertion failed. This preserves evidence for CI even on regression:

```sh
if ! mealyctl eval run ./evaluation-suite.json > ./evaluation-report.json; then
  jq '.summary, [.cases[] | select(.passed == false)]' ./evaluation-report.json
  exit 1
fi
```

Do not publish a report blindly. It contains stable task/session/run IDs and SHA-256 commitments
to the suite and inputs. It contains no prompt text, response text, success-criterion text,
timeline payload, validation rubric/evidence body, tool arguments, provider error, credential, or
filesystem path, but low-entropy text may still be guessable from an unsalted digest. Treat
reports according to the evaluated workload's sensitivity.

## Contract

A minimal successful case is:

```json
{
  "contractVersion": "mealy.evaluation-suite.v1",
  "suiteId": "ci.core",
  "cases": [
    {
      "caseId": "assistant.success",
      "input": {
        "content": "Return one concise acknowledgement."
      },
      "expect": {
        "settledStatus": "succeeded",
        "finalResponse": {
          "presence": "present"
        },
        "validation": {
          "presence": "present",
          "outcomes": ["passed"]
        },
        "replay": {},
        "requiredEvents": [
          {
            "eventType": "validation.completed",
            "minimum": 1,
            "maximum": 1
          },
          {
            "eventType": "task.succeeded",
            "minimum": 1,
            "maximum": 1
          }
        ],
        "forbiddenEvents": ["effect.dispatched"],
        "budgets": {
          "maximumDurationMs": 20000,
          "maximumModelCalls": 2,
          "maximumRetries": 0
        }
      },
      "timeoutMs": 30000,
      "pollIntervalMs": 100
    }
  ]
}
```

Suite and case IDs are unique, 1–128-byte ASCII identifiers using letters, digits, `.`, `_`, `:`,
or `-`. A suite contains 1–128 cases. Input is nonempty UTF-8 up to 256 KiB. An input may also
carry an exact `providerSelection`; omission uses normal automatic session routing.

`timeoutMs` is 1 second through 1 hour. `pollIntervalMs` is 20 ms through 5 seconds and cannot
exceed the timeout. `settledStatus` may be `waiting`, `paused`, `succeeded`, `failed`, or
`cancelled`; transient queue/running/cancelling states cannot terminate an evaluation.

Assertions are opt-in except `settledStatus` and complete timeline pagination:

- `finalResponse` checks presence and, optionally, an exact lowercase SHA-256 without exposing
  response text.
- `validation` checks presence and accepted durable outcomes and mechanisms.
- `replay` checks evidence completeness, zero live provider/tool calls, and equality with the
  canonical final digest; its three checks default to true.
- `requiredEvents` applies inclusive count bounds to exact event types and retains first/last
  cursor plus event-envelope digest citations.
- `forbiddenEvents` requires a zero count. An event cannot be both required and forbidden.
- `budgets` can independently cap monotonic duration, completed model calls, prepared read-tool
  calls, accepted delegated runs, classified retries, input/output tokens, provider-neutral cost
  microunits, and output bytes.

The runner reads at most 50,000 timeline events per case and does not truncate silently.

## Safety and recovery scenarios

The evaluator never approves an effect. A safety scenario can expect `waiting`, require
`effect.proposed` and `approval.requested`, and forbid `approval.approved`,
`effect.dispatched`, and `effect.succeeded`. A separately governed human or harness may resolve an
approval, but that action is deliberately outside the evaluator.

Recovery checks use canonical event requirements and replay evidence. Crash injection and daemon
restart remain the responsibility of the outer deterministic process harness; the evaluator
does not receive service-manager, signal, storage, or fault-injection authority. After the harness
restarts Mealy, the same contract can assert the required recovery events, settled task state,
zero-live-call replay, and resource ceilings. This separation keeps evaluation incapable of
turning a scenario file into host-control authority.

For deterministic CI, start the ordinary daemon with its local fake provider and run the suite
through the public API. Live-provider evaluation is useful for regression observation but should
not replace deterministic gates, because model/provider behavior and latency can change outside a
source revision.

## Report integrity

The report includes:

- contract, suite ID, validated typed-suite digest, start/completion times, and a digest over the
  typed report payload;
- per-case pass/fail assertions;
- input digest; canonical session/task/run IDs; final and success-criteria digests;
- validation ID, fresh-context manifest ID, and validation cursor;
- structured usage and monotonic duration;
- relevant event counts, cursor ranges, and first/last envelope digests; and
- replay availability, completeness, final digest, and live-call counts.

The report digest detects later report modification; it is not a signature and does not establish
who ran the suite. Release qualification must retain the report inside the normal attested CI or
release evidence chain.
