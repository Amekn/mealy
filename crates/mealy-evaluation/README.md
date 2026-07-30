# mealy-evaluation

`mealy-evaluation` defines Mealy's strict, versioned scenario-suite and
privacy-preserving report contracts. Its runner drives a real daemon only through the stable
authenticated owner API exposed by `mealy-client`; it has no storage access, provider shortcut,
approval bypass, or hidden test endpoint.

Each case creates a fresh session, admits one idempotent input, waits for an explicitly expected
settled state, and evaluates canonical task, validation, usage, replay, and timeline evidence.
Checks cover task success, safety event invariants, deterministic response digests, independent
validation, recovery event sequences, duration, token/cost budgets, and replay completeness.

Reports contain suite/input digests, canonical IDs, fixed assertions, usage counters, validation
references, and event-envelope digests. They deliberately omit prompt text, final response text,
timeline payloads, tool arguments, errors, credentials, and arbitrary model-authored content.
Every report carries a SHA-256 digest over its typed payload.

The evaluator never resolves an approval. A scenario that proposes an effect must either expect
the task to park in `waiting`, or arrange an independently governed approval outside the
evaluation runner.
