# Scenario Tests

Scenario tests start `mealyd`, use the same authenticated API as clients, and inject deterministic crashes at documented boundaries. A scenario must state the requirement IDs it proves and inspect durable outcomes after restart.

[`../../docs/evaluation-suite-v1.json`](../../docs/evaluation-suite-v1.json) is the public
`mealy.evaluation-suite.v1` example for VAL-016. The runner itself has no crash or service
authority; recovery scenarios compose this contract with the outer process harness, then assert
canonical recovery events and recorded replay.
