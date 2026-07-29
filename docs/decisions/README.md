# Architecture Decision Records

ADRs record decisions that shape multiple modules or are expensive to reverse. They describe why a decision was made, not just the chosen implementation.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-modular-monolith-and-workers.md) | Modular monolith with isolated workers | Accepted |
| [0002](0002-transactional-journal.md) | Canonical tables plus an atomic transition journal | Accepted |
| [0003](0003-effect-recovery.md) | Explicit unknown outcomes and idempotency-aware recovery | Accepted |
| [0004](0004-security-boundaries.md) | OS sandboxing and out-of-process extensions | Accepted |
| [0005](0005-durable-session-inbox.md) | Runtime-owned durable session inbox | Accepted |
| [0006](0006-context-and-memory.md) | Context manifests, epochs, and governed memory | Accepted |
| [0007](0007-local-api.md) | Versioned loopback HTTP/JSON and SSE first | Accepted |
| [0008](0008-risk-based-validation.md) | Risk-based independent validation | Accepted |
| [0009](0009-sqlite-writer-and-snapshot-readers.md) | One SQLite writer, bounded snapshot readers, and bundled context evidence | Accepted |
| [0010](0010-disconnect-resistant-update-transaction.md) | Disconnect-resistant, health-gated release update transaction | Accepted |
| [0011](0011-session-lineage-and-thin-workbench-clients.md) | Canonical session lineage and thin workbench clients | Accepted |
| [0012](0012-transactional-provider-primary-switch.md) | Transactional promotion of an already-configured provider route | Accepted |
| [0013](0013-atomic-parallel-delegation-groups.md) | Atomic, ordered groups for bounded parallel delegation | Accepted |
| [0014](0014-governed-streamable-http-mcp.md) | Governed Streamable HTTP MCP boundary | Accepted |
| [0015](0015-crash-safe-slack-channel-boundary.md) | Crash-safe Slack channel boundary | Accepted |
| [0016](0016-owner-classified-effectful-mcp.md) | Owner-classified effectful MCP through the durable effect ledger | Accepted |
| [0017](0017-content-addressed-bounded-image-input.md) | Content-addressed bounded image input | Accepted |
| [0018](0018-governed-image-generation-effect.md) | Governed image generation through the durable effect ledger | Accepted |
| [0019](0019-one-shot-transactional-browser-effects.md) | One-shot transactional browser effects | Accepted |
| [0020](0020-threshold-signed-inert-package-registry.md) | Threshold-signed inert package registry | Accepted |
| [0021](0021-derived-semantic-memory-index.md) | Privacy-scoped derived semantic memory | Accepted |

New ADRs use the next four-digit number and begin as `Proposed`. Superseding an ADR keeps the old file and links both directions.
