# Schemas

This directory holds reviewed fixtures for external contracts such as OpenAPI, extension manifests, executor RPC, and extension-host RPC.

Rust DTOs or schema-specific source modules remain the source of truth. Generated schema changes require compatibility tests and review; generated output must not be edited by hand.

The strict evaluation-suite/report source is `crates/mealy-evaluation`. The checked executable
example is [`../docs/evaluation-suite-v1.json`](../docs/evaluation-suite-v1.json);
unknown JSON fields are rejected rather than treated as forward-compatible authority.
