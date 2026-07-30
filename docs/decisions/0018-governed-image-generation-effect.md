# ADR 0018: Governed image generation through the durable effect ledger

Status: Accepted (2026-07-29)

## Context

Image generation is an external, potentially billable mutation. A model call can create
provider-side work before the client receives a response, so an interrupted request cannot be
assumed safe to repeat. Provider output is also hostile binary input: base64, declared media type,
reported cost, dimensions, metadata, and compressed size all require independent bounds before the
result can become a Mealy artifact.

OpenAI exposes image generation at `POST /v1/images/generations`, while OpenRouter's dedicated
Image API uses `POST /api/v1/images`. Both can return base64 image bytes, but their request and
usage shapes differ. Treating either API as an ordinary model response would bypass Mealy's exact
approval, effect-attempt, budget, artifact, recovery, and recorded-replay contracts.

## Decision

1. Image generation is the high-risk built-in effect `image.generate`. It is never ambient
   provider functionality and is absent unless stopped-daemon configuration declares one exact
   adapter.
2. Configuration pins the protocol, canonical base URL, provider/model identity, residency label,
   opaque credential reference, size, quality, JPEG output, maximum provider cost, maximum output
   bytes, and timeout. Remote endpoints require HTTPS and a credential reference. Cleartext is
   accepted only for a literal loopback endpoint. Proxies and redirects are disabled.
3. The first protocol set is OpenAI Images and OpenRouter Images. Each uses its dedicated endpoint
   and exact bounded request/response parser. Streaming, multiple outputs, edits, masks, reference
   images, provider fallback, SVG, and URL-only results are rejected.
4. The model supplies one bounded prompt only. The trusted daemon injects the configured model,
   size, quality, JPEG format, and maximum cost. A schema trigger preserves the exact raw model
   prompt as origin evidence while independently proving every injected field.
5. Task promotion grants only the exact tool descriptor, adapter digest, logical
   `media.image.generate` capability, network origin, optional opaque secret reference, and
   executable adapter identity. Runtime proposal and pre-dispatch checks reconstruct that complete
   immutable ceiling.
6. Every invocation requires an exact authenticated `service_operator` approval. The approval
   binds the prompt, target provider/model, adapter and descriptor identities, configured
   constraints, risk, effect class, recovery strategy, and validity interval. A denial releases
   the reservation without crossing the provider boundary.
7. Before parking for approval, one immutable reservation records the complete approved cost and
   output-byte authority. The reservation can transition only once from `reserved` to `settled`;
   deletion, reopening, widening, and identity changes are rejected by SQLite.
8. The effect is `non_idempotent` with `never_retry` recovery. The daemon durably records a fenced
   running attempt before the request. Confirmed 4xx rejection is a definite failure. Any
   transport ambiguity, 5xx result, or process interruption after dispatch parks
   `outcome_unknown`, charges the full approved cost reservation conservatively, and requires
   authenticated revision-fenced owner reconciliation. Restart never dispatches it again.
9. A confirmed response must contain exactly one bounded base64 result and a nonnegative reported
   cost no larger than the reservation. Raw bytes enter the existing fresh no-network media
   normalizer. Only the resulting canonical metadata-free JPEG, within the configured and global
   2 MiB ceiling, may be committed.
10. Blob publication precedes the outcome transaction. One transaction commits the terminal
    effect outcome, settled cost/output usage, owner-private artifact metadata, immutable
    effect-output reference, and journal event. A missing or changed blob, metadata row,
    reference, event, charge, prompt origin, capability, or model-attempt link makes replay
    incomplete.
11. Recorded replay opens no provider connection, resolves no credential, asks for no approval,
    and performs no retry. It verifies the durable graph and content-addressed bytes only.
12. Generated-image retrieval uses the existing authenticated artifact metadata/content
    endpoints. Enabling the backend capability does not imply safe rendering in the TUI,
    dashboard, or remote channels; each client surface needs its own rendering and hostile-content
    qualification.

The transport contracts follow the official
[OpenAI image-generation guide](https://developers.openai.com/api/docs/guides/image-generation)
and [OpenRouter image-generation guide](https://openrouter.ai/docs/guides/overview/multimodal/image-generation),
while deliberately implementing a smaller deterministic subset.

## Consequences

- Image generation inherits Mealy's existing approval, crash honesty, owner reconciliation,
  content-addressed artifact, and replay guarantees instead of creating a parallel action system.
- A crash can overcharge local conservative accounting up to the owner-approved maximum even when
  the provider ultimately did no work. It cannot cause an automatic duplicate provider request.
- Provider configuration is intentionally single-route in this slice. Cross-provider fallback
  would need a new approval and budget contract rather than silently changing the approved target.
- Canonical JPEG output trades alpha and provider-specific formats for one small, metadata-free,
  safely identifiable artifact contract.
- Existing installations have no image-generation authority. Schema 22 is additive and leaves
  historical effects unchanged.

## Evidence

Application, guided stopped-home CLI, and adapter tests cover configuration, rollback history,
credential-reference handling, policy/approval binding, request pinning, cost conversion,
response bounds, and definite-versus-ambiguous failures. Real daemon/provider
process tests prove approval and immutable reservation before dispatch, exact request shape,
canonical artifact commit and authenticated retrieval, denial without a provider call,
crash-after-dispatch with no retry and full conservative settlement, explicit reconciliation,
zero-live-call replay, and missing-blob corruption detection. Forward migration, encrypted restore,
and package-managed schema rollback tests prove schema 22 can be added while an exact schema-13
snapshot remains activatable.

## Rejected alternatives

### Expose provider image generation as a normal model modality

Rejected because it would bypass effect approval, non-idempotent recovery, cost reservation, and
artifact settlement.

### Retry a timed-out generation with the same prompt

Rejected because neither supported API provides a downstream idempotency contract that proves the
first generation did not occur.

### Trust provider URLs, media declarations, or reported dimensions

Rejected because URLs introduce provider retention and mutable fetch authority, while declarations
do not prove bounded complete image bytes or metadata removal.

### Let the model choose model, quality, size, format, or cost

Rejected because those values expand spend and output authority. They remain operator-controlled,
digest-bound configuration injected by the trusted daemon.
