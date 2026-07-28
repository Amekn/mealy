# ADR 0017: Content-addressed bounded image input

Status: Accepted (2026-07-29)

## Context

Mealy's canonical session input, context manifests, model-attempt reservations, provider requests,
recorded replay, exports, and clients are text-first. Adding an image only at a provider adapter
would bypass the durable inbox, owner authorization, context evidence, token and byte budgets,
provider routing, and crash/replay guarantees.

Images are also hostile binary input. A file extension or claimed media type does not prove the
format, decoded dimensions, animation state, metadata contents, or decompression cost. Remote URLs
would add an ambient network fetch and mutable content after admission. Provider file IDs would
bind canonical Mealy state to provider-owned retention. Compressed byte size does not predict
vision-token usage.

The supported provider contracts differ. OpenAI Responses accepts ordered `input_image` content
with a data URL and detail selection; its vision-token rules depend on model family and detail.
Anthropic Messages accepts ordered base64 image source blocks and applies its own bounded visual
tokenization. Both support PNG, JPEG, and WebP. Mealy needs a smaller common contract that remains
predictable across local OpenAI-compatible endpoints as well as those hosted APIs.

## Decision

1. The first media slice supports authenticated owner-supplied PNG, JPEG, and WebP image input
   only. Animated GIF, SVG, PDF, audio, video, remote URLs, and provider-hosted file IDs are not
   accepted by this contract.
2. An ingress adapter must bound encoded bytes before allocation and send them to a fresh
   identity-pinned, empty-environment, no-network Bubblewrap worker with no home, workspace,
   credential, or writable host mount. That worker applies OS resource limits, catches recoverable
   decoder panics, decodes with library limits, rejects animation and malformed or unsupported
   structures, enforces dimensions and decoded-pixel limits, removes metadata by re-encoding
   pixels, and returns a bounded result. The daemon independently verifies its dimensions,
   signature, media type, size, digest, and canonical bytes. Decoder release notes explicitly
   acknowledge that hostile input can panic some decoders, so in-process daemon decoding is
   forbidden even when a library limit is configured. A claimed media type or magic prefix alone
   is never sufficient at the public ingress boundary.
3. Canonical normalized bytes are committed to Mealy's owner-private content-addressed artifact
   store before input admission. A later transaction links ordered artifact identities to the
   durable inbox entry. A crash before that link may leave only an unreferenced blob, which the
   existing age-gated garbage collector can safely remove; the reverse ordering is forbidden.
4. Admission binds the exact ordered image vector into idempotency: artifact ID, media type,
   SHA-256 digest, normalized byte size, and dimensions. Reusing a delivery key with any different
   image evidence is a conflict. Cross-principal or cross-channel artifact reuse fails closed.
5. One provider request accepts at most four images, at most 2 MiB of canonical bytes per image,
   and at most 4 MiB in aggregate. These limits include all included context messages, not merely
   the newest input.
6. Images may appear only on authenticated user messages. Context compilation includes their
   immutable evidence in the source digest, projection digest, manifest, and recorded normalized
   provider request. Excluded items never leak image bytes into a provider request.
7. Each included image reserves 8,192 input tokens in addition to its text. This deliberately
   exceeds Anthropic's documented high-resolution visual-token cap and OpenAI's low-detail costs.
   OpenAI-compatible dispatch therefore requests `detail: low` in this first slice. A future
   higher-detail mode requires a model-specific, operator-verified reservation ceiling rather
   than silently weakening this bound.
8. Provider routing requires the `image` input modality whenever compiled context contains an
   image. Image capability is explicit for an exact endpoint/model and defaults off for existing
   configuration. Unsupported routes fail before model-attempt reservation or dispatch.
9. Immediately before serialization, the adapter revalidates count, placement, canonical base64,
   media signature, size, digest, aggregate bytes, modality, and context reservation. OpenAI
   content is emitted image-first followed by text; Anthropic content is emitted image-first
   followed by text.
10. The immutable normalized request contains the bounded canonical bytes as base64 as well as its
    content-addressed evidence. This bounded duplication makes a prepared request exact across
    restart and makes recorded replay independent of a live provider. Artifact authorization and
    integrity are still rechecked when the context is compiled.
11. Image output and image generation are separate capabilities. Generation crosses an external
    effect and must have its own provider contract, permission/policy decision, byte/cost
    reservation, artifact settlement, safe rendering, and ambiguous-outcome treatment.
12. Public API, CLI, TUI, dashboard, and channel attachment support remains disabled until the
    complete decode/re-encode, inbox linkage, context hydration, authorization, migration, export,
    crash, corruption, and supported-provider tests are present.

This decision follows the current OpenAI
[Images and vision guide](https://developers.openai.com/api/docs/guides/images-vision) and
Anthropic [vision contract](https://platform.claude.com/docs/en/build-with-claude/vision), while
deliberately selecting a smaller common denominator.

## Consequences

- An image follows the same durable admission, routing, budgeting, recovery, and replay path as
  text instead of becoming an adapter-only side channel.
- Low detail is a deliberate first-release fidelity tradeoff for portable, conservative
  accounting. Higher detail can be added without changing old request evidence.
- Metadata, filenames, mutable URLs, and provider retention identifiers do not enter prompts.
- The normalized request may add up to roughly 5.4 MiB of base64 to one bounded SQLite evidence
  row. That cost is accepted for exact recovery and replay and remains below the adapter's 8 MiB
  request ceiling after the existing text bounds.
- A provider may report fewer input tokens than reserved. Settlement charges reported usage but
  cannot exceed the durable reservation.
- Existing text-only configurations and requests retain their serialized shape and authority.

## Rejected alternatives

### Send user paths or remote URLs directly to a provider

Rejected because paths disclose host structure and URLs introduce mutable content, ambient
network authority, redirect/SSRF risk, and replay drift.

### Trust MIME declarations or magic bytes

Rejected because neither proves a complete, bounded, non-animated decode or removes metadata.

### Estimate vision tokens from compressed byte size

Rejected because provider vision tokenization depends on decoded dimensions, detail, and model,
not PNG/JPEG/WebP compression ratio.

### Store only a provider file ID

Rejected because provider retention, authorization, deletion, and identity would then determine
whether Mealy can recover or replay its own canonical session.

### Enable high or automatic OpenAI detail immediately

Rejected because current model families have materially different and evolving tokenization
rules. Automatic detail can select original resolution, defeating a portable fixed reservation.
