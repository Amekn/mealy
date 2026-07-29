# ADR 0021: Privacy-scoped derived semantic memory

Status: Accepted

## Context

ADR 0006 makes governed memory canonical in SQLite and permits embeddings only as optional derived
indexes. Semantic retrieval can improve recall when an owner's wording differs from stored memory,
but it introduces a new disclosure boundary, model/configuration drift, vector reconstruction and
deletion obligations, and another failure mode. Making a vector store authoritative would weaken
Mealy's provenance, correction, sensitivity, retention, backup, and replay guarantees.

OpenAI-compatible embedding endpoints are widely deployable, including owner-hosted llama.cpp
servers. Native approximate-nearest-neighbour extensions could improve large-index performance,
but adding a loadable SQLite extension would also add a platform-specific executable and supply
chain before Mealy needs one.

## Decision

Semantic retrieval is disabled by default. It is enabled only by a stopped-home
`memoryEmbedding` privacy policy that pins the exact endpoint, model, residency, dimensions,
document/query prefixes, deadline, and optional broker credential. Clear-text transport is
accepted only for a literal loopback IP; every other endpoint requires HTTPS and a credential.
The adapter ignores ambient proxies, refuses redirects, bounds requests and responses, and exposes
only fixed local error classifications. A dedicated bounded worker thread owns and destroys the
blocking HTTP client and credential; asynchronous daemon control code holds only a request channel.

Canonical governed-memory rows remain the sole source of truth. Per-principal semantic vectors are
a complete, rebuildable cache tied to:

- the active logical memory and exact active revision;
- the canonical content digest and workspace namespace;
- the complete non-secret embedding-policy digest and exact vector dimensions; and
- one atomic successful rebuild time.

An explicit semantic rebuild snapshots all active memory candidates for the authenticated
principal, performs bounded embedding batches outside the SQLite writer, then atomically replaces
the complete vector set only if every canonical revision/digest fence still matches. No background
job silently exports memory. An empty active set may become a healthy empty index.

Correction, expiry, deletion, rejection, or any active-revision status/content transition removes
affected derived vectors and marks the principal index stale in the same canonical transaction.
Failed rebuilds record only a safe degraded classification and never make a partial vector set
searchable. Old derived rows may remain for diagnosis until replacement, but stale, degraded,
incomplete, wrong-policy, or wrong-dimension sets are never queried.

Hybrid search first applies canonical principal, channel, workspace, active-status, sensitivity,
and digest checks. It combines bounded FTS5 and cosine-ranked results with deterministic
reciprocal-rank fusion. The response says whether it actually used `hybrid`, ordinary `lexical`,
or `lexical_fallback`, and reports a fixed semantic status. Disabled, stale, degraded,
incompatible, unbuilt, or temporarily unavailable semantic retrieval falls back to lexical search
instead of failing ordinary memory use. Returned memory remains the normal cited canonical
projection; vectors are never context evidence.

The initial implementation uses bounded exact cosine scan over normalized little-endian `f32`
vectors. A future ANN implementation may replace this derived search representation behind the
same store contract only if clean rebuild, lifecycle invalidation, package portability, and
adversarial qualification remain intact.

## Consequences

- Owners can choose a local embedding model without changing their chat provider.
- Remote embeddings are an explicit memory-and-query disclosure decision, not an ambient provider
  feature.
- Canonical backup, export, correction, deletion, replay, and audit do not depend on vector bytes.
- Model, dimensions, prefix, endpoint, or residency changes require a complete explicit rebuild.
- Hybrid recall remains available during healthy operation, while lexical retrieval remains the
  predictable safety path during endpoint or index failure.
- Exact scan deliberately limits the first release to 10,000 active revisions per principal.
  Larger deployments require a separately reviewed derived-index architecture.
