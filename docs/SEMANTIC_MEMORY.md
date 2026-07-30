# Optional semantic memory

Mealy's v0.5 semantic-memory foundation adds opt-in hybrid retrieval without changing the
governed-memory source of truth. It is unreleased until the v0.5 qualification and publication
gate completes.

## What it does

Ordinary memory search uses local SQLite FTS5. Hybrid search additionally embeds the owner's query
and compares it with a complete derived vector cache, then deterministically fuses lexical and
semantic rank. Every result is still the canonical memory record with its exact revision,
namespace, sensitivity, status, and source citations.

Semantic retrieval does not automatically discover an endpoint, extract new memories, promote a
proposal, change context trust, or make a vector authoritative. It is disabled when
`memoryEmbedding` is absent. Chat can request hybrid retrieval, but it safely uses lexical results
when semantic retrieval is disabled, stale, degraded, incompatible, unbuilt, or temporarily
unavailable.

## Privacy boundary

An explicit semantic rebuild sends every active memory revision owned by the authenticated
principal to the configured embedding endpoint in bounded batches. A hybrid query sends that
query to the same endpoint. Choose a remote endpoint only when its operator, residency, retention,
and model policy are acceptable for all of that material.

The policy pins the exact:

- API base ending at its version prefix;
- embedding model and output dimensions;
- owner-declared residency;
- document and query prefixes;
- request timeout; and
- optional broker credential reference.

Literal-loopback HTTP is permitted for an owner-hosted model. All other destinations require
HTTPS plus a credential imported once into Mealy's private broker. The adapter uses no ambient
proxy, accepts no redirect, bounds request/response bytes, and never includes the endpoint,
credential, memory text, query, or downstream response body in its error.

## Configure a local embedding server

First run an OpenAI-compatible embedding model whose server implements `POST /v1/embeddings`.
Verify the model's exact output dimensions from that model's trusted documentation. A chat-only
model or a server started without embedding support is not sufficient.

Stop Mealy, then approve the exact local disclosure policy. For a model that uses retrieval
prefixes:

```sh
systemctl --user stop mealy.service
mealyctl --home "$HOME/.mealy" config memory-embedding \
  --base-url http://127.0.0.1:8080/v1 \
  --model nomic-embed-text \
  --dimensions 768 \
  --residency owner-host \
  --document-prefix 'search_document: ' \
  --query-prefix 'search_query: ' \
  --approve
systemctl --user start mealy.service
```

The configuration command performs a bounded one-text compatibility probe before writing the
policy. Use `--skip-connectivity-test` only for an intentionally offline staged setup; the first
rebuild will still fail safely until a compatible endpoint is available.

## Configure an authenticated endpoint

Keep the credential out of shell history by placing it in a named environment variable, then
import it under an opaque broker identity:

```sh
export MEALY_EMBEDDING_API_KEY='set-this-outside-shell-history'
systemctl --user stop mealy.service
mealyctl --home "$HOME/.mealy" config memory-embedding \
  --base-url https://embedding.example/v1 \
  --model exact-embedding-model \
  --dimensions 1024 \
  --residency reviewed-provider-region \
  --secret-id memory-embedding-primary \
  --credential-env MEALY_EMBEDDING_API_KEY \
  --approve
unset MEALY_EMBEDDING_API_KEY
systemctl --user start mealy.service
```

The stored non-secret configuration contains only the broker identity. Changing the endpoint,
model, dimensions, prefixes, or residency changes the policy digest and requires a complete
rebuild.

## Build and use the derived index

After the daemon is healthy and the workspace has governed active memories:

```sh
mealyctl --home "$HOME/.mealy" memory rebuild-index --semantic
mealyctl --home "$HOME/.mealy" memory search \
  --workspace WORKSPACE_IDENTITY \
  --hybrid 'meaning rather than exact stored wording'
```

A successful rebuild reports `semanticIndex.status: healthy`, the policy digest, dimensions,
active revision count, and rebuild time. Hybrid results report:

- `retrievalMode: hybrid` and `semanticStatus: healthy` when both paths were fused;
- `retrievalMode: lexical_fallback` plus a fixed status when lexical search was used safely; or
- `retrievalMode: lexical` when hybrid was not requested.

Hits may include `lexicalRank`, `semanticSimilarity`, and `fusedRankScore`. These values explain
retrieval order; they do not change the memory's confidence, provenance, or trust.

## Lifecycle and recovery

Correction, expiry, rejection, deletion, or active-revision status/content changes invalidate the
affected vector and mark the complete index stale in the same SQLite transaction. Hybrid queries
then fall back to lexical retrieval without sending the query to the embedding endpoint until the
owner runs another semantic rebuild. This state survives a hard restart.

A rebuild embeds outside the SQLite writer and publishes only a complete set whose exact active
revision and content-digest fences still match. Endpoint failure records a fixed `degraded` state;
no partial set becomes searchable. Canonical memory remains available through lexical search.

To stop all future embedding calls:

```sh
systemctl --user stop mealy.service
mealyctl --home "$HOME/.mealy" config memory-embedding-disable --approve
systemctl --user start mealy.service
```

Disabling retains canonical memory and the broker credential for deliberate rollback. Revoke the
now-unreferenced broker secret separately only when configuration history will no longer need it.
Derived vectors are never a substitute for user-visible deletion, retention, backup, or audit
policy.

See [ADR 0021](decisions/0021-derived-semantic-memory-index.md) for the architecture and
[the threat model](THREAT_MODEL.md) for disclosure and lifecycle controls.
