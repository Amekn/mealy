# ADR 0014: Governed Streamable HTTP MCP boundary

Status: Accepted (2026-07-29)

Implementation status: transport, complete catalog pinning, exact static-resource reads, exact
prompt retrieval, and non-mutating OAuth protected-resource/authorization-server metadata
discovery are implemented. A pre-registered-public-client authorization-code/PKCE login, private
rotating token broker, separately approved OAuth-backed activation, proactive/`401` refresh,
reference-safe local revocation, and secret-backup/migration recovery are also implemented.
Registration/CIMD, issuer-side revocation, scope-challenge parking, resource-template
invocation/subscriptions, resumable GET, health, and effectful calls remain subsequent slices.

## Context

At the start of this decision, Mealy supported schema-pinned, read-only MCP tools from
digest-pinned local executables inside a fresh Bubblewrap stdio sandbox. That boundary did not
cover remote Streamable HTTP servers, OAuth, resources, prompts, or tools with external effects.

The stable MCP revision implemented by Mealy remains `2025-11-25`. A
`2026-07-28` release candidate exists, but release-candidate semantics are not
accepted into a production evidence contract before a stable revision and
explicit migration decision.

Streamable HTTP is not ordinary REST:

- every client message is a new POST to one endpoint, which may return one
  JSON response or an SSE stream;
- a server may issue an opaque session identifier during initialization and
  require it on subsequent requests;
- SSE connections may disconnect without cancelling the request and may be
  resumed through GET with `Last-Event-ID`;
- protected servers use OAuth protected-resource metadata, authorization
  server discovery, PKCE, resource indicators, and audience-bound tokens;
- resource and prompt listings are application-controlled context, not
  automatically trusted model instructions; and
- a network interruption after an effectful tool POST can leave its external
  outcome ambiguous.

Treating a remote server as another read-only stdio executable would therefore
weaken destination authority, credential isolation, replay, approval, and
unknown-outcome guarantees.

## Decision

1. Mealy adds a separate schema-versioned Streamable HTTP server grant while
   retaining the existing stdio grant and user-facing MCP namespace. Server
   identities are unique across both transports.
2. Each HTTP grant pins one canonical endpoint, negotiated stable protocol
   revision, advertised capabilities, complete paginated tool/resource/prompt
   inventories, and exact owner-selected grants. Configuration contains
   credential references only, never bearer, refresh, client-secret, code
   verifier, state, or session values.
3. Production endpoints require HTTPS. Literal-loopback HTTP is allowed only
   for explicit test/local origins. Userinfo, fragments, implicit redirects,
   mixed-origin redirects, private/link-local/cloud-metadata destinations,
   ambiguous IP spellings, and DNS answers containing any disallowed address
   fail closed. Resolution is pinned for the connection attempt.
4. Requests send both required Accept media types, the negotiated
   `MCP-Protocol-Version`, and the exact in-memory `MCP-Session-Id` when one was
   issued. Session identifiers are treated as secrets, never logged or
   persisted, and are destroyed when a bounded operation ends. A 404 session
   response permits one fresh initialization only before any effect dispatch.
5. JSON and SSE responses share one bounded parser. Message bytes, event
   count, event-ID bytes, retry delay, reconnect count, total deadline, and
   server-initiated requests are bounded. Disconnect is not cancellation.
   Resumption uses GET and the last event ID only for read-only operations.
6. OAuth follows the `2025-11-25` authorization specification: protected
   resource metadata and OAuth/OIDC discovery are validated through the same
   SSRF-resistant network boundary; authorization code flow requires PKCE
   S256 and exact state; authorization and token requests include the canonical
   MCP resource indicator; access and rotating refresh tokens remain in the
   hardened credential broker. Token passthrough and tokens issued for a
   different resource are forbidden.
7. OAuth login, scope expansion, credential replacement, and revocation are
   explicit owner commands. A scope challenge parks the requesting work and
   creates inspectable authorization evidence; it does not silently broaden
   scopes. Revocation immediately prevents new context epochs and dispatches,
   cancels safe in-flight reads, and records whether any effect outcome needs
   reconciliation.
8. Resources and prompts are host-controlled data. Listing is fully paginated
   and pinned during inspection. The owner grants exact resource URIs,
   templates, or prompt names and argument schemas. Reads/gets are bounded,
   content-typed, cited as untrusted evidence, and never become hidden system
   instructions. Change notifications invalidate the grant until explicit
   reinspection; they do not silently mutate active context.
9. Remote tool annotations are untrusted hints. Every granted tool has an
   owner-selected Mealy effect class, risk class, idempotency declaration,
   recovery strategy, timeout, output limit, and approval policy. Read-only
   tools use the read ledger. Effectful tools enter the existing prepared
   effect, policy, approval, dispatch-attempt, outcome, validation, and replay
   state machine.
10. A read-only call may retry only before dispatch or under a bounded,
    resumable response contract. An effectful call is never automatically
    retried after its POST crosses the dispatch boundary. A timeout,
    disconnect, or malformed terminal stream after dispatch records
    `outcome_unknown` unless an independently pinned idempotency/task protocol
    can reconcile it.
11. Provider-visible tool identities remain collision resistant and include
    transport, endpoint, protocol, inventory, grant, and credential-generation
    evidence in their descriptor digest. Tokens, session identifiers, OAuth
    codes, and server secrets never enter prompts, tool results, timelines,
    exports, or replay bundles.
12. Startup may verify enabled read-only grants. It must not perform an
    effectful call, interactive OAuth flow, scope expansion, or server-driven
    sampling. Server-originated sampling, roots, elicitation, and arbitrary
    client requests remain disabled until separately versioned decisions.

## Alternatives considered

### Reuse the generic web fetch tool

Rejected. It does not implement MCP initialization, sessions, JSON-RPC/SSE
correlation, capability negotiation, OAuth discovery, or effect ambiguity.

### Trust MCP tool annotations

Rejected. They are server-controlled metadata and cannot grant external
authority, choose approval policy, or make a call safe to retry.

### Persist remote sessions for performance

Rejected initially. Durable opaque sessions increase hijacking and cross-run
confusion risk. Fresh bounded sessions make authority and replay easier to
reason about. Connection/session pooling requires a later contract.

### Automatically consume resources and prompts

Rejected. Remote content is untrusted evidence. Automatic hidden inclusion
would create a prompt-injection and authority-escalation path.

### Retry every failed HTTP POST

Rejected. For effectful tools a response loss after dispatch does not prove
the external action did not occur.

## Expected consequences

- Remote MCP interoperability requires more protocol code and evidence than a
  generic HTTP adapter.
- Exact inventory pinning makes server changes visible and reviewable instead
  of silently changing model authority.
- OAuth setup is more deliberate, but credentials and scope changes remain
  owner-controlled and auditable.
- Read-only resources, prompts, and tools can share transport machinery while
  retaining distinct capability and context semantics.
- Effectful MCP calls inherit Mealy's existing approval and unknown-outcome
  guarantees rather than creating a weaker second effect system.
- The first implementation can land in independently testable slices:
  transport/inventory, resources/prompts, OAuth, then effectful calls.

The metadata OAuth slice deliberately stops before authorization. `oauth-inspect` sends one
unauthenticated protected-resource probe, prefers an advertised `resource_metadata` challenge,
falls back through the required path-scoped then root well-known URLs, validates the exact resource
audience, and discovers OAuth or OpenID issuer metadata in specification order. Every fetch is
bounded, redirect/proxy free, SSRF checked, and DNS pinned. Multiple issuers require an exact owner
selection, and missing authorization-code or PKCE S256 support fails closed. It creates no client,
browser flow, state, verifier, code, token, broker entry, configuration, or model authority.

The next slice adds only owner authorization and initial token custody. While the daemon is stopped,
`oauth-login` requires explicit approval, a reviewed pre-registered public client ID, and a new
portable token-family ID. Mealy creates fresh state and a PKCE verifier, requests the exact MCP
`resource`, uses only S256, binds an ephemeral literal-IPv4 loopback callback with a strict Host and
request parser, and exchanges the code once through the pinned network boundary. A response must be
JSON Bearer material with `no-store`/`no-cache`, bounded secrets, and equal-or-narrower scopes.
Tokens are zeroizing in memory and stored in a no-symlink owner-private directory as a `0600`
generation-one record whose non-secret grant pins resource, issuer, token endpoint, client, scopes,
and metadata digest. Configuration and model authority remain unchanged.

The runtime slice keeps login separate from authority. `oauth-add` reloads the private record,
revalidates its exact metadata/audience and the complete live catalog, and then publishes only its
non-secret grant plus selected catalog pins. Startup and re-enable repeat metadata verification.
Access resolution proactively refreshes near expiry under a per-family cross-process lock, repeats
the exact resource and client, rejects scope changes and non-rotated public-client refresh tokens,
and atomically advances a monotonic generation. A `401` can force one refresh fenced to the
rejected generation and one retry; concurrent rejections cannot create a refresh storm. Local
revocation requires zero configuration references, removes the validated record durably, and
retains the lock inode. Authenticated encrypted backups and migration rollback include validated
records; secret-free backups declare them excluded. Dynamic client registration, CIMD,
issuer-side revocation, resource-template expansion/subscriptions, resumable GET, and effectful
calls require subsequent contracts.
