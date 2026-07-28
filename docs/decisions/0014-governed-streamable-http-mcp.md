# ADR 0014: Governed Streamable HTTP MCP boundary

Status: Accepted (2026-07-29)

Implementation status: transport, complete catalog pinning, exact static-resource reads, and exact
prompt retrieval are implemented. Resource-template invocation/subscriptions, resumable GET,
OAuth, health, and effectful calls remain subsequent slices.

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
