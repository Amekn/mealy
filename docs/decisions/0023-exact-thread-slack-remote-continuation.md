# ADR 0023: Exact-thread Slack remote continuation

Status: Accepted

## Context

Mealy's Slack boundary binds one verified application, workspace, bot, human owner, and
conversation. Reactive output can recover the exact originating thread from durable inbound
evidence. Proactive automation has no originating event, so selecting the newest thread, the most
recently active thread, or an ambient channel would silently broaden authority.

An inbound public callback is also unnecessary. Slack Socket Mode and Web API already provide
outbound daemon connections, and the local owner API is the existing administration authority.
Remote continuation therefore needs a bounded route grant, not another network ingress.

## Decision

Represent proactive continuation as one client-keyed, short-lived route to one exact Slack thread
that was previously admitted from the allowlisted owner. Creation requires:

- a canonical client-proposed UUIDv7 and exact-retry semantics;
- one active Slack binding and open dedicated session under the authenticated principal;
- an admitted envelope matching its workspace, owner member, conversation, session, and thread;
- an exclusive lifetime of at least one minute and at most 30 days; and
- no overlapping effective continuation for the binding.

Creation atomically records the global timeline high cursor and a private journal event. Historical
events at or below that cursor are not continuation work. The immutable route retains its source
acknowledgement and expires without deleting evidence. Explicit revocation is terminal,
revision-fenced, and journalled. Parent-binding revocation makes the child route ineffective.

Automation may use the route only for a static notification and must store the exact continuation
ID in its definition. Proactive Slack prompt automation remains rejected. The target is
revalidated at definition creation/edit, before atomic outbox publication, and at delivery claim.
The outbox payload declares `slack_remote_continuation`; a missing, expired, revoked, mismatched, or
ambiguous route is terminal rather than being misclassified as local delivery. Runtime resolution
never substitutes another continuation.

The daemon opens no new inbound listener. Slack Socket Mode receives events over the existing
outbound connection, the Web API sends the message, and local-bearer administration creates,
inspects, and revokes the route.

## Consequences

- Proactive Slack notifications have a deterministic owner-approved destination.
- Possession of a thread timestamp or Slack credential is insufficient without admitted source
  evidence and local-owner authorization.
- Revocation and expiry can race definition execution or delivery without widening authority,
  because every publication boundary revalidates the same route.
- A notification run records durable enqueueing separately from Slack's remote display outcome.
- Only one effective pin per binding simplifies owner intent and prevents ambiguous delivery.
- Slack prompts and generic remote interactive sessions remain outside this decision.
- Multi-user hosting and public inbound continuation endpoints remain outside the v0.5 milestone.
