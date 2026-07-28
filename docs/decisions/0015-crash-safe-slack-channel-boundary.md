# ADR 0015: Crash-safe Slack channel boundary

Status: Accepted

## Context

Mealy already had durable signed-webhook, Telegram, and Discord adapters, but each platform had
grown its own transport-specific input and output code. Slack Socket Mode adds a different
correctness boundary: Slack expects an acknowledgement for every envelope, may stop redelivery
after receiving it, periodically rotates WebSocket connections, and may distribute events
unpredictably when one app opens multiple connections. An acknowledgement sent before canonical
local evidence could therefore lose user input after a daemon crash.

Slack also uses two independent credential authorities. An `xapp-` token opens Socket Mode while
an `xoxb-` bot token verifies identities and sends Web API messages. Proving that each token works
does not by itself prove they belong to the same Slack application.

## Decision

1. A pure `ChannelAdapter` contract owns only bounded platform normalization and outbound
   preparation. It has no database, network, credential, approval, or provider authority. Slack is
   its first implementation.
2. One Slack binding authorizes one exact local owner, workspace, Slack app, bot member, human
   member, conversation, mention policy, and dedicated Mealy session.
3. Setup live-verifies the bot token through `auth.test`, the human through `users.info`, the
   conversation through `conversations.info`, and the app token through
   `apps.connections.open`. Both token values are then stored only in the owner-private credential
   broker. SQLite retains opaque secret IDs and SHA-256 pins.
4. The first Socket Mode `hello.connection_info.app_id` must equal the app identity returned for
   the bot token. A mismatch closes the connection before any event is accepted.
5. Active routes sharing one app token use one connection. Sharing is allowed only for the same
   owner and identical workspace, application, bot, app-token secret/digest, and bot-token
   secret/digest pins. Route changes restart that installation worker.
6. Before sending a Socket Mode acknowledgement, Mealy commits the envelope ID, complete body
   digest, and complete bounded normalized `admit` or `ignore` disposition. It then sends the
   acknowledgement, records that observation, and completes the disposition. On restart it
   completes every still-reserved disposition, including one Slack already acknowledged.
   Repeated envelope IDs are accepted only with the identical body and normalized disposition.
7. Admitted input uses the ordinary durable session inbox and outbox. The receipt retains the
   exact Slack thread root. A progress, completion, or approval notification must resolve that
   originating receipt; there is no channel-root fallback.
8. Outbound messages use the durable outbox ID as Slack `client_msg_id`, disable rich parsing and
   unfurls, escape Slack control text, enforce a conservative 4,000-character ceiling, pace each
   conversation to one send per second, and honor bounded `Retry-After`.
9. Slack is not an approval authority. Approval notifications are informational and direct the
   owner to the authenticated local dashboard or CLI. Slack `/approve` and `/deny` text is durably
   ignored.
10. Safe mode resolves neither token and starts no Slack connection or delivery worker. Terminal
    revocation removes credentials only when the final active route using them is revoked, while
    retaining session, envelope, health, and journal evidence.

## Consequences

- A crash after Slack accepts an acknowledgement cannot erase the already normalized action.
- Multiple routes do not create nondeterministic event ownership across parallel Socket Mode
  connections.
- Socket Mode needs no public ingress listener, reducing network exposure.
- Slack output can be retried after definite failure using a stable downstream identity, while
  exact thread routing prevents cross-conversation leakage.
- Adding another platform can reuse normalization types, but transport acknowledgement,
  credential verification, persistence, and delivery semantics remain explicit platform adapters;
  the shared interface does not pretend those guarantees are identical.
- Slack cannot be used to approve effects until a future design supplies separately authenticated,
  replay-safe interactive authority rather than treating chat text as consent.

## Rejected alternatives

### Acknowledge before persistence

Rejected because a daemon crash after the remote acknowledgement would permanently lose an event
Slack is no longer obliged to redeliver.

### Store only the raw envelope

Rejected because recovery would reinterpret untrusted bytes under whatever adapter version happens
to run after restart. The normalized bounded disposition is the durable decision.

### One WebSocket per route

Rejected because Slack distributes events among an app's concurrent connections rather than
broadcasting every event to every route.

### Treat a successful app-token open as bot-token binding

Rejected because the two credentials can come from different apps. The Socket Mode `app_id` is an
independent runtime equality check.

### Accept Slack approval commands as ordinary chat text

Rejected because message authorship is not the same as Mealy's authenticated, exact-subject,
revision- and expiry-bound approval command.
