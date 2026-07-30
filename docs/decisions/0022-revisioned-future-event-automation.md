# ADR 0022: Revisioned future-event automation

Status: Accepted

## Context

Mealy's recurring scheduler has a deliberately immutable five-field cron definition, explicit
misfire/overlap policy, and a cursor advanced with each terminal occurrence. Adding one-shot
sentinels, mutable definitions, and event cursors to that table would blur its published recovery
contract. Event automation also creates two risks absent from cron: replaying historical events and
forming autonomous prompt-trigger cycles.

Remote channels add a routing constraint. Telegram, Discord, and webhook bindings identify one
exact destination, while one Slack session can contain multiple threads. A proactive message cannot
safely infer which Slack thread the owner intended.

## Decision

Keep recurring schedules unchanged and add a separate `automation` aggregate. It stores:

- distinct manager and target bindings under one active principal;
- one one-shot UTC-millisecond trigger or one exact direct-session event trigger;
- one prompt action or static notification action;
- immutable definition revisions and a revision-fenced lifecycle;
- one exclusive global timeline cursor for event rules; and
- leased, uniquely keyed occurrence history.

Creation and editing capture the global timeline high watermark transactionally for an event rule.
The driver selects only direct `session` aggregate events from the exact source session and exact
event type after that cursor. Pausing stops claims; resuming advances to the current high watermark
so paused events do not replay.

Create commands carry a caller-proposed UUIDv7. An exact replay returns the current projection
before temporal or target validation, including after the due time, lifecycle advancement, cursor
movement, or target revocation. Reusing that identifier with a different definition conflicts.
This preserves retry safety without weakening authorization for new or changed work.

Event rules may only notify. Notifications contain owner-authored static text and fixed event
identity metadata, never the source payload. One-shot prompts still enter the existing durable
session inbox and approval/effect pipeline. Prompt admission uses an automation/occurrence-derived
idempotency key.

Each occurrence has a 30-second reclaimable lease. Notification completion atomically creates one
outbox record, terminal run evidence, cursor/status advancement, and an automation journal event.
One-shot terminal outcomes complete the aggregate. Event terminal outcomes advance the cursor and
leave it active.

Automation targets may be local, an exact signed webhook installation, or an exact Telegram or
Discord installation and route. Arbitrary extension-channel names are rejected rather than
treated as local delivery. Slack targets were rejected pending an explicit thread-pinning
contract; [ADR 0023](0023-exact-thread-slack-remote-continuation.md) now permits static Slack
notifications through that separate exact route while retaining the prompt prohibition. The exact
binding is validated at create/edit time and again immediately before notification outbox
publication; revocation produces terminal failed run evidence and no outbox row. Safe mode starts
no automation driver and rejects mutation through the existing API boundary.

## Consequences

- The recurring schedule schema and its upgrade/recovery guarantees do not change.
- One-shot work can run below cron's one-minute granularity without claiming real-time timing.
- Historical and paused-time event replay is structurally prevented.
- Event payloads cannot become implicit model input, and event rules cannot create agent loops.
- Crash recovery may repeat a bounded admission attempt but cannot duplicate the inbox entry or
  notification outbox row.
- An exact create retry remains safe after time, lifecycle, cursor, or authorization state changes;
  a semantically different reuse of the same identifier cannot alias the original command.
- Editing is whole-definition replacement under an exact revision fence; terminal definitions are
  immutable.
- Proactive Slack routing is delegated to ADR 0023's exact owner-approved continuation contract.
