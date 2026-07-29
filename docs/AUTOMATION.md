# Durable automation and notifications

Mealy schema 29 adds revisioned one-shot and future event automations without changing the
published recurring-cron contract. Schema 30 adds an exact-thread Slack notification route.
Automations are disabled with the rest of the dispatch plane in safe mode. Their canonical
definition, revisions, trigger cursor, leased runs, journal events, and notification outbox
evidence live in SQLite and survive a clean or hard restart.

## Choose the right trigger

Use `schedule create` for a recurring five-field cron expression. Use `automation` for one of:

- one prompt submitted once at a future RFC 3339 instant;
- one static notification sent once at a future RFC 3339 instant; or
- one static notification after each future direct event of one exact source-session event type.

One-shot creation and editing require a strictly future instant no more than 366 days away. The
CLI requires an explicit UTC offset, so daylight-saving and host-time-zone changes cannot reinterpret
the request. The driver scans every 250 milliseconds; this supports justified sub-minute work
without promising hard real-time dispatch.

```sh
mealyctl --home "$HOME/.mealy" automation create-once-prompt SESSION_ID \
  --name "review build" --at "2026-08-01T09:00:00+12:00" \
  "Review the latest build evidence."

mealyctl --home "$HOME/.mealy" automation create-once-notify SESSION_ID \
  --name "stand up" --at "2026-08-01T09:25:00+12:00" \
  "Stand-up begins in five minutes."
```

A prompt beginning `/act`, `/edit`, `/manage`, or `/run` is rejected unless creation or editing
also includes `--allow-approval-required-action`. That opt-in does not approve an effect. The
admitted task still uses the normal capability ceiling, effect ledger, subject-bound approval, and
recovery rules.

## Future event notifications

An event rule observes one existing same-principal source session and one exact canonical event
type. Useful direct session-aggregate types include `input.accepted`, `turn.completed`,
`turn.failed`, and `turn.cancelled`.

```sh
mealyctl --home "$HOME/.mealy" automation create-event-notify \
  SOURCE_SESSION_ID TELEGRAM_OR_DISCORD_SESSION_ID \
  --name "completion notice" --event-type turn.completed \
  "The watched session completed."
```

Creation records the global timeline high watermark in the same transaction as the definition.
Events at or below that cursor are never replayed. Each matching future event advances the cursor
only after its exact run reaches a terminal outcome. Pausing retains the cursor. Resuming moves it
to the then-current high watermark, deliberately skipping events accumulated while paused.
Editing an event rule does the same.

Event actions are notification-only. Mealy does not copy the source event payload into either the
notification or a model prompt. The delivered body contains only the owner's static message plus
the source event type and cursor. This prevents prompt injection through journal payloads and
prevents event-rule cycles from creating autonomous agent work.

## Delivery routes

The destination is an existing session owned by the same principal. A local destination records a
durable local notification. Active webhook, Telegram, and Discord session bindings use their
existing signed or token-digest-pinned outbound boundaries, retries, and revocation behavior.

Proactive Slack prompt automation remains rejected. A Slack binding may span multiple threads and
choosing the newest thread at delivery time is never an exact route. Schema 30 allows only static
notification automation when the owner first pins one exact previously admitted Slack thread and
passes its active `--remote-continuation-id` to the create or edit command. The definition stores
that exact ID and cannot silently switch to another pin. See
[exact-thread remote continuation](REMOTE_CONTINUATION.md).

Channel revocation after automation creation does not restore authority. The exact target binding
and any Slack continuation are revalidated before outbox publication; if no longer active, the
occurrence terminates as `failed` with no outbox record. The declared delivery route is revalidated
again when an outbox delivery is claimed. A revoked or expired Slack continuation is terminal
rather than being treated as local delivery. The automation run remains an honest record that the
durable notification was enqueued, not a claim that a remote service displayed it.

## Edit and lifecycle

List the canonical definition and current revision before changing it:

```sh
mealyctl --home "$HOME/.mealy" automation list
mealyctl --home "$HOME/.mealy" automation status AUTOMATION_ID
mealyctl --home "$HOME/.mealy" automation runs AUTOMATION_ID --limit 20
```

Every edit and lifecycle command carries the exact displayed revision. A stale revision conflicts
without mutation.

```sh
mealyctl --home "$HOME/.mealy" automation pause AUTOMATION_ID \
  --expected-revision REVISION
mealyctl --home "$HOME/.mealy" automation resume AUTOMATION_ID \
  --expected-revision REVISION
mealyctl --home "$HOME/.mealy" automation cancel AUTOMATION_ID \
  --expected-revision REVISION
```

The `edit-once-prompt`, `edit-once-notify`, and `edit-event-notify` commands replace the whole
definition. An edit is rejected while a run is claimed. Completed one-shots and cancelled
automations are terminal and cannot be edited or reopened.

## Crash and deduplication contract

Creation generates one canonical UUIDv7 before dispatch and prints
`MEALY_AUTOMATION_ID UUID` before making the request. Retain that line and the exact definition
after an ambiguous response, then repeat the same create command with
`--automation-id UUID`. A caller may also supply its own canonical UUIDv7 on the first attempt. An
exact retry returns the current existing projection even after the one-shot due time,
event-cursor movement, lifecycle advancement, or target revocation, without another creation
event. Reusing the identity with any different ownership, name, trigger, target, action text, or
action opt-in conflicts.

The driver claims one exact `time:MILLISECONDS` or `event:CURSOR` occurrence for 30 seconds. A
different daemon cannot use an unexpired claim. After expiry, a restart reclaims the same run
identity. Prompt admission uses:

```text
automation:AUTOMATION_ID:TRIGGER_KEY
```

as the durable inbox key. A crash after admission but before automation completion therefore
reconciles to the existing inbox entry instead of submitting a duplicate. Notification completion
atomically writes the terminal run, cursor/status transition, automation journal event, and one
outbox row.

Transient SQLite unavailability leaves the claim recoverable. Bounded permanent admission failures
become `failed` run-history rows. One-shots become `completed` after any terminal run result. Event
rules remain active and advance beyond a terminally failed source occurrence so one poison event
cannot block all later notifications.

`mealyctl status`, `metrics`, and `doctor` expose active/paused definitions plus claimed/failed
occurrences. A claim persisting beyond one lease interval or a rising failure count should be
investigated with `automation runs`.

Do not edit `automation`, `automation_revision`, or `automation_run` directly. Use the authenticated
API/CLI so ownership checks, optimistic fences, journal sequences, trigger cursors, and outbox
evidence remain consistent.
