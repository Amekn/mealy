# Exact-thread Slack remote continuation

Schema 30 adds an outbound-only, single-owner continuation route for proactive Slack
notifications. It does not expose an inbound internet listener and it never guesses the newest or
most recently active Slack thread. The owner must first send a message that Mealy admits through
the existing verified workspace, member, and conversation binding. The local owner can then pin
that exact thread for between one minute and 30 days.

## Before pinning

Create and inspect the Slack binding as described in the quickstart. Send Mealy a message in the
thread that should receive proactive notifications and wait for the normal acknowledgement. Obtain:

- `BINDING_ID` and `SESSION_ID` from `channel slack-status`;
- the Slack thread root timestamp (`thread_ts`) from the admitted message; and
- an expiry appropriate for the work. The CLI accepts whole hours from 1 through 720 and defaults
  to 168 hours.

Pin the exact admitted thread:

```sh
mealyctl --home "$HOME/.mealy" channel slack-continuation-pin BINDING_ID \
  --thread-id 1785254000.000100 --expires-in-hours 24
```

When it creates an identity, the CLI prints `MEALY_REMOTE_CONTINUATION_ID UUID` before the request.
Retain that line and the exact arguments. If the response is lost, repeat the command with
`--remote-continuation-id UUID`. An exact retry returns the existing route even after it expires;
reusing the ID with different binding, thread, or expiry conflicts.

Creation fails unless SQLite contains an admitted Slack envelope from the binding's exact
allowlisted owner, workspace, and conversation with the same thread root. Only one unexpired
continuation can be active for a Slack binding. Expiry is exclusive and does not delete evidence.
Creation captures the global timeline high watermark so historical events are never treated as
new continuation activity.

## Use the route

Slack prompt automation remains unsupported: a proactive prompt would create unattended agent
work. Static notification automation can target the binding's dedicated session when it explicitly
names the continuation:

```sh
mealyctl --home "$HOME/.mealy" automation create-once-notify SESSION_ID \
  --name "build result" --at "2026-08-01T09:25:00+12:00" \
  --remote-continuation-id REMOTE_CONTINUATION_ID \
  "The build qualification finished."

mealyctl --home "$HOME/.mealy" automation create-event-notify \
  SOURCE_SESSION_ID SESSION_ID \
  --name "completion notice" --event-type turn.completed \
  --remote-continuation-id REMOTE_CONTINUATION_ID \
  "The watched session completed."
```

The automation definition stores that exact continuation ID. Delivery cannot substitute another
thread or a later pin. The target is checked when the definition is created or edited, immediately
before its outbox row is published, and again when the outbox delivery is claimed. Expiry,
continuation revocation, Slack-binding revocation, session closure, identity mismatch, or a missing
route fails closed. A revoked route is deliberately reported as unavailable rather than disclosing
more lifecycle detail to an unauthorized caller.

Normal reactive Slack replies are unchanged: acknowledgements, turn results, and approval
notifications continue to derive their exact thread from the originating admitted event. The pin
only authorizes proactive `automation.notification` output.

## Inspect and revoke

```sh
mealyctl --home "$HOME/.mealy" channel slack-continuation-list BINDING_ID
mealyctl --home "$HOME/.mealy" channel slack-continuation-status \
  BINDING_ID REMOTE_CONTINUATION_ID
mealyctl --home "$HOME/.mealy" channel slack-continuation-revoke \
  BINDING_ID REMOTE_CONTINUATION_ID --expected-revision REVISION
```

Revocation is terminal and revision-fenced. It retains the creation, source-envelope,
no-replay-cursor, and revocation evidence while removing delivery authority. Revoking the parent
Slack binding also makes every child continuation ineffective and removes its brokered tokens.

Do not edit `slack_remote_continuation`, its audit events, or the automation route column directly.
Use the authenticated local API or CLI so source evidence, owner identity, optimistic revisions,
expiry, and outbox routing remain consistent.
