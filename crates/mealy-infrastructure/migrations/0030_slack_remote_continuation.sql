PRAGMA foreign_keys = ON;

-- One owner may explicitly pin one exact Slack thread that was already admitted through the
-- existing workspace/member/conversation allowlist. The route is outbound-only, expires, and
-- never guesses a latest or ambient thread.
CREATE TABLE slack_remote_continuation (
    remote_continuation_id TEXT PRIMARY KEY CHECK (length(remote_continuation_id) > 0),
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    binding_id TEXT NOT NULL REFERENCES slack_channel_binding(binding_id) ON DELETE RESTRICT,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    thread_id TEXT NOT NULL CHECK (
        length(thread_id) BETWEEN 3 AND 23
        AND thread_id GLOB '[0-9]*.[0-9]*'
    ),
    source_acknowledgement_id TEXT NOT NULL,
    synchronized_after_cursor INTEGER NOT NULL CHECK (synchronized_after_cursor >= 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    revoked_event_id TEXT UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    revoked_at_ms INTEGER,
    FOREIGN KEY(binding_id, source_acknowledgement_id)
        REFERENCES slack_envelope_receipt(binding_id, acknowledgement_id) ON DELETE RESTRICT,
    CHECK (
        (status = 'active' AND revoked_event_id IS NULL AND revoked_at_ms IS NULL)
        OR
        (status = 'revoked' AND revoked_event_id IS NOT NULL
         AND revoked_at_ms IS NOT NULL AND revoked_at_ms >= created_at_ms)
    )
) STRICT;

CREATE INDEX slack_remote_continuation_owner_idx
    ON slack_remote_continuation(principal_id, created_at_ms, remote_continuation_id);
CREATE INDEX slack_remote_continuation_route_idx
    ON slack_remote_continuation(binding_id, status, expires_at_ms, remote_continuation_id);

CREATE TRIGGER slack_remote_continuation_insert_guard
BEFORE INSERT ON slack_remote_continuation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM slack_channel_binding binding
        JOIN channel_binding_registry registry USING(binding_id)
        JOIN session ON session.id = binding.session_id
        JOIN slack_envelope_receipt receipt
          ON receipt.binding_id = binding.binding_id
         AND receipt.acknowledgement_id = NEW.source_acknowledgement_id
        WHERE binding.binding_id = NEW.binding_id
          AND binding.principal_id = NEW.principal_id
          AND binding.session_id = NEW.session_id
          AND binding.status = 'active'
          AND registry.status = 'active'
          AND session.status <> 'closed'
          AND receipt.state = 'admitted'
          AND receipt.session_id = NEW.session_id
          AND receipt.workspace_id = binding.team_id
          AND receipt.conversation_id = binding.slack_channel_id
          AND receipt.sender_id = binding.slack_user_id
          AND receipt.thread_id = NEW.thread_id
    ) THEN RAISE(ABORT, 'Slack continuation lacks exact admitted thread evidence') END;

    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM slack_remote_continuation existing
        WHERE existing.binding_id = NEW.binding_id
          AND existing.status = 'active'
          AND existing.expires_at_ms > NEW.created_at_ms
    ) THEN RAISE(ABORT, 'Slack binding already has an effective remote continuation') END;
END;

CREATE TRIGGER slack_remote_continuation_transition_guard
BEFORE UPDATE ON slack_remote_continuation
BEGIN
    SELECT CASE WHEN NEW.remote_continuation_id <> OLD.remote_continuation_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.binding_id <> OLD.binding_id
        OR NEW.session_id <> OLD.session_id
        OR NEW.thread_id <> OLD.thread_id
        OR NEW.source_acknowledgement_id <> OLD.source_acknowledgement_id
        OR NEW.synchronized_after_cursor <> OLD.synchronized_after_cursor
        OR NEW.created_event_id <> OLD.created_event_id
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.expires_at_ms <> OLD.expires_at_ms
        OR NEW.revision <> OLD.revision + 1
        OR OLD.status <> 'active'
        OR NEW.status <> 'revoked'
    THEN RAISE(ABORT, 'invalid Slack remote-continuation transition') END;
END;

CREATE TRIGGER slack_remote_continuation_immutable_delete
BEFORE DELETE ON slack_remote_continuation
BEGIN
    SELECT RAISE(ABORT, 'Slack remote-continuation evidence cannot be removed');
END;

-- A Slack notification definition pins the exact continuation identity. Update/recreate is
-- required to use another thread; runtime delivery cannot silently switch routes.
ALTER TABLE automation
    ADD COLUMN slack_remote_continuation_id TEXT
        REFERENCES slack_remote_continuation(remote_continuation_id) ON DELETE RESTRICT;

CREATE INDEX automation_slack_remote_continuation_idx
    ON automation(slack_remote_continuation_id, status, automation_id);

CREATE TRIGGER automation_slack_remote_route_insert_guard
BEFORE INSERT ON automation
BEGIN
    SELECT CASE WHEN NEW.slack_remote_continuation_id IS NOT NULL
        AND NEW.action_kind <> 'notify'
    THEN RAISE(ABORT, 'only notification automation may use a Slack continuation') END;

    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM slack_channel_binding route
        JOIN channel_binding_registry registry USING(binding_id)
        WHERE route.session_id = NEW.target_session_id
          AND route.binding_id = NEW.target_binding_id
          AND route.principal_id = NEW.principal_id
          AND route.status = 'active'
          AND registry.status = 'active'
    ) AND (
        NEW.action_kind <> 'notify'
        OR NEW.slack_remote_continuation_id IS NULL
        OR NOT EXISTS(
            SELECT 1 FROM slack_remote_continuation continuation
            WHERE continuation.remote_continuation_id = NEW.slack_remote_continuation_id
              AND continuation.principal_id = NEW.principal_id
              AND continuation.binding_id = NEW.target_binding_id
              AND continuation.session_id = NEW.target_session_id
              AND continuation.status = 'active'
              AND continuation.expires_at_ms > NEW.updated_at_ms
        )
    ) THEN RAISE(ABORT, 'Slack notification lacks an effective exact-thread continuation') END;

    SELECT CASE WHEN NEW.slack_remote_continuation_id IS NOT NULL AND NOT EXISTS(
        SELECT 1 FROM slack_channel_binding route
        WHERE route.session_id = NEW.target_session_id
          AND route.binding_id = NEW.target_binding_id
          AND route.principal_id = NEW.principal_id
          AND route.status = 'active'
    ) THEN RAISE(ABORT, 'Slack continuation does not belong to the automation target') END;
END;

CREATE TRIGGER automation_slack_remote_route_update_guard
BEFORE UPDATE OF target_binding_id, target_session_id, action_kind, slack_remote_continuation_id
ON automation
BEGIN
    SELECT CASE WHEN NEW.slack_remote_continuation_id IS NOT NULL
        AND NEW.action_kind <> 'notify'
    THEN RAISE(ABORT, 'only notification automation may use a Slack continuation') END;

    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM slack_channel_binding route
        JOIN channel_binding_registry registry USING(binding_id)
        WHERE route.session_id = NEW.target_session_id
          AND route.binding_id = NEW.target_binding_id
          AND route.principal_id = NEW.principal_id
          AND route.status = 'active'
          AND registry.status = 'active'
    ) AND (
        NEW.action_kind <> 'notify'
        OR NEW.slack_remote_continuation_id IS NULL
        OR NOT EXISTS(
            SELECT 1 FROM slack_remote_continuation continuation
            WHERE continuation.remote_continuation_id = NEW.slack_remote_continuation_id
              AND continuation.principal_id = NEW.principal_id
              AND continuation.binding_id = NEW.target_binding_id
              AND continuation.session_id = NEW.target_session_id
              AND continuation.status = 'active'
              AND continuation.expires_at_ms > NEW.updated_at_ms
        )
    ) THEN RAISE(ABORT, 'Slack notification lacks an effective exact-thread continuation') END;

    SELECT CASE WHEN NEW.slack_remote_continuation_id IS NOT NULL AND NOT EXISTS(
        SELECT 1 FROM slack_channel_binding route
        WHERE route.session_id = NEW.target_session_id
          AND route.binding_id = NEW.target_binding_id
          AND route.principal_id = NEW.principal_id
          AND route.status = 'active'
    ) THEN RAISE(ABORT, 'Slack continuation does not belong to the automation target') END;
END;
