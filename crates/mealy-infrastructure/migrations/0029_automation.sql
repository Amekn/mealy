PRAGMA foreign_keys = ON;

-- Revisioned one-shot and direct-session-event automation. Recurring cron schedules remain in
-- agent_schedule so their already-published immutable/recovery contract does not change.
CREATE TABLE automation (
    automation_id TEXT PRIMARY KEY CHECK (length(automation_id) > 0),
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    manager_binding_id TEXT NOT NULL CHECK (length(manager_binding_id) > 0),
    target_binding_id TEXT NOT NULL CHECK (length(target_binding_id) > 0),
    target_session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (
        length(CAST(name AS BLOB)) BETWEEN 1 AND 128 AND trim(name) = name
    ),
    trigger_kind TEXT NOT NULL CHECK (trigger_kind IN ('one_shot', 'session_event')),
    due_at_ms INTEGER CHECK (due_at_ms IS NULL OR due_at_ms >= 0),
    source_session_id TEXT REFERENCES session(id) ON DELETE RESTRICT,
    source_event_type TEXT CHECK (
        source_event_type IS NULL OR length(source_event_type) BETWEEN 1 AND 128
    ),
    source_after_cursor INTEGER CHECK (source_after_cursor IS NULL OR source_after_cursor >= 0),
    action_kind TEXT NOT NULL CHECK (action_kind IN ('submit_prompt', 'notify')),
    action_body TEXT NOT NULL CHECK (length(CAST(action_body AS BLOB)) BETWEEN 1 AND 65536),
    approval_required_actions_allowed INTEGER NOT NULL
        CHECK (approval_required_actions_allowed IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('active', 'paused', 'completed', 'cancelled')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    CHECK (
        (
            trigger_kind = 'one_shot'
            AND due_at_ms IS NOT NULL
            AND source_session_id IS NULL
            AND source_event_type IS NULL
            AND source_after_cursor IS NULL
        )
        OR (
            trigger_kind = 'session_event'
            AND due_at_ms IS NULL
            AND source_session_id IS NOT NULL
            AND source_event_type IS NOT NULL
            AND source_after_cursor IS NOT NULL
            AND action_kind = 'notify'
            AND status <> 'completed'
        )
    ),
    CHECK (
        (action_kind = 'submit_prompt')
        OR (action_kind = 'notify' AND length(CAST(action_body AS BLOB)) <= 4096
            AND approval_required_actions_allowed = 0)
    )
) STRICT;

CREATE INDEX automation_owner_idx
    ON automation(principal_id, created_at_ms, automation_id);
CREATE INDEX automation_due_idx
    ON automation(status, trigger_kind, due_at_ms, automation_id);
CREATE INDEX automation_event_idx
    ON automation(status, trigger_kind, source_session_id, source_event_type, source_after_cursor);

CREATE TRIGGER automation_insert_guard
BEFORE INSERT ON automation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM principal_registry principal
        JOIN channel_binding_registry manager
          ON manager.principal_id = principal.principal_id
        WHERE principal.principal_id = NEW.principal_id
          AND principal.status = 'active'
          AND manager.binding_id = NEW.manager_binding_id
          AND manager.status = 'active'
    ) THEN RAISE(ABORT, 'automation manager ownership is invalid') END;

    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM session target
        JOIN channel_binding_registry binding
          ON binding.binding_id = target.channel_binding_id
         AND binding.principal_id = target.principal_id
        WHERE target.id = NEW.target_session_id
          AND target.principal_id = NEW.principal_id
          AND target.channel_binding_id = NEW.target_binding_id
          AND target.status <> 'closed'
          AND binding.status = 'active'
    ) THEN RAISE(ABORT, 'automation target ownership is invalid') END;

    SELECT CASE WHEN NEW.trigger_kind = 'session_event' AND NOT EXISTS(
        SELECT 1 FROM session source
        JOIN channel_binding_registry source_binding
          ON source_binding.binding_id = source.channel_binding_id
         AND source_binding.principal_id = source.principal_id
        WHERE source.id = NEW.source_session_id
          AND source.principal_id = NEW.principal_id
          AND source.status <> 'closed'
          AND source_binding.status = 'active'
    ) THEN RAISE(ABORT, 'automation source ownership is invalid') END;
END;

CREATE TRIGGER automation_definition_update_guard
BEFORE UPDATE OF target_binding_id, target_session_id, name, trigger_kind, due_at_ms,
                 source_session_id, source_event_type, action_kind, action_body,
                 approval_required_actions_allowed
ON automation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM session target
        JOIN channel_binding_registry binding
          ON binding.binding_id = target.channel_binding_id
         AND binding.principal_id = target.principal_id
        WHERE target.id = NEW.target_session_id
          AND target.principal_id = NEW.principal_id
          AND target.channel_binding_id = NEW.target_binding_id
          AND target.status <> 'closed'
          AND binding.status = 'active'
    ) THEN RAISE(ABORT, 'automation target ownership is invalid') END;

    SELECT CASE WHEN NEW.trigger_kind = 'session_event' AND NOT EXISTS(
        SELECT 1 FROM session source
        JOIN channel_binding_registry source_binding
          ON source_binding.binding_id = source.channel_binding_id
         AND source_binding.principal_id = source.principal_id
        WHERE source.id = NEW.source_session_id
          AND source.principal_id = NEW.principal_id
          AND source.status <> 'closed'
          AND source_binding.status = 'active'
    ) THEN RAISE(ABORT, 'automation source ownership is invalid') END;
END;

CREATE TRIGGER automation_transition_guard
BEFORE UPDATE ON automation
BEGIN
    SELECT CASE WHEN NEW.automation_id <> OLD.automation_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.manager_binding_id <> OLD.manager_binding_id
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.revision <> OLD.revision + 1
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR OLD.status IN ('completed', 'cancelled')
        OR NEW.source_after_cursor IS NOT NULL
           AND OLD.source_after_cursor IS NOT NULL
           AND NEW.trigger_kind = OLD.trigger_kind
           AND NEW.source_session_id = OLD.source_session_id
           AND NEW.source_event_type = OLD.source_event_type
           AND NEW.source_after_cursor < OLD.source_after_cursor
    THEN RAISE(ABORT, 'invalid automation transition') END;
END;

CREATE TRIGGER automation_immutable_delete
BEFORE DELETE ON automation
BEGIN
    SELECT RAISE(ABORT, 'automation audit history cannot be removed');
END;

CREATE TABLE automation_revision (
    automation_id TEXT NOT NULL REFERENCES automation(automation_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    definition_json TEXT NOT NULL CHECK (json_valid(definition_json)),
    definition_digest TEXT NOT NULL CHECK (
        length(definition_digest) = 64 AND definition_digest NOT GLOB '*[^0-9a-f]*'
    ),
    event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    recorded_at_ms INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
    PRIMARY KEY(automation_id, revision)
) STRICT;

CREATE TRIGGER automation_revision_immutable_update
BEFORE UPDATE ON automation_revision
BEGIN
    SELECT RAISE(ABORT, 'automation revision evidence is immutable');
END;

CREATE TRIGGER automation_revision_immutable_delete
BEFORE DELETE ON automation_revision
BEGIN
    SELECT RAISE(ABORT, 'automation revision evidence cannot be removed');
END;

CREATE TABLE automation_run (
    automation_run_id TEXT PRIMARY KEY CHECK (length(automation_run_id) > 0),
    automation_id TEXT NOT NULL REFERENCES automation(automation_id) ON DELETE RESTRICT,
    trigger_key TEXT NOT NULL CHECK (length(trigger_key) BETWEEN 1 AND 160),
    triggered_at_ms INTEGER NOT NULL CHECK (triggered_at_ms >= 0),
    source_event_cursor INTEGER CHECK (source_event_cursor IS NULL OR source_event_cursor > 0),
    source_event_id TEXT REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    source_event_type TEXT CHECK (
        source_event_type IS NULL OR length(source_event_type) BETWEEN 1 AND 128
    ),
    status TEXT NOT NULL CHECK (status IN ('claimed', 'admitted', 'notified', 'failed')),
    claim_owner_id TEXT NOT NULL CHECK (length(claim_owner_id) > 0),
    claim_expires_at_ms INTEGER NOT NULL,
    inbox_entry_id TEXT REFERENCES session_inbox(inbox_entry_id) ON DELETE RESTRICT,
    outbox_id TEXT REFERENCES outbox(outbox_id) ON DELETE RESTRICT,
    reason TEXT CHECK (
        reason IS NULL OR (length(reason) BETWEEN 1 AND 4096 AND trim(reason) = reason)
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    completed_at_ms INTEGER,
    UNIQUE(automation_id, trigger_key),
    CHECK (claim_expires_at_ms > created_at_ms),
    CHECK (
        (
            source_event_cursor IS NULL
            AND source_event_id IS NULL
            AND source_event_type IS NULL
            AND trigger_key = 'time:' || CAST(triggered_at_ms AS TEXT)
        )
        OR (
            source_event_cursor IS NOT NULL
            AND source_event_id IS NOT NULL
            AND source_event_type IS NOT NULL
            AND trigger_key = 'event:' || CAST(source_event_cursor AS TEXT)
        )
    ),
    CHECK (
        (
            status = 'claimed'
            AND inbox_entry_id IS NULL AND outbox_id IS NULL AND reason IS NULL
            AND completed_at_ms IS NULL
        )
        OR (
            status = 'admitted'
            AND inbox_entry_id IS NOT NULL AND outbox_id IS NULL AND reason IS NULL
            AND completed_at_ms IS NOT NULL AND completed_at_ms >= created_at_ms
        )
        OR (
            status = 'notified'
            AND inbox_entry_id IS NULL AND outbox_id IS NOT NULL AND reason IS NULL
            AND completed_at_ms IS NOT NULL AND completed_at_ms >= created_at_ms
        )
        OR (
            status = 'failed'
            AND inbox_entry_id IS NULL AND outbox_id IS NULL AND reason IS NOT NULL
            AND completed_at_ms IS NOT NULL AND completed_at_ms >= created_at_ms
        )
    )
) STRICT;

CREATE INDEX automation_run_history_idx
    ON automation_run(automation_id, triggered_at_ms DESC, automation_run_id DESC);
CREATE INDEX automation_run_claim_idx
    ON automation_run(status, claim_expires_at_ms, automation_run_id);

CREATE TRIGGER automation_run_transition_guard
BEFORE UPDATE ON automation_run
BEGIN
    SELECT CASE WHEN NEW.automation_run_id <> OLD.automation_run_id
        OR NEW.automation_id <> OLD.automation_id
        OR NEW.trigger_key <> OLD.trigger_key
        OR NEW.triggered_at_ms <> OLD.triggered_at_ms
        OR NEW.source_event_cursor IS NOT OLD.source_event_cursor
        OR NEW.source_event_id IS NOT OLD.source_event_id
        OR NEW.source_event_type IS NOT OLD.source_event_type
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR OLD.status <> 'claimed'
    THEN RAISE(ABORT, 'invalid automation run transition') END;
END;

CREATE TRIGGER automation_run_immutable_delete
BEFORE DELETE ON automation_run
BEGIN
    SELECT RAISE(ABORT, 'automation run history cannot be removed');
END;
