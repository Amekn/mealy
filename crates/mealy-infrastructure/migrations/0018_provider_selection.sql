-- Provider/model choices are resolved at admission and copied onto the new turn. This preserves
-- exact execution identity across queueing, retries, daemon restarts, and later session-default
-- changes. A missing pair means the compatible configured route remains automatic.
CREATE TABLE IF NOT EXISTS session_provider_selection (
    session_id TEXT PRIMARY KEY REFERENCES session(id) ON DELETE CASCADE,
    provider_id TEXT CHECK (provider_id IS NULL OR length(provider_id) BETWEEN 1 AND 128),
    model_id TEXT CHECK (model_id IS NULL OR length(model_id) BETWEEN 1 AND 256),
    selection_event_id TEXT NOT NULL UNIQUE
        REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    updated_at_ms INTEGER NOT NULL,
    CHECK ((provider_id IS NULL) = (model_id IS NULL))
) STRICT;

ALTER TABLE session_inbox ADD COLUMN provider_selection_source TEXT NOT NULL
    DEFAULT 'inherited'
    CHECK (provider_selection_source IN ('inherited', 'automatic', 'exact'));
ALTER TABLE session_inbox ADD COLUMN selected_provider_id TEXT
    CHECK (selected_provider_id IS NULL OR length(selected_provider_id) BETWEEN 1 AND 128);
ALTER TABLE session_inbox ADD COLUMN selected_model_id TEXT
    CHECK (selected_model_id IS NULL OR length(selected_model_id) BETWEEN 1 AND 256);

ALTER TABLE turn ADD COLUMN selected_provider_id TEXT
    CHECK (selected_provider_id IS NULL OR length(selected_provider_id) BETWEEN 1 AND 128);
ALTER TABLE turn ADD COLUMN selected_model_id TEXT
    CHECK (selected_model_id IS NULL OR length(selected_model_id) BETWEEN 1 AND 256);

CREATE TRIGGER IF NOT EXISTS session_provider_selection_insert_binding
BEFORE INSERT ON session_provider_selection
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM session
        JOIN journal_event event ON event.event_id = NEW.selection_event_id
        WHERE session.id = NEW.session_id
          AND event.aggregate_kind = 'session'
          AND event.aggregate_id = NEW.session_id
          AND event.event_type IN ('session.created', 'session.provider_selection_updated')
          AND event.actor_principal_id = session.principal_id
          AND event.occurred_at_ms = NEW.updated_at_ms
    ) THEN RAISE(ABORT, 'session provider selection event binding is inconsistent') END;
END;

CREATE TRIGGER IF NOT EXISTS session_provider_selection_update_binding
BEFORE UPDATE ON session_provider_selection
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM session
        JOIN journal_event event ON event.event_id = NEW.selection_event_id
        WHERE session.id = NEW.session_id
          AND event.aggregate_kind = 'session'
          AND event.aggregate_id = NEW.session_id
          AND event.event_type = 'session.provider_selection_updated'
          AND event.actor_principal_id = session.principal_id
          AND event.occurred_at_ms = NEW.updated_at_ms
    ) THEN RAISE(ABORT, 'session provider selection update event binding is inconsistent') END;
END;

CREATE TRIGGER IF NOT EXISTS session_inbox_provider_selection_insert
BEFORE INSERT ON session_inbox
BEGIN
    SELECT CASE WHEN
        (NEW.selected_provider_id IS NULL) <> (NEW.selected_model_id IS NULL)
        OR (
            NEW.provider_selection_source = 'exact'
            AND NEW.selected_provider_id IS NULL
        )
        OR (
            NEW.provider_selection_source = 'automatic'
            AND NEW.selected_provider_id IS NOT NULL
        )
    THEN RAISE(ABORT, 'inbox provider selection is inconsistent') END;
END;

CREATE TRIGGER IF NOT EXISTS session_inbox_provider_selection_immutable
BEFORE UPDATE OF provider_selection_source, selected_provider_id, selected_model_id
ON session_inbox
BEGIN
    SELECT RAISE(ABORT, 'admitted inbox provider selection is immutable');
END;

CREATE TRIGGER IF NOT EXISTS turn_provider_selection_insert
BEFORE INSERT ON turn
BEGIN
    SELECT CASE WHEN
        (NEW.selected_provider_id IS NULL) <> (NEW.selected_model_id IS NULL)
        OR NOT EXISTS(
            SELECT 1 FROM session_inbox inbox
            WHERE inbox.inbox_entry_id = NEW.inbox_entry_id
              AND inbox.session_id = NEW.session_id
              AND inbox.selected_provider_id IS NEW.selected_provider_id
              AND inbox.selected_model_id IS NEW.selected_model_id
        )
    THEN RAISE(ABORT, 'turn provider selection does not match admitted input') END;
END;

CREATE TRIGGER IF NOT EXISTS turn_provider_selection_immutable
BEFORE UPDATE OF selected_provider_id, selected_model_id ON turn
BEGIN
    SELECT RAISE(ABORT, 'turn provider selection is immutable');
END;
