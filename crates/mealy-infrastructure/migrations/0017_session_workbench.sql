-- Canonical owner titles and immutable session checkpoints are the durable foundation shared by
-- the v0.3 terminal and dashboard workbenches. Derived fallback titles remain migration-free.
CREATE TABLE IF NOT EXISTS session_metadata (
    session_id TEXT PRIMARY KEY REFERENCES session(id) ON DELETE CASCADE,
    owner_title TEXT NOT NULL CHECK (
        length(CAST(owner_title AS BLOB)) BETWEEN 1 AND 160
        AND length(owner_title) BETWEEN 1 AND 72
        AND owner_title = trim(owner_title)
    ),
    owner_title_event_id TEXT NOT NULL
        REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    owner_title_updated_at_ms INTEGER NOT NULL,
    UNIQUE (session_id, owner_title_event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS session_checkpoint (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    source_cursor INTEGER NOT NULL REFERENCES timeline_event(cursor) ON DELETE RESTRICT
        CHECK (source_cursor > 0),
    source_turn_id TEXT REFERENCES turn(id) ON DELETE RESTRICT,
    context_epoch_id TEXT REFERENCES context_epoch(id) ON DELETE RESTRICT,
    source_session_revision INTEGER NOT NULL CHECK (source_session_revision >= 0),
    created_session_revision INTEGER NOT NULL CHECK (
        created_session_revision = source_session_revision + 1
    ),
    config_digest TEXT CHECK (
        config_digest IS NULL OR (
            length(config_digest) = 64 AND config_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    policy_digest TEXT CHECK (
        policy_digest IS NULL OR (
            length(policy_digest) = 64 AND policy_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    workspace_identity TEXT CHECK (
        workspace_identity IS NULL OR length(workspace_identity) BETWEEN 1 AND 2048
    ),
    workspace_authority_digest TEXT NOT NULL CHECK (
        length(workspace_authority_digest) = 64
        AND workspace_authority_digest NOT GLOB '*[^0-9a-f]*'
    ),
    provider_id TEXT CHECK (provider_id IS NULL OR length(provider_id) BETWEEN 1 AND 128),
    model_id TEXT CHECK (model_id IS NULL OR length(model_id) BETWEEN 1 AND 128),
    label TEXT CHECK (
        label IS NULL OR (
            length(CAST(label AS BLOB)) BETWEEN 1 AND 160
            AND length(label) BETWEEN 1 AND 72
            AND label = trim(label)
        )
    ),
    created_event_id TEXT NOT NULL UNIQUE
        REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    created_at_ms INTEGER NOT NULL,
    UNIQUE (id, session_id),
    FOREIGN KEY (session_id, principal_id)
        REFERENCES session(id, principal_id) ON DELETE RESTRICT,
    CHECK ((provider_id IS NULL) = (model_id IS NULL)),
    CHECK (
        (context_epoch_id IS NULL AND config_digest IS NULL
         AND policy_digest IS NULL AND workspace_identity IS NULL)
        OR
        (context_epoch_id IS NOT NULL AND config_digest IS NOT NULL
         AND policy_digest IS NOT NULL AND workspace_identity IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS session_checkpoint_owner_idx
    ON session_checkpoint(session_id, created_at_ms DESC, id DESC);

CREATE TRIGGER IF NOT EXISTS session_metadata_time_insert
BEFORE INSERT ON session_metadata
BEGIN
    SELECT CASE WHEN NEW.owner_title_updated_at_ms < (
        SELECT created_at_ms FROM session WHERE id = NEW.session_id
    ) THEN RAISE(ABORT, 'session owner title time predates session creation') END;
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM journal_event event
        JOIN session owner_session
          ON owner_session.id = NEW.session_id
        WHERE event.event_id = NEW.owner_title_event_id
          AND event.aggregate_kind = 'session'
          AND event.aggregate_id = NEW.session_id
          AND event.event_type = 'session.title_updated'
          AND event.actor_principal_id = owner_session.principal_id
          AND event.occurred_at_ms = NEW.owner_title_updated_at_ms
    ) THEN RAISE(ABORT, 'session owner title event binding is inconsistent') END;
END;

CREATE TRIGGER IF NOT EXISTS session_metadata_time_update
BEFORE UPDATE ON session_metadata
BEGIN
    SELECT CASE WHEN NEW.owner_title_updated_at_ms < (
        SELECT created_at_ms FROM session WHERE id = NEW.session_id
    ) THEN RAISE(ABORT, 'session owner title time predates session creation') END;
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM journal_event event
        JOIN session owner_session
          ON owner_session.id = NEW.session_id
        WHERE event.event_id = NEW.owner_title_event_id
          AND event.aggregate_kind = 'session'
          AND event.aggregate_id = NEW.session_id
          AND event.event_type = 'session.title_updated'
          AND event.actor_principal_id = owner_session.principal_id
          AND event.occurred_at_ms = NEW.owner_title_updated_at_ms
    ) THEN RAISE(ABORT, 'session owner title event binding is inconsistent') END;
END;

CREATE TRIGGER IF NOT EXISTS session_checkpoint_binding_insert
BEFORE INSERT ON session_checkpoint
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM session
        WHERE id = NEW.session_id
          AND principal_id = NEW.principal_id
          AND revision = NEW.source_session_revision
    ) THEN RAISE(ABORT, 'checkpoint source session revision is inconsistent') END;
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM journal_event event
        JOIN timeline_event timeline ON timeline.event_id = event.event_id
        WHERE event.event_id = NEW.created_event_id
          AND event.aggregate_kind = 'session'
          AND event.aggregate_id = NEW.session_id
          AND event.event_type = 'session.checkpoint_created'
          AND event.actor_principal_id = NEW.principal_id
          AND event.correlation_id = NEW.correlation_id
          AND event.occurred_at_ms = NEW.created_at_ms
          AND timeline.cursor > NEW.source_cursor
    ) THEN RAISE(ABORT, 'checkpoint creation event binding is inconsistent') END;
    SELECT CASE WHEN NEW.source_turn_id IS NOT NULL AND NOT EXISTS(
        SELECT 1 FROM turn
        WHERE id = NEW.source_turn_id
          AND session_id = NEW.session_id
          AND status = 'completed'
          AND turn_kind = 'canonical'
    ) THEN RAISE(ABORT, 'checkpoint turn is not a completed canonical session turn') END;
    SELECT CASE WHEN NEW.context_epoch_id IS NOT NULL AND NOT EXISTS(
        SELECT 1 FROM context_epoch
        WHERE id = NEW.context_epoch_id
          AND session_id = NEW.session_id
          AND config_digest = NEW.config_digest
          AND policy_digest = NEW.policy_digest
          AND workspace_identity = NEW.workspace_identity
    ) THEN RAISE(ABORT, 'checkpoint context epoch binding is inconsistent') END;
END;

CREATE TRIGGER IF NOT EXISTS session_checkpoint_immutable_update
BEFORE UPDATE ON session_checkpoint
BEGIN
    SELECT RAISE(ABORT, 'session checkpoint evidence is immutable');
END;

CREATE TRIGGER IF NOT EXISTS session_checkpoint_immutable_delete
BEFORE DELETE ON session_checkpoint
BEGIN
    SELECT RAISE(ABORT, 'session checkpoint evidence is immutable');
END;
