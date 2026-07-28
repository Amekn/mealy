-- Canonical owner titles, immutable checkpoints, and immutable fork lineage are the durable
-- foundation shared by the v0.3 terminal and dashboard workbenches. Derived fallback titles and
-- bounded read-only transcript exports remain migration-free.
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

-- Every ordinary session is its own lineage root. A fork is a fresh session whose only parent
-- edge is one immutable checkpoint; operational state is never cloned across that edge.
CREATE TABLE IF NOT EXISTS session_lineage (
    session_id TEXT PRIMARY KEY REFERENCES session(id) ON DELETE RESTRICT,
    root_session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    parent_checkpoint_id TEXT REFERENCES session_checkpoint(id) ON DELETE RESTRICT,
    fork_event_id TEXT UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    CHECK (
        (
            session_id = root_session_id
            AND parent_checkpoint_id IS NULL
            AND fork_event_id IS NULL
        )
        OR
        (
            session_id <> root_session_id
            AND parent_checkpoint_id IS NOT NULL
            AND fork_event_id IS NOT NULL
        )
    )
) STRICT;

INSERT OR IGNORE INTO session_lineage(
    session_id, root_session_id, parent_checkpoint_id, fork_event_id, created_at_ms
)
SELECT id, id, NULL, NULL, created_at_ms
FROM session;

CREATE TABLE IF NOT EXISTS session_fork_command (
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    channel_binding_id TEXT NOT NULL CHECK (length(channel_binding_id) > 0),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 128
        AND idempotency_key = trim(idempotency_key)
    ),
    source_checkpoint_id TEXT NOT NULL
        REFERENCES session_checkpoint(id) ON DELETE RESTRICT,
    fork_session_id TEXT NOT NULL UNIQUE
        REFERENCES session_lineage(session_id) ON DELETE RESTRICT,
    event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (principal_id, channel_binding_id, idempotency_key)
) STRICT;

-- Fork history is citation-like evidence. User text remains in its immutable admitted inbox row;
-- assistant text remains in its terminal message row. Digests are pinned here and rechecked on
-- every context projection or export.
CREATE TABLE IF NOT EXISTS session_fork_context_reference (
    fork_session_id TEXT NOT NULL
        REFERENCES session_lineage(session_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 32),
    source_checkpoint_id TEXT NOT NULL
        REFERENCES session_checkpoint(id) ON DELETE RESTRICT,
    source_turn_id TEXT NOT NULL REFERENCES turn(id) ON DELETE RESTRICT,
    source_inbox_entry_id TEXT NOT NULL
        REFERENCES session_inbox(inbox_entry_id) ON DELETE RESTRICT,
    source_user_content_digest TEXT NOT NULL CHECK (
        length(source_user_content_digest) = 64
        AND source_user_content_digest NOT GLOB '*[^0-9a-f]*'
    ),
    source_assistant_message_id TEXT NOT NULL REFERENCES message(id) ON DELETE RESTRICT,
    source_assistant_content_digest TEXT NOT NULL CHECK (
        length(source_assistant_content_digest) = 64
        AND source_assistant_content_digest NOT GLOB '*[^0-9a-f]*'
    ),
    source_completion_cursor INTEGER NOT NULL
        REFERENCES timeline_event(cursor) ON DELETE RESTRICT CHECK (source_completion_cursor > 0),
    PRIMARY KEY (fork_session_id, ordinal),
    UNIQUE (fork_session_id, source_turn_id),
    UNIQUE (fork_session_id, source_inbox_entry_id),
    UNIQUE (fork_session_id, source_assistant_message_id)
) STRICT;

CREATE INDEX IF NOT EXISTS session_lineage_root_idx
    ON session_lineage(root_session_id, created_at_ms, session_id);

CREATE TRIGGER IF NOT EXISTS session_lineage_binding_insert
BEFORE INSERT ON session_lineage
WHEN NEW.parent_checkpoint_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM session_checkpoint checkpoint
        JOIN session_lineage source_lineage
          ON source_lineage.session_id = checkpoint.session_id
        JOIN session source_session ON source_session.id = checkpoint.session_id
        JOIN session fork_session ON fork_session.id = NEW.session_id
        JOIN journal_event event ON event.event_id = NEW.fork_event_id
        WHERE checkpoint.id = NEW.parent_checkpoint_id
          AND source_lineage.root_session_id = NEW.root_session_id
          AND checkpoint.principal_id = fork_session.principal_id
          AND source_session.principal_id = fork_session.principal_id
          AND source_session.channel_binding_id = fork_session.channel_binding_id
          AND event.aggregate_kind = 'session'
          AND event.aggregate_id = NEW.session_id
          AND event.aggregate_sequence = 0
          AND event.event_type = 'session.forked'
          AND event.actor_principal_id = fork_session.principal_id
          AND event.occurred_at_ms = NEW.created_at_ms
    ) THEN RAISE(ABORT, 'fork lineage binding is inconsistent') END;
END;

CREATE TRIGGER IF NOT EXISTS session_lineage_immutable_update
BEFORE UPDATE ON session_lineage
BEGIN
    SELECT RAISE(ABORT, 'session lineage is immutable');
END;

CREATE TRIGGER IF NOT EXISTS session_lineage_immutable_delete
BEFORE DELETE ON session_lineage
BEGIN
    SELECT RAISE(ABORT, 'session lineage is immutable');
END;

CREATE TRIGGER IF NOT EXISTS session_fork_command_binding_insert
BEFORE INSERT ON session_fork_command
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM session_lineage lineage
        JOIN session fork_session ON fork_session.id = lineage.session_id
        JOIN journal_event event ON event.event_id = NEW.event_id
        WHERE lineage.session_id = NEW.fork_session_id
          AND lineage.parent_checkpoint_id = NEW.source_checkpoint_id
          AND lineage.fork_event_id = NEW.event_id
          AND fork_session.principal_id = NEW.principal_id
          AND fork_session.channel_binding_id = NEW.channel_binding_id
          AND event.aggregate_kind = 'session'
          AND event.aggregate_id = NEW.fork_session_id
          AND event.aggregate_sequence = 0
          AND event.event_type = 'session.forked'
          AND event.actor_principal_id = NEW.principal_id
          AND event.correlation_id = NEW.correlation_id
          AND event.occurred_at_ms = NEW.created_at_ms
          AND lineage.created_at_ms = NEW.created_at_ms
    ) THEN RAISE(ABORT, 'fork command receipt binding is inconsistent') END;
END;

CREATE TRIGGER IF NOT EXISTS session_fork_command_immutable_update
BEFORE UPDATE ON session_fork_command
BEGIN
    SELECT RAISE(ABORT, 'session fork command receipt is immutable');
END;

CREATE TRIGGER IF NOT EXISTS session_fork_command_immutable_delete
BEFORE DELETE ON session_fork_command
BEGIN
    SELECT RAISE(ABORT, 'session fork command receipt is immutable');
END;

CREATE TRIGGER IF NOT EXISTS session_fork_context_reference_binding_insert
BEFORE INSERT ON session_fork_context_reference
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM session_lineage lineage
        JOIN session_checkpoint checkpoint
          ON checkpoint.id = NEW.source_checkpoint_id
        JOIN turn source_turn ON source_turn.id = NEW.source_turn_id
        JOIN session_inbox source_inbox
          ON source_inbox.inbox_entry_id = NEW.source_inbox_entry_id
        JOIN task source_task ON source_task.id = source_turn.task_id
        JOIN run source_run
          ON source_run.id = source_turn.run_id
         AND source_run.task_id = source_task.id
        JOIN run_loop_state loop ON loop.run_id = source_run.id
        JOIN message assistant
          ON assistant.id = NEW.source_assistant_message_id
         AND assistant.id = loop.final_message_id
        JOIN journal_event completion
          ON completion.aggregate_kind = 'turn'
         AND completion.aggregate_id = source_turn.id
         AND completion.event_type = 'turn.completed'
        JOIN timeline_event completion_timeline
          ON completion_timeline.event_id = completion.event_id
        WHERE lineage.session_id = NEW.fork_session_id
          AND lineage.parent_checkpoint_id = NEW.source_checkpoint_id
          AND checkpoint.session_id = source_turn.session_id
          AND source_turn.context_epoch_id IS checkpoint.context_epoch_id
          AND source_turn.status = 'completed'
          AND source_turn.turn_kind = 'canonical'
          AND source_task.status = 'succeeded'
          AND source_run.status = 'succeeded'
          AND source_inbox.session_id = source_turn.session_id
          AND source_inbox.promoted_turn_id = source_turn.id
          AND source_inbox.state = 'promoted'
          AND assistant.session_id = source_turn.session_id
          AND assistant.turn_id = source_turn.id
          AND assistant.task_id = source_task.id
          AND assistant.run_id = source_run.id
          AND assistant.role = 'assistant'
          AND assistant.media_type = 'text/plain; charset=utf-8'
          AND assistant.sensitivity = 'internal'
          AND assistant.content_inline IS NOT NULL
          AND assistant.content_artifact_id IS NULL
          AND assistant.content_digest = NEW.source_assistant_content_digest
          AND completion_timeline.cursor = NEW.source_completion_cursor
          AND completion_timeline.cursor <= checkpoint.source_cursor
    ) THEN RAISE(ABORT, 'fork conversation reference binding is inconsistent') END;
END;

CREATE TRIGGER IF NOT EXISTS session_fork_context_reference_immutable_update
BEFORE UPDATE ON session_fork_context_reference
BEGIN
    SELECT RAISE(ABORT, 'session fork conversation reference is immutable');
END;

CREATE TRIGGER IF NOT EXISTS session_fork_context_reference_immutable_delete
BEFORE DELETE ON session_fork_context_reference
BEGIN
    SELECT RAISE(ABORT, 'session fork conversation reference is immutable');
END;
