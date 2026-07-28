PRAGMA foreign_keys = ON;

-- A Slack binding grants one exact workspace/member/conversation route. Multiple routes may share
-- one verified app installation only when every credential and bot identity pin is identical; the
-- daemon groups those routes behind one Socket Mode connection.
CREATE TABLE slack_channel_binding (
    binding_id TEXT PRIMARY KEY
        REFERENCES channel_binding_registry(binding_id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL REFERENCES principal_registry(principal_id) ON DELETE RESTRICT,
    session_id TEXT NOT NULL UNIQUE REFERENCES session(id) ON DELETE RESTRICT,
    team_id TEXT NOT NULL CHECK (
        length(team_id) BETWEEN 2 AND 64
        AND substr(team_id, 1, 1) = 'T'
        AND team_id NOT GLOB '*[^A-Z0-9]*'
    ),
    team_name TEXT NOT NULL CHECK (length(CAST(team_name AS BLOB)) BETWEEN 1 AND 128),
    slack_user_id TEXT NOT NULL CHECK (
        length(slack_user_id) BETWEEN 2 AND 64
        AND substr(slack_user_id, 1, 1) IN ('U', 'W')
        AND slack_user_id NOT GLOB '*[^A-Z0-9]*'
    ),
    slack_channel_id TEXT NOT NULL CHECK (
        length(slack_channel_id) BETWEEN 2 AND 64
        AND substr(slack_channel_id, 1, 1) IN ('C', 'G', 'D')
        AND slack_channel_id NOT GLOB '*[^A-Z0-9]*'
    ),
    bot_user_id TEXT NOT NULL CHECK (
        length(bot_user_id) BETWEEN 2 AND 64
        AND substr(bot_user_id, 1, 1) IN ('U', 'W')
        AND bot_user_id NOT GLOB '*[^A-Z0-9]*'
        AND bot_user_id <> slack_user_id
    ),
    bot_name TEXT NOT NULL CHECK (length(CAST(bot_name AS BLOB)) BETWEEN 1 AND 128),
    require_mention INTEGER NOT NULL CHECK (require_mention IN (0, 1)),
    app_token_secret_id TEXT NOT NULL CHECK (length(app_token_secret_id) BETWEEN 1 AND 128),
    app_token_digest TEXT NOT NULL CHECK (
        length(app_token_digest) = 64 AND app_token_digest NOT GLOB '*[^0-9a-f]*'
    ),
    bot_token_secret_id TEXT NOT NULL CHECK (
        length(bot_token_secret_id) BETWEEN 1 AND 128
        AND bot_token_secret_id <> app_token_secret_id
    ),
    bot_token_digest TEXT NOT NULL CHECK (
        length(bot_token_digest) = 64 AND bot_token_digest NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_event_id TEXT NOT NULL UNIQUE REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    revoked_at_ms INTEGER,
    UNIQUE(binding_id, principal_id),
    UNIQUE(team_id, slack_channel_id, slack_user_id),
    CHECK (slack_channel_id NOT LIKE 'D%' OR require_mention = 0),
    CHECK (
        (status = 'active' AND revoked_at_ms IS NULL)
        OR (status = 'revoked' AND revoked_at_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX slack_channel_owner_idx
    ON slack_channel_binding(principal_id, created_at_ms, binding_id);
CREATE INDEX slack_channel_installation_idx
    ON slack_channel_binding(app_token_digest, status, created_at_ms, binding_id);

CREATE TRIGGER slack_channel_binding_insert_guard
BEFORE INSERT ON slack_channel_binding
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM channel_binding_registry binding
        JOIN session ON session.id = NEW.session_id
        WHERE binding.binding_id = NEW.binding_id
          AND binding.principal_id = NEW.principal_id
          AND binding.channel_kind = 'extension_channel'
          AND binding.installation_id = 'builtin.slack.socket.v1'
          AND binding.status = 'active'
          AND session.principal_id = NEW.principal_id
          AND session.channel_binding_id = NEW.binding_id
    ) THEN RAISE(ABORT, 'Slack binding lacks exact registry and session identity') END;

    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM slack_channel_binding existing
        WHERE (
                existing.app_token_secret_id = NEW.app_token_secret_id
                OR existing.app_token_digest = NEW.app_token_digest
              )
          AND (
                existing.app_token_secret_id <> NEW.app_token_secret_id
                OR existing.app_token_digest <> NEW.app_token_digest
                OR existing.bot_token_secret_id <> NEW.bot_token_secret_id
                OR existing.bot_token_digest <> NEW.bot_token_digest
                OR existing.team_id <> NEW.team_id
                OR existing.bot_user_id <> NEW.bot_user_id
              )
    ) THEN RAISE(ABORT, 'shared Slack installation authority is inconsistent') END;
END;

CREATE TRIGGER slack_channel_binding_transition
BEFORE UPDATE ON slack_channel_binding
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.principal_id <> OLD.principal_id
        OR NEW.session_id <> OLD.session_id
        OR NEW.team_id <> OLD.team_id
        OR NEW.team_name <> OLD.team_name
        OR NEW.slack_user_id <> OLD.slack_user_id
        OR NEW.slack_channel_id <> OLD.slack_channel_id
        OR NEW.bot_user_id <> OLD.bot_user_id
        OR NEW.bot_name <> OLD.bot_name
        OR NEW.require_mention <> OLD.require_mention
        OR NEW.app_token_secret_id <> OLD.app_token_secret_id
        OR NEW.app_token_digest <> OLD.app_token_digest
        OR NEW.bot_token_secret_id <> OLD.bot_token_secret_id
        OR NEW.bot_token_digest <> OLD.bot_token_digest
        OR NEW.created_event_id <> OLD.created_event_id
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.revision <> OLD.revision + 1
        OR OLD.status <> 'active' OR NEW.status <> 'revoked'
    THEN RAISE(ABORT, 'invalid Slack channel revocation transition') END;
END;

CREATE TRIGGER slack_channel_binding_immutable_delete
BEFORE DELETE ON slack_channel_binding
BEGIN
    SELECT RAISE(ABORT, 'Slack channel evidence cannot be removed');
END;

CREATE TABLE slack_channel_health (
    binding_id TEXT PRIMARY KEY
        REFERENCES slack_channel_binding(binding_id) ON DELETE RESTRICT,
    last_success_at_ms INTEGER,
    last_failure_at_ms INTEGER,
    consecutive_failures INTEGER NOT NULL CHECK (consecutive_failures >= 0),
    last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK (
        (consecutive_failures = 0 AND last_error_code IS NULL)
        OR (consecutive_failures > 0 AND last_failure_at_ms IS NOT NULL
            AND last_error_code IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER slack_channel_health_transition
BEFORE UPDATE ON slack_channel_health
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.revision <> OLD.revision + 1
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.last_success_at_ms IS NOT NULL
           AND OLD.last_success_at_ms IS NOT NULL
           AND NEW.last_success_at_ms < OLD.last_success_at_ms
        OR NEW.last_failure_at_ms IS NOT NULL
           AND OLD.last_failure_at_ms IS NOT NULL
           AND NEW.last_failure_at_ms < OLD.last_failure_at_ms
    THEN RAISE(ABORT, 'invalid Slack channel health transition') END;
END;

CREATE TRIGGER slack_channel_health_immutable_delete
BEFORE DELETE ON slack_channel_health
BEGIN
    SELECT RAISE(ABORT, 'Slack channel health cannot be removed');
END;

-- The complete normalized action is stored before the transport acknowledgement. A restart can
-- therefore finish admission even when Slack does not redeliver an already acknowledged envelope.
CREATE TABLE slack_envelope_receipt (
    binding_id TEXT NOT NULL
        REFERENCES slack_channel_binding(binding_id) ON DELETE RESTRICT,
    acknowledgement_id TEXT NOT NULL CHECK (
        length(acknowledgement_id) BETWEEN 1 AND 128
        AND acknowledgement_id NOT GLOB '*[^A-Za-z0-9_-]*'
    ),
    body_digest TEXT NOT NULL CHECK (
        length(body_digest) = 64 AND body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    disposition_kind TEXT NOT NULL CHECK (disposition_kind IN ('admit', 'ignore')),
    delivery_id TEXT CHECK (
        delivery_id IS NULL OR (
            length(delivery_id) BETWEEN 1 AND 128
            AND delivery_id NOT GLOB '*[^A-Za-z0-9_-]*'
        )
    ),
    workspace_id TEXT,
    conversation_id TEXT,
    thread_id TEXT,
    sender_id TEXT,
    normalized_text TEXT CHECK (
        normalized_text IS NULL
        OR length(CAST(normalized_text AS BLOB)) BETWEEN 1 AND 32768
    ),
    source_locator TEXT CHECK (
        source_locator IS NULL OR length(CAST(source_locator AS BLOB)) BETWEEN 1 AND 512
    ),
    ignore_reason TEXT CHECK (
        ignore_reason IS NULL OR (
            length(ignore_reason) BETWEEN 1 AND 256
            AND ignore_reason NOT GLOB '*[^a-z0-9_]*'
        )
    ),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'admitted', 'ignored')),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    inbox_entry_id TEXT REFERENCES session_inbox(inbox_entry_id) ON DELETE RESTRICT,
    acknowledgement_outbox_id TEXT REFERENCES outbox(outbox_id) ON DELETE RESTRICT,
    acknowledged_at_ms INTEGER,
    received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0),
    completed_at_ms INTEGER,
    PRIMARY KEY(binding_id, acknowledgement_id),
    CHECK (
        (
            disposition_kind = 'admit'
            AND delivery_id IS NOT NULL
            AND workspace_id IS NOT NULL
            AND conversation_id IS NOT NULL
            AND sender_id IS NOT NULL
            AND normalized_text IS NOT NULL
            AND source_locator IS NOT NULL
            AND ignore_reason IS NULL
        )
        OR (
            disposition_kind = 'ignore'
            AND delivery_id IS NULL
            AND workspace_id IS NULL
            AND conversation_id IS NULL
            AND thread_id IS NULL
            AND sender_id IS NULL
            AND normalized_text IS NULL
            AND source_locator IS NULL
            AND ignore_reason IS NOT NULL
        )
    ),
    CHECK (acknowledged_at_ms IS NULL OR acknowledged_at_ms >= received_at_ms),
    CHECK (
        (state = 'reserved' AND inbox_entry_id IS NULL
         AND acknowledgement_outbox_id IS NULL AND completed_at_ms IS NULL)
        OR (state = 'admitted' AND disposition_kind = 'admit'
            AND inbox_entry_id IS NOT NULL AND acknowledgement_outbox_id IS NOT NULL
            AND completed_at_ms IS NOT NULL AND completed_at_ms >= received_at_ms)
        OR (state = 'ignored' AND disposition_kind = 'ignore'
            AND inbox_entry_id IS NULL AND acknowledgement_outbox_id IS NULL
            AND completed_at_ms IS NOT NULL AND completed_at_ms >= received_at_ms)
    )
) STRICT;

CREATE UNIQUE INDEX slack_delivery_identity_idx
    ON slack_envelope_receipt(binding_id, delivery_id)
    WHERE delivery_id IS NOT NULL;
CREATE INDEX slack_envelope_recovery_idx
    ON slack_envelope_receipt(state, received_at_ms, binding_id, acknowledgement_id);
CREATE INDEX slack_envelope_inbox_route_idx
    ON slack_envelope_receipt(binding_id, inbox_entry_id)
    WHERE inbox_entry_id IS NOT NULL;

CREATE TRIGGER slack_envelope_insert_guard
BEFORE INSERT ON slack_envelope_receipt
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM slack_channel_binding binding
        JOIN channel_binding_registry registry ON registry.binding_id = binding.binding_id
        WHERE binding.binding_id = NEW.binding_id
          AND binding.session_id = NEW.session_id
          AND binding.status = 'active'
          AND registry.status = 'active'
          AND (
                NEW.disposition_kind = 'ignore'
                OR (
                    NEW.workspace_id = binding.team_id
                    AND NEW.conversation_id = binding.slack_channel_id
                    AND NEW.sender_id = binding.slack_user_id
                )
              )
    ) THEN RAISE(ABORT, 'Slack envelope lacks exact active route authority') END;
END;

CREATE TRIGGER slack_envelope_transition
BEFORE UPDATE ON slack_envelope_receipt
BEGIN
    SELECT CASE WHEN NEW.binding_id <> OLD.binding_id
        OR NEW.acknowledgement_id <> OLD.acknowledgement_id
        OR NEW.body_digest <> OLD.body_digest
        OR NEW.disposition_kind <> OLD.disposition_kind
        OR NEW.delivery_id IS NOT OLD.delivery_id
        OR NEW.workspace_id IS NOT OLD.workspace_id
        OR NEW.conversation_id IS NOT OLD.conversation_id
        OR NEW.thread_id IS NOT OLD.thread_id
        OR NEW.sender_id IS NOT OLD.sender_id
        OR NEW.normalized_text IS NOT OLD.normalized_text
        OR NEW.source_locator IS NOT OLD.source_locator
        OR NEW.ignore_reason IS NOT OLD.ignore_reason
        OR NEW.session_id <> OLD.session_id
        OR NEW.received_at_ms <> OLD.received_at_ms
        OR NOT (
            (
                OLD.state = 'reserved'
                AND NEW.state = 'reserved'
                AND OLD.acknowledged_at_ms IS NULL
                AND NEW.acknowledged_at_ms IS NOT NULL
                AND NEW.inbox_entry_id IS NULL
                AND NEW.acknowledgement_outbox_id IS NULL
                AND NEW.completed_at_ms IS NULL
            )
            OR (
                OLD.state = 'reserved'
                AND NEW.state IN ('admitted', 'ignored')
                AND NEW.acknowledged_at_ms IS OLD.acknowledged_at_ms
            )
        )
    THEN RAISE(ABORT, 'invalid Slack envelope transition') END;
END;

CREATE TRIGGER slack_envelope_immutable_delete
BEFORE DELETE ON slack_envelope_receipt
BEGIN
    SELECT RAISE(ABORT, 'Slack envelope evidence cannot be removed');
END;
