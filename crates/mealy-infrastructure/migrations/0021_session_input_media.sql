-- Ordered image evidence is linked only after its canonical content-addressed blob and logical
-- artifact metadata exist in the same transaction. Raw bytes remain outside SQLite.
CREATE TABLE session_inbox_media (
    inbox_entry_id TEXT NOT NULL
        REFERENCES session_inbox(inbox_entry_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 3),
    artifact_id TEXT NOT NULL UNIQUE,
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE RESTRICT,
    media_type TEXT NOT NULL CHECK (media_type IN ('image/png', 'image/jpeg')),
    width INTEGER NOT NULL CHECK (width BETWEEN 1 AND 2048),
    height INTEGER NOT NULL CHECK (height BETWEEN 1 AND 2048),
    PRIMARY KEY(inbox_entry_id, ordinal),
    FOREIGN KEY (artifact_id, principal_id, session_id)
        REFERENCES artifact(id, principal_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id, principal_id)
        REFERENCES session(id, principal_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX session_inbox_media_owner_idx
    ON session_inbox_media(principal_id, session_id, inbox_entry_id, ordinal);

CREATE TRIGGER session_inbox_media_insert_guard
BEFORE INSERT ON session_inbox_media
BEGIN
    SELECT CASE WHEN NEW.ordinal <> (
        SELECT COUNT(*) FROM session_inbox_media existing
        WHERE existing.inbox_entry_id = NEW.inbox_entry_id
    ) THEN RAISE(ABORT, 'input image ordinals must be contiguous') END;

    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM session_inbox inbox
        JOIN session owner_session ON owner_session.id = inbox.session_id
        JOIN artifact image ON image.id = NEW.artifact_id
        JOIN artifact_blob blob
          ON blob.algorithm = image.blob_algorithm AND blob.digest = image.blob_digest
        WHERE inbox.inbox_entry_id = NEW.inbox_entry_id
          AND inbox.session_id = NEW.session_id
          AND owner_session.principal_id = NEW.principal_id
          AND image.principal_id = NEW.principal_id
          AND image.session_id = NEW.session_id
          AND image.media_type = NEW.media_type
          AND image.origin_kind = 'session_input'
          AND image.origin_id = NEW.inbox_entry_id
          AND image.producer_kind = 'builtin'
          AND image.producer_id = 'mealyd.media-normalizer.v1'
          AND image.sensitivity = 'private'
          AND image.retention_class = 'session_history'
          AND image.created_at_ms = inbox.accepted_at_ms
          AND blob.committed_at_ms <= inbox.accepted_at_ms
          AND blob.size_bytes BETWEEN 1 AND 2097152
    ) THEN RAISE(ABORT, 'input image evidence does not match its owner and artifact') END;

    SELECT CASE WHEN 4194304 < (
        SELECT COALESCE(SUM(blob.size_bytes), 0)
        FROM session_inbox_media existing
        JOIN artifact image ON image.id = existing.artifact_id
        JOIN artifact_blob blob
          ON blob.algorithm = image.blob_algorithm AND blob.digest = image.blob_digest
        WHERE existing.inbox_entry_id = NEW.inbox_entry_id
    ) + (
        SELECT blob.size_bytes
        FROM artifact image
        JOIN artifact_blob blob
          ON blob.algorithm = image.blob_algorithm AND blob.digest = image.blob_digest
        WHERE image.id = NEW.artifact_id
    ) THEN RAISE(ABORT, 'input image aggregate exceeds its byte bound') END;
END;

CREATE TRIGGER session_inbox_media_create_reference
AFTER INSERT ON session_inbox_media
BEGIN
    INSERT INTO artifact_reference(
        artifact_id, principal_id, session_id, owner_kind, owner_id, relation, created_at_ms
    )
    SELECT NEW.artifact_id, NEW.principal_id, NEW.session_id, 'session_inbox',
           NEW.inbox_entry_id, 'input_image', inbox.accepted_at_ms
    FROM session_inbox inbox
    WHERE inbox.inbox_entry_id = NEW.inbox_entry_id;
END;

CREATE TRIGGER session_inbox_media_immutable_update
BEFORE UPDATE ON session_inbox_media
BEGIN
    SELECT RAISE(ABORT, 'input image evidence is immutable');
END;

CREATE TRIGGER session_inbox_media_immutable_delete
BEFORE DELETE ON session_inbox_media
BEGIN
    SELECT RAISE(ABORT, 'input image evidence is immutable');
END;

CREATE TRIGGER session_input_artifact_immutable_update
BEFORE UPDATE ON artifact
WHEN EXISTS(
    SELECT 1 FROM session_inbox_media media WHERE media.artifact_id = OLD.id
)
BEGIN
    SELECT RAISE(ABORT, 'input image artifact evidence is immutable');
END;

CREATE TRIGGER session_input_blob_immutable_update
BEFORE UPDATE ON artifact_blob
WHEN (
        NEW.algorithm <> OLD.algorithm
        OR NEW.digest <> OLD.digest
        OR NEW.size_bytes <> OLD.size_bytes
        OR NEW.relative_path <> OLD.relative_path
    )
  AND EXISTS(
    SELECT 1
    FROM artifact image
    JOIN session_inbox_media media ON media.artifact_id = image.id
    WHERE image.blob_algorithm = OLD.algorithm AND image.blob_digest = OLD.digest
)
BEGIN
    SELECT RAISE(ABORT, 'input image blob evidence is immutable');
END;

CREATE TRIGGER session_input_reference_insert_guard
BEFORE INSERT ON artifact_reference
WHEN NEW.owner_kind = 'session_inbox' OR NEW.relation = 'input_image'
BEGIN
    SELECT CASE WHEN NEW.owner_kind <> 'session_inbox'
        OR NEW.relation <> 'input_image'
        OR NOT EXISTS(
            SELECT 1
            FROM session_inbox inbox
            JOIN session owner_session ON owner_session.id = inbox.session_id
            JOIN artifact image ON image.id = NEW.artifact_id
            JOIN session_inbox_media media ON media.artifact_id = image.id
            WHERE image.id = NEW.artifact_id
              AND image.principal_id = NEW.principal_id
              AND image.session_id = NEW.session_id
              AND image.origin_kind = 'session_input'
              AND image.origin_id = NEW.owner_id
              AND inbox.inbox_entry_id = NEW.owner_id
              AND inbox.session_id = NEW.session_id
              AND owner_session.principal_id = NEW.principal_id
              AND media.inbox_entry_id = NEW.owner_id
              AND media.principal_id = NEW.principal_id
              AND media.session_id = NEW.session_id
              AND NEW.created_at_ms = inbox.accepted_at_ms
        )
    THEN RAISE(ABORT, 'input image artifact reference is invalid') END;
END;

CREATE TRIGGER session_input_reference_immutable_update
BEFORE UPDATE ON artifact_reference
WHEN OLD.owner_kind = 'session_inbox' OR OLD.relation = 'input_image'
BEGIN
    SELECT RAISE(ABORT, 'input image artifact reference is immutable');
END;

CREATE TRIGGER session_input_reference_immutable_delete
BEFORE DELETE ON artifact_reference
WHEN OLD.owner_kind = 'session_inbox' OR OLD.relation = 'input_image'
BEGIN
    SELECT RAISE(ABORT, 'input image artifact reference is immutable');
END;
