-- Optional semantic vectors are disposable derived data. Canonical memory content, lifecycle,
-- provenance, namespace, and sensitivity remain authoritative in the v9 tables.

CREATE TABLE memory_semantic_index_state (
    principal_id TEXT PRIMARY KEY CHECK (length(principal_id) > 0),
    config_digest TEXT NOT NULL CHECK (
        length(config_digest) = 64 AND config_digest NOT GLOB '*[^0-9a-f]*'
    ),
    health TEXT NOT NULL CHECK (health IN ('healthy', 'stale', 'degraded')),
    dimensions INTEGER NOT NULL CHECK (dimensions BETWEEN 1 AND 8192),
    indexed_revision_count INTEGER NOT NULL CHECK (indexed_revision_count >= 0),
    last_rebuilt_at_ms INTEGER CHECK (last_rebuilt_at_ms IS NULL OR last_rebuilt_at_ms >= 0),
    last_error_code TEXT CHECK (
        last_error_code IS NULL
        OR (
            length(last_error_code) BETWEEN 1 AND 64
            AND last_error_code NOT GLOB '*[^a-z0-9_]*'
        )
    ),
    CHECK (
        (health = 'degraded' AND last_error_code IS NOT NULL)
        OR (health <> 'degraded' AND last_error_code IS NULL)
    )
) STRICT;

CREATE TABLE memory_semantic_vector (
    revision_id TEXT PRIMARY KEY REFERENCES memory_revision(id) ON DELETE CASCADE,
    memory_id TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL CHECK (length(principal_id) > 0),
    workspace_identity TEXT NOT NULL CHECK (length(workspace_identity) BETWEEN 1 AND 1024),
    content_digest TEXT NOT NULL CHECK (
        length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'
    ),
    config_digest TEXT NOT NULL CHECK (
        length(config_digest) = 64 AND config_digest NOT GLOB '*[^0-9a-f]*'
    ),
    dimensions INTEGER NOT NULL CHECK (dimensions BETWEEN 1 AND 8192),
    vector_blob BLOB NOT NULL CHECK (length(vector_blob) = dimensions * 4),
    indexed_at_ms INTEGER NOT NULL CHECK (indexed_at_ms >= 0),
    UNIQUE (revision_id, memory_id),
    FOREIGN KEY (memory_id, principal_id, workspace_identity)
        REFERENCES memory(id, principal_id, workspace_identity) ON DELETE CASCADE
) STRICT;

CREATE INDEX memory_semantic_vector_scope_idx
    ON memory_semantic_vector(
        principal_id, workspace_identity, config_digest, memory_id, revision_id
    );

CREATE TRIGGER memory_revision_semantic_invalidate
AFTER UPDATE OF status, content_text ON memory_revision
BEGIN
    DELETE FROM memory_semantic_vector WHERE revision_id = OLD.id;
    UPDATE memory_semantic_index_state
       SET health = 'stale',
           indexed_revision_count = (
               SELECT COUNT(*) FROM memory_semantic_vector vector
               WHERE vector.principal_id = memory_semantic_index_state.principal_id
           ),
           last_error_code = NULL
     WHERE principal_id = (
         SELECT owner.principal_id FROM memory owner WHERE owner.id = NEW.memory_id
     );
END;
