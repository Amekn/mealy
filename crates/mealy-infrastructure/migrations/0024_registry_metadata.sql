CREATE TABLE registry_trust_root (
    registry_id TEXT NOT NULL
        CHECK(
            length(registry_id) BETWEEN 1 AND 255
            AND registry_id NOT GLOB '*[^A-Za-z0-9._:-]*'
        ),
    root_version INTEGER NOT NULL CHECK(root_version > 0),
    root_digest TEXT NOT NULL
        CHECK(
            length(root_digest) = 64
            AND root_digest NOT GLOB '*[^0-9a-f]*'
        ),
    root_json BLOB NOT NULL CHECK(length(root_json) BETWEEN 1 AND 131072),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
    activated_at_ms INTEGER NOT NULL CHECK(activated_at_ms >= 0),
    PRIMARY KEY(registry_id, root_version),
    UNIQUE(registry_id, root_digest),
    UNIQUE(registry_id, root_version, root_digest)
) STRICT;

CREATE TRIGGER registry_trust_root_immutable_update
BEFORE UPDATE ON registry_trust_root
BEGIN
    SELECT RAISE(ABORT, 'registry trust-root evidence is immutable');
END;

CREATE TRIGGER registry_trust_root_immutable_delete
BEFORE DELETE ON registry_trust_root
BEGIN
    SELECT RAISE(ABORT, 'registry trust-root evidence is immutable');
END;

CREATE TABLE registry_trust_root_head (
    registry_id TEXT PRIMARY KEY,
    root_version INTEGER NOT NULL CHECK(root_version > 0),
    root_digest TEXT NOT NULL
        CHECK(
            length(root_digest) = 64
            AND root_digest NOT GLOB '*[^0-9a-f]*'
        ),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
    FOREIGN KEY(registry_id, root_version, root_digest)
        REFERENCES registry_trust_root(registry_id, root_version, root_digest)
) STRICT;

CREATE TRIGGER registry_trust_root_head_monotonic_update
BEFORE UPDATE ON registry_trust_root_head
BEGIN
    SELECT CASE WHEN
        NEW.registry_id != OLD.registry_id
        OR NEW.root_version != OLD.root_version + 1
        OR NEW.root_digest = OLD.root_digest
    THEN RAISE(ABORT, 'registry trust-root head must advance exactly once') END;
END;

CREATE TRIGGER registry_trust_root_head_no_delete
BEFORE DELETE ON registry_trust_root_head
BEGIN
    SELECT RAISE(ABORT, 'registry trust-root head cannot be deleted');
END;

CREATE TABLE registry_snapshot (
    registry_id TEXT NOT NULL,
    root_version INTEGER NOT NULL CHECK(root_version > 0),
    snapshot_version INTEGER NOT NULL CHECK(snapshot_version > 0),
    envelope_digest TEXT NOT NULL
        CHECK(
            length(envelope_digest) = 64
            AND envelope_digest NOT GLOB '*[^0-9a-f]*'
        ),
    payload_digest TEXT NOT NULL
        CHECK(
            length(payload_digest) = 64
            AND payload_digest NOT GLOB '*[^0-9a-f]*'
        ),
    envelope_bytes BLOB NOT NULL CHECK(length(envelope_bytes) BETWEEN 1 AND 4194304),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
    accepted_at_ms INTEGER NOT NULL CHECK(accepted_at_ms >= 0),
    PRIMARY KEY(registry_id, snapshot_version),
    UNIQUE(registry_id, envelope_digest),
    UNIQUE(registry_id, root_version, snapshot_version, envelope_digest),
    FOREIGN KEY(registry_id, root_version)
        REFERENCES registry_trust_root(registry_id, root_version)
) STRICT;

CREATE TRIGGER registry_snapshot_current_root_insert
BEFORE INSERT ON registry_snapshot
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM registry_trust_root_head root
        WHERE root.registry_id = NEW.registry_id
          AND root.root_version = NEW.root_version
    ) THEN RAISE(ABORT, 'registry snapshot is not authorized by the active root') END;
END;

CREATE TRIGGER registry_snapshot_immutable_update
BEFORE UPDATE ON registry_snapshot
BEGIN
    SELECT RAISE(ABORT, 'registry snapshot evidence is immutable');
END;

CREATE TRIGGER registry_snapshot_immutable_delete
BEFORE DELETE ON registry_snapshot
BEGIN
    SELECT RAISE(ABORT, 'registry snapshot evidence is immutable');
END;

CREATE TABLE registry_snapshot_head (
    registry_id TEXT PRIMARY KEY,
    root_version INTEGER NOT NULL CHECK(root_version > 0),
    snapshot_version INTEGER NOT NULL CHECK(snapshot_version > 0),
    envelope_digest TEXT NOT NULL
        CHECK(
            length(envelope_digest) = 64
            AND envelope_digest NOT GLOB '*[^0-9a-f]*'
        ),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
    FOREIGN KEY(registry_id, root_version, snapshot_version, envelope_digest)
        REFERENCES registry_snapshot(
            registry_id, root_version, snapshot_version, envelope_digest
        )
) STRICT;

CREATE TRIGGER registry_snapshot_head_monotonic_update
BEFORE UPDATE ON registry_snapshot_head
BEGIN
    SELECT CASE WHEN
        NEW.registry_id != OLD.registry_id
        OR NEW.snapshot_version <= OLD.snapshot_version
        OR NEW.root_version < OLD.root_version
    THEN RAISE(ABORT, 'registry snapshot head must advance monotonically') END;
END;

CREATE TRIGGER registry_snapshot_head_no_delete
BEFORE DELETE ON registry_snapshot_head
BEGIN
    SELECT RAISE(ABORT, 'registry snapshot head cannot be deleted');
END;
