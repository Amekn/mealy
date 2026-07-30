CREATE TABLE registry_release (
    registry_id TEXT NOT NULL
        CHECK(
            length(registry_id) BETWEEN 1 AND 255
            AND registry_id NOT GLOB '*[^A-Za-z0-9._:-]*'
        ),
    package_id TEXT NOT NULL
        CHECK(
            length(package_id) BETWEEN 1 AND 255
            AND package_id NOT GLOB '*[^A-Za-z0-9._:-]*'
        ),
    package_kind TEXT NOT NULL CHECK(package_kind IN ('extension', 'skill')),
    version TEXT NOT NULL
        CHECK(
            length(version) BETWEEN 1 AND 128
            AND version NOT GLOB '*[^A-Za-z0-9._+-]*'
        ),
    publisher_id TEXT NOT NULL
        CHECK(
            length(publisher_id) BETWEEN 1 AND 255
            AND publisher_id NOT GLOB '*[^A-Za-z0-9._:-]*'
        ),
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
    envelope_bytes BLOB NOT NULL CHECK(length(envelope_bytes) BETWEEN 1 AND 2097152),
    manifest_digest TEXT NOT NULL
        CHECK(
            length(manifest_digest) = 64
            AND manifest_digest NOT GLOB '*[^0-9a-f]*'
        ),
    package_digest TEXT NOT NULL
        CHECK(
            length(package_digest) = 64
            AND package_digest NOT GLOB '*[^0-9a-f]*'
        ),
    accepted_snapshot_version INTEGER NOT NULL CHECK(accepted_snapshot_version > 0),
    accepted_snapshot_root_version INTEGER NOT NULL CHECK(accepted_snapshot_root_version > 0),
    accepted_snapshot_envelope_digest TEXT NOT NULL
        CHECK(
            length(accepted_snapshot_envelope_digest) = 64
            AND accepted_snapshot_envelope_digest NOT GLOB '*[^0-9a-f]*'
        ),
    accepted_host_api_version INTEGER NOT NULL CHECK(accepted_host_api_version > 0),
    accepted_at_ms INTEGER NOT NULL CHECK(accepted_at_ms >= 0),
    PRIMARY KEY(registry_id, package_id, version),
    UNIQUE(registry_id, envelope_digest),
    FOREIGN KEY(
        registry_id, accepted_snapshot_root_version, accepted_snapshot_version,
        accepted_snapshot_envelope_digest
    ) REFERENCES registry_snapshot(
        registry_id, root_version, snapshot_version, envelope_digest
    )
) STRICT;

CREATE TRIGGER registry_release_immutable_update
BEFORE UPDATE ON registry_release
BEGIN
    SELECT RAISE(ABORT, 'registry release evidence is immutable');
END;

CREATE TRIGGER registry_release_immutable_delete
BEFORE DELETE ON registry_release
BEGIN
    SELECT RAISE(ABORT, 'registry release evidence is immutable');
END;
