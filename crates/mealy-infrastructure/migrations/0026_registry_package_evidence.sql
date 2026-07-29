CREATE TABLE registry_package (
    registry_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    package_kind TEXT NOT NULL CHECK(package_kind IN ('extension', 'skill')),
    version TEXT NOT NULL,
    release_envelope_digest TEXT NOT NULL
        CHECK(
            length(release_envelope_digest) = 64
            AND release_envelope_digest NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_blob_algorithm TEXT NOT NULL CHECK(manifest_blob_algorithm = 'sha256'),
    manifest_blob_digest TEXT NOT NULL
        CHECK(
            length(manifest_blob_digest) = 64
            AND manifest_blob_digest NOT GLOB '*[^0-9a-f]*'
        ),
    package_blob_algorithm TEXT NOT NULL CHECK(package_blob_algorithm = 'sha256'),
    package_blob_digest TEXT NOT NULL
        CHECK(
            length(package_blob_digest) = 64
            AND package_blob_digest NOT GLOB '*[^0-9a-f]*'
        ),
    staged_at_ms INTEGER NOT NULL CHECK(staged_at_ms >= 0),
    PRIMARY KEY(registry_id, package_id, version),
    FOREIGN KEY(registry_id, package_id, version)
        REFERENCES registry_release(registry_id, package_id, version)
        ON DELETE RESTRICT,
    FOREIGN KEY(manifest_blob_algorithm, manifest_blob_digest)
        REFERENCES artifact_blob(algorithm, digest)
        ON DELETE RESTRICT,
    FOREIGN KEY(package_blob_algorithm, package_blob_digest)
        REFERENCES artifact_blob(algorithm, digest)
        ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER registry_package_insert_guard
BEFORE INSERT ON registry_package
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM registry_release release
        WHERE release.registry_id = NEW.registry_id
          AND release.package_id = NEW.package_id
          AND release.version = NEW.version
          AND release.package_kind = NEW.package_kind
          AND release.envelope_digest = NEW.release_envelope_digest
          AND release.manifest_digest = NEW.manifest_blob_digest
          AND release.package_digest = NEW.package_blob_digest
    ) THEN RAISE(ABORT, 'registry package does not match accepted release evidence') END;
END;

CREATE TRIGGER registry_package_immutable_update
BEFORE UPDATE ON registry_package
BEGIN
    SELECT RAISE(ABORT, 'registry package evidence is immutable');
END;

CREATE TRIGGER registry_package_immutable_delete
BEFORE DELETE ON registry_package
BEGIN
    SELECT RAISE(ABORT, 'registry package evidence is immutable');
END;
