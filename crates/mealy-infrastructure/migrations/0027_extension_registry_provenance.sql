CREATE TABLE extension_manifest_registry_provenance (
    extension_id TEXT NOT NULL,
    manifest_ordinal INTEGER NOT NULL CHECK(manifest_ordinal > 0),
    manifest_digest TEXT NOT NULL
        CHECK(
            length(manifest_digest) = 64
            AND manifest_digest NOT GLOB '*[^0-9a-f]*'
        ),
    registry_id TEXT NOT NULL CHECK(length(registry_id) BETWEEN 1 AND 255),
    package_id TEXT NOT NULL CHECK(length(package_id) BETWEEN 1 AND 255),
    package_version TEXT NOT NULL CHECK(length(package_version) BETWEEN 1 AND 128),
    release_envelope_digest TEXT NOT NULL
        CHECK(
            length(release_envelope_digest) = 64
            AND release_envelope_digest NOT GLOB '*[^0-9a-f]*'
        ),
    archive_digest TEXT NOT NULL
        CHECK(
            length(archive_digest) = 64
            AND archive_digest NOT GLOB '*[^0-9a-f]*'
        ),
    recorded_event_id TEXT NOT NULL UNIQUE
        REFERENCES journal_event(event_id) ON DELETE RESTRICT,
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms >= 0),
    PRIMARY KEY(extension_id, manifest_ordinal),
    FOREIGN KEY(extension_id, manifest_ordinal, manifest_digest)
        REFERENCES extension_manifest_revision(extension_id, ordinal, manifest_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY(registry_id, package_id, package_version)
        REFERENCES registry_package(registry_id, package_id, version)
        ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER extension_manifest_registry_provenance_insert_guard
BEFORE INSERT ON extension_manifest_registry_provenance
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM extension_manifest_revision revision
        JOIN registry_package package
          ON package.registry_id = NEW.registry_id
         AND package.package_id = NEW.package_id
         AND package.version = NEW.package_version
        WHERE revision.extension_id = NEW.extension_id
          AND revision.ordinal = NEW.manifest_ordinal
          AND revision.manifest_digest = NEW.manifest_digest
          AND revision.version = NEW.package_version
          AND package.package_kind = 'extension'
          AND package.release_envelope_digest = NEW.release_envelope_digest
          AND package.manifest_blob_digest = NEW.manifest_digest
          AND package.package_blob_digest = NEW.archive_digest
    ) THEN RAISE(ABORT, 'extension registry provenance does not match exact staged evidence') END;
END;

CREATE TRIGGER extension_manifest_registry_provenance_immutable_update
BEFORE UPDATE ON extension_manifest_registry_provenance
BEGIN
    SELECT RAISE(ABORT, 'extension registry provenance is immutable');
END;

CREATE TRIGGER extension_manifest_registry_provenance_immutable_delete
BEFORE DELETE ON extension_manifest_registry_provenance
BEGIN
    SELECT RAISE(ABORT, 'extension registry provenance is immutable');
END;
