use super::SqliteStore;
use crate::InspectedRegistryPackageArchive;
use mealy_application::{
    CommittedArtifactBlob, InspectedRegistryRelease, InspectedRegistrySnapshot,
    InspectedRegistryTrustRoot, RegistryMetadataStore, RegistryMetadataStoreError,
    RegistryPackageKind, RegistryPackageState, RegistryReleaseCommit, RegistryReleaseState,
    RegistrySnapshotCommit, RegistrySnapshotState, RegistryTrustRootCommit, RegistryTrustRootState,
    inspect_initial_registry_trust_root, inspect_registry_release, inspect_registry_snapshot,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

impl RegistryMetadataStore for SqliteStore {
    fn registry_trust_root(
        &self,
        registry_id: &str,
    ) -> Result<Option<InspectedRegistryTrustRoot>, RegistryMetadataStoreError> {
        load_trust_root(&self.connection, registry_id)
    }

    fn registry_snapshot_state(
        &self,
        registry_id: &str,
    ) -> Result<Option<RegistrySnapshotState>, RegistryMetadataStoreError> {
        load_snapshot_state(&self.connection, registry_id)
    }

    fn registry_snapshot(
        &self,
        registry_id: &str,
    ) -> Result<Option<InspectedRegistrySnapshot>, RegistryMetadataStoreError> {
        load_current_snapshot(&self.connection, registry_id)
    }

    fn registry_release(
        &self,
        registry_id: &str,
        package_id: &str,
        version: &str,
    ) -> Result<Option<(InspectedRegistryRelease, RegistryReleaseState)>, RegistryMetadataStoreError>
    {
        load_release(&self.connection, registry_id, package_id, version)
    }

    fn registry_package(
        &self,
        registry_id: &str,
        package_id: &str,
        version: &str,
    ) -> Result<Option<RegistryPackageState>, RegistryMetadataStoreError> {
        load_package(&self.connection, registry_id, package_id, version)
    }

    fn commit_registry_trust_root(
        &mut self,
        commit: RegistryTrustRootCommit,
    ) -> Result<RegistryTrustRootState, RegistryMetadataStoreError> {
        if commit.activated_at_ms < 0 {
            return Err(invariant("trust-root activation time is negative"));
        }
        let verified = inspect_initial_registry_trust_root(
            &commit.inspected.root_bytes,
            commit.activated_at_ms,
        )
        .map_err(|_| invariant("application supplied invalid trust-root evidence"))?;
        if verified != commit.inspected {
            return Err(invariant("trust-root inspection evidence drifted"));
        }
        let target = commit.inspected.state();
        let root_version = to_i64(target.root_version, "trust-root version")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite)?;
        let actual = load_root_state(&transaction, &target.registry_id)?;
        if actual.as_ref() == Some(&target) {
            let stored = load_trust_root(&transaction, &target.registry_id)?
                .ok_or_else(|| invariant("trust-root head lost its immutable evidence"))?;
            if stored != commit.inspected {
                return Err(invariant("trust-root digest aliases different bytes"));
            }
            transaction.commit().map_err(map_sqlite)?;
            return Ok(target);
        }
        if actual != commit.expected {
            return Err(RegistryMetadataStoreError::Conflict);
        }
        match &commit.expected {
            None => {}
            Some(expected)
                if expected.registry_id == target.registry_id
                    && expected.root_version.checked_add(1) == Some(target.root_version) => {}
            _ => {
                return Err(invariant(
                    "trust-root transition is not initial or consecutive",
                ));
            }
        }
        transaction
            .execute(
                "INSERT INTO registry_trust_root(
                     registry_id, root_version, root_digest, root_json,
                     expires_at_ms, activated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    target.registry_id,
                    root_version,
                    target.root_digest,
                    commit.inspected.root_bytes,
                    target.expires_at_ms,
                    commit.activated_at_ms,
                ],
            )
            .map_err(map_sqlite)?;
        if let Some(expected) = &commit.expected {
            let changed = transaction
                .execute(
                    "UPDATE registry_trust_root_head
                     SET root_version = ?1, root_digest = ?2, expires_at_ms = ?3
                     WHERE registry_id = ?4 AND root_version = ?5 AND root_digest = ?6",
                    params![
                        root_version,
                        target.root_digest,
                        target.expires_at_ms,
                        target.registry_id,
                        to_i64(expected.root_version, "expected trust-root version")?,
                        expected.root_digest,
                    ],
                )
                .map_err(map_sqlite)?;
            if changed != 1 {
                return Err(RegistryMetadataStoreError::Conflict);
            }
        } else {
            transaction
                .execute(
                    "INSERT INTO registry_trust_root_head(
                         registry_id, root_version, root_digest, expires_at_ms
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        target.registry_id,
                        root_version,
                        target.root_digest,
                        target.expires_at_ms,
                    ],
                )
                .map_err(map_sqlite)?;
        }
        transaction.commit().map_err(map_sqlite)?;
        Ok(target)
    }

    fn commit_registry_snapshot(
        &mut self,
        commit: RegistrySnapshotCommit,
    ) -> Result<RegistrySnapshotState, RegistryMetadataStoreError> {
        if commit.accepted_at_ms < 0 {
            return Err(invariant("snapshot acceptance time is negative"));
        }
        let registry_id = commit.inspected.state.registry_id.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite)?;
        let root = load_trust_root(&transaction, &registry_id)?
            .ok_or(RegistryMetadataStoreError::TrustRootNotFound)?;
        let actual = load_snapshot_state(&transaction, &registry_id)?;
        if actual != commit.expected {
            return Err(RegistryMetadataStoreError::Conflict);
        }
        let verified = inspect_registry_snapshot(
            &commit.inspected.envelope_bytes,
            &root.trust_root,
            actual.as_ref(),
            commit.accepted_at_ms,
        )
        .map_err(|_| invariant("application supplied invalid registry snapshot evidence"))?;
        if verified != commit.inspected {
            return Err(invariant("registry snapshot inspection evidence drifted"));
        }
        let target = verified.state;
        if actual.as_ref() == Some(&target) {
            transaction.commit().map_err(map_sqlite)?;
            return Ok(target);
        }
        let root_version = to_i64(target.root_version, "snapshot root version")?;
        let snapshot_version = to_i64(target.version, "snapshot version")?;
        transaction
            .execute(
                "INSERT INTO registry_snapshot(
                     registry_id, root_version, snapshot_version, envelope_digest,
                     payload_digest, envelope_bytes, expires_at_ms, accepted_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    target.registry_id,
                    root_version,
                    snapshot_version,
                    target.envelope_digest,
                    commit.inspected.payload_digest,
                    commit.inspected.envelope_bytes,
                    target.expires_at_ms,
                    commit.accepted_at_ms,
                ],
            )
            .map_err(map_sqlite)?;
        if let Some(expected) = &actual {
            let changed = transaction
                .execute(
                    "UPDATE registry_snapshot_head
                     SET root_version = ?1, snapshot_version = ?2,
                         envelope_digest = ?3, expires_at_ms = ?4
                     WHERE registry_id = ?5 AND root_version = ?6
                       AND snapshot_version = ?7 AND envelope_digest = ?8",
                    params![
                        root_version,
                        snapshot_version,
                        target.envelope_digest,
                        target.expires_at_ms,
                        target.registry_id,
                        to_i64(expected.root_version, "expected snapshot root version")?,
                        to_i64(expected.version, "expected snapshot version")?,
                        expected.envelope_digest,
                    ],
                )
                .map_err(map_sqlite)?;
            if changed != 1 {
                return Err(RegistryMetadataStoreError::Conflict);
            }
        } else {
            transaction
                .execute(
                    "INSERT INTO registry_snapshot_head(
                         registry_id, root_version, snapshot_version,
                         envelope_digest, expires_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        target.registry_id,
                        root_version,
                        snapshot_version,
                        target.envelope_digest,
                        target.expires_at_ms,
                    ],
                )
                .map_err(map_sqlite)?;
        }
        transaction.commit().map_err(map_sqlite)?;
        Ok(target)
    }

    fn commit_registry_release(
        &mut self,
        commit: RegistryReleaseCommit,
    ) -> Result<RegistryReleaseState, RegistryMetadataStoreError> {
        if commit.accepted_at_ms < 0 || commit.host_api_version == 0 {
            return Err(invariant("registry release acceptance inputs are invalid"));
        }
        let registry_id = commit.inspected.release.registry_id.clone();
        let package_id = commit.inspected.release.package_id.clone();
        let version = commit.inspected.release.version.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite)?;
        let root = load_trust_root(&transaction, &registry_id)?
            .ok_or(RegistryMetadataStoreError::TrustRootNotFound)?;
        let actual_snapshot_state = load_snapshot_state(&transaction, &registry_id)?
            .ok_or(RegistryMetadataStoreError::SnapshotNotFound)?;
        if actual_snapshot_state != commit.expected_snapshot {
            return Err(RegistryMetadataStoreError::Conflict);
        }
        let stored_snapshot = load_current_snapshot(&transaction, &registry_id)?
            .ok_or(RegistryMetadataStoreError::SnapshotNotFound)?;
        let verified_snapshot = inspect_registry_snapshot(
            &stored_snapshot.envelope_bytes,
            &root.trust_root,
            Some(&actual_snapshot_state),
            commit.accepted_at_ms,
        )
        .map_err(|_| invariant("active snapshot cannot admit registry release evidence"))?;
        if verified_snapshot != stored_snapshot {
            return Err(invariant(
                "active snapshot evidence differs from its durable fence",
            ));
        }
        let target = verified_snapshot
            .snapshot
            .target(&package_id, &version)
            .ok_or_else(|| invariant("registry release target is absent from active snapshot"))?;
        let verified = inspect_registry_release(
            &commit.inspected.envelope_bytes,
            &verified_snapshot,
            target,
            commit.host_api_version,
        )
        .map_err(|_| invariant("application supplied invalid registry release evidence"))?;
        if verified != commit.inspected {
            return Err(invariant("registry release inspection evidence drifted"));
        }
        if let Some((stored, state)) =
            load_release(&transaction, &registry_id, &package_id, &version)?
        {
            if stored == verified {
                transaction.commit().map_err(map_sqlite)?;
                return Ok(state);
            }
            return Err(RegistryMetadataStoreError::Conflict);
        }
        ensure_release_digest_unaliased(&transaction, &registry_id, &verified.envelope_digest)?;
        let state = release_state(
            &verified,
            &actual_snapshot_state,
            commit.host_api_version,
            commit.accepted_at_ms,
        );
        transaction
            .execute(
                "INSERT INTO registry_release(
                     registry_id, package_id, package_kind, version, publisher_id,
                     envelope_digest, payload_digest, envelope_bytes,
                     manifest_digest, package_digest, accepted_snapshot_version,
                     accepted_snapshot_root_version, accepted_snapshot_envelope_digest,
                     accepted_host_api_version, accepted_at_ms
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
                 )",
                params![
                    state.registry_id,
                    state.package_id,
                    package_kind_text(state.kind),
                    state.version,
                    state.publisher_id,
                    state.envelope_digest,
                    state.payload_digest,
                    verified.envelope_bytes,
                    state.manifest_digest,
                    state.package_digest,
                    to_i64(state.accepted_snapshot_version, "accepted snapshot version")?,
                    to_i64(
                        state.accepted_snapshot_root_version,
                        "accepted snapshot root version"
                    )?,
                    state.accepted_snapshot_envelope_digest,
                    i64::from(state.accepted_host_api_version),
                    state.accepted_at_ms,
                ],
            )
            .map_err(map_sqlite)?;
        transaction.commit().map_err(map_sqlite)?;
        Ok(state)
    }
}

impl SqliteStore {
    /// Atomically binds exact inspected manifest/archive blobs to accepted release evidence.
    ///
    /// The package token can only be created by the strict extraction-free archive inspector.
    /// Blob publication occurs first; a failed database transaction therefore leaves at most
    /// content-addressed orphan files eligible for the normal age-gated garbage collector.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryMetadataStoreError`] for stale authorization, evidence drift, blob
    /// conflicts, corruption, or unavailable persistence.
    pub fn commit_registry_package(
        &mut self,
        inspected: &InspectedRegistryPackageArchive,
        manifest_blob: CommittedArtifactBlob,
        package_blob: CommittedArtifactBlob,
        expected_snapshot: &RegistrySnapshotState,
        host_api_version: u32,
        staged_at_ms: i64,
    ) -> Result<RegistryPackageState, RegistryMetadataStoreError> {
        if staged_at_ms < 0 || host_api_version == 0 {
            return Err(invariant("registry package staging inputs are invalid"));
        }
        manifest_blob
            .validate()
            .map_err(|_| invariant("registry manifest blob descriptor is invalid"))?;
        package_blob
            .validate()
            .map_err(|_| invariant("registry package blob descriptor is invalid"))?;
        let registry_id = inspected.release().release.registry_id.clone();
        let package_id = inspected.release().release.package_id.clone();
        let version = inspected.release().release.version.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite)?;
        let verified_release = authorize_registry_package_stage(
            &transaction,
            inspected,
            expected_snapshot,
            host_api_version,
            staged_at_ms,
        )?;
        if inspected.manifest().manifest_digest != manifest_blob.digest
            || inspected.archive_digest() != package_blob.digest
            || u64::try_from(inspected.manifest().manifest_bytes.len()).ok()
                != Some(manifest_blob.size_bytes)
            || inspected.archive_size_bytes() != package_blob.size_bytes
        {
            return Err(invariant(
                "registry package blobs differ from inspected exact bytes",
            ));
        }
        if let Some(state) = load_package(&transaction, &registry_id, &package_id, &version)? {
            if state.release_envelope_digest == verified_release.envelope_digest
                && state.manifest_blob == manifest_blob
                && state.package_blob == package_blob
            {
                transaction.commit().map_err(map_sqlite)?;
                return Ok(state);
            }
            return Err(RegistryMetadataStoreError::Conflict);
        }
        insert_artifact_blob(&transaction, &manifest_blob, staged_at_ms)?;
        insert_artifact_blob(&transaction, &package_blob, staged_at_ms)?;
        let state = RegistryPackageState {
            registry_id,
            package_id,
            kind: verified_release.release.kind,
            version,
            release_envelope_digest: verified_release.envelope_digest,
            manifest_blob,
            package_blob,
            staged_at_ms,
        };
        transaction
            .execute(
                "INSERT INTO registry_package(
                     registry_id, package_id, package_kind, version,
                     release_envelope_digest, manifest_blob_algorithm,
                     manifest_blob_digest, package_blob_algorithm,
                     package_blob_digest, staged_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    state.registry_id,
                    state.package_id,
                    package_kind_text(state.kind),
                    state.version,
                    state.release_envelope_digest,
                    state.manifest_blob.algorithm,
                    state.manifest_blob.digest,
                    state.package_blob.algorithm,
                    state.package_blob.digest,
                    state.staged_at_ms,
                ],
            )
            .map_err(map_sqlite)?;
        transaction.commit().map_err(map_sqlite)?;
        Ok(state)
    }
}

fn authorize_registry_package_stage(
    transaction: &Transaction<'_>,
    inspected: &InspectedRegistryPackageArchive,
    expected_snapshot: &RegistrySnapshotState,
    host_api_version: u32,
    staged_at_ms: i64,
) -> Result<InspectedRegistryRelease, RegistryMetadataStoreError> {
    let registry_id = &inspected.release().release.registry_id;
    let package_id = &inspected.release().release.package_id;
    let version = &inspected.release().release.version;
    let root = load_trust_root(transaction, registry_id)?
        .ok_or(RegistryMetadataStoreError::TrustRootNotFound)?;
    let snapshot_state = load_snapshot_state(transaction, registry_id)?
        .ok_or(RegistryMetadataStoreError::SnapshotNotFound)?;
    if &snapshot_state != expected_snapshot {
        return Err(RegistryMetadataStoreError::Conflict);
    }
    let stored_snapshot = load_current_snapshot(transaction, registry_id)?
        .ok_or(RegistryMetadataStoreError::SnapshotNotFound)?;
    let verified_snapshot = inspect_registry_snapshot(
        &stored_snapshot.envelope_bytes,
        &root.trust_root,
        Some(&snapshot_state),
        staged_at_ms,
    )
    .map_err(|_| invariant("active snapshot cannot authorize registry package staging"))?;
    if verified_snapshot != stored_snapshot {
        return Err(invariant(
            "active snapshot evidence differs from its durable fence",
        ));
    }
    let target = verified_snapshot
        .snapshot
        .target(package_id, version)
        .ok_or_else(|| invariant("registry package target is absent from active snapshot"))?;
    let verified_release = inspect_registry_release(
        &inspected.release().envelope_bytes,
        &verified_snapshot,
        target,
        host_api_version,
    )
    .map_err(|_| invariant("registry package release is no longer authorized"))?;
    if &verified_release != inspected.release() {
        return Err(invariant("registry package release evidence drifted"));
    }
    let (accepted_release, _) = load_release(transaction, registry_id, package_id, version)?
        .ok_or_else(|| invariant("registry package has no accepted release evidence"))?;
    if accepted_release != verified_release {
        return Err(invariant(
            "registry package release differs from accepted evidence",
        ));
    }
    Ok(verified_release)
}

fn insert_artifact_blob(
    transaction: &Transaction<'_>,
    blob: &CommittedArtifactBlob,
    committed_at_ms: i64,
) -> Result<(), RegistryMetadataStoreError> {
    transaction
        .execute(
            "INSERT INTO artifact_blob(
                 algorithm, digest, size_bytes, relative_path, committed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(algorithm, digest) DO NOTHING",
            params![
                blob.algorithm,
                blob.digest,
                to_i64(blob.size_bytes, "registry artifact blob size")?,
                blob.relative_path,
                committed_at_ms,
            ],
        )
        .map_err(map_sqlite)?;
    let stored = transaction
        .query_row(
            "SELECT size_bytes, relative_path
             FROM artifact_blob WHERE algorithm = ?1 AND digest = ?2",
            params![blob.algorithm, blob.digest],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(map_sqlite)?;
    if u64::try_from(stored.0).ok() != Some(blob.size_bytes) || stored.1 != blob.relative_path {
        return Err(RegistryMetadataStoreError::Conflict);
    }
    Ok(())
}

fn ensure_release_digest_unaliased(
    transaction: &Transaction<'_>,
    registry_id: &str,
    envelope_digest: &str,
) -> Result<(), RegistryMetadataStoreError> {
    let alias: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM registry_release
                 WHERE registry_id = ?1 AND envelope_digest = ?2
             )",
            params![registry_id, envelope_digest],
            |row| row.get(0),
        )
        .map_err(map_sqlite)?;
    if alias {
        Err(RegistryMetadataStoreError::Conflict)
    } else {
        Ok(())
    }
}

fn load_trust_root(
    connection: &Connection,
    registry_id: &str,
) -> Result<Option<InspectedRegistryTrustRoot>, RegistryMetadataStoreError> {
    let row = connection
        .query_row(
            "SELECT root.root_json, root.root_digest, root.activated_at_ms
             FROM registry_trust_root_head head
             JOIN registry_trust_root root
               ON root.registry_id = head.registry_id
              AND root.root_version = head.root_version
              AND root.root_digest = head.root_digest
             WHERE head.registry_id = ?1",
            [registry_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite)?;
    let Some((root_bytes, expected_digest, activated_at_ms)) = row else {
        return Ok(None);
    };
    let inspected = inspect_initial_registry_trust_root(&root_bytes, activated_at_ms)
        .map_err(|_| invariant("stored trust-root bytes are invalid"))?;
    if inspected.trust_root.registry_id != registry_id || inspected.root_digest != expected_digest {
        return Err(invariant(
            "stored trust-root identity or digest is inconsistent",
        ));
    }
    Ok(Some(inspected))
}

fn load_trust_root_version(
    connection: &Connection,
    registry_id: &str,
    root_version: u64,
) -> Result<InspectedRegistryTrustRoot, RegistryMetadataStoreError> {
    let row = connection
        .query_row(
            "SELECT root_json, root_digest, activated_at_ms
             FROM registry_trust_root
             WHERE registry_id = ?1 AND root_version = ?2",
            params![
                registry_id,
                to_i64(root_version, "stored trust-root version")?
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite)?
        .ok_or_else(|| invariant("snapshot lost its authorizing trust root"))?;
    let inspected = inspect_initial_registry_trust_root(&row.0, row.2)
        .map_err(|_| invariant("stored historical trust-root bytes are invalid"))?;
    if inspected.trust_root.registry_id != registry_id
        || inspected.trust_root.root_version != root_version
        || inspected.root_digest != row.1
    {
        return Err(invariant(
            "stored historical trust-root identity or digest is inconsistent",
        ));
    }
    Ok(inspected)
}

fn load_root_state(
    connection: &Connection,
    registry_id: &str,
) -> Result<Option<RegistryTrustRootState>, RegistryMetadataStoreError> {
    connection
        .query_row(
            "SELECT registry_id, root_version, root_digest, expires_at_ms
             FROM registry_trust_root_head WHERE registry_id = ?1",
            [registry_id],
            |row| {
                Ok(RegistryTrustRootState {
                    registry_id: row.get(0)?,
                    root_version: from_i64(row.get(1)?, "stored trust-root version")?,
                    root_digest: row.get(2)?,
                    expires_at_ms: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite)?
        .map(validate_root_state)
        .transpose()
}

fn load_snapshot_state(
    connection: &Connection,
    registry_id: &str,
) -> Result<Option<RegistrySnapshotState>, RegistryMetadataStoreError> {
    connection
        .query_row(
            "SELECT registry_id, root_version, snapshot_version,
                    envelope_digest, expires_at_ms
             FROM registry_snapshot_head WHERE registry_id = ?1",
            [registry_id],
            |row| {
                Ok(RegistrySnapshotState {
                    registry_id: row.get(0)?,
                    root_version: from_i64(row.get(1)?, "stored snapshot root version")?,
                    version: from_i64(row.get(2)?, "stored snapshot version")?,
                    envelope_digest: row.get(3)?,
                    expires_at_ms: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite)?
        .map(validate_snapshot_state)
        .transpose()
}

fn load_current_snapshot(
    connection: &Connection,
    registry_id: &str,
) -> Result<Option<InspectedRegistrySnapshot>, RegistryMetadataStoreError> {
    let state = load_snapshot_state(connection, registry_id)?;
    state
        .map(|state| {
            load_snapshot_evidence(
                connection,
                registry_id,
                state.version,
                &state.envelope_digest,
            )
        })
        .transpose()
}

fn load_snapshot_evidence(
    connection: &Connection,
    registry_id: &str,
    snapshot_version: u64,
    envelope_digest: &str,
) -> Result<InspectedRegistrySnapshot, RegistryMetadataStoreError> {
    let row = connection
        .query_row(
            "SELECT root_version, payload_digest, envelope_bytes,
                    expires_at_ms, accepted_at_ms
             FROM registry_snapshot
             WHERE registry_id = ?1 AND snapshot_version = ?2 AND envelope_digest = ?3",
            params![
                registry_id,
                to_i64(snapshot_version, "stored snapshot version")?,
                envelope_digest,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite)?
        .ok_or_else(|| invariant("snapshot head lost its immutable evidence"))?;
    let root_version =
        u64::try_from(row.0).map_err(|_| invariant("stored snapshot root version is negative"))?;
    let root = load_trust_root_version(connection, registry_id, root_version)?;
    let inspected = inspect_registry_snapshot(&row.2, &root.trust_root, None, row.4)
        .map_err(|_| invariant("stored registry snapshot evidence is invalid"))?;
    if inspected.state.registry_id != registry_id
        || inspected.state.root_version != root_version
        || inspected.state.version != snapshot_version
        || inspected.state.envelope_digest != envelope_digest
        || inspected.state.expires_at_ms != row.3
        || inspected.payload_digest != row.1
    {
        return Err(invariant(
            "stored registry snapshot identity or digest is inconsistent",
        ));
    }
    Ok(inspected)
}

fn load_release(
    connection: &Connection,
    registry_id: &str,
    package_id: &str,
    version: &str,
) -> Result<Option<(InspectedRegistryRelease, RegistryReleaseState)>, RegistryMetadataStoreError> {
    let row = connection
        .query_row(
            "SELECT package_kind, publisher_id, envelope_digest, payload_digest,
                    envelope_bytes, manifest_digest, package_digest,
                    accepted_snapshot_version, accepted_snapshot_root_version,
                    accepted_snapshot_envelope_digest, accepted_host_api_version,
                    accepted_at_ms
             FROM registry_release
             WHERE registry_id = ?1 AND package_id = ?2 AND version = ?3",
            params![registry_id, package_id, version],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let kind = parse_package_kind(&row.0)?;
    let snapshot_version = u64::try_from(row.7)
        .map_err(|_| invariant("stored release snapshot version is negative"))?;
    let snapshot_root_version = u64::try_from(row.8)
        .map_err(|_| invariant("stored release snapshot root version is negative"))?;
    let host_api_version = u32::try_from(row.10)
        .map_err(|_| invariant("stored release host API version is invalid"))?;
    let snapshot = load_snapshot_evidence(connection, registry_id, snapshot_version, &row.9)?;
    if snapshot.state.root_version != snapshot_root_version {
        return Err(invariant(
            "stored release snapshot root identity is inconsistent",
        ));
    }
    let authorizing_root = load_trust_root_version(connection, registry_id, snapshot_root_version)?;
    if row.11 < 0
        || row.11 >= snapshot.state.expires_at_ms
        || row.11 >= authorizing_root.trust_root.expires_at_ms
    {
        return Err(invariant(
            "stored release acceptance time is outside its trust window",
        ));
    }
    let target = snapshot
        .snapshot
        .target(package_id, version)
        .ok_or_else(|| invariant("stored release target is absent from its accepted snapshot"))?;
    let inspected = inspect_registry_release(&row.4, &snapshot, target, host_api_version)
        .map_err(|_| invariant("stored registry release evidence is invalid"))?;
    let expected = release_state(&inspected, &snapshot.state, host_api_version, row.11);
    if expected.kind != kind
        || expected.publisher_id != row.1
        || expected.envelope_digest != row.2
        || expected.payload_digest != row.3
        || expected.manifest_digest != row.5
        || expected.package_digest != row.6
    {
        return Err(invariant(
            "stored registry release identity or digest is inconsistent",
        ));
    }
    Ok(Some((inspected, expected)))
}

fn load_package(
    connection: &Connection,
    registry_id: &str,
    package_id: &str,
    version: &str,
) -> Result<Option<RegistryPackageState>, RegistryMetadataStoreError> {
    let row = connection
        .query_row(
            "SELECT package.package_kind, package.release_envelope_digest,
                    package.staged_at_ms,
                    manifest.algorithm, manifest.digest, manifest.size_bytes,
                    manifest.relative_path,
                    archive.algorithm, archive.digest, archive.size_bytes,
                    archive.relative_path
             FROM registry_package package
             JOIN artifact_blob manifest
               ON manifest.algorithm = package.manifest_blob_algorithm
              AND manifest.digest = package.manifest_blob_digest
             JOIN artifact_blob archive
               ON archive.algorithm = package.package_blob_algorithm
              AND archive.digest = package.package_blob_digest
             WHERE package.registry_id = ?1
               AND package.package_id = ?2
               AND package.version = ?3",
            params![registry_id, package_id, version],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let (_, release_state) = load_release(connection, registry_id, package_id, version)?
        .ok_or_else(|| invariant("registry package lost accepted release evidence"))?;
    let manifest_size =
        u64::try_from(row.5).map_err(|_| invariant("registry manifest blob size is negative"))?;
    let package_size =
        u64::try_from(row.9).map_err(|_| invariant("registry package blob size is negative"))?;
    let manifest_blob = CommittedArtifactBlob {
        algorithm: row.3,
        digest: row.4,
        size_bytes: manifest_size,
        relative_path: row.6,
    };
    let package_blob = CommittedArtifactBlob {
        algorithm: row.7,
        digest: row.8,
        size_bytes: package_size,
        relative_path: row.10,
    };
    manifest_blob
        .validate()
        .map_err(|_| invariant("stored registry manifest blob is invalid"))?;
    package_blob
        .validate()
        .map_err(|_| invariant("stored registry package blob is invalid"))?;
    let kind = parse_package_kind(&row.0)?;
    if row.2 < 0
        || kind != release_state.kind
        || row.1 != release_state.envelope_digest
        || manifest_blob.digest != release_state.manifest_digest
        || package_blob.digest != release_state.package_digest
    {
        return Err(invariant(
            "stored registry package identity or blobs are inconsistent",
        ));
    }
    Ok(Some(RegistryPackageState {
        registry_id: registry_id.to_owned(),
        package_id: package_id.to_owned(),
        kind,
        version: version.to_owned(),
        release_envelope_digest: row.1,
        manifest_blob,
        package_blob,
        staged_at_ms: row.2,
    }))
}

fn release_state(
    inspected: &InspectedRegistryRelease,
    snapshot: &RegistrySnapshotState,
    host_api_version: u32,
    accepted_at_ms: i64,
) -> RegistryReleaseState {
    RegistryReleaseState {
        registry_id: inspected.release.registry_id.clone(),
        package_id: inspected.release.package_id.clone(),
        kind: inspected.release.kind,
        version: inspected.release.version.clone(),
        publisher_id: inspected.release.publisher_id.clone(),
        envelope_digest: inspected.envelope_digest.clone(),
        payload_digest: inspected.payload_digest.clone(),
        manifest_digest: inspected.release.manifest.sha256_digest.clone(),
        package_digest: inspected.release.package.sha256_digest.clone(),
        accepted_snapshot_version: snapshot.version,
        accepted_snapshot_root_version: snapshot.root_version,
        accepted_snapshot_envelope_digest: snapshot.envelope_digest.clone(),
        accepted_host_api_version: host_api_version,
        accepted_at_ms,
    }
}

const fn package_kind_text(kind: RegistryPackageKind) -> &'static str {
    match kind {
        RegistryPackageKind::Extension => "extension",
        RegistryPackageKind::Skill => "skill",
    }
}

fn parse_package_kind(value: &str) -> Result<RegistryPackageKind, RegistryMetadataStoreError> {
    match value {
        "extension" => Ok(RegistryPackageKind::Extension),
        "skill" => Ok(RegistryPackageKind::Skill),
        _ => Err(invariant("stored registry package kind is invalid")),
    }
}

fn validate_root_state(
    state: RegistryTrustRootState,
) -> Result<RegistryTrustRootState, RegistryMetadataStoreError> {
    if state.registry_id.is_empty()
        || state.root_version == 0
        || !is_digest(&state.root_digest)
        || state.expires_at_ms <= 0
    {
        return Err(invariant("stored trust-root head is invalid"));
    }
    Ok(state)
}

fn validate_snapshot_state(
    state: RegistrySnapshotState,
) -> Result<RegistrySnapshotState, RegistryMetadataStoreError> {
    if state.registry_id.is_empty()
        || state.root_version == 0
        || state.version == 0
        || !is_digest(&state.envelope_digest)
        || state.expires_at_ms <= 0
    {
        return Err(invariant("stored registry snapshot head is invalid"));
    }
    Ok(state)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn to_i64(value: u64, name: &str) -> Result<i64, RegistryMetadataStoreError> {
    i64::try_from(value).map_err(|_| invariant(&format!("{name} exceeds SQLite INTEGER")))
}

fn from_i64(value: i64, name: &str) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            format!("{name} is negative").into(),
        )
    })
}

fn map_sqlite(error: rusqlite::Error) -> RegistryMetadataStoreError {
    let message = error.to_string();
    drop(error);
    RegistryMetadataStoreError::Unavailable(message)
}

fn invariant(message: &str) -> RegistryMetadataStoreError {
    RegistryMetadataStoreError::InvariantViolation(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer as _, SigningKey};
    use mealy_application::{
        ArtifactBlobStore, REGISTRY_RELEASE_CONTRACT_VERSION, REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE,
        REGISTRY_RELEASE_PAYLOAD_TYPE, REGISTRY_ROOT_PAYLOAD_TYPE,
        REGISTRY_SKILL_MANIFEST_MEDIA_TYPE, REGISTRY_SKILL_PACKAGE_MEDIA_TYPE,
        REGISTRY_SNAPSHOT_CONTRACT_VERSION, REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
        RegistryContentDescriptor, RegistryMetadataStore, RegistryPackageKind, RegistryPublicKey,
        RegistryPublisher, RegistryRelease, RegistrySignature, RegistrySignatureAlgorithm,
        RegistrySignedEnvelope, RegistrySnapshot, RegistryTarget, RegistryTrustRoot,
        RegistryUseCaseError, RegistryWithdrawal, accept_registry_release,
        accept_registry_snapshot, active_registry_snapshot, bootstrap_registry_trust_root,
        rotate_registry_trust_root, sha256_digest,
    };
    use mealy_domain::{SKILL_MANIFEST_CONTRACT_VERSION, SkillAsset, SkillManifest};
    use std::{collections::BTreeSet, io::Cursor};
    use tar::{Builder, EntryType, Header};

    const NOW_MS: i64 = 10_000;
    const ROOT_CONTEXT: &str = "MEALY-REGISTRY-ROOT-V1";
    const RELEASE_CONTEXT: &str = "MEALY-REGISTRY-RELEASE-V1";
    const SNAPSHOT_CONTEXT: &str = "MEALY-REGISTRY-SNAPSHOT-V1";

    #[test]
    #[allow(clippy::too_many_lines)] // One sequential proof crosses bootstrap, refresh, rotation, and reopen.
    fn roots_and_snapshots_are_atomic_monotonic_and_restart_durable() {
        let temporary = tempfile::tempdir().expect("temporary registry home");
        let database = temporary.path().join("state.sqlite3");
        let old_key = SigningKey::from_bytes(&[17; 32]);
        let new_key = SigningKey::from_bytes(&[19; 32]);
        let publisher_key = SigningKey::from_bytes(&[23; 32]);
        let root = RegistryTrustRoot {
            registry_id: "dev.mealy.registry".to_owned(),
            root_version: 7,
            keys: vec![public_key(&old_key)],
            threshold: 1,
            expires_at_ms: NOW_MS + 600_000,
        };
        let root_bytes = serde_json::to_vec(&root).expect("initial root");
        let snapshot_one = snapshot(1, &publisher_key);
        let snapshot_one_envelope = signed_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_CONTEXT,
            &snapshot_one,
            &[&old_key],
        );

        let mut store = SqliteStore::open(&database, NOW_MS).expect("registry store");
        let root_state =
            bootstrap_registry_trust_root(&mut store, &root_bytes, NOW_MS).expect("root bootstrap");
        assert_eq!(root_state.root_version, 7);
        let first = accept_registry_snapshot(
            &mut store,
            &root.registry_id,
            &snapshot_one_envelope,
            NOW_MS,
        )
        .expect("first snapshot");
        assert_eq!(first.version, 1);
        drop(store);

        let mut reopened = SqliteStore::open(&database, NOW_MS + 1).expect("reopen registry store");
        let exact_replay = accept_registry_snapshot(
            &mut reopened,
            &root.registry_id,
            &snapshot_one_envelope,
            NOW_MS + 1,
        )
        .expect("exact snapshot replay");
        assert_eq!(exact_replay, first);
        let snapshot_two = snapshot(2, &publisher_key);
        let snapshot_two_envelope = signed_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_CONTEXT,
            &snapshot_two,
            &[&old_key],
        );
        let second = accept_registry_snapshot(
            &mut reopened,
            &root.registry_id,
            &snapshot_two_envelope,
            NOW_MS + 2,
        )
        .expect("second snapshot");
        assert_eq!(second.version, 2);
        assert!(matches!(
            accept_registry_snapshot(
                &mut reopened,
                &root.registry_id,
                &snapshot_one_envelope,
                NOW_MS + 3
            ),
            Err(RegistryUseCaseError::Verification(
                mealy_application::RegistryError::Rollback
            ))
        ));

        let next_root = RegistryTrustRoot {
            registry_id: root.registry_id.clone(),
            root_version: 8,
            keys: vec![public_key(&new_key)],
            threshold: 1,
            expires_at_ms: NOW_MS + 900_000,
        };
        let rotation = signed_envelope(
            REGISTRY_ROOT_PAYLOAD_TYPE,
            ROOT_CONTEXT,
            &next_root,
            &[&old_key, &new_key],
        );
        let rotated =
            rotate_registry_trust_root(&mut reopened, &root.registry_id, &rotation, NOW_MS + 4)
                .expect("rotate root");
        assert_eq!(rotated.root_version, 8);
        assert_eq!(
            rotate_registry_trust_root(&mut reopened, &root.registry_id, &rotation, NOW_MS + 5,)
                .expect("exact rotation replay"),
            rotated
        );
        assert!(
            active_registry_snapshot(&reopened, &root.registry_id, NOW_MS + 5).is_err(),
            "a root rotation must require a newly authorized snapshot before release admission"
        );

        let snapshot_three = snapshot(3, &publisher_key);
        let snapshot_three_envelope = signed_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_CONTEXT,
            &snapshot_three,
            &[&new_key],
        );
        let third = accept_registry_snapshot(
            &mut reopened,
            &root.registry_id,
            &snapshot_three_envelope,
            NOW_MS + 6,
        )
        .expect("post-rotation snapshot");
        assert_eq!(third.root_version, 8);
        assert_eq!(third.version, 3);
        assert!(
            reopened
                .connection
                .execute(
                    "DELETE FROM registry_snapshot WHERE registry_id = ?1",
                    [&root.registry_id],
                )
                .is_err(),
            "immutable snapshot evidence must reject deletion"
        );
        drop(reopened);

        let final_store = SqliteStore::open(&database, NOW_MS + 7).expect("final registry reopen");
        assert_eq!(
            final_store
                .registry_trust_root(&root.registry_id)
                .expect("load root")
                .expect("active root")
                .state(),
            rotated
        );
        assert_eq!(
            final_store
                .registry_snapshot_state(&root.registry_id)
                .expect("load snapshot"),
            Some(third)
        );
        final_store
            .verify_storage_integrity()
            .expect("registry storage integrity");
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One proof crosses accept, replay, reopen, and withdrawal.
    fn publisher_release_and_package_evidence_are_exact_durable_and_withdrawal_aware() {
        let temporary = tempfile::tempdir().expect("temporary registry home");
        let database = temporary.path().join("state.sqlite3");
        let artifacts =
            crate::FileArtifactBlobStore::new(temporary.path().join("artifacts"), 1024 * 1024)
                .expect("artifact store");
        let root_key = SigningKey::from_bytes(&[31; 32]);
        let publisher_key = SigningKey::from_bytes(&[37; 32]);
        let root = RegistryTrustRoot {
            registry_id: "dev.mealy.registry".to_owned(),
            root_version: 1,
            keys: vec![public_key(&root_key)],
            threshold: 1,
            expires_at_ms: NOW_MS + 600_000,
        };
        let instruction = b"Review the requested change.\n";
        let manifest = SkillManifest {
            contract_version: SKILL_MANIFEST_CONTRACT_VERSION.to_owned(),
            skill_id: "dev.mealy.skill.review".to_owned(),
            version: "1.0.0".to_owned(),
            instructions: vec![SkillAsset {
                relative_path: "instructions/review.md".to_owned(),
                media_type: "text/markdown".to_owned(),
                content_digest: sha256_digest(instruction),
                size_bytes: u64::try_from(instruction.len()).expect("instruction size"),
            }],
            resources: Vec::new(),
            required_tools: BTreeSet::new(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest).expect("skill manifest");
        let package_bytes = deterministic_archive(&[
            ("manifest.json", &manifest_bytes, 0o644),
            ("instructions/review.md", instruction, 0o644),
        ]);
        let release = RegistryRelease {
            contract_version: REGISTRY_RELEASE_CONTRACT_VERSION.to_owned(),
            registry_id: root.registry_id.clone(),
            package_id: manifest.skill_id.clone(),
            kind: RegistryPackageKind::Skill,
            publisher_id: "dev.mealy".to_owned(),
            version: manifest.version.clone(),
            manifest: descriptor(REGISTRY_SKILL_MANIFEST_MEDIA_TYPE, &manifest_bytes),
            package: descriptor(REGISTRY_SKILL_PACKAGE_MEDIA_TYPE, &package_bytes),
            minimum_host_api: 1,
            maximum_host_api: 1,
            dependencies: Vec::new(),
            published_at_ms: NOW_MS,
        };
        let release_envelope = signed_envelope(
            REGISTRY_RELEASE_PAYLOAD_TYPE,
            RELEASE_CONTEXT,
            &release,
            &[&publisher_key],
        );
        let target = RegistryTarget {
            package_id: release.package_id.clone(),
            kind: release.kind,
            version: release.version.clone(),
            publisher_id: release.publisher_id.clone(),
            release_envelope: descriptor(REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE, &release_envelope),
            withdrawal: None,
        };
        let snapshot = snapshot_with_target(1, &publisher_key, target.clone());
        let snapshot_envelope = signed_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_CONTEXT,
            &snapshot,
            &[&root_key],
        );
        let mut store = SqliteStore::open(&database, NOW_MS).expect("registry store");
        bootstrap_registry_trust_root(
            &mut store,
            &serde_json::to_vec(&root).expect("root bytes"),
            NOW_MS,
        )
        .expect("root bootstrap");
        accept_registry_snapshot(&mut store, &root.registry_id, &snapshot_envelope, NOW_MS)
            .expect("snapshot");
        let accepted = accept_registry_release(
            &mut store,
            &root.registry_id,
            &release.package_id,
            &release.version,
            &release_envelope,
            1,
            NOW_MS + 1,
        )
        .expect("release evidence");
        assert_eq!(accepted.envelope_digest, sha256_digest(&release_envelope));
        assert_eq!(accepted.accepted_snapshot_version, 1);
        assert_eq!(
            accept_registry_release(
                &mut store,
                &root.registry_id,
                &release.package_id,
                &release.version,
                &release_envelope,
                1,
                NOW_MS + 2,
            )
            .expect("exact release replay"),
            accepted
        );
        let (inspected_release, _) = store
            .registry_release(&root.registry_id, &release.package_id, &release.version)
            .expect("load accepted release")
            .expect("accepted release");
        let inspected_package = crate::inspect_registry_package_archive(
            &inspected_release,
            &manifest_bytes,
            &package_bytes,
        )
        .expect("inspect exact package");
        let bridged_skill = crate::inspected_registry_skill_package(&inspected_package)
            .expect("bridge registry package into inert skill lifecycle");
        let installed_skill =
            crate::publish_skill_package(&bridged_skill, &temporary.path().join("skills"))
                .expect("publish bridged skill");
        assert_eq!(
            crate::inspect_skill_package(
                &installed_skill.join("manifest.json"),
                &installed_skill,
                Some(bridged_skill.manifest_digest()),
            )
            .expect("reinspect bridged skill"),
            bridged_skill
        );
        let manifest_blob = artifacts.commit(&manifest_bytes).expect("manifest blob");
        let package_blob = artifacts.commit(&package_bytes).expect("package blob");
        let snapshot_state = store
            .registry_snapshot_state(&root.registry_id)
            .expect("snapshot state")
            .expect("active snapshot");
        let mut mismatched_manifest_blob = manifest_blob.clone();
        mismatched_manifest_blob.size_bytes += 1;
        assert!(matches!(
            store.commit_registry_package(
                &inspected_package,
                mismatched_manifest_blob,
                package_blob.clone(),
                &snapshot_state,
                1,
                NOW_MS + 2,
            ),
            Err(mealy_application::RegistryMetadataStoreError::InvariantViolation(_))
        ));
        assert!(
            store
                .registry_package(&root.registry_id, &release.package_id, &release.version)
                .expect("load rejected package")
                .is_none(),
            "mismatched blob evidence must commit no package row"
        );
        assert!(
            store
                .artifact_blob_records()
                .expect("rejected package blob records")
                .is_empty(),
            "mismatched blob evidence must commit no database blob rows"
        );
        let staged = store
            .commit_registry_package(
                &inspected_package,
                manifest_blob.clone(),
                package_blob.clone(),
                &snapshot_state,
                1,
                NOW_MS + 2,
            )
            .expect("stage package");
        assert_eq!(staged.manifest_blob, manifest_blob);
        assert_eq!(staged.package_blob, package_blob);
        assert_eq!(
            store
                .commit_registry_package(
                    &inspected_package,
                    staged.manifest_blob.clone(),
                    staged.package_blob.clone(),
                    &snapshot_state,
                    1,
                    NOW_MS + 3,
                )
                .expect("exact package replay"),
            staged
        );
        assert_eq!(
            store
                .artifact_blob_records()
                .expect("backup-visible package blobs")
                .len(),
            2
        );
        assert!(
            store
                .connection
                .execute(
                    "UPDATE registry_release SET package_digest = ?1
                     WHERE registry_id = ?2 AND package_id = ?3 AND version = ?4",
                    rusqlite::params![
                        "a".repeat(64),
                        root.registry_id,
                        release.package_id,
                        release.version,
                    ],
                )
                .is_err(),
            "immutable release evidence must reject updates"
        );
        assert!(
            store
                .connection
                .execute(
                    "UPDATE registry_package SET staged_at_ms = staged_at_ms + 1
                     WHERE registry_id = ?1 AND package_id = ?2 AND version = ?3",
                    rusqlite::params![root.registry_id, release.package_id, release.version],
                )
                .is_err(),
            "immutable package evidence must reject updates"
        );
        assert!(
            store
                .connection
                .execute(
                    "DELETE FROM registry_package
                     WHERE registry_id = ?1 AND package_id = ?2 AND version = ?3",
                    rusqlite::params![root.registry_id, release.package_id, release.version],
                )
                .is_err(),
            "immutable package evidence must reject deletes"
        );
        drop(store);

        let mut reopened = SqliteStore::open(&database, NOW_MS + 3).expect("reopen registry store");
        let (_, reopened_state) = reopened
            .registry_release(&root.registry_id, &release.package_id, &release.version)
            .expect("load release")
            .expect("durable release");
        assert_eq!(reopened_state, accepted);
        let reopened_package = reopened
            .registry_package(&root.registry_id, &release.package_id, &release.version)
            .expect("load package")
            .expect("durable package");
        assert_eq!(reopened_package, staged);
        assert_eq!(
            artifacts
                .read(&reopened_package.manifest_blob)
                .expect("read manifest blob"),
            manifest_bytes
        );
        assert_eq!(
            artifacts
                .read(&reopened_package.package_blob)
                .expect("read package blob"),
            package_bytes
        );

        let mut withdrawn_target = target;
        withdrawn_target.withdrawal = Some(RegistryWithdrawal {
            withdrawn_at_ms: NOW_MS,
            reason: "publisher key compromise".to_owned(),
        });
        let withdrawn_snapshot = snapshot_with_target(2, &publisher_key, withdrawn_target);
        let withdrawn_envelope = signed_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_CONTEXT,
            &withdrawn_snapshot,
            &[&root_key],
        );
        accept_registry_snapshot(
            &mut reopened,
            &root.registry_id,
            &withdrawn_envelope,
            NOW_MS + 4,
        )
        .expect("withdrawn snapshot remains auditable");
        assert!(matches!(
            accept_registry_release(
                &mut reopened,
                &root.registry_id,
                &release.package_id,
                &release.version,
                &release_envelope,
                1,
                NOW_MS + 5,
            ),
            Err(RegistryUseCaseError::Verification(
                mealy_application::RegistryError::Withdrawn
            ))
        ));
        assert!(matches!(
            reopened.commit_registry_package(
                &inspected_package,
                reopened_package.manifest_blob,
                reopened_package.package_blob,
                &reopened
                    .registry_snapshot_state(&root.registry_id)
                    .expect("withdrawn snapshot state")
                    .expect("withdrawn snapshot"),
                1,
                NOW_MS + 6,
            ),
            Err(mealy_application::RegistryMetadataStoreError::InvariantViolation(_))
        ));
        assert!(
            reopened
                .registry_release(&root.registry_id, &release.package_id, &release.version)
                .expect("load historical release")
                .is_some()
        );
        reopened
            .verify_storage_integrity()
            .expect("release storage integrity");
    }

    fn snapshot(version: u64, publisher_key: &SigningKey) -> RegistrySnapshot {
        RegistrySnapshot {
            contract_version: REGISTRY_SNAPSHOT_CONTRACT_VERSION.to_owned(),
            registry_id: "dev.mealy.registry".to_owned(),
            version,
            generated_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 300_000,
            publishers: vec![RegistryPublisher {
                publisher_id: "dev.mealy".to_owned(),
                keys: vec![public_key(publisher_key)],
                threshold: 1,
            }],
            targets: Vec::new(),
        }
    }

    fn snapshot_with_target(
        version: u64,
        publisher_key: &SigningKey,
        target: RegistryTarget,
    ) -> RegistrySnapshot {
        let mut snapshot = snapshot(version, publisher_key);
        snapshot.targets = vec![target];
        snapshot
    }

    fn descriptor(media_type: &str, bytes: &[u8]) -> RegistryContentDescriptor {
        RegistryContentDescriptor {
            media_type: media_type.to_owned(),
            sha256_digest: sha256_digest(bytes),
            size_bytes: u64::try_from(bytes.len()).expect("fixture length"),
        }
    }

    fn deterministic_archive(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for (path, bytes, mode) in entries {
            let mut header = Header::new_ustar();
            header.set_path(path).expect("archive path");
            header.set_size(u64::try_from(bytes.len()).expect("archive entry size"));
            header.set_mode(*mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_entry_type(EntryType::Regular);
            header.set_cksum();
            builder
                .append(&header, Cursor::new(bytes))
                .expect("archive entry");
        }
        builder.into_inner().expect("archive")
    }

    fn public_key(signing_key: &SigningKey) -> RegistryPublicKey {
        let bytes = signing_key.verifying_key().to_bytes();
        RegistryPublicKey {
            key_id: sha256_digest(&bytes),
            algorithm: RegistrySignatureAlgorithm::Ed25519,
            public_key_base64url: URL_SAFE_NO_PAD.encode(bytes),
        }
    }

    fn signed_envelope<T: serde::Serialize>(
        payload_type: &str,
        context: &str,
        payload: &T,
        keys: &[&SigningKey],
    ) -> Vec<u8> {
        let payload = serde_json::to_vec(payload).expect("payload");
        let mut material = Vec::from(context.as_bytes());
        material.push(0);
        material.extend_from_slice(&payload);
        let mut signatures = keys
            .iter()
            .map(|key| RegistrySignature {
                key_id: sha256_digest(&key.verifying_key().to_bytes()),
                signature_base64url: URL_SAFE_NO_PAD.encode(key.sign(&material).to_bytes()),
            })
            .collect::<Vec<_>>();
        signatures.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        serde_json::to_vec(&RegistrySignedEnvelope {
            payload_type: payload_type.to_owned(),
            payload_base64url: URL_SAFE_NO_PAD.encode(payload),
            signatures,
        })
        .expect("signed envelope")
    }
}
