use super::SqliteStore;
use mealy_application::{
    InspectedRegistryTrustRoot, RegistryMetadataStore, RegistryMetadataStoreError,
    RegistrySnapshotCommit, RegistrySnapshotState, RegistryTrustRootCommit, RegistryTrustRootState,
    inspect_initial_registry_trust_root, inspect_registry_snapshot,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

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
        REGISTRY_ROOT_PAYLOAD_TYPE, REGISTRY_SNAPSHOT_CONTRACT_VERSION,
        REGISTRY_SNAPSHOT_PAYLOAD_TYPE, RegistryMetadataStore, RegistryPublicKey,
        RegistryPublisher, RegistrySignature, RegistrySignatureAlgorithm, RegistrySignedEnvelope,
        RegistrySnapshot, RegistryTrustRoot, RegistryUseCaseError, accept_registry_snapshot,
        bootstrap_registry_trust_root, rotate_registry_trust_root, sha256_digest,
    };

    const NOW_MS: i64 = 10_000;
    const ROOT_CONTEXT: &str = "MEALY-REGISTRY-ROOT-V1";
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
