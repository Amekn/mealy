use super::SqliteStore;
use mealy_application::{
    InputAdmissionCommit, InputAdmissionOutcome, InputAdmissionReceipt, InputImageArtifactCommit,
    MAXIMUM_PROVIDER_IMAGE_INPUT_TOTAL_BYTES, MAXIMUM_PROVIDER_IMAGE_INPUTS, ProviderSelection,
    ProviderSelectionPreference, SessionCreationCommit, SessionStore, SessionStoreError,
    sha256_digest,
};
use mealy_domain::{DeliveryMode, SessionId};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{collections::BTreeSet, fmt::Display, str::FromStr, time::SystemTime};

impl SessionStore for SqliteStore {
    fn create_session(&mut self, commit: SessionCreationCommit) -> Result<(), SessionStoreError> {
        if commit
            .provider_selection
            .as_ref()
            .is_some_and(|selection| !selection.is_valid())
        {
            return Err(invariant(
                "application supplied an invalid provider selection",
            ));
        }
        let created_at_ms = epoch_milliseconds(commit.created_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;

        transaction
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?4)",
                params![
                    commit.session_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    commit.ownership.channel_binding_id().to_string(),
                    created_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO session_lineage(\
                    session_id, root_session_id, parent_checkpoint_id, fork_event_id, created_at_ms\
                 ) VALUES (?1, ?1, NULL, NULL, ?2)",
                params![commit.session_id.to_string(), created_at_ms],
            )
            .map_err(map_sqlite_error)?;

        transaction
            .execute(
                "INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                    sensitivity, payload_json\
                 ) VALUES (?1, 'session', ?2, 0, 'session.created', 1, ?3, ?4, ?5, \
                           'private', ?6)",
                params![
                    commit.event_id.to_string(),
                    commit.session_id.to_string(),
                    created_at_ms,
                    commit.ownership.principal_id().to_string(),
                    commit.correlation_id.to_string(),
                    json!({
                        "channel_binding_id": commit.ownership.channel_binding_id(),
                        "provider_selection": commit.provider_selection.as_ref().map_or_else(
                            || json!({ "mode": "automatic" }),
                            |selection| {
                                json!({
                                    "mode": "exact",
                                    "provider_id": selection.provider_id,
                                    "model_id": selection.model_id,
                                })
                            },
                        ),
                    })
                    .to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;

        if let Some(selection) = &commit.provider_selection {
            transaction
                .execute(
                    "INSERT INTO session_provider_selection(\
                        session_id, provider_id, model_id, selection_event_id, updated_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        commit.session_id.to_string(),
                        selection.provider_id,
                        selection.model_id,
                        commit.event_id.to_string(),
                        created_at_ms,
                    ],
                )
                .map_err(map_sqlite_error)?;
        }

        transaction
            .execute(
                "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
                 VALUES ('session', ?1, 0)",
                [commit.session_id.to_string()],
            )
            .map_err(map_sqlite_error)?;
        transaction.commit().map_err(map_sqlite_error)
    }

    fn admit_input(
        &mut self,
        commit: InputAdmissionCommit,
    ) -> Result<InputAdmissionOutcome, SessionStoreError> {
        validate_input_images(&commit.images, commit.accepted_at)?;
        let accepted_at_ms = epoch_milliseconds(commit.accepted_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;

        if !active_identity(&transaction, commit.ownership)? {
            return Err(SessionStoreError::Unauthorized);
        }

        let session = load_session(&transaction, commit.session_id)?;

        if session.principal_id != commit.ownership.principal_id().to_string()
            || session.channel_binding_id != commit.ownership.channel_binding_id().to_string()
        {
            return Err(SessionStoreError::Unauthorized);
        }

        if let Some(stored) = load_admission(&transaction, commit.session_id, &commit.dedupe_key)? {
            if stored.delivery_mode != commit.delivery_mode.as_str()
                || stored.content != commit.content
                || !stored.matches_preference(&commit.provider_selection)
                || !stored.matches_images(&commit.images)
            {
                return Err(SessionStoreError::IdempotencyConflict);
            }
            return stored
                .into_receipt(commit.session_id)
                .map(InputAdmissionOutcome::Duplicate);
        }

        let pending_inputs = transaction
            .query_row(
                "SELECT COUNT(*) FROM session_inbox WHERE session_id = ?1 AND state = 'pending'",
                [commit.session_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(map_sqlite_error)?;
        let maximum_pending_inputs = i64::try_from(commit.maximum_pending_inputs)
            .map_err(|_| invariant("session pending-input limit exceeds SQLite"))?;
        if maximum_pending_inputs == 0 || pending_inputs >= maximum_pending_inputs {
            return Err(SessionStoreError::Backpressure);
        }

        let inbox_sequence =
            insert_inbox_and_advance(&transaction, &commit, &session, accepted_at_ms)?;
        insert_input_images(&transaction, &commit, accepted_at_ms)?;
        append_input_journal(&transaction, &commit, inbox_sequence, accepted_at_ms)?;
        append_acknowledgement(&transaction, &commit, inbox_sequence, accepted_at_ms)?;
        let timeline_cursor = admission_cursor(&transaction, &commit.event_id.to_string())?;
        let (provider_selection, provider_selection_source) = resolved_provider_selection(
            &transaction,
            commit.session_id,
            &commit.provider_selection,
        )?;

        transaction.commit().map_err(map_sqlite_error)?;
        Ok(InputAdmissionOutcome::Accepted(InputAdmissionReceipt {
            session_id: commit.session_id,
            inbox_entry_id: commit.inbox_entry_id,
            image_artifact_ids: commit
                .images
                .iter()
                .map(|image| image.artifact_id)
                .collect(),
            inbox_sequence,
            delivery_mode: commit.delivery_mode,
            provider_selection,
            provider_selection_source,
            event_id: commit.event_id,
            outbox_id: commit.outbox_id,
            correlation_id: commit.correlation_id,
            accepted_at: system_time_from_epoch_milliseconds(accepted_at_ms)?,
            timeline_cursor,
        }))
    }
}

fn active_identity(
    transaction: &Transaction<'_>,
    ownership: mealy_application::OwnershipContext,
) -> Result<bool, SessionStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(\
                SELECT 1 FROM principal_registry principal \
                JOIN channel_binding_registry binding \
                  ON binding.principal_id = principal.principal_id \
                WHERE principal.principal_id = ?1 AND principal.status = 'active' \
                  AND binding.binding_id = ?2 AND binding.status = 'active'\
             )",
            params![
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)
}

struct SessionRow {
    principal_id: String,
    channel_binding_id: String,
    next_inbox_sequence: i64,
    revision: i64,
}

struct StoredAdmission {
    inbox_entry_id: String,
    inbox_sequence: i64,
    delivery_mode: String,
    content: String,
    provider_selection_source: String,
    selected_provider_id: Option<String>,
    selected_model_id: Option<String>,
    event_id: String,
    outbox_id: String,
    correlation_id: String,
    accepted_at_ms: i64,
    timeline_cursor: i64,
    images: Vec<StoredAdmissionImage>,
}

struct StoredAdmissionImage {
    artifact_id: String,
    algorithm: String,
    digest: String,
    size_bytes: i64,
    relative_path: String,
    media_type: String,
    width: i64,
    height: i64,
}

impl StoredAdmission {
    fn matches_preference(&self, preference: &ProviderSelectionPreference) -> bool {
        match preference {
            ProviderSelectionPreference::InheritSession => {
                self.provider_selection_source == "inherited"
            }
            ProviderSelectionPreference::Automatic => {
                self.provider_selection_source == "automatic"
                    && self.selected_provider_id.is_none()
                    && self.selected_model_id.is_none()
            }
            ProviderSelectionPreference::Exact(selection) => {
                self.provider_selection_source == "exact"
                    && self.selected_provider_id.as_deref() == Some(&selection.provider_id)
                    && self.selected_model_id.as_deref() == Some(&selection.model_id)
            }
        }
    }

    fn matches_images(&self, images: &[InputImageArtifactCommit]) -> bool {
        self.images.len() == images.len()
            && self.images.iter().zip(images).all(|(stored, supplied)| {
                stored.artifact_id == supplied.artifact_id.to_string()
                    && stored.algorithm == supplied.blob.algorithm
                    && stored.digest == supplied.blob.digest
                    && u64::try_from(stored.size_bytes).ok() == Some(supplied.blob.size_bytes)
                    && stored.relative_path == supplied.blob.relative_path
                    && stored.media_type == supplied.media_type
                    && u32::try_from(stored.width).ok() == Some(supplied.width)
                    && u32::try_from(stored.height).ok() == Some(supplied.height)
            })
    }
}

fn resolved_provider_selection(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    preference: &ProviderSelectionPreference,
) -> Result<(Option<ProviderSelection>, String), SessionStoreError> {
    let selection = match preference {
        ProviderSelectionPreference::InheritSession => transaction
            .query_row(
                "SELECT provider_id, model_id FROM session_provider_selection \
                 WHERE session_id = ?1",
                [session_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_error)?
            .map(|(provider_id, model_id)| selection_from_pair(provider_id, model_id))
            .transpose()?
            .flatten(),
        ProviderSelectionPreference::Automatic => None,
        ProviderSelectionPreference::Exact(selection) => Some(selection.clone()),
    };
    Ok((selection, preference.source().to_owned()))
}

fn selection_from_pair(
    provider_id: Option<String>,
    model_id: Option<String>,
) -> Result<Option<ProviderSelection>, SessionStoreError> {
    match (provider_id, model_id) {
        (None, None) => Ok(None),
        (Some(provider_id), Some(model_id)) => {
            let selection = ProviderSelection {
                provider_id,
                model_id,
            };
            if selection.is_valid() {
                Ok(Some(selection))
            } else {
                Err(invariant("stored provider selection is invalid"))
            }
        }
        _ => Err(invariant("stored provider selection pair is incomplete")),
    }
}

fn load_session(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<SessionRow, SessionStoreError> {
    transaction
        .query_row(
            "SELECT principal_id, channel_binding_id, next_inbox_sequence, revision \
             FROM session WHERE id = ?1",
            [session_id.to_string()],
            |row| {
                Ok(SessionRow {
                    principal_id: row.get(0)?,
                    channel_binding_id: row.get(1)?,
                    next_inbox_sequence: row.get(2)?,
                    revision: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(SessionStoreError::SessionNotFound)
}

fn validate_input_images(
    images: &[InputImageArtifactCommit],
    accepted_at: SystemTime,
) -> Result<(), SessionStoreError> {
    if images.len() > MAXIMUM_PROVIDER_IMAGE_INPUTS {
        return Err(invariant("input image count exceeds its bound"));
    }
    let mut artifact_ids = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for image in images {
        if !image.is_valid()
            || image.committed_at > accepted_at
            || !artifact_ids.insert(image.artifact_id)
        {
            return Err(invariant("input image evidence is invalid or duplicated"));
        }
        total_bytes = total_bytes
            .checked_add(image.blob.size_bytes)
            .ok_or_else(|| invariant("input image byte total overflow"))?;
    }
    if total_bytes > u64::try_from(MAXIMUM_PROVIDER_IMAGE_INPUT_TOTAL_BYTES).unwrap_or(u64::MAX) {
        return Err(invariant("input image byte total exceeds its bound"));
    }
    Ok(())
}

fn insert_inbox_and_advance(
    transaction: &Transaction<'_>,
    commit: &InputAdmissionCommit,
    session: &SessionRow,
    accepted_at_ms: i64,
) -> Result<u64, SessionStoreError> {
    let (provider_selection, provider_selection_source) =
        resolved_provider_selection(transaction, commit.session_id, &commit.provider_selection)?;
    let inbox_sequence = positive_u64(session.next_inbox_sequence, "inbox sequence")?;
    let following_sequence = session
        .next_inbox_sequence
        .checked_add(1)
        .ok_or_else(|| invariant("session inbox sequence overflow"))?;
    let following_revision = session
        .revision
        .checked_add(1)
        .ok_or_else(|| invariant("session revision overflow"))?;

    transaction
        .execute(
            "INSERT INTO session_inbox(\
                inbox_entry_id, session_id, sequence, dedupe_key, delivery_mode, content, \
                provider_selection_source, selected_provider_id, selected_model_id, \
                admission_event_id, acknowledgement_outbox_id, correlation_id, accepted_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                commit.inbox_entry_id.to_string(),
                commit.session_id.to_string(),
                session.next_inbox_sequence,
                commit.dedupe_key,
                commit.delivery_mode.as_str(),
                commit.content,
                provider_selection_source,
                provider_selection.as_ref().map(|value| &value.provider_id),
                provider_selection.as_ref().map(|value| &value.model_id),
                commit.event_id.to_string(),
                commit.outbox_id.to_string(),
                commit.correlation_id.to_string(),
                accepted_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;

    let updated = transaction
        .execute(
            "UPDATE session \
             SET next_inbox_sequence = ?1, revision = ?2, updated_at_ms = MAX(updated_at_ms, ?3) \
             WHERE id = ?4 AND principal_id = ?5 AND channel_binding_id = ?6 \
               AND next_inbox_sequence = ?7 AND revision = ?8",
            params![
                following_sequence,
                following_revision,
                accepted_at_ms,
                commit.session_id.to_string(),
                commit.ownership.principal_id().to_string(),
                commit.ownership.channel_binding_id().to_string(),
                session.next_inbox_sequence,
                session.revision,
            ],
        )
        .map_err(map_sqlite_error)?;
    if updated != 1 {
        return Err(SessionStoreError::Conflict);
    }
    Ok(inbox_sequence)
}

fn insert_input_images(
    transaction: &Transaction<'_>,
    commit: &InputAdmissionCommit,
    accepted_at_ms: i64,
) -> Result<(), SessionStoreError> {
    let principal_id = commit.ownership.principal_id().to_string();
    let session_id = commit.session_id.to_string();
    let inbox_entry_id = commit.inbox_entry_id.to_string();
    let access_policy_json =
        json!({"principalId": principal_id, "sessionId": session_id}).to_string();
    let access_policy_digest = sha256_digest(access_policy_json.as_bytes());
    for (ordinal, image) in commit.images.iter().enumerate() {
        let committed_at_ms = epoch_milliseconds(image.committed_at)?;
        let size_bytes = i64::try_from(image.blob.size_bytes)
            .map_err(|_| invariant("input image size exceeds SQLite"))?;
        transaction
            .execute(
                "INSERT INTO artifact_blob(\
                    algorithm, digest, size_bytes, relative_path, committed_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(algorithm, digest) DO UPDATE SET \
                    committed_at_ms = MIN(artifact_blob.committed_at_ms, excluded.committed_at_ms)",
                params![
                    image.blob.algorithm,
                    image.blob.digest,
                    size_bytes,
                    image.blob.relative_path,
                    committed_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        let blob_matches = transaction
            .query_row(
                "SELECT size_bytes = ?1 AND relative_path = ?2 \
                 FROM artifact_blob WHERE algorithm = ?3 AND digest = ?4",
                params![
                    size_bytes,
                    image.blob.relative_path,
                    image.blob.algorithm,
                    image.blob.digest,
                ],
                |row| row.get::<_, bool>(0),
            )
            .map_err(map_sqlite_error)?;
        if !blob_matches {
            return Err(invariant(
                "input image blob metadata conflicts with its content address",
            ));
        }
        transaction
            .execute(
                "INSERT INTO artifact(\
                    id, blob_algorithm, blob_digest, principal_id, session_id, media_type, \
                    origin_kind, origin_id, producer_kind, producer_id, sensitivity, \
                    retention_class, access_policy_json, access_policy_digest, created_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'session_input', ?7, 'builtin', \
                           'mealyd.media-normalizer.v1', 'private', 'session_history', \
                           ?8, ?9, ?10)",
                params![
                    image.artifact_id.to_string(),
                    image.blob.algorithm,
                    image.blob.digest,
                    principal_id,
                    session_id,
                    image.media_type,
                    inbox_entry_id,
                    access_policy_json,
                    access_policy_digest,
                    accepted_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO session_inbox_media(\
                    inbox_entry_id, ordinal, artifact_id, principal_id, session_id, media_type, \
                    width, height\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    inbox_entry_id,
                    i64::try_from(ordinal)
                        .map_err(|_| invariant("input image ordinal exceeds SQLite"))?,
                    image.artifact_id.to_string(),
                    principal_id,
                    session_id,
                    image.media_type,
                    i64::from(image.width),
                    i64::from(image.height),
                ],
            )
            .map_err(map_sqlite_error)?;
    }
    Ok(())
}

fn append_input_journal(
    transaction: &Transaction<'_>,
    commit: &InputAdmissionCommit,
    inbox_sequence: u64,
    accepted_at_ms: i64,
) -> Result<(), SessionStoreError> {
    let journal_sequence = next_journal_sequence(transaction, commit.session_id)?;
    let event_version = if commit.images.is_empty() { 1 } else { 2 };
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                sensitivity, payload_json\
             ) VALUES (?1, 'session', ?2, ?3, 'input.accepted', ?4, ?5, ?6, ?7, \
                       'private', ?8)",
            params![
                commit.event_id.to_string(),
                commit.session_id.to_string(),
                journal_sequence,
                event_version,
                accepted_at_ms,
                commit.ownership.principal_id().to_string(),
                commit.correlation_id.to_string(),
                json!({
                    "inbox_entry_id": commit.inbox_entry_id,
                    "inbox_sequence": inbox_sequence,
                    "delivery_mode": commit.delivery_mode,
                    "provider_selection_source": commit.provider_selection.source(),
                    "images": commit.images.iter().map(|image| json!({
                        "artifact_id": image.artifact_id,
                        "algorithm": image.blob.algorithm,
                        "digest": image.blob.digest,
                        "size_bytes": image.blob.size_bytes,
                        "media_type": image.media_type,
                        "width": image.width,
                        "height": image.height,
                    })).collect::<Vec<_>>(),
                })
                .to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "UPDATE aggregate_sequence SET sequence = ?1 \
             WHERE aggregate_kind = 'session' AND aggregate_id = ?2",
            params![journal_sequence, commit.session_id.to_string()],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn append_acknowledgement(
    transaction: &Transaction<'_>,
    commit: &InputAdmissionCommit,
    inbox_sequence: u64,
    accepted_at_ms: i64,
) -> Result<(), SessionStoreError> {
    transaction
        .execute(
            "INSERT INTO outbox(outbox_id, topic, payload_json, created_at_ms) \
             VALUES (?1, 'session.input_acknowledgement', ?2, ?3)",
            params![
                commit.outbox_id.to_string(),
                json!({
                    "session_id": commit.session_id,
                    "inbox_entry_id": commit.inbox_entry_id,
                    "inbox_sequence": inbox_sequence,
                    "event_id": commit.event_id,
                })
                .to_string(),
                accepted_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

impl StoredAdmission {
    fn into_receipt(
        self,
        session_id: SessionId,
    ) -> Result<InputAdmissionReceipt, SessionStoreError> {
        Ok(InputAdmissionReceipt {
            session_id,
            inbox_entry_id: parse_id(&self.inbox_entry_id, "inbox entry ID")?,
            image_artifact_ids: self
                .images
                .into_iter()
                .map(|image| parse_id(&image.artifact_id, "input image artifact ID"))
                .collect::<Result<Vec<_>, _>>()?,
            inbox_sequence: positive_u64(self.inbox_sequence, "inbox sequence")?,
            delivery_mode: parse_delivery_mode(&self.delivery_mode)?,
            provider_selection: selection_from_pair(
                self.selected_provider_id,
                self.selected_model_id,
            )?,
            provider_selection_source: self.provider_selection_source,
            event_id: parse_id(&self.event_id, "event ID")?,
            outbox_id: parse_id(&self.outbox_id, "outbox ID")?,
            correlation_id: parse_id(&self.correlation_id, "correlation ID")?,
            accepted_at: system_time_from_epoch_milliseconds(self.accepted_at_ms)?,
            timeline_cursor: positive_u64(self.timeline_cursor, "admission timeline cursor")?,
        })
    }
}

fn load_admission(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    dedupe_key: &str,
) -> Result<Option<StoredAdmission>, SessionStoreError> {
    let mut admission = transaction
        .query_row(
            "SELECT i.inbox_entry_id, i.sequence, i.delivery_mode, i.content, \
                    i.provider_selection_source, i.selected_provider_id, i.selected_model_id, \
                    i.admission_event_id, i.acknowledgement_outbox_id, i.correlation_id, \
                    i.accepted_at_ms, te.cursor \
             FROM session_inbox i \
             JOIN timeline_event te ON te.event_id = i.admission_event_id \
             WHERE i.session_id = ?1 AND i.dedupe_key = ?2",
            params![session_id.to_string(), dedupe_key],
            |row| {
                Ok(StoredAdmission {
                    inbox_entry_id: row.get(0)?,
                    inbox_sequence: row.get(1)?,
                    delivery_mode: row.get(2)?,
                    content: row.get(3)?,
                    provider_selection_source: row.get(4)?,
                    selected_provider_id: row.get(5)?,
                    selected_model_id: row.get(6)?,
                    event_id: row.get(7)?,
                    outbox_id: row.get(8)?,
                    correlation_id: row.get(9)?,
                    accepted_at_ms: row.get(10)?,
                    timeline_cursor: row.get(11)?,
                    images: Vec::new(),
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?;
    if let Some(stored) = &mut admission {
        stored.images = load_admission_images(transaction, &stored.inbox_entry_id)?;
    }
    Ok(admission)
}

fn load_admission_images(
    transaction: &Transaction<'_>,
    inbox_entry_id: &str,
) -> Result<Vec<StoredAdmissionImage>, SessionStoreError> {
    let mut statement = transaction
        .prepare(
            "SELECT media.artifact_id, image.blob_algorithm, image.blob_digest, \
                    blob.size_bytes, blob.relative_path, media.media_type, media.width, \
                    media.height \
             FROM session_inbox_media media \
             JOIN artifact image ON image.id = media.artifact_id \
             JOIN artifact_blob blob \
               ON blob.algorithm = image.blob_algorithm AND blob.digest = image.blob_digest \
             WHERE media.inbox_entry_id = ?1 \
             ORDER BY media.ordinal",
        )
        .map_err(map_sqlite_error)?;
    statement
        .query_map([inbox_entry_id], |row| {
            Ok(StoredAdmissionImage {
                artifact_id: row.get(0)?,
                algorithm: row.get(1)?,
                digest: row.get(2)?,
                size_bytes: row.get(3)?,
                relative_path: row.get(4)?,
                media_type: row.get(5)?,
                width: row.get(6)?,
                height: row.get(7)?,
            })
        })
        .map_err(map_sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_sqlite_error)
}

fn admission_cursor(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<u64, SessionStoreError> {
    let cursor = transaction
        .query_row(
            "SELECT cursor FROM timeline_event WHERE event_id = ?1",
            [event_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("accepted input is missing its timeline cursor"))?;
    positive_u64(cursor, "admission timeline cursor")
}

fn next_journal_sequence(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<i64, SessionStoreError> {
    let current = transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence \
             WHERE aggregate_kind = 'session' AND aggregate_id = ?1",
            [session_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("session aggregate sequence is missing"))?;
    current
        .checked_add(1)
        .ok_or_else(|| invariant("session journal sequence overflow"))
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, SessionStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("application clock returned a time before the Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| invariant("application clock exceeds the SQLite timestamp range"))
}

fn system_time_from_epoch_milliseconds(value: i64) -> Result<SystemTime, SessionStoreError> {
    let milliseconds = u64::try_from(value)
        .map_err(|_| invariant("stored acceptance time precedes the Unix epoch"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(milliseconds))
        .ok_or_else(|| invariant("stored acceptance time exceeds SystemTime"))
}

fn positive_u64(value: i64, field: &str) -> Result<u64, SessionStoreError> {
    let value =
        u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))?;
    if value == 0 {
        return Err(invariant(format!("stored {field} is zero")));
    }
    Ok(value)
}

fn parse_id<T>(value: &str, field: &str) -> Result<T, SessionStoreError>
where
    T: FromStr,
    T::Err: Display,
{
    value
        .parse()
        .map_err(|error| invariant(format!("stored {field} is invalid: {error}")))
}

fn parse_delivery_mode(value: &str) -> Result<DeliveryMode, SessionStoreError> {
    match value {
        "queue" => Ok(DeliveryMode::Queue),
        "steer_at_boundary" => Ok(DeliveryMode::SteerAtBoundary),
        "interrupt_then_queue" => Ok(DeliveryMode::InterruptThenQueue),
        _ => Err(invariant(format!(
            "stored delivery mode {value:?} is invalid"
        ))),
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> SessionStoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            SessionStoreError::Conflict
        }
        other => SessionStoreError::Unavailable(other.to_string()),
    }
}

fn invariant(message: impl Into<String>) -> SessionStoreError {
    SessionStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use mealy_application::{
        ArtifactEvidenceStore, ArtifactEvidenceStoreError, CommittedArtifactBlob,
        InputAdmissionCommit, InputAdmissionOutcome, InputImageArtifactCommit, OwnershipContext,
        ProviderSelectionPreference, SessionCreationCommit, SessionStore, SessionStoreError,
        sha256_digest,
    };
    use mealy_domain::{
        ArtifactId, ChannelBindingId, CorrelationId, DeliveryMode, EventId, InboxEntryId, OutboxId,
        PrincipalId, SessionId,
    };
    use rusqlite::params;
    use serde_json::Value;
    use std::time::{Duration, SystemTime};

    const NOW_MS: i64 = 1_782_062_400_000;

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(NOW_MS as u64)
    }

    fn owner() -> OwnershipContext {
        OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new())
    }

    fn create_commit(session_id: SessionId, ownership: OwnershipContext) -> SessionCreationCommit {
        SessionCreationCommit {
            session_id,
            ownership,
            provider_selection: None,
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            created_at: now(),
        }
    }

    fn admission_commit(
        session_id: SessionId,
        ownership: OwnershipContext,
        dedupe_key: &str,
        content: &str,
    ) -> InputAdmissionCommit {
        InputAdmissionCommit {
            session_id,
            ownership,
            inbox_entry_id: InboxEntryId::new(),
            delivery_mode: DeliveryMode::Queue,
            dedupe_key: dedupe_key.to_owned(),
            content: content.to_owned(),
            images: Vec::new(),
            provider_selection: ProviderSelectionPreference::InheritSession,
            maximum_pending_inputs: 1_024,
            event_id: EventId::new(),
            outbox_id: OutboxId::new(),
            correlation_id: CorrelationId::new(),
            accepted_at: now(),
        }
    }

    fn image_commit(
        artifact_id: ArtifactId,
        content: &[u8],
        media_type: &str,
        width: u32,
        height: u32,
    ) -> InputImageArtifactCommit {
        InputImageArtifactCommit {
            artifact_id,
            blob: CommittedArtifactBlob::new_sha256(
                sha256_digest(content),
                u64::try_from(content.len()).expect("image size fits u64"),
            )
            .expect("valid committed image descriptor"),
            committed_at: now(),
            media_type: media_type.to_owned(),
            width,
            height,
        }
    }

    #[test]
    fn input_admission_is_atomic_monotonic_and_idempotent() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");

        let first_commit = admission_commit(session_id, ownership, "delivery-1", "hello");
        let accepted = store
            .admit_input(first_commit.clone())
            .expect("accept first input");
        assert!(matches!(accepted, InputAdmissionOutcome::Accepted(_)));
        assert_eq!(accepted.receipt().inbox_sequence, 1);

        let duplicate = store
            .admit_input(first_commit)
            .expect("return original duplicate receipt");
        assert!(duplicate.is_duplicate());
        assert_eq!(duplicate.receipt(), accepted.receipt());

        let second = store
            .admit_input(admission_commit(
                session_id,
                ownership,
                "delivery-2",
                "world",
            ))
            .expect("accept second input");
        assert_eq!(second.receipt().inbox_sequence, 2);
        assert_eq!(store.journal_count().expect("journal count"), 3);
        assert_eq!(store.outbox_count().expect("outbox count"), 2);
    }

    #[test]
    fn changed_input_with_same_key_is_rejected_without_writes() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        store
            .admit_input(admission_commit(
                session_id,
                ownership,
                "delivery-1",
                "original",
            ))
            .expect("accept original input");

        let error = store
            .admit_input(admission_commit(
                session_id,
                ownership,
                "delivery-1",
                "changed",
            ))
            .expect_err("same key cannot bind changed content");
        assert_eq!(error, SessionStoreError::IdempotencyConflict);
        assert_eq!(store.journal_count().expect("journal count"), 2);
        assert_eq!(store.outbox_count().expect("outbox count"), 1);
    }

    #[test]
    fn pending_queue_limit_rejects_new_work_but_preserves_exact_idempotency() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        let mut first = admission_commit(session_id, ownership, "delivery-1", "first");
        first.maximum_pending_inputs = 1;
        let receipt = store
            .admit_input(first.clone())
            .expect("first input fits queue");
        assert!(!receipt.is_duplicate());

        let duplicate = store
            .admit_input(first)
            .expect("exact duplicate remains idempotent at capacity");
        assert!(duplicate.is_duplicate());
        assert_eq!(duplicate.receipt(), receipt.receipt());

        let mut second = admission_commit(session_id, ownership, "delivery-2", "second");
        second.maximum_pending_inputs = 1;
        assert_eq!(
            store.admit_input(second),
            Err(SessionStoreError::Backpressure)
        );
        assert_eq!(store.journal_count().expect("journal count"), 2);
        assert_eq!(store.outbox_count().expect("outbox count"), 1);
    }

    #[test]
    fn principal_and_channel_binding_must_both_match() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        let wrong_binding =
            OwnershipContext::new(ownership.principal_id(), ChannelBindingId::new());

        let error = store
            .admit_input(admission_commit(
                session_id,
                wrong_binding,
                "delivery-1",
                "forged",
            ))
            .expect_err("wrong channel binding must not access session");
        assert_eq!(error, SessionStoreError::Unauthorized);
        assert_eq!(store.journal_count().expect("journal count"), 1);
        assert_eq!(store.outbox_count().expect("outbox count"), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn image_admission_is_ordered_owner_private_idempotent_and_immutable() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        let first = image_commit(ArtifactId::new(), b"first image", "image/png", 32, 24);
        let second = image_commit(ArtifactId::new(), b"second image", "image/jpeg", 64, 48);
        let mut commit =
            admission_commit(session_id, ownership, "delivery-images", "compare these");
        commit.images = vec![first.clone(), second.clone()];

        let accepted = store
            .admit_input(commit.clone())
            .expect("accept image input");
        assert_eq!(
            accepted.receipt().image_artifact_ids,
            vec![first.artifact_id, second.artifact_id]
        );
        let duplicate = store
            .admit_input(commit.clone())
            .expect("return exact image duplicate");
        assert!(duplicate.is_duplicate());
        assert_eq!(duplicate.receipt(), accepted.receipt());

        let stored_images = store
            .connection
            .prepare(
                "SELECT artifact_id, media_type, width, height \
                 FROM session_inbox_media WHERE inbox_entry_id = ?1 ORDER BY ordinal",
            )
            .and_then(|mut statement| {
                statement
                    .query_map([commit.inbox_entry_id.to_string()], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .expect("load ordered image links");
        assert_eq!(
            stored_images,
            vec![
                (
                    first.artifact_id.to_string(),
                    "image/png".to_owned(),
                    32,
                    24
                ),
                (
                    second.artifact_id.to_string(),
                    "image/jpeg".to_owned(),
                    64,
                    48
                ),
            ]
        );

        let metadata = store
            .artifact_metadata(ownership, first.artifact_id)
            .expect("owner-authorized image metadata");
        assert_eq!(metadata.digest, first.blob.digest);
        assert_eq!(metadata.origin_kind, "session_input");
        assert_eq!(metadata.origin_id, commit.inbox_entry_id.to_string());
        assert_eq!(metadata.producer_id, "mealyd.media-normalizer.v1");
        assert_eq!(metadata.sensitivity, "private");
        assert_eq!(metadata.retention_class, "session_history");
        let reference_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM artifact_reference \
                 WHERE artifact_id = ?1 AND owner_kind = 'session_inbox' \
                   AND owner_id = ?2 AND relation = 'input_image'",
                params![
                    first.artifact_id.to_string(),
                    commit.inbox_entry_id.to_string()
                ],
                |row| row.get(0),
            )
            .expect("load trigger-created input reference");
        assert_eq!(reference_count, 1);
        let wrong_channel =
            OwnershipContext::new(ownership.principal_id(), ChannelBindingId::new());
        assert_eq!(
            store.artifact_metadata(wrong_channel, first.artifact_id),
            Err(ArtifactEvidenceStoreError::NotFound)
        );

        let (event_version, payload): (i64, String) = store
            .connection
            .query_row(
                "SELECT event_version, payload_json FROM journal_event WHERE event_id = ?1",
                [commit.event_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("load image admission journal fact");
        assert_eq!(event_version, 2);
        let payload: Value = serde_json::from_str(&payload).expect("valid journal payload");
        let journal_images = payload["images"]
            .as_array()
            .expect("journal image evidence");
        assert_eq!(journal_images.len(), 2);
        assert_eq!(
            journal_images[0]["artifact_id"],
            first.artifact_id.to_string()
        );
        assert!(journal_images[0].get("relative_path").is_none());

        assert!(
            store
                .connection
                .execute(
                    "UPDATE session_inbox_media SET width = width + 1 WHERE artifact_id = ?1",
                    [first.artifact_id.to_string()],
                )
                .is_err(),
            "ordered input evidence must reject mutation"
        );
        assert!(
            store
                .connection
                .execute(
                    "UPDATE artifact SET media_type = 'image/jpeg' WHERE id = ?1",
                    [first.artifact_id.to_string()],
                )
                .is_err(),
            "logical input artifact must reject mutation"
        );
        assert!(
            store
                .connection
                .execute(
                    "UPDATE artifact_blob SET size_bytes = size_bytes + 1 \
                     WHERE algorithm = ?1 AND digest = ?2",
                    params![first.blob.algorithm, first.blob.digest],
                )
                .is_err(),
            "input blob content metadata must reject mutation"
        );
        store
            .connection
            .execute(
                "UPDATE artifact_blob SET committed_at_ms = committed_at_ms + 1 \
                 WHERE algorithm = ?1 AND digest = ?2",
                params![first.blob.algorithm, first.blob.digest],
            )
            .expect("shared blob observation time remains independent of content identity");
        assert!(
            store
                .connection
                .execute(
                    "INSERT INTO artifact_reference(\
                        artifact_id, principal_id, session_id, owner_kind, owner_id, relation, \
                        created_at_ms\
                     ) VALUES (?1, ?2, ?3, 'session_inbox', ?4, 'input_image', ?5)",
                    params![
                        first.artifact_id.to_string(),
                        ownership.principal_id().to_string(),
                        session_id.to_string(),
                        InboxEntryId::new().to_string(),
                        NOW_MS,
                    ],
                )
                .is_err(),
            "an input reference cannot exist without its canonical media link"
        );
        assert!(
            store
                .connection
                .execute(
                    "DELETE FROM artifact_reference WHERE artifact_id = ?1",
                    [first.artifact_id.to_string()],
                )
                .is_err(),
            "input artifact reference must reject deletion"
        );
    }

    #[test]
    fn image_idempotency_binds_order_identity_content_and_dimensions() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        let first = image_commit(ArtifactId::new(), b"first image", "image/png", 32, 24);
        let second = image_commit(ArtifactId::new(), b"second image", "image/jpeg", 64, 48);
        let mut original =
            admission_commit(session_id, ownership, "delivery-images", "compare these");
        original.images = vec![first.clone(), second.clone()];
        store
            .admit_input(original.clone())
            .expect("accept original image input");

        let mut reordered = original.clone();
        reordered.images.swap(0, 1);
        let mut changed_identity = original.clone();
        changed_identity.images[0].artifact_id = ArtifactId::new();
        let mut changed_content = original.clone();
        changed_content.images[0] =
            image_commit(first.artifact_id, b"different image", "image/png", 32, 24);
        let mut changed_dimensions = original.clone();
        changed_dimensions.images[0].width += 1;

        for changed in [
            reordered,
            changed_identity,
            changed_content,
            changed_dimensions,
        ] {
            assert_eq!(
                store.admit_input(changed),
                Err(SessionStoreError::IdempotencyConflict)
            );
        }
        assert_eq!(store.journal_count().expect("journal count"), 2);
        assert_eq!(store.outbox_count().expect("outbox count"), 1);
    }

    #[test]
    fn late_outbox_failure_rolls_back_inbox_image_links_session_and_journal() {
        let mut store = SqliteStore::open_in_memory(NOW_MS).expect("open store");
        let session_id = SessionId::new();
        let ownership = owner();
        store
            .create_session(create_commit(session_id, ownership))
            .expect("create session");
        let first = admission_commit(session_id, ownership, "delivery-1", "first");
        store
            .admit_input(first.clone())
            .expect("accept first input");

        let mut colliding = admission_commit(session_id, ownership, "delivery-2", "second");
        colliding.outbox_id = first.outbox_id;
        let image = image_commit(
            ArtifactId::new(),
            b"transactional image",
            "image/png",
            32,
            24,
        );
        colliding.images.push(image);
        let error = store
            .admit_input(colliding)
            .expect_err("duplicate outbox ID must abort the full transaction");
        assert_eq!(error, SessionStoreError::Conflict);

        let counts: (i64, i64, i64, i64, i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT \
                    (SELECT COUNT(*) FROM session_inbox), \
                    (SELECT COUNT(*) FROM journal_event), \
                    (SELECT COUNT(*) FROM outbox), \
                    (SELECT next_inbox_sequence FROM session WHERE id = ?1), \
                    (SELECT COUNT(*) FROM session_inbox_media), \
                    (SELECT COUNT(*) FROM artifact), \
                    (SELECT COUNT(*) FROM artifact_blob), \
                    (SELECT COUNT(*) FROM artifact_reference)",
                [session_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .expect("read canonical counts");
        assert_eq!(counts, (1, 2, 1, 2, 0, 0, 0, 0));
    }
}
