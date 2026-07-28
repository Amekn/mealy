use super::{SqliteStore, timeline};
use mealy_application::{
    CreateSessionCheckpointCommit, OwnershipContext, SessionCheckpointView, SessionTitleReceipt,
    SessionWorkbenchStore, SessionWorkbenchStoreError, UpdateSessionTitleCommit, is_sha256_digest,
    sha256_digest, valid_session_metadata,
};
use mealy_domain::{ContextEpochId, CorrelationId, EventId, SessionId, TurnId};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{str::FromStr, time::SystemTime};

impl SessionWorkbenchStore for SqliteStore {
    fn update_session_title(
        &mut self,
        commit: UpdateSessionTitleCommit,
    ) -> Result<SessionTitleReceipt, SessionWorkbenchStoreError> {
        if !valid_session_metadata(&commit.title) {
            return Err(invariant("application supplied invalid session title"));
        }
        let updated_at_ms = epoch_milliseconds(commit.updated_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        require_active_identity(&transaction, commit.ownership)?;
        let session = load_session(&transaction, commit.session_id)?;
        authorize(&session, commit.ownership)?;
        let expected_revision = to_i64(commit.expected_revision, "expected session revision")?;
        if session.revision != expected_revision {
            return Err(SessionWorkbenchStoreError::Conflict);
        }
        let revision = session
            .revision
            .checked_add(1)
            .ok_or_else(|| invariant("session revision overflow"))?;
        let journal_sequence = next_journal_sequence(&transaction, commit.session_id)?;

        let payload = json!({
            "title": commit.title,
            "previous_revision": commit.expected_revision,
            "revision": revision,
        });
        insert_session_event(
            &transaction,
            commit.session_id,
            journal_sequence,
            &commit.event_id,
            "session.title_updated",
            &commit.correlation_id,
            commit.ownership,
            updated_at_ms,
            &payload,
        )?;
        transaction
            .execute(
                "INSERT INTO session_metadata(\
                    session_id, owner_title, owner_title_event_id, owner_title_updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(session_id) DO UPDATE SET \
                    owner_title = excluded.owner_title, \
                    owner_title_event_id = excluded.owner_title_event_id, \
                    owner_title_updated_at_ms = excluded.owner_title_updated_at_ms",
                params![
                    commit.session_id.to_string(),
                    commit.title,
                    commit.event_id.to_string(),
                    updated_at_ms,
                ],
            )
            .map_err(map_sqlite_error)?;
        let changed = transaction
            .execute(
                "UPDATE session SET revision = ?1, updated_at_ms = MAX(updated_at_ms, ?2) \
                 WHERE id = ?3 AND principal_id = ?4 AND channel_binding_id = ?5 \
                   AND revision = ?6",
                params![
                    revision,
                    updated_at_ms,
                    commit.session_id.to_string(),
                    commit.ownership.principal_id().to_string(),
                    commit.ownership.channel_binding_id().to_string(),
                    expected_revision,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(SessionWorkbenchStoreError::Conflict);
        }
        set_journal_sequence(&transaction, commit.session_id, journal_sequence)?;
        let stored_updated_at = transaction
            .query_row(
                "SELECT updated_at_ms FROM session WHERE id = ?1",
                [commit.session_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(map_sqlite_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(SessionTitleReceipt {
            session_id: commit.session_id,
            title: commit.title,
            revision: nonnegative_u64(revision, "session revision")?,
            event_id: commit.event_id,
            updated_at: system_time(stored_updated_at)?,
        })
    }

    fn create_session_checkpoint(
        &mut self,
        commit: CreateSessionCheckpointCommit,
    ) -> Result<SessionCheckpointView, SessionWorkbenchStoreError> {
        if commit
            .label
            .as_deref()
            .is_some_and(|label| !valid_session_metadata(label))
        {
            return Err(invariant("application supplied invalid checkpoint label"));
        }
        let created_at_ms = epoch_milliseconds(commit.created_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        require_active_identity(&transaction, commit.ownership)?;
        let session = load_session(&transaction, commit.session_id)?;
        authorize(&session, commit.ownership)?;
        let checkpoint = prepare_checkpoint(&transaction, &commit, &session, created_at_ms)?;
        persist_checkpoint(&transaction, &commit, &checkpoint)?;
        let view = checkpoint_view(
            &commit,
            checkpoint.boundary,
            checkpoint.source_cursor,
            checkpoint.workspace_authority_digest,
            nonnegative_u64(checkpoint.revision, "session revision")?,
            system_time(created_at_ms)?,
        );
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(view)
    }

    fn session_checkpoints(
        &self,
        session_id: SessionId,
        ownership: OwnershipContext,
        limit: usize,
    ) -> Result<Vec<SessionCheckpointView>, SessionWorkbenchStoreError> {
        let session = load_session_connection(&self.connection, session_id)?;
        authorize(&session, ownership)?;
        let limit =
            i64::try_from(limit).map_err(|_| invariant("checkpoint list limit exceeds SQLite"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT checkpoint.id, checkpoint.source_cursor, checkpoint.source_turn_id, \
                        checkpoint.context_epoch_id, checkpoint.source_session_revision, \
                        checkpoint.config_digest, checkpoint.policy_digest, \
                        checkpoint.workspace_identity, checkpoint.workspace_authority_digest, \
                        checkpoint.provider_id, checkpoint.model_id, checkpoint.label, \
                        checkpoint.created_event_id, checkpoint.created_at_ms, \
                        checkpoint.created_session_revision \
                 FROM session_checkpoint checkpoint \
                 JOIN session ON session.id = checkpoint.session_id \
                 WHERE checkpoint.session_id = ?1 AND session.principal_id = ?2 \
                   AND session.channel_binding_id = ?3 \
                 ORDER BY checkpoint.created_at_ms DESC, checkpoint.id DESC LIMIT ?4",
            )
            .map_err(map_sqlite_error)?;
        statement
            .query_map(
                params![
                    session_id.to_string(),
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                    limit,
                ],
                |row| {
                    Ok(StoredCheckpoint {
                        checkpoint_id: row.get(0)?,
                        source_cursor: row.get(1)?,
                        source_turn_id: row.get(2)?,
                        context_epoch_id: row.get(3)?,
                        source_session_revision: row.get(4)?,
                        config_digest: row.get(5)?,
                        policy_digest: row.get(6)?,
                        workspace_identity: row.get(7)?,
                        workspace_authority_digest: row.get(8)?,
                        provider_id: row.get(9)?,
                        model_id: row.get(10)?,
                        label: row.get(11)?,
                        event_id: row.get(12)?,
                        created_at_ms: row.get(13)?,
                        revision: row.get(14)?,
                    })
                },
            )
            .map_err(map_sqlite_error)?
            .map(|row| row.map_err(map_sqlite_error)?.into_view(session_id))
            .collect()
    }
}

#[derive(Clone)]
struct StoredSession {
    principal_id: String,
    channel_binding_id: String,
    revision: i64,
    active_turn_id: Option<String>,
    current_context_epoch_id: Option<String>,
}

struct CheckpointBoundary {
    source_turn_id: Option<TurnId>,
    context_epoch_id: Option<ContextEpochId>,
    config_digest: Option<String>,
    policy_digest: Option<String>,
    workspace_identity: Option<String>,
    provider_id: Option<String>,
    model_id: Option<String>,
}

struct PreparedCheckpoint {
    boundary: CheckpointBoundary,
    source_cursor: u64,
    workspace_authority_digest: String,
    expected_revision: i64,
    revision: i64,
    journal_sequence: i64,
    created_at_ms: i64,
}

struct StoredCheckpoint {
    checkpoint_id: String,
    source_cursor: i64,
    source_turn_id: Option<String>,
    context_epoch_id: Option<String>,
    source_session_revision: i64,
    config_digest: Option<String>,
    policy_digest: Option<String>,
    workspace_identity: Option<String>,
    workspace_authority_digest: String,
    provider_id: Option<String>,
    model_id: Option<String>,
    label: Option<String>,
    event_id: String,
    created_at_ms: i64,
    revision: i64,
}

impl StoredCheckpoint {
    fn into_view(
        self,
        session_id: SessionId,
    ) -> Result<SessionCheckpointView, SessionWorkbenchStoreError> {
        if !is_sha256_digest(&self.workspace_authority_digest)
            || self
                .config_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256_digest(digest))
            || self
                .policy_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256_digest(digest))
            || self
                .label
                .as_deref()
                .is_some_and(|label| !valid_session_metadata(label))
            || (self.provider_id.is_some() != self.model_id.is_some())
        {
            return Err(invariant("stored checkpoint evidence is malformed"));
        }
        Ok(SessionCheckpointView {
            checkpoint_id: parse_id(&self.checkpoint_id, "checkpoint ID")?,
            session_id,
            source_cursor: positive_u64(self.source_cursor, "checkpoint cursor")?,
            source_turn_id: self
                .source_turn_id
                .as_deref()
                .map(|value| parse_id(value, "checkpoint turn ID"))
                .transpose()?,
            context_epoch_id: self
                .context_epoch_id
                .as_deref()
                .map(|value| parse_id(value, "checkpoint context epoch ID"))
                .transpose()?,
            source_session_revision: nonnegative_u64(
                self.source_session_revision,
                "checkpoint source revision",
            )?,
            config_digest: self.config_digest,
            policy_digest: self.policy_digest,
            workspace_identity: self.workspace_identity,
            workspace_authority_digest: self.workspace_authority_digest,
            provider_id: self.provider_id,
            model_id: self.model_id,
            label: self.label,
            event_id: parse_id(&self.event_id, "checkpoint event ID")?,
            revision: nonnegative_u64(self.revision, "session revision")?,
            created_at: system_time(self.created_at_ms)?,
        })
    }
}

fn prepare_checkpoint(
    transaction: &Transaction<'_>,
    commit: &CreateSessionCheckpointCommit,
    session: &StoredSession,
    created_at_ms: i64,
) -> Result<PreparedCheckpoint, SessionWorkbenchStoreError> {
    let expected_revision = to_i64(commit.expected_revision, "expected session revision")?;
    if session.revision != expected_revision {
        return Err(SessionWorkbenchStoreError::Conflict);
    }
    if session.active_turn_id.is_some() || pending_input_count(transaction, commit.session_id)? != 0
    {
        return Err(SessionWorkbenchStoreError::NotQuiescent);
    }
    let boundary = load_checkpoint_boundary(transaction, session, commit.session_id)?;
    let source_cursor = timeline::high_watermark(transaction, commit.session_id)
        .map_err(|error| invariant(error.to_string()))?
        .0;
    if source_cursor == 0 {
        return Err(invariant("session has no creation timeline cursor"));
    }
    let workspace_authority_digest =
        authority_digest(commit.ownership, boundary.workspace_identity.as_deref());
    let revision = session
        .revision
        .checked_add(1)
        .ok_or_else(|| invariant("session revision overflow"))?;
    Ok(PreparedCheckpoint {
        boundary,
        source_cursor,
        workspace_authority_digest,
        expected_revision,
        revision,
        journal_sequence: next_journal_sequence(transaction, commit.session_id)?,
        created_at_ms,
    })
}

fn persist_checkpoint(
    transaction: &Transaction<'_>,
    commit: &CreateSessionCheckpointCommit,
    checkpoint: &PreparedCheckpoint,
) -> Result<(), SessionWorkbenchStoreError> {
    let payload = json!({
        "checkpoint_id": commit.checkpoint_id,
        "source_cursor": checkpoint.source_cursor,
        "source_turn_id": checkpoint.boundary.source_turn_id,
        "context_epoch_id": checkpoint.boundary.context_epoch_id,
        "source_session_revision": commit.expected_revision,
        "config_digest": checkpoint.boundary.config_digest,
        "policy_digest": checkpoint.boundary.policy_digest,
        "workspace_identity": checkpoint.boundary.workspace_identity,
        "workspace_authority_digest": checkpoint.workspace_authority_digest,
        "provider_id": checkpoint.boundary.provider_id,
        "model_id": checkpoint.boundary.model_id,
        "label": commit.label,
        "revision": checkpoint.revision,
    });
    insert_session_event(
        transaction,
        commit.session_id,
        checkpoint.journal_sequence,
        &commit.event_id,
        "session.checkpoint_created",
        &commit.correlation_id,
        commit.ownership,
        checkpoint.created_at_ms,
        &payload,
    )?;
    transaction
        .execute(
            "INSERT INTO session_checkpoint(\
                id, session_id, principal_id, source_cursor, source_turn_id, context_epoch_id, \
                source_session_revision, created_session_revision, config_digest, \
                policy_digest, workspace_identity, \
                workspace_authority_digest, provider_id, model_id, label, created_event_id, \
                correlation_id, created_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                       ?16, ?17, ?18)",
            params![
                commit.checkpoint_id.to_string(),
                commit.session_id.to_string(),
                commit.ownership.principal_id().to_string(),
                to_i64(checkpoint.source_cursor, "source cursor")?,
                checkpoint.boundary.source_turn_id.map(|id| id.to_string()),
                checkpoint
                    .boundary
                    .context_epoch_id
                    .map(|id| id.to_string()),
                checkpoint.expected_revision,
                checkpoint.revision,
                checkpoint.boundary.config_digest,
                checkpoint.boundary.policy_digest,
                checkpoint.boundary.workspace_identity,
                checkpoint.workspace_authority_digest,
                checkpoint.boundary.provider_id,
                checkpoint.boundary.model_id,
                commit.label,
                commit.event_id.to_string(),
                commit.correlation_id.to_string(),
                checkpoint.created_at_ms,
            ],
        )
        .map_err(map_sqlite_error)?;
    update_checkpoint_session_revision(transaction, commit, checkpoint)?;
    set_journal_sequence(transaction, commit.session_id, checkpoint.journal_sequence)
}

fn update_checkpoint_session_revision(
    transaction: &Transaction<'_>,
    commit: &CreateSessionCheckpointCommit,
    checkpoint: &PreparedCheckpoint,
) -> Result<(), SessionWorkbenchStoreError> {
    let changed = transaction
        .execute(
            "UPDATE session SET revision = ?1, updated_at_ms = MAX(updated_at_ms, ?2) \
             WHERE id = ?3 AND principal_id = ?4 AND channel_binding_id = ?5 AND revision = ?6",
            params![
                checkpoint.revision,
                checkpoint.created_at_ms,
                commit.session_id.to_string(),
                commit.ownership.principal_id().to_string(),
                commit.ownership.channel_binding_id().to_string(),
                checkpoint.expected_revision,
            ],
        )
        .map_err(map_sqlite_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(SessionWorkbenchStoreError::Conflict)
    }
}

fn checkpoint_view(
    commit: &CreateSessionCheckpointCommit,
    boundary: CheckpointBoundary,
    source_cursor: u64,
    workspace_authority_digest: String,
    revision: u64,
    created_at: SystemTime,
) -> SessionCheckpointView {
    SessionCheckpointView {
        checkpoint_id: commit.checkpoint_id,
        session_id: commit.session_id,
        source_cursor,
        source_turn_id: boundary.source_turn_id,
        context_epoch_id: boundary.context_epoch_id,
        source_session_revision: commit.expected_revision,
        config_digest: boundary.config_digest,
        policy_digest: boundary.policy_digest,
        workspace_identity: boundary.workspace_identity,
        workspace_authority_digest,
        provider_id: boundary.provider_id,
        model_id: boundary.model_id,
        label: commit.label.clone(),
        event_id: commit.event_id,
        revision,
        created_at,
    }
}

fn load_checkpoint_boundary(
    transaction: &Transaction<'_>,
    session: &StoredSession,
    session_id: SessionId,
) -> Result<CheckpointBoundary, SessionWorkbenchStoreError> {
    let last_turn = transaction
        .query_row(
            "SELECT turn.id, turn.status, turn.context_epoch_id, epoch.config_digest, \
                    epoch.policy_digest, epoch.workspace_identity, \
                    (SELECT attempt.provider_id FROM model_attempt attempt \
                     WHERE attempt.run_id = turn.run_id ORDER BY attempt.ordinal DESC LIMIT 1), \
                    (SELECT attempt.model_id FROM model_attempt attempt \
                     WHERE attempt.run_id = turn.run_id ORDER BY attempt.ordinal DESC LIMIT 1) \
             FROM turn LEFT JOIN context_epoch epoch ON epoch.id = turn.context_epoch_id \
             WHERE turn.session_id = ?1 AND turn.turn_kind = 'canonical' \
             ORDER BY turn.created_at_ms DESC, turn.id DESC LIMIT 1",
            [session_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?;
    if let Some((turn_id, status, epoch_id, config, policy, workspace, provider, model)) = last_turn
    {
        if status != "completed" {
            return Err(SessionWorkbenchStoreError::NotQuiescent);
        }
        validate_epoch_tuple(
            epoch_id.as_deref(),
            config.as_deref(),
            policy.as_deref(),
            workspace.as_deref(),
        )?;
        if provider.is_some() != model.is_some() {
            return Err(invariant("checkpoint provider/model binding is incomplete"));
        }
        return Ok(CheckpointBoundary {
            source_turn_id: Some(parse_id(&turn_id, "checkpoint turn ID")?),
            context_epoch_id: epoch_id
                .as_deref()
                .map(|value| parse_id(value, "checkpoint context epoch ID"))
                .transpose()?,
            config_digest: config,
            policy_digest: policy,
            workspace_identity: workspace,
            provider_id: provider,
            model_id: model,
        });
    }

    let Some(epoch_id) = session.current_context_epoch_id.as_deref() else {
        return Ok(CheckpointBoundary {
            source_turn_id: None,
            context_epoch_id: None,
            config_digest: None,
            policy_digest: None,
            workspace_identity: None,
            provider_id: None,
            model_id: None,
        });
    };
    let (config, policy, workspace) = transaction
        .query_row(
            "SELECT config_digest, policy_digest, workspace_identity \
             FROM context_epoch WHERE id = ?1 AND session_id = ?2",
            params![epoch_id, session_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("current context epoch is missing"))?;
    Ok(CheckpointBoundary {
        source_turn_id: None,
        context_epoch_id: Some(parse_id(epoch_id, "checkpoint context epoch ID")?),
        config_digest: Some(config),
        policy_digest: Some(policy),
        workspace_identity: Some(workspace),
        provider_id: None,
        model_id: None,
    })
}

fn validate_epoch_tuple(
    epoch_id: Option<&str>,
    config: Option<&str>,
    policy: Option<&str>,
    workspace: Option<&str>,
) -> Result<(), SessionWorkbenchStoreError> {
    let complete =
        epoch_id.is_some() && config.is_some() && policy.is_some() && workspace.is_some();
    let absent = epoch_id.is_none() && config.is_none() && policy.is_none() && workspace.is_none();
    if (!complete && !absent)
        || config.is_some_and(|value| !is_sha256_digest(value))
        || policy.is_some_and(|value| !is_sha256_digest(value))
    {
        Err(invariant("checkpoint context epoch binding is incomplete"))
    } else {
        Ok(())
    }
}

fn authority_digest(ownership: OwnershipContext, workspace_identity: Option<&str>) -> String {
    sha256_digest(
        json!({
            "channel_binding_id": ownership.channel_binding_id(),
            "principal_id": ownership.principal_id(),
            "workspace_identity": workspace_identity,
        })
        .to_string()
        .as_bytes(),
    )
}

fn require_active_identity(
    transaction: &Transaction<'_>,
    ownership: OwnershipContext,
) -> Result<(), SessionWorkbenchStoreError> {
    let active = transaction
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
            |row| row.get::<_, bool>(0),
        )
        .map_err(map_sqlite_error)?;
    if active {
        Ok(())
    } else {
        Err(SessionWorkbenchStoreError::Unauthorized)
    }
}

fn load_session(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<StoredSession, SessionWorkbenchStoreError> {
    load_session_connection(transaction, session_id)
}

fn load_session_connection(
    connection: &rusqlite::Connection,
    session_id: SessionId,
) -> Result<StoredSession, SessionWorkbenchStoreError> {
    connection
        .query_row(
            "SELECT principal_id, channel_binding_id, revision, active_turn_id, \
                    current_context_epoch_id FROM session WHERE id = ?1",
            [session_id.to_string()],
            |row| {
                Ok(StoredSession {
                    principal_id: row.get(0)?,
                    channel_binding_id: row.get(1)?,
                    revision: row.get(2)?,
                    active_turn_id: row.get(3)?,
                    current_context_epoch_id: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(SessionWorkbenchStoreError::SessionNotFound)
}

fn authorize(
    session: &StoredSession,
    ownership: OwnershipContext,
) -> Result<(), SessionWorkbenchStoreError> {
    if session.principal_id == ownership.principal_id().to_string()
        && session.channel_binding_id == ownership.channel_binding_id().to_string()
    {
        Ok(())
    } else {
        Err(SessionWorkbenchStoreError::Unauthorized)
    }
}

fn pending_input_count(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<i64, SessionWorkbenchStoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM session_inbox WHERE session_id = ?1 AND state = 'pending'",
            [session_id.to_string()],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)
}

fn next_journal_sequence(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<i64, SessionWorkbenchStoreError> {
    let sequence = transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence \
             WHERE aggregate_kind = 'session' AND aggregate_id = ?1",
            [session_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("session aggregate sequence is missing"))?;
    sequence
        .checked_add(1)
        .ok_or_else(|| invariant("session journal sequence overflow"))
}

#[allow(clippy::too_many_arguments)]
fn insert_session_event(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    sequence: i64,
    event_id: &EventId,
    event_type: &str,
    correlation_id: &CorrelationId,
    ownership: OwnershipContext,
    occurred_at_ms: i64,
    payload: &serde_json::Value,
) -> Result<(), SessionWorkbenchStoreError> {
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, 'session', ?2, ?3, ?4, 1, ?5, ?6, ?7, 'private', ?8)",
            params![
                event_id.to_string(),
                session_id.to_string(),
                sequence,
                event_type,
                occurred_at_ms,
                ownership.principal_id().to_string(),
                correlation_id.to_string(),
                payload.to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn set_journal_sequence(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    sequence: i64,
) -> Result<(), SessionWorkbenchStoreError> {
    let changed = transaction
        .execute(
            "UPDATE aggregate_sequence SET sequence = ?1 \
             WHERE aggregate_kind = 'session' AND aggregate_id = ?2",
            params![sequence, session_id.to_string()],
        )
        .map_err(map_sqlite_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(invariant("session aggregate sequence update was lost"))
    }
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, SessionWorkbenchStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("transaction timestamp predates Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| invariant("transaction timestamp exceeds SQLite"))
}

fn system_time(value: i64) -> Result<SystemTime, SessionWorkbenchStoreError> {
    let value = u64::try_from(value).map_err(|_| invariant("stored timestamp is negative"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(value))
        .ok_or_else(|| invariant("stored timestamp exceeds SystemTime"))
}

fn to_i64(value: u64, field: &str) -> Result<i64, SessionWorkbenchStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite")))
}

fn positive_u64(value: i64, field: &str) -> Result<u64, SessionWorkbenchStoreError> {
    let value = nonnegative_u64(value, field)?;
    if value == 0 {
        Err(invariant(format!("{field} is zero")))
    } else {
        Ok(value)
    }
}

fn nonnegative_u64(value: i64, field: &str) -> Result<u64, SessionWorkbenchStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, SessionWorkbenchStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("{field} is invalid")))
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> SessionWorkbenchStoreError {
    SessionWorkbenchStoreError::Unavailable(error.to_string())
}

fn invariant(message: impl Into<String>) -> SessionWorkbenchStoreError {
    SessionWorkbenchStoreError::InvariantViolation(message.into())
}
