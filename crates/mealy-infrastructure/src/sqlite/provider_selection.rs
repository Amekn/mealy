use super::SqliteStore;
use mealy_application::{
    OwnershipContext, ProviderSelection, ProviderSelectionStore, ProviderSelectionStoreError,
    SessionProviderSelectionView, UpdateSessionProviderSelectionCommit,
};
use mealy_domain::SessionId;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{str::FromStr, time::SystemTime};

impl ProviderSelectionStore for SqliteStore {
    fn session_provider_selection(
        &self,
        session_id: SessionId,
        ownership: OwnershipContext,
    ) -> Result<SessionProviderSelectionView, ProviderSelectionStoreError> {
        load_view(&self.connection, session_id, ownership)
    }

    fn update_session_provider_selection(
        &mut self,
        commit: UpdateSessionProviderSelectionCommit,
    ) -> Result<SessionProviderSelectionView, ProviderSelectionStoreError> {
        if commit
            .selection
            .as_ref()
            .is_some_and(|selection| !selection.is_valid())
        {
            return Err(invariant(
                "application supplied an invalid provider selection",
            ));
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
            return Err(ProviderSelectionStoreError::Conflict);
        }
        let revision = session
            .revision
            .checked_add(1)
            .ok_or_else(|| invariant("session revision overflow"))?;
        let journal_sequence = next_journal_sequence(&transaction, commit.session_id)?;
        insert_event(
            &transaction,
            &commit,
            journal_sequence,
            revision,
            updated_at_ms,
        )?;
        let (provider_id, model_id) = commit.selection.as_ref().map_or((None, None), |selection| {
            (
                Some(selection.provider_id.as_str()),
                Some(selection.model_id.as_str()),
            )
        });
        transaction
            .execute(
                "INSERT INTO session_provider_selection(\
                    session_id, provider_id, model_id, selection_event_id, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(session_id) DO UPDATE SET \
                    provider_id = excluded.provider_id, model_id = excluded.model_id, \
                    selection_event_id = excluded.selection_event_id, \
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    commit.session_id.to_string(),
                    provider_id,
                    model_id,
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
            return Err(ProviderSelectionStoreError::Conflict);
        }
        set_journal_sequence(&transaction, commit.session_id, journal_sequence)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(SessionProviderSelectionView {
            session_id: commit.session_id,
            selection: commit.selection,
            revision: nonnegative_u64(revision, "session revision")?,
            event_id: Some(commit.event_id),
            updated_at: system_time(updated_at_ms)?,
        })
    }
}

struct StoredSession {
    principal_id: String,
    channel_binding_id: String,
    revision: i64,
}

fn load_view(
    connection: &rusqlite::Connection,
    session_id: SessionId,
    ownership: OwnershipContext,
) -> Result<SessionProviderSelectionView, ProviderSelectionStoreError> {
    let row = connection
        .query_row(
            "SELECT session.principal_id, session.channel_binding_id, session.revision, \
                    selection.provider_id, selection.model_id, selection.selection_event_id, \
                    COALESCE(selection.updated_at_ms, session.created_at_ms) \
             FROM session \
             LEFT JOIN session_provider_selection selection ON selection.session_id = session.id \
             WHERE session.id = ?1",
            [session_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(ProviderSelectionStoreError::SessionNotFound)?;
    let session = StoredSession {
        principal_id: row.0,
        channel_binding_id: row.1,
        revision: row.2,
    };
    authorize(&session, ownership)?;
    let selection = selection_from_pair(row.3, row.4)?;
    Ok(SessionProviderSelectionView {
        session_id,
        selection,
        revision: nonnegative_u64(session.revision, "session revision")?,
        event_id: row
            .5
            .as_deref()
            .map(|value| parse_id(value, "provider selection event ID"))
            .transpose()?,
        updated_at: system_time(row.6)?,
    })
}

fn load_session(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<StoredSession, ProviderSelectionStoreError> {
    transaction
        .query_row(
            "SELECT principal_id, channel_binding_id, revision FROM session WHERE id = ?1",
            [session_id.to_string()],
            |row| {
                Ok(StoredSession {
                    principal_id: row.get(0)?,
                    channel_binding_id: row.get(1)?,
                    revision: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(ProviderSelectionStoreError::SessionNotFound)
}

fn selection_from_pair(
    provider_id: Option<String>,
    model_id: Option<String>,
) -> Result<Option<ProviderSelection>, ProviderSelectionStoreError> {
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

fn require_active_identity(
    transaction: &Transaction<'_>,
    ownership: OwnershipContext,
) -> Result<(), ProviderSelectionStoreError> {
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
        Err(ProviderSelectionStoreError::Unauthorized)
    }
}

fn authorize(
    session: &StoredSession,
    ownership: OwnershipContext,
) -> Result<(), ProviderSelectionStoreError> {
    if session.principal_id == ownership.principal_id().to_string()
        && session.channel_binding_id == ownership.channel_binding_id().to_string()
    {
        Ok(())
    } else {
        Err(ProviderSelectionStoreError::Unauthorized)
    }
}

fn next_journal_sequence(
    transaction: &Transaction<'_>,
    session_id: SessionId,
) -> Result<i64, ProviderSelectionStoreError> {
    transaction
        .query_row(
            "SELECT sequence + 1 FROM aggregate_sequence \
             WHERE aggregate_kind = 'session' AND aggregate_id = ?1",
            [session_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("session aggregate sequence is missing"))
}

fn insert_event(
    transaction: &Transaction<'_>,
    commit: &UpdateSessionProviderSelectionCommit,
    sequence: i64,
    revision: i64,
    updated_at_ms: i64,
) -> Result<(), ProviderSelectionStoreError> {
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, 'session', ?2, ?3, 'session.provider_selection_updated', 1, ?4, ?5, \
                       ?6, 'private', ?7)",
            params![
                commit.event_id.to_string(),
                commit.session_id.to_string(),
                sequence,
                updated_at_ms,
                commit.ownership.principal_id().to_string(),
                commit.correlation_id.to_string(),
                json!({
                    "mode": if commit.selection.is_some() { "exact" } else { "automatic" },
                    "provider_id": commit.selection.as_ref().map(|value| &value.provider_id),
                    "model_id": commit.selection.as_ref().map(|value| &value.model_id),
                    "previous_revision": commit.expected_revision,
                    "revision": revision,
                    "applies_to": "future_new_turns",
                })
                .to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(())
}

fn set_journal_sequence(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    sequence: i64,
) -> Result<(), ProviderSelectionStoreError> {
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

fn epoch_milliseconds(time: SystemTime) -> Result<i64, ProviderSelectionStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("transaction timestamp predates Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| invariant("transaction timestamp exceeds SQLite"))
}

fn system_time(value: i64) -> Result<SystemTime, ProviderSelectionStoreError> {
    let value = u64::try_from(value).map_err(|_| invariant("stored timestamp is negative"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(value))
        .ok_or_else(|| invariant("stored timestamp exceeds SystemTime"))
}

fn to_i64(value: u64, field: &str) -> Result<i64, ProviderSelectionStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite")))
}

fn nonnegative_u64(value: i64, field: &str) -> Result<u64, ProviderSelectionStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, ProviderSelectionStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("{field} is invalid")))
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> ProviderSelectionStoreError {
    ProviderSelectionStoreError::Unavailable(error.to_string())
}

fn invariant(message: impl Into<String>) -> ProviderSelectionStoreError {
    ProviderSelectionStoreError::InvariantViolation(message.into())
}
