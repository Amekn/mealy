use super::{SqliteStore, artifact, timeline};
use mealy_application::{
    ArtifactEvidenceStoreError, OwnershipContext, SESSION_TRANSCRIPT_MAXIMUM_CONTENT_BYTES,
    SESSION_TRANSCRIPT_MAXIMUM_TURNS, SessionTranscriptAssistantMessage, SessionTranscriptLineage,
    SessionTranscriptSnapshot, SessionTranscriptStore, SessionTranscriptStoreError,
    SessionTranscriptTurn, SessionTranscriptUserMessage, TimelineCursor, derive_session_title,
    is_sha256_digest, sha256_digest, valid_session_metadata,
};
use mealy_domain::{ArtifactId, SessionId};
use rusqlite::{OptionalExtension, params};
use std::{str::FromStr, time::SystemTime};

impl SessionTranscriptStore for SqliteStore {
    fn session_transcript_snapshot(
        &self,
        session_id: SessionId,
        ownership: OwnershipContext,
    ) -> Result<SessionTranscriptSnapshot, SessionTranscriptStoreError> {
        let header = load_header(&self.connection, session_id, ownership)?;
        let high_watermark = timeline::high_watermark(&self.connection, session_id)
            .map_err(|error| unavailable(error.to_string()))?;
        let total_eligible_turns = eligible_turn_count(&self.connection, session_id)?;
        let rows = load_bounded_rows(&self.connection, session_id)?;
        let mut turns = Vec::with_capacity(rows.len());
        let mut included_content_bytes = 0_u64;
        let mut previous_sequence = None;
        for row in rows {
            let turn = row.into_turn(&self.connection, ownership)?;
            if previous_sequence.is_some_and(|previous| previous >= turn.sequence) {
                return Err(invariant(
                    "transcript turn sequences are not strictly increasing",
                ));
            }
            previous_sequence = Some(turn.sequence);
            included_content_bytes = included_content_bytes
                .checked_add(turn.user.byte_length)
                .and_then(|value| value.checked_add(turn.assistant.byte_length))
                .ok_or_else(|| invariant("transcript content byte count overflow"))?;
            turns.push(turn);
        }
        if turns.len() > SESSION_TRANSCRIPT_MAXIMUM_TURNS
            || included_content_bytes > SESSION_TRANSCRIPT_MAXIMUM_CONTENT_BYTES
        {
            return Err(invariant("bounded transcript query exceeded its contract"));
        }
        let included_turns = u64::try_from(turns.len())
            .map_err(|_| invariant("included transcript turn count exceeds u64"))?;
        let omitted_turns = total_eligible_turns
            .checked_sub(included_turns)
            .ok_or_else(|| invariant("included transcript count exceeds eligible count"))?;
        let lineage = header.to_lineage(session_id)?;
        let title_source = if header.owner_title.is_some() {
            "owner"
        } else {
            "derived"
        };
        Ok(SessionTranscriptSnapshot {
            session_id,
            title: header
                .owner_title
                .unwrap_or_else(|| derive_session_title(header.first_input.as_deref())),
            title_source: title_source.to_owned(),
            status: header.status,
            revision: nonnegative_u64(header.revision, "session revision")?,
            created_at: system_time(header.created_at_ms)?,
            updated_at: system_time(header.updated_at_ms)?,
            high_watermark,
            lineage,
            total_eligible_turns,
            omitted_turns,
            included_content_bytes,
            oldest_included_sequence: turns.first().map(|turn| turn.sequence),
            turns,
        })
    }
}

struct StoredTranscriptHeader {
    owner_title: Option<String>,
    first_input: Option<String>,
    status: String,
    revision: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
    root_session_id: String,
    parent_checkpoint_id: Option<String>,
    fork_event_id: Option<String>,
    parent_session_id: Option<String>,
    parent_checkpoint_cursor: Option<i64>,
}

impl StoredTranscriptHeader {
    fn to_lineage(
        &self,
        session_id: SessionId,
    ) -> Result<SessionTranscriptLineage, SessionTranscriptStoreError> {
        let root_session_id = parse_id(&self.root_session_id, "lineage root session ID")?;
        let parent_session_id = self
            .parent_session_id
            .as_deref()
            .map(|value| parse_id(value, "lineage parent session ID"))
            .transpose()?;
        let parent_checkpoint_id = self
            .parent_checkpoint_id
            .as_deref()
            .map(|value| parse_id(value, "lineage parent checkpoint ID"))
            .transpose()?;
        let parent_checkpoint_cursor = self
            .parent_checkpoint_cursor
            .map(|value| positive_u64(value, "lineage checkpoint cursor").map(TimelineCursor))
            .transpose()?;
        let fork_event_id = self
            .fork_event_id
            .as_deref()
            .map(|value| parse_id(value, "lineage fork event ID"))
            .transpose()?;
        let is_root = root_session_id == session_id;
        if is_root
            != (parent_session_id.is_none()
                && parent_checkpoint_id.is_none()
                && parent_checkpoint_cursor.is_none()
                && fork_event_id.is_none())
            || (!is_root
                && (parent_session_id.is_none()
                    || parent_checkpoint_id.is_none()
                    || parent_checkpoint_cursor.is_none()
                    || fork_event_id.is_none()))
        {
            return Err(invariant("stored session lineage shape is inconsistent"));
        }
        Ok(SessionTranscriptLineage {
            root_session_id,
            parent_session_id,
            parent_checkpoint_id,
            parent_checkpoint_cursor,
            fork_event_id,
        })
    }
}

fn load_header(
    connection: &rusqlite::Connection,
    session_id: SessionId,
    ownership: OwnershipContext,
) -> Result<StoredTranscriptHeader, SessionTranscriptStoreError> {
    let header = connection
        .query_row(
            "SELECT metadata.owner_title, \
                    (SELECT first_inbox.content FROM session_inbox first_inbox \
                     WHERE first_inbox.session_id = session.id \
                     ORDER BY first_inbox.sequence LIMIT 1), \
                    session.status, session.revision, session.created_at_ms, \
                    session.updated_at_ms, lineage.root_session_id, \
                    lineage.parent_checkpoint_id, lineage.fork_event_id, \
                    parent_checkpoint.session_id, parent_checkpoint.source_cursor \
             FROM session \
             JOIN session_lineage lineage ON lineage.session_id = session.id \
             LEFT JOIN session_metadata metadata ON metadata.session_id = session.id \
             LEFT JOIN session_checkpoint parent_checkpoint \
               ON parent_checkpoint.id = lineage.parent_checkpoint_id \
             WHERE session.id = ?1 AND session.principal_id = ?2 \
               AND session.channel_binding_id = ?3",
            params![
                session_id.to_string(),
                ownership.principal_id().to_string(),
                ownership.channel_binding_id().to_string(),
            ],
            |row| {
                Ok(StoredTranscriptHeader {
                    owner_title: row.get(0)?,
                    first_input: row.get(1)?,
                    status: row.get(2)?,
                    revision: row.get(3)?,
                    created_at_ms: row.get(4)?,
                    updated_at_ms: row.get(5)?,
                    root_session_id: row.get(6)?,
                    parent_checkpoint_id: row.get(7)?,
                    fork_event_id: row.get(8)?,
                    parent_session_id: row.get(9)?,
                    parent_checkpoint_cursor: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .ok_or(SessionTranscriptStoreError::NotFound)?;
    if !matches!(header.status.as_str(), "active" | "paused" | "closed")
        || header
            .owner_title
            .as_deref()
            .is_some_and(|title| !valid_session_metadata(title))
        || header.created_at_ms < 0
        || header.updated_at_ms < header.created_at_ms
    {
        return Err(invariant("stored transcript session header is malformed"));
    }
    Ok(header)
}

fn eligible_turn_count(
    connection: &rusqlite::Connection,
    session_id: SessionId,
) -> Result<u64, SessionTranscriptStoreError> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) \
             FROM turn \
             JOIN session_inbox inbox ON inbox.inbox_entry_id = turn.inbox_entry_id \
             JOIN task ON task.id = turn.task_id \
             JOIN run ON run.id = turn.run_id AND run.task_id = task.id \
             JOIN run_loop_state loop ON loop.run_id = run.id \
             JOIN message assistant ON assistant.id = loop.final_message_id \
             JOIN model_attempt final_attempt \
               ON final_attempt.attempt_id = assistant.source_attempt_id \
              AND final_attempt.run_id = run.id \
             JOIN journal_event completion \
               ON completion.aggregate_kind = 'turn' \
              AND completion.aggregate_id = turn.id \
              AND completion.event_type = 'turn.completed' \
             JOIN timeline_event completion_timeline \
               ON completion_timeline.event_id = completion.event_id \
             JOIN timeline_event admission_timeline \
               ON admission_timeline.event_id = inbox.admission_event_id \
             WHERE turn.session_id = ?1 AND turn.turn_kind = 'canonical' \
               AND turn.status = 'completed' AND task.status = 'succeeded' \
               AND run.status = 'succeeded' AND loop.next_action = 'terminal' \
               AND inbox.state = 'promoted' AND inbox.promoted_turn_id = turn.id \
               AND assistant.session_id = ?1 AND assistant.turn_id = turn.id \
               AND assistant.task_id = task.id AND assistant.run_id = run.id \
               AND assistant.role = 'assistant' \
               AND assistant.media_type = 'text/plain; charset=utf-8' \
               AND assistant.sensitivity = 'internal' \
               AND final_attempt.state = 'completed' \
               AND final_attempt.response_kind = 'final'",
            [session_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    nonnegative_u64(count, "eligible transcript turn count")
}

#[allow(clippy::too_many_lines)]
fn load_bounded_rows(
    connection: &rusqlite::Connection,
    session_id: SessionId,
) -> Result<Vec<StoredTranscriptTurn>, SessionTranscriptStoreError> {
    let maximum_turns = i64::try_from(SESSION_TRANSCRIPT_MAXIMUM_TURNS)
        .map_err(|_| invariant("transcript turn bound exceeds SQLite"))?;
    let maximum_bytes = i64::try_from(SESSION_TRANSCRIPT_MAXIMUM_CONTENT_BYTES)
        .map_err(|_| invariant("transcript content bound exceeds SQLite"))?;
    let mut statement = connection
        .prepare(
            "WITH candidates AS (\
                 SELECT inbox.sequence, turn.id AS turn_id, turn.task_id, turn.run_id, \
                        turn.context_epoch_id, final_attempt.provider_id, \
                        final_attempt.model_id, inbox.inbox_entry_id, \
                        inbox.content AS user_content, inbox.admission_event_id, \
                        admission_timeline.cursor AS admission_cursor, \
                        inbox.accepted_at_ms, assistant.id AS assistant_message_id, \
                        assistant.content_inline, \
                        assistant.content_artifact_id, assistant.content_digest, \
                        assistant.byte_length, assistant.media_type, assistant.sensitivity, \
                        assistant.created_at_ms, \
                        completion.event_id AS completion_event_id, \
                        completion_timeline.cursor AS completion_cursor, turn.completed_at_ms, \
                        ROW_NUMBER() OVER (ORDER BY inbox.sequence DESC) AS recency_rank, \
                        SUM(length(CAST(inbox.content AS BLOB)) + assistant.byte_length) OVER (\
                            ORDER BY inbox.sequence DESC \
                            ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW\
                        ) AS cumulative_bytes \
                 FROM turn \
                 JOIN session_inbox inbox ON inbox.inbox_entry_id = turn.inbox_entry_id \
                 JOIN task ON task.id = turn.task_id \
                 JOIN run ON run.id = turn.run_id AND run.task_id = task.id \
                 JOIN run_loop_state loop ON loop.run_id = run.id \
                 JOIN message assistant ON assistant.id = loop.final_message_id \
                 JOIN model_attempt final_attempt \
                   ON final_attempt.attempt_id = assistant.source_attempt_id \
                  AND final_attempt.run_id = run.id \
                 JOIN journal_event completion \
                   ON completion.aggregate_kind = 'turn' \
                  AND completion.aggregate_id = turn.id \
                  AND completion.event_type = 'turn.completed' \
                 JOIN timeline_event completion_timeline \
                   ON completion_timeline.event_id = completion.event_id \
                 JOIN timeline_event admission_timeline \
                   ON admission_timeline.event_id = inbox.admission_event_id \
                 WHERE turn.session_id = ?1 AND turn.turn_kind = 'canonical' \
                   AND turn.status = 'completed' AND task.status = 'succeeded' \
                   AND run.status = 'succeeded' AND loop.next_action = 'terminal' \
                   AND inbox.state = 'promoted' AND inbox.promoted_turn_id = turn.id \
                   AND assistant.session_id = ?1 AND assistant.turn_id = turn.id \
                   AND assistant.task_id = task.id AND assistant.run_id = run.id \
                   AND assistant.role = 'assistant' \
                   AND assistant.media_type = 'text/plain; charset=utf-8' \
                   AND assistant.sensitivity = 'internal' \
                   AND final_attempt.state = 'completed' \
                   AND final_attempt.response_kind = 'final'\
             ) \
             SELECT sequence, turn_id, task_id, run_id, context_epoch_id, provider_id, model_id, \
                    inbox_entry_id, user_content, admission_event_id, admission_cursor, \
                    accepted_at_ms, assistant_message_id, content_inline, content_artifact_id, \
                    content_digest, byte_length, media_type, sensitivity, created_at_ms, \
                    completion_event_id, completion_cursor, completed_at_ms \
             FROM candidates \
             WHERE recency_rank <= ?2 AND cumulative_bytes <= ?3 \
             ORDER BY sequence",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    statement
        .query_map(
            params![session_id.to_string(), maximum_turns, maximum_bytes],
            |row| {
                Ok(StoredTranscriptTurn {
                    sequence: row.get(0)?,
                    turn_id: row.get(1)?,
                    task_id: row.get(2)?,
                    run_id: row.get(3)?,
                    context_epoch_id: row.get(4)?,
                    provider_id: row.get(5)?,
                    model_id: row.get(6)?,
                    inbox_entry_id: row.get(7)?,
                    user_content: row.get(8)?,
                    admission_event_id: row.get(9)?,
                    admission_cursor: row.get(10)?,
                    accepted_at_ms: row.get(11)?,
                    assistant_message_id: row.get(12)?,
                    assistant_content_inline: row.get(13)?,
                    assistant_artifact_id: row.get(14)?,
                    assistant_content_digest: row.get(15)?,
                    assistant_byte_length: row.get(16)?,
                    assistant_media_type: row.get(17)?,
                    assistant_sensitivity: row.get(18)?,
                    assistant_created_at_ms: row.get(19)?,
                    completion_event_id: row.get(20)?,
                    completion_cursor: row.get(21)?,
                    completed_at_ms: row.get(22)?,
                })
            },
        )
        .map_err(|error| map_sqlite_error(&error))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|error| map_sqlite_error(&error))
}

struct StoredTranscriptTurn {
    sequence: i64,
    turn_id: String,
    task_id: String,
    run_id: String,
    context_epoch_id: String,
    provider_id: String,
    model_id: String,
    inbox_entry_id: String,
    user_content: String,
    admission_event_id: String,
    admission_cursor: i64,
    accepted_at_ms: i64,
    assistant_message_id: String,
    assistant_content_inline: Option<String>,
    assistant_artifact_id: Option<String>,
    assistant_content_digest: String,
    assistant_byte_length: i64,
    assistant_media_type: String,
    assistant_sensitivity: String,
    assistant_created_at_ms: i64,
    completion_event_id: String,
    completion_cursor: i64,
    completed_at_ms: i64,
}

impl StoredTranscriptTurn {
    fn into_turn(
        self,
        connection: &rusqlite::Connection,
        ownership: OwnershipContext,
    ) -> Result<SessionTranscriptTurn, SessionTranscriptStoreError> {
        let user_byte_length = u64::try_from(self.user_content.len())
            .map_err(|_| invariant("user transcript content length exceeds u64"))?;
        let assistant_byte_length =
            nonnegative_u64(self.assistant_byte_length, "assistant content byte length")?;
        if self.user_content.is_empty()
            || !is_sha256_digest(&self.assistant_content_digest)
            || self.assistant_media_type != "text/plain; charset=utf-8"
            || self.assistant_sensitivity != "internal"
            || self.assistant_content_inline.is_some() == self.assistant_artifact_id.is_some()
        {
            return Err(invariant("stored transcript message shape is malformed"));
        }
        let content_artifact = self
            .assistant_artifact_id
            .as_deref()
            .map(|value| {
                let artifact_id = parse_id::<ArtifactId>(value, "assistant artifact ID")?;
                artifact::load_authorized_artifact(connection, ownership, artifact_id)
                    .map_err(map_artifact_error)
            })
            .transpose()?;
        if let Some(content) = &self.assistant_content_inline {
            if u64::try_from(content.len()).ok() != Some(assistant_byte_length)
                || sha256_digest(content.as_bytes()) != self.assistant_content_digest
            {
                return Err(invariant(
                    "inline assistant transcript content does not match its evidence",
                ));
            }
        } else if content_artifact.as_ref().is_none_or(|descriptor| {
            descriptor.metadata().digest != self.assistant_content_digest
                || descriptor.metadata().size_bytes != assistant_byte_length
                || descriptor.metadata().media_type != self.assistant_media_type
                || descriptor.metadata().sensitivity != self.assistant_sensitivity
        }) {
            return Err(invariant(
                "assistant artifact metadata does not match its message evidence",
            ));
        }
        Ok(SessionTranscriptTurn {
            sequence: positive_u64(self.sequence, "transcript inbox sequence")?,
            turn_id: parse_id(&self.turn_id, "transcript turn ID")?,
            task_id: parse_id(&self.task_id, "transcript task ID")?,
            run_id: parse_id(&self.run_id, "transcript run ID")?,
            context_epoch_id: parse_id(&self.context_epoch_id, "transcript context epoch ID")?,
            provider_id: self.provider_id,
            model_id: self.model_id,
            user: SessionTranscriptUserMessage {
                inbox_entry_id: parse_id(&self.inbox_entry_id, "transcript inbox entry ID")?,
                content_digest: sha256_digest(self.user_content.as_bytes()),
                content: self.user_content,
                byte_length: user_byte_length,
                admission_event_id: parse_id(&self.admission_event_id, "input admission event ID")?,
                admission_cursor: TimelineCursor(positive_u64(
                    self.admission_cursor,
                    "input admission cursor",
                )?),
                accepted_at: system_time(self.accepted_at_ms)?,
            },
            assistant: SessionTranscriptAssistantMessage {
                message_id: parse_id(&self.assistant_message_id, "assistant message ID")?,
                content_inline: self.assistant_content_inline,
                content_artifact,
                content_digest: self.assistant_content_digest,
                byte_length: assistant_byte_length,
                media_type: self.assistant_media_type,
                sensitivity: self.assistant_sensitivity,
                created_at: system_time(self.assistant_created_at_ms)?,
            },
            completion_event_id: parse_id(&self.completion_event_id, "turn completion event ID")?,
            completion_cursor: TimelineCursor(positive_u64(
                self.completion_cursor,
                "turn completion cursor",
            )?),
            completed_at: system_time(self.completed_at_ms)?,
        })
    }
}

fn map_artifact_error(error: ArtifactEvidenceStoreError) -> SessionTranscriptStoreError {
    match error {
        ArtifactEvidenceStoreError::NotFound => {
            invariant("assistant transcript artifact is absent or unauthorized")
        }
        ArtifactEvidenceStoreError::Unavailable(message) => unavailable(message),
        ArtifactEvidenceStoreError::InvariantViolation(message) => invariant(message),
    }
}

fn map_sqlite_error(error: &rusqlite::Error) -> SessionTranscriptStoreError {
    unavailable(error.to_string())
}

fn parse_id<T>(value: &str, label: &str) -> Result<T, SessionTranscriptStoreError>
where
    T: FromStr,
{
    value
        .parse()
        .map_err(|_| invariant(format!("stored {label} is invalid")))
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64, SessionTranscriptStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{label} is negative")))
}

fn positive_u64(value: i64, label: &str) -> Result<u64, SessionTranscriptStoreError> {
    let value = nonnegative_u64(value, label)?;
    if value == 0 {
        Err(invariant(format!("{label} is zero")))
    } else {
        Ok(value)
    }
}

fn system_time(milliseconds: i64) -> Result<SystemTime, SessionTranscriptStoreError> {
    let milliseconds =
        u64::try_from(milliseconds).map_err(|_| invariant("stored timestamp is negative"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(milliseconds))
        .ok_or_else(|| invariant("stored timestamp is out of range"))
}

fn unavailable(message: impl Into<String>) -> SessionTranscriptStoreError {
    SessionTranscriptStoreError::Unavailable(message.into())
}

fn invariant(message: impl Into<String>) -> SessionTranscriptStoreError {
    SessionTranscriptStoreError::InvariantViolation(message.into())
}
