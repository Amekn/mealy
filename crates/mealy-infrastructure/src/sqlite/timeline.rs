use super::SqliteStore;
use mealy_application::{
    OwnershipContext, SessionSearchHitView, SessionSearchQuery, SessionStatusView,
    SessionSummaryView, TimelineCursor, TimelineEvent, TimelinePage, TimelineQuery, TimelineStore,
    TimelineStoreError, derive_session_title, session_search_excerpt, sha256_digest,
    valid_session_metadata,
};
use mealy_domain::SessionId;
use rusqlite::{OptionalExtension, params};
use std::{str::FromStr, time::SystemTime};

impl TimelineStore for SqliteStore {
    fn sessions(
        &self,
        ownership: OwnershipContext,
        limit: usize,
    ) -> Result<Vec<SessionSummaryView>, TimelineStoreError> {
        let limit = i64::try_from(limit)
            .map_err(|_| invariant("session list limit exceeds SQLite range"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT session.id, metadata.owner_title, \
                        (SELECT inbox.content FROM session_inbox inbox \
                         WHERE inbox.session_id = session.id \
                         ORDER BY inbox.sequence ASC LIMIT 1), \
                        session.status, session.revision, \
                        (SELECT COUNT(*) FROM session_inbox inbox \
                         WHERE inbox.session_id = session.id AND inbox.state = 'pending'), \
                        session.active_turn_id, session.created_at_ms, session.updated_at_ms \
                 FROM session LEFT JOIN session_metadata metadata \
                   ON metadata.session_id = session.id \
                 WHERE principal_id = ?1 AND channel_binding_id = ?2 \
                 ORDER BY updated_at_ms DESC, id DESC LIMIT ?3",
            )
            .map_err(map_sqlite_error)?;
        statement
            .query_map(
                params![
                    ownership.principal_id().to_string(),
                    ownership.channel_binding_id().to_string(),
                    limit,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .map_err(map_sqlite_error)?
            .map(|row| {
                let (
                    session_id,
                    owner_title,
                    first_input,
                    status,
                    revision,
                    pending_inputs,
                    active_turn_id,
                    created_at_ms,
                    updated_at_ms,
                ) = row.map_err(map_sqlite_error)?;
                if !matches!(status.as_str(), "active" | "paused" | "closed") {
                    return Err(invariant("session status is invalid"));
                }
                if owner_title
                    .as_deref()
                    .is_some_and(|title| !valid_session_metadata(title))
                {
                    return Err(invariant("session owner title is invalid"));
                }
                let title_source = if owner_title.is_some() {
                    "owner"
                } else {
                    "derived"
                };
                Ok(SessionSummaryView {
                    session_id: parse_id(&session_id, "session ID")?,
                    title: owner_title
                        .unwrap_or_else(|| derive_session_title(first_input.as_deref())),
                    title_source: title_source.to_owned(),
                    status,
                    revision: nonnegative_u64(revision, "session revision")?,
                    pending_inputs: nonnegative_u64(pending_inputs, "pending input count")?,
                    active_turn_id: active_turn_id
                        .as_deref()
                        .map(|value| parse_id(value, "active turn ID"))
                        .transpose()?,
                    created_at: system_time(created_at_ms)?,
                    updated_at: system_time(updated_at_ms)?,
                })
            })
            .collect()
    }

    fn search_sessions(
        &self,
        query: &SessionSearchQuery,
    ) -> Result<Vec<SessionSearchHitView>, TimelineStoreError> {
        if query.query.is_empty()
            || query.query.len() > 4_096
            || query.query.trim() != query.query
            || query.query.chars().any(char::is_control)
            || !(1..=100).contains(&query.limit)
        {
            return Err(TimelineStoreError::InvalidSearch);
        }
        let limit = i64::try_from(query.limit)
            .map_err(|_| invariant("session search limit exceeds SQLite range"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT session.id, metadata.owner_title, \
                        (SELECT first_inbox.content FROM session_inbox first_inbox \
                         WHERE first_inbox.session_id = session.id \
                         ORDER BY first_inbox.sequence ASC LIMIT 1), \
                        turn.id, turn.task_id, inbox.content, final_message.content_inline, \
                        final_message.content_digest, turn.created_at_ms \
                 FROM turn \
                 JOIN session ON session.id = turn.session_id \
                 LEFT JOIN session_metadata metadata ON metadata.session_id = session.id \
                 JOIN session_inbox inbox ON inbox.inbox_entry_id = turn.inbox_entry_id \
                 JOIN run_loop_state loop ON loop.run_id = turn.run_id \
                 LEFT JOIN message final_message ON final_message.id = loop.final_message_id \
                 WHERE session.principal_id = ?1 AND session.channel_binding_id = ?2 \
                   AND turn.turn_kind = 'canonical' AND (\
                       instr(lower(inbox.content), lower(?3)) > 0 OR \
                       instr(lower(COALESCE(final_message.content_inline, '')), lower(?3)) > 0\
                   ) \
                 ORDER BY turn.created_at_ms DESC, turn.id DESC LIMIT ?4",
            )
            .map_err(map_sqlite_error)?;
        statement
            .query_map(
                params![
                    query.ownership.principal_id().to_string(),
                    query.ownership.channel_binding_id().to_string(),
                    query.query,
                    limit,
                ],
                |row| {
                    Ok(StoredSessionSearchHit {
                        session_id: row.get(0)?,
                        owner_title: row.get(1)?,
                        first_input: row.get(2)?,
                        turn_id: row.get(3)?,
                        task_id: row.get(4)?,
                        user_content: row.get(5)?,
                        assistant_content: row.get(6)?,
                        assistant_content_digest: row.get(7)?,
                        created_at_ms: row.get(8)?,
                    })
                },
            )
            .map_err(map_sqlite_error)?
            .map(|row| row.map_err(map_sqlite_error)?.into_view(&query.query))
            .collect()
    }

    #[allow(clippy::too_many_lines)]
    fn timeline_page(&self, query: TimelineQuery) -> Result<TimelinePage, TimelineStoreError> {
        authorize(&self.connection, query.session_id, query.ownership)?;
        let high_watermark = high_watermark(&self.connection, query.session_id)?;
        if let Some(after) = query.after {
            let earliest = retention_floor(&self.connection)?;
            if after.0.saturating_add(1) < earliest.0 {
                return Err(TimelineStoreError::Gap { earliest });
            }
            if after.0 > high_watermark.0 {
                return Err(TimelineStoreError::CursorAhead);
            }
        }

        let after = query.after.unwrap_or_default().0;
        let sql_limit = i64::try_from(query.limit.saturating_add(1))
            .map_err(|_| invariant("timeline page limit exceeds SQLite range"))?;
        let after =
            i64::try_from(after).map_err(|_| invariant("timeline cursor exceeds SQLite range"))?;
        // CROSS JOIN is a deliberate planner fence: the requested cursor range is
        // scanned first, and each candidate event receives bounded indexed lineage checks.
        let mut statement = self
            .connection
            .prepare(
                "SELECT te.cursor, je.event_id, je.aggregate_kind, je.aggregate_id, \
                        je.aggregate_sequence, je.event_type, je.event_version, je.occurred_at_ms, \
                        je.correlation_id, je.causation_id, je.payload_json \
                 FROM timeline_event te CROSS JOIN journal_event je \
                 WHERE te.cursor > ?1 AND (\
                    je.event_id = te.event_id AND (\
                        (je.aggregate_kind = 'session' AND je.aggregate_id = ?2) OR \
                        (je.aggregate_kind = 'task' AND EXISTS(\
                            SELECT 1 FROM run task_run \
                            JOIN run_lineage lineage ON lineage.run_id = task_run.id \
                            JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                            WHERE task_run.task_id = je.aggregate_id \
                              AND root_turn.session_id = ?2 \
                              AND root_turn.turn_kind = 'canonical'\
                        )) OR \
                        (je.aggregate_kind = 'run' AND EXISTS(\
                            SELECT 1 FROM run_lineage lineage \
                            JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                            WHERE lineage.run_id = je.aggregate_id \
                              AND root_turn.session_id = ?2 \
                              AND root_turn.turn_kind = 'canonical'\
                        )) OR \
                        (je.aggregate_kind = 'turn' AND EXISTS(\
                            SELECT 1 FROM turn candidate \
                            WHERE candidate.id = je.aggregate_id AND candidate.session_id = ?2\
                        )) OR \
                        (je.aggregate_kind = 'context_epoch' AND EXISTS(\
                            SELECT 1 FROM context_epoch epoch \
                            WHERE epoch.id = je.aggregate_id AND epoch.session_id = ?2\
                        )) OR \
                        (je.aggregate_kind = 'context_manifest' AND EXISTS(\
                            SELECT 1 FROM context_manifest manifest \
                            WHERE manifest.id = je.aggregate_id AND manifest.session_id = ?2\
                        )) OR \
                        (je.aggregate_kind = 'model_attempt' AND EXISTS(\
                            SELECT 1 FROM model_attempt attempt \
                            JOIN run_lineage lineage ON lineage.run_id = attempt.run_id \
                            JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                            WHERE attempt.attempt_id = je.aggregate_id \
                              AND root_turn.session_id = ?2 \
                              AND root_turn.turn_kind = 'canonical'\
                        )) OR \
                        (je.aggregate_kind = 'tool_call' AND EXISTS(\
                            SELECT 1 FROM tool_call call \
                            JOIN run_lineage lineage ON lineage.run_id = call.run_id \
                            JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                            WHERE call.tool_call_id = je.aggregate_id \
                              AND root_turn.session_id = ?2 \
                              AND root_turn.turn_kind = 'canonical'\
                        )) OR \
                        (je.aggregate_kind = 'effect' AND EXISTS(\
                            SELECT 1 FROM effect candidate \
                            JOIN run_lineage lineage ON lineage.run_id = candidate.run_id \
                            JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                            WHERE candidate.id = je.aggregate_id \
                              AND root_turn.session_id = ?2 \
                              AND root_turn.turn_kind = 'canonical'\
                        )) OR \
                        (je.aggregate_kind = 'approval' AND EXISTS(\
                            SELECT 1 FROM approval_request approval \
                            JOIN effect candidate ON candidate.id = approval.effect_id \
                            JOIN run_lineage lineage ON lineage.run_id = candidate.run_id \
                            JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                            WHERE approval.approval_id = je.aggregate_id \
                              AND root_turn.session_id = ?2 \
                              AND root_turn.turn_kind = 'canonical'\
                        )) OR \
                        (je.aggregate_kind = 'validation' AND EXISTS(\
                            SELECT 1 FROM validation_record validation \
                            JOIN run_lineage lineage ON lineage.run_id = validation.producer_run_id \
                            JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                            WHERE validation.id = je.aggregate_id \
                              AND root_turn.session_id = ?2 \
                              AND root_turn.turn_kind = 'canonical'\
                        )) OR \
                        (je.aggregate_kind = 'delegation' AND EXISTS(\
                            SELECT 1 FROM delegation candidate \
                            WHERE candidate.id = je.aggregate_id AND (\
                                EXISTS(\
                                    SELECT 1 FROM run_lineage parent_lineage \
                                    JOIN turn parent_root \
                                      ON parent_root.run_id = parent_lineage.root_run_id \
                                    WHERE parent_lineage.run_id = candidate.parent_run_id \
                                      AND parent_root.session_id = ?2 \
                                      AND parent_root.turn_kind = 'canonical'\
                                ) OR EXISTS(\
                                    SELECT 1 FROM run_lineage child_lineage \
                                    JOIN turn child_root \
                                      ON child_root.run_id = child_lineage.root_run_id \
                                    WHERE child_lineage.run_id = candidate.child_run_id \
                                      AND child_root.session_id = ?2 \
                                      AND child_root.turn_kind = 'canonical'\
                                )\
                            )\
                        )) OR \
                        (je.aggregate_kind = 'delegation_group' AND EXISTS(\
                            SELECT 1 FROM delegation_group candidate \
                            JOIN run_lineage lineage ON lineage.run_id = candidate.parent_run_id \
                            JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                            WHERE candidate.id = je.aggregate_id \
                              AND root_turn.session_id = ?2 \
                              AND root_turn.turn_kind = 'canonical'\
                        )) OR \
                        (je.aggregate_kind = 'resource_claim' AND EXISTS(\
                            SELECT 1 FROM resource_claim claim \
                            JOIN run_lineage lineage ON lineage.run_id = claim.run_id \
                            JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                            WHERE claim.claim_id = je.aggregate_id \
                              AND root_turn.session_id = ?2 \
                              AND root_turn.turn_kind = 'canonical'\
                        )) OR \
                        (je.aggregate_kind = 'compaction' AND EXISTS(\
                            SELECT 1 FROM session_compaction compaction \
                            WHERE compaction.id = je.aggregate_id AND compaction.session_id = ?2\
                        )) OR \
                        (je.aggregate_kind = 'memory' AND EXISTS(\
                            SELECT 1 FROM memory candidate \
                            JOIN session owner_session ON owner_session.id = ?2 \
                            WHERE candidate.id = je.aggregate_id \
                              AND candidate.principal_id = owner_session.principal_id \
                              AND candidate.workspace_identity IN (\
                                  SELECT workspace_identity FROM context_epoch \
                                  WHERE session_id = ?2\
                              )\
                        )) OR \
                        (je.aggregate_kind = 'artifact' AND EXISTS(\
                            SELECT 1 FROM artifact candidate \
                            WHERE candidate.id = je.aggregate_id AND candidate.session_id = ?2\
                        )) OR \
                        (je.aggregate_kind = 'message' AND EXISTS(\
                            SELECT 1 FROM message candidate \
                            WHERE candidate.id = je.aggregate_id AND candidate.session_id = ?2\
                        ))\
                    )\
                 ) ORDER BY te.cursor LIMIT ?3",
            )
            .map_err(map_sqlite_error)?;
        let mut events = statement
            .query_map(
                params![after, query.session_id.to_string(), sql_limit],
                |row| {
                    Ok(StoredTimelineEvent {
                        cursor: row.get(0)?,
                        event_id: row.get(1)?,
                        aggregate_kind: row.get(2)?,
                        aggregate_id: row.get(3)?,
                        aggregate_sequence: row.get(4)?,
                        event_type: row.get(5)?,
                        event_version: row.get(6)?,
                        occurred_at_ms: row.get(7)?,
                        correlation_id: row.get(8)?,
                        causation_id: row.get(9)?,
                        payload_json: row.get(10)?,
                    })
                },
            )
            .map_err(map_sqlite_error)?
            .map(|row| {
                row.map_err(map_sqlite_error)
                    .and_then(StoredTimelineEvent::try_into_event)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = events.len() > query.limit;
        events.truncate(query.limit);
        Ok(TimelinePage {
            events,
            high_watermark,
            has_more,
        })
    }

    fn session_status(
        &self,
        session_id: SessionId,
        ownership: OwnershipContext,
    ) -> Result<SessionStatusView, TimelineStoreError> {
        authorize(&self.connection, session_id, ownership)?;
        let (revision, pending_inputs, active_turn_id): (i64, i64, Option<String>) = self
            .connection
            .query_row(
                "SELECT s.revision, \
                        (SELECT COUNT(*) FROM session_inbox i \
                         WHERE i.session_id = s.id AND i.state = 'pending'), \
                        s.active_turn_id \
                 FROM session s WHERE s.id = ?1",
                [session_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(map_sqlite_error)?;
        let latest_cursor = high_watermark(&self.connection, session_id)?;
        Ok(SessionStatusView {
            session_id,
            revision: nonnegative_u64(revision, "session revision")?,
            pending_inputs: nonnegative_u64(pending_inputs, "pending input count")?,
            active_turn_id: active_turn_id
                .as_deref()
                .map(|value| parse_id(value, "active turn ID"))
                .transpose()?,
            latest_cursor,
        })
    }
}

fn retention_floor(
    connection: &rusqlite::Connection,
) -> Result<TimelineCursor, TimelineStoreError> {
    let value = connection
        .query_row(
            "SELECT earliest_available_cursor FROM timeline_retention WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    positive_u64(value, "timeline retention floor").map(TimelineCursor)
}

struct StoredTimelineEvent {
    cursor: i64,
    event_id: String,
    aggregate_kind: String,
    aggregate_id: String,
    aggregate_sequence: i64,
    event_type: String,
    event_version: i64,
    occurred_at_ms: i64,
    correlation_id: String,
    causation_id: Option<String>,
    payload_json: String,
}

struct StoredSessionSearchHit {
    session_id: String,
    owner_title: Option<String>,
    first_input: Option<String>,
    turn_id: String,
    task_id: String,
    user_content: String,
    assistant_content: Option<String>,
    assistant_content_digest: Option<String>,
    created_at_ms: i64,
}

impl StoredSessionSearchHit {
    fn into_view(self, query: &str) -> Result<SessionSearchHitView, TimelineStoreError> {
        if self.assistant_content.as_ref().is_some_and(|content| {
            self.assistant_content_digest
                .as_ref()
                .is_none_or(|digest| sha256_digest(content.as_bytes()) != *digest)
        }) {
            return Err(invariant("stored searchable assistant content is invalid"));
        }
        let user_excerpt = session_search_excerpt(&self.user_content, query);
        let assistant_excerpt = self
            .assistant_content
            .as_deref()
            .and_then(|content| session_search_excerpt(content, query));
        if user_excerpt.is_none() && assistant_excerpt.is_none() {
            return Err(invariant("session search row does not contain its query"));
        }
        if self
            .owner_title
            .as_deref()
            .is_some_and(|title| !valid_session_metadata(title))
        {
            return Err(invariant("session owner title is invalid"));
        }
        let session_title_source = if self.owner_title.is_some() {
            "owner"
        } else {
            "derived"
        };
        Ok(SessionSearchHitView {
            session_id: parse_id(&self.session_id, "session ID")?,
            session_title: self
                .owner_title
                .unwrap_or_else(|| derive_session_title(self.first_input.as_deref())),
            session_title_source: session_title_source.to_owned(),
            turn_id: parse_id(&self.turn_id, "turn ID")?,
            task_id: parse_id(&self.task_id, "task ID")?,
            user_excerpt,
            user_content_digest: sha256_digest(self.user_content.as_bytes()),
            assistant_excerpt,
            assistant_content_digest: self.assistant_content_digest,
            created_at: system_time(self.created_at_ms)?,
        })
    }
}

impl StoredTimelineEvent {
    fn try_into_event(self) -> Result<TimelineEvent, TimelineStoreError> {
        Ok(TimelineEvent {
            cursor: TimelineCursor(positive_u64(self.cursor, "timeline cursor")?),
            event_id: parse_id(&self.event_id, "event ID")?,
            aggregate_kind: self.aggregate_kind,
            aggregate_id: self.aggregate_id,
            aggregate_sequence: nonnegative_u64(self.aggregate_sequence, "aggregate sequence")?,
            event_type: self.event_type,
            event_version: u32::try_from(self.event_version)
                .map_err(|_| invariant("event version is outside u32 range"))?,
            occurred_at: system_time(self.occurred_at_ms)?,
            correlation_id: parse_id(&self.correlation_id, "correlation ID")?,
            causation_id: self
                .causation_id
                .as_deref()
                .map(|value| parse_id(value, "causation ID"))
                .transpose()?,
            payload_json: self.payload_json,
        })
    }
}

fn authorize(
    connection: &rusqlite::Connection,
    session_id: SessionId,
    ownership: OwnershipContext,
) -> Result<(), TimelineStoreError> {
    let stored = connection
        .query_row(
            "SELECT principal_id, channel_binding_id FROM session WHERE id = ?1",
            [session_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(TimelineStoreError::SessionNotFound)?;
    if stored.0 == ownership.principal_id().to_string()
        && stored.1 == ownership.channel_binding_id().to_string()
    {
        Ok(())
    } else {
        Err(TimelineStoreError::Unauthorized)
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn high_watermark(
    connection: &rusqlite::Connection,
    session_id: SessionId,
) -> Result<TimelineCursor, TimelineStoreError> {
    // CROSS JOIN is a deliberate planner fence: inspect the newest presentation
    // rows first, then perform bounded primary-key lineage checks for each event.
    // Materializing every historical aggregate for a long-lived session made
    // concurrent timeline reads grow with the complete session history.
    let maximum = connection
        .query_row(
            "SELECT te.cursor \
             FROM timeline_event te CROSS JOIN journal_event je \
             WHERE je.event_id = te.event_id AND (\
                (je.aggregate_kind = 'session' AND je.aggregate_id = ?2) OR \
                (je.aggregate_kind = 'task' AND EXISTS(\
                    SELECT 1 FROM run task_run \
                    JOIN run_lineage lineage ON lineage.run_id = task_run.id \
                    JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                    WHERE task_run.task_id = je.aggregate_id \
                      AND root_turn.session_id = ?2 \
                      AND root_turn.turn_kind = 'canonical'\
                )) OR \
                (je.aggregate_kind = 'run' AND EXISTS(\
                    SELECT 1 FROM run_lineage lineage \
                    JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                    WHERE lineage.run_id = je.aggregate_id \
                      AND root_turn.session_id = ?2 \
                      AND root_turn.turn_kind = 'canonical'\
                )) OR \
                (je.aggregate_kind = 'turn' AND EXISTS(\
                    SELECT 1 FROM turn candidate \
                    WHERE candidate.id = je.aggregate_id AND candidate.session_id = ?2\
                )) OR \
                (je.aggregate_kind = 'context_epoch' AND EXISTS(\
                    SELECT 1 FROM context_epoch epoch \
                    WHERE epoch.id = je.aggregate_id AND epoch.session_id = ?2\
                )) OR \
                (je.aggregate_kind = 'context_manifest' AND EXISTS(\
                    SELECT 1 FROM context_manifest manifest \
                    WHERE manifest.id = je.aggregate_id AND manifest.session_id = ?2\
                )) OR \
                (je.aggregate_kind = 'model_attempt' AND EXISTS(\
                    SELECT 1 FROM model_attempt attempt \
                    JOIN run_lineage lineage ON lineage.run_id = attempt.run_id \
                    JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                    WHERE attempt.attempt_id = je.aggregate_id \
                      AND root_turn.session_id = ?2 \
                      AND root_turn.turn_kind = 'canonical'\
                )) OR \
                (je.aggregate_kind = 'tool_call' AND EXISTS(\
                    SELECT 1 FROM tool_call call \
                    JOIN run_lineage lineage ON lineage.run_id = call.run_id \
                    JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                    WHERE call.tool_call_id = je.aggregate_id \
                      AND root_turn.session_id = ?2 \
                      AND root_turn.turn_kind = 'canonical'\
                )) OR \
                (je.aggregate_kind = 'effect' AND EXISTS(\
                    SELECT 1 FROM effect candidate \
                    JOIN run_lineage lineage ON lineage.run_id = candidate.run_id \
                    JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                    WHERE candidate.id = je.aggregate_id \
                      AND root_turn.session_id = ?2 \
                      AND root_turn.turn_kind = 'canonical'\
                )) OR \
                (je.aggregate_kind = 'approval' AND EXISTS(\
                    SELECT 1 FROM approval_request approval \
                    JOIN effect candidate ON candidate.id = approval.effect_id \
                    JOIN run_lineage lineage ON lineage.run_id = candidate.run_id \
                    JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                    WHERE approval.approval_id = je.aggregate_id \
                      AND root_turn.session_id = ?2 \
                      AND root_turn.turn_kind = 'canonical'\
                )) OR \
                (je.aggregate_kind = 'validation' AND EXISTS(\
                    SELECT 1 FROM validation_record validation \
                    JOIN run_lineage lineage ON lineage.run_id = validation.producer_run_id \
                    JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                    WHERE validation.id = je.aggregate_id \
                      AND root_turn.session_id = ?2 \
                      AND root_turn.turn_kind = 'canonical'\
                )) OR \
                (je.aggregate_kind = 'delegation' AND EXISTS(\
                    SELECT 1 FROM delegation candidate \
                    WHERE candidate.id = je.aggregate_id AND (\
                        EXISTS(\
                            SELECT 1 FROM run_lineage parent_lineage \
                            JOIN turn parent_root ON parent_root.run_id = parent_lineage.root_run_id \
                            WHERE parent_lineage.run_id = candidate.parent_run_id \
                              AND parent_root.session_id = ?2 \
                              AND parent_root.turn_kind = 'canonical'\
                        ) OR EXISTS(\
                            SELECT 1 FROM run_lineage child_lineage \
                            JOIN turn child_root ON child_root.run_id = child_lineage.root_run_id \
                            WHERE child_lineage.run_id = candidate.child_run_id \
                              AND child_root.session_id = ?2 \
                              AND child_root.turn_kind = 'canonical'\
                        )\
                    )\
                )) OR \
                (je.aggregate_kind = 'delegation_group' AND EXISTS(\
                    SELECT 1 FROM delegation_group candidate \
                    JOIN run_lineage lineage ON lineage.run_id = candidate.parent_run_id \
                    JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                    WHERE candidate.id = je.aggregate_id \
                      AND root_turn.session_id = ?2 \
                      AND root_turn.turn_kind = 'canonical'\
                )) OR \
                (je.aggregate_kind = 'resource_claim' AND EXISTS(\
                    SELECT 1 FROM resource_claim claim \
                    JOIN run_lineage lineage ON lineage.run_id = claim.run_id \
                    JOIN turn root_turn ON root_turn.run_id = lineage.root_run_id \
                    WHERE claim.claim_id = je.aggregate_id \
                      AND root_turn.session_id = ?2 \
                      AND root_turn.turn_kind = 'canonical'\
                )) OR \
                (je.aggregate_kind = 'compaction' AND EXISTS(\
                    SELECT 1 FROM session_compaction compaction \
                    WHERE compaction.id = je.aggregate_id AND compaction.session_id = ?2\
                )) OR \
                (je.aggregate_kind = 'memory' AND EXISTS(\
                    SELECT 1 FROM memory candidate \
                    JOIN session owner_session ON owner_session.id = ?2 \
                    WHERE candidate.id = je.aggregate_id \
                      AND candidate.principal_id = owner_session.principal_id \
                      AND candidate.workspace_identity IN (\
                          SELECT workspace_identity FROM context_epoch WHERE session_id = ?2\
                      )\
                )) OR \
                (je.aggregate_kind = 'artifact' AND EXISTS(\
                    SELECT 1 FROM artifact candidate \
                    WHERE candidate.id = je.aggregate_id AND candidate.session_id = ?2\
                )) OR \
                (je.aggregate_kind = 'message' AND EXISTS(\
                    SELECT 1 FROM message candidate \
                    WHERE candidate.id = je.aggregate_id AND candidate.session_id = ?2\
                ))\
             ) ORDER BY te.cursor DESC LIMIT 1",
            params![0_i64, session_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_error)?;
    maximum
        .map(|value| positive_u64(value, "maximum timeline cursor").map(TimelineCursor))
        .transpose()?
        .map_or_else(|| Ok(TimelineCursor::default()), Ok)
}

fn system_time(value: i64) -> Result<SystemTime, TimelineStoreError> {
    let value = u64::try_from(value).map_err(|_| invariant("stored timestamp is negative"))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(value))
        .ok_or_else(|| invariant("stored timestamp exceeds SystemTime"))
}

fn positive_u64(value: i64, field: &str) -> Result<u64, TimelineStoreError> {
    let value = nonnegative_u64(value, field)?;
    if value == 0 {
        Err(invariant(format!("stored {field} is zero")))
    } else {
        Ok(value)
    }
}

fn nonnegative_u64(value: i64, field: &str) -> Result<u64, TimelineStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, TimelineStoreError> {
    value
        .parse()
        .map_err(|_| invariant(format!("stored {field} is invalid")))
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> TimelineStoreError {
    TimelineStoreError::Unavailable(error.to_string())
}

fn invariant(message: impl Into<String>) -> TimelineStoreError {
    TimelineStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::{SqliteStore, high_watermark};
    use mealy_application::{
        IdGenerator, OwnershipContext, TimelineCursor, TimelineQuery, TimelineStoreError,
        create_session, query_timeline,
    };
    use mealy_domain::{ChannelBindingId, PrincipalId};
    use mealy_testkit::{TestClock, TestIdGenerator};
    use rusqlite::params;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn explicit_retention_floor_reports_a_real_cursor_gap() {
        let now = 1_782_062_400_000;
        let clock = TestClock::new(now);
        let ids = TestIdGenerator::new(now.cast_unsigned());
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let mut store = SqliteStore::open_in_memory(now).expect("open store");
        let session_id =
            create_session(&mut store, &clock, &ids, ownership).expect("create session");
        store
            .connection
            .execute("DELETE FROM timeline_event WHERE cursor = 1", [])
            .expect("simulate retained presentation row");
        store
            .connection
            .execute(
                "UPDATE timeline_retention \
                 SET earliest_available_cursor = 2, updated_at_ms = ?1 WHERE singleton = 1",
                [now],
            )
            .expect("advance explicit retention floor");

        let error = query_timeline(
            &store,
            TimelineQuery {
                session_id,
                ownership,
                after: Some(TimelineCursor(0)),
                limit: 100,
            },
        )
        .expect_err("cursor before explicit retention floor must report a gap");
        assert_eq!(
            error,
            mealy_application::TimelineUseCaseError::Store(TimelineStoreError::Gap {
                earliest: TimelineCursor(2)
            })
        );
    }

    #[test]
    fn latest_timeline_reads_are_bounded_by_recent_events_not_complete_history() {
        const HISTORICAL_EVENTS: usize = 50_000;
        const PROGRESS_GRANULARITY: i32 = 100;
        const MAX_PROGRESS_CALLBACKS: usize = 10;

        let now = 1_782_062_400_000;
        let clock = TestClock::new(now);
        let ids = TestIdGenerator::new(now.cast_unsigned());
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let mut store = SqliteStore::open_in_memory(now).expect("open store");
        let session_id =
            create_session(&mut store, &clock, &ids, ownership).expect("create session");

        {
            let transaction = store.connection.transaction().expect("begin transaction");
            {
                let mut insert = transaction
                    .prepare(
                        "INSERT INTO journal_event (\
                            event_id, aggregate_kind, aggregate_id, aggregate_sequence, \
                            event_type, event_version, occurred_at_ms, correlation_id, payload_json\
                         ) VALUES (?1, 'session', ?2, ?3, 'test.synthetic', 1, ?4, ?5, '{}')",
                    )
                    .expect("prepare synthetic history insert");
                for sequence in 2..=HISTORICAL_EVENTS + 1 {
                    insert
                        .execute(params![
                            ids.generate_event_id().to_string(),
                            session_id.to_string(),
                            i64::try_from(sequence).expect("sequence fits SQLite"),
                            now + i64::try_from(sequence).expect("timestamp fits SQLite"),
                            ids.generate_correlation_id().to_string(),
                        ])
                        .expect("insert synthetic history");
                }
            }
            transaction.commit().expect("commit synthetic history");
        }

        let progress_callbacks = Arc::new(AtomicUsize::new(0));
        let callback_counter = Arc::clone(&progress_callbacks);
        store
            .connection
            .progress_handler(
                PROGRESS_GRANULARITY,
                Some(move || {
                    callback_counter.fetch_add(1, Ordering::Relaxed);
                    false
                }),
            )
            .expect("install progress handler");
        let watermark = high_watermark(&store.connection, session_id).expect("query watermark");
        let page = query_timeline(
            &store,
            TimelineQuery {
                session_id,
                ownership,
                after: Some(TimelineCursor(
                    u64::try_from(HISTORICAL_EVENTS).expect("cursor fits u64"),
                )),
                limit: 100,
            },
        )
        .expect("query latest timeline page");
        store
            .connection
            .progress_handler(0, None::<fn() -> bool>)
            .expect("remove progress handler");

        assert_eq!(
            watermark,
            TimelineCursor(u64::try_from(HISTORICAL_EVENTS + 1).expect("cursor fits u64"))
        );
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].cursor, watermark);
        assert!(
            progress_callbacks.load(Ordering::Relaxed) <= MAX_PROGRESS_CALLBACKS,
            "latest-cursor and timeline-page lookups must seek from recent presentation rows"
        );
    }
}
