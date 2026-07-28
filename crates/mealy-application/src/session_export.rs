use crate::{ArtifactContentDescriptor, OwnershipContext, TimelineCursor};
use mealy_domain::{
    ContextEpochId, EventId, InboxEntryId, MessageId, RunId, SessionCheckpointId, SessionId,
    TaskId, TurnId,
};
use std::time::SystemTime;
use thiserror::Error;

/// Maximum successful canonical conversation pairs included in one transcript export.
pub const SESSION_TRANSCRIPT_MAXIMUM_TURNS: usize = 1_000;
/// Maximum combined UTF-8 user and assistant content bytes included in one transcript export.
pub const SESSION_TRANSCRIPT_MAXIMUM_CONTENT_BYTES: u64 = 4 * 1024 * 1024;

/// Immutable lineage evidence included with an owner-authorized transcript snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTranscriptLineage {
    /// Root of this session's lineage.
    pub root_session_id: SessionId,
    /// Immediate source session for a fork, when applicable.
    pub parent_session_id: Option<SessionId>,
    /// Immutable checkpoint that created this fork, when applicable.
    pub parent_checkpoint_id: Option<SessionCheckpointId>,
    /// Source cursor captured by the parent checkpoint.
    pub parent_checkpoint_cursor: Option<TimelineCursor>,
    /// Immutable `session.forked` event, when applicable.
    pub fork_event_id: Option<EventId>,
}

/// User-side transcript evidence tied to its durable admission fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTranscriptUserMessage {
    /// Durable admitted input identity.
    pub inbox_entry_id: InboxEntryId,
    /// Verbatim owner-visible UTF-8 content.
    pub content: String,
    /// SHA-256 digest of the exact UTF-8 bytes.
    pub content_digest: String,
    /// Exact UTF-8 byte count.
    pub byte_length: u64,
    /// Immutable admission journal event.
    pub admission_event_id: EventId,
    /// Timeline cursor of the admission event.
    pub admission_cursor: TimelineCursor,
    /// Canonical admission time.
    pub accepted_at: SystemTime,
}

/// Assistant-side transcript evidence tied to a terminal canonical run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTranscriptAssistantMessage {
    /// Durable terminal message identity.
    pub message_id: MessageId,
    /// Bounded inline content, or `None` when content is artifact-backed.
    pub content_inline: Option<String>,
    /// Authorized path-private descriptor, or `None` when content is inline.
    pub content_artifact: Option<ArtifactContentDescriptor>,
    /// SHA-256 digest of the exact logical content bytes.
    pub content_digest: String,
    /// Exact logical content byte count.
    pub byte_length: u64,
    /// Declared media type.
    pub media_type: String,
    /// Stable sensitivity classification.
    pub sensitivity: String,
    /// Canonical message commit time.
    pub created_at: SystemTime,
}

/// One successful canonical user/assistant conversation pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTranscriptTurn {
    /// Stable session inbox order.
    pub sequence: u64,
    /// Canonical turn identity.
    pub turn_id: TurnId,
    /// Canonical task identity.
    pub task_id: TaskId,
    /// Canonical run identity.
    pub run_id: RunId,
    /// Context epoch used by this turn.
    pub context_epoch_id: ContextEpochId,
    /// Provider used by the final completed model attempt.
    pub provider_id: String,
    /// Model used by the final completed model attempt.
    pub model_id: String,
    /// Owner input and admission citation.
    pub user: SessionTranscriptUserMessage,
    /// Final assistant response and content evidence.
    pub assistant: SessionTranscriptAssistantMessage,
    /// Immutable terminal turn event.
    pub completion_event_id: EventId,
    /// Timeline cursor of the terminal turn event.
    pub completion_cursor: TimelineCursor,
    /// Canonical turn completion time.
    pub completed_at: SystemTime,
}

/// One coherent bounded owner-authorized canonical transcript snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTranscriptSnapshot {
    /// Exported session.
    pub session_id: SessionId,
    /// Canonical owner title or deterministic derived title.
    pub title: String,
    /// Stable title source: `owner` or `derived`.
    pub title_source: String,
    /// Canonical session lifecycle state.
    pub status: String,
    /// Canonical session revision.
    pub revision: u64,
    /// Session creation time.
    pub created_at: SystemTime,
    /// Latest canonical session update time.
    pub updated_at: SystemTime,
    /// Highest session-visible cursor in this read snapshot.
    pub high_watermark: TimelineCursor,
    /// Immutable lineage evidence.
    pub lineage: SessionTranscriptLineage,
    /// Total successful canonical conversation pairs visible at the snapshot boundary.
    pub total_eligible_turns: u64,
    /// Older eligible pairs omitted to preserve the fixed turn/content bounds.
    pub omitted_turns: u64,
    /// Combined exact content bytes represented in `turns`.
    pub included_content_bytes: u64,
    /// Oldest included inbox sequence, absent for an empty transcript.
    pub oldest_included_sequence: Option<u64>,
    /// Ordered successful canonical conversation pairs.
    pub turns: Vec<SessionTranscriptTurn>,
}

/// Persistence failures for canonical transcript snapshots.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SessionTranscriptStoreError {
    /// Session is absent or deliberately hidden from the supplied owner and channel.
    #[error("session transcript was not found")]
    NotFound,
    /// Persistence dependency failed.
    #[error("session transcript store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical evidence violates the transcript contract.
    #[error("session transcript invariant violation: {0}")]
    InvariantViolation(String),
}

/// Read-only owner-authorized canonical transcript boundary.
pub trait SessionTranscriptStore {
    /// Loads one coherent bounded snapshot of successful canonical conversation pairs.
    ///
    /// # Errors
    ///
    /// Returns [`SessionTranscriptStoreError`] when the session is absent/unauthorized,
    /// persistence fails, or stored evidence is inconsistent.
    fn session_transcript_snapshot(
        &self,
        session_id: SessionId,
        ownership: OwnershipContext,
    ) -> Result<SessionTranscriptSnapshot, SessionTranscriptStoreError>;
}

/// Loads one bounded canonical transcript snapshot through the application port.
///
/// # Errors
///
/// Returns [`SessionTranscriptStoreError`] for authorization, persistence, or invariant failure.
pub fn query_session_transcript(
    store: &impl SessionTranscriptStore,
    session_id: SessionId,
    ownership: OwnershipContext,
) -> Result<SessionTranscriptSnapshot, SessionTranscriptStoreError> {
    store.session_transcript_snapshot(session_id, ownership)
}
