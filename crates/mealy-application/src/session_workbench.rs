use crate::{Clock, IdGenerator, OwnershipContext};
use mealy_domain::{
    ContextEpochId, CorrelationId, EventId, SessionCheckpointId, SessionId, TurnId,
};
use std::time::SystemTime;
use thiserror::Error;

/// Maximum UTF-8 bytes in an owner title or checkpoint label.
pub const SESSION_METADATA_MAXIMUM_BYTES: usize = 160;
/// Maximum Unicode scalar values in an owner title or checkpoint label.
pub const SESSION_METADATA_MAXIMUM_CHARACTERS: usize = 72;
/// Maximum UTF-8 bytes in a durable fork command idempotency key.
pub const SESSION_FORK_IDEMPOTENCY_KEY_MAXIMUM_BYTES: usize = 128;

/// Revision-fenced command to set a canonical owner title.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateSessionTitleCommand {
    /// Target session.
    pub session_id: SessionId,
    /// Exact authenticated owner and binding.
    pub ownership: OwnershipContext,
    /// Revision observed before the command.
    pub expected_revision: u64,
    /// Bounded terminal-safe owner title.
    pub title: String,
}

/// Complete atomic persistence input for a canonical title update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateSessionTitleCommit {
    /// Target session.
    pub session_id: SessionId,
    /// Exact authenticated owner and binding.
    pub ownership: OwnershipContext,
    /// Revision observed before the command.
    pub expected_revision: u64,
    /// Validated title.
    pub title: String,
    /// Immutable journal event.
    pub event_id: EventId,
    /// Command/event correlation.
    pub correlation_id: CorrelationId,
    /// Application-assigned transaction time.
    pub updated_at: SystemTime,
}

/// Durable result of a title update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTitleReceipt {
    /// Updated session.
    pub session_id: SessionId,
    /// Canonical title.
    pub title: String,
    /// Revision after the update.
    pub revision: u64,
    /// Immutable journal fact.
    pub event_id: EventId,
    /// Committed transaction time.
    pub updated_at: SystemTime,
}

/// Revision-fenced command to capture one quiescent session boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateSessionCheckpointCommand {
    /// Target session.
    pub session_id: SessionId,
    /// Exact authenticated owner and binding.
    pub ownership: OwnershipContext,
    /// Revision observed before the command.
    pub expected_revision: u64,
    /// Optional bounded owner label.
    pub label: Option<String>,
}

/// Complete atomic persistence input for a checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateSessionCheckpointCommit {
    /// Immutable checkpoint identity.
    pub checkpoint_id: SessionCheckpointId,
    /// Target session.
    pub session_id: SessionId,
    /// Exact authenticated owner and binding.
    pub ownership: OwnershipContext,
    /// Revision observed before the command.
    pub expected_revision: u64,
    /// Optional validated owner label.
    pub label: Option<String>,
    /// Immutable journal event.
    pub event_id: EventId,
    /// Command/event correlation.
    pub correlation_id: CorrelationId,
    /// Application-assigned transaction time.
    pub created_at: SystemTime,
}

/// Immutable exact-bound checkpoint projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCheckpointView {
    /// Checkpoint identity.
    pub checkpoint_id: SessionCheckpointId,
    /// Owning session.
    pub session_id: SessionId,
    /// Timeline high watermark immediately before checkpoint creation.
    pub source_cursor: u64,
    /// Latest completed canonical turn, when one exists.
    pub source_turn_id: Option<TurnId>,
    /// Exact context epoch, when the session has initialized one.
    pub context_epoch_id: Option<ContextEpochId>,
    /// Session revision captured before checkpoint creation.
    pub source_session_revision: u64,
    /// Context configuration digest, when initialized.
    pub config_digest: Option<String>,
    /// Context policy digest, when initialized.
    pub policy_digest: Option<String>,
    /// Provider-neutral workspace identity, when initialized.
    pub workspace_identity: Option<String>,
    /// Digest binding owner, channel, and workspace identity at capture.
    pub workspace_authority_digest: String,
    /// Provider used by the source turn's latest model attempt.
    pub provider_id: Option<String>,
    /// Model used by the source turn's latest model attempt.
    pub model_id: Option<String>,
    /// Optional owner label.
    pub label: Option<String>,
    /// Immutable journal fact.
    pub event_id: EventId,
    /// Revision after checkpoint creation.
    pub revision: u64,
    /// Committed creation time.
    pub created_at: SystemTime,
}

/// Idempotent command to create a fresh session from one immutable checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkSessionCommand {
    /// Source session named by the authenticated route.
    pub source_session_id: SessionId,
    /// Immutable source checkpoint.
    pub checkpoint_id: SessionCheckpointId,
    /// Exact authenticated owner and binding.
    pub ownership: OwnershipContext,
    /// Stable caller key for duplicate-safe retry.
    pub idempotency_key: String,
}

/// Complete atomic persistence input for a session fork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkSessionCommit {
    /// Fresh child session identity.
    pub fork_session_id: SessionId,
    /// Source session named by the authenticated route.
    pub source_session_id: SessionId,
    /// Immutable source checkpoint.
    pub checkpoint_id: SessionCheckpointId,
    /// Exact authenticated owner and binding.
    pub ownership: OwnershipContext,
    /// Validated duplicate-safe caller key.
    pub idempotency_key: String,
    /// Immutable `session.forked` journal event.
    pub event_id: EventId,
    /// Command/event correlation.
    pub correlation_id: CorrelationId,
    /// Application-assigned transaction time.
    pub created_at: SystemTime,
}

/// Durable result of creating or replaying one session fork command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionForkReceipt {
    /// Fresh child session.
    pub fork_session_id: SessionId,
    /// Lineage root shared with the source session.
    pub root_session_id: SessionId,
    /// Immediate source session that owns the checkpoint.
    pub source_session_id: SessionId,
    /// Immutable parent checkpoint.
    pub source_checkpoint_id: SessionCheckpointId,
    /// Count of successful conversation pairs referenced by the child.
    pub referenced_turns: u64,
    /// Immutable fork event.
    pub event_id: EventId,
    /// Original command/event correlation.
    pub correlation_id: CorrelationId,
    /// Original commit time.
    pub created_at: SystemTime,
    /// Whether this call returned the original receipt for the same command key.
    pub duplicate: bool,
}

/// Persistence failures for canonical session-workbench mutations and queries.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SessionWorkbenchStoreError {
    /// Session does not exist.
    #[error("session was not found")]
    SessionNotFound,
    /// Checkpoint does not exist.
    #[error("session checkpoint was not found")]
    CheckpointNotFound,
    /// Checkpoint precedes the currently retained timeline boundary.
    #[error("session checkpoint is outside the retained timeline")]
    CheckpointNotRetained,
    /// Exact principal/channel binding does not own the session.
    #[error("session access is unauthorized")]
    Unauthorized,
    /// Optimistic-concurrency state changed.
    #[error("session revision conflicts with canonical state")]
    Conflict,
    /// A fork command key was already bound to a different checkpoint.
    #[error("session fork idempotency key conflicts with its original command")]
    IdempotencyConflict,
    /// Checkpoints are accepted only at a quiescent canonical boundary.
    #[error("session is not at a quiescent checkpoint boundary")]
    NotQuiescent,
    /// Persistence dependency failed.
    #[error("session workbench store is unavailable: {0}")]
    Unavailable(String),
    /// Stored evidence violates the contract.
    #[error("session workbench invariant violation: {0}")]
    InvariantViolation(String),
}

/// Atomic canonical session-workbench persistence boundary.
pub trait SessionWorkbenchStore {
    /// Updates owner title, revision, and journal in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`SessionWorkbenchStoreError`] on authorization, conflict, or persistence failure.
    fn update_session_title(
        &mut self,
        commit: UpdateSessionTitleCommit,
    ) -> Result<SessionTitleReceipt, SessionWorkbenchStoreError>;

    /// Captures a quiescent checkpoint and its journal fact in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`SessionWorkbenchStoreError`] on authorization, conflict, unsafe boundary, or
    /// persistence failure.
    fn create_session_checkpoint(
        &mut self,
        commit: CreateSessionCheckpointCommit,
    ) -> Result<SessionCheckpointView, SessionWorkbenchStoreError>;

    /// Lists bounded newest-first immutable checkpoints for one exact owner binding.
    ///
    /// # Errors
    ///
    /// Returns [`SessionWorkbenchStoreError`] on authorization, invalid evidence, or persistence
    /// failure.
    fn session_checkpoints(
        &self,
        session_id: SessionId,
        ownership: OwnershipContext,
        limit: usize,
    ) -> Result<Vec<SessionCheckpointView>, SessionWorkbenchStoreError>;

    /// Creates a fresh child session and immutable conversation references atomically.
    ///
    /// # Errors
    ///
    /// Returns [`SessionWorkbenchStoreError`] on authorization, conflicting duplicate command,
    /// invalid source evidence, or persistence failure.
    fn fork_session(
        &mut self,
        commit: ForkSessionCommit,
    ) -> Result<SessionForkReceipt, SessionWorkbenchStoreError>;
}

/// Validation or persistence rejection for session-workbench commands.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SessionWorkbenchUseCaseError {
    /// Owner title or checkpoint label is empty, padded, unsafe, or exceeds its bounds.
    #[error("session title or checkpoint label is invalid")]
    InvalidMetadata,
    /// Checkpoint list limit must be one through 100.
    #[error("session checkpoint limit must be between 1 and 100")]
    InvalidLimit,
    /// Fork command key is empty, padded, unsafe, or exceeds its bound.
    #[error("session fork idempotency key is invalid")]
    InvalidIdempotencyKey,
    /// Persistence rejected the operation.
    #[error(transparent)]
    Store(#[from] SessionWorkbenchStoreError),
}

/// Sets an owner title under an optimistic-concurrency fence.
///
/// # Errors
///
/// Returns [`SessionWorkbenchUseCaseError`] before persistence for unsafe text or after any
/// atomic storage rejection.
pub fn update_session_title(
    store: &mut impl SessionWorkbenchStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    command: UpdateSessionTitleCommand,
) -> Result<SessionTitleReceipt, SessionWorkbenchUseCaseError> {
    if !valid_session_metadata(&command.title) {
        return Err(SessionWorkbenchUseCaseError::InvalidMetadata);
    }
    store
        .update_session_title(UpdateSessionTitleCommit {
            session_id: command.session_id,
            ownership: command.ownership,
            expected_revision: command.expected_revision,
            title: command.title,
            event_id: ids.generate_event_id(),
            correlation_id: ids.generate_correlation_id(),
            updated_at: clock.now(),
        })
        .map_err(Into::into)
}

/// Captures an immutable checkpoint at a quiescent canonical boundary.
///
/// # Errors
///
/// Returns [`SessionWorkbenchUseCaseError`] for unsafe labels or storage rejection.
pub fn create_session_checkpoint(
    store: &mut impl SessionWorkbenchStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    command: CreateSessionCheckpointCommand,
) -> Result<SessionCheckpointView, SessionWorkbenchUseCaseError> {
    if command
        .label
        .as_deref()
        .is_some_and(|label| !valid_session_metadata(label))
    {
        return Err(SessionWorkbenchUseCaseError::InvalidMetadata);
    }
    store
        .create_session_checkpoint(CreateSessionCheckpointCommit {
            checkpoint_id: ids.generate_session_checkpoint_id(),
            session_id: command.session_id,
            ownership: command.ownership,
            expected_revision: command.expected_revision,
            label: command.label,
            event_id: ids.generate_event_id(),
            correlation_id: ids.generate_correlation_id(),
            created_at: clock.now(),
        })
        .map_err(Into::into)
}

/// Lists immutable checkpoints for one exact owner binding.
///
/// # Errors
///
/// Returns [`SessionWorkbenchUseCaseError`] for invalid bounds or storage rejection.
pub fn query_session_checkpoints(
    store: &impl SessionWorkbenchStore,
    session_id: SessionId,
    ownership: OwnershipContext,
    limit: usize,
) -> Result<Vec<SessionCheckpointView>, SessionWorkbenchUseCaseError> {
    if !(1..=100).contains(&limit) {
        return Err(SessionWorkbenchUseCaseError::InvalidLimit);
    }
    store
        .session_checkpoints(session_id, ownership, limit)
        .map_err(Into::into)
}

/// Creates or exactly replays a durable session fork from one immutable checkpoint.
///
/// # Errors
///
/// Returns [`SessionWorkbenchUseCaseError`] for an invalid command key or any atomic storage
/// rejection.
pub fn fork_session(
    store: &mut impl SessionWorkbenchStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    command: ForkSessionCommand,
) -> Result<SessionForkReceipt, SessionWorkbenchUseCaseError> {
    if !valid_fork_idempotency_key(&command.idempotency_key) {
        return Err(SessionWorkbenchUseCaseError::InvalidIdempotencyKey);
    }
    store
        .fork_session(ForkSessionCommit {
            fork_session_id: ids.generate_session_id(),
            source_session_id: command.source_session_id,
            checkpoint_id: command.checkpoint_id,
            ownership: command.ownership,
            idempotency_key: command.idempotency_key,
            event_id: ids.generate_event_id(),
            correlation_id: ids.generate_correlation_id(),
            created_at: clock.now(),
        })
        .map_err(Into::into)
}

/// Returns whether owner-visible session metadata is bounded and safe for terminal/web display.
#[must_use]
pub fn valid_session_metadata(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= SESSION_METADATA_MAXIMUM_BYTES
        && value.chars().count() <= SESSION_METADATA_MAXIMUM_CHARACTERS
        && !value.chars().any(unsafe_metadata_character)
}

/// Returns whether a fork command key is canonical, bounded, and safe to persist.
#[must_use]
pub fn valid_fork_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= SESSION_FORK_IDEMPOTENCY_KEY_MAXIMUM_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn unsafe_metadata_character(character: char) -> bool {
    let codepoint = u32::from(character);
    character.is_control()
        || matches!(
            codepoint,
            0x061c
                | 0x200b..=0x200f
                | 0x2028..=0x202e
                | 0x2060..=0x206f
                | 0xfeff
        )
}

#[cfg(test)]
mod tests {
    use super::{valid_fork_idempotency_key, valid_session_metadata};

    #[test]
    fn session_metadata_rejects_padding_controls_bidi_and_oversize_text() {
        assert!(valid_session_metadata("Release planning"));
        assert!(!valid_session_metadata(""));
        assert!(!valid_session_metadata(" padded"));
        assert!(!valid_session_metadata("line\nbreak"));
        assert!(!valid_session_metadata("unsafe\u{202e}title"));
        assert!(!valid_session_metadata(&"界".repeat(73)));
    }

    #[test]
    fn fork_idempotency_key_is_ascii_canonical_and_bounded() {
        assert!(valid_fork_idempotency_key("mealyctl:019f-fork.retry_1"));
        assert!(!valid_fork_idempotency_key(""));
        assert!(!valid_fork_idempotency_key(" padded"));
        assert!(!valid_fork_idempotency_key("contains/slash"));
        assert!(!valid_fork_idempotency_key(&"x".repeat(129)));
    }
}
