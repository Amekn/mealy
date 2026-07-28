use crate::{Clock, IdGenerator, OwnershipContext, ProviderSelection};
use mealy_domain::{CorrelationId, EventId, SessionId};
use std::time::SystemTime;
use thiserror::Error;

/// Revision-fenced command to change the default route for future new session turns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateSessionProviderSelectionCommand {
    /// Target session.
    pub session_id: SessionId,
    /// Exact authenticated owner and channel binding.
    pub ownership: OwnershipContext,
    /// Revision observed before the update.
    pub expected_revision: u64,
    /// Exact configured provider/model, or `None` to restore compatible automatic routing.
    pub selection: Option<ProviderSelection>,
}

/// Complete atomic persistence input for a session provider-selection update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateSessionProviderSelectionCommit {
    /// Target session.
    pub session_id: SessionId,
    /// Exact authenticated owner and channel binding.
    pub ownership: OwnershipContext,
    /// Revision observed before the update.
    pub expected_revision: u64,
    /// Exact configured provider/model, or `None` for automatic routing.
    pub selection: Option<ProviderSelection>,
    /// Immutable `session.provider_selection_updated` event.
    pub event_id: EventId,
    /// Command/event correlation.
    pub correlation_id: CorrelationId,
    /// Application-assigned commit time.
    pub updated_at: SystemTime,
}

/// Canonical current default route for future new turns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionProviderSelectionView {
    /// Owning session.
    pub session_id: SessionId,
    /// Exact selected provider/model, or `None` for automatic routing.
    pub selection: Option<ProviderSelection>,
    /// Current session revision.
    pub revision: u64,
    /// Event that established the current exact selection, when present.
    pub event_id: Option<EventId>,
    /// Time at which the current selection became effective.
    pub updated_at: SystemTime,
}

/// Persistence failures for session-scoped provider selection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderSelectionStoreError {
    /// Session does not exist.
    #[error("session was not found")]
    SessionNotFound,
    /// Exact principal/channel binding does not own the session.
    #[error("session access is unauthorized")]
    Unauthorized,
    /// Optimistic-concurrency state changed.
    #[error("session revision conflicts with canonical state")]
    Conflict,
    /// Persistence dependency failed.
    #[error("provider selection store is unavailable: {0}")]
    Unavailable(String),
    /// Stored evidence violates the contract.
    #[error("provider selection store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Atomic canonical session provider-selection persistence boundary.
pub trait ProviderSelectionStore {
    /// Reads the current exact default, or automatic routing, for one exact owner binding.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderSelectionStoreError`] on authorization or persistence failure.
    fn session_provider_selection(
        &self,
        session_id: SessionId,
        ownership: OwnershipContext,
    ) -> Result<SessionProviderSelectionView, ProviderSelectionStoreError>;

    /// Updates selection, revision, and journal in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderSelectionStoreError`] on authorization, conflict, or persistence failure.
    fn update_session_provider_selection(
        &mut self,
        commit: UpdateSessionProviderSelectionCommit,
    ) -> Result<SessionProviderSelectionView, ProviderSelectionStoreError>;
}

/// Validation or persistence rejection for provider-selection commands.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderSelectionUseCaseError {
    /// The exact provider or model identity is malformed.
    #[error("provider selection is invalid")]
    InvalidSelection,
    /// Persistence rejected the operation.
    #[error(transparent)]
    Store(#[from] ProviderSelectionStoreError),
}

/// Reads one session's canonical provider-selection default.
///
/// # Errors
///
/// Returns [`ProviderSelectionUseCaseError`] when authorization or persistence fails.
pub fn query_session_provider_selection(
    store: &impl ProviderSelectionStore,
    session_id: SessionId,
    ownership: OwnershipContext,
) -> Result<SessionProviderSelectionView, ProviderSelectionUseCaseError> {
    store
        .session_provider_selection(session_id, ownership)
        .map_err(Into::into)
}

/// Updates the default route for future new turns under a session-revision fence.
///
/// # Errors
///
/// Returns [`ProviderSelectionUseCaseError`] before persistence for unsafe identities, or after
/// any atomic storage rejection.
pub fn update_session_provider_selection(
    store: &mut impl ProviderSelectionStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    command: UpdateSessionProviderSelectionCommand,
) -> Result<SessionProviderSelectionView, ProviderSelectionUseCaseError> {
    if command
        .selection
        .as_ref()
        .is_some_and(|selection| !selection.is_valid())
    {
        return Err(ProviderSelectionUseCaseError::InvalidSelection);
    }
    store
        .update_session_provider_selection(UpdateSessionProviderSelectionCommit {
            session_id: command.session_id,
            ownership: command.ownership,
            expected_revision: command.expected_revision,
            selection: command.selection,
            event_id: ids.generate_event_id(),
            correlation_id: ids.generate_correlation_id(),
            updated_at: clock.now(),
        })
        .map_err(Into::into)
}
