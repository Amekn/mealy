use crate::OwnershipContext;
use mealy_domain::{
    AutomationId, AutomationRunId, CorrelationId, EventId, InboxEntryId, OutboxId, SessionId,
    WorkerId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum UTF-8 bytes in an owner-visible automation name.
pub const MAXIMUM_AUTOMATION_NAME_BYTES: usize = 128;
/// Maximum UTF-8 bytes in a static notification body.
pub const MAXIMUM_AUTOMATION_MESSAGE_BYTES: usize = 4_096;
/// Maximum UTF-8 bytes admitted as a scheduled agent input.
pub const MAXIMUM_AUTOMATION_PROMPT_BYTES: usize = 64 * 1_024;
/// Maximum bytes in an exact canonical journal event type.
pub const MAXIMUM_AUTOMATION_EVENT_TYPE_BYTES: usize = 128;
/// Maximum future horizon for a newly created or edited one-shot trigger.
pub const MAXIMUM_AUTOMATION_ONE_SHOT_HORIZON_MS: i64 = 366 * 24 * 60 * 60 * 1_000;

/// Owner-visible automation lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationStatus {
    /// Trigger occurrences may be claimed.
    Active,
    /// Definition and history remain while claims are disabled.
    Paused,
    /// A one-shot trigger reached a terminal outcome.
    Completed,
    /// Owner terminally disabled the definition.
    Cancelled,
}

/// Trigger definition accepted from an authenticated owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AutomationTrigger {
    /// Fire once at or after an exact UTC epoch-millisecond instant.
    OneShot {
        /// Exact due instant.
        due_at_ms: i64,
    },
    /// Observe future direct session-aggregate events with one exact type.
    SessionEvent {
        /// Existing same-principal source session.
        source_session_id: SessionId,
        /// Exact canonical journal event type, such as `turn.completed`.
        event_type: String,
    },
}

/// Stored trigger state, including the non-replay event cursor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AutomationTriggerView {
    /// Fire once at or after an exact UTC epoch-millisecond instant.
    OneShot {
        /// Exact due instant.
        due_at_ms: i64,
    },
    /// Observe future direct session-aggregate events after an exclusive cursor.
    SessionEvent {
        /// Existing same-principal source session.
        source_session_id: SessionId,
        /// Exact canonical journal event type.
        event_type: String,
        /// Exclusive global timeline cursor. Events at or below it are never replayed.
        after_cursor: u64,
    },
}

/// Bounded action executed for one claimed trigger occurrence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AutomationAction {
    /// Admit a deterministic prompt through the existing durable session inbox.
    SubmitPrompt {
        /// Existing same-principal destination session.
        target_session_id: SessionId,
        /// Exact content admitted for the occurrence.
        prompt: String,
        /// Explicit owner opt-in when the prompt selects an approval-required action mode.
        approval_required_actions_allowed: bool,
    },
    /// Enqueue a static notification through the destination session's revocable channel.
    Notify {
        /// Existing same-principal destination session.
        target_session_id: SessionId,
        /// Owner-authored bounded notification text.
        message: String,
    },
}

impl AutomationAction {
    /// Returns the exact session that receives the action.
    #[must_use]
    pub const fn target_session_id(&self) -> SessionId {
        match self {
            Self::SubmitPrompt {
                target_session_id, ..
            }
            | Self::Notify {
                target_session_id, ..
            } => *target_session_id,
        }
    }
}

/// Canonical owner-authorized automation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationView {
    /// Stable automation identity.
    pub automation_id: AutomationId,
    /// Exact management principal and binding.
    pub manager_ownership: OwnershipContext,
    /// Exact target session ownership, which may use another binding of the same principal.
    pub target_ownership: OwnershipContext,
    /// Bounded owner-visible label.
    pub name: String,
    /// Stored trigger and runtime cursor.
    pub trigger: AutomationTriggerView,
    /// Bounded action.
    pub action: AutomationAction,
    /// Current lifecycle.
    pub status: AutomationStatus,
    /// Optimistic-concurrency and runtime-cursor revision.
    pub revision: u64,
    /// Creation UTC epoch milliseconds.
    pub created_at_ms: i64,
    /// Last definition or runtime transition UTC epoch milliseconds.
    pub updated_at_ms: i64,
}

/// Lifecycle of one trigger occurrence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationRunStatus {
    /// One daemon lifetime owns the bounded execution attempt.
    Claimed,
    /// The deterministic prompt was accepted or already present.
    Admitted,
    /// A durable notification outbox row was created.
    Notified,
    /// A terminal bounded action failure was recorded.
    Failed,
}

/// Durable history projection for one trigger occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationRunView {
    /// Stable occurrence identity.
    pub automation_run_id: AutomationRunId,
    /// Owning automation.
    pub automation_id: AutomationId,
    /// Stable trigger key (`time:<millis>` or `event:<cursor>`).
    pub trigger_key: String,
    /// One-shot due instant when time-triggered.
    pub triggered_at_ms: i64,
    /// Direct source event cursor when event-triggered.
    pub source_event_cursor: Option<u64>,
    /// Direct source journal event identity when event-triggered.
    pub source_event_id: Option<EventId>,
    /// Exact source event type when event-triggered.
    pub source_event_type: Option<String>,
    /// Current occurrence lifecycle.
    pub status: AutomationRunStatus,
    /// Accepted inbox entry for a prompt action.
    pub inbox_entry_id: Option<InboxEntryId>,
    /// Durable notification outbox row for a notification action.
    pub outbox_id: Option<OutboxId>,
    /// Stable bounded terminal failure classification.
    pub reason: Option<String>,
    /// First claim UTC epoch milliseconds.
    pub created_at_ms: i64,
    /// Terminal UTC epoch milliseconds.
    pub completed_at_ms: Option<i64>,
}

/// Trusted-driver candidate carrying the exact unconsumed trigger occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationCandidate {
    /// Current canonical automation snapshot.
    pub automation: AutomationView,
    /// Stable occurrence key.
    pub trigger_key: String,
    /// One-shot due instant or source event occurrence instant.
    pub triggered_at_ms: i64,
    /// Source cursor for an event trigger.
    pub source_event_cursor: Option<u64>,
    /// Source journal event for an event trigger.
    pub source_event_id: Option<EventId>,
    /// Exact event type for an event trigger.
    pub source_event_type: Option<String>,
}

/// Complete atomic automation creation evidence.
pub struct CreateAutomationCommit {
    /// New stable identity.
    pub automation_id: AutomationId,
    /// Authenticated management principal and binding.
    pub manager_ownership: OwnershipContext,
    /// Owner-visible label.
    pub name: String,
    /// Trigger definition.
    pub trigger: AutomationTrigger,
    /// Action definition.
    pub action: AutomationAction,
    /// Canonical creation event.
    pub event_id: EventId,
    /// Command correlation identity.
    pub correlation_id: CorrelationId,
    /// Creation UTC epoch milliseconds.
    pub created_at_ms: i64,
}

/// Editable automation definition under an optimistic revision fence.
pub struct EditAutomationCommit {
    /// Target automation.
    pub automation_id: AutomationId,
    /// Authenticated management principal and binding.
    pub manager_ownership: OwnershipContext,
    /// Exact observed revision.
    pub expected_revision: u64,
    /// Replacement owner-visible label.
    pub name: String,
    /// Replacement trigger. Event triggers start after the edit transaction's high watermark.
    pub trigger: AutomationTrigger,
    /// Replacement action.
    pub action: AutomationAction,
    /// Canonical edit event.
    pub event_id: EventId,
    /// Command correlation identity.
    pub correlation_id: CorrelationId,
    /// Edit UTC epoch milliseconds.
    pub edited_at_ms: i64,
}

/// Owner lifecycle command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomationTransition {
    /// Disable claims without changing trigger state.
    Pause,
    /// Re-enable claims without replaying events observed while paused.
    Resume,
    /// Terminally disable the definition.
    Cancel,
}

/// Complete atomic lifecycle transition evidence.
pub struct TransitionAutomationCommit {
    /// Target automation.
    pub automation_id: AutomationId,
    /// Authenticated management principal and binding.
    pub manager_ownership: OwnershipContext,
    /// Exact observed revision.
    pub expected_revision: u64,
    /// Requested transition.
    pub transition: AutomationTransition,
    /// Canonical transition event.
    pub event_id: EventId,
    /// Command correlation identity.
    pub correlation_id: CorrelationId,
    /// Transition UTC epoch milliseconds.
    pub transitioned_at_ms: i64,
}

/// One crash-recoverable trigger claim.
pub struct ClaimAutomationRunCommit {
    /// Candidate automation.
    pub automation_id: AutomationId,
    /// Observed revision.
    pub expected_revision: u64,
    /// Exact candidate trigger key.
    pub trigger_key: String,
    /// One-shot due instant or event occurrence instant.
    pub triggered_at_ms: i64,
    /// Exact source cursor for an event trigger.
    pub source_event_cursor: Option<u64>,
    /// Exact source event for an event trigger.
    pub source_event_id: Option<EventId>,
    /// Exact source event type for an event trigger.
    pub source_event_type: Option<String>,
    /// New identity when no prior claim exists.
    pub proposed_automation_run_id: AutomationRunId,
    /// Claiming daemon lifetime.
    pub owner_id: WorkerId,
    /// Claim time.
    pub claimed_at_ms: i64,
    /// Exclusive claim expiry.
    pub claim_expires_at_ms: i64,
}

/// Result of an exact occurrence claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomationClaimOutcome {
    /// Caller owns the returned new or expired claim.
    Claimed(Box<AutomationRunView>),
    /// Another claim, revision, or lifecycle transition won.
    Busy,
}

/// Atomic terminal outcome and trigger-cursor advancement evidence.
pub struct CompleteAutomationRunCommit {
    /// Owning automation.
    pub automation_id: AutomationId,
    /// Exact claimed occurrence.
    pub automation_run_id: AutomationRunId,
    /// Claiming daemon lifetime.
    pub owner_id: WorkerId,
    /// Terminal status; `Claimed` is rejected.
    pub status: AutomationRunStatus,
    /// Accepted inbox entry for `Admitted`.
    pub inbox_entry_id: Option<InboxEntryId>,
    /// Proposed outbox identity for `Notified`.
    pub outbox_id: Option<OutboxId>,
    /// Stable bounded reason for `Failed`.
    pub reason: Option<String>,
    /// Canonical terminal outcome event.
    pub event_id: EventId,
    /// Correlation identity for the driver action.
    pub correlation_id: CorrelationId,
    /// Completion UTC epoch milliseconds.
    pub completed_at_ms: i64,
}

/// Automation administration and driver persistence failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AutomationStoreError {
    /// Automation is absent or deliberately hidden.
    #[error("automation was not found")]
    NotFound,
    /// Principal or binding is not authorized for this automation/session.
    #[error("automation access is unauthorized")]
    Unauthorized,
    /// Revision, claim, uniqueness, or lifecycle conflict.
    #[error("automation operation conflicts with canonical state")]
    Conflict,
    /// Proposed contract is invalid.
    #[error("automation contract is invalid: {0}")]
    InvalidContract(String),
    /// Persistence dependency failed.
    #[error("automation store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical evidence is corrupt.
    #[error("automation store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Canonical automation administration and crash-safe trigger port.
pub trait AutomationStore {
    /// Creates one active automation and its revision-zero evidence atomically.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError`] for invalid, unauthorized, conflicting, or unavailable
    /// state.
    fn create_automation(
        &mut self,
        commit: CreateAutomationCommit,
    ) -> Result<AutomationView, AutomationStoreError>;
    /// Reads one principal-authorized automation.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError`] when absent, unauthorized, unavailable, or corrupt.
    fn automation(
        &self,
        manager_ownership: OwnershipContext,
        automation_id: AutomationId,
    ) -> Result<AutomationView, AutomationStoreError>;
    /// Lists all automations owned by the authenticated principal.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError`] when authorization or persistence fails.
    fn automations(
        &self,
        manager_ownership: OwnershipContext,
    ) -> Result<Vec<AutomationView>, AutomationStoreError>;
    /// Replaces a definition under an exact revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError`] for invalid definition, ownership, revision, or storage.
    fn edit_automation(
        &mut self,
        commit: EditAutomationCommit,
    ) -> Result<AutomationView, AutomationStoreError>;
    /// Applies a lifecycle transition under an exact revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError`] for invalid lifecycle, ownership, revision, or storage.
    fn transition_automation(
        &mut self,
        commit: TransitionAutomationCommit,
    ) -> Result<AutomationView, AutomationStoreError>;
    /// Reads a bounded stable batch of due one-shot and direct session-event candidates.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError`] for invalid bounds or unavailable/corrupt persistence.
    fn due_automations(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<AutomationCandidate>, AutomationStoreError>;
    /// Claims or reclaims one exact trigger occurrence.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError`] for invalid evidence or unavailable/corrupt persistence.
    fn claim_automation_run(
        &mut self,
        commit: ClaimAutomationRunCommit,
    ) -> Result<AutomationClaimOutcome, AutomationStoreError>;
    /// Terminates a claim and advances its trigger cursor atomically.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError`] for stale ownership, invalid outcome, or storage failure.
    fn complete_automation_run(
        &mut self,
        commit: CompleteAutomationRunCommit,
    ) -> Result<AutomationRunView, AutomationStoreError>;
    /// Reads bounded newest-first occurrence history.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError`] for invalid bounds, authorization, or persistence failure.
    fn automation_runs(
        &self,
        manager_ownership: OwnershipContext,
        automation_id: AutomationId,
        limit: usize,
    ) -> Result<Vec<AutomationRunView>, AutomationStoreError>;
}

/// Invalid automation definition or stored projection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AutomationContractError {
    /// Name is absent, padded, controlling, or oversized.
    #[error("automation name is invalid")]
    InvalidName,
    /// One-shot instant is absent, not future, or outside the supported horizon.
    #[error("automation one-shot time is invalid")]
    InvalidOneShotTime,
    /// Event type is absent, noncanonical, or oversized.
    #[error("automation event type is invalid")]
    InvalidEventType,
    /// Prompt is absent, contains NUL, or is oversized.
    #[error("automation prompt is invalid")]
    InvalidPrompt,
    /// Approval-required prompt prefix lacks explicit owner opt-in.
    #[error("automation approval-required action needs explicit opt-in")]
    ActionOptInRequired,
    /// Notification is absent, contains NUL, or is oversized.
    #[error("automation notification is invalid")]
    InvalidNotification,
    /// Event-triggered agent submission is deliberately unsupported to prevent autonomous loops.
    #[error("session-event automations may only notify")]
    EventPromptForbidden,
    /// Stored evidence contradicts the canonical contract.
    #[error("stored automation projection is invalid")]
    InvalidView,
}

/// Validates a new/edit definition and its cross-trigger safety policy.
///
/// # Errors
///
/// Returns [`AutomationContractError`] when any field is unsafe, ambiguous, or unbounded.
pub fn validate_automation_definition(
    name: &str,
    trigger: &AutomationTrigger,
    action: &AutomationAction,
    command_at_ms: i64,
) -> Result<(), AutomationContractError> {
    validate_name(name)?;
    validate_trigger(trigger, command_at_ms)?;
    validate_action(action)?;
    if matches!(trigger, AutomationTrigger::SessionEvent { .. })
        && matches!(action, AutomationAction::SubmitPrompt { .. })
    {
        return Err(AutomationContractError::EventPromptForbidden);
    }
    Ok(())
}

/// Validates a rehydrated canonical automation snapshot.
///
/// # Errors
///
/// Returns [`AutomationContractError::InvalidView`] for contradictory persisted state.
pub fn validate_automation_view(view: &AutomationView) -> Result<(), AutomationContractError> {
    let trigger = match &view.trigger {
        AutomationTriggerView::OneShot { due_at_ms } => AutomationTrigger::OneShot {
            due_at_ms: *due_at_ms,
        },
        AutomationTriggerView::SessionEvent {
            source_session_id,
            event_type,
            ..
        } => AutomationTrigger::SessionEvent {
            source_session_id: *source_session_id,
            event_type: event_type.clone(),
        },
    };
    validate_name(&view.name)?;
    validate_action(&view.action)?;
    if matches!(trigger, AutomationTrigger::SessionEvent { .. })
        && matches!(view.action, AutomationAction::SubmitPrompt { .. })
    {
        return Err(AutomationContractError::InvalidView);
    }
    if let AutomationTrigger::SessionEvent { event_type, .. } = &trigger {
        validate_event_type(event_type)?;
    }
    if let AutomationTrigger::OneShot { due_at_ms } = trigger
        && due_at_ms < 0
    {
        return Err(AutomationContractError::InvalidView);
    }
    if view.manager_ownership.principal_id() != view.target_ownership.principal_id()
        || view.action.target_session_id()
            != match &view.action {
                AutomationAction::SubmitPrompt {
                    target_session_id, ..
                }
                | AutomationAction::Notify {
                    target_session_id, ..
                } => *target_session_id,
            }
        || view.created_at_ms < 0
        || view.updated_at_ms < view.created_at_ms
        || matches!(
            (&view.trigger, view.status),
            (
                AutomationTriggerView::SessionEvent { .. },
                AutomationStatus::Completed
            )
        )
    {
        return Err(AutomationContractError::InvalidView);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), AutomationContractError> {
    if name.is_empty()
        || name.len() > MAXIMUM_AUTOMATION_NAME_BYTES
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        Err(AutomationContractError::InvalidName)
    } else {
        Ok(())
    }
}

fn validate_trigger(
    trigger: &AutomationTrigger,
    command_at_ms: i64,
) -> Result<(), AutomationContractError> {
    if command_at_ms < 0 {
        return Err(AutomationContractError::InvalidOneShotTime);
    }
    match trigger {
        AutomationTrigger::OneShot { due_at_ms }
            if *due_at_ms > command_at_ms
                && due_at_ms.saturating_sub(command_at_ms)
                    <= MAXIMUM_AUTOMATION_ONE_SHOT_HORIZON_MS =>
        {
            Ok(())
        }
        AutomationTrigger::OneShot { .. } => Err(AutomationContractError::InvalidOneShotTime),
        AutomationTrigger::SessionEvent { event_type, .. } => validate_event_type(event_type),
    }
}

fn validate_event_type(event_type: &str) -> Result<(), AutomationContractError> {
    if event_type.is_empty()
        || event_type.len() > MAXIMUM_AUTOMATION_EVENT_TYPE_BYTES
        || event_type.starts_with('.')
        || event_type.ends_with('.')
        || !event_type.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        Err(AutomationContractError::InvalidEventType)
    } else {
        Ok(())
    }
}

fn validate_action(action: &AutomationAction) -> Result<(), AutomationContractError> {
    match action {
        AutomationAction::SubmitPrompt {
            prompt,
            approval_required_actions_allowed,
            ..
        } => {
            if prompt.is_empty()
                || prompt.len() > MAXIMUM_AUTOMATION_PROMPT_BYTES
                || prompt.contains('\0')
            {
                return Err(AutomationContractError::InvalidPrompt);
            }
            if ["/act ", "/run ", "/edit ", "/manage "]
                .iter()
                .any(|prefix| prompt.starts_with(prefix))
                && !approval_required_actions_allowed
            {
                return Err(AutomationContractError::ActionOptInRequired);
            }
            Ok(())
        }
        AutomationAction::Notify { message, .. } => {
            if message.is_empty()
                || message.len() > MAXIMUM_AUTOMATION_MESSAGE_BYTES
                || message.contains('\0')
                || message.trim() != message
            {
                Err(AutomationContractError::InvalidNotification)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AutomationAction, AutomationContractError, AutomationTrigger,
        MAXIMUM_AUTOMATION_ONE_SHOT_HORIZON_MS, validate_automation_definition,
    };
    use mealy_domain::SessionId;

    #[test]
    fn one_shot_supports_sub_minute_prompt_and_requires_action_opt_in() {
        let target_session_id = SessionId::new();
        assert!(
            validate_automation_definition(
                "quick check",
                &AutomationTrigger::OneShot { due_at_ms: 1_001 },
                &AutomationAction::SubmitPrompt {
                    target_session_id,
                    prompt: "Check the build status.".to_owned(),
                    approval_required_actions_allowed: false,
                },
                1_000,
            )
            .is_ok()
        );
        assert_eq!(
            validate_automation_definition(
                "unsafe",
                &AutomationTrigger::OneShot { due_at_ms: 2_000 },
                &AutomationAction::SubmitPrompt {
                    target_session_id,
                    prompt: "/run publish it".to_owned(),
                    approval_required_actions_allowed: false,
                },
                1_000,
            ),
            Err(AutomationContractError::ActionOptInRequired)
        );
        assert_eq!(
            validate_automation_definition(
                "too far",
                &AutomationTrigger::OneShot {
                    due_at_ms: 1_000 + MAXIMUM_AUTOMATION_ONE_SHOT_HORIZON_MS + 1,
                },
                &AutomationAction::Notify {
                    target_session_id,
                    message: "hello".to_owned(),
                },
                1_000,
            ),
            Err(AutomationContractError::InvalidOneShotTime)
        );
    }

    #[test]
    fn event_trigger_is_exact_future_notification_only() {
        let session = SessionId::new();
        assert!(
            validate_automation_definition(
                "completion",
                &AutomationTrigger::SessionEvent {
                    source_session_id: session,
                    event_type: "turn.completed".to_owned(),
                },
                &AutomationAction::Notify {
                    target_session_id: session,
                    message: "The watched session completed.".to_owned(),
                },
                1_000,
            )
            .is_ok()
        );
        assert_eq!(
            validate_automation_definition(
                "loop",
                &AutomationTrigger::SessionEvent {
                    source_session_id: session,
                    event_type: "turn.completed".to_owned(),
                },
                &AutomationAction::SubmitPrompt {
                    target_session_id: session,
                    prompt: "Continue.".to_owned(),
                    approval_required_actions_allowed: false,
                },
                1_000,
            ),
            Err(AutomationContractError::EventPromptForbidden)
        );
    }
}
