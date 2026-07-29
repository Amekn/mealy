use crate::{
    ChannelInboundMessage, InputAdmissionReceipt, OwnershipContext, SlackAdapter, is_sha256_digest,
    valid_provider_secret_id, valid_slack_acknowledgement_id, valid_slack_app_id,
    valid_slack_delivery_id,
};
use mealy_domain::{
    ApprovalId, ChannelBindingId, CorrelationId, EventId, InboxEntryId, PrincipalId,
    RemoteContinuationId, SessionId, TaskId,
};
use std::time::SystemTime;
use thiserror::Error;

/// Maximum UTF-8 bytes retained from a verified Slack display name.
pub const SLACK_MAXIMUM_DISPLAY_NAME_BYTES: usize = 128;
/// Maximum safe operator-facing Slack socket failure-code bytes.
pub const SLACK_MAXIMUM_ERROR_CODE_BYTES: usize = 128;
/// Maximum durable ignored-envelope reason bytes.
pub const SLACK_MAXIMUM_IGNORE_REASON_BYTES: usize = 256;
/// Minimum owner-visible lifetime for one proactive remote-continuation pin.
pub const SLACK_REMOTE_CONTINUATION_MINIMUM_LIFETIME_MS: i64 = 60 * 1_000;
/// Maximum lifetime for one proactive remote-continuation pin.
pub const SLACK_REMOTE_CONTINUATION_MAXIMUM_LIFETIME_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

/// Durable lifecycle of one exact Slack app/workspace/member/conversation binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackChannelStatus {
    /// Socket Mode input and Web API output are authorized.
    Active,
    /// Both brokered token authorities are terminally revoked while evidence remains.
    Revoked,
}

/// Effective lifecycle of one exact Slack remote-continuation pin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackRemoteContinuationStatus {
    /// The exact observed thread may receive proactive owner-authorized notifications.
    Active,
    /// The bounded owner-approved lifetime elapsed.
    Expired,
    /// The owner terminally revoked the pin.
    Revoked,
}

/// Owner-safe projection of one authenticated exact-thread remote continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackRemoteContinuationView {
    /// Stable client-proposed `UUIDv7` creation/retry identity.
    pub remote_continuation_id: RemoteContinuationId,
    /// Local owner principal.
    pub principal_id: PrincipalId,
    /// Exact Slack channel binding.
    pub binding_id: ChannelBindingId,
    /// Dedicated durable Slack session continued by this route.
    pub session_id: SessionId,
    /// Exact verified Slack workspace.
    pub team_id: String,
    /// Exact allowlisted Slack member.
    pub slack_user_id: String,
    /// Exact Slack conversation.
    pub slack_channel_id: String,
    /// Exact previously admitted Slack thread root.
    pub thread_id: String,
    /// Exclusive global timeline cursor at activation; older events are never replayed.
    pub synchronized_after_cursor: u64,
    /// Effective lifecycle at the caller-supplied observation time.
    pub status: SlackRemoteContinuationStatus,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Pin creation UTC epoch milliseconds.
    pub created_at_ms: i64,
    /// Exclusive expiry UTC epoch milliseconds.
    pub expires_at_ms: i64,
    /// Last lifecycle update UTC epoch milliseconds.
    pub updated_at_ms: i64,
    /// Terminal revocation UTC epoch milliseconds.
    pub revoked_at_ms: Option<i64>,
}

/// Atomic exact-thread remote-continuation creation.
pub struct CreateSlackRemoteContinuationCommit {
    /// Authenticated local administrator.
    pub administrative_ownership: OwnershipContext,
    /// Client-proposed `UUIDv7` creation/retry identity.
    pub remote_continuation_id: RemoteContinuationId,
    /// Exact Slack binding.
    pub binding_id: ChannelBindingId,
    /// Exact thread already observed in an admitted envelope.
    pub thread_id: String,
    /// Exclusive bounded expiry UTC epoch milliseconds.
    pub expires_at_ms: i64,
    /// Canonical activation event.
    pub event_id: EventId,
    /// End-to-end command correlation.
    pub correlation_id: CorrelationId,
    /// Creation time.
    pub created_at: SystemTime,
}

/// Terminal owner-authorized exact-thread continuation revocation.
pub struct RevokeSlackRemoteContinuationCommit {
    /// Authenticated local administrator.
    pub administrative_ownership: OwnershipContext,
    /// Exact Slack binding.
    pub binding_id: ChannelBindingId,
    /// Exact continuation.
    pub remote_continuation_id: RemoteContinuationId,
    /// Optimistic-concurrency lifecycle fence.
    pub expected_revision: u64,
    /// Canonical revocation event.
    pub event_id: EventId,
    /// End-to-end command correlation.
    pub correlation_id: CorrelationId,
    /// Revocation time.
    pub revoked_at: SystemTime,
}

/// Owner-authorized Slack binding projection without credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackChannelBindingView {
    /// Stable verified channel binding.
    pub binding_id: ChannelBindingId,
    /// Local owner principal.
    pub principal_id: PrincipalId,
    /// Dedicated durable conversation session.
    pub session_id: SessionId,
    /// Exact verified Slack workspace.
    pub team_id: String,
    /// Human-readable workspace name observed during setup.
    pub team_name: String,
    /// Exact Slack application identity bound to both token authorities.
    pub app_id: String,
    /// Exact allowlisted Slack member.
    pub slack_user_id: String,
    /// Exact allowlisted Slack conversation.
    pub slack_channel_id: String,
    /// Verified bot member identity.
    pub bot_user_id: String,
    /// Human-readable bot name observed during setup.
    pub bot_name: String,
    /// Whether shared-channel input must explicitly mention the bot.
    pub require_mention: bool,
    /// Opaque owner-private Socket Mode app-token broker identity.
    pub app_token_secret_id: String,
    /// Digest pin for the brokered Socket Mode app token.
    pub app_token_digest: String,
    /// Opaque owner-private bot-token broker identity.
    pub bot_token_secret_id: String,
    /// Digest pin for the brokered Web API bot token.
    pub bot_token_digest: String,
    /// Current terminal lifecycle state.
    pub status: SlackChannelStatus,
    /// Optimistic-concurrency revision for owner lifecycle commands.
    pub revision: u64,
    /// Most recent successful Socket Mode observation.
    pub last_success_at_ms: Option<i64>,
    /// Most recent failed Socket Mode observation.
    pub last_failure_at_ms: Option<i64>,
    /// Consecutive bounded connection or protocol failures.
    pub consecutive_failures: u64,
    /// Stable secret-free failure code.
    pub last_error_code: Option<String>,
    /// Creation UTC epoch milliseconds.
    pub created_at_ms: i64,
    /// Last lifecycle update UTC epoch milliseconds.
    pub updated_at_ms: i64,
}

/// Atomic Slack binding, registry, and dedicated-session creation.
pub struct RegisterSlackChannelCommit {
    /// Authenticated local administrator.
    pub administrative_ownership: OwnershipContext,
    /// New channel binding identity.
    pub binding_id: ChannelBindingId,
    /// New dedicated session identity.
    pub session_id: SessionId,
    /// Exact verified Slack workspace.
    pub team_id: String,
    /// Bounded workspace display name.
    pub team_name: String,
    /// Exact Slack application identity reported by bot-token verification.
    pub app_id: String,
    /// Exact allowed Slack sender.
    pub slack_user_id: String,
    /// Exact allowed Slack conversation.
    pub slack_channel_id: String,
    /// Verified bot member identity.
    pub bot_user_id: String,
    /// Bounded bot display name.
    pub bot_name: String,
    /// Whether shared-channel input requires a bot mention.
    pub require_mention: bool,
    /// Opaque app-token broker identity.
    pub app_token_secret_id: String,
    /// SHA-256 digest of the already-brokered app token.
    pub app_token_digest: String,
    /// Opaque bot-token broker identity.
    pub bot_token_secret_id: String,
    /// SHA-256 digest of the already-brokered bot token.
    pub bot_token_digest: String,
    /// Canonical `session.created` event.
    pub session_event_id: EventId,
    /// Canonical `channel.slack_registered` event.
    pub binding_event_id: EventId,
    /// End-to-end setup correlation.
    pub correlation_id: CorrelationId,
    /// Creation time.
    pub created_at: SystemTime,
}

/// Terminal owner-authorized Slack binding revocation.
pub struct RevokeSlackChannelCommit {
    /// Authenticated local administrator.
    pub administrative_ownership: OwnershipContext,
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Optimistic-concurrency lifecycle fence.
    pub expected_revision: u64,
    /// Canonical revocation event.
    pub event_id: EventId,
    /// End-to-end command correlation.
    pub correlation_id: CorrelationId,
    /// Revocation time.
    pub revoked_at: SystemTime,
}

/// Durable normalized action captured before acknowledging one Slack envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlackReservedDisposition {
    /// Admit this exact bounded untrusted message.
    Admit(ChannelInboundMessage),
    /// Deliberately ignore the envelope under a stable bounded reason.
    Ignore(String),
}

/// Durable reservation committed before the Socket Mode acknowledgement is sent.
pub struct ReserveSlackEnvelopeCommit {
    /// Exact Slack binding which received the envelope.
    pub binding_id: ChannelBindingId,
    /// Socket Mode acknowledgement identity.
    pub acknowledgement_id: String,
    /// Digest of the complete raw Socket Mode envelope.
    pub body_digest: String,
    /// Normalized action recoverable after a crash.
    pub disposition: SlackReservedDisposition,
    /// Receipt time.
    pub received_at: SystemTime,
}

/// Result of reserving one exact Socket Mode envelope and body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackEnvelopeReservation {
    /// New durable reservation owned by this processing attempt.
    Reserved,
    /// The same body was reserved before a crash and must resume.
    ExistingReserved,
    /// The same envelope is terminal and needs only a duplicate acknowledgement.
    ExistingCompleted,
}

/// Recoverable secret-free Slack envelope reserved but not yet terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingSlackEnvelope {
    /// Exact Slack binding.
    pub binding_id: ChannelBindingId,
    /// Socket Mode acknowledgement identity.
    pub acknowledgement_id: String,
    /// Digest of the complete raw envelope.
    pub body_digest: String,
    /// Durable normalized action.
    pub disposition: SlackReservedDisposition,
    /// Whether an acknowledgement was durably observed as sent.
    pub acknowledged_at_ms: Option<i64>,
    /// Original receipt time.
    pub received_at_ms: i64,
}

/// Records that one reserved envelope was acknowledged to Slack.
pub struct AcknowledgeSlackEnvelopeCommit {
    /// Exact Slack binding.
    pub binding_id: ChannelBindingId,
    /// Reserved Socket Mode acknowledgement identity.
    pub acknowledgement_id: String,
    /// Acknowledgement time.
    pub acknowledged_at: SystemTime,
}

/// Terminal processing result for one reserved Slack envelope.
pub enum SlackEnvelopeDisposition {
    /// Exact idempotent session admission completed.
    Admitted(InputAdmissionReceipt),
    /// The envelope was deliberately ignored under the reserved reason.
    Ignored(String),
}

/// Attaches terminal processing evidence to one reserved Slack envelope.
pub struct CompleteSlackEnvelopeCommit {
    /// Exact Slack binding.
    pub binding_id: ChannelBindingId,
    /// Reserved Socket Mode acknowledgement identity.
    pub acknowledgement_id: String,
    /// Terminal admitted or ignored result.
    pub disposition: SlackEnvelopeDisposition,
    /// Completion time.
    pub completed_at: SystemTime,
}

/// One durable secret-free Socket Mode health observation.
pub struct RecordSlackSocketCommit {
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Whether the Slack connection or protocol exchange succeeded.
    pub succeeded: bool,
    /// Stable error code on failure; absent on success.
    pub error_code: Option<String>,
    /// Observation time.
    pub observed_at: SystemTime,
}

/// Internal active Slack target for one Socket Mode connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackSocketTarget {
    /// Exact channel binding.
    pub binding_id: ChannelBindingId,
    /// Exact workspace.
    pub team_id: String,
    /// Exact application required in the Socket Mode hello.
    pub app_id: String,
    /// Exact allowed sender.
    pub slack_user_id: String,
    /// Exact allowed conversation.
    pub slack_channel_id: String,
    /// Verified bot member.
    pub bot_user_id: String,
    /// Whether shared-channel input requires a mention.
    pub require_mention: bool,
    /// Dedicated destination session.
    pub session_id: SessionId,
    /// Effective session owner/channel binding.
    pub ownership: OwnershipContext,
    /// Opaque app-token broker identity.
    pub app_token_secret_id: String,
    /// Required app-token digest.
    pub app_token_digest: String,
    /// Opaque bot-token broker identity.
    pub bot_token_secret_id: String,
    /// Required bot-token digest.
    pub bot_token_digest: String,
}

/// Canonical identifiers available when resolving a thread-safe Slack outbox route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackOutboundContext<'a> {
    /// Dedicated Slack session.
    pub session_id: SessionId,
    /// Exact supported outbox topic.
    pub topic: &'a str,
    /// Input identity supplied by acknowledgement or promotion topics.
    pub inbox_entry_id: Option<InboxEntryId>,
    /// Task identity supplied by turn completion.
    pub task_id: Option<TaskId>,
    /// Approval identity supplied by effect notification.
    pub approval_id: Option<ApprovalId>,
    /// Exact proactive remote-continuation route for automation notifications.
    pub remote_continuation_id: Option<RemoteContinuationId>,
    /// Delivery-time UTC epoch milliseconds used to revalidate expiry.
    pub observed_at_ms: i64,
}

/// Internal exact Slack destination for one existing session outbox notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundSlackTarget {
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Exact proactive route when this is a remote-continuation notification.
    pub remote_continuation_id: Option<RemoteContinuationId>,
    /// Exact Slack conversation.
    pub slack_channel_id: String,
    /// Exact verified Slack workspace used to reconstruct the pure adapter.
    pub team_id: String,
    /// Exact allowlisted Slack member used to reconstruct the pure adapter.
    pub slack_user_id: String,
    /// Exact originating thread root, when resolvable.
    pub thread_id: Option<String>,
    /// Verified bot member identity.
    pub bot_user_id: String,
    /// Whether inbound shared-channel messages require a mention.
    pub require_mention: bool,
    /// Opaque bot-token broker identity.
    pub bot_token_secret_id: String,
    /// Required bot-token digest.
    pub bot_token_digest: String,
}

/// Slack administration, envelope-ledger, and routing persistence failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SlackChannelStoreError {
    /// Binding is absent or deliberately hidden.
    #[error("Slack channel was not found")]
    NotFound,
    /// Binding is terminally revoked.
    #[error("Slack channel is revoked")]
    Revoked,
    /// Revision, envelope identity, or immutable evidence conflicts.
    #[error("Slack channel operation conflicts with canonical state")]
    Conflict,
    /// Supplied fields violate the bounded channel contract.
    #[error("Slack channel contract is invalid: {0}")]
    InvalidContract(String),
    /// Persistence is temporarily unavailable.
    #[error("Slack channel store is unavailable: {0}")]
    Unavailable(String),
    /// Canonical stored evidence violates an invariant.
    #[error("Slack channel invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for Slack administration, crash-safe Socket Mode acknowledgement, and outbox routing.
pub trait SlackChannelStore {
    /// Creates one exact app/workspace/member/conversation binding and session atomically.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for invalid, unauthorized, or conflicting state.
    fn register_slack_channel(
        &mut self,
        commit: RegisterSlackChannelCommit,
    ) -> Result<SlackChannelBindingView, SlackChannelStoreError>;

    /// Terminally revokes one owner-authorized binding.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for ownership, revision, or lifecycle conflicts.
    fn revoke_slack_channel(
        &mut self,
        commit: RevokeSlackChannelCommit,
    ) -> Result<SlackChannelBindingView, SlackChannelStoreError>;

    /// Reads one binding through authenticated owner administration.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] when absent, unauthorized, or corrupt.
    fn slack_channel(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
    ) -> Result<SlackChannelBindingView, SlackChannelStoreError>;

    /// Lists owner-authorized Slack bindings in stable order.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for authorization or persistence failure.
    fn slack_channels(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<SlackChannelBindingView>, SlackChannelStoreError>;

    /// Creates or exactly replays one bounded exact-thread remote continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for unobserved threads, overlap, authorization,
    /// invalid lifetime, or persistence failure.
    fn create_slack_remote_continuation(
        &mut self,
        commit: CreateSlackRemoteContinuationCommit,
    ) -> Result<SlackRemoteContinuationView, SlackChannelStoreError>;

    /// Reads one owner-authorized remote continuation at an explicit observation time.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] when absent, unauthorized, invalid, or corrupt.
    fn slack_remote_continuation(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
        remote_continuation_id: RemoteContinuationId,
        observed_at_ms: i64,
    ) -> Result<SlackRemoteContinuationView, SlackChannelStoreError>;

    /// Lists exact-thread continuations in stable creation order.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for authorization, invalid time, or persistence.
    fn slack_remote_continuations(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
        observed_at_ms: i64,
    ) -> Result<Vec<SlackRemoteContinuationView>, SlackChannelStoreError>;

    /// Terminally revokes one exact-thread continuation under a revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for authorization, revision, lifecycle, or persistence.
    fn revoke_slack_remote_continuation(
        &mut self,
        commit: RevokeSlackRemoteContinuationCommit,
    ) -> Result<SlackRemoteContinuationView, SlackChannelStoreError>;

    /// Lists a bounded stable batch of active Socket Mode targets.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for invalid bounds or persistence failure.
    fn active_slack_socket_targets(
        &self,
        limit: usize,
    ) -> Result<Vec<SlackSocketTarget>, SlackChannelStoreError>;

    /// Reserves or recovers one exact envelope before transport acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for conflicting bodies or inactive authority.
    fn reserve_slack_envelope(
        &mut self,
        commit: ReserveSlackEnvelopeCommit,
    ) -> Result<SlackEnvelopeReservation, SlackChannelStoreError>;

    /// Records a sent acknowledgement idempotently.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for absent reservations or stale evidence.
    fn acknowledge_slack_envelope(
        &mut self,
        commit: AcknowledgeSlackEnvelopeCommit,
    ) -> Result<(), SlackChannelStoreError>;

    /// Lists a bounded stable batch of reserved envelopes for restart recovery.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for invalid bounds or persistence failure.
    fn pending_slack_envelopes(
        &self,
        binding_id: ChannelBindingId,
        limit: usize,
    ) -> Result<Vec<PendingSlackEnvelope>, SlackChannelStoreError>;

    /// Commits terminal envelope evidence after acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for invalid receipts, stale state, or persistence.
    fn complete_slack_envelope(
        &mut self,
        commit: CompleteSlackEnvelopeCommit,
    ) -> Result<(), SlackChannelStoreError>;

    /// Records current secret-free Socket Mode health for operator diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] for malformed codes, inactive state, or persistence.
    fn record_slack_socket(
        &mut self,
        commit: RecordSlackSocketCommit,
    ) -> Result<(), SlackChannelStoreError>;

    /// Resolves an active Slack destination and exact originating thread for an outbox record.
    ///
    /// # Errors
    ///
    /// Returns [`SlackChannelStoreError`] when routing evidence is corrupt or ambiguous.
    fn outbound_slack_target(
        &self,
        context: SlackOutboundContext<'_>,
    ) -> Result<Option<OutboundSlackTarget>, SlackChannelStoreError>;
}

/// Validates all non-secret Slack binding fields and credential evidence.
///
/// # Errors
///
/// Returns [`SlackChannelStoreError::InvalidContract`] for malformed identity or evidence.
#[allow(clippy::too_many_arguments)]
pub fn validate_slack_binding(
    team_id: &str,
    team_name: &str,
    app_id: &str,
    slack_user_id: &str,
    slack_channel_id: &str,
    bot_user_id: &str,
    bot_name: &str,
    require_mention: bool,
    app_token_secret_id: &str,
    app_token_digest: &str,
    bot_token_secret_id: &str,
    bot_token_digest: &str,
) -> Result<(), SlackChannelStoreError> {
    let adapter_valid = SlackAdapter::new(
        team_id.to_owned(),
        slack_user_id.to_owned(),
        slack_channel_id.to_owned(),
        bot_user_id.to_owned(),
        require_mention,
    )
    .is_ok();
    if !adapter_valid
        || !valid_display_name(team_name)
        || !valid_slack_app_id(app_id)
        || !valid_display_name(bot_name)
        || !valid_provider_secret_id(app_token_secret_id)
        || !valid_provider_secret_id(bot_token_secret_id)
        || app_token_secret_id == bot_token_secret_id
        || !is_sha256_digest(app_token_digest)
        || !is_sha256_digest(bot_token_digest)
    {
        Err(SlackChannelStoreError::InvalidContract(
            "Slack identity or credential evidence is invalid".to_owned(),
        ))
    } else {
        Ok(())
    }
}

/// Stable session idempotency key for one admitted Slack event.
///
/// # Errors
///
/// Returns [`SlackChannelStoreError::InvalidContract`] for a malformed event identity.
pub fn slack_input_dedupe_key(
    binding_id: ChannelBindingId,
    delivery_id: &str,
) -> Result<String, SlackChannelStoreError> {
    if valid_slack_delivery_id(delivery_id) {
        Ok(format!("slack:{binding_id}:{delivery_id}"))
    } else {
        Err(SlackChannelStoreError::InvalidContract(
            "Slack delivery identity is invalid".to_owned(),
        ))
    }
}

/// Validates the immutable bounded normalized reservation contract.
///
/// # Errors
///
/// Returns [`SlackChannelStoreError::InvalidContract`] for malformed evidence.
pub fn validate_slack_reservation(
    acknowledgement_id: &str,
    body_digest: &str,
    disposition: &SlackReservedDisposition,
) -> Result<(), SlackChannelStoreError> {
    let disposition_valid = match disposition {
        SlackReservedDisposition::Admit(message) => {
            valid_slack_delivery_id(&message.delivery_id)
                && is_sha256_digest(&message.body_digest)
                && message.body_digest == body_digest
                && !message.text.is_empty()
                && message.text.len() <= crate::SLACK_MAXIMUM_INBOUND_TEXT_BYTES
                && !message.source_locator.is_empty()
                && message.source_locator.len() <= 512
        }
        SlackReservedDisposition::Ignore(reason) => valid_reason(reason),
    };
    if valid_slack_acknowledgement_id(acknowledgement_id)
        && is_sha256_digest(body_digest)
        && disposition_valid
    {
        Ok(())
    } else {
        Err(SlackChannelStoreError::InvalidContract(
            "Slack envelope reservation is invalid".to_owned(),
        ))
    }
}

fn valid_display_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= SLACK_MAXIMUM_DISPLAY_NAME_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_reason(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= SLACK_MAXIMUM_IGNORE_REASON_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::{
        SlackReservedDisposition, slack_input_dedupe_key, validate_slack_binding,
        validate_slack_reservation,
    };
    use crate::ChannelInboundMessage;
    use mealy_domain::ChannelBindingId;

    #[test]
    fn binding_contract_fences_two_exact_token_authorities() {
        assert!(
            validate_slack_binding(
                "T01234567",
                "Mealy Test",
                "A01234567",
                "U01234567",
                "C01234567",
                "U07654321",
                "mealy",
                true,
                "slack.app.binding",
                &"a".repeat(64),
                "slack.bot.binding",
                &"b".repeat(64),
            )
            .is_ok()
        );
        assert!(
            validate_slack_binding(
                "T01234567",
                "Mealy Test",
                "A01234567",
                "U01234567",
                "C01234567",
                "U07654321",
                "mealy",
                true,
                "slack.same.binding",
                &"a".repeat(64),
                "slack.same.binding",
                &"b".repeat(64),
            )
            .is_err()
        );
    }

    #[test]
    fn envelope_reservation_binds_body_and_session_dedupe_identity() {
        let binding_id = ChannelBindingId::new();
        let digest = "a".repeat(64);
        let disposition = SlackReservedDisposition::Admit(ChannelInboundMessage {
            delivery_id: "Ev01234567".to_owned(),
            workspace_id: "T01234567".to_owned(),
            conversation_id: "C01234567".to_owned(),
            thread_id: Some("1785254000.000100".to_owned()),
            sender_id: "U01234567".to_owned(),
            text: "review the incident".to_owned(),
            body_digest: digest.clone(),
            source_locator: "slack://T01234567/C01234567/Ev01234567".to_owned(),
        });
        assert!(validate_slack_reservation("env-1", &digest, &disposition).is_ok());
        assert_eq!(
            slack_input_dedupe_key(binding_id, "Ev01234567").expect("Slack dedupe"),
            format!("slack:{binding_id}:Ev01234567")
        );
        assert!(
            validate_slack_reservation("env-1", &"b".repeat(64), &disposition).is_err(),
            "body digest drift must fail closed"
        );
    }
}
