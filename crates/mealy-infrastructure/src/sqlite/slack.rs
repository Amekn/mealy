use super::SqliteStore;
use mealy_application::{
    AcknowledgeSlackEnvelopeCommit, CompleteSlackEnvelopeCommit, OutboundSlackTarget,
    OwnershipContext, PendingSlackEnvelope, RecordSlackSocketCommit, RegisterSlackChannelCommit,
    ReserveSlackEnvelopeCommit, RevokeSlackChannelCommit, SLACK_MAXIMUM_ERROR_CODE_BYTES,
    SlackChannelBindingView, SlackChannelStatus, SlackChannelStore, SlackChannelStoreError,
    SlackEnvelopeDisposition, SlackEnvelopeReservation, SlackOutboundContext,
    SlackReservedDisposition, SlackSocketTarget, sha256_digest, valid_slack_acknowledgement_id,
    validate_slack_binding, validate_slack_reservation,
};
use mealy_domain::{ChannelBindingId, PrincipalId};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::{str::FromStr, time::SystemTime};

const SLACK_INSTALLATION_ID: &str = "builtin.slack.socket.v1";
const MAXIMUM_SOCKET_TARGETS: usize = 100;
const MAXIMUM_PENDING_ENVELOPES: usize = 1_000;

impl SlackChannelStore for SqliteStore {
    #[allow(clippy::too_many_lines)]
    fn register_slack_channel(
        &mut self,
        commit: RegisterSlackChannelCommit,
    ) -> Result<SlackChannelBindingView, SlackChannelStoreError> {
        validate_slack_binding(
            &commit.team_id,
            &commit.team_name,
            &commit.slack_user_id,
            &commit.slack_channel_id,
            &commit.bot_user_id,
            &commit.bot_name,
            commit.require_mention,
            &commit.app_token_secret_id,
            &commit.app_token_digest,
            &commit.bot_token_secret_id,
            &commit.bot_token_digest,
        )?;
        let created_at_ms = epoch_milliseconds(commit.created_at)?;
        let principal_id = commit.administrative_ownership.principal_id();
        let external_subject = format!(
            "slack:team:{}:user:{}:channel:{}",
            commit.team_id, commit.slack_user_id, commit.slack_channel_id
        );
        let external_subject_digest = sha256_digest(external_subject.as_bytes());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.administrative_ownership)?;
        transaction
            .execute(
                "INSERT INTO channel_binding_registry(\
                    binding_id, principal_id, channel_kind, status, revision, installation_id, \
                    external_subject, external_subject_digest, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, 'extension_channel', 'active', 0, ?3, ?4, ?5, ?6, ?6)",
                params![
                    commit.binding_id.to_string(),
                    principal_id.to_string(),
                    SLACK_INSTALLATION_ID,
                    external_subject,
                    external_subject_digest,
                    created_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?4)",
                params![
                    commit.session_id.to_string(),
                    principal_id.to_string(),
                    commit.binding_id.to_string(),
                    created_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction
            .execute(
                "INSERT INTO session_lineage(\
                    session_id, root_session_id, parent_checkpoint_id, fork_event_id, created_at_ms\
                 ) VALUES (?1, ?1, NULL, NULL, ?2)",
                params![commit.session_id.to_string(), created_at_ms],
            )
            .map_err(map_registration_error)?;
        transaction
            .execute(
                "INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                    sensitivity, payload_json\
                 ) VALUES (?1, 'session', ?2, 0, 'session.created', 1, ?3, ?4, ?5, \
                           'private', ?6)",
                params![
                    commit.session_event_id.to_string(),
                    commit.session_id.to_string(),
                    created_at_ms,
                    principal_id.to_string(),
                    commit.correlation_id.to_string(),
                    json!({
                        "channel_binding_id": commit.binding_id,
                        "channel_kind": "slack_socket",
                    })
                    .to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
                 VALUES ('session', ?1, 0)",
                [commit.session_id.to_string()],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO journal_event(\
                    event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                    event_version, occurred_at_ms, actor_principal_id, correlation_id, \
                    sensitivity, payload_json\
                 ) VALUES (?1, 'channel_binding', ?2, 0, 'channel.slack_registered', 1, ?3, \
                           ?4, ?5, 'private', ?6)",
                params![
                    commit.binding_event_id.to_string(),
                    commit.binding_id.to_string(),
                    created_at_ms,
                    principal_id.to_string(),
                    commit.correlation_id.to_string(),
                    json!({
                        "binding_id": commit.binding_id,
                        "session_id": commit.session_id,
                        "team_id": commit.team_id,
                        "team_name": commit.team_name,
                        "slack_user_id": commit.slack_user_id,
                        "slack_channel_id": commit.slack_channel_id,
                        "bot_user_id": commit.bot_user_id,
                        "bot_name": commit.bot_name,
                        "require_mention": commit.require_mention,
                        "app_token_secret_id": commit.app_token_secret_id,
                        "app_token_digest": commit.app_token_digest,
                        "bot_token_secret_id": commit.bot_token_secret_id,
                        "bot_token_digest": commit.bot_token_digest,
                    })
                    .to_string(),
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
                 VALUES ('channel_binding', ?1, 0)",
                [commit.binding_id.to_string()],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO slack_channel_binding(\
                    binding_id, principal_id, session_id, team_id, team_name, slack_user_id, \
                    slack_channel_id, bot_user_id, bot_name, require_mention, app_token_secret_id, \
                    app_token_digest, bot_token_secret_id, bot_token_digest, status, revision, \
                    created_event_id, created_at_ms, updated_at_ms\
                 ) VALUES (\
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                    'active', 0, ?15, ?16, ?16\
                 )",
                params![
                    commit.binding_id.to_string(),
                    principal_id.to_string(),
                    commit.session_id.to_string(),
                    commit.team_id,
                    commit.team_name,
                    commit.slack_user_id,
                    commit.slack_channel_id,
                    commit.bot_user_id,
                    commit.bot_name,
                    commit.require_mention,
                    commit.app_token_secret_id,
                    commit.app_token_digest,
                    commit.bot_token_secret_id,
                    commit.bot_token_digest,
                    commit.binding_event_id.to_string(),
                    created_at_ms,
                ],
            )
            .map_err(map_registration_error)?;
        transaction
            .execute(
                "INSERT INTO slack_channel_health(\
                    binding_id, consecutive_failures, revision, updated_at_ms\
                 ) VALUES (?1, 0, 0, ?2)",
                params![commit.binding_id.to_string(), created_at_ms],
            )
            .map_err(map_registration_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_binding(&self.connection, commit.binding_id)
    }

    fn revoke_slack_channel(
        &mut self,
        commit: RevokeSlackChannelCommit,
    ) -> Result<SlackChannelBindingView, SlackChannelStoreError> {
        let revoked_at_ms = epoch_milliseconds(commit.revoked_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.administrative_ownership)?;
        let current = load_binding(&transaction, commit.binding_id)?;
        if current.principal_id != commit.administrative_ownership.principal_id() {
            return Err(SlackChannelStoreError::NotFound);
        }
        if current.status != SlackChannelStatus::Active
            || current.revision != commit.expected_revision
        {
            return Err(SlackChannelStoreError::Conflict);
        }
        let revision = to_i64(commit.expected_revision)?;
        let changed_registry = transaction
            .execute(
                "UPDATE channel_binding_registry SET status = 'revoked', revision = revision + 1, \
                    updated_at_ms = ?1, revoked_at_ms = ?1 \
                 WHERE binding_id = ?2 AND principal_id = ?3 AND status = 'active' \
                   AND revision = ?4",
                params![
                    revoked_at_ms,
                    commit.binding_id.to_string(),
                    current.principal_id.to_string(),
                    revision,
                ],
            )
            .map_err(map_sqlite_error)?;
        let changed_binding = transaction
            .execute(
                "UPDATE slack_channel_binding SET status = 'revoked', revision = revision + 1, \
                    updated_at_ms = ?1, revoked_at_ms = ?1 \
                 WHERE binding_id = ?2 AND principal_id = ?3 AND status = 'active' \
                   AND revision = ?4",
                params![
                    revoked_at_ms,
                    commit.binding_id.to_string(),
                    current.principal_id.to_string(),
                    revision,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed_registry != 1 || changed_binding != 1 {
            return Err(SlackChannelStoreError::Conflict);
        }
        append_revocation_event(&transaction, &commit, current.principal_id, revoked_at_ms)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_binding(&self.connection, commit.binding_id)
    }

    fn slack_channel(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
    ) -> Result<SlackChannelBindingView, SlackChannelStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        let view = load_binding(&self.connection, binding_id)?;
        if view.principal_id == ownership.principal_id() {
            Ok(view)
        } else {
            Err(SlackChannelStoreError::NotFound)
        }
    }

    fn slack_channels(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<SlackChannelBindingView>, SlackChannelStoreError> {
        authorize_administrator(&self.connection, ownership)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT binding_id FROM slack_channel_binding WHERE principal_id = ?1 \
                 ORDER BY created_at_ms, binding_id",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map([ownership.principal_id().to_string()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| load_binding(&self.connection, parse_id(&id, "Slack binding ID")?))
            .collect()
    }

    fn active_slack_socket_targets(
        &self,
        limit: usize,
    ) -> Result<Vec<SlackSocketTarget>, SlackChannelStoreError> {
        if limit == 0 || limit > MAXIMUM_SOCKET_TARGETS {
            return Err(invalid_contract("Slack socket target limit is invalid"));
        }
        let sql_limit = i64::try_from(limit)
            .map_err(|_| invalid_contract("Slack socket target limit exceeds SQLite"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT binding_id FROM slack_channel_binding binding \
                 JOIN channel_binding_registry registry USING(binding_id) \
                 WHERE binding.status = 'active' AND registry.status = 'active' \
                 ORDER BY binding.created_at_ms, binding.binding_id LIMIT ?1",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map([sql_limit], |row| row.get::<_, String>(0))
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| {
                let binding_id = parse_id(&id, "Slack binding ID")?;
                let binding = load_binding(&self.connection, binding_id)?;
                Ok(SlackSocketTarget {
                    binding_id,
                    team_id: binding.team_id,
                    slack_user_id: binding.slack_user_id,
                    slack_channel_id: binding.slack_channel_id,
                    bot_user_id: binding.bot_user_id,
                    require_mention: binding.require_mention,
                    session_id: binding.session_id,
                    ownership: OwnershipContext::new(binding.principal_id, binding_id),
                    app_token_secret_id: binding.app_token_secret_id,
                    app_token_digest: binding.app_token_digest,
                    bot_token_secret_id: binding.bot_token_secret_id,
                    bot_token_digest: binding.bot_token_digest,
                })
            })
            .collect()
    }

    fn reserve_slack_envelope(
        &mut self,
        commit: ReserveSlackEnvelopeCommit,
    ) -> Result<SlackEnvelopeReservation, SlackChannelStoreError> {
        validate_slack_reservation(
            &commit.acknowledgement_id,
            &commit.body_digest,
            &commit.disposition,
        )?;
        let received_at_ms = epoch_milliseconds(commit.received_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let binding = load_binding(&transaction, commit.binding_id)?;
        if binding.status != SlackChannelStatus::Active {
            return Err(SlackChannelStoreError::Revoked);
        }
        validate_disposition_route(&binding, &commit.disposition)?;
        let desired = StoredDisposition::from_reserved(&commit.disposition);
        let existing = load_receipt(&transaction, commit.binding_id, &commit.acknowledgement_id)?;
        if let Some(existing) = existing {
            if existing.body_digest != commit.body_digest || existing.disposition != desired {
                return Err(SlackChannelStoreError::Conflict);
            }
            transaction.commit().map_err(map_sqlite_error)?;
            return match existing.state.as_str() {
                "reserved" => Ok(SlackEnvelopeReservation::ExistingReserved),
                "admitted" | "ignored" => Ok(SlackEnvelopeReservation::ExistingCompleted),
                _ => Err(invariant("stored Slack envelope state is invalid")),
            };
        }
        insert_receipt(
            &transaction,
            commit.binding_id,
            binding.session_id,
            &commit.acknowledgement_id,
            &commit.body_digest,
            &desired,
            received_at_ms,
        )?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(SlackEnvelopeReservation::Reserved)
    }

    fn acknowledge_slack_envelope(
        &mut self,
        commit: AcknowledgeSlackEnvelopeCommit,
    ) -> Result<(), SlackChannelStoreError> {
        if !valid_slack_acknowledgement_id(&commit.acknowledgement_id) {
            return Err(invalid_contract(
                "Slack acknowledgement identity is invalid",
            ));
        }
        let acknowledged_at_ms = epoch_milliseconds(commit.acknowledged_at)?;
        let current = load_receipt(
            &self.connection,
            commit.binding_id,
            &commit.acknowledgement_id,
        )?
        .ok_or(SlackChannelStoreError::Conflict)?;
        if current.acknowledged_at_ms.is_some() || current.state != "reserved" {
            return Ok(());
        }
        let changed = self
            .connection
            .execute(
                "UPDATE slack_envelope_receipt SET acknowledged_at_ms = ?1 \
                 WHERE binding_id = ?2 AND acknowledgement_id = ?3 AND state = 'reserved' \
                   AND acknowledged_at_ms IS NULL AND received_at_ms <= ?1",
                params![
                    acknowledged_at_ms,
                    commit.binding_id.to_string(),
                    commit.acknowledgement_id,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(SlackChannelStoreError::Conflict)
        }
    }

    fn pending_slack_envelopes(
        &self,
        binding_id: ChannelBindingId,
        limit: usize,
    ) -> Result<Vec<PendingSlackEnvelope>, SlackChannelStoreError> {
        if limit == 0 || limit > MAXIMUM_PENDING_ENVELOPES {
            return Err(invalid_contract("Slack pending-envelope limit is invalid"));
        }
        let binding = load_binding(&self.connection, binding_id)?;
        if binding.status != SlackChannelStatus::Active {
            return Err(SlackChannelStoreError::Revoked);
        }
        let sql_limit = i64::try_from(limit)
            .map_err(|_| invalid_contract("Slack pending-envelope limit exceeds SQLite"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT acknowledgement_id FROM slack_envelope_receipt \
                 WHERE binding_id = ?1 AND state = 'reserved' \
                 ORDER BY received_at_ms, acknowledgement_id LIMIT ?2",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map(params![binding_id.to_string(), sql_limit], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|acknowledgement_id| {
                let receipt = load_receipt(&self.connection, binding_id, &acknowledgement_id)?
                    .ok_or_else(|| invariant("pending Slack envelope disappeared"))?;
                let body_digest = receipt.body_digest;
                let disposition = receipt.disposition.into_reserved(body_digest.clone())?;
                Ok(PendingSlackEnvelope {
                    binding_id,
                    acknowledgement_id,
                    body_digest,
                    disposition,
                    acknowledged_at_ms: receipt.acknowledged_at_ms,
                    received_at_ms: receipt.received_at_ms,
                })
            })
            .collect()
    }

    fn complete_slack_envelope(
        &mut self,
        commit: CompleteSlackEnvelopeCommit,
    ) -> Result<(), SlackChannelStoreError> {
        if !valid_slack_acknowledgement_id(&commit.acknowledgement_id) {
            return Err(invalid_contract(
                "Slack acknowledgement identity is invalid",
            ));
        }
        let completed_at_ms = epoch_milliseconds(commit.completed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let binding = load_binding(&transaction, commit.binding_id)?;
        let current = load_receipt(&transaction, commit.binding_id, &commit.acknowledgement_id)?
            .ok_or(SlackChannelStoreError::Conflict)?;
        let (state, inbox_id, outbox_id) = match &commit.disposition {
            SlackEnvelopeDisposition::Admitted(admission) => {
                if admission.session_id != binding.session_id || current.disposition.kind != "admit"
                {
                    return Err(invalid_contract(
                        "Slack admission belongs to another reservation or session",
                    ));
                }
                (
                    "admitted",
                    Some(admission.inbox_entry_id.to_string()),
                    Some(admission.outbox_id.to_string()),
                )
            }
            SlackEnvelopeDisposition::Ignored(reason) => {
                if current.disposition.kind != "ignore"
                    || current.disposition.ignore_reason.as_deref() != Some(reason)
                {
                    return Err(invalid_contract(
                        "Slack ignored result differs from its reservation",
                    ));
                }
                ("ignored", None, None)
            }
        };
        if current.state != "reserved" {
            if current.state == state
                && current.inbox_entry_id == inbox_id
                && current.acknowledgement_outbox_id == outbox_id
            {
                transaction.commit().map_err(map_sqlite_error)?;
                return Ok(());
            }
            return Err(SlackChannelStoreError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE slack_envelope_receipt SET state = ?1, inbox_entry_id = ?2, \
                    acknowledgement_outbox_id = ?3, completed_at_ms = ?4 \
                 WHERE binding_id = ?5 AND acknowledgement_id = ?6 AND state = 'reserved' \
                   AND received_at_ms <= ?4",
                params![
                    state,
                    inbox_id,
                    outbox_id,
                    completed_at_ms,
                    commit.binding_id.to_string(),
                    commit.acknowledgement_id,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(SlackChannelStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)
    }

    fn record_slack_socket(
        &mut self,
        commit: RecordSlackSocketCommit,
    ) -> Result<(), SlackChannelStoreError> {
        if commit.succeeded != commit.error_code.is_none()
            || commit.error_code.as_deref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > SLACK_MAXIMUM_ERROR_CODE_BYTES
                    || code.trim() != code
                    || code.chars().any(char::is_control)
            })
        {
            return Err(invalid_contract("Slack socket health evidence is invalid"));
        }
        let observed_at_ms = epoch_milliseconds(commit.observed_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        if load_binding(&transaction, commit.binding_id)?.status != SlackChannelStatus::Active {
            return Err(SlackChannelStoreError::Revoked);
        }
        let changed = if commit.succeeded {
            transaction.execute(
                "UPDATE slack_channel_health SET last_success_at_ms = ?1, \
                    consecutive_failures = 0, last_error_code = NULL, revision = revision + 1, \
                    updated_at_ms = ?1 WHERE binding_id = ?2",
                params![observed_at_ms, commit.binding_id.to_string()],
            )
        } else {
            transaction.execute(
                "UPDATE slack_channel_health SET last_failure_at_ms = ?1, \
                    consecutive_failures = MIN(consecutive_failures + 1, 1000000000), \
                    last_error_code = ?2, revision = revision + 1, updated_at_ms = ?1 \
                 WHERE binding_id = ?3",
                params![
                    observed_at_ms,
                    commit.error_code,
                    commit.binding_id.to_string(),
                ],
            )
        }
        .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(SlackChannelStoreError::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)
    }

    fn outbound_slack_target(
        &self,
        context: SlackOutboundContext<'_>,
    ) -> Result<Option<OutboundSlackTarget>, SlackChannelStoreError> {
        if !supported_outbound_context(&context) {
            return Ok(None);
        }
        let binding_id = self
            .connection
            .query_row(
                "SELECT binding.binding_id FROM session \
                 JOIN slack_channel_binding binding \
                   ON binding.binding_id = session.channel_binding_id \
                  AND binding.session_id = session.id \
                 JOIN channel_binding_registry registry USING(binding_id) \
                 WHERE session.id = ?1 AND binding.status = 'active' \
                   AND registry.status = 'active'",
                [context.session_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_sqlite_error)?;
        let Some(binding_id) = binding_id else {
            return Ok(None);
        };
        let binding_id = parse_id(&binding_id, "Slack binding ID")?;
        let binding = load_binding(&self.connection, binding_id)?;
        let thread_id = resolve_thread(&self.connection, binding_id, &context)?
            .ok_or_else(|| invariant("Slack outbox input could not resolve an exact thread"))?;
        Ok(Some(OutboundSlackTarget {
            binding_id,
            slack_channel_id: binding.slack_channel_id,
            thread_id: Some(thread_id),
            bot_user_id: binding.bot_user_id,
            bot_token_secret_id: binding.bot_token_secret_id,
            bot_token_digest: binding.bot_token_digest,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredDisposition {
    kind: String,
    delivery_id: Option<String>,
    workspace_id: Option<String>,
    conversation_id: Option<String>,
    thread_id: Option<String>,
    sender_id: Option<String>,
    normalized_text: Option<String>,
    source_locator: Option<String>,
    ignore_reason: Option<String>,
}

impl StoredDisposition {
    fn from_reserved(disposition: &SlackReservedDisposition) -> Self {
        match disposition {
            SlackReservedDisposition::Admit(message) => Self {
                kind: "admit".to_owned(),
                delivery_id: Some(message.delivery_id.clone()),
                workspace_id: Some(message.workspace_id.clone()),
                conversation_id: Some(message.conversation_id.clone()),
                thread_id: message.thread_id.clone(),
                sender_id: Some(message.sender_id.clone()),
                normalized_text: Some(message.text.clone()),
                source_locator: Some(message.source_locator.clone()),
                ignore_reason: None,
            },
            SlackReservedDisposition::Ignore(reason) => Self {
                kind: "ignore".to_owned(),
                delivery_id: None,
                workspace_id: None,
                conversation_id: None,
                thread_id: None,
                sender_id: None,
                normalized_text: None,
                source_locator: None,
                ignore_reason: Some(reason.clone()),
            },
        }
    }

    fn into_reserved(
        self,
        body_digest: String,
    ) -> Result<SlackReservedDisposition, SlackChannelStoreError> {
        match self.kind.as_str() {
            "admit" => Ok(SlackReservedDisposition::Admit(
                mealy_application::ChannelInboundMessage {
                    delivery_id: required(self.delivery_id, "delivery ID")?,
                    workspace_id: required(self.workspace_id, "workspace ID")?,
                    conversation_id: required(self.conversation_id, "conversation ID")?,
                    thread_id: self.thread_id,
                    sender_id: required(self.sender_id, "sender ID")?,
                    text: required(self.normalized_text, "normalized text")?,
                    body_digest,
                    source_locator: required(self.source_locator, "source locator")?,
                },
            )),
            "ignore" => Ok(SlackReservedDisposition::Ignore(required(
                self.ignore_reason,
                "ignore reason",
            )?)),
            _ => Err(invariant("stored Slack disposition kind is invalid")),
        }
    }
}

struct ReceiptRow {
    body_digest: String,
    disposition: StoredDisposition,
    state: String,
    inbox_entry_id: Option<String>,
    acknowledgement_outbox_id: Option<String>,
    acknowledged_at_ms: Option<i64>,
    received_at_ms: i64,
}

fn insert_receipt(
    transaction: &Transaction<'_>,
    binding_id: ChannelBindingId,
    session_id: mealy_domain::SessionId,
    acknowledgement_id: &str,
    body_digest: &str,
    disposition: &StoredDisposition,
    received_at_ms: i64,
) -> Result<(), SlackChannelStoreError> {
    transaction
        .execute(
            "INSERT INTO slack_envelope_receipt(\
                binding_id, acknowledgement_id, body_digest, disposition_kind, delivery_id, \
                workspace_id, conversation_id, thread_id, sender_id, normalized_text, \
                source_locator, ignore_reason, state, session_id, received_at_ms\
             ) VALUES (\
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'reserved', ?13, ?14\
             )",
            params![
                binding_id.to_string(),
                acknowledgement_id,
                body_digest,
                disposition.kind,
                disposition.delivery_id,
                disposition.workspace_id,
                disposition.conversation_id,
                disposition.thread_id,
                disposition.sender_id,
                disposition.normalized_text,
                disposition.source_locator,
                disposition.ignore_reason,
                session_id.to_string(),
                received_at_ms,
            ],
        )
        .map_err(map_registration_error)?;
    Ok(())
}

fn load_receipt(
    connection: &rusqlite::Connection,
    binding_id: ChannelBindingId,
    acknowledgement_id: &str,
) -> Result<Option<ReceiptRow>, SlackChannelStoreError> {
    connection
        .query_row(
            "SELECT body_digest, disposition_kind, delivery_id, workspace_id, conversation_id, \
                    thread_id, sender_id, normalized_text, source_locator, ignore_reason, state, \
                    inbox_entry_id, acknowledgement_outbox_id, acknowledged_at_ms, received_at_ms \
             FROM slack_envelope_receipt WHERE binding_id = ?1 AND acknowledgement_id = ?2",
            params![binding_id.to_string(), acknowledgement_id],
            |row| {
                Ok(ReceiptRow {
                    body_digest: row.get(0)?,
                    disposition: StoredDisposition {
                        kind: row.get(1)?,
                        delivery_id: row.get(2)?,
                        workspace_id: row.get(3)?,
                        conversation_id: row.get(4)?,
                        thread_id: row.get(5)?,
                        sender_id: row.get(6)?,
                        normalized_text: row.get(7)?,
                        source_locator: row.get(8)?,
                        ignore_reason: row.get(9)?,
                    },
                    state: row.get(10)?,
                    inbox_entry_id: row.get(11)?,
                    acknowledgement_outbox_id: row.get(12)?,
                    acknowledged_at_ms: row.get(13)?,
                    received_at_ms: row.get(14)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)
}

fn validate_disposition_route(
    binding: &SlackChannelBindingView,
    disposition: &SlackReservedDisposition,
) -> Result<(), SlackChannelStoreError> {
    if let SlackReservedDisposition::Admit(message) = disposition
        && (message.workspace_id != binding.team_id
            || message.conversation_id != binding.slack_channel_id
            || message.sender_id != binding.slack_user_id
            || message
                .thread_id
                .as_deref()
                .is_none_or(|thread| !valid_thread(thread)))
    {
        return Err(invalid_contract(
            "Slack admitted message exceeds its exact binding route",
        ));
    }
    Ok(())
}

fn supported_outbound_context(context: &SlackOutboundContext<'_>) -> bool {
    match context.topic {
        "session.input_acknowledgement"
        | "session.input_promoted"
        | "session.input_steered"
        | "session.interrupt_requested" => {
            context.inbox_entry_id.is_some()
                && context.task_id.is_none()
                && context.approval_id.is_none()
        }
        "session.turn_completed" => {
            context.inbox_entry_id.is_none()
                && context.task_id.is_some()
                && context.approval_id.is_none()
        }
        "effect.approval_requested" => {
            context.inbox_entry_id.is_none()
                && context.task_id.is_none()
                && context.approval_id.is_some()
        }
        _ => false,
    }
}

fn resolve_thread(
    connection: &rusqlite::Connection,
    binding_id: ChannelBindingId,
    context: &SlackOutboundContext<'_>,
) -> Result<Option<String>, SlackChannelStoreError> {
    let (predicate, identity) = if let Some(inbox_entry_id) = context.inbox_entry_id {
        ("receipt.inbox_entry_id = ?2", inbox_entry_id.to_string())
    } else if let Some(task_id) = context.task_id {
        (
            "receipt.inbox_entry_id = (SELECT inbox_entry_id FROM turn WHERE task_id = ?2)",
            task_id.to_string(),
        )
    } else if let Some(approval_id) = context.approval_id {
        (
            "receipt.inbox_entry_id = (\
                SELECT turn.inbox_entry_id FROM approval_request approval \
                JOIN turn ON turn.task_id = approval.task_id \
                WHERE approval.approval_id = ?2\
             )",
            approval_id.to_string(),
        )
    } else {
        return Ok(None);
    };
    let query = format!(
        "SELECT receipt.thread_id FROM slack_envelope_receipt receipt \
         WHERE receipt.binding_id = ?1 AND receipt.state = 'admitted' AND {predicate}"
    );
    let thread = connection
        .query_row(&query, params![binding_id.to_string(), identity], |row| {
            row.get::<_, Option<String>>(0)
        })
        .optional()
        .map_err(map_sqlite_error)?
        .flatten();
    if thread.as_deref().is_some_and(|value| !valid_thread(value)) {
        return Err(invariant("stored Slack thread identity is invalid"));
    }
    Ok(thread)
}

fn append_revocation_event(
    transaction: &Transaction<'_>,
    commit: &RevokeSlackChannelCommit,
    principal_id: PrincipalId,
    revoked_at_ms: i64,
) -> Result<(), SlackChannelStoreError> {
    let sequence = transaction
        .query_row(
            "SELECT sequence FROM aggregate_sequence \
             WHERE aggregate_kind = 'channel_binding' AND aggregate_id = ?1",
            [commit.binding_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    if sequence != 0 {
        return Err(invariant("Slack channel sequence is invalid"));
    }
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, 'channel_binding', ?2, 1, 'channel.slack_revoked', 1, ?3, ?4, ?5, \
                       'private', ?6)",
            params![
                commit.event_id.to_string(),
                commit.binding_id.to_string(),
                revoked_at_ms,
                principal_id.to_string(),
                commit.correlation_id.to_string(),
                json!({"binding_id": commit.binding_id}).to_string(),
            ],
        )
        .map_err(map_sqlite_error)?;
    let changed = transaction
        .execute(
            "UPDATE aggregate_sequence SET sequence = 1 \
             WHERE aggregate_kind = 'channel_binding' AND aggregate_id = ?1 AND sequence = 0",
            [commit.binding_id.to_string()],
        )
        .map_err(map_sqlite_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(SlackChannelStoreError::Conflict)
    }
}

fn authorize_administrator(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<(), SlackChannelStoreError> {
    let authorized = connection
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
    if authorized {
        Ok(())
    } else {
        Err(SlackChannelStoreError::NotFound)
    }
}

#[allow(clippy::too_many_lines)]
fn load_binding(
    connection: &rusqlite::Connection,
    binding_id: ChannelBindingId,
) -> Result<SlackChannelBindingView, SlackChannelStoreError> {
    let row = connection
        .query_row(
            "SELECT binding.principal_id, binding.session_id, binding.team_id, binding.team_name, \
                    binding.slack_user_id, binding.slack_channel_id, binding.bot_user_id, \
                    binding.bot_name, binding.require_mention, binding.app_token_secret_id, \
                    binding.app_token_digest, binding.bot_token_secret_id, \
                    binding.bot_token_digest, binding.status, binding.revision, \
                    binding.created_at_ms, binding.updated_at_ms, health.last_success_at_ms, \
                    health.last_failure_at_ms, health.consecutive_failures, health.last_error_code, \
                    registry.principal_id, registry.channel_kind, registry.installation_id, \
                    registry.status, registry.revision \
             FROM slack_channel_binding binding \
             JOIN slack_channel_health health USING(binding_id) \
             JOIN channel_binding_registry registry USING(binding_id) \
             WHERE binding.binding_id = ?1",
            [binding_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, bool>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, Option<i64>>(17)?,
                    row.get::<_, Option<i64>>(18)?,
                    row.get::<_, i64>(19)?,
                    row.get::<_, Option<String>>(20)?,
                    row.get::<_, String>(21)?,
                    row.get::<_, String>(22)?,
                    row.get::<_, Option<String>>(23)?,
                    row.get::<_, String>(24)?,
                    row.get::<_, i64>(25)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(SlackChannelStoreError::NotFound)?;
    if row.0 != row.21
        || row.22 != "extension_channel"
        || row.23.as_deref() != Some(SLACK_INSTALLATION_ID)
        || row.13 != row.24
        || row.14 != row.25
        || row.19 < 0
    {
        return Err(invariant("Slack binding and registry diverged"));
    }
    validate_slack_binding(
        &row.2, &row.3, &row.4, &row.5, &row.6, &row.7, row.8, &row.9, &row.10, &row.11, &row.12,
    )
    .map_err(|_| invariant("stored Slack binding is invalid"))?;
    Ok(SlackChannelBindingView {
        binding_id,
        principal_id: parse_id(&row.0, "Slack principal ID")?,
        session_id: parse_id(&row.1, "Slack session ID")?,
        team_id: row.2,
        team_name: row.3,
        slack_user_id: row.4,
        slack_channel_id: row.5,
        bot_user_id: row.6,
        bot_name: row.7,
        require_mention: row.8,
        app_token_secret_id: row.9,
        app_token_digest: row.10,
        bot_token_secret_id: row.11,
        bot_token_digest: row.12,
        status: match row.13.as_str() {
            "active" => SlackChannelStatus::Active,
            "revoked" => SlackChannelStatus::Revoked,
            _ => return Err(invariant("Slack binding status is invalid")),
        },
        revision: nonnegative(row.14, "Slack binding revision")?,
        last_success_at_ms: row.17,
        last_failure_at_ms: row.18,
        consecutive_failures: nonnegative(row.19, "Slack consecutive failures")?,
        last_error_code: row.20,
        created_at_ms: row.15,
        updated_at_ms: row.16,
    })
}

fn valid_thread(value: &str) -> bool {
    let Some((seconds, micros)) = value.split_once('.') else {
        return false;
    };
    !seconds.is_empty()
        && seconds.len() <= 16
        && !micros.is_empty()
        && micros.len() <= 6
        && seconds.bytes().all(|byte| byte.is_ascii_digit())
        && micros.bytes().all(|byte| byte.is_ascii_digit())
}

fn required(value: Option<String>, field: &str) -> Result<String, SlackChannelStoreError> {
    value.ok_or_else(|| invariant(format!("stored Slack {field} is absent")))
}

fn epoch_milliseconds(time: SystemTime) -> Result<i64, SlackChannelStoreError> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invariant("Slack channel time precedes the Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| invariant("Slack channel time exceeds SQLite"))
}

fn nonnegative(value: i64, field: &str) -> Result<u64, SlackChannelStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn to_i64(value: u64) -> Result<i64, SlackChannelStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract("Slack revision exceeds SQLite"))
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, SlackChannelStoreError> {
    T::from_str(value).map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn map_registration_error(error: rusqlite::Error) -> SlackChannelStoreError {
    if matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    ) {
        SlackChannelStoreError::Conflict
    } else {
        map_sqlite_error(error)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> SlackChannelStoreError {
    SlackChannelStoreError::Unavailable(error.to_string())
}

fn invalid_contract(message: impl Into<String>) -> SlackChannelStoreError {
    SlackChannelStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> SlackChannelStoreError {
    SlackChannelStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::SlackChannelStore;
    use mealy_application::{
        AcknowledgeSlackEnvelopeCommit, AdmitInputCommand, ChannelInboundMessage,
        CompleteSlackEnvelopeCommit, InputAdmissionLimits, OwnershipContext,
        RecordSlackSocketCommit, RegisterSlackChannelCommit, ReserveSlackEnvelopeCommit,
        RevokeSlackChannelCommit, SlackChannelStatus, SlackEnvelopeDisposition,
        SlackEnvelopeReservation, SlackOutboundContext, SlackReservedDisposition, admit_input,
        sha256_digest, slack_input_dedupe_key,
    };
    use mealy_domain::{
        ChannelBindingId, CorrelationId, DeliveryMode, EventId, PrincipalId, SessionId,
    };
    use mealy_testkit::{TestClock, TestIdGenerator};
    use std::time::{Duration, SystemTime};

    #[test]
    #[allow(clippy::too_many_lines)]
    fn socket_reservation_ack_recovery_thread_routing_and_revocation_are_durable() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_hours(500_000);
        let clock = TestClock::new(1_800_000_000_000);
        let ids = TestIdGenerator::new(1_800_000_000_000);
        let mut store = super::SqliteStore::open_in_memory(1).expect("store");
        let principal_id = PrincipalId::new();
        let administrator = OwnershipContext::new(principal_id, ChannelBindingId::new());
        store
            .register_local_identity(administrator, 1)
            .expect("register administrator");
        let binding_id = ChannelBindingId::new();
        let session_id = SessionId::new();
        let app_digest = sha256_digest(b"xapp-test");
        let bot_digest = sha256_digest(b"xoxb-test");
        let binding = store
            .register_slack_channel(RegisterSlackChannelCommit {
                administrative_ownership: administrator,
                binding_id,
                session_id,
                team_id: "T01234567".to_owned(),
                team_name: "Mealy Test".to_owned(),
                slack_user_id: "U01234567".to_owned(),
                slack_channel_id: "C01234567".to_owned(),
                bot_user_id: "U07654321".to_owned(),
                bot_name: "mealy".to_owned(),
                require_mention: true,
                app_token_secret_id: format!("slack.app.{binding_id}"),
                app_token_digest: app_digest.clone(),
                bot_token_secret_id: format!("slack.bot.{binding_id}"),
                bot_token_digest: bot_digest.clone(),
                session_event_id: EventId::new(),
                binding_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at: now,
            })
            .expect("register Slack binding");
        assert_eq!(binding.status, SlackChannelStatus::Active);
        let targets = store
            .active_slack_socket_targets(10)
            .expect("socket targets");
        assert_eq!(targets[0].app_token_digest, app_digest);
        assert_eq!(targets[0].bot_token_digest, bot_digest);

        let body_digest = sha256_digest(br#"{"envelope_id":"env-1"}"#);
        let disposition = SlackReservedDisposition::Admit(ChannelInboundMessage {
            delivery_id: "Ev01234567".to_owned(),
            workspace_id: "T01234567".to_owned(),
            conversation_id: "C01234567".to_owned(),
            thread_id: Some("1785254000.000100".to_owned()),
            sender_id: "U01234567".to_owned(),
            text: "review the incident".to_owned(),
            body_digest: body_digest.clone(),
            source_locator: "slack://T01234567/C01234567/Ev01234567".to_owned(),
        });
        assert_eq!(
            store
                .reserve_slack_envelope(ReserveSlackEnvelopeCommit {
                    binding_id,
                    acknowledgement_id: "env-1".to_owned(),
                    body_digest: body_digest.clone(),
                    disposition: disposition.clone(),
                    received_at: now,
                })
                .expect("reserve envelope"),
            SlackEnvelopeReservation::Reserved
        );
        assert_eq!(
            store
                .reserve_slack_envelope(ReserveSlackEnvelopeCommit {
                    binding_id,
                    acknowledgement_id: "env-1".to_owned(),
                    body_digest: body_digest.clone(),
                    disposition,
                    received_at: now,
                })
                .expect("recover reservation"),
            SlackEnvelopeReservation::ExistingReserved
        );
        store
            .acknowledge_slack_envelope(AcknowledgeSlackEnvelopeCommit {
                binding_id,
                acknowledgement_id: "env-1".to_owned(),
                acknowledged_at: now + Duration::from_millis(1),
            })
            .expect("record acknowledgement");
        let pending = store
            .pending_slack_envelopes(binding_id, 10)
            .expect("pending envelope");
        assert_eq!(pending.len(), 1);
        assert!(pending[0].acknowledged_at_ms.is_some());
        let SlackReservedDisposition::Admit(recovered) = &pending[0].disposition else {
            panic!("expected admitted reservation");
        };
        assert_eq!(recovered.body_digest, body_digest);

        let outcome = admit_input(
            &mut store,
            &clock,
            &ids,
            InputAdmissionLimits::default(),
            AdmitInputCommand {
                session_id,
                ownership: OwnershipContext::new(principal_id, binding_id),
                dedupe_key: slack_input_dedupe_key(binding_id, "Ev01234567").expect("dedupe key"),
                delivery_mode: DeliveryMode::Queue,
                content: recovered.text.clone(),
                provider_selection: mealy_application::ProviderSelectionPreference::InheritSession,
            },
        )
        .expect("admit Slack input");
        let admission = outcome.receipt().clone();
        store
            .complete_slack_envelope(CompleteSlackEnvelopeCommit {
                binding_id,
                acknowledgement_id: "env-1".to_owned(),
                disposition: SlackEnvelopeDisposition::Admitted(admission.clone()),
                completed_at: now + Duration::from_millis(2),
            })
            .expect("complete envelope");
        assert!(
            store
                .pending_slack_envelopes(binding_id, 10)
                .expect("no pending envelopes")
                .is_empty()
        );
        let target = store
            .outbound_slack_target(SlackOutboundContext {
                session_id,
                topic: "session.input_acknowledgement",
                inbox_entry_id: Some(admission.inbox_entry_id),
                task_id: None,
                approval_id: None,
            })
            .expect("Slack route")
            .expect("active Slack target");
        assert_eq!(target.thread_id.as_deref(), Some("1785254000.000100"));
        assert_eq!(
            store
                .reserve_slack_envelope(ReserveSlackEnvelopeCommit {
                    binding_id,
                    acknowledgement_id: "env-1".to_owned(),
                    body_digest,
                    disposition: pending[0].disposition.clone(),
                    received_at: now,
                })
                .expect("recognize completed envelope"),
            SlackEnvelopeReservation::ExistingCompleted
        );

        store
            .record_slack_socket(RecordSlackSocketCommit {
                binding_id,
                succeeded: false,
                error_code: Some("slack_socket_closed".to_owned()),
                observed_at: now + Duration::from_millis(3),
            })
            .expect("failed socket health");
        assert_eq!(
            store
                .slack_channel(administrator, binding_id)
                .expect("failed health view")
                .consecutive_failures,
            1
        );
        store
            .record_slack_socket(RecordSlackSocketCommit {
                binding_id,
                succeeded: true,
                error_code: None,
                observed_at: now + Duration::from_millis(4),
            })
            .expect("healthy socket");
        let revoked = store
            .revoke_slack_channel(RevokeSlackChannelCommit {
                administrative_ownership: administrator,
                binding_id,
                expected_revision: 0,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                revoked_at: now + Duration::from_millis(5),
            })
            .expect("revoke channel");
        assert_eq!(revoked.status, SlackChannelStatus::Revoked);
        assert!(
            store
                .active_slack_socket_targets(10)
                .expect("no active targets")
                .is_empty()
        );
    }
}
