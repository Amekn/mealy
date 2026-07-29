use super::SqliteStore;
use mealy_application::{
    AutomationAction, AutomationCandidate, AutomationClaimOutcome, AutomationRunStatus,
    AutomationRunView, AutomationStatus, AutomationStore, AutomationStoreError,
    AutomationTransition, AutomationTrigger, AutomationTriggerView, AutomationView,
    ClaimAutomationRunCommit, CompleteAutomationRunCommit, CreateAutomationCommit,
    EditAutomationCommit, OwnershipContext, TransitionAutomationCommit, sha256_digest,
    validate_automation_definition, validate_automation_view,
};
use mealy_domain::{
    AutomationId, AutomationRunId, EventId, InboxEntryId, OutboxId, PrincipalId, SessionId,
};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::str::FromStr;

const MAXIMUM_DUE_LIMIT: usize = 100;
const MAXIMUM_HISTORY_LIMIT: usize = 1_000;
const MAXIMUM_CLAIM_MS: i64 = 5 * 60 * 1_000;
const MAXIMUM_REASON_BYTES: usize = 4_096;

impl AutomationStore for SqliteStore {
    #[allow(clippy::too_many_lines)]
    fn create_automation(
        &mut self,
        commit: CreateAutomationCommit,
    ) -> Result<AutomationView, AutomationStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.manager_ownership)?;
        match load_automation(
            &transaction,
            commit.automation_id,
            Some(commit.manager_ownership),
        ) {
            Ok(existing)
                if existing.manager_ownership == commit.manager_ownership
                    && existing.name == commit.name
                    && trigger_matches(&existing.trigger, &commit.trigger)
                    && existing.action == commit.action =>
            {
                return Ok(existing);
            }
            Ok(_) => return Err(AutomationStoreError::Conflict),
            Err(AutomationStoreError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let target_ownership = session_ownership(
            &transaction,
            commit.manager_ownership.principal_id(),
            commit.action.target_session_id(),
            "target",
        )?;
        ensure_automation_target_supported(&transaction, &commit.action)?;
        authorize_source(
            &transaction,
            commit.manager_ownership.principal_id(),
            &commit.trigger,
        )?;
        validate_automation_definition(
            &commit.name,
            &commit.trigger,
            &commit.action,
            commit.created_at_ms,
        )
        .map_err(|error| invalid_contract(error.to_string()))?;
        let source_after_cursor =
            if matches!(commit.trigger, AutomationTrigger::SessionEvent { .. }) {
                Some(high_cursor(&transaction)?)
            } else {
                None
            };
        let definition = definition_json(
            &commit.name,
            &commit.trigger,
            &commit.action,
            source_after_cursor,
        );
        let definition_json = definition.to_string();
        let definition_digest = sha256_digest(definition_json.as_bytes());
        let (trigger_kind, due_at_ms, source_session_id, source_event_type) =
            trigger_columns(&commit.trigger);
        let (action_kind, action_body, approval_allowed) = action_columns(&commit.action);
        transaction
            .execute(
                "INSERT INTO automation(\
                automation_id, principal_id, manager_binding_id, target_binding_id, \
                target_session_id, name, trigger_kind, due_at_ms, source_session_id, \
                source_event_type, source_after_cursor, action_kind, action_body, \
                approval_required_actions_allowed, status, revision, created_at_ms, updated_at_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                       'active', 0, ?15, ?15)",
                params![
                    commit.automation_id.to_string(),
                    commit.manager_ownership.principal_id().to_string(),
                    commit.manager_ownership.channel_binding_id().to_string(),
                    target_ownership.channel_binding_id().to_string(),
                    commit.action.target_session_id().to_string(),
                    commit.name,
                    trigger_kind,
                    due_at_ms,
                    source_session_id,
                    source_event_type,
                    source_after_cursor.map(to_i64).transpose()?,
                    action_kind,
                    action_body,
                    i64::from(approval_allowed),
                    commit.created_at_ms,
                ],
            )
            .map_err(map_constraint_error)?;
        transaction
            .execute(
                "INSERT INTO aggregate_sequence(aggregate_kind, aggregate_id, sequence) \
                 VALUES ('automation', ?1, 0)",
                [commit.automation_id.to_string()],
            )
            .map_err(map_constraint_error)?;
        append_event(
            &transaction,
            commit.automation_id,
            0,
            commit.event_id,
            "automation.created",
            commit.created_at_ms,
            Some(commit.manager_ownership.principal_id()),
            commit.correlation_id,
            json!({
                "action_kind": action_kind,
                "definition_digest": definition_digest,
                "name": commit.name,
                "target_session_id": commit.action.target_session_id(),
                "trigger_kind": trigger_kind,
            }),
        )?;
        transaction
            .execute(
                "INSERT INTO automation_revision(automation_id, revision, definition_json, \
                                                definition_digest, event_id, recorded_at_ms) \
                 VALUES (?1, 0, ?2, ?3, ?4, ?5)",
                params![
                    commit.automation_id.to_string(),
                    definition_json,
                    definition_digest,
                    commit.event_id.to_string(),
                    commit.created_at_ms,
                ],
            )
            .map_err(map_constraint_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_automation(
            &self.connection,
            commit.automation_id,
            Some(commit.manager_ownership),
        )
    }

    fn automation(
        &self,
        manager_ownership: OwnershipContext,
        automation_id: AutomationId,
    ) -> Result<AutomationView, AutomationStoreError> {
        authorize_administrator(&self.connection, manager_ownership)?;
        load_automation(&self.connection, automation_id, Some(manager_ownership))
    }

    fn automations(
        &self,
        manager_ownership: OwnershipContext,
    ) -> Result<Vec<AutomationView>, AutomationStoreError> {
        authorize_administrator(&self.connection, manager_ownership)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT automation_id FROM automation WHERE principal_id = ?1 \
                 ORDER BY created_at_ms, automation_id",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map([manager_ownership.principal_id().to_string()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| {
                load_automation(
                    &self.connection,
                    parse_id(&id, "automation ID")?,
                    Some(manager_ownership),
                )
            })
            .collect()
    }

    #[allow(clippy::too_many_lines)]
    fn edit_automation(
        &mut self,
        commit: EditAutomationCommit,
    ) -> Result<AutomationView, AutomationStoreError> {
        validate_automation_definition(
            &commit.name,
            &commit.trigger,
            &commit.action,
            commit.edited_at_ms,
        )
        .map_err(|error| invalid_contract(error.to_string()))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.manager_ownership)?;
        let current = load_automation(
            &transaction,
            commit.automation_id,
            Some(commit.manager_ownership),
        )?;
        if current.revision != commit.expected_revision
            || commit.edited_at_ms < current.updated_at_ms
            || !matches!(
                current.status,
                AutomationStatus::Active | AutomationStatus::Paused
            )
            || has_active_claim(&transaction, commit.automation_id)?
        {
            return Err(AutomationStoreError::Conflict);
        }
        let target_ownership = session_ownership(
            &transaction,
            commit.manager_ownership.principal_id(),
            commit.action.target_session_id(),
            "target",
        )?;
        ensure_automation_target_supported(&transaction, &commit.action)?;
        authorize_source(
            &transaction,
            commit.manager_ownership.principal_id(),
            &commit.trigger,
        )?;
        let source_after_cursor =
            if matches!(commit.trigger, AutomationTrigger::SessionEvent { .. }) {
                Some(high_cursor(&transaction)?)
            } else {
                None
            };
        let definition = definition_json(
            &commit.name,
            &commit.trigger,
            &commit.action,
            source_after_cursor,
        );
        let definition_json = definition.to_string();
        let definition_digest = sha256_digest(definition_json.as_bytes());
        let (trigger_kind, due_at_ms, source_session_id, source_event_type) =
            trigger_columns(&commit.trigger);
        let (action_kind, action_body, approval_allowed) = action_columns(&commit.action);
        let next_revision = commit
            .expected_revision
            .checked_add(1)
            .ok_or_else(|| invalid_contract("automation revision overflow"))?;
        let changed = transaction
            .execute(
                "UPDATE automation SET target_binding_id = ?1, target_session_id = ?2, name = ?3, \
                    trigger_kind = ?4, due_at_ms = ?5, source_session_id = ?6, \
                    source_event_type = ?7, source_after_cursor = ?8, action_kind = ?9, \
                    action_body = ?10, approval_required_actions_allowed = ?11, \
                    revision = ?12, updated_at_ms = ?13 \
                 WHERE automation_id = ?14 AND principal_id = ?15 AND revision = ?16 \
                   AND status IN ('active', 'paused') \
                   AND NOT EXISTS (SELECT 1 FROM automation_run run \
                                   WHERE run.automation_id = automation.automation_id \
                                     AND run.status = 'claimed')",
                params![
                    target_ownership.channel_binding_id().to_string(),
                    commit.action.target_session_id().to_string(),
                    commit.name,
                    trigger_kind,
                    due_at_ms,
                    source_session_id,
                    source_event_type,
                    source_after_cursor.map(to_i64).transpose()?,
                    action_kind,
                    action_body,
                    i64::from(approval_allowed),
                    to_i64(next_revision)?,
                    commit.edited_at_ms,
                    commit.automation_id.to_string(),
                    commit.manager_ownership.principal_id().to_string(),
                    to_i64(commit.expected_revision)?,
                ],
            )
            .map_err(map_constraint_error)?;
        if changed != 1 {
            return Err(AutomationStoreError::Conflict);
        }
        append_event(
            &transaction,
            commit.automation_id,
            increment_sequence(&transaction, commit.automation_id)?,
            commit.event_id,
            "automation.edited",
            commit.edited_at_ms,
            Some(commit.manager_ownership.principal_id()),
            commit.correlation_id,
            json!({
                "action_kind": action_kind,
                "definition_digest": definition_digest,
                "revision": next_revision,
                "target_session_id": commit.action.target_session_id(),
                "trigger_kind": trigger_kind,
            }),
        )?;
        transaction
            .execute(
                "INSERT INTO automation_revision(automation_id, revision, definition_json, \
                                                definition_digest, event_id, recorded_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    commit.automation_id.to_string(),
                    to_i64(next_revision)?,
                    definition_json,
                    definition_digest,
                    commit.event_id.to_string(),
                    commit.edited_at_ms,
                ],
            )
            .map_err(map_constraint_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_automation(
            &self.connection,
            commit.automation_id,
            Some(commit.manager_ownership),
        )
    }

    fn transition_automation(
        &mut self,
        commit: TransitionAutomationCommit,
    ) -> Result<AutomationView, AutomationStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        authorize_administrator(&transaction, commit.manager_ownership)?;
        let current = load_automation(
            &transaction,
            commit.automation_id,
            Some(commit.manager_ownership),
        )?;
        if current.revision != commit.expected_revision
            || commit.transitioned_at_ms < current.updated_at_ms
            || has_active_claim(&transaction, commit.automation_id)?
        {
            return Err(AutomationStoreError::Conflict);
        }
        let (expected_status, new_status, event_type) = match (current.status, commit.transition) {
            (AutomationStatus::Active, AutomationTransition::Pause) => {
                ("active", "paused", "automation.paused")
            }
            (AutomationStatus::Paused, AutomationTransition::Resume) => {
                ("paused", "active", "automation.resumed")
            }
            (AutomationStatus::Active | AutomationStatus::Paused, AutomationTransition::Cancel) => {
                (
                    status_text(current.status),
                    "cancelled",
                    "automation.cancelled",
                )
            }
            _ => return Err(AutomationStoreError::Conflict),
        };
        let source_after_cursor = if commit.transition == AutomationTransition::Resume
            && matches!(current.trigger, AutomationTriggerView::SessionEvent { .. })
        {
            Some(high_cursor(&transaction)?)
        } else {
            trigger_after_cursor(&current.trigger)
        };
        let next_revision = commit
            .expected_revision
            .checked_add(1)
            .ok_or_else(|| invalid_contract("automation revision overflow"))?;
        let changed = transaction
            .execute(
                "UPDATE automation SET status = ?1, source_after_cursor = ?2, revision = ?3, \
                    updated_at_ms = ?4 \
                 WHERE automation_id = ?5 AND principal_id = ?6 AND revision = ?7 \
                   AND status = ?8 \
                   AND NOT EXISTS (SELECT 1 FROM automation_run run \
                                   WHERE run.automation_id = automation.automation_id \
                                     AND run.status = 'claimed')",
                params![
                    new_status,
                    source_after_cursor.map(to_i64).transpose()?,
                    to_i64(next_revision)?,
                    commit.transitioned_at_ms,
                    commit.automation_id.to_string(),
                    commit.manager_ownership.principal_id().to_string(),
                    to_i64(commit.expected_revision)?,
                    expected_status,
                ],
            )
            .map_err(map_constraint_error)?;
        if changed != 1 {
            return Err(AutomationStoreError::Conflict);
        }
        append_event(
            &transaction,
            commit.automation_id,
            increment_sequence(&transaction, commit.automation_id)?,
            commit.event_id,
            event_type,
            commit.transitioned_at_ms,
            Some(commit.manager_ownership.principal_id()),
            commit.correlation_id,
            json!({
                "after_cursor": source_after_cursor,
                "revision": next_revision,
                "status": new_status,
            }),
        )?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_automation(
            &self.connection,
            commit.automation_id,
            Some(commit.manager_ownership),
        )
    }

    fn due_automations(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<AutomationCandidate>, AutomationStoreError> {
        if now_ms < 0 || !(1..=MAXIMUM_DUE_LIMIT).contains(&limit) {
            return Err(invalid_contract("due automation query is invalid"));
        }
        let sql_limit =
            i64::try_from(limit).map_err(|_| invalid_contract("due limit exceeds SQLite"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT automation_id, trigger_key, triggered_at_ms, source_event_cursor, \
                        source_event_id, source_event_type \
                 FROM (\
                    SELECT automation.automation_id AS automation_id, \
                           'time:' || CAST(automation.due_at_ms AS TEXT) AS trigger_key, \
                           automation.due_at_ms AS triggered_at_ms, \
                           NULL AS source_event_cursor, NULL AS source_event_id, \
                           NULL AS source_event_type \
                    FROM automation \
                    WHERE automation.status = 'active' \
                      AND automation.trigger_kind = 'one_shot' \
                      AND automation.due_at_ms <= ?1 \
                      AND NOT EXISTS (\
                          SELECT 1 FROM automation_run run \
                          WHERE run.automation_id = automation.automation_id \
                            AND run.trigger_key = 'time:' || CAST(automation.due_at_ms AS TEXT) \
                            AND (run.status <> 'claimed' OR run.claim_expires_at_ms > ?1)\
                      ) \
                    UNION ALL \
                    SELECT automation.automation_id, \
                           'event:' || CAST(timeline.cursor AS TEXT), \
                           journal.occurred_at_ms, timeline.cursor, journal.event_id, \
                           journal.event_type \
                    FROM automation \
                    JOIN timeline_event timeline ON timeline.cursor = (\
                        SELECT MIN(candidate.cursor) FROM timeline_event candidate \
                        JOIN journal_event candidate_event \
                          ON candidate_event.event_id = candidate.event_id \
                        WHERE candidate.cursor > automation.source_after_cursor \
                          AND candidate_event.aggregate_kind = 'session' \
                          AND candidate_event.aggregate_id = automation.source_session_id \
                          AND candidate_event.event_type = automation.source_event_type\
                    ) \
                    JOIN journal_event journal ON journal.event_id = timeline.event_id \
                    WHERE automation.status = 'active' \
                      AND automation.trigger_kind = 'session_event' \
                      AND journal.occurred_at_ms <= ?1 \
                      AND NOT EXISTS (\
                          SELECT 1 FROM automation_run run \
                          WHERE run.automation_id = automation.automation_id \
                            AND run.trigger_key = 'event:' || CAST(timeline.cursor AS TEXT) \
                            AND (run.status <> 'claimed' OR run.claim_expires_at_ms > ?1)\
                      )\
                 ) ORDER BY triggered_at_ms, automation_id LIMIT ?2",
            )
            .map_err(map_sqlite_error)?;
        let rows = statement
            .query_map(params![now_ms, sql_limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?;
        rows.into_iter()
            .map(
                |(
                    automation_id,
                    trigger_key,
                    triggered_at_ms,
                    source_cursor,
                    source_event_id,
                    source_event_type,
                )| {
                    let automation_id = parse_id(&automation_id, "automation ID")?;
                    Ok(AutomationCandidate {
                        automation: load_automation(&self.connection, automation_id, None)?,
                        trigger_key,
                        triggered_at_ms,
                        source_event_cursor: source_cursor
                            .map(|cursor| nonnegative(cursor, "source cursor"))
                            .transpose()?,
                        source_event_id: source_event_id
                            .as_deref()
                            .map(|id| parse_id(id, "source event ID"))
                            .transpose()?,
                        source_event_type,
                    })
                },
            )
            .collect()
    }

    fn claim_automation_run(
        &mut self,
        commit: ClaimAutomationRunCommit,
    ) -> Result<AutomationClaimOutcome, AutomationStoreError> {
        validate_claim(&commit)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let automation = load_automation(&transaction, commit.automation_id, None)?;
        if automation.status != AutomationStatus::Active
            || automation.revision != commit.expected_revision
            || !claim_matches_trigger(&transaction, &automation, &commit)?
        {
            return Ok(AutomationClaimOutcome::Busy);
        }
        let existing = load_run_by_key(&transaction, commit.automation_id, &commit.trigger_key)?;
        if let Some(existing) = existing {
            if existing.status != AutomationRunStatus::Claimed {
                return Ok(AutomationClaimOutcome::Busy);
            }
            let changed = transaction
                .execute(
                    "UPDATE automation_run SET claim_owner_id = ?1, claim_expires_at_ms = ?2 \
                     WHERE automation_run_id = ?3 AND status = 'claimed' \
                       AND claim_expires_at_ms <= ?4",
                    params![
                        commit.owner_id.to_string(),
                        commit.claim_expires_at_ms,
                        existing.automation_run_id.to_string(),
                        commit.claimed_at_ms,
                    ],
                )
                .map_err(map_constraint_error)?;
            if changed != 1 {
                return Ok(AutomationClaimOutcome::Busy);
            }
            transaction.commit().map_err(map_sqlite_error)?;
            return load_run(&self.connection, existing.automation_run_id)
                .map(Box::new)
                .map(AutomationClaimOutcome::Claimed);
        }
        transaction
            .execute(
                "INSERT INTO automation_run(\
                    automation_run_id, automation_id, trigger_key, triggered_at_ms, \
                    source_event_cursor, source_event_id, source_event_type, status, \
                    claim_owner_id, claim_expires_at_ms, created_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'claimed', ?8, ?9, ?10)",
                params![
                    commit.proposed_automation_run_id.to_string(),
                    commit.automation_id.to_string(),
                    commit.trigger_key,
                    commit.triggered_at_ms,
                    commit.source_event_cursor.map(to_i64).transpose()?,
                    commit.source_event_id.map(|id| id.to_string()),
                    commit.source_event_type,
                    commit.owner_id.to_string(),
                    commit.claim_expires_at_ms,
                    commit.claimed_at_ms,
                ],
            )
            .map_err(map_constraint_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_run(&self.connection, commit.proposed_automation_run_id)
            .map(Box::new)
            .map(AutomationClaimOutcome::Claimed)
    }

    #[allow(clippy::too_many_lines)]
    fn complete_automation_run(
        &mut self,
        commit: CompleteAutomationRunCommit,
    ) -> Result<AutomationRunView, AutomationStoreError> {
        validate_completion(&commit)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let automation = load_automation(&transaction, commit.automation_id, None)?;
        let run = load_run(&transaction, commit.automation_run_id)?;
        if run.automation_id != automation.automation_id
            || run.status != AutomationRunStatus::Claimed
            || commit.completed_at_ms < run.created_at_ms
        {
            return Err(AutomationStoreError::Conflict);
        }
        let claim_owner = transaction
            .query_row(
                "SELECT claim_owner_id FROM automation_run WHERE automation_run_id = ?1",
                [commit.automation_run_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .map_err(map_sqlite_error)?;
        if claim_owner != commit.owner_id.to_string() {
            return Err(AutomationStoreError::Conflict);
        }
        validate_completion_for_action(&automation.action, &commit)?;
        if commit.status == AutomationRunStatus::Notified {
            let outbox_id = commit
                .outbox_id
                .ok_or_else(|| invalid_contract("notification outbox ID is absent"))?;
            let AutomationAction::Notify {
                target_session_id,
                message,
            } = &automation.action
            else {
                return Err(invalid_contract("notification outcome has a prompt action"));
            };
            let current_target = session_ownership(
                &transaction,
                automation.manager_ownership.principal_id(),
                *target_session_id,
                "target",
            )?;
            if current_target != automation.target_ownership {
                return Err(AutomationStoreError::Unauthorized);
            }
            ensure_automation_target_supported(&transaction, &automation.action).map_err(
                |error| match error {
                    AutomationStoreError::InvalidContract(_)
                    | AutomationStoreError::Unauthorized => AutomationStoreError::Unauthorized,
                    other => other,
                },
            )?;
            transaction
                .execute(
                    "INSERT INTO outbox(outbox_id, topic, payload_json, created_at_ms) \
                     VALUES (?1, 'automation.notification', ?2, ?3)",
                    params![
                        outbox_id.to_string(),
                        json!({
                            "automation_id": automation.automation_id,
                            "automation_run_id": run.automation_run_id,
                            "message": message,
                            "session_id": target_session_id,
                            "source_event_cursor": run.source_event_cursor,
                            "source_event_id": run.source_event_id,
                            "source_event_type": run.source_event_type,
                            "triggered_at_ms": run.triggered_at_ms,
                        })
                        .to_string(),
                        commit.completed_at_ms,
                    ],
                )
                .map_err(map_constraint_error)?;
        }
        let changed = transaction
            .execute(
                "UPDATE automation_run SET status = ?1, inbox_entry_id = ?2, outbox_id = ?3, \
                    reason = ?4, completed_at_ms = ?5 \
                 WHERE automation_run_id = ?6 AND automation_id = ?7 AND status = 'claimed' \
                   AND claim_owner_id = ?8",
                params![
                    run_status_text(commit.status),
                    commit.inbox_entry_id.map(|id| id.to_string()),
                    commit.outbox_id.map(|id| id.to_string()),
                    commit.reason,
                    commit.completed_at_ms,
                    commit.automation_run_id.to_string(),
                    commit.automation_id.to_string(),
                    commit.owner_id.to_string(),
                ],
            )
            .map_err(map_constraint_error)?;
        if changed != 1 {
            return Err(AutomationStoreError::Conflict);
        }
        let next_revision = automation
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid_contract("automation revision overflow"))?;
        let (new_status, new_cursor) = match &automation.trigger {
            AutomationTriggerView::OneShot { .. } => ("completed", None),
            AutomationTriggerView::SessionEvent { after_cursor, .. } => {
                let cursor = run
                    .source_event_cursor
                    .filter(|cursor| cursor > after_cursor)
                    .ok_or_else(|| invariant("event run cursor does not advance automation"))?;
                ("active", Some(cursor))
            }
        };
        let changed = transaction
            .execute(
                "UPDATE automation SET status = ?1, source_after_cursor = ?2, revision = ?3, \
                    updated_at_ms = ?4 \
                 WHERE automation_id = ?5 AND status = 'active' AND revision = ?6",
                params![
                    new_status,
                    new_cursor.map(to_i64).transpose()?,
                    to_i64(next_revision)?,
                    commit.completed_at_ms,
                    commit.automation_id.to_string(),
                    to_i64(automation.revision)?,
                ],
            )
            .map_err(map_constraint_error)?;
        if changed != 1 {
            return Err(AutomationStoreError::Conflict);
        }
        let sequence = increment_sequence(&transaction, commit.automation_id)?;
        append_event(
            &transaction,
            commit.automation_id,
            sequence,
            commit.event_id,
            match commit.status {
                AutomationRunStatus::Admitted => "automation.admitted",
                AutomationRunStatus::Notified => "automation.notified",
                AutomationRunStatus::Failed => "automation.failed",
                AutomationRunStatus::Claimed => unreachable!("validated terminal status"),
            },
            commit.completed_at_ms,
            None,
            commit.correlation_id,
            json!({
                "automation_run_id": commit.automation_run_id,
                "inbox_entry_id": commit.inbox_entry_id,
                "outbox_id": commit.outbox_id,
                "reason": commit.reason,
                "revision": next_revision,
                "source_event_cursor": run.source_event_cursor,
                "status": run_status_text(commit.status),
            }),
        )?;
        transaction.commit().map_err(map_sqlite_error)?;
        load_run(&self.connection, commit.automation_run_id)
    }

    fn automation_runs(
        &self,
        manager_ownership: OwnershipContext,
        automation_id: AutomationId,
        limit: usize,
    ) -> Result<Vec<AutomationRunView>, AutomationStoreError> {
        authorize_administrator(&self.connection, manager_ownership)?;
        load_automation(&self.connection, automation_id, Some(manager_ownership))?;
        if !(1..=MAXIMUM_HISTORY_LIMIT).contains(&limit) {
            return Err(invalid_contract("automation history limit is invalid"));
        }
        let limit =
            i64::try_from(limit).map_err(|_| invalid_contract("history limit exceeds SQLite"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT automation_run_id FROM automation_run WHERE automation_id = ?1 \
                 ORDER BY triggered_at_ms DESC, automation_run_id DESC LIMIT ?2",
            )
            .map_err(map_sqlite_error)?;
        let ids = statement
            .query_map(params![automation_id.to_string(), limit], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?;
        ids.into_iter()
            .map(|id| load_run(&self.connection, parse_id(&id, "automation run ID")?))
            .collect()
    }
}

fn load_automation(
    connection: &rusqlite::Connection,
    automation_id: AutomationId,
    ownership: Option<OwnershipContext>,
) -> Result<AutomationView, AutomationStoreError> {
    let row = connection
        .query_row(
            "SELECT principal_id, manager_binding_id, target_binding_id, target_session_id, name, \
                    trigger_kind, due_at_ms, source_session_id, source_event_type, \
                    source_after_cursor, action_kind, action_body, \
                    approval_required_actions_allowed, status, revision, created_at_ms, updated_at_ms \
             FROM automation WHERE automation_id = ?1",
            [automation_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, bool>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(AutomationStoreError::NotFound)?;
    let principal_id = parse_id(&row.0, "automation principal ID")?;
    if ownership.is_some_and(|owner| owner.principal_id() != principal_id) {
        return Err(AutomationStoreError::NotFound);
    }
    let target_session_id = parse_id(&row.3, "automation target session ID")?;
    let trigger = match row.5.as_str() {
        "one_shot" if row.6.is_some() && row.7.is_none() && row.8.is_none() && row.9.is_none() => {
            AutomationTriggerView::OneShot {
                due_at_ms: row.6.expect("checked"),
            }
        }
        "session_event"
            if row.6.is_none() && row.7.is_some() && row.8.is_some() && row.9.is_some() =>
        {
            AutomationTriggerView::SessionEvent {
                source_session_id: parse_id(
                    row.7.as_deref().expect("checked"),
                    "automation source session ID",
                )?,
                event_type: row.8.expect("checked"),
                after_cursor: nonnegative(row.9.expect("checked"), "automation source cursor")?,
            }
        }
        _ => return Err(invariant("stored automation trigger is invalid")),
    };
    let action = match row.10.as_str() {
        "submit_prompt" => AutomationAction::SubmitPrompt {
            target_session_id,
            prompt: row.11,
            approval_required_actions_allowed: row.12,
        },
        "notify" if !row.12 => AutomationAction::Notify {
            target_session_id,
            message: row.11,
        },
        _ => return Err(invariant("stored automation action is invalid")),
    };
    let view = AutomationView {
        automation_id,
        manager_ownership: OwnershipContext::new(
            principal_id,
            parse_id(&row.1, "automation manager binding ID")?,
        ),
        target_ownership: OwnershipContext::new(
            principal_id,
            parse_id(&row.2, "automation target binding ID")?,
        ),
        name: row.4,
        trigger,
        action,
        status: parse_status(&row.13)?,
        revision: nonnegative(row.14, "automation revision")?,
        created_at_ms: row.15,
        updated_at_ms: row.16,
    };
    validate_automation_view(&view).map_err(|error| invariant(error.to_string()))?;
    Ok(view)
}

fn load_run(
    connection: &rusqlite::Connection,
    automation_run_id: AutomationRunId,
) -> Result<AutomationRunView, AutomationStoreError> {
    let row = connection
        .query_row(
            "SELECT automation_id, trigger_key, triggered_at_ms, source_event_cursor, \
                    source_event_id, source_event_type, status, inbox_entry_id, outbox_id, reason, \
                    created_at_ms, completed_at_ms \
             FROM automation_run WHERE automation_run_id = ?1",
            [automation_run_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(AutomationStoreError::NotFound)?;
    let status = parse_run_status(&row.6)?;
    let inbox_entry_id = row
        .7
        .as_deref()
        .map(|id| parse_id(id, "automation inbox entry ID"))
        .transpose()?;
    let outbox_id = row
        .8
        .as_deref()
        .map(|id| parse_id(id, "automation outbox ID"))
        .transpose()?;
    let completed_at_ms = row.11;
    if row.2 < 0
        || row.10 < 0
        || completed_at_ms.is_some_and(|completed| completed < row.10)
        || !valid_run_shape(
            status,
            inbox_entry_id,
            outbox_id,
            row.9.as_deref(),
            completed_at_ms,
        )
    {
        return Err(invariant("stored automation run is invalid"));
    }
    Ok(AutomationRunView {
        automation_run_id,
        automation_id: parse_id(&row.0, "automation run parent ID")?,
        trigger_key: row.1,
        triggered_at_ms: row.2,
        source_event_cursor: row
            .3
            .map(|cursor| nonnegative(cursor, "automation run event cursor"))
            .transpose()?,
        source_event_id: row
            .4
            .as_deref()
            .map(|id| parse_id(id, "automation run source event ID"))
            .transpose()?,
        source_event_type: row.5,
        status,
        inbox_entry_id,
        outbox_id,
        reason: row.9,
        created_at_ms: row.10,
        completed_at_ms,
    })
}

fn load_run_by_key(
    connection: &rusqlite::Connection,
    automation_id: AutomationId,
    trigger_key: &str,
) -> Result<Option<AutomationRunView>, AutomationStoreError> {
    let id = connection
        .query_row(
            "SELECT automation_run_id FROM automation_run \
             WHERE automation_id = ?1 AND trigger_key = ?2",
            params![automation_id.to_string(), trigger_key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?;
    id.map(|id| load_run(connection, parse_id(&id, "automation run ID")?))
        .transpose()
}

fn validate_claim(commit: &ClaimAutomationRunCommit) -> Result<(), AutomationStoreError> {
    if commit.trigger_key.is_empty()
        || commit.trigger_key.len() > 160
        || commit.triggered_at_ms < 0
        || commit.claimed_at_ms < 0
        || commit.claim_expires_at_ms <= commit.claimed_at_ms
        || commit
            .claim_expires_at_ms
            .saturating_sub(commit.claimed_at_ms)
            > MAXIMUM_CLAIM_MS
    {
        return Err(invalid_contract("automation claim is invalid"));
    }
    let event_shape = commit.source_event_cursor.is_some()
        && commit.source_event_id.is_some()
        && commit.source_event_type.is_some();
    if event_shape
        != (commit.trigger_key.starts_with("event:") && !commit.trigger_key.starts_with("time:"))
        || !event_shape
            && (!commit.trigger_key.starts_with("time:")
                || commit.source_event_cursor.is_some()
                || commit.source_event_id.is_some()
                || commit.source_event_type.is_some())
    {
        return Err(invalid_contract(
            "automation claim trigger shape is invalid",
        ));
    }
    Ok(())
}

fn claim_matches_trigger(
    transaction: &Transaction<'_>,
    automation: &AutomationView,
    commit: &ClaimAutomationRunCommit,
) -> Result<bool, AutomationStoreError> {
    match &automation.trigger {
        AutomationTriggerView::OneShot { due_at_ms } => Ok(commit.trigger_key
            == format!("time:{due_at_ms}")
            && commit.triggered_at_ms == *due_at_ms
            && commit.claimed_at_ms >= *due_at_ms
            && commit.source_event_cursor.is_none()
            && commit.source_event_id.is_none()
            && commit.source_event_type.is_none()),
        AutomationTriggerView::SessionEvent {
            source_session_id,
            event_type,
            after_cursor,
        } => {
            let Some(cursor) = commit.source_event_cursor else {
                return Ok(false);
            };
            let Some(event_id) = commit.source_event_id else {
                return Ok(false);
            };
            if cursor <= *after_cursor
                || commit.trigger_key != format!("event:{cursor}")
                || commit.source_event_type.as_deref() != Some(event_type)
            {
                return Ok(false);
            }
            let cursor = to_i64(cursor)?;
            let matched = transaction
                .query_row(
                    "SELECT EXISTS(\
                        SELECT 1 FROM timeline_event timeline \
                        JOIN journal_event journal ON journal.event_id = timeline.event_id \
                        WHERE timeline.cursor = ?1 AND journal.event_id = ?2 \
                          AND journal.aggregate_kind = 'session' AND journal.aggregate_id = ?3 \
                          AND journal.event_type = ?4 AND journal.occurred_at_ms = ?5\
                     )",
                    params![
                        cursor,
                        event_id.to_string(),
                        source_session_id.to_string(),
                        event_type,
                        commit.triggered_at_ms,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(map_sqlite_error)?;
            Ok(matched)
        }
    }
}

fn validate_completion(commit: &CompleteAutomationRunCommit) -> Result<(), AutomationStoreError> {
    if commit.completed_at_ms < 0 || commit.status == AutomationRunStatus::Claimed {
        return Err(invalid_contract("automation completion is not terminal"));
    }
    let valid = match commit.status {
        AutomationRunStatus::Admitted => {
            commit.inbox_entry_id.is_some() && commit.outbox_id.is_none() && commit.reason.is_none()
        }
        AutomationRunStatus::Notified => {
            commit.inbox_entry_id.is_none() && commit.outbox_id.is_some() && commit.reason.is_none()
        }
        AutomationRunStatus::Failed => {
            commit.inbox_entry_id.is_none()
                && commit.outbox_id.is_none()
                && commit.reason.as_deref().is_some_and(valid_reason)
        }
        AutomationRunStatus::Claimed => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_contract("automation completion shape is invalid"))
    }
}

fn validate_completion_for_action(
    action: &AutomationAction,
    commit: &CompleteAutomationRunCommit,
) -> Result<(), AutomationStoreError> {
    if commit.status == AutomationRunStatus::Failed
        || matches!(
            (action, commit.status),
            (
                AutomationAction::SubmitPrompt { .. },
                AutomationRunStatus::Admitted
            ) | (
                AutomationAction::Notify { .. },
                AutomationRunStatus::Notified
            )
        )
    {
        Ok(())
    } else {
        Err(invalid_contract(
            "automation completion does not match its action",
        ))
    }
}

fn valid_run_shape(
    status: AutomationRunStatus,
    inbox_entry_id: Option<InboxEntryId>,
    outbox_id: Option<OutboxId>,
    reason: Option<&str>,
    completed_at_ms: Option<i64>,
) -> bool {
    match status {
        AutomationRunStatus::Claimed => {
            inbox_entry_id.is_none()
                && outbox_id.is_none()
                && reason.is_none()
                && completed_at_ms.is_none()
        }
        AutomationRunStatus::Admitted => {
            inbox_entry_id.is_some()
                && outbox_id.is_none()
                && reason.is_none()
                && completed_at_ms.is_some()
        }
        AutomationRunStatus::Notified => {
            inbox_entry_id.is_none()
                && outbox_id.is_some()
                && reason.is_none()
                && completed_at_ms.is_some()
        }
        AutomationRunStatus::Failed => {
            inbox_entry_id.is_none()
                && outbox_id.is_none()
                && reason.is_some_and(valid_reason)
                && completed_at_ms.is_some()
        }
    }
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= MAXIMUM_REASON_BYTES
        && reason.trim() == reason
        && !reason.chars().any(char::is_control)
}

fn trigger_columns(
    trigger: &AutomationTrigger,
) -> (&'static str, Option<i64>, Option<String>, Option<String>) {
    match trigger {
        AutomationTrigger::OneShot { due_at_ms } => ("one_shot", Some(*due_at_ms), None, None),
        AutomationTrigger::SessionEvent {
            source_session_id,
            event_type,
        } => (
            "session_event",
            None,
            Some(source_session_id.to_string()),
            Some(event_type.clone()),
        ),
    }
}

fn action_columns(action: &AutomationAction) -> (&'static str, String, bool) {
    match action {
        AutomationAction::SubmitPrompt {
            prompt,
            approval_required_actions_allowed,
            ..
        } => (
            "submit_prompt",
            prompt.clone(),
            *approval_required_actions_allowed,
        ),
        AutomationAction::Notify { message, .. } => ("notify", message.clone(), false),
    }
}

fn definition_json(
    name: &str,
    trigger: &AutomationTrigger,
    action: &AutomationAction,
    source_after_cursor: Option<u64>,
) -> serde_json::Value {
    json!({
        "action": action,
        "name": name,
        "source_after_cursor": source_after_cursor,
        "trigger": trigger,
    })
}

fn trigger_matches(view: &AutomationTriggerView, trigger: &AutomationTrigger) -> bool {
    match (view, trigger) {
        (
            AutomationTriggerView::OneShot { due_at_ms: stored },
            AutomationTrigger::OneShot { due_at_ms },
        ) => stored == due_at_ms,
        (
            AutomationTriggerView::SessionEvent {
                source_session_id: stored_session,
                event_type: stored_type,
                ..
            },
            AutomationTrigger::SessionEvent {
                source_session_id,
                event_type,
            },
        ) => stored_session == source_session_id && stored_type == event_type,
        _ => false,
    }
}

fn trigger_after_cursor(trigger: &AutomationTriggerView) -> Option<u64> {
    match trigger {
        AutomationTriggerView::OneShot { .. } => None,
        AutomationTriggerView::SessionEvent { after_cursor, .. } => Some(*after_cursor),
    }
}

fn authorize_source(
    transaction: &Transaction<'_>,
    principal_id: PrincipalId,
    trigger: &AutomationTrigger,
) -> Result<(), AutomationStoreError> {
    let AutomationTrigger::SessionEvent {
        source_session_id, ..
    } = trigger
    else {
        return Ok(());
    };
    session_ownership(transaction, principal_id, *source_session_id, "source").map(|_| ())
}

fn ensure_automation_target_supported(
    connection: &rusqlite::Connection,
    action: &AutomationAction,
) -> Result<(), AutomationStoreError> {
    let target_session_id = action.target_session_id();
    let route = connection
        .query_row(
            "SELECT registry.channel_kind, registry.installation_id, \
                    EXISTS(SELECT 1 FROM webhook_channel_binding route \
                           WHERE route.session_id = session.id AND route.status = 'active'), \
                    EXISTS(SELECT 1 FROM telegram_channel_binding route \
                           WHERE route.session_id = session.id AND route.status = 'active'), \
                    EXISTS(SELECT 1 FROM discord_channel_binding route \
                           WHERE route.session_id = session.id AND route.status = 'active'), \
                    EXISTS(SELECT 1 FROM slack_channel_binding route \
                           WHERE route.session_id = session.id AND route.status = 'active') \
             FROM session \
             JOIN channel_binding_registry registry \
               ON registry.binding_id = session.channel_binding_id \
             WHERE session.id = ?1 AND session.status <> 'closed' \
               AND registry.status = 'active'",
            [target_session_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(AutomationStoreError::Unauthorized)?;
    match route {
        (kind, None, false, false, false, false)
            if matches!(kind.as_str(), "local_cli" | "legacy_session") =>
        {
            Ok(())
        }
        (kind, Some(installation), true, false, false, false)
            if kind == "signed_webhook" && installation == "builtin.signed_webhook.v1" =>
        {
            Ok(())
        }
        (kind, Some(installation), false, true, false, false)
            if kind == "extension_channel" && installation == "builtin.telegram.v1" =>
        {
            Ok(())
        }
        (kind, Some(installation), false, false, true, false)
            if kind == "extension_channel" && installation == "builtin.discord.dm.v1" =>
        {
            Ok(())
        }
        (kind, Some(installation), false, false, false, true)
            if kind == "extension_channel" && installation == "builtin.slack.socket.v1" =>
        {
            Err(invalid_contract(
                "Slack automation needs an explicit pinned thread",
            ))
        }
        _ => Err(invalid_contract(
            "automation notification target has no supported exact delivery route",
        )),
    }
}

fn session_ownership(
    connection: &rusqlite::Connection,
    principal_id: PrincipalId,
    session_id: SessionId,
    kind: &str,
) -> Result<OwnershipContext, AutomationStoreError> {
    let binding_id = connection
        .query_row(
            "SELECT session.channel_binding_id FROM session \
             JOIN principal_registry principal ON principal.principal_id = session.principal_id \
             JOIN channel_binding_registry binding \
               ON binding.binding_id = session.channel_binding_id \
              AND binding.principal_id = session.principal_id \
             WHERE session.id = ?1 AND session.principal_id = ?2 AND session.status <> 'closed' \
               AND principal.status = 'active' AND binding.status = 'active'",
            params![session_id.to_string(), principal_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(AutomationStoreError::Unauthorized)?;
    Ok(OwnershipContext::new(
        principal_id,
        parse_id(&binding_id, &format!("automation {kind} binding ID"))?,
    ))
}

fn authorize_administrator(
    connection: &rusqlite::Connection,
    ownership: OwnershipContext,
) -> Result<(), AutomationStoreError> {
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
        Err(AutomationStoreError::Unauthorized)
    }
}

fn has_active_claim(
    transaction: &Transaction<'_>,
    automation_id: AutomationId,
) -> Result<bool, AutomationStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM automation_run \
                           WHERE automation_id = ?1 AND status = 'claimed')",
            [automation_id.to_string()],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)
}

fn high_cursor(transaction: &Transaction<'_>) -> Result<u64, AutomationStoreError> {
    let cursor = transaction
        .query_row(
            "SELECT COALESCE(MAX(cursor), 0) FROM timeline_event",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite_error)?;
    nonnegative(cursor, "timeline high watermark")
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
fn append_event(
    transaction: &Transaction<'_>,
    automation_id: AutomationId,
    sequence: i64,
    event_id: EventId,
    event_type: &str,
    occurred_at_ms: i64,
    actor_principal_id: Option<PrincipalId>,
    correlation_id: mealy_domain::CorrelationId,
    payload: serde_json::Value,
) -> Result<(), AutomationStoreError> {
    transaction
        .execute(
            "INSERT INTO journal_event(\
                event_id, aggregate_kind, aggregate_id, aggregate_sequence, event_type, \
                event_version, occurred_at_ms, actor_principal_id, correlation_id, sensitivity, \
                payload_json\
             ) VALUES (?1, 'automation', ?2, ?3, ?4, 1, ?5, ?6, ?7, 'private', ?8)",
            params![
                event_id.to_string(),
                automation_id.to_string(),
                sequence,
                event_type,
                occurred_at_ms,
                actor_principal_id.map(|id| id.to_string()),
                correlation_id.to_string(),
                payload.to_string(),
            ],
        )
        .map_err(map_constraint_error)?;
    Ok(())
}

fn increment_sequence(
    transaction: &Transaction<'_>,
    automation_id: AutomationId,
) -> Result<i64, AutomationStoreError> {
    transaction
        .query_row(
            "UPDATE aggregate_sequence SET sequence = sequence + 1 \
             WHERE aggregate_kind = 'automation' AND aggregate_id = ?1 RETURNING sequence",
            [automation_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or_else(|| invariant("automation aggregate sequence is missing"))
}

const fn status_text(status: AutomationStatus) -> &'static str {
    match status {
        AutomationStatus::Active => "active",
        AutomationStatus::Paused => "paused",
        AutomationStatus::Completed => "completed",
        AutomationStatus::Cancelled => "cancelled",
    }
}

fn parse_status(value: &str) -> Result<AutomationStatus, AutomationStoreError> {
    match value {
        "active" => Ok(AutomationStatus::Active),
        "paused" => Ok(AutomationStatus::Paused),
        "completed" => Ok(AutomationStatus::Completed),
        "cancelled" => Ok(AutomationStatus::Cancelled),
        _ => Err(invariant("stored automation status is invalid")),
    }
}

const fn run_status_text(status: AutomationRunStatus) -> &'static str {
    match status {
        AutomationRunStatus::Claimed => "claimed",
        AutomationRunStatus::Admitted => "admitted",
        AutomationRunStatus::Notified => "notified",
        AutomationRunStatus::Failed => "failed",
    }
}

fn parse_run_status(value: &str) -> Result<AutomationRunStatus, AutomationStoreError> {
    match value {
        "claimed" => Ok(AutomationRunStatus::Claimed),
        "admitted" => Ok(AutomationRunStatus::Admitted),
        "notified" => Ok(AutomationRunStatus::Notified),
        "failed" => Ok(AutomationRunStatus::Failed),
        _ => Err(invariant("stored automation run status is invalid")),
    }
}

fn parse_id<T: FromStr>(value: &str, field: &str) -> Result<T, AutomationStoreError> {
    T::from_str(value).map_err(|_| invariant(format!("stored {field} is invalid")))
}

fn nonnegative(value: i64, field: &str) -> Result<u64, AutomationStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

fn to_i64(value: u64) -> Result<i64, AutomationStoreError> {
    i64::try_from(value).map_err(|_| invalid_contract("automation value exceeds SQLite"))
}

fn map_constraint_error(error: rusqlite::Error) -> AutomationStoreError {
    match &error {
        rusqlite::Error::SqliteFailure(details, _)
            if details.code == ErrorCode::ConstraintViolation =>
        {
            AutomationStoreError::Conflict
        }
        _ => map_sqlite_error(error),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_sqlite_error(error: rusqlite::Error) -> AutomationStoreError {
    AutomationStoreError::Unavailable(error.to_string())
}

fn invalid_contract(message: impl Into<String>) -> AutomationStoreError {
    AutomationStoreError::InvalidContract(message.into())
}

fn invariant(message: impl Into<String>) -> AutomationStoreError {
    AutomationStoreError::InvariantViolation(message.into())
}

#[cfg(test)]
mod tests {
    use super::AutomationStore;
    use crate::{SqliteStore, SystemClock, SystemIdGenerator};
    use mealy_application::{
        AdmitInputCommand, AutomationAction, AutomationClaimOutcome, AutomationRunStatus,
        AutomationStatus, AutomationStoreError, AutomationTrigger, ClaimAutomationRunCommit,
        CompleteAutomationRunCommit, CreateAutomationCommit, InputAdmissionLimits,
        OwnershipContext, ProviderSelectionPreference, RegisterWebhookChannelCommit,
        WebhookChannelStore, admit_input, create_session,
    };
    use mealy_domain::{
        AutomationId, AutomationRunId, ChannelBindingId, CorrelationId, DeliveryMode, EventId,
        OutboxId, PrincipalId, SessionId, WorkerId,
    };
    use rusqlite::params;
    use std::time::{Duration, SystemTime};

    fn fixture() -> (SqliteStore, OwnershipContext, mealy_domain::SessionId) {
        let mut store = SqliteStore::open_in_memory(0).expect("automation store");
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let session_id = create_session(&mut store, &SystemClock, &SystemIdGenerator, ownership)
            .expect("automation session");
        (store, ownership, session_id)
    }

    #[test]
    fn creation_identity_replays_after_time_and_timeline_advance() {
        let (mut store, ownership, session_id) = fixture();
        let one_shot_id = AutomationId::new();
        let one_shot = store
            .create_automation(CreateAutomationCommit {
                automation_id: one_shot_id,
                manager_ownership: ownership,
                name: "idempotent reminder".to_owned(),
                trigger: AutomationTrigger::OneShot { due_at_ms: 1_001 },
                action: AutomationAction::Notify {
                    target_session_id: session_id,
                    message: "Only enqueue this once.".to_owned(),
                },
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 1_000,
            })
            .expect("create one-shot");
        let delayed_replay = store
            .create_automation(CreateAutomationCommit {
                automation_id: one_shot_id,
                manager_ownership: ownership,
                name: "idempotent reminder".to_owned(),
                trigger: AutomationTrigger::OneShot { due_at_ms: 1_001 },
                action: AutomationAction::Notify {
                    target_session_id: session_id,
                    message: "Only enqueue this once.".to_owned(),
                },
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 2_000,
            })
            .expect("replay after due time");
        assert_eq!(delayed_replay, one_shot);

        let event_id = AutomationId::new();
        let event_automation = store
            .create_automation(CreateAutomationCommit {
                automation_id: event_id,
                manager_ownership: ownership,
                name: "idempotent event".to_owned(),
                trigger: AutomationTrigger::SessionEvent {
                    source_session_id: session_id,
                    event_type: "input.accepted".to_owned(),
                },
                action: AutomationAction::Notify {
                    target_session_id: session_id,
                    message: "Observe future events once.".to_owned(),
                },
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 2_000,
            })
            .expect("create event automation");
        admit_input(
            &mut store,
            &SystemClock,
            &SystemIdGenerator,
            InputAdmissionLimits::new(256, 4_096, 32),
            AdmitInputCommand {
                session_id,
                ownership,
                dedupe_key: "advance-before-create-replay".to_owned(),
                delivery_mode: DeliveryMode::Queue,
                content: "Advance the durable timeline.".to_owned(),
                provider_selection: ProviderSelectionPreference::InheritSession,
            },
        )
        .expect("advance timeline");
        let event_replay = store
            .create_automation(CreateAutomationCommit {
                automation_id: event_id,
                manager_ownership: ownership,
                name: "idempotent event".to_owned(),
                trigger: AutomationTrigger::SessionEvent {
                    source_session_id: session_id,
                    event_type: "input.accepted".to_owned(),
                },
                action: AutomationAction::Notify {
                    target_session_id: session_id,
                    message: "Observe future events once.".to_owned(),
                },
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 3_000,
            })
            .expect("replay after timeline advance");
        assert_eq!(event_replay, event_automation);
        assert_eq!(
            store
                .automations(ownership)
                .expect("list unique definitions")
                .len(),
            2
        );
    }

    #[test]
    fn unsupported_extension_channel_is_not_treated_as_local_delivery() {
        let (mut store, ownership, _) = fixture();
        let unsupported_binding_id = ChannelBindingId::new();
        let unsupported_session_id = SessionId::new();
        store
            .connection
            .execute(
                "INSERT INTO channel_binding_registry(\
                    binding_id, principal_id, channel_kind, status, revision, installation_id, \
                    external_subject, external_subject_digest, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, 'extension_channel', 'active', 0, \
                           'untrusted.extension.channel', 'extension:route', ?3, 1000, 1000)",
                params![
                    unsupported_binding_id.to_string(),
                    ownership.principal_id().to_string(),
                    "a".repeat(64),
                ],
            )
            .expect("register unsupported extension channel");
        store
            .connection
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, 1000, 1000)",
                params![
                    unsupported_session_id.to_string(),
                    ownership.principal_id().to_string(),
                    unsupported_binding_id.to_string(),
                ],
            )
            .expect("create unsupported channel session");
        for (name, action) in [
            (
                "unsupported notification",
                AutomationAction::Notify {
                    target_session_id: unsupported_session_id,
                    message: "Do not misclassify this as local.".to_owned(),
                },
            ),
            (
                "unsupported prompt",
                AutomationAction::SubmitPrompt {
                    target_session_id: unsupported_session_id,
                    prompt: "Do not admit work without an exact return route.".to_owned(),
                    approval_required_actions_allowed: false,
                },
            ),
        ] {
            let result = store.create_automation(CreateAutomationCommit {
                automation_id: AutomationId::new(),
                manager_ownership: ownership,
                name: name.to_owned(),
                trigger: AutomationTrigger::OneShot { due_at_ms: 1_001 },
                action,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 1_000,
            });
            assert!(matches!(
                result,
                Err(AutomationStoreError::InvalidContract(message))
                    if message.contains("no supported exact delivery route")
            ));
        }
    }

    #[test]
    fn exact_creation_replay_remains_readable_after_target_revocation() {
        let (mut store, ownership, _) = fixture();
        let target_binding_id = ChannelBindingId::new();
        let target_session_id = SessionId::new();
        store
            .connection
            .execute(
                "INSERT INTO channel_binding_registry(\
                    binding_id, principal_id, channel_kind, status, revision, \
                    created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, 'local_cli', 'active', 0, 1000, 1000)",
                params![
                    target_binding_id.to_string(),
                    ownership.principal_id().to_string(),
                ],
            )
            .expect("register distinct target binding");
        store
            .connection
            .execute(
                "INSERT INTO session(\
                    id, principal_id, channel_binding_id, created_at_ms, updated_at_ms\
                 ) VALUES (?1, ?2, ?3, 1000, 1000)",
                params![
                    target_session_id.to_string(),
                    ownership.principal_id().to_string(),
                    target_binding_id.to_string(),
                ],
            )
            .expect("create distinct target session");
        let automation_id = AutomationId::new();
        let created = store
            .create_automation(CreateAutomationCommit {
                automation_id,
                manager_ownership: ownership,
                name: "revocation-safe replay".to_owned(),
                trigger: AutomationTrigger::OneShot { due_at_ms: 1_001 },
                action: AutomationAction::Notify {
                    target_session_id,
                    message: "Retain existing evidence.".to_owned(),
                },
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 1_000,
            })
            .expect("create against active target");
        store
            .connection
            .execute(
                "UPDATE channel_binding_registry SET status = 'revoked', \
                    revision = revision + 1, updated_at_ms = updated_at_ms + 1, \
                    revoked_at_ms = updated_at_ms + 1 \
                 WHERE binding_id = ?1",
                [target_binding_id.to_string()],
            )
            .expect("revoke distinct target");
        let replay = store
            .create_automation(CreateAutomationCommit {
                automation_id,
                manager_ownership: ownership,
                name: "revocation-safe replay".to_owned(),
                trigger: AutomationTrigger::OneShot { due_at_ms: 1_001 },
                action: AutomationAction::Notify {
                    target_session_id,
                    message: "Retain existing evidence.".to_owned(),
                },
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 2_000,
            })
            .expect("reconcile exact creation after target revocation");
        assert_eq!(replay, created);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn one_shot_claim_notification_and_completion_are_exact_and_durable() {
        let (mut store, ownership, session_id) = fixture();
        let automation = store
            .create_automation(CreateAutomationCommit {
                automation_id: AutomationId::new(),
                manager_ownership: ownership,
                name: "quick reminder".to_owned(),
                trigger: AutomationTrigger::OneShot { due_at_ms: 1_001 },
                action: AutomationAction::Notify {
                    target_session_id: session_id,
                    message: "Review the completed build.".to_owned(),
                },
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 1_000,
            })
            .expect("create one-shot");
        assert!(
            store
                .due_automations(1_000, 10)
                .expect("not due")
                .is_empty()
        );
        let candidate = store
            .due_automations(1_001, 10)
            .expect("due")
            .pop()
            .expect("candidate");
        assert_eq!(candidate.automation, automation);
        let first_owner_id = WorkerId::new();
        let run = match store
            .claim_automation_run(ClaimAutomationRunCommit {
                automation_id: automation.automation_id,
                expected_revision: automation.revision,
                trigger_key: candidate.trigger_key,
                triggered_at_ms: candidate.triggered_at_ms,
                source_event_cursor: None,
                source_event_id: None,
                source_event_type: None,
                proposed_automation_run_id: AutomationRunId::new(),
                owner_id: first_owner_id,
                claimed_at_ms: 1_001,
                claim_expires_at_ms: 1_101,
            })
            .expect("claim")
        {
            AutomationClaimOutcome::Claimed(run) => run,
            AutomationClaimOutcome::Busy => panic!("due one-shot must claim"),
        };
        assert_eq!(
            store
                .claim_automation_run(ClaimAutomationRunCommit {
                    automation_id: automation.automation_id,
                    expected_revision: automation.revision,
                    trigger_key: format!("time:{}", candidate.triggered_at_ms),
                    triggered_at_ms: candidate.triggered_at_ms,
                    source_event_cursor: None,
                    source_event_id: None,
                    source_event_type: None,
                    proposed_automation_run_id: AutomationRunId::new(),
                    owner_id: WorkerId::new(),
                    claimed_at_ms: 1_050,
                    claim_expires_at_ms: 1_150,
                })
                .expect("unexpired claim is busy"),
            AutomationClaimOutcome::Busy
        );
        let recovered_owner_id = WorkerId::new();
        let recovered = match store
            .claim_automation_run(ClaimAutomationRunCommit {
                automation_id: automation.automation_id,
                expected_revision: automation.revision,
                trigger_key: format!("time:{}", candidate.triggered_at_ms),
                triggered_at_ms: candidate.triggered_at_ms,
                source_event_cursor: None,
                source_event_id: None,
                source_event_type: None,
                proposed_automation_run_id: AutomationRunId::new(),
                owner_id: recovered_owner_id,
                claimed_at_ms: 1_101,
                claim_expires_at_ms: 1_201,
            })
            .expect("expired claim recovers")
        {
            AutomationClaimOutcome::Claimed(run) => run,
            AutomationClaimOutcome::Busy => panic!("expired one-shot claim must recover"),
        };
        assert_eq!(recovered.automation_run_id, run.automation_run_id);
        let outbox_id = OutboxId::new();
        let completed = store
            .complete_automation_run(CompleteAutomationRunCommit {
                automation_id: automation.automation_id,
                automation_run_id: run.automation_run_id,
                owner_id: recovered_owner_id,
                status: AutomationRunStatus::Notified,
                inbox_entry_id: None,
                outbox_id: Some(outbox_id),
                reason: None,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at_ms: 1_002,
            })
            .expect("complete notification");
        assert_eq!(completed.outbox_id, Some(outbox_id));
        assert_eq!(
            store
                .automation(ownership, automation.automation_id)
                .expect("completed one-shot")
                .status,
            AutomationStatus::Completed
        );
        assert!(
            store
                .due_automations(1_100, 10)
                .expect("no replay")
                .is_empty()
        );
        let payload = store
            .connection
            .query_row(
                "SELECT payload_json FROM outbox WHERE outbox_id = ?1 \
                 AND topic = 'automation.notification'",
                [outbox_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .expect("notification outbox");
        assert!(payload.contains("Review the completed build."));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn revoked_notification_target_fails_before_outbox_publication() {
        let (mut store, ownership, _) = fixture();
        let target_binding_id = ChannelBindingId::new();
        let target_session_id = SessionId::new();
        store
            .register_webhook_channel(RegisterWebhookChannelCommit {
                administrative_ownership: ownership,
                binding_id: target_binding_id,
                session_id: target_session_id,
                external_subject: "automation-owner".to_owned(),
                callback_url: "http://127.0.0.1:4318/automation".to_owned(),
                secret_digest: "a".repeat(64),
                session_event_id: EventId::new(),
                binding_event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            })
            .expect("register exact webhook target");
        let automation = store
            .create_automation(CreateAutomationCommit {
                automation_id: AutomationId::new(),
                manager_ownership: ownership,
                name: "revoked route".to_owned(),
                trigger: AutomationTrigger::OneShot { due_at_ms: 1_001 },
                action: AutomationAction::Notify {
                    target_session_id,
                    message: "This route must still be active.".to_owned(),
                },
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 1_000,
            })
            .expect("create notification");
        let candidate = store
            .due_automations(1_001, 10)
            .expect("due notification")
            .pop()
            .expect("notification candidate");
        let owner_id = WorkerId::new();
        let run = match store
            .claim_automation_run(ClaimAutomationRunCommit {
                automation_id: automation.automation_id,
                expected_revision: automation.revision,
                trigger_key: candidate.trigger_key,
                triggered_at_ms: candidate.triggered_at_ms,
                source_event_cursor: None,
                source_event_id: None,
                source_event_type: None,
                proposed_automation_run_id: AutomationRunId::new(),
                owner_id,
                claimed_at_ms: 1_001,
                claim_expires_at_ms: 1_101,
            })
            .expect("claim notification")
        {
            AutomationClaimOutcome::Claimed(run) => run,
            AutomationClaimOutcome::Busy => panic!("notification must claim"),
        };
        store
            .connection
            .execute(
                "UPDATE webhook_channel_binding SET status = 'revoked', \
                    revision = revision + 1, updated_at_ms = updated_at_ms + 1, \
                    revoked_at_ms = updated_at_ms + 1 \
                 WHERE binding_id = ?1",
                [target_binding_id.to_string()],
            )
            .expect("revoke exact route without changing the registry");
        assert!(
            store
                .connection
                .query_row(
                    "SELECT status = 'active' FROM channel_binding_registry \
                     WHERE binding_id = ?1",
                    [target_binding_id.to_string()],
                    |row| row.get::<_, bool>(0),
                )
                .expect("registry remains active"),
            "the test must exercise provider-route revalidation, not registry revocation"
        );
        let proposed_outbox_id = OutboxId::new();
        assert_eq!(
            store.complete_automation_run(CompleteAutomationRunCommit {
                automation_id: automation.automation_id,
                automation_run_id: run.automation_run_id,
                owner_id,
                status: AutomationRunStatus::Notified,
                inbox_entry_id: None,
                outbox_id: Some(proposed_outbox_id),
                reason: None,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at_ms: 1_002,
            }),
            Err(AutomationStoreError::Unauthorized)
        );
        let failed = store
            .complete_automation_run(CompleteAutomationRunCommit {
                automation_id: automation.automation_id,
                automation_run_id: run.automation_run_id,
                owner_id,
                status: AutomationRunStatus::Failed,
                inbox_entry_id: None,
                outbox_id: None,
                reason: Some("notification_target_unauthorized".to_owned()),
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at_ms: 1_002,
            })
            .expect("record terminal target failure");
        assert_eq!(failed.status, AutomationRunStatus::Failed);
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM outbox WHERE outbox_id = ?1",
                    [proposed_outbox_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("outbox count"),
            0
        );
    }

    #[test]
    fn session_event_starts_after_creation_and_advances_exact_cursor_once() {
        let (mut store, ownership, session_id) = fixture();
        let automation = store
            .create_automation(CreateAutomationCommit {
                automation_id: AutomationId::new(),
                manager_ownership: ownership,
                name: "accepted input signal".to_owned(),
                trigger: AutomationTrigger::SessionEvent {
                    source_session_id: session_id,
                    event_type: "input.accepted".to_owned(),
                },
                action: AutomationAction::Notify {
                    target_session_id: session_id,
                    message: "A watched input was accepted.".to_owned(),
                },
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                created_at_ms: 1_000,
            })
            .expect("create event automation");
        assert!(
            store
                .due_automations(i64::MAX, 10)
                .expect("historical session events ignored")
                .is_empty()
        );
        admit_input(
            &mut store,
            &SystemClock,
            &SystemIdGenerator,
            InputAdmissionLimits::new(256, 4_096, 32),
            AdmitInputCommand {
                session_id,
                ownership,
                dedupe_key: "automation-event-fixture".to_owned(),
                delivery_mode: DeliveryMode::Queue,
                content: "Trigger one future event.".to_owned(),
                provider_selection: ProviderSelectionPreference::InheritSession,
            },
        )
        .expect("admit source event");
        let candidate = store
            .due_automations(i64::MAX, 10)
            .expect("future event due")
            .pop()
            .expect("event candidate");
        let source_cursor = candidate.source_event_cursor.expect("source cursor");
        let owner_id = WorkerId::new();
        let run = match store
            .claim_automation_run(ClaimAutomationRunCommit {
                automation_id: automation.automation_id,
                expected_revision: automation.revision,
                trigger_key: candidate.trigger_key,
                triggered_at_ms: candidate.triggered_at_ms,
                source_event_cursor: candidate.source_event_cursor,
                source_event_id: candidate.source_event_id,
                source_event_type: candidate.source_event_type,
                proposed_automation_run_id: AutomationRunId::new(),
                owner_id,
                claimed_at_ms: candidate.triggered_at_ms,
                claim_expires_at_ms: candidate.triggered_at_ms + 100,
            })
            .expect("claim event")
        {
            AutomationClaimOutcome::Claimed(run) => run,
            AutomationClaimOutcome::Busy => panic!("future exact event must claim"),
        };
        store
            .complete_automation_run(CompleteAutomationRunCommit {
                automation_id: automation.automation_id,
                automation_run_id: run.automation_run_id,
                owner_id,
                status: AutomationRunStatus::Notified,
                inbox_entry_id: None,
                outbox_id: Some(OutboxId::new()),
                reason: None,
                event_id: EventId::new(),
                correlation_id: CorrelationId::new(),
                completed_at_ms: candidate.triggered_at_ms + 1,
            })
            .expect("complete event");
        let advanced = store
            .automation(ownership, automation.automation_id)
            .expect("advanced automation");
        assert!(matches!(
            advanced.trigger,
            mealy_application::AutomationTriggerView::SessionEvent {
                after_cursor,
                ..
            } if after_cursor == source_cursor
        ));
        assert!(
            store
                .due_automations(i64::MAX, 10)
                .expect("event consumed once")
                .is_empty()
        );
    }
}
