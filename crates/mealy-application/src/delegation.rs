use crate::{
    AgentLoopLimits, AgentStoreError, OwnershipContext, ReadToolDescriptor,
    ToolDescriptorEvidenceError, sha256_digest,
};
use mealy_domain::{
    CapabilityGrant, CorrelationId, DelegationGroupId, DelegationId, EventId, InboxEntryId,
    LeaseFence, LeaseId, OutboxId, RunId, TaskId, TaskSuccessCriteria, ToolCallId, TurnId,
    WorkerId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime},
};

/// Stable contract version for delegated work packages.
pub const DELEGATION_CONTRACT_VERSION: &str = "mealy.delegation.v1";

/// Provider-visible identity for bounded internal child work.
pub const AGENT_DELEGATE_TOOL_ID: &str = "agent.delegate";

/// Provider-visible identity for one atomically admitted, bounded parallel child group.
pub const AGENT_DELEGATE_PARALLEL_TOOL_ID: &str = "agent.delegate_parallel";

/// Canonical locator returned when a child result becomes parent tool evidence.
pub const AGENT_DELEGATE_RESULT_LOCATOR: &str = "delegation://result";

/// Canonical locator returned when an ordered group result becomes parent tool evidence.
pub const AGENT_DELEGATE_GROUP_RESULT_LOCATOR: &str = "delegation://group-result";

/// Maximum provider-visible delegated objective bytes.
pub const MAXIMUM_DELEGATION_OBJECTIVE_BYTES: usize = 4_096;

/// Maximum provider-visible delegated instruction bytes.
pub const MAXIMUM_DELEGATION_INSTRUCTION_BYTES: usize = 16_384;

/// Maximum explicit context-package bytes accepted from the parent model.
pub const MAXIMUM_DELEGATION_CONTEXT_BYTES: usize = 32_768;

/// Maximum independently checkable criteria in one provider-created work order.
pub const MAXIMUM_DELEGATION_CRITERIA: usize = 8;

/// Minimum useful parallel fan-out accepted from one provider decision.
pub const MINIMUM_PARALLEL_DELEGATIONS: usize = 2;

/// Hard provider-visible parallel fan-out bound.
pub const MAXIMUM_PARALLEL_DELEGATIONS: usize = 8;

/// Maximum canonical child-key bytes.
pub const MAXIMUM_DELEGATION_CHILD_KEY_BYTES: usize = 64;

/// Provider-facing, authority-free request for one bounded child computation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDelegationRequest {
    /// Exact child objective.
    pub objective: String,
    /// Self-contained instructions; implicit parent history is never inherited.
    pub instructions: String,
    /// Concrete result checks the child should satisfy.
    pub success_criteria: Vec<String>,
    /// Explicit bounded context selected by the parent model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

impl AgentDelegationRequest {
    /// Parses and validates the exact provider-visible delegation argument contract.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError::InvariantViolation`] for extra fields, invalid shapes, or
    /// over-bound text/context.
    pub fn from_arguments(arguments: &Value) -> Result<Self, AgentStoreError> {
        let request = serde_json::from_value::<Self>(arguments.clone())
            .map_err(|_| invalid_delegation_arguments())?;
        let valid_text = |text: &str, maximum: usize| {
            !text.is_empty()
                && text.len() <= maximum
                && text.trim() == text
                && !text.chars().any(char::is_control)
        };
        if !valid_text(&request.objective, MAXIMUM_DELEGATION_OBJECTIVE_BYTES)
            || !valid_text(&request.instructions, MAXIMUM_DELEGATION_INSTRUCTION_BYTES)
            || request.success_criteria.is_empty()
            || request.success_criteria.len() > MAXIMUM_DELEGATION_CRITERIA
            || request
                .success_criteria
                .iter()
                .any(|criterion| !valid_text(criterion, 4_096))
            || request.context.as_ref().is_some_and(|context| {
                !context.is_object()
                    || context.as_object().is_some_and(serde_json::Map::is_empty)
                    || serde_json::to_vec(context)
                        .map_or(true, |bytes| bytes.len() > MAXIMUM_DELEGATION_CONTEXT_BYTES)
            })
        {
            return Err(invalid_delegation_arguments());
        }
        Ok(request)
    }
}

/// One keyed child work order inside an ordered parallel delegation request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParallelAgentDelegationChild {
    /// Provider-chosen stable result key, unique within the group.
    pub child_key: String,
    /// Exact child objective.
    pub objective: String,
    /// Self-contained instructions; implicit parent history is never inherited.
    pub instructions: String,
    /// Concrete result checks the child should satisfy.
    pub success_criteria: Vec<String>,
    /// Explicit bounded context selected by the parent model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

impl ParallelAgentDelegationChild {
    fn delegation_request(&self) -> AgentDelegationRequest {
        AgentDelegationRequest {
            objective: self.objective.clone(),
            instructions: self.instructions.clone(),
            success_criteria: self.success_criteria.clone(),
            context: self.context.clone(),
        }
    }
}

/// Provider-facing request for one atomically admitted, deterministically ordered child group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParallelAgentDelegationRequest {
    /// Ordered child work orders. Request order is the canonical result order.
    pub delegations: Vec<ParallelAgentDelegationChild>,
}

impl ParallelAgentDelegationRequest {
    /// Parses and validates the exact provider-visible parallel delegation contract.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError::InvariantViolation`] for extra fields, invalid child keys,
    /// duplicate keys, invalid work orders, or fan-out outside the fixed bound.
    pub fn from_arguments(arguments: &Value) -> Result<Self, AgentStoreError> {
        let request = serde_json::from_value::<Self>(arguments.clone())
            .map_err(|_| invalid_parallel_delegation_arguments())?;
        if !(MINIMUM_PARALLEL_DELEGATIONS..=MAXIMUM_PARALLEL_DELEGATIONS)
            .contains(&request.delegations.len())
        {
            return Err(invalid_parallel_delegation_arguments());
        }
        let mut keys = BTreeSet::new();
        for child in &request.delegations {
            if !valid_delegation_child_key(&child.child_key)
                || !keys.insert(child.child_key.as_str())
                || AgentDelegationRequest::from_arguments(
                    &serde_json::to_value(child.delegation_request())
                        .map_err(|_| invalid_parallel_delegation_arguments())?,
                )
                .is_err()
            {
                return Err(invalid_parallel_delegation_arguments());
            }
        }
        Ok(request)
    }
}

fn valid_delegation_child_key(value: &str) -> bool {
    let key = value.as_bytes();
    !key.is_empty()
        && key.len() <= MAXIMUM_DELEGATION_CHILD_KEY_BYTES
        && value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || (index > 0 && matches!(character, '.' | '_' | '-'))
        })
}

fn invalid_delegation_arguments() -> AgentStoreError {
    AgentStoreError::InvariantViolation(
        "agent delegation arguments are outside the bounded contract".to_owned(),
    )
}

fn invalid_parallel_delegation_arguments() -> AgentStoreError {
    AgentStoreError::InvariantViolation(
        "parallel agent delegation arguments are outside the bounded contract".to_owned(),
    )
}

/// Builds the immutable provider and durable-evidence descriptor for internal delegation.
///
/// # Errors
///
/// Returns [`ToolDescriptorEvidenceError`] only if the fixed timeout cannot be encoded.
pub fn agent_delegate_tool_descriptor() -> Result<ReadToolDescriptor, ToolDescriptorEvidenceError> {
    let input_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "objective": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_DELEGATION_OBJECTIVE_BYTES
            },
            "instructions": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_DELEGATION_INSTRUCTION_BYTES
            },
            "successCriteria": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_DELEGATION_CRITERIA,
                "items": {"type": "string", "minLength": 1, "maxLength": 4096}
            },
            "context": {
                "type": "object",
                "minProperties": 1
            }
        },
        "required": ["objective", "instructions", "successCriteria"],
        "additionalProperties": false
    });
    let mut descriptor = ReadToolDescriptor {
        tool_id: AGENT_DELEGATE_TOOL_ID.to_owned(),
        version: "1".to_owned(),
        schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        input_schema,
        output_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "contractVersion": {"const": "mealy.delegation-result.v1"},
                "delegationId": {"type": "string"},
                "childTaskId": {"type": "string"},
                "childRunId": {"type": "string"},
                "status": {"enum": ["succeeded", "failed", "cancelled"]},
                "summary": {"type": "string"},
                "sourceLocator": {"const": AGENT_DELEGATE_RESULT_LOCATOR}
            },
            "required": [
                "contractVersion", "delegationId", "childTaskId", "childRunId", "status",
                "summary", "sourceLocator"
            ],
            "additionalProperties": false
        }),
        descriptor_digest: String::new(),
        // Internal durable computation is replay-safe and has no external effect authority.
        effect_class: "read_only".to_owned(),
        risk_class: "low".to_owned(),
        required_capability: "agent:delegate".to_owned(),
        timeout: Duration::from_mins(5),
        maximum_output_bytes: 64 * 1024,
        conflict_key_template: "agent-delegate:{objective}".to_owned(),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    Ok(descriptor)
}

/// Builds the immutable provider descriptor for one bounded parallel delegation group.
///
/// # Errors
///
/// Returns [`ToolDescriptorEvidenceError`] only if the fixed timeout cannot be encoded.
pub fn agent_delegate_parallel_tool_descriptor()
-> Result<ReadToolDescriptor, ToolDescriptorEvidenceError> {
    let child_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "childKey": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_DELEGATION_CHILD_KEY_BYTES,
                "pattern": "^[a-z0-9][a-z0-9._-]*$"
            },
            "objective": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_DELEGATION_OBJECTIVE_BYTES
            },
            "instructions": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_DELEGATION_INSTRUCTION_BYTES
            },
            "successCriteria": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_DELEGATION_CRITERIA,
                "items": {"type": "string", "minLength": 1, "maxLength": 4096}
            },
            "context": {"type": "object", "minProperties": 1}
        },
        "required": ["childKey", "objective", "instructions", "successCriteria"],
        "additionalProperties": false
    });
    let input_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "delegations": {
                "type": "array",
                "minItems": MINIMUM_PARALLEL_DELEGATIONS,
                "maxItems": MAXIMUM_PARALLEL_DELEGATIONS,
                "items": child_schema
            }
        },
        "required": ["delegations"],
        "additionalProperties": false
    });
    let mut descriptor = ReadToolDescriptor {
        tool_id: AGENT_DELEGATE_PARALLEL_TOOL_ID.to_owned(),
        version: "1".to_owned(),
        schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        input_schema,
        output_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "contractVersion": {"const": "mealy.delegation-group-result.v1"},
                "parentToolCallId": {"type": "string"},
                "status": {"const": "all_terminal"},
                "delegations": {
                    "type": "array",
                    "minItems": MINIMUM_PARALLEL_DELEGATIONS,
                    "maxItems": MAXIMUM_PARALLEL_DELEGATIONS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "childKey": {"type": "string"},
                            "delegationId": {"type": "string"},
                            "childTaskId": {"type": "string"},
                            "childRunId": {"type": "string"},
                            "status": {"enum": ["succeeded", "failed", "cancelled"]},
                            "summary": {"type": "string"}
                        },
                        "required": [
                            "childKey", "delegationId", "childTaskId", "childRunId", "status",
                            "summary"
                        ],
                        "additionalProperties": false
                    }
                },
                "sourceLocator": {"const": AGENT_DELEGATE_GROUP_RESULT_LOCATOR}
            },
            "required": [
                "contractVersion", "parentToolCallId", "status", "delegations", "sourceLocator"
            ],
            "additionalProperties": false
        }),
        descriptor_digest: String::new(),
        effect_class: "read_only".to_owned(),
        risk_class: "low".to_owned(),
        required_capability: "agent:delegate".to_owned(),
        timeout: Duration::from_mins(5),
        maximum_output_bytes: 64 * 1024,
        conflict_key_template: "agent-delegate-parallel".to_owned(),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    Ok(descriptor)
}

/// Conflict domain protected by one exclusive resource claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    /// Canonical workspace mutation scope.
    WorkspaceWrite,
    /// Named external service mutation scope.
    ServiceMutation,
    /// Governed memory namespace.
    MemoryNamespace,
    /// Exclusive local device.
    Device,
}

impl ResourceClass {
    /// Stable storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceWrite => "workspace_write",
            Self::ServiceMutation => "service_mutation",
            Self::MemoryNamespace => "memory_namespace",
            Self::Device => "device",
        }
    }
}

/// Complete bounded delegation contract proposed under a parent fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareDelegationCommit {
    /// Exact live parent ownership.
    pub parent_fence: LeaseFence,
    /// Stable delegation identity.
    pub delegation_id: DelegationId,
    /// Fresh child task.
    pub child_task_id: TaskId,
    /// Fresh child run.
    pub child_run_id: RunId,
    /// Self-contained work order.
    pub work_order: Value,
    /// Explicit child success criteria.
    pub success_criteria: TaskSuccessCriteria,
    /// Bounded context package; never the parent's implicit full history.
    pub context_package: Value,
    /// Child authority requested by the parent.
    pub requested_capabilities: CapabilityGrant,
    /// Current policy ceiling independently intersected with parent authority.
    pub policy_capabilities: CapabilityGrant,
    /// Separate child execution budget.
    pub child_budget: AgentLoopLimits,
    /// Delegation journal event.
    pub event_id: EventId,
    /// Commit time.
    pub prepared_at: SystemTime,
}

/// Atomic agent-loop launch that binds a prepared parent tool call to one child and parks the
/// parent until the child commits a terminal result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchAgentDelegationCommit {
    /// Complete delegation contract and fresh child identities.
    pub delegation: PrepareDelegationCommit,
    /// Exact prepared provider-originated parent tool call.
    pub parent_tool_call_id: ToolCallId,
    /// Fresh delegated turn identity.
    pub child_turn_id: TurnId,
    /// Synthetic promoted inbox identity holding only the explicit child package.
    pub child_inbox_entry_id: InboxEntryId,
    /// Reserved identity required by the inbox schema; no external acknowledgement is emitted.
    pub child_acknowledgement_outbox_id: OutboxId,
    /// Parent tool-call started event.
    pub tool_event_id: EventId,
    /// Parent lease release event.
    pub lease_event_id: EventId,
    /// Parent run waiting event.
    pub parent_run_event_id: EventId,
    /// Parent task waiting event.
    pub parent_task_event_id: EventId,
}

/// One fully materialized child inside an atomic parallel launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchParallelDelegationChildCommit {
    /// Canonical provider key used in deterministic group results.
    pub child_key: String,
    /// Complete isolated child contract and identities.
    pub delegation: PrepareDelegationCommit,
    /// Fresh delegated turn identity.
    pub child_turn_id: TurnId,
    /// Synthetic promoted inbox identity.
    pub child_inbox_entry_id: InboxEntryId,
    /// Reserved schema identity; no external acknowledgement is emitted.
    pub child_acknowledgement_outbox_id: OutboxId,
}

/// Atomic provider-originated launch of an ordered bounded parallel child group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchParallelAgentDelegationCommit {
    /// Fresh durable group identity.
    pub group_id: DelegationGroupId,
    /// Exact prepared provider-originated parent tool call.
    pub parent_tool_call_id: ToolCallId,
    /// Ordered children; vector order is the canonical group ordinal.
    pub children: Vec<LaunchParallelDelegationChildCommit>,
    /// Delegation-group admission event.
    pub group_event_id: EventId,
    /// Parent tool-call started event.
    pub tool_event_id: EventId,
    /// Parent lease release event.
    pub lease_event_id: EventId,
    /// Parent run waiting event.
    pub parent_run_event_id: EventId,
    /// Parent task waiting event.
    pub parent_task_event_id: EventId,
}

/// Fenced acquisition of one exclusive conflict key by a child run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireResourceClaimCommit {
    /// Exact child worker ownership.
    pub fence: LeaseFence,
    /// Owning delegation.
    pub delegation_id: DelegationId,
    /// Stable claim identity.
    pub claim_id: EventId,
    /// Conflict domain.
    pub resource_class: ResourceClass,
    /// Canonical exact resource key.
    pub resource_key: String,
    /// Claim journal event.
    pub event_id: EventId,
    /// End-to-end trace correlation.
    pub correlation_id: CorrelationId,
    /// Acquisition time.
    pub acquired_at: SystemTime,
}

/// Starts one queued child under a fresh durable lease and fencing token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartDelegationCommit {
    /// Delegation whose child becomes active.
    pub delegation_id: DelegationId,
    /// Fresh child lease identity.
    pub lease_id: LeaseId,
    /// Child worker identity.
    pub owner_id: WorkerId,
    /// Child start journal event.
    pub event_id: EventId,
    /// End-to-end trace correlation.
    pub correlation_id: CorrelationId,
    /// Lease acquisition time.
    pub started_at: SystemTime,
    /// Exclusive lease expiry.
    pub expires_at: SystemTime,
}

/// Fenced terminal child result and resource-release boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordDelegationResultCommit {
    /// Exact child lease; superseded workers cannot commit.
    pub child_fence: LeaseFence,
    /// Owning delegation.
    pub delegation_id: DelegationId,
    /// Structured result returned to the parent.
    pub result: Value,
    /// Whether the child established its own criteria.
    pub succeeded: bool,
    /// Delegation result journal event.
    pub event_id: EventId,
    /// End-to-end trace correlation.
    pub correlation_id: CorrelationId,
    /// Result time.
    pub completed_at: SystemTime,
}

/// Durable delegation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationView {
    /// Stable delegation identity.
    pub delegation_id: DelegationId,
    /// Parent run.
    pub parent_run_id: RunId,
    /// Child task.
    pub child_task_id: TaskId,
    /// Child run.
    pub child_run_id: RunId,
    /// Effective child authority.
    pub effective_capabilities: CapabilityGrant,
    /// Separate child budget.
    pub child_budget: AgentLoopLimits,
    /// Queued/running/terminal state.
    pub state: String,
    /// Structured terminal result.
    pub result: Option<Value>,
}

/// Durable delegation and resource-ownership port.
pub trait DelegationStore {
    /// Atomically creates child task/run lineage, exact authority intersection, separate budget,
    /// context package, and parent delegated-run reservation.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale parent ownership, widened capabilities, exhausted
    /// delegation budget, malformed packages, or storage failure.
    fn prepare_delegation(
        &mut self,
        commit: PrepareDelegationCommit,
    ) -> Result<DelegationView, AgentStoreError>;

    /// Atomically starts a provider-originated delegation, materializes its isolated child turn,
    /// and releases the parent lease into a durable waiting state.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale parent ownership, model/tool divergence, exhausted
    /// child authority, malformed context, or storage failure.
    fn launch_agent_delegation(
        &mut self,
        commit: LaunchAgentDelegationCommit,
    ) -> Result<DelegationView, AgentStoreError>;

    /// Atomically validates and launches every ordered child, reserves the complete fan-out, and
    /// parks the parent exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] without partial writes when any child contract, identity,
    /// authority, budget, or provider-origin binding is invalid.
    fn launch_parallel_agent_delegation(
        &mut self,
        commit: LaunchParallelAgentDelegationCommit,
    ) -> Result<Vec<DelegationView>, AgentStoreError>;

    /// Starts one queued child under a fresh lease.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for a non-queued child, invalid expiry, or storage failure.
    fn start_delegation(
        &mut self,
        commit: StartDelegationCommit,
    ) -> Result<LeaseFence, AgentStoreError>;

    /// Acquires one exclusive resource conflict key under the exact child fence.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError::Conflict`] when another live run owns the key.
    fn acquire_resource_claim(
        &mut self,
        commit: AcquireResourceClaimCommit,
    ) -> Result<(), AgentStoreError>;

    /// Commits a structured terminal result, releases claims, and settles the parent's delegated
    /// run reservation. A stale child fence cannot commit.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for stale ownership, malformed result, divergent state, or
    /// storage failure.
    fn record_delegation_result(
        &mut self,
        commit: RecordDelegationResultCommit,
    ) -> Result<DelegationView, AgentStoreError>;

    /// Loads one delegation through the owning session principal/channel.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for unauthorized/missing or corrupt state.
    fn delegation(
        &self,
        ownership: OwnershipContext,
        delegation_id: DelegationId,
    ) -> Result<DelegationView, AgentStoreError>;

    /// Lists a bounded newest-first set of delegations owned by one principal/channel pair.
    ///
    /// # Errors
    ///
    /// Returns [`AgentStoreError`] for an invalid limit, corrupt evidence, or storage failure.
    fn delegations(
        &self,
        ownership: OwnershipContext,
        limit: usize,
    ) -> Result<Vec<DelegationView>, AgentStoreError>;
}

/// Validates bounded, object-shaped delegation package fields.
///
/// # Errors
///
/// Returns [`AgentStoreError::InvariantViolation`] for malformed work or capability evidence.
pub fn validate_delegation_commit(commit: &PrepareDelegationCommit) -> Result<(), AgentStoreError> {
    if commit.child_run_id == commit.parent_fence.run_id()
        || !commit.work_order.is_object()
        || commit
            .work_order
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        || !commit.context_package.is_object()
        || commit
            .context_package
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        || serde_json::to_vec(&commit.work_order).map_or(true, |bytes| bytes.len() > 65_536)
        || serde_json::to_vec(&commit.context_package).map_or(true, |bytes| bytes.len() > 262_144)
        || commit.success_criteria.validate().is_err()
        || commit.requested_capabilities.validate().is_err()
        || commit.policy_capabilities.validate().is_err()
        || commit.child_budget.validate().is_err()
    {
        return Err(AgentStoreError::InvariantViolation(
            "delegation contract is invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Validates all cross-child invariants before a parallel launch can open a write transaction.
///
/// # Errors
///
/// Returns [`AgentStoreError::InvariantViolation`] for invalid fan-out, duplicate identities or
/// keys, mismatched parent fences/times, or an invalid child contract.
pub fn validate_parallel_delegation_commit(
    commit: &LaunchParallelAgentDelegationCommit,
) -> Result<(), AgentStoreError> {
    if !(MINIMUM_PARALLEL_DELEGATIONS..=MAXIMUM_PARALLEL_DELEGATIONS)
        .contains(&commit.children.len())
    {
        return Err(invalid_parallel_delegation_arguments());
    }
    let expected_fence = commit.children[0].delegation.parent_fence;
    let expected_time = commit.children[0].delegation.prepared_at;
    let mut keys = BTreeSet::new();
    let mut delegation_ids = BTreeSet::new();
    let mut task_ids = BTreeSet::new();
    let mut run_ids = BTreeSet::new();
    let mut turn_ids = BTreeSet::new();
    let mut inbox_ids = BTreeSet::new();
    for child in &commit.children {
        validate_delegation_commit(&child.delegation)?;
        if child.delegation.parent_fence != expected_fence
            || child.delegation.prepared_at != expected_time
            || !valid_delegation_child_key(&child.child_key)
            || !keys.insert(child.child_key.as_str())
            || !delegation_ids.insert(child.delegation.delegation_id)
            || !task_ids.insert(child.delegation.child_task_id)
            || !run_ids.insert(child.delegation.child_run_id)
            || !turn_ids.insert(child.child_turn_id)
            || !inbox_ids.insert(child.child_inbox_entry_id)
        {
            return Err(AgentStoreError::InvariantViolation(
                "parallel delegation group identities or parent boundary diverged".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AGENT_DELEGATE_GROUP_RESULT_LOCATOR, AGENT_DELEGATE_PARALLEL_TOOL_ID,
        ParallelAgentDelegationRequest, agent_delegate_parallel_tool_descriptor,
    };
    use serde_json::json;

    fn child(key: &str) -> serde_json::Value {
        json!({
            "childKey": key,
            "objective": format!("Investigate {key}"),
            "instructions": "Return bounded cited evidence",
            "successCriteria": ["A concrete result is returned"],
            "context": {"scope": key}
        })
    }

    #[test]
    fn parallel_request_preserves_provider_order_and_unique_keys() {
        let parsed = ParallelAgentDelegationRequest::from_arguments(&json!({
            "delegations": [child("first"), child("second")]
        }))
        .expect("bounded parallel request");
        assert_eq!(parsed.delegations[0].child_key, "first");
        assert_eq!(parsed.delegations[1].child_key, "second");
    }

    #[test]
    fn parallel_request_rejects_duplicate_or_noncanonical_keys() {
        for arguments in [
            json!({"delegations": [child("same"), child("same")]}),
            json!({"delegations": [child("Upper"), child("other")]}),
            json!({"delegations": [child("-first"), child("other")]}),
            json!({"delegations": [child("one")]}),
        ] {
            assert!(ParallelAgentDelegationRequest::from_arguments(&arguments).is_err());
        }
    }

    #[test]
    fn parallel_descriptor_is_canonical_and_bounded() {
        let descriptor =
            agent_delegate_parallel_tool_descriptor().expect("parallel delegation descriptor");
        descriptor.validate_evidence().expect("descriptor evidence");
        assert_eq!(descriptor.tool_id, AGENT_DELEGATE_PARALLEL_TOOL_ID);
        assert_eq!(
            descriptor.output_schema["properties"]["sourceLocator"]["const"],
            AGENT_DELEGATE_GROUP_RESULT_LOCATOR
        );
    }
}
