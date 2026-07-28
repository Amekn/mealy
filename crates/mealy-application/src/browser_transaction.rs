use crate::{
    ApprovalSubject, ApprovalSubjectError, BrowserConfig, PolicyDecision, PolicyEvaluation,
    PolicyObligations, PolicyRequest, ToolConcurrency, ToolDescriptor, canonical_arguments_digest,
    is_sha256_digest, sha256_digest,
};
use mealy_domain::{
    ChannelBindingId, EffectClass, EffectId, ExecutorKind, IdempotencyClass, PolicyProfile,
    PrincipalId, RecoveryStrategy, RiskClass, RunId, TaskId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Duration};
use thiserror::Error;
use url::Url;

/// Stable model-visible identity of the one-shot transactional browser effect.
pub const BROWSER_TRANSACTION_TOOL_ID: &str = "browser.transact";
/// Capability prefix bound to one installed browser/runtime identity.
pub const BROWSER_TRANSACTION_CAPABILITY_PREFIX: &str = "network:browser:transaction";
/// Deterministic policy bundle for every transactional browser proposal.
pub const BROWSER_TRANSACTION_POLICY_VERSION: &str = "mealy.browser-transaction-policy.v1";
/// Stable explanation rendered for an exact matching transaction.
pub const BROWSER_TRANSACTION_APPROVAL_EXPLANATION: &str =
    "browser_transaction_requires_exact_owner_approval";
/// Maximum public form controls in one submission.
pub const BROWSER_TRANSACTION_MAXIMUM_FIELDS: usize = 32;
/// Maximum owner-private upload artifacts in one submission.
pub const BROWSER_TRANSACTION_MAXIMUM_UPLOADS: usize = 4;
/// Maximum one public form-control value.
pub const BROWSER_TRANSACTION_MAXIMUM_FIELD_BYTES: usize = 8 * 1024;
/// Maximum aggregate public form-control bytes.
pub const BROWSER_TRANSACTION_MAXIMUM_FIELDS_BYTES: usize = 64 * 1024;
/// Maximum one upload admitted to the isolated call.
pub const BROWSER_TRANSACTION_MAXIMUM_UPLOAD_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum aggregate upload bytes admitted to the isolated call.
pub const BROWSER_TRANSACTION_MAXIMUM_UPLOADS_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum confirmed download admitted to private artifact storage.
pub const BROWSER_TRANSACTION_MAXIMUM_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum model-visible JSON result after any binary has become an artifact.
pub const BROWSER_TRANSACTION_MAXIMUM_OUTPUT_BYTES: u64 = 1024 * 1024;
/// Hard one-shot browser deadline.
pub const BROWSER_TRANSACTION_TIMEOUT_MS: u64 = 60_000;

/// One exact public text control supplied to a POST form.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserTransactionField {
    name: String,
    value: String,
}

impl BrowserTransactionField {
    /// Exact HTML control name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Exact owner-approved public value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// One exact owner-private artifact mounted as a form upload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserTransactionUpload {
    control_name: String,
    artifact_id: String,
    artifact_digest: String,
    file_name: String,
    media_type: String,
    size_bytes: u64,
}

impl BrowserTransactionUpload {
    /// Exact file-control name.
    #[must_use]
    pub fn control_name(&self) -> &str {
        &self.control_name
    }

    /// Canonical owner-private artifact identity.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Expected SHA-256 digest rechecked before mounting.
    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    /// Bounded basename presented to the remote form.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Exact declared media type rechecked against artifact metadata.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Exact byte length rechecked against metadata and blob bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// Strict normalized one-shot transaction request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserTransactionRequest {
    initial_url: String,
    form_digest: String,
    #[serde(default)]
    fields: Vec<BrowserTransactionField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    submitter: Option<BrowserTransactionField>,
    #[serde(default)]
    uploads: Vec<BrowserTransactionUpload>,
}

impl BrowserTransactionRequest {
    /// Canonical initial page URL.
    #[must_use]
    pub fn initial_url(&self) -> &str {
        &self.initial_url
    }

    /// Digest of the exact inert form catalog entry observed before approval.
    #[must_use]
    pub fn form_digest(&self) -> &str {
        &self.form_digest
    }

    /// Ordered exact public controls.
    #[must_use]
    pub fn fields(&self) -> &[BrowserTransactionField] {
        &self.fields
    }

    /// Optional exact submitter name/value.
    #[must_use]
    pub const fn submitter(&self) -> Option<&BrowserTransactionField> {
        self.submitter.as_ref()
    }

    /// Ordered exact upload artifact bindings.
    #[must_use]
    pub fn uploads(&self) -> &[BrowserTransactionUpload] {
        &self.uploads
    }

    /// Canonical approved origin.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserTransactionContractError::InvalidArguments`] only if trusted code
    /// constructed this request without normalization.
    pub fn origin(&self) -> Result<String, BrowserTransactionContractError> {
        Url::parse(&self.initial_url)
            .map(|url| url.origin().ascii_serialization())
            .map_err(|_| BrowserTransactionContractError::InvalidArguments)
    }
}

/// Exact runtime authority reconstructed for one transaction proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserTransactionPolicyGrant {
    /// Authenticated owner principal.
    pub principal_id: PrincipalId,
    /// Authenticated channel binding.
    pub channel_binding_id: ChannelBindingId,
    /// Owning task.
    pub task_id: TaskId,
    /// Proposing run.
    pub run_id: RunId,
    /// Exact generic descriptor digest.
    pub tool_descriptor_digest: String,
    /// Content-pinned browser and adapter identity.
    pub runtime_identity_digest: String,
    /// Exact logical capability.
    pub capability: String,
    /// Exact origin-scoped external target.
    pub target_resource: String,
    /// Exact origin-scoped network authority.
    pub network_destination: String,
    /// First accepted evaluation instant.
    pub valid_from_ms: i64,
    /// Exclusive grant expiry.
    pub expires_at_ms: i64,
}

impl BrowserTransactionPolicyGrant {
    fn validate(&self) -> Result<(), BrowserTransactionContractError> {
        if !is_sha256_digest(&self.tool_descriptor_digest)
            || !is_sha256_digest(&self.runtime_identity_digest)
            || !valid_label(&self.capability, 1_024)
            || !self
                .capability
                .starts_with(BROWSER_TRANSACTION_CAPABILITY_PREFIX)
            || !valid_label(&self.target_resource, 4_096)
            || !self.target_resource.starts_with("browser-transaction:")
            || !valid_label(&self.network_destination, 4_096)
            || !self.network_destination.starts_with("origin:")
            || self.valid_from_ms < 0
            || self.expires_at_ms <= self.valid_from_ms
        {
            return Err(BrowserTransactionContractError::InvalidGrant);
        }
        Ok(())
    }
}

/// Builds the content identity of the browser executable plus transaction contract.
///
/// # Errors
///
/// Returns [`BrowserTransactionContractError::InvalidConfiguration`] unless read-only and
/// transactional browser authority are both explicitly enabled.
pub fn browser_transaction_runtime_identity_digest(
    config: &BrowserConfig,
) -> Result<String, BrowserTransactionContractError> {
    config
        .validate()
        .map_err(|_| BrowserTransactionContractError::InvalidConfiguration)?;
    if !config.enabled() || !config.transactional_enabled() {
        return Err(BrowserTransactionContractError::InvalidConfiguration);
    }
    Ok(sha256_digest(
        json!({
            "contractVersion": "mealy.browser-transaction-runtime.v1",
            "bundleDigest": config.bundle_digest(),
            "executableDigest": config.executable_digest(),
            "product": config.product(),
            "protocolVersion": config.protocol_version(),
            "profile": "fresh-one-shot-same-origin-post",
            "maximumFields": BROWSER_TRANSACTION_MAXIMUM_FIELDS,
            "maximumUploads": BROWSER_TRANSACTION_MAXIMUM_UPLOADS,
            "maximumUploadsBytes": BROWSER_TRANSACTION_MAXIMUM_UPLOADS_BYTES,
            "maximumDownloadBytes": BROWSER_TRANSACTION_MAXIMUM_DOWNLOAD_BYTES,
        })
        .to_string()
        .as_bytes(),
    ))
}

/// Exact capability placed into newly promoted run ceilings.
///
/// # Errors
///
/// Returns [`BrowserTransactionContractError::InvalidConfiguration`] when transactional browser
/// authority is not active.
pub fn browser_transaction_required_capability(
    config: &BrowserConfig,
) -> Result<String, BrowserTransactionContractError> {
    Ok(format!(
        "{BROWSER_TRANSACTION_CAPABILITY_PREFIX}:sha256:{}",
        browser_transaction_runtime_identity_digest(config)?
    ))
}

/// Builds the immutable model-facing transactional browser descriptor.
///
/// # Errors
///
/// Returns [`BrowserTransactionContractError`] when configuration or descriptor evidence is
/// invalid.
pub fn browser_transaction_tool_descriptor(
    config: &BrowserConfig,
) -> Result<ToolDescriptor, BrowserTransactionContractError> {
    let runtime_identity_digest = browser_transaction_runtime_identity_digest(config)?;
    let input_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "initialUrl": {"type": "string", "minLength": 1, "maxLength": 4096},
            "formDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "fields": {
                "type": "array",
                "maxItems": BROWSER_TRANSACTION_MAXIMUM_FIELDS,
                "items": transaction_field_schema()
            },
            "submitter": {
                "oneOf": [
                    {"type": "null"},
                    transaction_field_schema()
                ]
            },
            "uploads": {
                "type": "array",
                "maxItems": BROWSER_TRANSACTION_MAXIMUM_UPLOADS,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "controlName": {"type": "string", "minLength": 1, "maxLength": 256},
                        "artifactId": {"type": "string", "minLength": 1, "maxLength": 128},
                        "artifactDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "fileName": {"type": "string", "minLength": 1, "maxLength": 255},
                        "mediaType": {"type": "string", "minLength": 1, "maxLength": 128},
                        "sizeBytes": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": BROWSER_TRANSACTION_MAXIMUM_UPLOAD_BYTES
                        }
                    },
                    "required": [
                        "controlName", "artifactId", "artifactDigest", "fileName", "mediaType",
                        "sizeBytes"
                    ]
                }
            }
        },
        "required": ["initialUrl", "formDigest"]
    });
    let output_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "artifactId": {"type": ["string", "null"]},
            "artifactDigest": {"type": ["string", "null"]},
            "finalUrl": {"type": "string", "minLength": 1, "maxLength": 4096},
            "formDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "requestDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "responseStatus": {"type": "integer", "minimum": 100, "maximum": 599},
            "text": {"type": "string", "maxLength": 131_072},
            "title": {"type": "string", "maxLength": 4096},
            "truncatedText": {"type": "boolean"}
        },
        "required": [
            "artifactId", "artifactDigest", "finalUrl", "formDigest", "requestDigest",
            "responseStatus", "text", "title", "truncatedText"
        ]
    });
    let input_schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let output_schema_digest = sha256_digest(output_schema.to_string().as_bytes());
    let mut descriptor = ToolDescriptor {
        tool_id: BROWSER_TRANSACTION_TOOL_ID.to_owned(),
        version: format!("1.0.0+{}", &runtime_identity_digest[..16]),
        input_schema,
        output_schema,
        input_schema_digest,
        output_schema_digest,
        descriptor_digest: String::new(),
        effect_class: EffectClass::NonIdempotent,
        risk_class: RiskClass::High,
        required_capabilities: vec![browser_transaction_required_capability(config)?],
        timeout: Duration::from_millis(BROWSER_TRANSACTION_TIMEOUT_MS),
        maximum_output_bytes: BROWSER_TRANSACTION_MAXIMUM_OUTPUT_BYTES,
        concurrency: ToolConcurrency::Serial,
        conflict_key_templates: vec!["browser-transaction-origin".to_owned()],
        idempotency: IdempotencyClass::NonIdempotent,
        recovery: RecoveryStrategy::NeverRetry,
        executor: ExecutorKind::Builtin,
        executable_identity_digest: runtime_identity_digest,
    };
    descriptor.descriptor_digest = descriptor
        .computed_descriptor_digest()
        .map_err(|_| BrowserTransactionContractError::InvalidDescriptor)?;
    descriptor
        .validate()
        .map_err(|_| BrowserTransactionContractError::InvalidDescriptor)?;
    Ok(descriptor)
}

/// Strictly normalizes one exact model-requested transaction.
///
/// Optional collections are materialized, while security-sensitive URL identity must already be
/// canonical. Calling this on canonical output is idempotent for safe durable revalidation.
///
/// # Errors
///
/// Returns [`BrowserTransactionContractError::InvalidArguments`] for unsafe, ambiguous,
/// oversized, duplicate, or extra fields.
pub fn normalize_browser_transaction_arguments(
    arguments: &Value,
) -> Result<Value, BrowserTransactionContractError> {
    let mut request = serde_json::from_value::<BrowserTransactionRequest>(arguments.clone())
        .map_err(|_| BrowserTransactionContractError::InvalidArguments)?;
    request.initial_url = canonical_url(&request.initial_url)?;
    if !is_sha256_digest(&request.form_digest)
        || request.fields.len() > BROWSER_TRANSACTION_MAXIMUM_FIELDS
        || request.uploads.len() > BROWSER_TRANSACTION_MAXIMUM_UPLOADS
        || request.fields.is_empty() && request.uploads.is_empty() && request.submitter.is_none()
    {
        return Err(BrowserTransactionContractError::InvalidArguments);
    }
    let mut control_names = BTreeSet::new();
    let mut field_bytes = 0_usize;
    for field in request.fields.iter().chain(request.submitter.iter()) {
        validate_field(field)?;
        field_bytes = field_bytes
            .checked_add(field.name.len())
            .and_then(|bytes| bytes.checked_add(field.value.len()))
            .ok_or(BrowserTransactionContractError::InvalidArguments)?;
        if !control_names.insert(field.name.clone()) {
            return Err(BrowserTransactionContractError::InvalidArguments);
        }
    }
    if field_bytes > BROWSER_TRANSACTION_MAXIMUM_FIELDS_BYTES {
        return Err(BrowserTransactionContractError::InvalidArguments);
    }
    let mut upload_bytes = 0_u64;
    let mut artifact_ids = BTreeSet::new();
    for upload in &request.uploads {
        upload_bytes = upload_bytes
            .checked_add(upload.size_bytes)
            .ok_or(BrowserTransactionContractError::InvalidArguments)?;
        if !valid_control_name(&upload.control_name)
            || !control_names.insert(upload.control_name.clone())
            || !valid_label(&upload.artifact_id, 128)
            || !artifact_ids.insert(upload.artifact_id.clone())
            || !is_sha256_digest(&upload.artifact_digest)
            || !valid_file_name(&upload.file_name)
            || !valid_media_type(&upload.media_type)
            || !(1..=BROWSER_TRANSACTION_MAXIMUM_UPLOAD_BYTES).contains(&upload.size_bytes)
        {
            return Err(BrowserTransactionContractError::InvalidArguments);
        }
    }
    if upload_bytes > BROWSER_TRANSACTION_MAXIMUM_UPLOADS_BYTES {
        return Err(BrowserTransactionContractError::InvalidArguments);
    }
    serde_json::to_value(request).map_err(|_| BrowserTransactionContractError::InvalidArguments)
}

/// Reconstructs exact origin-scoped policy authority for one normalized request.
///
/// # Errors
///
/// Returns [`BrowserTransactionContractError`] for divergent configuration, descriptor, request,
/// or time evidence.
#[allow(clippy::too_many_arguments)]
pub fn browser_transaction_policy_grant(
    config: &BrowserConfig,
    descriptor: &ToolDescriptor,
    normalized_arguments: &Value,
    principal_id: PrincipalId,
    channel_binding_id: ChannelBindingId,
    task_id: TaskId,
    run_id: RunId,
    valid_from_ms: i64,
    expires_at_ms: i64,
) -> Result<BrowserTransactionPolicyGrant, BrowserTransactionContractError> {
    let canonical = normalize_browser_transaction_arguments(normalized_arguments)?;
    if canonical != *normalized_arguments
        || descriptor != &browser_transaction_tool_descriptor(config)?
        || valid_from_ms < 0
        || expires_at_ms <= valid_from_ms
    {
        return Err(BrowserTransactionContractError::InvalidGrant);
    }
    let request = serde_json::from_value::<BrowserTransactionRequest>(canonical)
        .map_err(|_| BrowserTransactionContractError::InvalidArguments)?;
    let origin = request.origin()?;
    let grant = BrowserTransactionPolicyGrant {
        principal_id,
        channel_binding_id,
        task_id,
        run_id,
        tool_descriptor_digest: descriptor.descriptor_digest.clone(),
        runtime_identity_digest: browser_transaction_runtime_identity_digest(config)?,
        capability: browser_transaction_required_capability(config)?,
        target_resource: format!("browser-transaction:{origin}"),
        network_destination: format!("origin:{origin}"),
        valid_from_ms,
        expires_at_ms,
    };
    grant.validate()?;
    Ok(grant)
}

/// Evaluates one exact browser transaction and requires owner approval on every match.
#[must_use]
pub fn evaluate_browser_transaction_policy(
    request: &PolicyRequest,
    grant: &BrowserTransactionPolicyGrant,
) -> PolicyEvaluation {
    let deny = |explanation: &str| PolicyEvaluation {
        decision: PolicyDecision::Deny,
        obligations: denied_obligations(request.requested_profile),
        policy_version: request.policy_version.clone(),
        explanation: explanation.to_owned(),
    };
    if request.validate().is_err() || grant.validate().is_err() {
        return deny("invalid_browser_transaction_request");
    }
    if request.principal_id != grant.principal_id
        || request.channel_binding_id != grant.channel_binding_id
        || request.task_id != grant.task_id
        || request.run_id != grant.run_id
    {
        return deny("browser_transaction_owner_or_run_not_granted");
    }
    if request.evaluated_at_ms < grant.valid_from_ms
        || request.evaluated_at_ms >= grant.expires_at_ms
    {
        return deny("browser_transaction_grant_not_current");
    }
    let arguments_valid = normalize_browser_transaction_arguments(&request.normalized_arguments)
        .is_ok_and(|canonical| canonical == request.normalized_arguments)
        && request
            .normalized_arguments
            .get("initialUrl")
            .and_then(Value::as_str)
            .and_then(|initial_url| Url::parse(initial_url).ok())
            .is_some_and(|url| {
                let origin = url.origin().ascii_serialization();
                grant.target_resource == format!("browser-transaction:{origin}")
                    && grant.network_destination == format!("origin:{origin}")
            });
    let exact_form_claim = request
        .normalized_arguments
        .get("formDigest")
        .and_then(Value::as_str)
        .map(|form_digest| {
            format!(
                "browser-transaction-form:{}:{form_digest}",
                grant.target_resource
            )
        });
    if !arguments_valid
        || request.agent_role != "assistant"
        || request.policy_version != BROWSER_TRANSACTION_POLICY_VERSION
        || request.task_risk != RiskClass::High
        || request.tool.tool_id != BROWSER_TRANSACTION_TOOL_ID
        || request.tool.effect_class != EffectClass::NonIdempotent
        || request.tool.risk_class != RiskClass::High
        || request.tool.idempotency != IdempotencyClass::NonIdempotent
        || request.tool.recovery != RecoveryStrategy::NeverRetry
        || request.tool.executor != ExecutorKind::Builtin
        || request.tool.descriptor_digest != grant.tool_descriptor_digest
        || request.tool.executable_identity_digest != grant.runtime_identity_digest
        || request.tool.required_capabilities != [grant.capability.clone()]
        || request.target_resources != [grant.target_resource.clone()]
        || !request.workspace_roots.is_empty()
        || exact_form_claim
            .as_ref()
            .is_none_or(|claim| request.resource_claims != [claim.clone()])
        || !request.secret_references.is_empty()
        || request.network_destinations != [grant.network_destination.clone()]
        || request.requested_capability != grant.capability
        || request.requested_profile != PolicyProfile::ServiceOperator
        || request.enforceable_profiles != [PolicyProfile::ServiceOperator]
    {
        return deny("no_matching_browser_transaction_rule");
    }
    PolicyEvaluation {
        decision: PolicyDecision::RequireApproval,
        obligations: PolicyObligations {
            profile: PolicyProfile::ServiceOperator,
            readable_paths: Vec::new(),
            writable_paths: Vec::new(),
            allowed_executable_identity_digests: vec![
                request.tool.executable_identity_digest.clone(),
            ],
            allow_process_spawn: true,
            allowed_environment_variables: Vec::new(),
            network_destinations: vec![grant.network_destination.clone()],
            secret_references: Vec::new(),
            argument_rewrite: None,
            redactions: Vec::new(),
            maximum_duration_ms: BROWSER_TRANSACTION_TIMEOUT_MS,
            maximum_output_bytes: BROWSER_TRANSACTION_MAXIMUM_OUTPUT_BYTES,
            maximum_memory_bytes: 1024 * 1024 * 1024,
            maximum_processes: 256,
            validator_required: true,
        },
        policy_version: BROWSER_TRANSACTION_POLICY_VERSION.to_owned(),
        explanation: BROWSER_TRANSACTION_APPROVAL_EXPLANATION.to_owned(),
    }
}

/// Constructs the immutable approval subject for one exact browser transaction.
///
/// # Errors
///
/// Returns [`BrowserTransactionContractError`] for divergent policy, authority, or expiry
/// evidence.
pub fn browser_transaction_approval_subject(
    effect_id: EffectId,
    request: &PolicyRequest,
    grant: &BrowserTransactionPolicyGrant,
    expires_at_ms: i64,
) -> Result<ApprovalSubject, BrowserTransactionContractError> {
    if evaluate_browser_transaction_policy(request, grant).decision
        != PolicyDecision::RequireApproval
        || expires_at_ms <= request.evaluated_at_ms
        || expires_at_ms > grant.expires_at_ms
    {
        return Err(BrowserTransactionContractError::InvalidApproval);
    }
    let subject = ApprovalSubject {
        principal_id: request.principal_id,
        task_id: request.task_id,
        effect_id,
        tool_id: request.tool.tool_id.clone(),
        tool_version: request.tool.version.clone(),
        canonical_arguments_digest: canonical_arguments_digest(&request.normalized_arguments),
        capability_scope: grant.capability.clone(),
        target_resources: request.target_resources.clone(),
        executable_identity_digest: request.tool.executable_identity_digest.clone(),
        policy_version: BROWSER_TRANSACTION_POLICY_VERSION.to_owned(),
        expires_at_ms,
    };
    subject.validate()?;
    Ok(subject)
}

fn transaction_field_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 256},
            "value": {
                "type": "string",
                "maxLength": BROWSER_TRANSACTION_MAXIMUM_FIELD_BYTES
            }
        },
        "required": ["name", "value"]
    })
}

fn canonical_url(value: &str) -> Result<String, BrowserTransactionContractError> {
    if value.is_empty() || value.len() > 4_096 || value.trim() != value {
        return Err(BrowserTransactionContractError::InvalidArguments);
    }
    let url = Url::parse(value).map_err(|_| BrowserTransactionContractError::InvalidArguments)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || !matches!(url.scheme(), "http" | "https")
    {
        return Err(BrowserTransactionContractError::InvalidArguments);
    }
    let canonical = url.to_string();
    if canonical != value {
        return Err(BrowserTransactionContractError::InvalidArguments);
    }
    Ok(canonical)
}

fn validate_field(field: &BrowserTransactionField) -> Result<(), BrowserTransactionContractError> {
    if !valid_control_name(&field.name)
        || field.value.len() > BROWSER_TRANSACTION_MAXIMUM_FIELD_BYTES
        || field
            .value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(BrowserTransactionContractError::InvalidArguments);
    }
    Ok(())
}

fn valid_control_name(value: &str) -> bool {
    valid_label(value, 256)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'[' | b']')
        })
}

fn valid_file_name(value: &str) -> bool {
    valid_label(value, 255)
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
}

fn valid_media_type(value: &str) -> bool {
    valid_label(value, 128)
        && value.contains('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'+' | b'-'))
}

fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn denied_obligations(profile: PolicyProfile) -> PolicyObligations {
    PolicyObligations {
        profile,
        readable_paths: Vec::new(),
        writable_paths: Vec::new(),
        allowed_executable_identity_digests: Vec::new(),
        allow_process_spawn: false,
        allowed_environment_variables: Vec::new(),
        network_destinations: Vec::new(),
        secret_references: Vec::new(),
        argument_rewrite: None,
        redactions: Vec::new(),
        maximum_duration_ms: 0,
        maximum_output_bytes: 0,
        maximum_memory_bytes: 0,
        maximum_processes: 0,
        validator_required: false,
    }
}

/// Invalid transactional browser configuration, request, policy, or approval evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BrowserTransactionContractError {
    /// Transaction authority is disabled or its installed runtime is invalid.
    #[error("transactional browser configuration is invalid")]
    InvalidConfiguration,
    /// Model-supplied form, control, URL, or artifact bindings are invalid.
    #[error("transactional browser arguments are invalid")]
    InvalidArguments,
    /// Generic tool descriptor evidence could not be constructed safely.
    #[error("transactional browser descriptor is invalid")]
    InvalidDescriptor,
    /// Reconstructed origin-scoped runtime authority is invalid.
    #[error("transactional browser policy grant is invalid")]
    InvalidGrant,
    /// Policy, request, grant, or expiry does not match the approval subject.
    #[error("transactional browser approval evidence is invalid")]
    InvalidApproval,
    /// Generic approval evidence is malformed.
    #[error(transparent)]
    Approval(#[from] ApprovalSubjectError),
}

#[cfg(test)]
mod tests {
    use super::{
        BROWSER_TRANSACTION_POLICY_VERSION, BrowserTransactionContractError,
        browser_transaction_approval_subject, browser_transaction_policy_grant,
        browser_transaction_required_capability, browser_transaction_tool_descriptor,
        evaluate_browser_transaction_policy, normalize_browser_transaction_arguments,
    };
    use crate::{BrowserConfig, PolicyDecision, PolicyRequest};
    use mealy_domain::{
        ChannelBindingId, EffectId, PolicyProfile, PrincipalId, RiskClass, RunId, TaskId,
    };
    use serde_json::{Value, json};

    fn config() -> BrowserConfig {
        BrowserConfig::new(
            true,
            format!("browser-runtimes/{}", "1".repeat(64)),
            "1".repeat(64),
            "chrome-headless-shell".to_owned(),
            "2".repeat(64),
            "HeadlessChrome/151.0.7922.47".to_owned(),
            "1.3".to_owned(),
        )
        .expect("browser config")
        .with_transactional_enabled(true)
    }

    fn arguments() -> Value {
        json!({
            "initialUrl": "https://example.test/form",
            "formDigest": "3".repeat(64),
            "fields": [
                {"name": "email", "value": "owner@example.test"},
                {"name": "message", "value": "exact request"}
            ],
            "submitter": {"name": "action", "value": "send"},
            "uploads": [{
                "controlName": "attachment",
                "artifactId": "019f0000-0000-7000-8000-000000000001",
                "artifactDigest": "4".repeat(64),
                "fileName": "evidence.txt",
                "mediaType": "text/plain",
                "sizeBytes": 16
            }]
        })
    }

    #[test]
    fn configuration_keeps_transaction_authority_separate() {
        let disabled = config().with_transactional_enabled(false);
        assert!(matches!(
            browser_transaction_tool_descriptor(&disabled),
            Err(BrowserTransactionContractError::InvalidConfiguration)
        ));
        assert!(
            browser_transaction_required_capability(&config())
                .expect("capability")
                .starts_with("network:browser:transaction:sha256:")
        );
    }

    #[test]
    fn arguments_are_exact_bounded_and_idempotently_normalized() {
        let normalized =
            normalize_browser_transaction_arguments(&arguments()).expect("normalize arguments");
        assert_eq!(
            normalize_browser_transaction_arguments(&normalized).expect("renormalize"),
            normalized
        );
        let mut duplicate = arguments();
        duplicate["uploads"][0]["controlName"] = Value::from("email");
        assert!(normalize_browser_transaction_arguments(&duplicate).is_err());
        let mut extra = arguments();
        extra["actionUrl"] = Value::from("https://attacker.test/");
        assert!(normalize_browser_transaction_arguments(&extra).is_err());
        let mut credential_url = arguments();
        credential_url["initialUrl"] = Value::from("https://owner:secret@example.test/form");
        assert!(normalize_browser_transaction_arguments(&credential_url).is_err());
        let mut noncanonical_url = arguments();
        noncanonical_url["initialUrl"] = Value::from("HTTPS://EXAMPLE.TEST:443/form");
        assert!(normalize_browser_transaction_arguments(&noncanonical_url).is_err());
    }

    #[test]
    fn exact_origin_policy_always_requires_approval() {
        let config = config();
        let descriptor =
            browser_transaction_tool_descriptor(&config).expect("transaction descriptor");
        let normalized =
            normalize_browser_transaction_arguments(&arguments()).expect("normalize arguments");
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let grant = browser_transaction_policy_grant(
            &config,
            &descriptor,
            &normalized,
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            1_000,
            11_000,
        )
        .expect("policy grant");
        let request = PolicyRequest {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            agent_role: "assistant".to_owned(),
            task_risk: RiskClass::High,
            tool: descriptor,
            normalized_arguments: normalized.clone(),
            target_resources: vec![grant.target_resource.clone()],
            workspace_roots: Vec::new(),
            resource_claims: vec![format!(
                "browser-transaction-form:{}:{}",
                grant.target_resource,
                normalized["formDigest"].as_str().expect("form digest")
            )],
            secret_references: Vec::new(),
            network_destinations: vec![grant.network_destination.clone()],
            requested_capability: grant.capability.clone(),
            requested_profile: PolicyProfile::ServiceOperator,
            enforceable_profiles: vec![PolicyProfile::ServiceOperator],
            evaluated_at_ms: 1_000,
            policy_version: BROWSER_TRANSACTION_POLICY_VERSION.to_owned(),
        };
        assert_eq!(
            evaluate_browser_transaction_policy(&request, &grant).decision,
            PolicyDecision::RequireApproval
        );
        browser_transaction_approval_subject(EffectId::new(), &request, &grant, 10_000)
            .expect("approval subject");
        let mut widened = request;
        widened.network_destinations = vec!["origin:https://attacker.test".to_owned()];
        assert_eq!(
            evaluate_browser_transaction_policy(&widened, &grant).decision,
            PolicyDecision::Deny
        );
        let mut changed_form = arguments();
        changed_form["formDigest"] = Value::from("9".repeat(64));
        widened.normalized_arguments =
            normalize_browser_transaction_arguments(&changed_form).expect("changed form");
        widened.network_destinations = vec![grant.network_destination.clone()];
        assert_eq!(
            evaluate_browser_transaction_policy(&widened, &grant).decision,
            PolicyDecision::Deny
        );
    }
}
