use crate::{
    ApprovalSubject, ApprovalSubjectError, PolicyDecision, PolicyEvaluation, PolicyObligations,
    PolicyRequest, ProviderCredentialReference, ToolConcurrency, ToolDescriptor,
    canonical_arguments_digest, is_sha256_digest, sha256_digest, validate_provider_base_url,
};
use mealy_domain::{
    ChannelBindingId, EffectClass, EffectId, ExecutorKind, IdempotencyClass, PolicyProfile,
    PrincipalId, RecoveryStrategy, RiskClass, RunId, TaskId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// Stable model-visible identity of the governed image-generation effect.
pub const IMAGE_GENERATION_TOOL_ID: &str = "image.generate";
/// Logical capability required by every image-generation task.
pub const IMAGE_GENERATION_CAPABILITY_PREFIX: &str = "media.image.generate";
/// Deterministic policy bundle used for image-generation proposals.
pub const IMAGE_GENERATION_POLICY_VERSION: &str = "mealy.image-generation-policy.v1";
/// Stable approval explanation for a matched image-generation request.
pub const IMAGE_GENERATION_APPROVAL_EXPLANATION: &str =
    "image_generation_requires_exact_owner_approval";
/// Maximum UTF-8 bytes accepted in one generation prompt.
pub const IMAGE_GENERATION_MAXIMUM_PROMPT_BYTES: usize = 8 * 1024;
/// Maximum canonical generated image bytes accepted into the private artifact store.
pub const IMAGE_GENERATION_MAXIMUM_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;
/// Minimum useful provider deadline.
pub const IMAGE_GENERATION_MINIMUM_TIMEOUT_MS: u64 = 1_000;
/// Maximum provider deadline accepted by configuration.
pub const IMAGE_GENERATION_MAXIMUM_TIMEOUT_MS: u64 = 180_000;

/// Exact remote image API wire protocol selected by stopped-daemon configuration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageGenerationProtocol {
    /// OpenAI-compatible `POST {base}/images/generations`.
    OpenAiImages,
    /// `OpenRouter` dedicated `POST {base}/images`.
    OpenRouterImages,
}

/// Non-secret, exact authority for one governed image-generation adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageGenerationConfig {
    provider_id: String,
    protocol: ImageGenerationProtocol,
    base_url: String,
    model: String,
    credential: Option<ProviderCredentialReference>,
    residency: String,
    size: String,
    quality: String,
    maximum_cost_microunits: u64,
    maximum_output_bytes: u64,
    timeout_ms: u64,
}

impl ImageGenerationConfig {
    /// Validates the exact endpoint, model, credential reference, output, cost, and deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ImageGenerationContractError::InvalidConfiguration`] for any unsafe or
    /// non-canonical authority.
    pub fn validate(&self) -> Result<(), ImageGenerationContractError> {
        let local = validate_provider_base_url(&self.base_url)
            .map_err(|_| ImageGenerationContractError::InvalidConfiguration)?;
        Url::parse(&self.base_url)
            .map_err(|_| ImageGenerationContractError::InvalidConfiguration)?;
        if !valid_label(&self.provider_id, 128)
            || !valid_label(&self.model, 256)
            || !valid_label(&self.residency, 128)
            || self.base_url.ends_with('/')
            || !matches!(self.size.as_str(), "1024x1024" | "1536x1024" | "1024x1536")
            || !matches!(self.quality.as_str(), "low" | "medium" | "high")
            || self.maximum_cost_microunits == 0
            || self.maximum_cost_microunits > 1_000_000_000_000
            || self.maximum_output_bytes == 0
            || self.maximum_output_bytes > IMAGE_GENERATION_MAXIMUM_OUTPUT_BYTES
            || !(IMAGE_GENERATION_MINIMUM_TIMEOUT_MS..=IMAGE_GENERATION_MAXIMUM_TIMEOUT_MS)
                .contains(&self.timeout_ms)
            || self
                .credential
                .as_ref()
                .is_some_and(|credential| credential.validate().is_err())
            || !local && self.credential.is_none()
        {
            return Err(ImageGenerationContractError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Stable provider identity retained in durable evidence.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Exact remote wire protocol.
    #[must_use]
    pub const fn protocol(&self) -> ImageGenerationProtocol {
        self.protocol
    }

    /// Exact configured provider API base.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Exact configured image model.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Opaque credential reference resolved only by the trusted daemon.
    #[must_use]
    pub const fn credential(&self) -> Option<&ProviderCredentialReference> {
        self.credential.as_ref()
    }

    /// Owner-declared data-residency label.
    #[must_use]
    pub fn residency(&self) -> &str {
        &self.residency
    }

    /// Operator-pinned output dimensions.
    #[must_use]
    pub fn size(&self) -> &str {
        &self.size
    }

    /// Operator-pinned output quality.
    #[must_use]
    pub fn quality(&self) -> &str {
        &self.quality
    }

    /// Maximum provider charge reserved for one approved generation.
    #[must_use]
    pub const fn maximum_cost_microunits(&self) -> u64 {
        self.maximum_cost_microunits
    }

    /// Maximum canonical output admitted to artifact storage.
    #[must_use]
    pub const fn maximum_output_bytes(&self) -> u64 {
        self.maximum_output_bytes
    }

    /// Exact provider deadline.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Exact buffered generation endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ImageGenerationContractError::InvalidConfiguration`] only when validation was
    /// bypassed.
    pub fn endpoint(&self) -> Result<String, ImageGenerationContractError> {
        self.validate()?;
        Ok(match self.protocol {
            ImageGenerationProtocol::OpenAiImages => {
                format!("{}/images/generations", self.base_url)
            }
            ImageGenerationProtocol::OpenRouterImages => format!("{}/images", self.base_url),
        })
    }

    /// Canonical network authority copied into capability and policy evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ImageGenerationContractError::InvalidConfiguration`] only when validation was
    /// bypassed.
    pub fn capability_network_destination(&self) -> Result<String, ImageGenerationContractError> {
        self.validate()?;
        Url::parse(&self.base_url)
            .map(|url| format!("origin:{}", url.origin().ascii_serialization()))
            .map_err(|_| ImageGenerationContractError::InvalidConfiguration)
    }

    /// Opaque credential authority copied into capability and policy evidence.
    #[must_use]
    pub fn capability_secret_reference(&self) -> Option<String> {
        self.credential
            .as_ref()
            .map(ProviderCredentialReference::capability_reference)
    }

    /// Logical external target shown in approvals and conflict claims.
    #[must_use]
    pub fn target_resource(&self) -> String {
        format!("image-provider://{}/model/{}", self.provider_id, self.model)
    }

    /// Collision-resistant adapter/configuration identity.
    #[must_use]
    pub fn adapter_identity_digest(&self) -> String {
        sha256_digest(
            json!({
                "contractVersion": "mealy.image-generation-adapter.v1",
                "providerId": self.provider_id,
                "protocol": self.protocol,
                "baseUrl": self.base_url,
                "model": self.model,
                "credentialReference": self.capability_secret_reference(),
                "residency": self.residency,
                "size": self.size,
                "quality": self.quality,
                "outputFormat": "jpeg",
                "maximumCostMicrounits": self.maximum_cost_microunits,
                "maximumOutputBytes": self.maximum_output_bytes,
                "timeoutMs": self.timeout_ms,
            })
            .to_string()
            .as_bytes(),
        )
    }

    /// Digest of operator-controlled arguments injected beside every model prompt.
    #[must_use]
    pub fn dispatch_constraints_digest(&self) -> String {
        sha256_digest(
            Value::Object(image_generation_dispatch_constraints(self))
                .to_string()
                .as_bytes(),
        )
    }

    /// Exact capability string copied into newly promoted task ceilings.
    #[must_use]
    pub fn required_capability(&self) -> String {
        format!(
            "{IMAGE_GENERATION_CAPABILITY_PREFIX}:{}:{}:sha256:{}",
            self.provider_id,
            self.model,
            self.adapter_identity_digest()
        )
    }
}

/// Exact runtime authority reconstructed for one image-generation proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageGenerationPolicyGrant {
    /// Authenticated owner principal.
    pub principal_id: PrincipalId,
    /// Authenticated channel binding.
    pub channel_binding_id: ChannelBindingId,
    /// Task whose immutable ceiling contains the image tool.
    pub task_id: TaskId,
    /// Run proposing the image effect.
    pub run_id: RunId,
    /// Exact generic descriptor digest.
    pub tool_descriptor_digest: String,
    /// Exact adapter/configuration identity digest.
    pub adapter_identity_digest: String,
    /// Digest of the operator-controlled arguments expected beside any approved prompt.
    pub dispatch_constraints_digest: String,
    /// Exact logical capability.
    pub capability: String,
    /// Exact logical provider/model target.
    pub target_resource: String,
    /// Canonical network authority.
    pub network_destination: String,
    /// Opaque credential authority, when configured.
    pub secret_reference: Option<String>,
    /// First accepted evaluation instant.
    pub valid_from_ms: i64,
    /// Exclusive grant expiry.
    pub expires_at_ms: i64,
}

impl ImageGenerationPolicyGrant {
    fn validate(&self) -> Result<(), ImageGenerationContractError> {
        if !is_sha256_digest(&self.tool_descriptor_digest)
            || !is_sha256_digest(&self.adapter_identity_digest)
            || !is_sha256_digest(&self.dispatch_constraints_digest)
            || !valid_label(&self.capability, 1_024)
            || !self
                .capability
                .starts_with(IMAGE_GENERATION_CAPABILITY_PREFIX)
            || !valid_label(&self.target_resource, 1_024)
            || !self.target_resource.starts_with("image-provider://")
            || !valid_label(&self.network_destination, 1_024)
            || !self.network_destination.starts_with("origin:")
            || self
                .secret_reference
                .as_ref()
                .is_some_and(|reference| !valid_label(reference, 1_024))
            || self.valid_from_ms < 0
            || self.expires_at_ms <= self.valid_from_ms
        {
            Err(ImageGenerationContractError::InvalidGrant)
        } else {
            Ok(())
        }
    }
}

/// Builds the immutable model-facing descriptor for the exact configured generator.
///
/// # Errors
///
/// Returns [`ImageGenerationContractError`] when configuration or descriptor evidence is invalid.
pub fn image_generation_tool_descriptor(
    config: &ImageGenerationConfig,
) -> Result<ToolDescriptor, ImageGenerationContractError> {
    config.validate()?;
    let input_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "prompt": {
                "type": "string",
                "minLength": 1,
                "maxLength": IMAGE_GENERATION_MAXIMUM_PROMPT_BYTES,
                "description": "Describe the single image to generate. The owner-configured model, size, quality, output format, cost ceiling, and endpoint cannot be changed."
            }
        },
        "required": ["prompt"]
    });
    let output_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "artifactId": {"type": "string"},
            "digest": {"type": "string"},
            "height": {"type": "integer", "minimum": 1},
            "mediaType": {"const": "image/jpeg"},
            "model": {"const": config.model()},
            "providerId": {"const": config.provider_id()},
            "sizeBytes": {"type": "integer", "minimum": 1},
            "width": {"type": "integer", "minimum": 1}
        },
        "required": [
            "artifactId", "digest", "height", "mediaType", "model", "providerId", "sizeBytes",
            "width"
        ]
    });
    let input_schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let output_schema_digest = sha256_digest(output_schema.to_string().as_bytes());
    let adapter_identity_digest = config.adapter_identity_digest();
    let mut descriptor = ToolDescriptor {
        tool_id: IMAGE_GENERATION_TOOL_ID.to_owned(),
        version: format!("1.0.0+{}", &adapter_identity_digest[..16]),
        input_schema,
        output_schema,
        input_schema_digest,
        output_schema_digest,
        descriptor_digest: String::new(),
        effect_class: EffectClass::NonIdempotent,
        risk_class: RiskClass::High,
        required_capabilities: vec![config.required_capability()],
        timeout: Duration::from_millis(config.timeout_ms()),
        maximum_output_bytes: config.maximum_output_bytes(),
        concurrency: ToolConcurrency::Serial,
        conflict_key_templates: vec![config.target_resource()],
        idempotency: IdempotencyClass::NonIdempotent,
        recovery: RecoveryStrategy::NeverRetry,
        executor: ExecutorKind::Builtin,
        executable_identity_digest: adapter_identity_digest,
    };
    descriptor.descriptor_digest = descriptor
        .computed_descriptor_digest()
        .map_err(|_| ImageGenerationContractError::InvalidDescriptor)?;
    descriptor
        .validate()
        .map_err(|_| ImageGenerationContractError::InvalidDescriptor)?;
    Ok(descriptor)
}

/// Strictly normalizes a model prompt and injects immutable operator-controlled dispatch fields.
///
/// Calling this on its own canonical output is idempotent, which permits safe pre-dispatch
/// revalidation of durable arguments.
///
/// # Errors
///
/// Returns [`ImageGenerationContractError::InvalidArguments`] for missing, extra, oversized, or
/// divergent data.
pub fn normalize_image_generation_arguments(
    config: &ImageGenerationConfig,
    arguments: &Value,
) -> Result<Value, ImageGenerationContractError> {
    config.validate()?;
    let object = arguments
        .as_object()
        .ok_or(ImageGenerationContractError::InvalidArguments)?;
    let prompt = object
        .get("prompt")
        .and_then(Value::as_str)
        .ok_or(ImageGenerationContractError::InvalidArguments)?;
    if prompt.is_empty()
        || prompt.len() > IMAGE_GENERATION_MAXIMUM_PROMPT_BYTES
        || prompt.trim() != prompt
        || prompt
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(ImageGenerationContractError::InvalidArguments);
    }
    let mut canonical = image_generation_dispatch_constraints(config);
    canonical.insert("prompt".to_owned(), Value::String(prompt.to_owned()));
    let canonical = Value::Object(canonical);
    if object.len() == 1 && object.contains_key("prompt") || arguments == &canonical {
        Ok(canonical)
    } else {
        Err(ImageGenerationContractError::InvalidArguments)
    }
}

/// Evaluates one exact configured image generator and requires owner approval on every match.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn evaluate_image_generation_policy(
    request: &PolicyRequest,
    grant: &ImageGenerationPolicyGrant,
) -> PolicyEvaluation {
    let deny = |explanation: &str| PolicyEvaluation {
        decision: PolicyDecision::Deny,
        obligations: denied_obligations(request.requested_profile),
        policy_version: request.policy_version.clone(),
        explanation: explanation.to_owned(),
    };
    if request.validate().is_err() || grant.validate().is_err() {
        return deny("invalid_image_generation_request");
    }
    if request.principal_id != grant.principal_id
        || request.channel_binding_id != grant.channel_binding_id
        || request.task_id != grant.task_id
        || request.run_id != grant.run_id
    {
        return deny("image_generation_owner_or_run_not_granted");
    }
    if request.evaluated_at_ms < grant.valid_from_ms
        || request.evaluated_at_ms >= grant.expires_at_ms
    {
        return deny("image_generation_grant_not_current");
    }
    let expected_secrets = grant.secret_reference.iter().cloned().collect::<Vec<_>>();
    let arguments = request.normalized_arguments.as_object();
    let arguments_valid = arguments.is_some_and(|arguments| {
        let constraints = json!({
            "maximumCostMicrounits": arguments.get("maximumCostMicrounits"),
            "model": arguments.get("model"),
            "outputFormat": arguments.get("outputFormat"),
            "quality": arguments.get("quality"),
            "size": arguments.get("size"),
        });
        arguments.len() == 6
            && arguments
                .get("prompt")
                .and_then(Value::as_str)
                .is_some_and(|prompt| {
                    !prompt.is_empty()
                        && prompt.len() <= IMAGE_GENERATION_MAXIMUM_PROMPT_BYTES
                        && prompt.trim() == prompt
                })
            && arguments
                .get("maximumCostMicrounits")
                .and_then(Value::as_u64)
                .is_some_and(|cost| cost > 0)
            && arguments.get("model").and_then(Value::as_str).is_some()
            && arguments.get("size").and_then(Value::as_str).is_some()
            && arguments.get("quality").and_then(Value::as_str).is_some()
            && arguments.get("outputFormat").and_then(Value::as_str) == Some("jpeg")
            && sha256_digest(constraints.to_string().as_bytes())
                == grant.dispatch_constraints_digest
    });
    if !arguments_valid
        || request.agent_role != "assistant"
        || request.policy_version != IMAGE_GENERATION_POLICY_VERSION
        || request.task_risk != RiskClass::High
        || request.tool.tool_id != IMAGE_GENERATION_TOOL_ID
        || request.tool.effect_class != EffectClass::NonIdempotent
        || request.tool.risk_class != RiskClass::High
        || request.tool.idempotency != IdempotencyClass::NonIdempotent
        || request.tool.recovery != RecoveryStrategy::NeverRetry
        || request.tool.executor != ExecutorKind::Builtin
        || request.tool.descriptor_digest != grant.tool_descriptor_digest
        || request.tool.executable_identity_digest != grant.adapter_identity_digest
        || request.tool.required_capabilities != [grant.capability.clone()]
        || request.target_resources != [grant.target_resource.clone()]
        || !request.workspace_roots.is_empty()
        || request.resource_claims
            != [format!(
                "image-generation:{}",
                grant.target_resource.as_str()
            )]
        || request.secret_references != expected_secrets
        || request.network_destinations != [grant.network_destination.clone()]
        || request.requested_capability != grant.capability
        || request.requested_profile != PolicyProfile::ServiceOperator
        || request.enforceable_profiles != [PolicyProfile::ServiceOperator]
    {
        return deny("no_matching_image_generation_rule");
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
            secret_references: expected_secrets,
            argument_rewrite: None,
            redactions: Vec::new(),
            maximum_duration_ms: u64::try_from(request.tool.timeout.as_millis())
                .unwrap_or(u64::MAX),
            maximum_output_bytes: request.tool.maximum_output_bytes,
            maximum_memory_bytes: 256 * 1024 * 1024,
            maximum_processes: 1,
            validator_required: true,
        },
        policy_version: IMAGE_GENERATION_POLICY_VERSION.to_owned(),
        explanation: IMAGE_GENERATION_APPROVAL_EXPLANATION.to_owned(),
    }
}

/// Constructs the immutable approval subject for one exact image-generation request.
///
/// # Errors
///
/// Returns [`ImageGenerationContractError`] for divergent policy, authority, or expiry evidence.
pub fn image_generation_approval_subject(
    effect_id: EffectId,
    request: &PolicyRequest,
    grant: &ImageGenerationPolicyGrant,
    expires_at_ms: i64,
) -> Result<ApprovalSubject, ImageGenerationContractError> {
    if evaluate_image_generation_policy(request, grant).decision != PolicyDecision::RequireApproval
        || expires_at_ms <= request.evaluated_at_ms
        || expires_at_ms > grant.expires_at_ms
    {
        return Err(ImageGenerationContractError::InvalidApproval);
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
        policy_version: IMAGE_GENERATION_POLICY_VERSION.to_owned(),
        expires_at_ms,
    };
    subject.validate()?;
    Ok(subject)
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

fn image_generation_dispatch_constraints(
    config: &ImageGenerationConfig,
) -> serde_json::Map<String, Value> {
    serde_json::Map::from_iter([
        (
            "maximumCostMicrounits".to_owned(),
            Value::from(config.maximum_cost_microunits()),
        ),
        ("model".to_owned(), Value::from(config.model())),
        ("outputFormat".to_owned(), Value::from("jpeg")),
        ("quality".to_owned(), Value::from(config.quality())),
        ("size".to_owned(), Value::from(config.size())),
    ])
}

fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Invalid image-generation configuration, arguments, policy, or approval evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ImageGenerationContractError {
    /// Non-secret adapter configuration is unsafe or non-canonical.
    #[error("image-generation configuration is invalid")]
    InvalidConfiguration,
    /// Model-supplied arguments are missing, oversized, divergent, or contain extra authority.
    #[error("image-generation arguments are invalid")]
    InvalidArguments,
    /// Generic tool descriptor evidence could not be constructed safely.
    #[error("image-generation descriptor is invalid")]
    InvalidDescriptor,
    /// Reconstructed runtime authority is invalid.
    #[error("image-generation policy grant is invalid")]
    InvalidGrant,
    /// Policy, request, grant, or expiry does not match the approval subject.
    #[error("image-generation approval evidence is invalid")]
    InvalidApproval,
    /// Generic approval evidence is malformed.
    #[error(transparent)]
    Approval(#[from] ApprovalSubjectError),
}

#[cfg(test)]
mod tests {
    use super::{
        IMAGE_GENERATION_POLICY_VERSION, ImageGenerationConfig, ImageGenerationContractError,
        ImageGenerationPolicyGrant, ImageGenerationProtocol, evaluate_image_generation_policy,
        image_generation_approval_subject, image_generation_tool_descriptor,
        normalize_image_generation_arguments,
    };
    use crate::{
        OwnershipContext, PolicyDecision, PolicyRequest, ProviderCredentialReference,
        canonical_arguments_digest,
    };
    use mealy_domain::{ChannelBindingId, EffectId, PolicyProfile, PrincipalId, RunId, TaskId};
    use serde_json::json;

    fn config(protocol: ImageGenerationProtocol) -> ImageGenerationConfig {
        ImageGenerationConfig {
            provider_id: "images-primary".to_owned(),
            protocol,
            base_url: match protocol {
                ImageGenerationProtocol::OpenAiImages => "https://api.openai.com/v1".to_owned(),
                ImageGenerationProtocol::OpenRouterImages => {
                    "https://openrouter.ai/api/v1".to_owned()
                }
            },
            model: "example/image-model".to_owned(),
            credential: Some(ProviderCredentialReference::Broker {
                secret_id: "images-primary".to_owned(),
            }),
            residency: "remote".to_owned(),
            size: "1024x1024".to_owned(),
            quality: "low".to_owned(),
            maximum_cost_microunits: 50_000,
            maximum_output_bytes: 2 * 1024 * 1024,
            timeout_ms: 120_000,
        }
    }

    #[test]
    fn configuration_pins_distinct_endpoints_and_rejects_ambient_remote_authority() {
        let openai = config(ImageGenerationProtocol::OpenAiImages);
        assert_eq!(
            openai.endpoint().expect("OpenAI endpoint"),
            "https://api.openai.com/v1/images/generations"
        );
        let openrouter = config(ImageGenerationProtocol::OpenRouterImages);
        assert_eq!(
            openrouter.endpoint().expect("OpenRouter endpoint"),
            "https://openrouter.ai/api/v1/images"
        );
        let mut missing_credential = openai;
        missing_credential.credential = None;
        assert_eq!(
            missing_credential.validate(),
            Err(ImageGenerationContractError::InvalidConfiguration)
        );
    }

    #[test]
    fn normalization_injects_operator_bounds_and_is_idempotent() {
        let config = config(ImageGenerationProtocol::OpenAiImages);
        let normalized =
            normalize_image_generation_arguments(&config, &json!({"prompt": "A quiet harbor"}))
                .expect("normalize prompt");
        assert_eq!(normalized["model"], json!("example/image-model"));
        assert_eq!(normalized["maximumCostMicrounits"], json!(50_000));
        assert_eq!(normalized["outputFormat"], json!("jpeg"));
        assert_eq!(
            normalize_image_generation_arguments(&config, &normalized)
                .expect("revalidate canonical arguments"),
            normalized
        );
        assert!(
            normalize_image_generation_arguments(
                &config,
                &json!({"prompt": "A quiet harbor", "quality": "high"})
            )
            .is_err()
        );
    }

    #[test]
    fn policy_and_approval_bind_exact_adapter_cost_and_prompt() {
        let config = config(ImageGenerationProtocol::OpenRouterImages);
        let descriptor = image_generation_tool_descriptor(&config).expect("descriptor");
        let ownership = OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new());
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let arguments =
            normalize_image_generation_arguments(&config, &json!({"prompt": "A quiet harbor"}))
                .expect("arguments");
        let grant = ImageGenerationPolicyGrant {
            principal_id: ownership.principal_id(),
            channel_binding_id: ownership.channel_binding_id(),
            task_id,
            run_id,
            tool_descriptor_digest: descriptor.descriptor_digest.clone(),
            adapter_identity_digest: config.adapter_identity_digest(),
            dispatch_constraints_digest: config.dispatch_constraints_digest(),
            capability: config.required_capability(),
            target_resource: config.target_resource(),
            network_destination: config
                .capability_network_destination()
                .expect("destination"),
            secret_reference: config.capability_secret_reference(),
            valid_from_ms: 1_000,
            expires_at_ms: 10_000,
        };
        let request = PolicyRequest {
            principal_id: ownership.principal_id(),
            channel_binding_id: ownership.channel_binding_id(),
            task_id,
            run_id,
            agent_role: "assistant".to_owned(),
            task_risk: descriptor.risk_class,
            tool: descriptor,
            normalized_arguments: arguments.clone(),
            target_resources: vec![config.target_resource()],
            workspace_roots: Vec::new(),
            resource_claims: vec![format!("image-generation:{}", config.target_resource())],
            secret_references: config.capability_secret_reference().into_iter().collect(),
            network_destinations: vec![
                config
                    .capability_network_destination()
                    .expect("destination"),
            ],
            requested_capability: config.required_capability(),
            requested_profile: PolicyProfile::ServiceOperator,
            enforceable_profiles: vec![PolicyProfile::ServiceOperator],
            evaluated_at_ms: 1_000,
            policy_version: IMAGE_GENERATION_POLICY_VERSION.to_owned(),
        };
        assert_eq!(
            evaluate_image_generation_policy(&request, &grant).decision,
            PolicyDecision::RequireApproval
        );
        let subject = image_generation_approval_subject(EffectId::new(), &request, &grant, 9_000)
            .expect("approval");
        assert_eq!(
            subject.canonical_arguments_digest,
            canonical_arguments_digest(&arguments)
        );

        let mut changed = request;
        changed.normalized_arguments["maximumCostMicrounits"] = json!(50_001);
        assert_eq!(
            evaluate_image_generation_policy(&changed, &grant).decision,
            PolicyDecision::Deny
        );
    }
}
