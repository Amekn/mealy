use crate::{estimate_tokens, is_sha256_digest, sha256_digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use mealy_domain::{ArtifactId, AttemptId, ContextManifestId, RunId};
use serde::{Deserialize, Serialize};
use std::{cmp::Reverse, collections::BTreeSet};
use thiserror::Error;

/// Conservative allowance for provider-side HTTP message framing, tool schemas, and tokenizer
/// variance that are not part of Mealy's normalized context estimate.
pub const DIRECT_PROVIDER_INPUT_TOKEN_OVERHEAD: u64 = 2_048;
/// Maximum number of normalized image inputs in one provider request.
pub const MAXIMUM_PROVIDER_IMAGE_INPUTS: usize = 4;
/// Maximum decoded bytes in one normalized image input.
pub const MAXIMUM_PROVIDER_IMAGE_INPUT_BYTES: usize = 2 * 1024 * 1024;
/// Maximum aggregate decoded image bytes in one normalized provider request.
pub const MAXIMUM_PROVIDER_IMAGE_INPUT_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum width or height of one canonical normalized image.
pub const MAXIMUM_PROVIDER_IMAGE_DIMENSION: u32 = 2_048;
/// Conservative provider-neutral token reservation for one low-detail normalized image.
///
/// The first image contract deliberately requests `OpenAI` `low` detail. This ceiling also exceeds
/// `Anthropic`'s documented high-resolution visual-token cap, leaving room for provider framing
/// without pretending that encoded byte size predicts vision-token usage.
pub const PROVIDER_IMAGE_INPUT_TOKEN_RESERVATION: u64 = 8_192;

const MAXIMUM_PROVIDER_IMAGE_BASE64_BYTES: usize =
    MAXIMUM_PROVIDER_IMAGE_INPUT_BYTES.div_ceil(3) * 4;

/// Exact configured provider/model identity selected for a future turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderSelection {
    /// Stable configured provider adapter identity.
    pub provider_id: String,
    /// Exact configured model identity.
    pub model_id: String,
}

impl ProviderSelection {
    /// Returns whether both identities are bounded, printable, and safe to persist or render.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        valid_provider_selection_label(&self.provider_id, 128)
            && valid_provider_selection_label(&self.model_id, 128)
    }
}

/// How one input resolves its provider/model at the atomic admission boundary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ProviderSelectionPreference {
    /// Resolve the session's current exact default, or automatic routing when it has none.
    #[default]
    InheritSession,
    /// Explicitly use the compatible automatic route for this new turn.
    Automatic,
    /// Pin this exact configured provider and model for this new turn.
    Exact(ProviderSelection),
}

impl ProviderSelectionPreference {
    /// Stable evidence spelling persisted with the admitted input.
    #[must_use]
    pub const fn source(&self) -> &'static str {
        match self {
            Self::InheritSession => "inherited",
            Self::Automatic => "automatic",
            Self::Exact(_) => "exact",
        }
    }

    /// Returns whether an exact requested selection is structurally safe.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match self {
            Self::InheritSession | Self::Automatic => true,
            Self::Exact(selection) => selection.is_valid(),
        }
    }
}

fn valid_provider_selection_label(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Versioned capability contract used for routing and request validation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCapabilities {
    /// Contract schema version.
    pub contract_version: String,
    /// Stable provider adapter identity.
    pub provider_id: String,
    /// Stable model identity.
    pub model_id: String,
    /// Normalized accepted input modalities such as `text` or `image`.
    pub input_modalities: BTreeSet<String>,
    /// Maximum normalized input tokens.
    pub context_tokens: u64,
    /// Maximum normalized generated tokens.
    pub maximum_output_tokens: u64,
    /// Conservative provider-owned input tokens added outside normalized Mealy context.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub input_token_overhead: u64,
    /// Whether normalized tool calls are supported.
    pub tool_calling: bool,
    /// Whether structured JSON outputs are supported.
    pub structured_output: bool,
    /// Supported normalized reasoning-control names.
    pub reasoning_controls: BTreeSet<String>,
    /// Whether the adapter can emit transient deltas.
    pub streaming: bool,
    /// Data-residency classification used by routing policy.
    pub residency: String,
    /// Whether this provider is local to the daemon boundary.
    pub local: bool,
    /// Provider price snapshot used by deterministic routing.
    pub pricing: ProviderPricing,
    /// Maximum simultaneous requests supported by this adapter instance.
    pub maximum_concurrent_requests: u64,
    /// Configured request-rate ceiling per minute.
    pub requests_per_minute: u64,
    /// Whether normalized errors may carry a downstream retry-after hint.
    pub retry_after_hints: bool,
}

/// Provider-neutral immutable pricing snapshot.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderPricing {
    /// Input-token price per one million tokens in configured currency microunits.
    pub input_microunits_per_million_tokens: u64,
    /// Output-token price per one million tokens in configured currency microunits.
    pub output_microunits_per_million_tokens: u64,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// One health/latency/trust-qualified routing candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRouteCandidate {
    /// Immutable adapter capability snapshot.
    pub capabilities: ProviderCapabilities,
    /// Current deterministic health state.
    pub available: bool,
    /// Bounded recent latency estimate.
    pub estimated_latency_ms: u64,
    /// Monotonic trust tier; fallback may never decrease it.
    pub trust_tier: u8,
}

/// Owner/policy constraints for deterministic provider routing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRoutingPolicy {
    /// Required normalized input modalities.
    pub required_input_modalities: BTreeSet<String>,
    /// Tool-call capability requirement.
    pub tool_calling: CapabilityRequirement,
    /// Structured-output capability requirement.
    pub structured_output: CapabilityRequirement,
    /// Required reasoning control, when any.
    pub required_reasoning_control: Option<String>,
    /// Allowed residency classifications.
    pub allowed_residencies: BTreeSet<String>,
    /// Permitted provider locality.
    pub locality: ProviderLocality,
    /// Maximum accepted input-token unit price.
    pub maximum_input_microunits_per_million_tokens: u64,
    /// Maximum accepted output-token unit price.
    pub maximum_output_microunits_per_million_tokens: u64,
    /// Maximum accepted latency estimate.
    pub maximum_latency_ms: u64,
    /// Minimum provider trust tier.
    pub minimum_trust_tier: u8,
    /// Ordered owner preference; omitted providers follow deterministic cost/latency ordering.
    pub preferred_provider_ids: Vec<String>,
    /// Explicit fallback policy.
    pub fallback: ProviderFallbackPolicy,
}

/// Whether a provider capability is optional or required by a route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityRequirement {
    /// The route does not depend on this capability.
    Optional,
    /// Every selected provider must expose this capability.
    Required,
}

/// Locality boundary accepted by a provider route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLocality {
    /// Any provider allowed by residency and trust policy may be selected.
    Any,
    /// Only providers inside the daemon's local trust boundary may be selected.
    LocalOnly,
}

/// Explicit provider fallback behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFallbackPolicy {
    /// Return a primary route only.
    Disabled,
    /// Return compatible fallbacks whose trust is no lower than the primary route.
    SameOrHigherTrust,
}

/// Deterministic primary route and explicitly authorized fallbacks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRoutePlan {
    /// Selected primary adapter/model snapshot.
    pub primary: ProviderRouteCandidate,
    /// Ordered compatible fallback candidates, empty unless policy explicitly allows fallback.
    pub fallbacks: Vec<ProviderRouteCandidate>,
    /// Stable owner-inspectable routing explanation.
    pub explanation: String,
}

/// Provider routing policy or candidate failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderRoutingError {
    /// Policy is empty, unbounded, or contradictory.
    #[error("provider routing policy is invalid")]
    InvalidPolicy,
    /// No healthy provider satisfies capability, privacy, cost, latency, and trust constraints.
    #[error("no provider satisfies the routing policy")]
    NoCompatibleProvider,
}

/// Selects a deterministic provider route without silently weakening privacy or tool semantics.
///
/// # Errors
///
/// Returns [`ProviderRoutingError`] for invalid policy or no compatible healthy candidate.
pub fn route_provider(
    policy: &ProviderRoutingPolicy,
    candidates: impl IntoIterator<Item = ProviderRouteCandidate>,
) -> Result<ProviderRoutePlan, ProviderRoutingError> {
    if policy.required_input_modalities.is_empty()
        || policy.allowed_residencies.is_empty()
        || policy.maximum_latency_ms == 0
        || policy.preferred_provider_ids.len() > 256
        || policy
            .preferred_provider_ids
            .iter()
            .any(|value| value.is_empty() || value.len() > 128)
    {
        return Err(ProviderRoutingError::InvalidPolicy);
    }
    let mut compatible = candidates
        .into_iter()
        .filter(|candidate| candidate_matches(policy, candidate))
        .collect::<Vec<_>>();
    compatible.sort_by_key(|candidate| {
        let preference = policy
            .preferred_provider_ids
            .iter()
            .position(|provider| provider == &candidate.capabilities.provider_id)
            .unwrap_or(usize::MAX);
        (
            preference,
            Reverse(candidate.capabilities.local),
            candidate
                .capabilities
                .pricing
                .input_microunits_per_million_tokens
                .saturating_add(
                    candidate
                        .capabilities
                        .pricing
                        .output_microunits_per_million_tokens,
                ),
            candidate.estimated_latency_ms,
            Reverse(candidate.trust_tier),
            candidate.capabilities.provider_id.clone(),
            candidate.capabilities.model_id.clone(),
        )
    });
    let primary = compatible
        .first()
        .cloned()
        .ok_or(ProviderRoutingError::NoCompatibleProvider)?;
    let fallbacks = if policy.fallback == ProviderFallbackPolicy::SameOrHigherTrust {
        compatible
            .into_iter()
            .skip(1)
            .filter(|candidate| candidate.trust_tier >= primary.trust_tier)
            .collect()
    } else {
        Vec::new()
    };
    Ok(ProviderRoutePlan {
        explanation: format!(
            "selected {}@{} within capability, residency, locality, trust, cost, and latency policy; fallback={}",
            primary.capabilities.provider_id,
            primary.capabilities.model_id,
            policy.fallback == ProviderFallbackPolicy::SameOrHigherTrust,
        ),
        primary,
        fallbacks,
    })
}

fn candidate_matches(policy: &ProviderRoutingPolicy, candidate: &ProviderRouteCandidate) -> bool {
    let capabilities = &candidate.capabilities;
    candidate.available
        && candidate.trust_tier >= policy.minimum_trust_tier
        && (policy.locality == ProviderLocality::Any || capabilities.local)
        && policy.allowed_residencies.contains(&capabilities.residency)
        && policy
            .required_input_modalities
            .is_subset(&capabilities.input_modalities)
        && (policy.tool_calling == CapabilityRequirement::Optional || capabilities.tool_calling)
        && (policy.structured_output == CapabilityRequirement::Optional
            || capabilities.structured_output)
        && policy
            .required_reasoning_control
            .as_ref()
            .is_none_or(|control| capabilities.reasoning_controls.contains(control))
        && capabilities.pricing.input_microunits_per_million_tokens
            <= policy.maximum_input_microunits_per_million_tokens
        && capabilities.pricing.output_microunits_per_million_tokens
            <= policy.maximum_output_microunits_per_million_tokens
        && candidate.estimated_latency_ms <= policy.maximum_latency_ms
        && capabilities.context_tokens > capabilities.input_token_overhead
        && capabilities.maximum_output_tokens != 0
        && capabilities.maximum_concurrent_requests != 0
        && capabilities.requests_per_minute != 0
}

/// Provider-neutral message role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    /// Versioned baseline instructions.
    System,
    /// Authenticated session input.
    User,
    /// Final assistant output carried into a later attempt.
    Assistant,
    /// Recorded read-only tool observation.
    Tool,
}

/// Provider-neutral message supplied by a context manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedMessage {
    /// Semantic role.
    pub role: MessageRole,
    /// Bounded UTF-8 content.
    pub content: String,
    /// Ordered owner-selected image artifacts; permitted only on authenticated user messages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<NormalizedImageInput>,
    /// Tool call whose observation this message carries, when applicable.
    pub tool_call_id: Option<String>,
}

/// One content-addressed, provider-neutral image carried by an authenticated user message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedImageInput {
    artifact_id: ArtifactId,
    media_type: String,
    sha256_digest: String,
    size_bytes: u64,
    data_base64: String,
}

impl NormalizedImageInput {
    /// Constructs one bounded normalized image from metadata-stripped bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderImageInputError`] when the media type, byte count, signature, or encoded
    /// representation is outside Mealy's provider-neutral image contract.
    pub fn new(
        artifact_id: ArtifactId,
        media_type: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Self, ProviderImageInputError> {
        let media_type = media_type.into();
        validate_image_bytes(&media_type, bytes)?;
        let image = Self {
            artifact_id,
            media_type,
            sha256_digest: sha256_digest(bytes),
            size_bytes: u64::try_from(bytes.len())
                .map_err(|_| ProviderImageInputError::InvalidContract)?,
            data_base64: BASE64_STANDARD.encode(bytes),
        };
        image.validated_bytes()?;
        Ok(image)
    }

    /// Canonical owner-scoped artifact identity.
    #[must_use]
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
    }

    /// Exact supported image media type.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Digest of the exact normalized image bytes.
    #[must_use]
    pub fn sha256_digest(&self) -> &str {
        &self.sha256_digest
    }

    /// Exact decoded byte count.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Conservative provider-neutral input-token reservation for this image.
    #[must_use]
    pub const fn token_reservation(&self) -> u64 {
        PROVIDER_IMAGE_INPUT_TOKEN_RESERVATION
    }

    /// Canonical standard-base64 provider payload without a data-URL prefix.
    #[must_use]
    pub fn data_base64(&self) -> &str {
        &self.data_base64
    }

    /// Decodes and revalidates durable image evidence before provider serialization.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderImageInputError`] for malformed base64, unsupported media, byte/digest
    /// drift, or a value outside the normalized bounds.
    pub fn validated_bytes(&self) -> Result<Vec<u8>, ProviderImageInputError> {
        if !is_sha256_digest(&self.sha256_digest)
            || self.data_base64.is_empty()
            || self.data_base64.len() > MAXIMUM_PROVIDER_IMAGE_BASE64_BYTES
        {
            return Err(ProviderImageInputError::InvalidContract);
        }
        let bytes = BASE64_STANDARD
            .decode(&self.data_base64)
            .map_err(|_| ProviderImageInputError::InvalidContract)?;
        validate_image_bytes(&self.media_type, &bytes)?;
        if u64::try_from(bytes.len()).ok() != Some(self.size_bytes)
            || sha256_digest(&bytes) != self.sha256_digest
            || BASE64_STANDARD.encode(&bytes) != self.data_base64
        {
            return Err(ProviderImageInputError::InvalidContract);
        }
        Ok(bytes)
    }
}

/// Invalid normalized image input or provider modality selection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderImageInputError {
    /// Image evidence, count, media type, signature, encoding, digest, or placement is invalid.
    #[error("normalized provider image input is invalid")]
    InvalidContract,
    /// The selected provider/model did not explicitly advertise image input.
    #[error("selected provider does not support normalized image input")]
    UnsupportedModality,
}

/// Revalidates all normalized image evidence before a provider reserves or dispatches work.
///
/// # Errors
///
/// Returns [`ProviderImageInputError`] for unsupported modality, non-user placement, invalid image
/// evidence, or request-level count and aggregate byte bounds.
pub fn validate_provider_image_inputs(
    request: &ProviderRequest,
    capabilities: &ProviderCapabilities,
) -> Result<(), ProviderImageInputError> {
    let image_count = request
        .messages
        .iter()
        .map(|message| message.images.len())
        .sum::<usize>();
    if image_count == 0 {
        return Ok(());
    }
    if image_count > MAXIMUM_PROVIDER_IMAGE_INPUTS {
        return Err(ProviderImageInputError::InvalidContract);
    }
    if !capabilities.input_modalities.contains("image") {
        return Err(ProviderImageInputError::UnsupportedModality);
    }
    let mut total_bytes = 0_usize;
    for message in &request.messages {
        if !message.images.is_empty() && message.role != MessageRole::User {
            return Err(ProviderImageInputError::InvalidContract);
        }
        for image in &message.images {
            let bytes = image.validated_bytes()?;
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or(ProviderImageInputError::InvalidContract)?;
            if total_bytes > MAXIMUM_PROVIDER_IMAGE_INPUT_TOTAL_BYTES {
                return Err(ProviderImageInputError::InvalidContract);
            }
        }
    }
    let normalized_input_tokens = request
        .messages
        .iter()
        .try_fold(0_u64, |total, message| {
            total.checked_add(estimate_normalized_message_tokens(message))
        })
        .and_then(|total| total.checked_add(capabilities.input_token_overhead))
        .ok_or(ProviderImageInputError::InvalidContract)?;
    if normalized_input_tokens > capabilities.context_tokens {
        return Err(ProviderImageInputError::InvalidContract);
    }
    Ok(())
}

/// Conservatively estimates provider input tokens for normalized text and image content.
///
/// Image tokens are reserved from an explicit fixed ceiling rather than inferred from compressed
/// byte size. Provider-reported terminal usage must still fit inside the durable reservation.
#[must_use]
pub fn estimate_normalized_message_tokens(message: &NormalizedMessage) -> u64 {
    message
        .images
        .iter()
        .fold(estimate_tokens(&message.content), |total, image| {
            total.saturating_add(image.token_reservation())
        })
}

fn validate_image_bytes(media_type: &str, bytes: &[u8]) -> Result<(), ProviderImageInputError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_PROVIDER_IMAGE_INPUT_BYTES {
        return Err(ProviderImageInputError::InvalidContract);
    }
    let signature_matches = match media_type {
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]) && bytes.ends_with(&[0xff, 0xd9]),
        "image/webp" => bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP",
        _ => false,
    };
    signature_matches
        .then_some(())
        .ok_or(ProviderImageInputError::InvalidContract)
}

/// Provider-neutral tool definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderToolDefinition {
    /// Stable tool identity.
    pub tool_id: String,
    /// Tool contract version.
    pub version: String,
    /// Human-readable purpose.
    pub description: String,
    /// Normalized JSON Schema.
    pub input_schema: serde_json::Value,
    /// Digest bound into the context manifest.
    pub schema_digest: String,
}

/// Complete normalized model request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRequest {
    /// Owning run.
    pub run_id: RunId,
    /// Durable attempt allocated before dispatch.
    pub attempt_id: AttemptId,
    /// Exact committed manifest used to build `messages`.
    pub context_manifest_id: ContextManifestId,
    /// Selected provider.
    pub provider_id: String,
    /// Selected model.
    pub model_id: String,
    /// Ordered manifest-derived messages.
    pub messages: Vec<NormalizedMessage>,
    /// Allowed tool contracts.
    pub tools: Vec<ProviderToolDefinition>,
    /// Bounded output-token request.
    pub maximum_output_tokens: u64,
    /// Absolute dispatch deadline in Unix milliseconds.
    pub deadline_at_ms: i64,
}

/// Normalized provider decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderResponse {
    /// Provider completed with user-facing text.
    Final {
        /// Bounded final content.
        text: String,
    },
    /// Provider requested one validated tool invocation.
    ToolCall {
        /// Stable declared tool identity.
        tool_id: String,
        /// Provider-neutral normalized arguments.
        arguments: serde_json::Value,
    },
}

/// Normalized provider usage accounting.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelUsage {
    /// Estimated or provider-reported input tokens.
    pub input_tokens: u64,
    /// Provider-reported output tokens.
    pub output_tokens: u64,
    /// Total tokens charged to the attempt.
    pub total_tokens: u64,
    /// Cost in provider-neutral millionths of the configured currency unit.
    pub cost_microunits: u64,
}

/// Complete terminal normalized provider output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderOutput {
    /// Normalized decision.
    pub response: ProviderResponse,
    /// Stable finish classification.
    pub finish_reason: String,
    /// Usage accounting.
    pub usage: ModelUsage,
    /// Opaque downstream request ID, if supplied.
    pub provider_request_id: Option<String>,
}

/// Stable provider failure class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorClass {
    /// Request violated the normalized contract.
    #[error("invalid request")]
    InvalidRequest,
    /// Provider was unavailable before a usable response.
    #[error("provider unavailable")]
    Unavailable,
    /// Provider rate limit rejected the attempt.
    #[error("provider rate limited")]
    RateLimited,
    /// Attempt deadline elapsed.
    #[error("provider timeout")]
    Timeout,
    /// Cancellation was observed.
    #[error("provider cancelled")]
    Cancelled,
    /// Provider returned an invalid or unsupported response.
    #[error("invalid provider response")]
    InvalidResponse,
}

impl ProviderErrorClass {
    /// Stable storage and event spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unavailable => "unavailable",
            Self::RateLimited => "rate_limited",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

/// Whether a failed adapter call proved the downstream provider outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailureDisposition {
    /// The provider did not accept work or returned a definite terminal response.
    Known,
    /// Dispatch crossed the network boundary without a provable terminal response.
    OutcomeUnknown,
}

/// Normalized provider failure with retry guidance.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{class}: {message}")]
pub struct ProviderError {
    /// Stable class.
    pub class: ProviderErrorClass,
    /// Redacted bounded detail.
    pub message: String,
    /// Whether retry under the same residency/tool policy may succeed.
    pub retryable: bool,
    /// Whether retry could duplicate downstream work or hide unknown usage/cost.
    pub disposition: ProviderFailureDisposition,
}

/// Cancellation probe passed into a provider dispatch without exposing storage internals.
pub trait CancellationProbe: Send + Sync {
    /// Returns whether the current run should stop at the next safe boundary.
    fn is_cancelled(&self) -> bool;
}

/// Non-authoritative bounded progress emitted before a normalized provider result is committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderProgress {
    /// Exact UTF-8 assistant text delta received from the provider stream.
    TextDelta(String),
}

/// Best-effort progress port kept separate from canonical provider result settlement.
pub trait ProviderProgressSink: Send + Sync {
    /// Observes one provider progress item. Implementations must remain bounded and must not treat
    /// this preview as the authoritative model response.
    fn emit(&self, progress: ProviderProgress);
}

/// Provider capability and normalized-completion port.
pub trait ModelProvider: Send + Sync + 'static {
    /// Returns the immutable routing capability snapshot.
    fn capabilities(&self) -> ProviderCapabilities;

    /// Performs one bounded normalized completion.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] for classified dispatch or response failures.
    fn complete(
        &self,
        request: &ProviderRequest,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ProviderOutput, ProviderError>;

    /// Performs one bounded completion while optionally emitting non-authoritative progress.
    ///
    /// Providers without streaming support use the terminal-only implementation by default.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] for classified dispatch or response failures.
    fn complete_with_progress(
        &self,
        request: &ProviderRequest,
        cancellation: &dyn CancellationProbe,
        _progress: &dyn ProviderProgressSink,
    ) -> Result<ProviderOutput, ProviderError> {
        self.complete(request, cancellation)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityRequirement, MessageRole, NormalizedImageInput, NormalizedMessage,
        ProviderCapabilities, ProviderFallbackPolicy, ProviderImageInputError, ProviderLocality,
        ProviderPricing, ProviderRequest, ProviderRouteCandidate, ProviderRoutingPolicy,
        route_provider, validate_provider_image_inputs,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use mealy_domain::{ArtifactId, AttemptId, ContextManifestId, RunId};
    use std::collections::BTreeSet;

    #[test]
    fn routing_enforces_capability_privacy_cost_latency_and_explicit_fallback() {
        let policy = ProviderRoutingPolicy {
            required_input_modalities: BTreeSet::from(["text".to_owned()]),
            tool_calling: CapabilityRequirement::Required,
            structured_output: CapabilityRequirement::Required,
            required_reasoning_control: Some("none".to_owned()),
            allowed_residencies: BTreeSet::from(["local".to_owned(), "trusted-region".to_owned()]),
            locality: ProviderLocality::Any,
            maximum_input_microunits_per_million_tokens: 10,
            maximum_output_microunits_per_million_tokens: 20,
            maximum_latency_ms: 500,
            minimum_trust_tier: 5,
            preferred_provider_ids: vec!["primary".to_owned()],
            fallback: ProviderFallbackPolicy::SameOrHigherTrust,
        };
        let primary = candidate("primary", "local", true, 7, 50, 2);
        let trusted_fallback = candidate("fallback", "trusted-region", false, 7, 100, 1);
        let less_trusted = candidate("less-trusted", "trusted-region", false, 6, 40, 0);
        let unavailable = ProviderRouteCandidate {
            available: false,
            ..candidate("unavailable", "local", true, 9, 1, 0)
        };
        let plan = route_provider(
            &policy,
            [
                less_trusted,
                trusted_fallback.clone(),
                unavailable,
                primary.clone(),
            ],
        )
        .expect("route");
        assert_eq!(plan.primary, primary);
        assert_eq!(plan.fallbacks, vec![trusted_fallback]);

        let no_fallback = ProviderRoutingPolicy {
            fallback: ProviderFallbackPolicy::Disabled,
            ..policy
        };
        let plan = route_provider(
            &no_fallback,
            [
                candidate("primary", "local", true, 7, 50, 2),
                candidate("fallback", "trusted-region", false, 7, 100, 1),
            ],
        )
        .expect("primary-only route");
        assert!(plan.fallbacks.is_empty());
    }

    #[test]
    fn normalized_image_input_is_content_bound_user_only_and_modality_gated() {
        let bytes = BASE64_STANDARD
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC")
            .expect("one-pixel PNG");
        let image =
            NormalizedImageInput::new(ArtifactId::new(), "image/png", &bytes).expect("image");
        assert_eq!(image.validated_bytes().expect("validated"), bytes);
        let mut corrupt_digest = image.clone();
        corrupt_digest.sha256_digest = "0".repeat(64);
        assert_eq!(
            corrupt_digest.validated_bytes(),
            Err(ProviderImageInputError::InvalidContract)
        );
        let mut corrupt_size = image.clone();
        corrupt_size.size_bytes = corrupt_size.size_bytes.saturating_add(1);
        assert_eq!(
            corrupt_size.validated_bytes(),
            Err(ProviderImageInputError::InvalidContract)
        );
        let mut corrupt_payload = image.clone();
        corrupt_payload.data_base64.replace_range(..4, "AAAA");
        assert_eq!(
            corrupt_payload.validated_bytes(),
            Err(ProviderImageInputError::InvalidContract)
        );
        let mut request = ProviderRequest {
            run_id: RunId::new(),
            attempt_id: AttemptId::new(),
            context_manifest_id: ContextManifestId::new(),
            provider_id: "vision".to_owned(),
            model_id: "vision-model".to_owned(),
            messages: vec![NormalizedMessage {
                role: MessageRole::User,
                content: "Describe this image.".to_owned(),
                images: vec![image.clone()],
                tool_call_id: None,
            }],
            tools: Vec::new(),
            maximum_output_tokens: 128,
            deadline_at_ms: 1,
        };
        let mut capabilities = candidate("vision", "local", true, 7, 50, 0).capabilities;
        assert_eq!(
            validate_provider_image_inputs(&request, &capabilities),
            Err(ProviderImageInputError::UnsupportedModality)
        );
        capabilities.input_modalities.insert("image".to_owned());
        assert_eq!(
            validate_provider_image_inputs(&request, &capabilities),
            Err(ProviderImageInputError::InvalidContract)
        );
        capabilities.context_tokens = 16_384;
        validate_provider_image_inputs(&request, &capabilities).expect("image-capable route");

        request.messages[0].role = MessageRole::Assistant;
        assert_eq!(
            validate_provider_image_inputs(&request, &capabilities),
            Err(ProviderImageInputError::InvalidContract)
        );
        request.messages[0].role = MessageRole::User;
        request.messages[0].images = vec![image; 5];
        assert_eq!(
            validate_provider_image_inputs(&request, &capabilities),
            Err(ProviderImageInputError::InvalidContract)
        );

        let legacy = serde_json::from_value::<NormalizedMessage>(serde_json::json!({
            "role": "user",
            "content": "legacy text",
            "toolCallId": null
        }))
        .expect("legacy message");
        assert!(legacy.images.is_empty());
    }

    fn candidate(
        provider_id: &str,
        residency: &str,
        local: bool,
        trust_tier: u8,
        latency_ms: u64,
        price: u64,
    ) -> ProviderRouteCandidate {
        ProviderRouteCandidate {
            capabilities: ProviderCapabilities {
                contract_version: "mealy.provider.v1".to_owned(),
                provider_id: provider_id.to_owned(),
                model_id: "model".to_owned(),
                input_modalities: BTreeSet::from(["text".to_owned()]),
                context_tokens: 8_192,
                maximum_output_tokens: 1_024,
                input_token_overhead: 0,
                tool_calling: true,
                structured_output: true,
                reasoning_controls: BTreeSet::from(["none".to_owned()]),
                streaming: true,
                residency: residency.to_owned(),
                local,
                pricing: ProviderPricing {
                    input_microunits_per_million_tokens: price,
                    output_microunits_per_million_tokens: price,
                },
                maximum_concurrent_requests: 2,
                requests_per_minute: 60,
                retry_after_hints: true,
            },
            available: true,
            estimated_latency_ms: latency_ms,
            trust_tier,
        }
    }
}
