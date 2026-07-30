use crate::{
    ApprovalSubject, ApprovalSubjectError, McpOAuthTokenGrant, PolicyDecision, PolicyEvaluation,
    PolicyObligations, PolicyRequest, ProviderCredentialReference, ReadToolDescriptor,
    ReadToolError, ToolConcurrency, ToolDescriptor, canonical_arguments_digest, is_sha256_digest,
    sha256_digest,
};
use mealy_domain::{
    ChannelBindingId, EffectClass, EffectId, ExecutorKind, IdempotencyClass, PolicyProfile,
    PrincipalId, RecoveryStrategy, RiskClass, RunId, TaskId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr, path::Path, time::Duration};
use thiserror::Error;
use url::Url;

/// Exact MCP protocol revision implemented by Mealy's local stdio client.
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
/// Maximum owner-reviewed tools exposed from one configured MCP server.
pub const MCP_MAXIMUM_TOOLS_PER_SERVER: usize = 64;
/// Maximum resources retained in one complete remote catalog.
pub const MCP_MAXIMUM_RESOURCES_PER_SERVER: usize = 256;
/// Maximum resource templates retained in one complete remote catalog.
pub const MCP_MAXIMUM_RESOURCE_TEMPLATES_PER_SERVER: usize = 128;
/// Maximum prompts retained in one complete remote catalog.
pub const MCP_MAXIMUM_PROMPTS_PER_SERVER: usize = 64;
/// Maximum combined owner-selected tools, resources, and prompts exposed by one HTTP server.
pub const MCP_MAXIMUM_HTTP_GRANTS_PER_SERVER: usize = 64;
/// Maximum direct, non-secret process arguments for one configured MCP server.
pub const MCP_MAXIMUM_ARGUMENTS: usize = 64;
/// Maximum canonical bytes retained for one advertised MCP tool definition.
pub const MCP_MAXIMUM_DEFINITION_BYTES: usize = 256 * 1024;

/// Maximum independently configured local stdio MCP servers.
pub const MCP_MAXIMUM_SERVERS: usize = 16;
/// Maximum canonical bytes accepted for one Streamable HTTP endpoint.
pub const MCP_MAXIMUM_HTTP_ENDPOINT_BYTES: usize = 2_048;
const MCP_MAXIMUM_ARGUMENT_BYTES: usize = 4_096;
const MCP_MAXIMUM_ARGUMENT_TOTAL_BYTES: usize = 32 * 1024;
const MCP_MAXIMUM_OUTPUT_BYTES: u64 = 1024 * 1024;
const MCP_MAXIMUM_TOOL_ARGUMENT_BYTES: usize = 64 * 1024;
const MCP_MAXIMUM_RESOURCE_URI_BYTES: usize = 4_096;
const MCP_MAXIMUM_PROMPT_ARGUMENTS: usize = 64;
const MCP_MAXIMUM_TIMEOUT_MS: u64 = 60_000;
const MCP_MINIMUM_TIMEOUT_MS: u64 = 100;
const MCP_EFFECT_MAXIMUM_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// Exact deterministic policy bundle for owner-classified MCP effects.
pub const MCP_EFFECT_POLICY_VERSION: &str = "mealy.mcp-effect-policy.v1";
/// Stable policy explanation for a matched approval-gated MCP effect.
pub const MCP_EFFECT_APPROVAL_EXPLANATION: &str = "mcp_effect_requires_exact_owner_approval";

/// Owner-attested effect contract for one exact MCP tool definition.
///
/// MCP annotations remain untrusted discovery metadata and never select this value.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpToolEffect {
    /// The exact operation cannot mutate any external or durable state.
    #[default]
    ReadOnly,
    /// Repeating the exact operation and arguments has no additional external effect.
    Idempotent,
    /// The operation may have an additional effect when repeated.
    NonIdempotent,
}

impl McpToolEffect {
    /// Whether this grant may execute only through the durable effect ledger.
    #[must_use]
    pub const fn is_effectful(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }
}

/// Exact runtime authority reconstructed for one owner-classified MCP effect proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpEffectPolicyGrant {
    /// Authenticated owner principal.
    pub principal_id: PrincipalId,
    /// Authenticated channel binding.
    pub channel_binding_id: ChannelBindingId,
    /// Task whose immutable ceiling contains the tool.
    pub task_id: TaskId,
    /// Run proposing the effect.
    pub run_id: RunId,
    /// Complete generic descriptor digest.
    pub tool_descriptor_digest: String,
    /// Aggregate executable/transport identity from the descriptor.
    pub executable_identity_digest: String,
    /// Exact owner-attested effect class.
    pub effect: McpToolEffect,
    /// Exact descriptor capability.
    pub capability: String,
    /// Exact logical remote target.
    pub target_resource: String,
    /// Exact HTTP destination, absent for isolated stdio.
    pub network_destination: Option<String>,
    /// Exact opaque credential reference, absent when no credential is needed.
    pub secret_reference: Option<String>,
    /// First accepted evaluation instant.
    pub valid_from_ms: i64,
    /// Exclusive grant expiry.
    pub expires_at_ms: i64,
}

impl McpEffectPolicyGrant {
    fn validate(&self) -> Result<(), McpEffectPolicyError> {
        if !self.effect.is_effectful()
            || !is_sha256_digest(&self.tool_descriptor_digest)
            || !is_sha256_digest(&self.executable_identity_digest)
            || self.capability.is_empty()
            || self.capability.len() > 1_024
            || self.target_resource.is_empty()
            || self.target_resource.len() > 1_024
            || !self.target_resource.starts_with("mcp://")
            || self
                .network_destination
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 1_024)
            || self
                .secret_reference
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 1_024)
            || self.valid_from_ms < 0
            || self.expires_at_ms <= self.valid_from_ms
        {
            Err(McpEffectPolicyError::InvalidContract)
        } else {
            Ok(())
        }
    }
}

/// Deterministic MCP effect policy or approval-subject failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum McpEffectPolicyError {
    /// Request, grant, or expiry does not match the exact supported effect contract.
    #[error("MCP effect contract is invalid")]
    InvalidContract,
    /// Generic approval evidence is malformed.
    #[error(transparent)]
    Approval(#[from] ApprovalSubjectError),
}

/// One exact MCP tool definition reviewed and granted by the owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpToolGrant {
    definition: Value,
    definition_digest: String,
    #[serde(default)]
    effect: McpToolEffect,
    timeout_ms: u64,
    maximum_output_bytes: u64,
}

impl McpToolGrant {
    /// Constructs a grant from one freshly discovered, exact server definition.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when the definition, JSON Schema, timeout, or output bound is
    /// unsafe or cannot be represented by the supported MCP subset.
    pub fn new(
        definition: Value,
        timeout_ms: u64,
        maximum_output_bytes: u64,
    ) -> Result<Self, McpConfigError> {
        Self::new_with_effect(
            definition,
            McpToolEffect::ReadOnly,
            timeout_ms,
            maximum_output_bytes,
        )
    }

    /// Constructs a grant with an explicit owner-attested effect contract.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when the definition, JSON Schema, effect contract, timeout, or
    /// output bound is unsafe or cannot be represented by the supported MCP subset.
    pub fn new_with_effect(
        definition: Value,
        effect: McpToolEffect,
        timeout_ms: u64,
        maximum_output_bytes: u64,
    ) -> Result<Self, McpConfigError> {
        let definition_digest = mcp_tool_definition_digest(&definition)?;
        let grant = Self {
            definition,
            definition_digest,
            effect,
            timeout_ms,
            maximum_output_bytes,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Exact server-advertised tool definition, including otherwise untrusted annotations.
    #[must_use]
    pub const fn definition(&self) -> &Value {
        &self.definition
    }

    /// SHA-256 of the canonical complete advertised definition.
    #[must_use]
    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    /// Exact owner-attested effect contract; remote annotations cannot change it.
    #[must_use]
    pub const fn effect(&self) -> McpToolEffect {
        self.effect
    }

    /// Remote, server-local tool name.
    ///
    /// # Panics
    ///
    /// Panics only if trusted code calls this accessor on a value that has bypassed `validate`.
    /// Normal construction and configuration loading validate the complete grant first.
    #[must_use]
    pub fn remote_name(&self) -> &str {
        self.definition
            .get("name")
            .and_then(Value::as_str)
            .expect("validated MCP tool grant always has a name")
    }

    /// Bounded server description retained as untrusted model-facing metadata.
    #[must_use]
    pub fn description(&self) -> &str {
        self.definition
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("Invokes an owner-reviewed MCP tool")
    }

    /// Exact advertised input JSON Schema.
    ///
    /// # Panics
    ///
    /// Panics only if trusted code calls this accessor on a value that has bypassed `validate`.
    /// Normal construction and configuration loading validate the complete grant first.
    #[must_use]
    pub fn input_schema(&self) -> &Value {
        self.definition
            .get("inputSchema")
            .expect("validated MCP tool grant always has an input schema")
    }

    /// Per-call wall-clock ceiling.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Maximum normalized terminal result bytes.
    #[must_use]
    pub const fn maximum_output_bytes(&self) -> u64 {
        self.maximum_output_bytes
    }

    fn validate(&self) -> Result<(), McpConfigError> {
        inspect_mcp_tool_definition(&self.definition)?;
        if mcp_tool_definition_digest(&self.definition)? != self.definition_digest
            || !(MCP_MINIMUM_TIMEOUT_MS..=MCP_MAXIMUM_TIMEOUT_MS).contains(&self.timeout_ms)
            || !(1..=MCP_MAXIMUM_OUTPUT_BYTES).contains(&self.maximum_output_bytes)
        {
            return Err(McpConfigError::InvalidToolGrant);
        }
        Ok(())
    }
}

/// One exact server-advertised resource selected for bounded read access.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpResourceGrant {
    definition: Value,
    definition_digest: String,
    timeout_ms: u64,
    maximum_output_bytes: u64,
}

impl McpResourceGrant {
    /// Constructs a grant from one freshly discovered exact resource definition.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when the definition or execution bounds are invalid.
    pub fn new(
        definition: Value,
        timeout_ms: u64,
        maximum_output_bytes: u64,
    ) -> Result<Self, McpConfigError> {
        let definition_digest = mcp_resource_definition_digest(&definition)?;
        let grant = Self {
            definition,
            definition_digest,
            timeout_ms,
            maximum_output_bytes,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Exact server-advertised resource definition.
    #[must_use]
    pub const fn definition(&self) -> &Value {
        &self.definition
    }

    /// SHA-256 of the exact canonical resource definition.
    #[must_use]
    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    /// Exact server-local resource URI.
    ///
    /// # Panics
    ///
    /// Panics only if trusted code calls this accessor on a value that bypassed `validate`.
    #[must_use]
    pub fn uri(&self) -> &str {
        self.definition
            .get("uri")
            .and_then(Value::as_str)
            .expect("validated MCP resource grant always has a URI")
    }

    /// Bounded untrusted description for model-facing tool metadata.
    #[must_use]
    pub fn description(&self) -> &str {
        self.definition
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("Reads one owner-reviewed MCP resource as untrusted evidence")
    }

    /// Per-call wall-clock ceiling.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Maximum normalized terminal result bytes.
    #[must_use]
    pub const fn maximum_output_bytes(&self) -> u64 {
        self.maximum_output_bytes
    }

    fn validate(&self) -> Result<(), McpConfigError> {
        inspect_mcp_resource_definition(&self.definition)?;
        if mcp_resource_definition_digest(&self.definition)? != self.definition_digest
            || !(MCP_MINIMUM_TIMEOUT_MS..=MCP_MAXIMUM_TIMEOUT_MS).contains(&self.timeout_ms)
            || !(1..=MCP_MAXIMUM_OUTPUT_BYTES).contains(&self.maximum_output_bytes)
        {
            return Err(McpConfigError::InvalidResourceGrant);
        }
        Ok(())
    }
}

/// One exact server-advertised prompt selected for bounded retrieval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpPromptGrant {
    definition: Value,
    definition_digest: String,
    timeout_ms: u64,
    maximum_output_bytes: u64,
}

impl McpPromptGrant {
    /// Constructs a grant from one freshly discovered exact prompt definition.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when the definition or execution bounds are invalid.
    pub fn new(
        definition: Value,
        timeout_ms: u64,
        maximum_output_bytes: u64,
    ) -> Result<Self, McpConfigError> {
        let definition_digest = mcp_prompt_definition_digest(&definition)?;
        let grant = Self {
            definition,
            definition_digest,
            timeout_ms,
            maximum_output_bytes,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Exact server-advertised prompt definition.
    #[must_use]
    pub const fn definition(&self) -> &Value {
        &self.definition
    }

    /// SHA-256 of the exact canonical prompt definition.
    #[must_use]
    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    /// Exact server-local prompt name.
    ///
    /// # Panics
    ///
    /// Panics only if trusted code calls this accessor on a value that bypassed `validate`.
    #[must_use]
    pub fn remote_name(&self) -> &str {
        self.definition
            .get("name")
            .and_then(Value::as_str)
            .expect("validated MCP prompt grant always has a name")
    }

    /// Bounded untrusted description for model-facing tool metadata.
    #[must_use]
    pub fn description(&self) -> &str {
        self.definition
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("Retrieves one owner-reviewed MCP prompt as untrusted evidence")
    }

    /// Exact generated object schema for the prompt's string arguments.
    ///
    /// # Panics
    ///
    /// Panics only if trusted code calls this accessor on a value that bypassed `validate`.
    #[must_use]
    pub fn input_schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();
        for argument in self
            .definition
            .get("arguments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = argument["name"]
                .as_str()
                .expect("validated MCP prompt argument always has a name");
            let mut schema = serde_json::Map::from_iter([(
                "type".to_owned(),
                Value::String("string".to_owned()),
            )]);
            if let Some(description) = argument.get("description").and_then(Value::as_str) {
                schema.insert(
                    "description".to_owned(),
                    Value::String(description.to_owned()),
                );
            }
            properties.insert(name.to_owned(), Value::Object(schema));
            if argument
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                required.push(Value::String(name.to_owned()));
            }
        }
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": properties,
            "required": required,
            "description": self.description(),
        })
    }

    /// Per-call wall-clock ceiling.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Maximum normalized terminal result bytes.
    #[must_use]
    pub const fn maximum_output_bytes(&self) -> u64 {
        self.maximum_output_bytes
    }

    fn validate(&self) -> Result<(), McpConfigError> {
        inspect_mcp_prompt_definition(&self.definition)?;
        if mcp_prompt_definition_digest(&self.definition)? != self.definition_digest
            || !(MCP_MINIMUM_TIMEOUT_MS..=MCP_MAXIMUM_TIMEOUT_MS).contains(&self.timeout_ms)
            || !(1..=MCP_MAXIMUM_OUTPUT_BYTES).contains(&self.maximum_output_bytes)
        {
            return Err(McpConfigError::InvalidPromptGrant);
        }
        Ok(())
    }
}

/// One schema-versioned, non-secret, digest-pinned local stdio MCP server grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpServerConfig {
    server_id: String,
    executable_path: String,
    executable_digest: String,
    arguments: Vec<String>,
    toolset_digest: String,
    enabled: bool,
    tools: Vec<McpToolGrant>,
}

impl McpServerConfig {
    /// Constructs a complete owner-reviewed local stdio server configuration.
    ///
    /// `executable_path` is a private Mealy-home-relative content-addressed path. Server code is
    /// never selected through `PATH` and receives no ambient environment or network authority.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for invalid identity, executable evidence, arguments, tool
    /// definitions, ordering, or bounds.
    pub fn new(
        server_id: String,
        executable_path: String,
        executable_digest: String,
        arguments: Vec<String>,
        toolset_digest: String,
        enabled: bool,
        mut tools: Vec<McpToolGrant>,
    ) -> Result<Self, McpConfigError> {
        tools.sort_by(|left, right| left.remote_name().cmp(right.remote_name()));
        let config = Self {
            server_id,
            executable_path,
            executable_digest,
            arguments,
            toolset_digest,
            enabled,
            tools,
        };
        config.validate()?;
        Ok(config)
    }

    /// Stable logical server identity.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Private Mealy-home-relative content-addressed executable path.
    #[must_use]
    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    /// SHA-256 of the exact installed executable bytes.
    #[must_use]
    pub fn executable_digest(&self) -> &str {
        &self.executable_digest
    }

    /// Direct non-secret server arguments, with no shell or expansion.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// SHA-256 binding the negotiated protocol revision and complete advertised tool list.
    #[must_use]
    pub fn toolset_digest(&self) -> &str {
        &self.toolset_digest
    }

    /// Whether the server is activated for new context epochs.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Exact owner-reviewed tool grants in remote-name order.
    #[must_use]
    pub fn tools(&self) -> &[McpToolGrant] {
        &self.tools
    }

    /// Returns an enabled/disabled copy while preserving exact reviewed evidence.
    #[must_use]
    pub fn with_enabled(&self, enabled: bool) -> Self {
        let mut changed = self.clone();
        changed.enabled = enabled;
        changed
    }

    /// Model-visible collision-resistant tool identity for one granted remote name.
    #[must_use]
    pub fn exposed_tool_id(&self, remote_name: &str) -> String {
        format!("mcp.{}.{}", self.server_id, remote_name)
    }

    /// Validates a complete server configuration loaded from durable non-secret configuration.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for malformed or non-canonical state.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        if !valid_mcp_name(&self.server_id, 32)
            || !crate::is_sha256_digest(&self.executable_digest)
            || self.executable_path != format!("mcp-servers/{}/server", self.executable_digest)
            || !safe_relative_path(&self.executable_path)
            || !crate::is_sha256_digest(&self.toolset_digest)
            || self.arguments.len() > MCP_MAXIMUM_ARGUMENTS
            || self
                .arguments
                .iter()
                .any(|argument| invalid_argument(argument))
            || self.arguments.iter().map(String::len).sum::<usize>()
                > MCP_MAXIMUM_ARGUMENT_TOTAL_BYTES
            || self.tools.is_empty()
            || self.tools.len() > MCP_MAXIMUM_TOOLS_PER_SERVER
        {
            return Err(McpConfigError::InvalidServer);
        }
        let mut names = BTreeSet::new();
        for tool in &self.tools {
            tool.validate()?;
            if !names.insert(tool.remote_name())
                || self.exposed_tool_id(tool.remote_name()).len() > 128
            {
                return Err(McpConfigError::InvalidServer);
            }
        }
        if !self
            .tools
            .windows(2)
            .all(|window| window[0].remote_name() < window[1].remote_name())
        {
            return Err(McpConfigError::InvalidServer);
        }
        Ok(())
    }
}

/// Optional non-secret authentication reference for a Streamable HTTP MCP server.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum McpHttpAuthentication {
    /// Server requires no transport credential.
    #[default]
    None,
    /// Resolve one bearer token through the existing hardened credential broker.
    Bearer {
        /// Opaque credential reference; the token never enters configuration.
        credential: ProviderCredentialReference,
    },
    /// Resolve and rotate one audience-bound OAuth token family through its dedicated broker.
    #[serde(rename = "oauth")]
    OAuth {
        /// Non-secret immutable token-family authority; access/refresh tokens never enter config.
        grant: McpOAuthTokenGrant,
    },
}

impl McpHttpAuthentication {
    /// Returns the configured static bearer credential reference, if any.
    #[must_use]
    pub const fn credential(&self) -> Option<&ProviderCredentialReference> {
        match self {
            Self::None | Self::OAuth { .. } => None,
            Self::Bearer { credential } => Some(credential),
        }
    }

    /// Returns the configured OAuth token-family grant, if any.
    #[must_use]
    pub const fn oauth_grant(&self) -> Option<&McpOAuthTokenGrant> {
        match self {
            Self::OAuth { grant } => Some(grant),
            Self::None | Self::Bearer { .. } => None,
        }
    }

    /// Returns the opaque broker capability reference for either authentication mode.
    #[must_use]
    pub fn capability_reference(&self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Bearer { credential } => Some(credential.capability_reference()),
            Self::OAuth { grant } => Some(grant.capability_reference()),
        }
    }

    fn validate(&self) -> Result<(), McpConfigError> {
        match self {
            Self::None => Ok(()),
            Self::Bearer { credential } => credential
                .validate()
                .map_err(|_| McpConfigError::InvalidServer),
            Self::OAuth { grant } => grant.validate().map_err(|_| McpConfigError::InvalidServer),
        }
    }
}

/// Validated non-secret endpoint authority used during pre-install discovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpHttpEndpointConfig {
    server_id: String,
    endpoint: String,
    #[serde(default)]
    authentication: McpHttpAuthentication,
}

impl McpHttpEndpointConfig {
    /// Constructs one canonical Streamable HTTP endpoint proposal.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for an invalid identity, endpoint, or credential reference.
    pub fn new(
        server_id: String,
        endpoint: String,
        authentication: McpHttpAuthentication,
    ) -> Result<Self, McpConfigError> {
        let config = Self {
            server_id,
            endpoint,
            authentication,
        };
        config.validate()?;
        Ok(config)
    }

    /// Stable logical server identity.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Exact canonical Streamable HTTP endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Optional non-secret authentication reference.
    #[must_use]
    pub const fn authentication(&self) -> &McpHttpAuthentication {
        &self.authentication
    }

    /// Validates a proposal loaded from an untrusted CLI or document boundary.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for an invalid identity, endpoint, or credential reference.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        if valid_mcp_name(&self.server_id, 32)
            && validated_mcp_http_endpoint(&self.endpoint).is_some()
            && self.authentication.validate().is_ok()
            && self
                .authentication
                .oauth_grant()
                .is_none_or(|grant| grant.resource() == self.endpoint)
        {
            Ok(())
        } else {
            Err(McpConfigError::InvalidServer)
        }
    }
}

/// One schema-pinned Streamable HTTP MCP server grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpHttpServerConfig {
    server_id: String,
    endpoint: String,
    #[serde(default)]
    authentication: McpHttpAuthentication,
    catalog_digest: String,
    enabled: bool,
    #[serde(default)]
    tools: Vec<McpToolGrant>,
    #[serde(default)]
    resources: Vec<McpResourceGrant>,
    #[serde(default)]
    prompts: Vec<McpPromptGrant>,
}

impl McpHttpServerConfig {
    /// Constructs a complete owner-reviewed Streamable HTTP server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for an unsafe endpoint, identity, credential reference,
    /// discovery digest, grant, ordering, or bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_id: String,
        endpoint: String,
        authentication: McpHttpAuthentication,
        catalog_digest: String,
        enabled: bool,
        mut tools: Vec<McpToolGrant>,
        mut resources: Vec<McpResourceGrant>,
        mut prompts: Vec<McpPromptGrant>,
    ) -> Result<Self, McpConfigError> {
        tools.sort_by(|left, right| left.remote_name().cmp(right.remote_name()));
        resources.sort_by(|left, right| left.uri().cmp(right.uri()));
        prompts.sort_by(|left, right| left.remote_name().cmp(right.remote_name()));
        let config = Self {
            server_id,
            endpoint,
            authentication,
            catalog_digest,
            enabled,
            tools,
            resources,
            prompts,
        };
        config.validate()?;
        Ok(config)
    }

    /// Stable logical server identity, unique across both MCP transports.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Exact canonical Streamable HTTP endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Optional non-secret transport credential reference.
    #[must_use]
    pub const fn authentication(&self) -> &McpHttpAuthentication {
        &self.authentication
    }

    /// SHA-256 binding the negotiated revision and complete advertised HTTP MCP catalog.
    #[must_use]
    pub fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }

    /// Whether this server is activated for new context epochs.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Exact owner-reviewed tool grants in remote-name order.
    #[must_use]
    pub fn tools(&self) -> &[McpToolGrant] {
        &self.tools
    }

    /// Exact owner-reviewed resource grants in URI order.
    #[must_use]
    pub fn resources(&self) -> &[McpResourceGrant] {
        &self.resources
    }

    /// Exact owner-reviewed prompt grants in remote-name order.
    #[must_use]
    pub fn prompts(&self) -> &[McpPromptGrant] {
        &self.prompts
    }

    /// Returns an enabled/disabled copy while preserving exact reviewed evidence.
    #[must_use]
    pub fn with_enabled(&self, enabled: bool) -> Self {
        let mut changed = self.clone();
        changed.enabled = enabled;
        changed
    }

    /// Model-visible collision-resistant identity for one granted remote name.
    #[must_use]
    pub fn exposed_tool_id(&self, remote_name: &str) -> String {
        format!("mcp.{}.tool.{}", self.server_id, remote_name)
    }

    /// Model-visible collision-resistant identity for one selected exact resource.
    #[must_use]
    pub fn exposed_resource_tool_id(&self, definition_digest: &str) -> String {
        format!("mcp.{}.resource.{}", self.server_id, definition_digest)
    }

    /// Model-visible identity for one selected prompt.
    #[must_use]
    pub fn exposed_prompt_tool_id(&self, remote_name: &str) -> String {
        format!("mcp.{}.prompt.{}", self.server_id, remote_name)
    }

    /// Canonical endpoint origin used for exact egress authority.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] only if validation was bypassed.
    pub fn endpoint_origin(&self) -> Result<String, McpConfigError> {
        validated_mcp_http_endpoint(&self.endpoint)
            .map(|endpoint| endpoint.origin().ascii_serialization())
            .ok_or(McpConfigError::InvalidServer)
    }

    /// Endpoint-only proposal suitable for a fresh owner-requested discovery.
    #[must_use]
    pub fn endpoint_config(&self) -> McpHttpEndpointConfig {
        McpHttpEndpointConfig {
            server_id: self.server_id.clone(),
            endpoint: self.endpoint.clone(),
            authentication: self.authentication.clone(),
        }
    }

    /// Exact destination claim copied into task capability grants.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] only if validation was bypassed.
    pub fn capability_network_destination(&self) -> Result<String, McpConfigError> {
        self.endpoint_origin()
            .map(|origin| format!("origin:{origin}"))
    }

    /// Opaque credential claim copied into task capability grants, when configured.
    #[must_use]
    pub fn capability_secret_reference(&self) -> Option<String> {
        self.authentication.capability_reference()
    }

    /// Validates one complete Streamable HTTP server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for malformed or non-canonical state.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        if self.endpoint_config().validate().is_err()
            || !crate::is_sha256_digest(&self.catalog_digest)
            || self
                .tools
                .len()
                .saturating_add(self.resources.len())
                .saturating_add(self.prompts.len())
                == 0
            || self
                .tools
                .len()
                .saturating_add(self.resources.len())
                .saturating_add(self.prompts.len())
                > MCP_MAXIMUM_HTTP_GRANTS_PER_SERVER
        {
            return Err(McpConfigError::InvalidServer);
        }
        let mut exposed_ids = BTreeSet::new();
        for tool in &self.tools {
            tool.validate()?;
            let exposed_id = self.exposed_tool_id(tool.remote_name());
            if exposed_id.len() > 128 || !exposed_ids.insert(exposed_id) {
                return Err(McpConfigError::InvalidServer);
            }
        }
        for resource in &self.resources {
            resource.validate()?;
            let exposed_id = self.exposed_resource_tool_id(resource.definition_digest());
            if exposed_id.len() > 128 || !exposed_ids.insert(exposed_id) {
                return Err(McpConfigError::InvalidServer);
            }
        }
        for prompt in &self.prompts {
            prompt.validate()?;
            let exposed_id = self.exposed_prompt_tool_id(prompt.remote_name());
            if exposed_id.len() > 128 || !exposed_ids.insert(exposed_id) {
                return Err(McpConfigError::InvalidServer);
            }
        }
        if !self
            .tools
            .windows(2)
            .all(|window| window[0].remote_name() < window[1].remote_name())
            || !self
                .resources
                .windows(2)
                .all(|window| window[0].uri() < window[1].uri())
            || !self
                .prompts
                .windows(2)
                .all(|window| window[0].remote_name() < window[1].remote_name())
        {
            return Err(McpConfigError::InvalidServer);
        }
        Ok(())
    }
}

pub(crate) fn validated_mcp_http_endpoint(value: &str) -> Option<Url> {
    if value.is_empty() || value.len() > MCP_MAXIMUM_HTTP_ENDPOINT_BYTES || value.trim() != value {
        return None;
    }
    let endpoint = Url::parse(value).ok()?;
    if endpoint.as_str() != value
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.host_str().is_none()
        || endpoint.path().is_empty()
    {
        return None;
    }
    let literal_address = endpoint
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok());
    let literal_loopback = literal_address.is_some_and(|address| address.is_loopback());
    (endpoint.scheme() == "https" && literal_address.is_none()
        || endpoint.scheme() == "http" && literal_loopback)
        .then_some(endpoint)
}

/// Validated projection of one server-advertised tool.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpToolInspection {
    /// Exact full server definition.
    pub definition: Value,
    /// Canonical definition digest.
    pub definition_digest: String,
}

/// Bounded result of MCP initialization and complete paginated tool discovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpServerDiscovery {
    /// Exact negotiated protocol revision.
    pub protocol_version: String,
    /// Bounded server implementation metadata returned at initialization.
    pub server_info: Value,
    /// Complete validated tools in name order.
    pub tools: Vec<McpToolInspection>,
}

impl McpServerDiscovery {
    /// Validates protocol identity, metadata bounds, tool definitions, digests, uniqueness, and
    /// canonical ordering.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when discovery evidence is malformed or oversized.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        if self.protocol_version != MCP_PROTOCOL_VERSION
            || !self.server_info.is_object()
            || serde_json::to_vec(&self.server_info)
                .map_err(|_| McpConfigError::InvalidDiscovery)?
                .len()
                > 64 * 1024
            || self.tools.is_empty()
            || self.tools.len() > MCP_MAXIMUM_TOOLS_PER_SERVER
        {
            return Err(McpConfigError::InvalidDiscovery);
        }
        let mut prior = None;
        for tool in &self.tools {
            let inspected = inspect_mcp_tool_definition(&tool.definition)?;
            if mcp_tool_definition_digest(&tool.definition)? != tool.definition_digest
                || prior.is_some_and(|name| name >= inspected.name)
            {
                return Err(McpConfigError::InvalidDiscovery);
            }
            prior = Some(inspected.name);
        }
        Ok(())
    }

    /// Finds one exact remote tool definition.
    #[must_use]
    pub fn tool(&self, remote_name: &str) -> Option<&McpToolInspection> {
        self.tools
            .iter()
            .find(|tool| tool.definition.get("name").and_then(Value::as_str) == Some(remote_name))
    }

    /// Digests the exact negotiated revision and complete canonical advertised tool set.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when discovery evidence is invalid.
    pub fn toolset_digest(&self) -> Result<String, McpConfigError> {
        self.validate()?;
        Ok(sha256_digest(
            json!({
                "contractVersion": "mealy.mcp-toolset.v1",
                "protocolVersion": self.protocol_version,
                "tools": self.tools,
            })
            .to_string()
            .as_bytes(),
        ))
    }
}

/// Exact validated projection of one advertised resource, template, or prompt definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpCatalogItemInspection {
    /// Exact full server definition.
    pub definition: Value,
    /// Canonical definition digest.
    pub definition_digest: String,
}

/// Bounded complete Streamable HTTP MCP catalog discovered in one initialized session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpHttpCatalogDiscovery {
    /// Exact negotiated protocol revision.
    pub protocol_version: String,
    /// Bounded server implementation metadata returned at initialization.
    pub server_info: Value,
    /// Exact negotiated tools capability object, when advertised.
    pub tools_capability: Option<Value>,
    /// Exact negotiated resources capability object, when advertised.
    pub resources_capability: Option<Value>,
    /// Exact negotiated prompts capability object, when advertised.
    pub prompts_capability: Option<Value>,
    /// Complete validated tools in remote-name order.
    pub tools: Vec<McpToolInspection>,
    /// Complete validated exact resources in URI order.
    pub resources: Vec<McpCatalogItemInspection>,
    /// Complete validated resource templates in URI-template order.
    pub resource_templates: Vec<McpCatalogItemInspection>,
    /// Complete validated prompts in remote-name order.
    pub prompts: Vec<McpCatalogItemInspection>,
}

impl McpHttpCatalogDiscovery {
    /// Validates negotiated capabilities, all paginated inventories, definition digests, bounds,
    /// uniqueness, and canonical ordering.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when catalog evidence is malformed or oversized.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        if self.protocol_version != MCP_PROTOCOL_VERSION
            || !self.server_info.is_object()
            || serde_json::to_vec(&self.server_info)
                .map_err(|_| McpConfigError::InvalidDiscovery)?
                .len()
                > 64 * 1024
            || self
                .tools_capability
                .as_ref()
                .is_some_and(|value| !value.is_object())
            || self
                .resources_capability
                .as_ref()
                .is_some_and(|value| !value.is_object())
            || self
                .prompts_capability
                .as_ref()
                .is_some_and(|value| !value.is_object())
            || serde_json::to_vec(&json!({
                "tools": self.tools_capability,
                "resources": self.resources_capability,
                "prompts": self.prompts_capability,
            }))
            .map_err(|_| McpConfigError::InvalidDiscovery)?
            .len()
                > 16 * 1024
            || self.tools_capability.is_none()
                && self.resources_capability.is_none()
                && self.prompts_capability.is_none()
            || self.tools_capability.is_none() && !self.tools.is_empty()
            || self.resources_capability.is_none()
                && (!self.resources.is_empty() || !self.resource_templates.is_empty())
            || self.prompts_capability.is_none() && !self.prompts.is_empty()
            || self.tools.len() > MCP_MAXIMUM_TOOLS_PER_SERVER
            || self.resources.len() > MCP_MAXIMUM_RESOURCES_PER_SERVER
            || self.resource_templates.len() > MCP_MAXIMUM_RESOURCE_TEMPLATES_PER_SERVER
            || self.prompts.len() > MCP_MAXIMUM_PROMPTS_PER_SERVER
        {
            return Err(McpConfigError::InvalidDiscovery);
        }
        validate_catalog_items(
            &self.tools,
            |definition| inspect_mcp_tool_definition(definition).map(|item| item.name),
            mcp_tool_definition_digest,
        )?;
        validate_catalog_items(
            &self.resources,
            |definition| inspect_mcp_resource_definition(definition),
            mcp_resource_definition_digest,
        )?;
        validate_catalog_items(
            &self.resource_templates,
            |definition| inspect_mcp_resource_template_definition(definition),
            mcp_resource_template_definition_digest,
        )?;
        validate_catalog_items(
            &self.prompts,
            |definition| inspect_mcp_prompt_definition(definition),
            mcp_prompt_definition_digest,
        )?;
        Ok(())
    }

    /// Finds one exact remote tool definition.
    #[must_use]
    pub fn tool(&self, remote_name: &str) -> Option<&McpToolInspection> {
        self.tools
            .iter()
            .find(|tool| tool.definition.get("name").and_then(Value::as_str) == Some(remote_name))
    }

    /// Finds one exact resource definition by URI.
    #[must_use]
    pub fn resource(&self, uri: &str) -> Option<&McpCatalogItemInspection> {
        self.resources
            .iter()
            .find(|resource| resource.definition.get("uri").and_then(Value::as_str) == Some(uri))
    }

    /// Finds one exact prompt definition by remote name.
    #[must_use]
    pub fn prompt(&self, remote_name: &str) -> Option<&McpCatalogItemInspection> {
        self.prompts.iter().find(|prompt| {
            prompt.definition.get("name").and_then(Value::as_str) == Some(remote_name)
        })
    }

    /// Digests the negotiated capability declarations and all complete canonical inventories.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] when discovery evidence is invalid.
    pub fn catalog_digest(&self) -> Result<String, McpConfigError> {
        self.validate()?;
        Ok(sha256_digest(
            json!({
                "contractVersion": "mealy.mcp-http-catalog.v1",
                "protocolVersion": self.protocol_version,
                "capabilities": {
                    "tools": self.tools_capability,
                    "resources": self.resources_capability,
                    "prompts": self.prompts_capability,
                },
                "tools": self.tools,
                "resources": self.resources,
                "resourceTemplates": self.resource_templates,
                "prompts": self.prompts,
            })
            .to_string()
            .as_bytes(),
        ))
    }
}

fn validate_catalog_items<'a, T, F, D>(
    items: &'a [T],
    inspect: F,
    digest: D,
) -> Result<(), McpConfigError>
where
    T: CatalogInspection,
    F: Fn(&'a Value) -> Result<&'a str, McpConfigError>,
    D: Fn(&Value) -> Result<String, McpConfigError>,
{
    let mut prior = None;
    for item in items {
        let key = inspect(item.definition())?;
        if digest(item.definition())? != item.definition_digest()
            || prior.is_some_and(|prior_key| prior_key >= key)
        {
            return Err(McpConfigError::InvalidDiscovery);
        }
        prior = Some(key);
    }
    Ok(())
}

trait CatalogInspection {
    fn definition(&self) -> &Value;
    fn definition_digest(&self) -> &str;
}

impl CatalogInspection for McpToolInspection {
    fn definition(&self) -> &Value {
        &self.definition
    }

    fn definition_digest(&self) -> &str {
        &self.definition_digest
    }
}

impl CatalogInspection for McpCatalogItemInspection {
    fn definition(&self) -> &Value {
        &self.definition
    }

    fn definition_digest(&self) -> &str {
        &self.definition_digest
    }
}

struct InspectedDefinition<'a> {
    name: &'a str,
}

/// Computes the canonical complete MCP tool-definition digest after strict inspection.
///
/// # Errors
///
/// Returns [`McpConfigError`] for an invalid, oversized, remotely-resolving, or unsupported schema.
pub fn mcp_tool_definition_digest(definition: &Value) -> Result<String, McpConfigError> {
    inspect_mcp_tool_definition(definition)?;
    let bytes =
        serde_json::to_vec(definition).map_err(|_| McpConfigError::InvalidToolDefinition)?;
    Ok(sha256_digest(&bytes))
}

fn inspect_mcp_tool_definition(
    definition: &Value,
) -> Result<InspectedDefinition<'_>, McpConfigError> {
    let object = definition
        .as_object()
        .ok_or(McpConfigError::InvalidToolDefinition)?;
    let bytes =
        serde_json::to_vec(definition).map_err(|_| McpConfigError::InvalidToolDefinition)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| valid_mcp_name(name, 64))
        .ok_or(McpConfigError::InvalidToolDefinition)?;
    if bytes.len() > MCP_MAXIMUM_DEFINITION_BYTES
        || object.get("description").is_some_and(|description| {
            description
                .as_str()
                .is_none_or(|text| text.len() > 4_096 || text.chars().any(char::is_control))
        })
        || object
            .get("execution")
            .and_then(|execution| execution.get("taskSupport"))
            .and_then(Value::as_str)
            == Some("required")
    {
        return Err(McpConfigError::InvalidToolDefinition);
    }
    let schema = object
        .get("inputSchema")
        .filter(|schema| schema.is_object())
        .ok_or(McpConfigError::InvalidToolDefinition)?;
    if schema.get("type").and_then(Value::as_str) != Some("object")
        || contains_external_schema_reference(schema)
        || jsonschema::validator_for(schema).is_err()
    {
        return Err(McpConfigError::InvalidToolSchema);
    }
    if let Some(output_schema) = object.get("outputSchema")
        && (!output_schema.is_object()
            || contains_external_schema_reference(output_schema)
            || jsonschema::validator_for(output_schema).is_err())
    {
        return Err(McpConfigError::InvalidToolSchema);
    }
    Ok(InspectedDefinition { name })
}

/// Computes the canonical complete digest of one exact MCP resource definition.
///
/// # Errors
///
/// Returns [`McpConfigError`] for malformed or oversized resource metadata.
pub fn mcp_resource_definition_digest(definition: &Value) -> Result<String, McpConfigError> {
    inspect_mcp_resource_definition(definition)?;
    canonical_catalog_definition_digest(definition, McpConfigError::InvalidResourceDefinition)
}

fn inspect_mcp_resource_definition(definition: &Value) -> Result<&str, McpConfigError> {
    let object = definition
        .as_object()
        .ok_or(McpConfigError::InvalidResourceDefinition)?;
    let uri = object
        .get("uri")
        .and_then(Value::as_str)
        .filter(|uri| valid_resource_uri(uri))
        .ok_or(McpConfigError::InvalidResourceDefinition)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| valid_mcp_name(name, 128))
        .ok_or(McpConfigError::InvalidResourceDefinition)?;
    if name.is_empty()
        || !valid_catalog_metadata(object)
        || object
            .get("size")
            .is_some_and(|size| size.as_u64().is_none())
    {
        return Err(McpConfigError::InvalidResourceDefinition);
    }
    Ok(uri)
}

/// Computes the canonical complete digest of one advertised MCP resource template.
///
/// # Errors
///
/// Returns [`McpConfigError`] for malformed or oversized template metadata.
pub fn mcp_resource_template_definition_digest(
    definition: &Value,
) -> Result<String, McpConfigError> {
    inspect_mcp_resource_template_definition(definition)?;
    canonical_catalog_definition_digest(
        definition,
        McpConfigError::InvalidResourceTemplateDefinition,
    )
}

fn inspect_mcp_resource_template_definition(definition: &Value) -> Result<&str, McpConfigError> {
    let object = definition
        .as_object()
        .ok_or(McpConfigError::InvalidResourceTemplateDefinition)?;
    let uri_template = object
        .get("uriTemplate")
        .and_then(Value::as_str)
        .filter(|template| {
            !template.is_empty()
                && template.len() <= MCP_MAXIMUM_RESOURCE_URI_BYTES
                && template.trim() == *template
                && !template.chars().any(char::is_control)
                && template.contains(':')
                && balanced_template_braces(template)
        })
        .ok_or(McpConfigError::InvalidResourceTemplateDefinition)?;
    if object
        .get("name")
        .and_then(Value::as_str)
        .is_none_or(|name| !valid_mcp_name(name, 128))
        || !valid_catalog_metadata(object)
    {
        return Err(McpConfigError::InvalidResourceTemplateDefinition);
    }
    Ok(uri_template)
}

/// Computes the canonical complete digest of one exact MCP prompt definition.
///
/// # Errors
///
/// Returns [`McpConfigError`] for malformed or oversized prompt metadata.
pub fn mcp_prompt_definition_digest(definition: &Value) -> Result<String, McpConfigError> {
    inspect_mcp_prompt_definition(definition)?;
    canonical_catalog_definition_digest(definition, McpConfigError::InvalidPromptDefinition)
}

fn inspect_mcp_prompt_definition(definition: &Value) -> Result<&str, McpConfigError> {
    let object = definition
        .as_object()
        .ok_or(McpConfigError::InvalidPromptDefinition)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| valid_mcp_name(name, 64))
        .ok_or(McpConfigError::InvalidPromptDefinition)?;
    if !valid_catalog_metadata(object) {
        return Err(McpConfigError::InvalidPromptDefinition);
    }
    let arguments = object
        .get("arguments")
        .map(|arguments| {
            arguments
                .as_array()
                .filter(|arguments| arguments.len() <= MCP_MAXIMUM_PROMPT_ARGUMENTS)
                .ok_or(McpConfigError::InvalidPromptDefinition)
        })
        .transpose()?
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut argument_names = BTreeSet::new();
    for argument in arguments {
        let argument = argument
            .as_object()
            .ok_or(McpConfigError::InvalidPromptDefinition)?;
        let argument_name = argument
            .get("name")
            .and_then(Value::as_str)
            .filter(|argument_name| valid_mcp_name(argument_name, 64))
            .ok_or(McpConfigError::InvalidPromptDefinition)?;
        if !argument_names.insert(argument_name)
            || argument.get("description").is_some_and(|description| {
                description
                    .as_str()
                    .is_none_or(|value| !valid_bounded_text(value, 4_096))
            })
            || argument
                .get("required")
                .is_some_and(|required| !required.is_boolean())
        {
            return Err(McpConfigError::InvalidPromptDefinition);
        }
    }
    Ok(name)
}

fn canonical_catalog_definition_digest(
    definition: &Value,
    error: McpConfigError,
) -> Result<String, McpConfigError> {
    let bytes = serde_json::to_vec(definition).map_err(|_| error)?;
    if bytes.len() > MCP_MAXIMUM_DEFINITION_BYTES {
        return Err(error);
    }
    Ok(sha256_digest(&bytes))
}

fn valid_catalog_metadata(object: &serde_json::Map<String, Value>) -> bool {
    serde_json::to_vec(object).is_ok_and(|bytes| bytes.len() <= MCP_MAXIMUM_DEFINITION_BYTES)
        && ["title", "description", "mimeType"]
            .into_iter()
            .all(|field| {
                object.get(field).is_none_or(|value| {
                    value
                        .as_str()
                        .is_some_and(|text| valid_bounded_text(text, 4_096))
                })
            })
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    value.len() <= maximum && !value.contains('\0')
}

fn valid_resource_uri(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MCP_MAXIMUM_RESOURCE_URI_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return false;
    }
    Url::parse(value).is_ok_and(|uri| {
        uri.as_str() == value && uri.username().is_empty() && uri.password().is_none()
    })
}

fn balanced_template_braces(value: &str) -> bool {
    let mut depth = 0_u8;
    for character in value.chars() {
        match character {
            '{' if depth == 0 => depth = 1,
            '}' if depth == 1 => depth = 0,
            '{' | '}' => return false,
            _ => {}
        }
    }
    depth == 0
}

/// Validates one exact model-proposed argument object against the pinned MCP JSON Schema.
///
/// # Errors
///
/// Returns [`ReadToolError::InvalidArguments`] before any MCP process is launched.
pub fn validate_mcp_tool_arguments(
    grant: &McpToolGrant,
    arguments: &Value,
) -> Result<(), ReadToolError> {
    if !arguments.is_object() {
        return Err(ReadToolError::InvalidArguments(
            "MCP tool arguments must be a JSON object".to_owned(),
        ));
    }
    let serialized = serde_json::to_vec(arguments)
        .map_err(|_| ReadToolError::InvalidArguments("arguments are not JSON".to_owned()))?;
    if serialized.len() > MCP_MAXIMUM_TOOL_ARGUMENT_BYTES {
        return Err(ReadToolError::InvalidArguments(
            "MCP tool arguments exceed the hard byte bound".to_owned(),
        ));
    }
    let validator = jsonschema::validator_for(grant.input_schema()).map_err(|_| {
        ReadToolError::Unavailable("pinned MCP input schema is no longer valid".to_owned())
    })?;
    validator.validate(arguments).map_err(|error| {
        ReadToolError::InvalidArguments(format!("MCP input schema rejected arguments: {error}"))
    })
}

/// Validates prompt argument strings against the exact advertised required/optional argument set.
///
/// # Errors
///
/// Returns [`ReadToolError::InvalidArguments`] before any remote request is sent.
pub fn validate_mcp_prompt_arguments(
    grant: &McpPromptGrant,
    arguments: &Value,
) -> Result<(), ReadToolError> {
    if !arguments.is_object() {
        return Err(ReadToolError::InvalidArguments(
            "MCP prompt arguments must be a JSON object".to_owned(),
        ));
    }
    let serialized = serde_json::to_vec(arguments)
        .map_err(|_| ReadToolError::InvalidArguments("arguments are not JSON".to_owned()))?;
    if serialized.len() > MCP_MAXIMUM_TOOL_ARGUMENT_BYTES {
        return Err(ReadToolError::InvalidArguments(
            "MCP prompt arguments exceed the hard byte bound".to_owned(),
        ));
    }
    let schema = grant.input_schema();
    let validator = jsonschema::validator_for(&schema).map_err(|_| {
        ReadToolError::Unavailable("pinned MCP prompt schema is no longer valid".to_owned())
    })?;
    validator.validate(arguments).map_err(|error| {
        ReadToolError::InvalidArguments(format!("MCP prompt schema rejected arguments: {error}"))
    })
}

/// Builds the immutable Mealy read-tool descriptor for one exact configured MCP grant.
///
/// # Errors
///
/// Returns a descriptor evidence error when canonical material cannot be represented.
pub fn mcp_read_tool_descriptor(
    server: &McpServerConfig,
    grant: &McpToolGrant,
) -> Result<ReadToolDescriptor, crate::ToolDescriptorEvidenceError> {
    if grant.effect() != McpToolEffect::ReadOnly {
        return Err(crate::ToolDescriptorEvidenceError::InvalidEffectContract);
    }
    let mut input_schema = grant.input_schema().clone();
    if let Some(object) = input_schema.as_object_mut() {
        object
            .entry("description")
            .or_insert_with(|| Value::String(grant.description().to_owned()));
    }
    let output_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "serverId": {"type": "string"},
            "toolName": {"type": "string"},
            "definitionDigest": {"type": "string"},
            "sourceLocator": {"type": "string"},
            "isError": {"type": "boolean"},
            "content": {"type": "array", "items": {"type": "object"}},
            "structuredContent": {}
        },
        "required": ["serverId", "toolName", "definitionDigest", "sourceLocator", "isError", "content"]
    });
    let schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let executable_identity_digest = sha256_digest(
        json!({
            "contractVersion": "mealy.mcp-stdio-tool.v1",
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverId": server.server_id(),
            "serverExecutableDigest": server.executable_digest(),
            "serverArguments": server.arguments(),
            "serverToolsetDigest": server.toolset_digest(),
            "toolDefinitionDigest": grant.definition_digest(),
        })
        .to_string()
        .as_bytes(),
    );
    let mut descriptor = ReadToolDescriptor {
        tool_id: server.exposed_tool_id(grant.remote_name()),
        version: format!(
            "{}+{}",
            MCP_PROTOCOL_VERSION,
            &executable_identity_digest[..16]
        ),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        schema_digest,
        effect_class: "read_only".to_owned(),
        risk_class: "medium".to_owned(),
        required_capability: format!(
            "mcp.invoke:{}:{}:sha256:{executable_identity_digest}",
            server.server_id(),
            grant.remote_name()
        ),
        timeout: Duration::from_millis(grant.timeout_ms()),
        maximum_output_bytes: grant.maximum_output_bytes(),
        conflict_key_template: format!("mcp://{}/{}", server.server_id(), grant.remote_name()),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    Ok(descriptor)
}

/// Builds the immutable Mealy read-tool descriptor for one Streamable HTTP MCP grant.
///
/// # Errors
///
/// Returns a descriptor evidence error when canonical material cannot be represented.
pub fn mcp_http_read_tool_descriptor(
    server: &McpHttpServerConfig,
    grant: &McpToolGrant,
) -> Result<ReadToolDescriptor, crate::ToolDescriptorEvidenceError> {
    if grant.effect() != McpToolEffect::ReadOnly {
        return Err(crate::ToolDescriptorEvidenceError::InvalidEffectContract);
    }
    let mut input_schema = grant.input_schema().clone();
    if let Some(object) = input_schema.as_object_mut() {
        object
            .entry("description")
            .or_insert_with(|| Value::String(grant.description().to_owned()));
    }
    let output_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "serverId": {"type": "string"},
            "toolName": {"type": "string"},
            "definitionDigest": {"type": "string"},
            "sourceLocator": {"type": "string"},
            "isError": {"type": "boolean"},
            "content": {"type": "array", "items": {"type": "object"}},
            "structuredContent": {}
        },
        "required": ["serverId", "toolName", "definitionDigest", "sourceLocator", "isError", "content"]
    });
    let schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let transport_identity_digest = sha256_digest(
        json!({
            "contractVersion": "mealy.mcp-streamable-http-tool.v1",
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverId": server.server_id(),
            "endpoint": server.endpoint(),
            "authenticationReference": server
                .authentication()
                .capability_reference(),
            "serverCatalogDigest": server.catalog_digest(),
            "toolDefinitionDigest": grant.definition_digest(),
        })
        .to_string()
        .as_bytes(),
    );
    let network_destination = server
        .capability_network_destination()
        .map_err(|_| crate::ToolDescriptorEvidenceError::DescriptorDigestMismatch)?;
    let secret_reference = server.capability_secret_reference();
    let authority_digest =
        mcp_http_authority_digest(&network_destination, secret_reference.as_deref());
    let mut descriptor = ReadToolDescriptor {
        tool_id: server.exposed_tool_id(grant.remote_name()),
        version: format!(
            "{}+{}",
            MCP_PROTOCOL_VERSION,
            &transport_identity_digest[..16]
        ),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        schema_digest,
        effect_class: "read_only".to_owned(),
        risk_class: "medium".to_owned(),
        required_capability: format!(
            "mcp.http.invoke:{}:tool.{}:sha256:{transport_identity_digest}:authority-sha256:{authority_digest}",
            server.server_id(),
            grant.remote_name()
        ),
        timeout: Duration::from_millis(grant.timeout_ms()),
        maximum_output_bytes: grant.maximum_output_bytes(),
        conflict_key_template: format!("mcp://{}/tool.{}", server.server_id(), grant.remote_name()),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    Ok(descriptor)
}

/// Builds the immutable governed-effect descriptor for one local stdio MCP grant.
///
/// The owner-attested effect contract, not the remote annotation, selects idempotency and
/// interrupted-dispatch recovery.
///
/// # Errors
///
/// Returns [`McpConfigError`] for a read-only grant or an invalid generic descriptor.
pub fn mcp_effect_tool_descriptor(
    server: &McpServerConfig,
    grant: &McpToolGrant,
) -> Result<ToolDescriptor, McpConfigError> {
    let (input_schema, output_schema) = mcp_tool_schemas(grant);
    let executable_identity_digest = sha256_digest(
        json!({
            "contractVersion": "mealy.mcp-stdio-effect-tool.v1",
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverId": server.server_id(),
            "serverExecutableDigest": server.executable_digest(),
            "serverArguments": server.arguments(),
            "serverToolsetDigest": server.toolset_digest(),
            "toolDefinitionDigest": grant.definition_digest(),
            "ownerEffectContract": grant.effect(),
        })
        .to_string()
        .as_bytes(),
    );
    mcp_effect_descriptor(
        server.exposed_tool_id(grant.remote_name()),
        input_schema,
        output_schema,
        format!(
            "mcp.invoke:{}:{}:sha256:{executable_identity_digest}",
            server.server_id(),
            grant.remote_name()
        ),
        format!("mcp://{}/{}", server.server_id(), grant.remote_name()),
        executable_identity_digest,
        grant,
    )
}

/// Builds the immutable governed-effect descriptor for one Streamable HTTP MCP grant.
///
/// # Errors
///
/// Returns [`McpConfigError`] for a read-only grant, invalid endpoint authority, or invalid
/// generic descriptor.
pub fn mcp_http_effect_tool_descriptor(
    server: &McpHttpServerConfig,
    grant: &McpToolGrant,
) -> Result<ToolDescriptor, McpConfigError> {
    let (input_schema, output_schema) = mcp_tool_schemas(grant);
    let transport_identity_digest = sha256_digest(
        json!({
            "contractVersion": "mealy.mcp-streamable-http-effect-tool.v1",
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverId": server.server_id(),
            "endpoint": server.endpoint(),
            "authenticationReference": server
                .authentication()
                .capability_reference(),
            "serverCatalogDigest": server.catalog_digest(),
            "toolDefinitionDigest": grant.definition_digest(),
            "ownerEffectContract": grant.effect(),
        })
        .to_string()
        .as_bytes(),
    );
    let network_destination = server
        .capability_network_destination()
        .map_err(|_| McpConfigError::InvalidToolGrant)?;
    let secret_reference = server.capability_secret_reference();
    let authority_digest =
        mcp_http_authority_digest(&network_destination, secret_reference.as_deref());
    mcp_effect_descriptor(
        server.exposed_tool_id(grant.remote_name()),
        input_schema,
        output_schema,
        format!(
            "mcp.http.invoke:{}:tool.{}:sha256:{transport_identity_digest}:authority-sha256:{authority_digest}",
            server.server_id(),
            grant.remote_name()
        ),
        format!("mcp://{}/tool.{}", server.server_id(), grant.remote_name()),
        transport_identity_digest,
        grant,
    )
}

fn mcp_tool_schemas(grant: &McpToolGrant) -> (Value, Value) {
    let mut input_schema = grant.input_schema().clone();
    if let Some(object) = input_schema.as_object_mut() {
        object
            .entry("description")
            .or_insert_with(|| Value::String(grant.description().to_owned()));
    }
    let output_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "serverId": {"type": "string"},
            "toolName": {"type": "string"},
            "definitionDigest": {"type": "string"},
            "sourceLocator": {"type": "string"},
            "isError": {"type": "boolean"},
            "content": {"type": "array", "items": {"type": "object"}},
            "structuredContent": {}
        },
        "required": ["serverId", "toolName", "definitionDigest", "sourceLocator", "isError", "content"]
    });
    (input_schema, output_schema)
}

#[allow(clippy::too_many_arguments)]
fn mcp_effect_descriptor(
    tool_id: String,
    input_schema: Value,
    output_schema: Value,
    required_capability: String,
    conflict_key: String,
    executable_identity_digest: String,
    grant: &McpToolGrant,
) -> Result<ToolDescriptor, McpConfigError> {
    let (effect_class, risk_class, idempotency, recovery) = match grant.effect() {
        McpToolEffect::ReadOnly => return Err(McpConfigError::InvalidToolGrant),
        McpToolEffect::Idempotent => (
            EffectClass::Idempotent,
            RiskClass::Medium,
            IdempotencyClass::Idempotent,
            RecoveryStrategy::Retry,
        ),
        McpToolEffect::NonIdempotent => (
            EffectClass::NonIdempotent,
            RiskClass::High,
            IdempotencyClass::NonIdempotent,
            RecoveryStrategy::Reconcile,
        ),
    };
    let input_schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let output_schema_digest = sha256_digest(output_schema.to_string().as_bytes());
    let mut descriptor = ToolDescriptor {
        tool_id,
        version: format!(
            "{}+{}",
            MCP_PROTOCOL_VERSION,
            &executable_identity_digest[..16]
        ),
        input_schema,
        output_schema,
        input_schema_digest,
        output_schema_digest,
        descriptor_digest: String::new(),
        effect_class,
        risk_class,
        required_capabilities: vec![required_capability],
        timeout: Duration::from_millis(grant.timeout_ms()),
        maximum_output_bytes: grant.maximum_output_bytes(),
        concurrency: ToolConcurrency::Serial,
        conflict_key_templates: vec![conflict_key],
        idempotency,
        recovery,
        executor: ExecutorKind::Builtin,
        executable_identity_digest,
    };
    descriptor.descriptor_digest = descriptor
        .computed_descriptor_digest()
        .map_err(|_| McpConfigError::InvalidToolGrant)?;
    descriptor
        .validate()
        .map_err(|_| McpConfigError::InvalidToolGrant)?;
    Ok(descriptor)
}

/// Evaluates one exact owner-classified MCP effect and requires bound approval on every match.
#[must_use]
pub fn evaluate_mcp_effect_policy(
    request: &PolicyRequest,
    grant: &McpEffectPolicyGrant,
) -> PolicyEvaluation {
    let deny = |explanation: &str| PolicyEvaluation {
        decision: PolicyDecision::Deny,
        obligations: denied_mcp_effect_obligations(request.requested_profile),
        policy_version: request.policy_version.clone(),
        explanation: explanation.to_owned(),
    };
    if request.validate().is_err() || grant.validate().is_err() {
        return deny("invalid_mcp_effect_request");
    }
    if request.principal_id != grant.principal_id
        || request.channel_binding_id != grant.channel_binding_id
        || request.task_id != grant.task_id
        || request.run_id != grant.run_id
    {
        return deny("mcp_effect_owner_or_run_not_granted");
    }
    if request.evaluated_at_ms < grant.valid_from_ms
        || request.evaluated_at_ms >= grant.expires_at_ms
    {
        return deny("mcp_effect_grant_not_current");
    }
    let (effect_class, risk_class, idempotency, recovery) = match grant.effect {
        McpToolEffect::ReadOnly => return deny("mcp_read_tool_cannot_use_effect_policy"),
        McpToolEffect::Idempotent => (
            EffectClass::Idempotent,
            RiskClass::Medium,
            IdempotencyClass::Idempotent,
            RecoveryStrategy::Retry,
        ),
        McpToolEffect::NonIdempotent => (
            EffectClass::NonIdempotent,
            RiskClass::High,
            IdempotencyClass::NonIdempotent,
            RecoveryStrategy::Reconcile,
        ),
    };
    let expected_network = grant
        .network_destination
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let expected_secrets = grant.secret_reference.iter().cloned().collect::<Vec<_>>();
    let arguments_valid = serde_json::to_vec(&request.normalized_arguments)
        .is_ok_and(|bytes| bytes.len() <= MCP_MAXIMUM_TOOL_ARGUMENT_BYTES)
        && jsonschema::validator_for(&request.tool.input_schema)
            .is_ok_and(|validator| validator.validate(&request.normalized_arguments).is_ok());
    if !arguments_valid
        || request.agent_role != "assistant"
        || request.policy_version != MCP_EFFECT_POLICY_VERSION
        || request.task_risk != risk_class
        || request.tool.effect_class != effect_class
        || request.tool.risk_class != risk_class
        || request.tool.idempotency != idempotency
        || request.tool.recovery != recovery
        || request.tool.executor != ExecutorKind::Builtin
        || request.tool.descriptor_digest != grant.tool_descriptor_digest
        || request.tool.executable_identity_digest != grant.executable_identity_digest
        || request.tool.required_capabilities != [grant.capability.clone()]
        || request.target_resources != [grant.target_resource.clone()]
        || !request.workspace_roots.is_empty()
        || request.resource_claims != [format!("mcp-effect:{}", grant.target_resource)]
        || request.secret_references != expected_secrets
        || request.network_destinations != expected_network
        || request.requested_capability != grant.capability
        || request.requested_profile != PolicyProfile::ServiceOperator
        || request.enforceable_profiles != [PolicyProfile::ServiceOperator]
    {
        return deny("no_matching_mcp_effect_rule");
    }
    PolicyEvaluation {
        decision: PolicyDecision::RequireApproval,
        obligations: expected_mcp_effect_obligations(request, grant),
        policy_version: MCP_EFFECT_POLICY_VERSION.to_owned(),
        explanation: MCP_EFFECT_APPROVAL_EXPLANATION.to_owned(),
    }
}

/// Constructs the immutable exact owner approval subject for one matched MCP effect.
///
/// # Errors
///
/// Returns [`McpEffectPolicyError`] when policy does not match or expiry is invalid.
pub fn mcp_effect_approval_subject(
    effect_id: EffectId,
    request: &PolicyRequest,
    grant: &McpEffectPolicyGrant,
    expires_at_ms: i64,
) -> Result<ApprovalSubject, McpEffectPolicyError> {
    if evaluate_mcp_effect_policy(request, grant).decision != PolicyDecision::RequireApproval
        || expires_at_ms <= request.evaluated_at_ms
        || expires_at_ms > grant.expires_at_ms
    {
        return Err(McpEffectPolicyError::InvalidContract);
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
        policy_version: MCP_EFFECT_POLICY_VERSION.to_owned(),
        expires_at_ms,
    };
    subject.validate()?;
    Ok(subject)
}

fn expected_mcp_effect_obligations(
    request: &PolicyRequest,
    grant: &McpEffectPolicyGrant,
) -> PolicyObligations {
    let spawns_server = grant.network_destination.is_none();
    PolicyObligations {
        profile: PolicyProfile::ServiceOperator,
        readable_paths: Vec::new(),
        writable_paths: Vec::new(),
        allowed_executable_identity_digests: vec![request.tool.executable_identity_digest.clone()],
        allow_process_spawn: spawns_server,
        allowed_environment_variables: Vec::new(),
        network_destinations: grant.network_destination.iter().cloned().collect(),
        secret_references: grant.secret_reference.iter().cloned().collect(),
        argument_rewrite: None,
        redactions: Vec::new(),
        maximum_duration_ms: u64::try_from(request.tool.timeout.as_millis()).unwrap_or(u64::MAX),
        maximum_output_bytes: request.tool.maximum_output_bytes,
        maximum_memory_bytes: if spawns_server {
            MCP_EFFECT_MAXIMUM_MEMORY_BYTES
        } else {
            0
        },
        maximum_processes: u32::from(spawns_server),
        validator_required: true,
    }
}

fn denied_mcp_effect_obligations(profile: PolicyProfile) -> PolicyObligations {
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

/// Builds the immutable read descriptor for one exact owner-selected HTTP MCP resource.
///
/// # Errors
///
/// Returns a descriptor evidence error when canonical material cannot be represented.
pub fn mcp_http_resource_read_descriptor(
    server: &McpHttpServerConfig,
    grant: &McpResourceGrant,
) -> Result<ReadToolDescriptor, crate::ToolDescriptorEvidenceError> {
    let input_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {},
        "description": grant.description(),
    });
    let output_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "serverId": {"type": "string"},
            "resourceUri": {"type": "string"},
            "definitionDigest": {"type": "string"},
            "sourceLocator": {"type": "string"},
            "contents": {"type": "array", "items": {"type": "object"}}
        },
        "required": ["serverId", "resourceUri", "definitionDigest", "sourceLocator", "contents"]
    });
    let schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let transport_identity_digest =
        http_catalog_item_identity_digest(server, "resource", grant.definition_digest());
    let authority_digest = http_server_authority_digest(server)?;
    let operation_id = format!("resource.{}", grant.definition_digest());
    let mut descriptor = ReadToolDescriptor {
        tool_id: server.exposed_resource_tool_id(grant.definition_digest()),
        version: format!(
            "{}+{}",
            MCP_PROTOCOL_VERSION,
            &transport_identity_digest[..16]
        ),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        schema_digest,
        effect_class: "read_only".to_owned(),
        risk_class: "medium".to_owned(),
        required_capability: format!(
            "mcp.http.invoke:{}:{operation_id}:sha256:{transport_identity_digest}:authority-sha256:{authority_digest}",
            server.server_id(),
        ),
        timeout: Duration::from_millis(grant.timeout_ms()),
        maximum_output_bytes: grant.maximum_output_bytes(),
        conflict_key_template: format!(
            "mcp://{}/resource.{}",
            server.server_id(),
            grant.definition_digest()
        ),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    Ok(descriptor)
}

/// Builds the immutable read descriptor for one owner-selected HTTP MCP prompt.
///
/// Returned prompt messages remain ordinary untrusted tool evidence and are never elevated into
/// hidden or system instructions.
///
/// # Errors
///
/// Returns a descriptor evidence error when canonical material cannot be represented.
pub fn mcp_http_prompt_read_descriptor(
    server: &McpHttpServerConfig,
    grant: &McpPromptGrant,
) -> Result<ReadToolDescriptor, crate::ToolDescriptorEvidenceError> {
    let input_schema = grant.input_schema();
    let output_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "serverId": {"type": "string"},
            "promptName": {"type": "string"},
            "definitionDigest": {"type": "string"},
            "sourceLocator": {"type": "string"},
            "description": {"type": ["string", "null"]},
            "messages": {"type": "array", "items": {"type": "object"}},
            "trust": {"const": "untrusted_tool_evidence"}
        },
        "required": [
            "serverId",
            "promptName",
            "definitionDigest",
            "sourceLocator",
            "description",
            "messages",
            "trust"
        ]
    });
    let schema_digest = sha256_digest(input_schema.to_string().as_bytes());
    let transport_identity_digest =
        http_catalog_item_identity_digest(server, "prompt", grant.definition_digest());
    let authority_digest = http_server_authority_digest(server)?;
    let operation_id = format!("prompt.{}", grant.remote_name());
    let mut descriptor = ReadToolDescriptor {
        tool_id: server.exposed_prompt_tool_id(grant.remote_name()),
        version: format!(
            "{}+{}",
            MCP_PROTOCOL_VERSION,
            &transport_identity_digest[..16]
        ),
        input_schema,
        output_schema,
        descriptor_digest: String::new(),
        schema_digest,
        effect_class: "read_only".to_owned(),
        risk_class: "medium".to_owned(),
        required_capability: format!(
            "mcp.http.invoke:{}:{operation_id}:sha256:{transport_identity_digest}:authority-sha256:{authority_digest}",
            server.server_id(),
        ),
        timeout: Duration::from_millis(grant.timeout_ms()),
        maximum_output_bytes: grant.maximum_output_bytes(),
        conflict_key_template: format!(
            "mcp://{}/prompt.{}",
            server.server_id(),
            grant.remote_name()
        ),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor.computed_descriptor_digest()?;
    Ok(descriptor)
}

fn http_catalog_item_identity_digest(
    server: &McpHttpServerConfig,
    kind: &str,
    definition_digest: &str,
) -> String {
    sha256_digest(
        json!({
            "contractVersion": "mealy.mcp-streamable-http-catalog-item.v1",
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverId": server.server_id(),
            "endpoint": server.endpoint(),
            "authenticationReference": server
                .authentication()
                .capability_reference(),
            "serverCatalogDigest": server.catalog_digest(),
            "kind": kind,
            "definitionDigest": definition_digest,
        })
        .to_string()
        .as_bytes(),
    )
}

fn http_server_authority_digest(
    server: &McpHttpServerConfig,
) -> Result<String, crate::ToolDescriptorEvidenceError> {
    let network_destination = server
        .capability_network_destination()
        .map_err(|_| crate::ToolDescriptorEvidenceError::DescriptorDigestMismatch)?;
    Ok(mcp_http_authority_digest(
        &network_destination,
        server.capability_secret_reference().as_deref(),
    ))
}

/// Digests one exact non-secret Streamable HTTP authority tuple.
///
/// Durable descriptors use this claim to prove that both endpoint egress and the opaque
/// credential reference remain present in an immutable task ceiling.
#[must_use]
pub fn mcp_http_authority_digest(
    network_destination: &str,
    secret_reference: Option<&str>,
) -> String {
    sha256_digest(
        json!({
            "contractVersion": "mealy.mcp-http-authority.v1",
            "networkDestination": network_destination,
            "secretReference": secret_reference,
        })
        .to_string()
        .as_bytes(),
    )
}

fn contains_external_schema_reference(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (key == "$ref"
                && value
                    .as_str()
                    .is_none_or(|reference| !reference.starts_with('#')))
                || (key == "$id")
                || contains_external_schema_reference(value)
        }),
        Value::Array(values) => values.iter().any(contains_external_schema_reference),
        _ => false,
    }
}

fn valid_mcp_name(value: &str, maximum: usize) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    let last = value.as_bytes()[value.len() - 1];
    value.len() <= maximum
        && first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn invalid_argument(value: &str) -> bool {
    value.len() > MCP_MAXIMUM_ARGUMENT_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

/// Invalid MCP configuration, discovery, schema, or owner grant evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpConfigError {
    /// Server identity, executable evidence, arguments, ordering, or bounds are invalid.
    #[error("MCP server configuration is invalid")]
    InvalidServer,
    /// Tool grant bounds or definition binding are invalid.
    #[error("MCP tool grant is invalid")]
    InvalidToolGrant,
    /// Resource grant bounds or definition binding are invalid.
    #[error("MCP resource grant is invalid")]
    InvalidResourceGrant,
    /// Prompt grant bounds or definition binding are invalid.
    #[error("MCP prompt grant is invalid")]
    InvalidPromptGrant,
    /// Advertised tool definition is malformed, oversized, or unsupported.
    #[error("MCP tool definition is invalid")]
    InvalidToolDefinition,
    /// Advertised resource definition is malformed or oversized.
    #[error("MCP resource definition is invalid")]
    InvalidResourceDefinition,
    /// Advertised resource template definition is malformed or oversized.
    #[error("MCP resource template definition is invalid")]
    InvalidResourceTemplateDefinition,
    /// Advertised prompt definition is malformed or oversized.
    #[error("MCP prompt definition is invalid")]
    InvalidPromptDefinition,
    /// Input/output JSON Schema is invalid or attempts external resolution.
    #[error("MCP tool JSON Schema is invalid or not self-contained")]
    InvalidToolSchema,
    /// Negotiated discovery evidence is invalid or non-canonical.
    #[error("MCP server discovery evidence is invalid")]
    InvalidDiscovery,
}

/// Validates deterministic identity ordering for a complete configured server list.
///
/// # Errors
///
/// Returns [`McpConfigError`] when the set exceeds its bound, is not in canonical unique server
/// identity order, or contains an invalid server/grant.
pub fn validate_mcp_server_set(servers: &[McpServerConfig]) -> Result<(), McpConfigError> {
    if servers.len() > MCP_MAXIMUM_SERVERS
        || !servers
            .windows(2)
            .all(|window| window[0].server_id() < window[1].server_id())
    {
        return Err(McpConfigError::InvalidServer);
    }
    for server in servers {
        server.validate()?;
    }
    Ok(())
}

/// Validates deterministic identity ordering for configured Streamable HTTP MCP servers.
///
/// # Errors
///
/// Returns [`McpConfigError`] for invalid grants, ordering, bounds, or a server identity reused by
/// the stdio transport.
pub fn validate_mcp_http_server_set(
    stdio_servers: &[McpServerConfig],
    http_servers: &[McpHttpServerConfig],
) -> Result<(), McpConfigError> {
    if http_servers.len().saturating_add(stdio_servers.len()) > MCP_MAXIMUM_SERVERS
        || !http_servers
            .windows(2)
            .all(|window| window[0].server_id() < window[1].server_id())
    {
        return Err(McpConfigError::InvalidServer);
    }
    let stdio_ids = stdio_servers
        .iter()
        .map(McpServerConfig::server_id)
        .collect::<BTreeSet<_>>();
    for server in http_servers {
        server.validate()?;
        if stdio_ids.contains(server.server_id()) {
            return Err(McpConfigError::InvalidServer);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MCP_PROTOCOL_VERSION, McpCatalogItemInspection, McpEffectPolicyGrant,
        McpHttpAuthentication, McpHttpCatalogDiscovery, McpHttpServerConfig, McpPromptGrant,
        McpResourceGrant, McpServerConfig, McpServerDiscovery, McpToolEffect, McpToolGrant,
        McpToolInspection, evaluate_mcp_effect_policy, mcp_effect_approval_subject,
        mcp_effect_tool_descriptor, mcp_http_effect_tool_descriptor,
        mcp_http_prompt_read_descriptor, mcp_http_read_tool_descriptor,
        mcp_http_resource_read_descriptor, mcp_prompt_definition_digest, mcp_read_tool_descriptor,
        mcp_resource_template_definition_digest, validate_mcp_http_server_set,
        validate_mcp_prompt_arguments, validate_mcp_tool_arguments,
    };
    use crate::{
        MCP_EFFECT_POLICY_VERSION, McpOAuthTokenGrant, PolicyDecision, PolicyRequest,
        ProviderCredentialReference,
    };
    use mealy_domain::{
        ChannelBindingId, EffectClass, EffectId, IdempotencyClass, PolicyProfile, PrincipalId,
        RecoveryStrategy, RiskClass, RunId, TaskId,
    };
    use serde_json::json;

    fn definition(name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "description": "Adds two integers without external effects",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "left": {"type": "integer"},
                    "right": {"type": "integer"}
                },
                "required": ["left", "right"]
            },
            "annotations": {"readOnlyHint": false}
        })
    }

    #[test]
    fn owner_grant_pins_complete_definition_and_builds_descriptor() {
        let grant = McpToolGrant::new(definition("add"), 5_000, 64 * 1024).expect("grant");
        let executable_digest = "a".repeat(64);
        let discovery = McpServerDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "fixture", "version": "1"}),
            tools: vec![McpToolInspection {
                definition: grant.definition().clone(),
                definition_digest: grant.definition_digest().to_owned(),
            }],
        };
        let server = McpServerConfig::new(
            "math".to_owned(),
            format!("mcp-servers/{executable_digest}/server"),
            executable_digest,
            Vec::new(),
            discovery.toolset_digest().expect("toolset digest"),
            true,
            vec![grant.clone()],
        )
        .expect("server");
        let descriptor = mcp_read_tool_descriptor(&server, &grant).expect("descriptor");
        descriptor.validate_evidence().expect("evidence");
        assert_eq!(descriptor.tool_id, "mcp.math.add");
        assert!(validate_mcp_tool_arguments(&grant, &json!({"left": 1, "right": 2})).is_ok());
        assert!(validate_mcp_tool_arguments(&grant, &json!({"left": 1})).is_err());
    }

    #[test]
    fn owner_effect_classification_is_explicit_backward_compatible_and_descriptor_bound() {
        let read = McpToolGrant::new(definition("read"), 5_000, 64 * 1024).expect("read grant");
        assert_eq!(read.effect(), McpToolEffect::ReadOnly);
        let mut legacy = serde_json::to_value(&read).expect("legacy grant JSON");
        legacy
            .as_object_mut()
            .expect("grant object")
            .remove("effect");
        let legacy: McpToolGrant = serde_json::from_value(legacy).expect("legacy grant");
        assert_eq!(legacy.effect(), McpToolEffect::ReadOnly);

        let effectful = McpToolGrant::new_with_effect(
            definition("write"),
            McpToolEffect::NonIdempotent,
            5_000,
            64 * 1024,
        )
        .expect("effectful grant");
        let executable_digest = "a".repeat(64);
        let discovery = McpServerDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "fixture", "version": "1"}),
            tools: vec![McpToolInspection {
                definition: effectful.definition().clone(),
                definition_digest: effectful.definition_digest().to_owned(),
            }],
        };
        let server = McpServerConfig::new(
            "actions".to_owned(),
            format!("mcp-servers/{executable_digest}/server"),
            executable_digest,
            Vec::new(),
            discovery.toolset_digest().expect("toolset digest"),
            true,
            vec![effectful.clone()],
        )
        .expect("server");
        assert!(mcp_read_tool_descriptor(&server, &effectful).is_err());
        let descriptor = mcp_effect_tool_descriptor(&server, &effectful).expect("descriptor");
        assert_eq!(descriptor.effect_class, EffectClass::NonIdempotent);
        assert_eq!(descriptor.risk_class, RiskClass::High);
        assert_eq!(descriptor.idempotency, IdempotencyClass::NonIdempotent);
        assert_eq!(descriptor.recovery, RecoveryStrategy::Reconcile);
        let idempotent = McpToolGrant::new_with_effect(
            definition("write"),
            McpToolEffect::Idempotent,
            5_000,
            64 * 1024,
        )
        .expect("idempotent grant");
        let idempotent_descriptor =
            mcp_effect_tool_descriptor(&server, &idempotent).expect("idempotent descriptor");
        assert_ne!(
            descriptor.executable_identity_digest,
            idempotent_descriptor.executable_identity_digest
        );
        assert_ne!(
            descriptor.descriptor_digest,
            idempotent_descriptor.descriptor_digest
        );
    }

    #[test]
    fn effect_policy_binds_owner_classification_authority_arguments_and_approval() {
        let tool = McpToolGrant::new_with_effect(
            definition("write"),
            McpToolEffect::NonIdempotent,
            5_000,
            64 * 1024,
        )
        .expect("effect grant");
        let executable_digest = "b".repeat(64);
        let discovery = McpServerDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "fixture", "version": "1"}),
            tools: vec![McpToolInspection {
                definition: tool.definition().clone(),
                definition_digest: tool.definition_digest().to_owned(),
            }],
        };
        let server = McpServerConfig::new(
            "effects".to_owned(),
            format!("mcp-servers/{executable_digest}/server"),
            executable_digest,
            Vec::new(),
            discovery.toolset_digest().expect("toolset digest"),
            true,
            vec![tool],
        )
        .expect("server");
        let descriptor =
            mcp_effect_tool_descriptor(&server, &server.tools()[0]).expect("descriptor");
        let principal_id = PrincipalId::new();
        let channel_binding_id = ChannelBindingId::new();
        let task_id = TaskId::new();
        let run_id = RunId::new();
        let capability = descriptor.required_capabilities[0].clone();
        let target = "mcp://effects/write".to_owned();
        let grant = McpEffectPolicyGrant {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            tool_descriptor_digest: descriptor.descriptor_digest.clone(),
            executable_identity_digest: descriptor.executable_identity_digest.clone(),
            effect: McpToolEffect::NonIdempotent,
            capability: capability.clone(),
            target_resource: target.clone(),
            network_destination: None,
            secret_reference: None,
            valid_from_ms: 10,
            expires_at_ms: 1_000,
        };
        let request = PolicyRequest {
            principal_id,
            channel_binding_id,
            task_id,
            run_id,
            agent_role: "assistant".to_owned(),
            task_risk: RiskClass::High,
            tool: descriptor,
            normalized_arguments: json!({"left": 1, "right": 2}),
            target_resources: vec![target.clone()],
            workspace_roots: Vec::new(),
            resource_claims: vec![format!("mcp-effect:{target}")],
            secret_references: Vec::new(),
            network_destinations: Vec::new(),
            requested_capability: capability.clone(),
            requested_profile: PolicyProfile::ServiceOperator,
            enforceable_profiles: vec![PolicyProfile::ServiceOperator],
            evaluated_at_ms: 100,
            policy_version: MCP_EFFECT_POLICY_VERSION.to_owned(),
        };
        let evaluation = evaluate_mcp_effect_policy(&request, &grant);
        assert_eq!(evaluation.decision, PolicyDecision::RequireApproval);
        assert_eq!(evaluation.obligations.maximum_processes, 1);
        assert!(evaluation.obligations.allow_process_spawn);
        let subject =
            mcp_effect_approval_subject(EffectId::new(), &request, &grant, 900).expect("subject");
        assert_eq!(subject.capability_scope, capability);

        let mut forged = request.clone();
        forged.normalized_arguments = json!({"left": 1});
        assert_eq!(
            evaluate_mcp_effect_policy(&forged, &grant).decision,
            PolicyDecision::Deny
        );
        let mut forged = request;
        forged.network_destinations = vec!["https://elsewhere.example".to_owned()];
        assert_eq!(
            evaluate_mcp_effect_policy(&forged, &grant).decision,
            PolicyDecision::Deny
        );
    }

    #[test]
    fn remote_schema_resolution_and_task_required_tools_fail_closed() {
        let mut remote = definition("remote");
        remote["inputSchema"] = json!({"type": "object", "$ref": "https://example.test/x"});
        assert!(McpToolGrant::new(remote, 1_000, 1_024).is_err());

        let mut task = definition("task");
        task["execution"] = json!({"taskSupport": "required"});
        assert!(McpToolGrant::new(task, 1_000, 1_024).is_err());
    }

    #[test]
    fn streamable_http_grant_pins_endpoint_credential_and_toolset() {
        let grant = McpToolGrant::new(definition("lookup"), 5_000, 64 * 1024).expect("grant");
        let discovery = McpServerDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "remote-fixture", "version": "1"}),
            tools: vec![McpToolInspection {
                definition: grant.definition().clone(),
                definition_digest: grant.definition_digest().to_owned(),
            }],
        };
        let server = McpHttpServerConfig::new(
            "remote".to_owned(),
            "https://mcp.example.test/mcp".to_owned(),
            McpHttpAuthentication::Bearer {
                credential: ProviderCredentialReference::Broker {
                    secret_id: "mcp-remote".to_owned(),
                },
            },
            discovery.toolset_digest().expect("toolset digest"),
            true,
            vec![grant.clone()],
            Vec::new(),
            Vec::new(),
        )
        .expect("HTTP server");
        assert_eq!(
            server.endpoint_origin().expect("endpoint origin"),
            "https://mcp.example.test"
        );
        assert!(validate_mcp_http_server_set(&[], std::slice::from_ref(&server)).is_ok());
        let descriptor = mcp_http_read_tool_descriptor(&server, &grant).expect("descriptor");
        descriptor.validate_evidence().expect("descriptor evidence");
        assert_eq!(descriptor.tool_id, "mcp.remote.tool.lookup");
        assert!(
            descriptor
                .required_capability
                .starts_with("mcp.http.invoke:remote:tool.lookup:sha256:")
        );
        assert!(
            descriptor
                .required_capability
                .contains(":authority-sha256:")
        );
        assert_eq!(
            server
                .capability_network_destination()
                .expect("network destination"),
            "origin:https://mcp.example.test"
        );
        assert_eq!(
            server.capability_secret_reference().as_deref(),
            Some("broker:mcp-remote")
        );
        let effectful = McpToolGrant::new_with_effect(
            definition("lookup"),
            McpToolEffect::Idempotent,
            5_000,
            64 * 1024,
        )
        .expect("effectful HTTP grant");
        let effect_server = McpHttpServerConfig::new(
            "remote".to_owned(),
            "https://mcp.example.test/mcp".to_owned(),
            server.authentication().clone(),
            server.catalog_digest().to_owned(),
            true,
            vec![effectful.clone()],
            Vec::new(),
            Vec::new(),
        )
        .expect("effectful HTTP server");
        assert!(mcp_http_read_tool_descriptor(&effect_server, &effectful).is_err());
        let effect_descriptor =
            mcp_http_effect_tool_descriptor(&effect_server, &effectful).expect("effect descriptor");
        assert_eq!(effect_descriptor.effect_class, EffectClass::Idempotent);
        assert_eq!(effect_descriptor.risk_class, RiskClass::Medium);
        assert_eq!(effect_descriptor.idempotency, IdempotencyClass::Idempotent);
        assert_eq!(effect_descriptor.recovery, RecoveryStrategy::Retry);
        assert!(effect_descriptor.required_capabilities[0].contains(":authority-sha256:"));
    }

    #[test]
    fn streamable_http_oauth_grant_binds_exact_audience_and_descriptor_authority() {
        let grant = McpToolGrant::new(definition("lookup"), 5_000, 64 * 1024).expect("grant");
        let oauth = McpOAuthTokenGrant::new(
            "remote-oauth".to_owned(),
            "https://mcp.example.test/mcp".to_owned(),
            "https://auth.example.test".to_owned(),
            "https://auth.example.test/token".to_owned(),
            "mealy-native".to_owned(),
            vec!["mcp:read".to_owned()],
            "a".repeat(64),
        )
        .expect("OAuth grant");
        let server = McpHttpServerConfig::new(
            "remote".to_owned(),
            "https://mcp.example.test/mcp".to_owned(),
            McpHttpAuthentication::OAuth {
                grant: oauth.clone(),
            },
            "b".repeat(64),
            true,
            vec![grant.clone()],
            Vec::new(),
            Vec::new(),
        )
        .expect("OAuth HTTP server");
        assert_eq!(
            server.capability_secret_reference().as_deref(),
            Some("mcp_oauth_broker:remote-oauth")
        );
        let descriptor = mcp_http_read_tool_descriptor(&server, &grant).expect("descriptor");
        descriptor.validate_evidence().expect("descriptor evidence");
        assert!(
            descriptor
                .required_capability
                .contains(":authority-sha256:")
        );

        let wrong_audience = McpHttpServerConfig::new(
            "remote".to_owned(),
            "https://other.example.test/mcp".to_owned(),
            McpHttpAuthentication::OAuth { grant: oauth },
            "b".repeat(64),
            true,
            vec![grant],
            Vec::new(),
            Vec::new(),
        );
        assert!(wrong_audience.is_err());
    }

    #[test]
    fn streamable_http_endpoint_fails_closed_for_ambiguous_or_private_authority() {
        let grant = McpToolGrant::new(definition("lookup"), 5_000, 64 * 1024).expect("grant");
        for endpoint in [
            "http://localhost:3000/mcp",
            "http://10.0.0.1/mcp",
            "https://10.0.0.1/mcp",
            "https://user@example.test/mcp",
            "https://example.test/mcp?tenant=other",
            "https://example.test/mcp#fragment",
        ] {
            assert!(
                McpHttpServerConfig::new(
                    "remote".to_owned(),
                    endpoint.to_owned(),
                    McpHttpAuthentication::None,
                    "a".repeat(64),
                    true,
                    vec![grant.clone()],
                    Vec::new(),
                    Vec::new(),
                )
                .is_err(),
                "{endpoint} unexpectedly passed"
            );
        }
        assert!(
            McpHttpServerConfig::new(
                "local".to_owned(),
                "http://127.0.0.1:3000/mcp".to_owned(),
                McpHttpAuthentication::None,
                "a".repeat(64),
                true,
                vec![grant],
                Vec::new(),
                Vec::new(),
            )
            .is_ok()
        );
    }

    #[test]
    fn http_catalog_pins_resources_templates_and_prompts_with_distinct_descriptors() {
        let resource_definition = json!({
            "uri": "fixture://docs/readme",
            "name": "readme",
            "description": "Documentation",
            "mimeType": "text/markdown"
        });
        let template_definition = json!({
            "uriTemplate": "fixture://docs/{name}",
            "name": "document"
        });
        let prompt_definition = json!({
            "name": "review",
            "description": "Review one topic",
            "arguments": [{"name": "topic", "required": true}]
        });
        let resource = McpResourceGrant::new(resource_definition.clone(), 5_000, 64 * 1_024)
            .expect("resource");
        let prompt =
            McpPromptGrant::new(prompt_definition.clone(), 5_000, 64 * 1_024).expect("prompt");
        let discovery = McpHttpCatalogDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "catalog", "version": "1"}),
            tools_capability: None,
            resources_capability: Some(json!({})),
            prompts_capability: Some(json!({})),
            tools: Vec::new(),
            resources: vec![McpCatalogItemInspection {
                definition: resource_definition,
                definition_digest: resource.definition_digest().to_owned(),
            }],
            resource_templates: vec![McpCatalogItemInspection {
                definition: template_definition.clone(),
                definition_digest: mcp_resource_template_definition_digest(&template_definition)
                    .expect("template digest"),
            }],
            prompts: vec![McpCatalogItemInspection {
                definition: prompt_definition,
                definition_digest: prompt.definition_digest().to_owned(),
            }],
        };
        let server = McpHttpServerConfig::new(
            "catalog".to_owned(),
            "https://mcp.example.test/mcp".to_owned(),
            McpHttpAuthentication::None,
            discovery.catalog_digest().expect("catalog digest"),
            true,
            Vec::new(),
            vec![resource.clone()],
            vec![prompt.clone()],
        )
        .expect("server");
        let resource_descriptor =
            mcp_http_resource_read_descriptor(&server, &resource).expect("resource descriptor");
        let prompt_descriptor =
            mcp_http_prompt_read_descriptor(&server, &prompt).expect("prompt descriptor");
        resource_descriptor
            .validate_evidence()
            .expect("resource evidence");
        prompt_descriptor
            .validate_evidence()
            .expect("prompt evidence");
        assert!(
            resource_descriptor
                .tool_id
                .starts_with("mcp.catalog.resource.")
        );
        assert_eq!(prompt_descriptor.tool_id, "mcp.catalog.prompt.review");
        assert!(validate_mcp_prompt_arguments(&prompt, &json!({"topic": "alpha"})).is_ok());
        assert!(validate_mcp_prompt_arguments(&prompt, &json!({})).is_err());
        assert!(validate_mcp_prompt_arguments(&prompt, &json!({"topic": 7})).is_err());

        let mut changed = discovery;
        changed.prompts[0].definition["description"] = json!("drifted");
        changed.prompts[0].definition_digest =
            mcp_prompt_definition_digest(&changed.prompts[0].definition)
                .expect("changed prompt digest");
        assert_ne!(
            changed.catalog_digest().expect("changed digest"),
            server.catalog_digest()
        );
    }

    #[test]
    fn discovery_requires_unique_canonical_tool_order() {
        let right = McpToolGrant::new(definition("right"), 1_000, 1_024).expect("right");
        let left = McpToolGrant::new(definition("left"), 1_000, 1_024).expect("left");
        let discovery = McpServerDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "fixture", "version": "1"}),
            tools: vec![
                McpToolInspection {
                    definition: left.definition().clone(),
                    definition_digest: left.definition_digest().to_owned(),
                },
                McpToolInspection {
                    definition: right.definition().clone(),
                    definition_digest: right.definition_digest().to_owned(),
                },
            ],
        };
        assert_eq!(discovery.validate(), Ok(()));
        let mut reversed = discovery;
        reversed.tools.reverse();
        assert!(reversed.validate().is_err());
    }
}
