use crate::{ProviderCredentialReference, ReadToolDescriptor, ReadToolError, sha256_digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr, path::Path, time::Duration};
use thiserror::Error;
use url::Url;

/// Exact MCP protocol revision implemented by Mealy's local stdio client.
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
/// Maximum owner-reviewed tools exposed from one configured MCP server.
pub const MCP_MAXIMUM_TOOLS_PER_SERVER: usize = 64;
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
const MCP_MAXIMUM_TIMEOUT_MS: u64 = 60_000;
const MCP_MINIMUM_TIMEOUT_MS: u64 = 100;

/// One exact MCP tool definition reviewed and granted by the owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpToolGrant {
    definition: Value,
    definition_digest: String,
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
        let definition_digest = mcp_tool_definition_digest(&definition)?;
        let grant = Self {
            definition,
            definition_digest,
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
            .unwrap_or("Invokes an owner-reviewed read-only MCP tool")
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
}

impl McpHttpAuthentication {
    /// Returns the configured credential reference, if any.
    #[must_use]
    pub const fn credential(&self) -> Option<&ProviderCredentialReference> {
        match self {
            Self::None => None,
            Self::Bearer { credential } => Some(credential),
        }
    }

    fn validate(&self) -> Result<(), McpConfigError> {
        match self {
            Self::None => Ok(()),
            Self::Bearer { credential } => credential
                .validate()
                .map_err(|_| McpConfigError::InvalidServer),
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
    toolset_digest: String,
    enabled: bool,
    tools: Vec<McpToolGrant>,
}

impl McpHttpServerConfig {
    /// Constructs a complete owner-reviewed Streamable HTTP server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for an unsafe endpoint, identity, credential reference,
    /// discovery digest, grant, ordering, or bound.
    pub fn new(
        server_id: String,
        endpoint: String,
        authentication: McpHttpAuthentication,
        toolset_digest: String,
        enabled: bool,
        mut tools: Vec<McpToolGrant>,
    ) -> Result<Self, McpConfigError> {
        tools.sort_by(|left, right| left.remote_name().cmp(right.remote_name()));
        let config = Self {
            server_id,
            endpoint,
            authentication,
            toolset_digest,
            enabled,
            tools,
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

    /// SHA-256 binding the negotiated revision and complete advertised tool list.
    #[must_use]
    pub fn toolset_digest(&self) -> &str {
        &self.toolset_digest
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
        format!("mcp.{}.{}", self.server_id, remote_name)
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
        self.authentication
            .credential()
            .map(ProviderCredentialReference::capability_reference)
    }

    /// Validates one complete Streamable HTTP server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`McpConfigError`] for malformed or non-canonical state.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        if self.endpoint_config().validate().is_err()
            || !crate::is_sha256_digest(&self.toolset_digest)
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

fn validated_mcp_http_endpoint(value: &str) -> Option<Url> {
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

/// Builds the immutable Mealy read-tool descriptor for one exact configured MCP grant.
///
/// # Errors
///
/// Returns a descriptor evidence error when canonical material cannot be represented.
pub fn mcp_read_tool_descriptor(
    server: &McpServerConfig,
    grant: &McpToolGrant,
) -> Result<ReadToolDescriptor, crate::ToolDescriptorEvidenceError> {
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
                .credential()
                .map(ProviderCredentialReference::capability_reference),
            "serverToolsetDigest": server.toolset_digest(),
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
            "mcp.http.invoke:{}:{}:sha256:{transport_identity_digest}:authority-sha256:{authority_digest}",
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
    !value.is_empty()
        && value.len() <= maximum
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
    /// Advertised tool definition is malformed, oversized, or unsupported.
    #[error("MCP tool definition is invalid")]
    InvalidToolDefinition,
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
        MCP_PROTOCOL_VERSION, McpHttpAuthentication, McpHttpServerConfig, McpServerConfig,
        McpServerDiscovery, McpToolGrant, McpToolInspection, mcp_http_read_tool_descriptor,
        mcp_read_tool_descriptor, validate_mcp_http_server_set, validate_mcp_tool_arguments,
    };
    use crate::ProviderCredentialReference;
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
        )
        .expect("HTTP server");
        assert_eq!(
            server.endpoint_origin().expect("endpoint origin"),
            "https://mcp.example.test"
        );
        assert!(validate_mcp_http_server_set(&[], std::slice::from_ref(&server)).is_ok());
        let descriptor = mcp_http_read_tool_descriptor(&server, &grant).expect("descriptor");
        descriptor.validate_evidence().expect("descriptor evidence");
        assert_eq!(descriptor.tool_id, "mcp.remote.lookup");
        assert!(
            descriptor
                .required_capability
                .starts_with("mcp.http.invoke:remote:lookup:sha256:")
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
            )
            .is_ok()
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
