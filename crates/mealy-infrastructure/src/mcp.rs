use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use mealy_application::{
    CancellationProbe, MCP_MAXIMUM_PROMPTS_PER_SERVER, MCP_MAXIMUM_RESOURCE_TEMPLATES_PER_SERVER,
    MCP_MAXIMUM_RESOURCES_PER_SERVER, MCP_MAXIMUM_TOOLS_PER_SERVER, MCP_PROTOCOL_VERSION,
    McpCatalogItemInspection, McpHttpAuthentication, McpHttpCatalogDiscovery,
    McpHttpEndpointConfig, McpHttpServerConfig, McpPromptGrant, McpResourceGrant, McpServerConfig,
    McpServerDiscovery, McpToolGrant, McpToolInspection, ReadOnlyTool, ReadToolDescriptor,
    ReadToolError, ReadToolOutput, mcp_http_prompt_read_descriptor, mcp_http_read_tool_descriptor,
    mcp_http_resource_read_descriptor, mcp_prompt_definition_digest, mcp_read_tool_descriptor,
    mcp_resource_definition_digest, mcp_resource_template_definition_digest,
    mcp_tool_definition_digest, sha256_digest, validate_mcp_prompt_arguments,
    validate_mcp_tool_arguments,
};
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, ORIGIN},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const MCP_LAUNCHER_ARGUMENT: &str = "--mcp-stdio-launcher";
const MCP_SANDBOX_LAUNCHER: &str = "/runtime/mealy-mcp-launcher";
const MCP_SANDBOX_SERVER: &str = "/mcp/server";
const MCP_MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MCP_MAXIMUM_MESSAGE_BYTES: usize = 1024 * 1024;
const MCP_MAXIMUM_STDOUT_BYTES: usize = 4 * 1024 * 1024;
const MCP_MAXIMUM_STDERR_BYTES: u64 = 64 * 1024;
const MCP_MAXIMUM_MESSAGES: usize = 256;
const MCP_MAXIMUM_LIST_PAGES: usize = 16;
const MCP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const MCP_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MCP_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const MCP_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MCP_HTTP_MAXIMUM_BODY_BYTES: u64 = 4 * 1024 * 1024;
const MCP_HTTP_MAXIMUM_SESSION_ID_BYTES: usize = 1_024;
const MCP_HTTP_MAXIMUM_EVENT_ID_BYTES: usize = 1_024;
const MCP_SESSION_ID_HEADER: HeaderName = HeaderName::from_static("mcp-session-id");
const MCP_PROTOCOL_VERSION_HEADER: HeaderName = HeaderName::from_static("mcp-protocol-version");

/// Reads the complete tool list from one digest-pinned MCP executable inside the hardened local
/// stdio sandbox. Discovery executes server code, so callers must require explicit owner intent.
///
/// # Errors
///
/// Returns [`McpHostError`] for executable identity changes, unavailable sandbox enforcement,
/// timeout, malformed MCP, unsupported protocol/capabilities, or unbounded output.
pub fn discover_mcp_stdio_server(
    bubblewrap_path: impl AsRef<Path>,
    launcher_path: impl AsRef<Path>,
    server_id: &str,
    executable_path: impl AsRef<Path>,
    executable_digest: &str,
    arguments: &[String],
) -> Result<McpServerDiscovery, McpHostError> {
    let endpoint = McpStdioEndpoint::new(
        bubblewrap_path.as_ref(),
        launcher_path.as_ref(),
        server_id,
        executable_path.as_ref(),
        executable_digest,
        arguments,
    )?;
    endpoint.discover(&NeverCancelled, MCP_DISCOVERY_TIMEOUT)
}

/// Builds and startup-verifies every enabled MCP tool before it can enter a model context epoch.
///
/// Disabled servers are validated by the daemon configuration layer but are never launched. Every
/// enabled server must reproduce the exact protocol/toolset digest and every exact reviewed tool
/// definition, otherwise startup fails closed.
///
/// # Errors
///
/// Returns [`McpHostError`] when installed content, the sandbox, discovery, or a grant pin fails.
pub fn load_mcp_read_tools(
    home: &Path,
    bubblewrap_path: &Path,
    launcher_path: &Path,
    servers: &[McpServerConfig],
) -> Result<Vec<McpReadTool>, McpHostError> {
    let home = fs::canonicalize(home)
        .map_err(|error| McpHostError::Io(format!("cannot canonicalize Mealy home: {error}")))?;
    let mut result = Vec::new();
    for server in servers.iter().filter(|server| server.enabled()) {
        server
            .validate()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        let requested = home.join(server.executable_path());
        let endpoint = Arc::new(McpStdioEndpoint::new(
            bubblewrap_path,
            launcher_path,
            server.server_id(),
            &requested,
            server.executable_digest(),
            server.arguments(),
        )?);
        let discovery = endpoint.discover(&NeverCancelled, MCP_DISCOVERY_TIMEOUT)?;
        verify_discovery(server, &discovery)?;
        for grant in server.tools() {
            result.push(McpReadTool::new(
                Arc::clone(&endpoint),
                server.clone(),
                grant.clone(),
            )?);
        }
    }
    result.sort_by(|left, right| left.descriptor.tool_id.cmp(&right.descriptor.tool_id));
    if result
        .windows(2)
        .any(|window| window[0].descriptor.tool_id == window[1].descriptor.tool_id)
    {
        return Err(McpHostError::InvalidConfiguration);
    }
    Ok(result)
}

/// Inspects one Streamable HTTP MCP server through an SSRF-resistant, redirect-free connection.
///
/// # Errors
///
/// Returns [`McpHostError`] for invalid configuration, missing or rejected credentials, unsafe
/// resolution, timeout, unsupported media framing, protocol violations, or unbounded discovery.
pub fn discover_mcp_http_server(
    server: &McpHttpServerConfig,
    credential: Option<Zeroizing<String>>,
) -> Result<McpHttpCatalogDiscovery, McpHostError> {
    let endpoint = McpHttpEndpoint::new(&server.endpoint_config(), credential.map(Arc::new))?;
    let discovery = endpoint.discover(&NeverCancelled, MCP_DISCOVERY_TIMEOUT)?;
    verify_http_discovery(server, &discovery)?;
    Ok(discovery)
}

/// Performs one fresh owner-requested discovery against an uninstalled Streamable HTTP endpoint.
///
/// The returned inventory remains untrusted until the owner selects exact tools, resources, or
/// prompts and persists the resulting complete catalog and definition digests in
/// [`McpHttpServerConfig`].
///
/// # Errors
///
/// Returns [`McpHostError`] for unsafe endpoint authority, credential mismatch, timeout, malformed
/// protocol, unsupported capabilities, or bounded-output violations.
pub fn inspect_mcp_http_endpoint(
    config: &McpHttpEndpointConfig,
    credential: Option<Zeroizing<String>>,
) -> Result<McpHttpCatalogDiscovery, McpHostError> {
    McpHttpEndpoint::new(config, credential.map(Arc::new))?
        .discover(&NeverCancelled, MCP_DISCOVERY_TIMEOUT)
}

/// Builds and startup-verifies all enabled Streamable HTTP MCP read tools.
///
/// Credentials are keyed by logical server identity and consumed into process-private endpoint
/// instances. Configuration and returned descriptors retain only opaque credential references.
///
/// # Errors
///
/// Returns [`McpHostError`] when endpoint authority, credential cardinality, discovery evidence,
/// or a reviewed tool definition fails closed.
pub fn load_mcp_http_read_tools(
    servers: &[McpHttpServerConfig],
    mut credentials: BTreeMap<String, Zeroizing<String>>,
) -> Result<Vec<McpHttpReadTool>, McpHostError> {
    let mut result = Vec::new();
    for server in servers.iter().filter(|server| server.enabled()) {
        server
            .validate()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        let credential = credentials.remove(server.server_id()).map(Arc::new);
        let requires_credential = matches!(
            server.authentication(),
            McpHttpAuthentication::Bearer { .. }
        );
        if requires_credential != credential.is_some() {
            return Err(McpHostError::InvalidConfiguration);
        }
        let endpoint = Arc::new(McpHttpEndpoint::new(&server.endpoint_config(), credential)?);
        let discovery = endpoint.discover(&NeverCancelled, MCP_DISCOVERY_TIMEOUT)?;
        verify_http_discovery(server, &discovery)?;
        for grant in server.tools() {
            result.push(McpHttpReadTool::Tool(McpHttpToolRead::new(
                Arc::clone(&endpoint),
                server.clone(),
                grant.clone(),
            )?));
        }
        for grant in server.resources() {
            result.push(McpHttpReadTool::Resource(McpHttpResourceRead::new(
                Arc::clone(&endpoint),
                server.clone(),
                grant.clone(),
            )?));
        }
        for grant in server.prompts() {
            result.push(McpHttpReadTool::Prompt(McpHttpPromptRead::new(
                Arc::clone(&endpoint),
                server.clone(),
                grant.clone(),
            )?));
        }
    }
    if !credentials.is_empty() {
        return Err(McpHostError::InvalidConfiguration);
    }
    result.sort_by(|left, right| left.descriptor().tool_id.cmp(&right.descriptor().tool_id));
    if result
        .windows(2)
        .any(|window| window[0].descriptor().tool_id == window[1].descriptor().tool_id)
    {
        return Err(McpHostError::InvalidConfiguration);
    }
    Ok(result)
}

fn verify_http_discovery(
    server: &McpHttpServerConfig,
    discovery: &McpHttpCatalogDiscovery,
) -> Result<(), McpHostError> {
    if discovery
        .catalog_digest()
        .map_err(|_| McpHostError::InvalidProtocol)?
        != server.catalog_digest()
        || server.tools().iter().any(|grant| {
            discovery
                .tool(grant.remote_name())
                .is_none_or(|discovered| {
                    discovered.definition_digest != grant.definition_digest()
                        || discovered.definition != *grant.definition()
                })
        })
        || server.resources().iter().any(|grant| {
            discovery.resource(grant.uri()).is_none_or(|discovered| {
                discovered.definition_digest != grant.definition_digest()
                    || discovered.definition != *grant.definition()
            })
        })
        || server.prompts().iter().any(|grant| {
            discovery
                .prompt(grant.remote_name())
                .is_none_or(|discovered| {
                    discovered.definition_digest != grant.definition_digest()
                        || discovered.definition != *grant.definition()
                })
        })
    {
        return Err(McpHostError::InventoryDrift);
    }
    Ok(())
}

/// One model-visible governed HTTP MCP catalog operation.
pub enum McpHttpReadTool {
    /// Invoke one exact schema-pinned read-only remote tool.
    Tool(McpHttpToolRead),
    /// Read one exact owner-selected remote resource URI.
    Resource(McpHttpResourceRead),
    /// Retrieve one exact owner-selected prompt as untrusted evidence.
    Prompt(McpHttpPromptRead),
}

impl std::fmt::Debug for McpHttpReadTool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpHttpReadTool")
            .field("tool_id", &self.descriptor().tool_id)
            .finish_non_exhaustive()
    }
}

impl ReadOnlyTool for McpHttpReadTool {
    fn descriptor(&self) -> ReadToolDescriptor {
        match self {
            Self::Tool(tool) => tool.descriptor(),
            Self::Resource(tool) => tool.descriptor(),
            Self::Prompt(tool) => tool.descriptor(),
        }
    }

    fn validate_arguments(&self, arguments: &Value) -> Result<(), ReadToolError> {
        match self {
            Self::Tool(tool) => tool.validate_arguments(arguments),
            Self::Resource(tool) => tool.validate_arguments(arguments),
            Self::Prompt(tool) => tool.validate_arguments(arguments),
        }
    }

    fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        match self {
            Self::Tool(tool) => tool.execute(arguments, cancellation),
            Self::Resource(tool) => tool.execute(arguments, cancellation),
            Self::Prompt(tool) => tool.execute(arguments, cancellation),
        }
    }
}

/// One exact HTTP MCP read-only tool invocation.
pub struct McpHttpToolRead {
    endpoint: Arc<McpHttpEndpoint>,
    server: McpHttpServerConfig,
    grant: McpToolGrant,
    descriptor: ReadToolDescriptor,
}

impl std::fmt::Debug for McpHttpToolRead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpHttpReadTool")
            .field("tool_id", &self.descriptor.tool_id)
            .field("endpoint_origin", &self.server.endpoint_origin().ok())
            .field(
                "credential_configured",
                &self.endpoint.authorization.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl McpHttpToolRead {
    fn new(
        endpoint: Arc<McpHttpEndpoint>,
        server: McpHttpServerConfig,
        grant: McpToolGrant,
    ) -> Result<Self, McpHostError> {
        let descriptor = mcp_http_read_tool_descriptor(&server, &grant)
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        descriptor
            .validate_evidence()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        Ok(Self {
            endpoint,
            server,
            grant,
            descriptor,
        })
    }
}

impl ReadOnlyTool for McpHttpToolRead {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &Value) -> Result<(), ReadToolError> {
        validate_mcp_tool_arguments(&self.grant, arguments)
    }

    fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        self.validate_arguments(arguments)?;
        let output = self
            .endpoint
            .call(
                &self.server,
                &self.grant,
                arguments,
                cancellation,
                Duration::from_millis(self.grant.timeout_ms()),
            )
            .map_err(|error| map_read_error(error, self.grant.maximum_output_bytes()))?;
        let bytes = serde_json::to_vec(&output).map_err(|_| {
            ReadToolError::Unavailable("MCP result normalization failed".to_owned())
        })?;
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual > self.grant.maximum_output_bytes() {
            return Err(ReadToolError::OutputTooLarge {
                actual,
                maximum: self.grant.maximum_output_bytes(),
            });
        }
        Ok(ReadToolOutput {
            media_type: "application/json".to_owned(),
            bytes,
            source_locator: format!(
                "mcp://{}/{}",
                self.server.server_id(),
                self.grant.remote_name()
            ),
        })
    }
}

/// One exact HTTP MCP resource read exposed as ordinary untrusted evidence.
pub struct McpHttpResourceRead {
    endpoint: Arc<McpHttpEndpoint>,
    server: McpHttpServerConfig,
    grant: McpResourceGrant,
    descriptor: ReadToolDescriptor,
}

impl McpHttpResourceRead {
    fn new(
        endpoint: Arc<McpHttpEndpoint>,
        server: McpHttpServerConfig,
        grant: McpResourceGrant,
    ) -> Result<Self, McpHostError> {
        let descriptor = mcp_http_resource_read_descriptor(&server, &grant)
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        descriptor
            .validate_evidence()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        Ok(Self {
            endpoint,
            server,
            grant,
            descriptor,
        })
    }
}

impl ReadOnlyTool for McpHttpResourceRead {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &Value) -> Result<(), ReadToolError> {
        if arguments.as_object().is_some_and(serde_json::Map::is_empty) {
            Ok(())
        } else {
            Err(ReadToolError::InvalidArguments(
                "MCP resource reads accept an empty object".to_owned(),
            ))
        }
    }

    fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        self.validate_arguments(arguments)?;
        let output = self
            .endpoint
            .read_resource(
                &self.server,
                &self.grant,
                cancellation,
                Duration::from_millis(self.grant.timeout_ms()),
            )
            .map_err(|error| map_read_error(error, self.grant.maximum_output_bytes()))?;
        bounded_catalog_output(
            &output,
            self.grant.maximum_output_bytes(),
            format!(
                "mcp://{}/resource/{}",
                self.server.server_id(),
                self.grant.definition_digest()
            ),
        )
    }
}

/// One exact HTTP MCP prompt retrieval exposed as ordinary untrusted evidence.
pub struct McpHttpPromptRead {
    endpoint: Arc<McpHttpEndpoint>,
    server: McpHttpServerConfig,
    grant: McpPromptGrant,
    descriptor: ReadToolDescriptor,
}

impl McpHttpPromptRead {
    fn new(
        endpoint: Arc<McpHttpEndpoint>,
        server: McpHttpServerConfig,
        grant: McpPromptGrant,
    ) -> Result<Self, McpHostError> {
        let descriptor = mcp_http_prompt_read_descriptor(&server, &grant)
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        descriptor
            .validate_evidence()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        Ok(Self {
            endpoint,
            server,
            grant,
            descriptor,
        })
    }
}

impl ReadOnlyTool for McpHttpPromptRead {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &Value) -> Result<(), ReadToolError> {
        validate_mcp_prompt_arguments(&self.grant, arguments)
    }

    fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        self.validate_arguments(arguments)?;
        let output = self
            .endpoint
            .get_prompt(
                &self.server,
                &self.grant,
                arguments,
                cancellation,
                Duration::from_millis(self.grant.timeout_ms()),
            )
            .map_err(|error| map_read_error(error, self.grant.maximum_output_bytes()))?;
        bounded_catalog_output(
            &output,
            self.grant.maximum_output_bytes(),
            format!(
                "mcp://{}/prompt/{}",
                self.server.server_id(),
                self.grant.remote_name()
            ),
        )
    }
}

fn bounded_catalog_output(
    output: &Value,
    maximum: u64,
    source_locator: String,
) -> Result<ReadToolOutput, ReadToolError> {
    let bytes = serde_json::to_vec(&output)
        .map_err(|_| ReadToolError::Unavailable("MCP result normalization failed".to_owned()))?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > maximum {
        return Err(ReadToolError::OutputTooLarge { actual, maximum });
    }
    Ok(ReadToolOutput {
        media_type: "application/json".to_owned(),
        bytes,
        source_locator,
    })
}

struct McpHttpEndpoint {
    client: Option<Client>,
    endpoint: Url,
    authorization: Option<Arc<Zeroizing<String>>>,
}

impl std::fmt::Debug for McpHttpEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpHttpEndpoint")
            .field("origin", &self.endpoint.origin().ascii_serialization())
            .field("credential_configured", &self.authorization.is_some())
            .finish_non_exhaustive()
    }
}

impl McpHttpEndpoint {
    fn new(
        config: &McpHttpEndpointConfig,
        authorization: Option<Arc<Zeroizing<String>>>,
    ) -> Result<Self, McpHostError> {
        config
            .validate()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        let requires_credential = matches!(
            config.authentication(),
            McpHttpAuthentication::Bearer { .. }
        );
        if requires_credential != authorization.is_some() {
            return Err(McpHostError::InvalidConfiguration);
        }
        let endpoint =
            Url::parse(config.endpoint()).map_err(|_| McpHostError::InvalidConfiguration)?;
        let authority = mealy_application::WebAccessConfig {
            enabled: true,
            allow_public_internet: false,
            allowed_domains: Vec::new(),
            allowed_origins: vec![endpoint.origin().ascii_serialization()],
            search: None,
        };
        authority
            .validate()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        let sockets = crate::web::resolve_pinned_web_destination(&endpoint, &authority)
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        let host = endpoint
            .host_str()
            .ok_or(McpHostError::InvalidConfiguration)?;
        let client = Client::builder()
            .connect_timeout(MCP_HTTP_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve_to_addrs(host, &sockets)
            .build()
            .map_err(|error| McpHostError::Io(format!("MCP HTTP client failed: {error}")))?;
        Ok(Self {
            client: Some(client),
            endpoint,
            authorization,
        })
    }

    fn discover(
        &self,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<McpHttpCatalogDiscovery, McpHostError> {
        let started = Instant::now();
        let session = self.initialize(cancellation, started, timeout)?;
        let discovery = self.discover_catalog(&session, cancellation, started, timeout);
        self.close(&session);
        discovery
    }

    fn call(
        &self,
        server: &McpHttpServerConfig,
        grant: &McpToolGrant,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<Value, McpHostError> {
        let started = Instant::now();
        let session = self.initialize(cancellation, started, timeout)?;
        let result = (|| {
            let discovery = self.discover_catalog(&session, cancellation, started, timeout)?;
            verify_http_discovery(server, &discovery)?;
            let remaining = timeout
                .checked_sub(started.elapsed())
                .ok_or(McpHostError::TimedOut)?;
            let result = self.request(
                &session,
                10_000,
                "tools/call",
                &json!({"name": grant.remote_name(), "arguments": arguments}),
                cancellation,
                remaining,
            )?;
            normalize_tool_result(&result, server.server_id(), grant)
        })();
        self.close(&session);
        result
    }

    fn read_resource(
        &self,
        server: &McpHttpServerConfig,
        grant: &McpResourceGrant,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<Value, McpHostError> {
        let started = Instant::now();
        let session = self.initialize(cancellation, started, timeout)?;
        let result = (|| {
            let discovery = self.discover_catalog(&session, cancellation, started, timeout)?;
            verify_http_discovery(server, &discovery)?;
            let remaining = timeout
                .checked_sub(started.elapsed())
                .ok_or(McpHostError::TimedOut)?;
            let result = self.request(
                &session,
                20_000,
                "resources/read",
                &json!({"uri": grant.uri()}),
                cancellation,
                remaining,
            )?;
            normalize_resource_result(&result, server.server_id(), grant)
        })();
        self.close(&session);
        result
    }

    fn get_prompt(
        &self,
        server: &McpHttpServerConfig,
        grant: &McpPromptGrant,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<Value, McpHostError> {
        let started = Instant::now();
        let session = self.initialize(cancellation, started, timeout)?;
        let result = (|| {
            let discovery = self.discover_catalog(&session, cancellation, started, timeout)?;
            verify_http_discovery(server, &discovery)?;
            let remaining = timeout
                .checked_sub(started.elapsed())
                .ok_or(McpHostError::TimedOut)?;
            let result = self.request(
                &session,
                30_000,
                "prompts/get",
                &json!({"name": grant.remote_name(), "arguments": arguments}),
                cancellation,
                remaining,
            )?;
            normalize_prompt_result(&result, server.server_id(), grant)
        })();
        self.close(&session);
        result
    }

    fn initialize(
        &self,
        cancellation: &dyn CancellationProbe,
        started: Instant,
        timeout: Duration,
    ) -> Result<McpHttpSession, McpHostError> {
        let remaining = timeout
            .checked_sub(started.elapsed())
            .ok_or(McpHostError::TimedOut)?;
        let (initialized, headers) = self.post_request(
            None,
            1,
            "initialize",
            &json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "mealy",
                    "title": "Mealy governed MCP client",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Schema-pinned Streamable HTTP MCP boundary"
                }
            }),
            cancellation,
            remaining,
        )?;
        let session_id = headers
            .get(&MCP_SESSION_ID_HEADER)
            .map(|value| {
                value
                    .to_str()
                    .ok()
                    .filter(|value| {
                        !value.is_empty()
                            && value.len() <= MCP_HTTP_MAXIMUM_SESSION_ID_BYTES
                            && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
                    })
                    .map(|value| Zeroizing::new(value.to_owned()))
                    .ok_or(McpHostError::InvalidProtocol)
            })
            .transpose()?;
        let parsed = (|| {
            let protocol_version = initialized
                .get("protocolVersion")
                .and_then(Value::as_str)
                .filter(|version| *version == MCP_PROTOCOL_VERSION)
                .ok_or(McpHostError::InvalidProtocol)?
                .to_owned();
            let capabilities = initialized
                .get("capabilities")
                .and_then(Value::as_object)
                .ok_or(McpHostError::InvalidProtocol)?;
            let tools_capability = capabilities.get("tools").cloned();
            let resources_capability = capabilities.get("resources").cloned();
            let prompts_capability = capabilities.get("prompts").cloned();
            if [
                &tools_capability,
                &resources_capability,
                &prompts_capability,
            ]
            .into_iter()
            .flatten()
            .any(|capability| !capability.is_object())
                || tools_capability.is_none()
                    && resources_capability.is_none()
                    && prompts_capability.is_none()
            {
                return Err(McpHostError::InvalidProtocol);
            }
            let server_info = initialized
                .get("serverInfo")
                .filter(|value| value.is_object())
                .cloned()
                .ok_or(McpHostError::InvalidProtocol)?;
            Ok(McpHttpSession {
                session_id: session_id.clone(),
                protocol_version,
                server_info,
                tools_capability,
                resources_capability,
                prompts_capability,
            })
        })();
        let session = match parsed {
            Ok(session) => session,
            Err(error) => {
                self.close_session_id(session_id.as_ref().map(|value| value.as_str()));
                return Err(error);
            }
        };
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            self.close(&session);
            return Err(McpHostError::TimedOut);
        };
        if let Err(error) =
            self.post_notification(&session, "notifications/initialized", None, remaining)
        {
            self.close(&session);
            return Err(error);
        }
        Ok(session)
    }

    fn discover_catalog(
        &self,
        session: &McpHttpSession,
        cancellation: &dyn CancellationProbe,
        started: Instant,
        timeout: Duration,
    ) -> Result<McpHttpCatalogDiscovery, McpHostError> {
        let tools = if session.tools_capability.is_some() {
            self.discover_inventory(
                session,
                cancellation,
                started,
                timeout,
                InventoryRequest {
                    method: "tools/list",
                    response_field: "tools",
                    key_field: "name",
                    maximum: MCP_MAXIMUM_TOOLS_PER_SERVER,
                    base_id: 100,
                    digest: mcp_tool_definition_digest,
                },
            )?
            .into_iter()
            .map(|item| McpToolInspection {
                definition: item.definition,
                definition_digest: item.definition_digest,
            })
            .collect()
        } else {
            Vec::new()
        };
        let resources = if session.resources_capability.is_some() {
            self.discover_inventory(
                session,
                cancellation,
                started,
                timeout,
                InventoryRequest {
                    method: "resources/list",
                    response_field: "resources",
                    key_field: "uri",
                    maximum: MCP_MAXIMUM_RESOURCES_PER_SERVER,
                    base_id: 1_000,
                    digest: mcp_resource_definition_digest,
                },
            )?
        } else {
            Vec::new()
        };
        let resource_templates = if session.resources_capability.is_some() {
            self.discover_inventory(
                session,
                cancellation,
                started,
                timeout,
                InventoryRequest {
                    method: "resources/templates/list",
                    response_field: "resourceTemplates",
                    key_field: "uriTemplate",
                    maximum: MCP_MAXIMUM_RESOURCE_TEMPLATES_PER_SERVER,
                    base_id: 2_000,
                    digest: mcp_resource_template_definition_digest,
                },
            )?
        } else {
            Vec::new()
        };
        let prompts = if session.prompts_capability.is_some() {
            self.discover_inventory(
                session,
                cancellation,
                started,
                timeout,
                InventoryRequest {
                    method: "prompts/list",
                    response_field: "prompts",
                    key_field: "name",
                    maximum: MCP_MAXIMUM_PROMPTS_PER_SERVER,
                    base_id: 3_000,
                    digest: mcp_prompt_definition_digest,
                },
            )?
        } else {
            Vec::new()
        };
        let discovery = McpHttpCatalogDiscovery {
            protocol_version: session.protocol_version.clone(),
            server_info: session.server_info.clone(),
            tools_capability: session.tools_capability.clone(),
            resources_capability: session.resources_capability.clone(),
            prompts_capability: session.prompts_capability.clone(),
            tools,
            resources,
            resource_templates,
            prompts,
        };
        discovery
            .validate()
            .map_err(|_| McpHostError::InvalidProtocol)?;
        Ok(discovery)
    }

    #[allow(clippy::too_many_arguments)]
    fn discover_inventory(
        &self,
        session: &McpHttpSession,
        cancellation: &dyn CancellationProbe,
        started: Instant,
        timeout: Duration,
        request: InventoryRequest,
    ) -> Result<Vec<McpCatalogItemInspection>, McpHostError> {
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut items = Vec::new();
        for page in 0..MCP_MAXIMUM_LIST_PAGES {
            let remaining = timeout
                .checked_sub(started.elapsed())
                .ok_or(McpHostError::TimedOut)?;
            let id = request
                .base_id
                .saturating_add(u64::try_from(page).unwrap_or(u64::MAX));
            let params = cursor
                .as_ref()
                .map_or_else(|| json!({}), |value| json!({"cursor": value}));
            let listed = self.request(
                session,
                id,
                request.method,
                &params,
                cancellation,
                remaining,
            )?;
            let page_items = listed
                .get(request.response_field)
                .and_then(Value::as_array)
                .ok_or(McpHostError::InvalidProtocol)?;
            if items.len().saturating_add(page_items.len()) > request.maximum {
                return Err(McpHostError::OutputLimitExceeded);
            }
            for definition in page_items {
                items.push(McpCatalogItemInspection {
                    definition: definition.clone(),
                    definition_digest: (request.digest)(definition)
                        .map_err(|_| McpHostError::InvalidProtocol)?,
                });
            }
            cursor = listed
                .get("nextCursor")
                .map(|value| {
                    value
                        .as_str()
                        .filter(|cursor| {
                            !cursor.is_empty()
                                && cursor.len() <= 1_024
                                && !cursor.chars().any(char::is_control)
                        })
                        .map(str::to_owned)
                        .ok_or(McpHostError::InvalidProtocol)
                })
                .transpose()?;
            let Some(next) = &cursor else {
                break;
            };
            if !seen_cursors.insert(next.clone()) || page + 1 == MCP_MAXIMUM_LIST_PAGES {
                return Err(McpHostError::InvalidProtocol);
            }
        }
        items.sort_by(|left, right| {
            left.definition[request.key_field]
                .as_str()
                .cmp(&right.definition[request.key_field].as_str())
        });
        Ok(items)
    }

    fn request(
        &self,
        session: &McpHttpSession,
        id: u64,
        method: &str,
        params: &Value,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<Value, McpHostError> {
        self.post_request(Some(session), id, method, params, cancellation, timeout)
            .map(|(result, _)| result)
    }

    fn post_request(
        &self,
        session: Option<&McpHttpSession>,
        id: u64,
        method: &str,
        params: &Value,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<(Value, HeaderMap), McpHostError> {
        if cancellation.is_cancelled() {
            return Err(McpHostError::Cancelled);
        }
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let response = self
            .request_builder(
                self.client()?.post(self.endpoint.clone()),
                session
                    .and_then(|session| session.session_id.as_ref())
                    .map(|value| value.as_str()),
            )?
            .header(ACCEPT, "application/json, text/event-stream")
            .json(&request)
            .timeout(timeout)
            .send()
            .map_err(|error| map_http_error(&error))?;
        let headers = response.headers().clone();
        let result = parse_http_response(response, id)?;
        if cancellation.is_cancelled() {
            return Err(McpHostError::Cancelled);
        }
        Ok((result, headers))
    }

    fn post_notification(
        &self,
        session: &McpHttpSession,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<(), McpHostError> {
        let mut message = serde_json::Map::from_iter([
            ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
            ("method".to_owned(), Value::String(method.to_owned())),
        ]);
        if let Some(params) = params {
            message.insert("params".to_owned(), params);
        }
        let response = self
            .request_builder(
                self.client()?.post(self.endpoint.clone()),
                session.session_id.as_ref().map(|value| value.as_str()),
            )?
            .header(ACCEPT, "application/json, text/event-stream")
            .json(&Value::Object(message))
            .timeout(timeout)
            .send()
            .map_err(|error| map_http_error(&error))?;
        match response.status() {
            StatusCode::ACCEPTED => Ok(()),
            StatusCode::UNAUTHORIZED => Err(McpHostError::AuthorizationRequired),
            StatusCode::NOT_FOUND => Err(McpHostError::SessionExpired),
            status => Err(McpHostError::HttpStatus(status.as_u16())),
        }
    }

    fn request_builder(
        &self,
        mut request: reqwest::blocking::RequestBuilder,
        session_id: Option<&str>,
    ) -> Result<reqwest::blocking::RequestBuilder, McpHostError> {
        request = request
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream")
            .header(ORIGIN, self.endpoint.origin().ascii_serialization())
            .header(&MCP_PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_VERSION);
        if let Some(session_id) = session_id {
            let mut header = HeaderValue::from_str(session_id)
                .map_err(|_| McpHostError::InvalidConfiguration)?;
            header.set_sensitive(true);
            request = request.header(&MCP_SESSION_ID_HEADER, header);
        }
        if let Some(authorization) = &self.authorization {
            let mut bearer = Zeroizing::new(String::with_capacity(
                "Bearer ".len() + authorization.as_ref().len(),
            ));
            bearer.push_str("Bearer ");
            bearer.push_str(authorization.as_ref().as_str());
            let mut header = HeaderValue::from_str(bearer.as_str())
                .map_err(|_| McpHostError::InvalidConfiguration)?;
            header.set_sensitive(true);
            request = request.header(AUTHORIZATION, header);
        }
        Ok(request)
    }

    fn close(&self, session: &McpHttpSession) {
        self.close_session_id(session.session_id.as_ref().map(|value| value.as_str()));
    }

    fn close_session_id(&self, session_id: Option<&str>) {
        let Some(session_id) = session_id else {
            return;
        };
        let Ok(client) = self.client() else {
            return;
        };
        let Ok(request) =
            self.request_builder(client.delete(self.endpoint.clone()), Some(session_id))
        else {
            return;
        };
        let _ = request.timeout(Duration::from_secs(1)).send();
    }

    fn client(&self) -> Result<&Client, McpHostError> {
        self.client.as_ref().ok_or(McpHostError::ProcessFailed)
    }
}

impl Drop for McpHttpEndpoint {
    fn drop(&mut self) {
        let Some(client) = self.client.take() else {
            return;
        };
        // reqwest's blocking client owns a small internal async runtime. Drop it on a plain worker
        // thread so daemon teardown is safe even while the composition root is leaving Tokio.
        let worker = thread::Builder::new()
            .name("mealy-mcp-http-client-drop".to_owned())
            .spawn(move || drop(client));
        if let Ok(worker) = worker {
            let _ = worker.join();
        }
    }
}

struct McpHttpSession {
    session_id: Option<Zeroizing<String>>,
    protocol_version: String,
    server_info: Value,
    tools_capability: Option<Value>,
    resources_capability: Option<Value>,
    prompts_capability: Option<Value>,
}

#[derive(Clone, Copy)]
struct InventoryRequest {
    method: &'static str,
    response_field: &'static str,
    key_field: &'static str,
    maximum: usize,
    base_id: u64,
    digest: fn(&Value) -> Result<String, mealy_application::McpConfigError>,
}

fn map_http_error(error: &reqwest::Error) -> McpHostError {
    if error.is_timeout() {
        McpHostError::TimedOut
    } else {
        McpHostError::Io(format!("MCP HTTP request failed: {error}"))
    }
}

fn parse_http_response(response: Response, expected_id: u64) -> Result<Value, McpHostError> {
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => return Err(McpHostError::AuthorizationRequired),
        StatusCode::NOT_FOUND => return Err(McpHostError::SessionExpired),
        status => return Err(McpHostError::HttpStatus(status.as_u16())),
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_owned)
        .ok_or(McpHostError::InvalidProtocol)?;
    let mut bytes = Vec::new();
    response
        .take(MCP_HTTP_MAXIMUM_BODY_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| McpHostError::Io(format!("MCP HTTP response read failed: {error}")))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MCP_HTTP_MAXIMUM_BODY_BYTES {
        return Err(McpHostError::OutputLimitExceeded);
    }
    match content_type.as_str() {
        "application/json" => {
            let message =
                serde_json::from_slice(&bytes).map_err(|_| McpHostError::InvalidProtocol)?;
            jsonrpc_result(&message, expected_id)?.ok_or(McpHostError::InvalidProtocol)
        }
        "text/event-stream" => parse_sse_response(&bytes, expected_id),
        _ => Err(McpHostError::InvalidProtocol),
    }
}

fn parse_sse_response(bytes: &[u8], expected_id: u64) -> Result<Value, McpHostError> {
    let text = std::str::from_utf8(bytes).map_err(|_| McpHostError::InvalidProtocol)?;
    let mut data = Vec::new();
    let mut messages = 0_usize;
    for raw_line in text.split('\n').chain(std::iter::once("")) {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            if data.is_empty() {
                continue;
            }
            messages = messages.saturating_add(1);
            if messages > MCP_MAXIMUM_MESSAGES {
                return Err(McpHostError::OutputLimitExceeded);
            }
            let joined = data.join("\n");
            data.clear();
            if joined.is_empty() {
                continue;
            }
            let message =
                serde_json::from_str(&joined).map_err(|_| McpHostError::InvalidProtocol)?;
            if let Some(result) = jsonrpc_result(&message, expected_id)? {
                return Ok(result);
            }
            continue;
        }
        if line.starts_with(':') || line.starts_with("event:") || line.starts_with("retry:") {
            continue;
        }
        if let Some(event_id) = line.strip_prefix("id:") {
            let event_id = event_id.strip_prefix(' ').unwrap_or(event_id);
            if event_id.len() > MCP_HTTP_MAXIMUM_EVENT_ID_BYTES
                || event_id.contains('\0')
                || event_id.chars().any(char::is_control)
            {
                return Err(McpHostError::InvalidProtocol);
            }
            continue;
        }
        let Some(value) = line.strip_prefix("data:") else {
            return Err(McpHostError::InvalidProtocol);
        };
        data.push(value.strip_prefix(' ').unwrap_or(value));
    }
    Err(McpHostError::InvalidProtocol)
}

fn jsonrpc_result(message: &Value, expected_id: u64) -> Result<Option<Value>, McpHostError> {
    let object = message.as_object().ok_or(McpHostError::InvalidProtocol)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(McpHostError::InvalidProtocol);
    }
    let Some(id) = object.get("id") else {
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .ok_or(McpHostError::InvalidProtocol)?;
        return if matches!(
            method,
            "notifications/message" | "notifications/progress" | "notifications/cancelled"
        ) {
            Ok(None)
        } else if matches!(
            method,
            "notifications/tools/list_changed"
                | "notifications/resources/list_changed"
                | "notifications/prompts/list_changed"
                | "notifications/resources/updated"
        ) {
            Err(McpHostError::InventoryDrift)
        } else {
            Err(McpHostError::InvalidProtocol)
        };
    };
    if object.get("method").is_some()
        || id.as_u64() != Some(expected_id)
        || object.get("result").is_some() == object.get("error").is_some()
    {
        return Err(McpHostError::InvalidProtocol);
    }
    if let Some(result) = object.get("result") {
        return Ok(Some(result.clone()));
    }
    Err(remote_error(object.get("error"))?)
}

fn normalize_resource_result(
    result: &Value,
    server_id: &str,
    grant: &McpResourceGrant,
) -> Result<Value, McpHostError> {
    let contents = result
        .get("contents")
        .and_then(Value::as_array)
        .filter(|contents| !contents.is_empty() && contents.len() <= 64)
        .ok_or(McpHostError::InvalidProtocol)?;
    let mut normalized = Vec::with_capacity(contents.len());
    for content in contents {
        let object = content.as_object().ok_or(McpHostError::InvalidProtocol)?;
        if object.get("uri").and_then(Value::as_str) != Some(grant.uri()) {
            return Err(McpHostError::InvalidProtocol);
        }
        validate_resource_content(object)?;
        let mut item =
            serde_json::Map::from_iter([("uri".to_owned(), Value::String(grant.uri().to_owned()))]);
        if let Some(mime_type) = object.get("mimeType") {
            item.insert("mimeType".to_owned(), mime_type.clone());
        }
        if let Some(text) = object.get("text") {
            item.insert("text".to_owned(), text.clone());
        }
        if let Some(blob) = object.get("blob") {
            item.insert("blob".to_owned(), blob.clone());
        }
        normalized.push(Value::Object(item));
    }
    Ok(json!({
        "serverId": server_id,
        "resourceUri": grant.uri(),
        "definitionDigest": grant.definition_digest(),
        "sourceLocator": format!("mcp://{server_id}/resource/{}", grant.definition_digest()),
        "contents": normalized,
    }))
}

fn normalize_prompt_result(
    result: &Value,
    server_id: &str,
    grant: &McpPromptGrant,
) -> Result<Value, McpHostError> {
    let description = result
        .get("description")
        .map(|value| {
            value
                .as_str()
                .filter(|text| text.len() <= 4_096 && !text.contains('\0'))
                .map(str::to_owned)
                .ok_or(McpHostError::InvalidProtocol)
        })
        .transpose()?;
    let messages = result
        .get("messages")
        .and_then(Value::as_array)
        .filter(|messages| !messages.is_empty() && messages.len() <= 128)
        .ok_or(McpHostError::InvalidProtocol)?;
    let mut normalized = Vec::with_capacity(messages.len());
    for message in messages {
        let object = message.as_object().ok_or(McpHostError::InvalidProtocol)?;
        let role = object
            .get("role")
            .and_then(Value::as_str)
            .filter(|role| matches!(*role, "user" | "assistant"))
            .ok_or(McpHostError::InvalidProtocol)?;
        let content = object.get("content").ok_or(McpHostError::InvalidProtocol)?;
        validate_prompt_content_block(content)?;
        normalized.push(json!({"role": role, "content": content}));
    }
    Ok(json!({
        "serverId": server_id,
        "promptName": grant.remote_name(),
        "definitionDigest": grant.definition_digest(),
        "sourceLocator": format!("mcp://{server_id}/prompt/{}", grant.remote_name()),
        "description": description,
        "messages": normalized,
        "trust": "untrusted_tool_evidence",
    }))
}

fn validate_resource_content(object: &serde_json::Map<String, Value>) -> Result<(), McpHostError> {
    if object.get("mimeType").is_some_and(|mime_type| {
        mime_type
            .as_str()
            .is_none_or(|value| value.is_empty() || value.len() > 256 || value.contains('\0'))
    }) {
        return Err(McpHostError::InvalidProtocol);
    }
    match (
        object.get("text").and_then(Value::as_str),
        object.get("blob").and_then(Value::as_str),
    ) {
        (Some(_), None) => Ok(()),
        (None, Some(blob)) if BASE64_STANDARD.decode(blob).is_ok() => Ok(()),
        _ => Err(McpHostError::InvalidProtocol),
    }
}

fn validate_prompt_content_block(content: &Value) -> Result<(), McpHostError> {
    let object = content.as_object().ok_or(McpHostError::InvalidProtocol)?;
    match object.get("type").and_then(Value::as_str) {
        Some("text") => object
            .get("text")
            .and_then(Value::as_str)
            .map(|_| ())
            .ok_or(McpHostError::InvalidProtocol),
        Some("image" | "audio") => {
            let data = object
                .get("data")
                .and_then(Value::as_str)
                .ok_or(McpHostError::InvalidProtocol)?;
            let mime_type = object
                .get("mimeType")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 256 && !value.contains('\0'))
                .ok_or(McpHostError::InvalidProtocol)?;
            if !mime_type.contains('/') || BASE64_STANDARD.decode(data).is_err() {
                return Err(McpHostError::InvalidProtocol);
            }
            Ok(())
        }
        Some("resource") => {
            let resource = object
                .get("resource")
                .and_then(Value::as_object)
                .ok_or(McpHostError::InvalidProtocol)?;
            if resource
                .get("uri")
                .and_then(Value::as_str)
                .is_none_or(|uri| uri.is_empty() || uri.len() > 4_096 || uri.contains('\0'))
            {
                return Err(McpHostError::InvalidProtocol);
            }
            validate_resource_content(resource)
        }
        Some("resource_link") => object
            .get("uri")
            .and_then(Value::as_str)
            .filter(|uri| !uri.is_empty() && uri.len() <= 4_096 && !uri.contains('\0'))
            .map(|_| ())
            .ok_or(McpHostError::InvalidProtocol),
        _ => Err(McpHostError::InvalidProtocol),
    }
}

fn verify_discovery(
    server: &McpServerConfig,
    discovery: &McpServerDiscovery,
) -> Result<(), McpHostError> {
    if discovery
        .toolset_digest()
        .map_err(|_| McpHostError::InvalidProtocol)?
        != server.toolset_digest()
    {
        return Err(McpHostError::InventoryDrift);
    }
    for grant in server.tools() {
        let Some(discovered) = discovery.tool(grant.remote_name()) else {
            return Err(McpHostError::InventoryDrift);
        };
        if discovered.definition_digest != grant.definition_digest()
            || discovered.definition != *grant.definition()
        {
            return Err(McpHostError::InventoryDrift);
        }
    }
    Ok(())
}

/// One model-visible, read-only MCP tool backed by a fresh isolated stdio session per call.
pub struct McpReadTool {
    endpoint: Arc<McpStdioEndpoint>,
    server: McpServerConfig,
    grant: McpToolGrant,
    descriptor: ReadToolDescriptor,
}

impl std::fmt::Debug for McpReadTool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpReadTool")
            .field("tool_id", &self.descriptor.tool_id)
            .field("definition_digest", &self.grant.definition_digest())
            .finish_non_exhaustive()
    }
}

impl McpReadTool {
    fn new(
        endpoint: Arc<McpStdioEndpoint>,
        server: McpServerConfig,
        grant: McpToolGrant,
    ) -> Result<Self, McpHostError> {
        let descriptor = mcp_read_tool_descriptor(&server, &grant)
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        descriptor
            .validate_evidence()
            .map_err(|_| McpHostError::InvalidConfiguration)?;
        Ok(Self {
            endpoint,
            server,
            grant,
            descriptor,
        })
    }
}

impl ReadOnlyTool for McpReadTool {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &Value) -> Result<(), ReadToolError> {
        validate_mcp_tool_arguments(&self.grant, arguments)
    }

    fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        self.validate_arguments(arguments)?;
        let output = self
            .endpoint
            .call(
                &self.server,
                &self.grant,
                arguments,
                cancellation,
                Duration::from_millis(self.grant.timeout_ms()),
            )
            .map_err(|error| map_read_error(error, self.grant.maximum_output_bytes()))?;
        let bytes = serde_json::to_vec(&output).map_err(|_| {
            ReadToolError::Unavailable("MCP result normalization failed".to_owned())
        })?;
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual > self.grant.maximum_output_bytes() {
            return Err(ReadToolError::OutputTooLarge {
                actual,
                maximum: self.grant.maximum_output_bytes(),
            });
        }
        Ok(ReadToolOutput {
            media_type: "application/json".to_owned(),
            bytes,
            source_locator: format!(
                "mcp://{}/{}",
                self.server.server_id(),
                self.grant.remote_name()
            ),
        })
    }
}

fn map_read_error(error: McpHostError, maximum: u64) -> ReadToolError {
    match error {
        McpHostError::Cancelled => ReadToolError::Cancelled,
        McpHostError::OutputLimitExceeded => ReadToolError::OutputTooLarge {
            actual: maximum.saturating_add(1),
            maximum,
        },
        McpHostError::RemoteToolError(message) => {
            ReadToolError::Unavailable(format!("MCP server rejected the tool call: {message}"))
        }
        McpHostError::TimedOut => ReadToolError::Unavailable("MCP call timed out".to_owned()),
        McpHostError::IdentityMismatch => {
            ReadToolError::Unavailable("MCP executable identity changed".to_owned())
        }
        McpHostError::InventoryDrift => {
            ReadToolError::Unavailable("MCP advertised inventory changed".to_owned())
        }
        McpHostError::InvalidConfiguration
        | McpHostError::UnsupportedHost(_)
        | McpHostError::Io(_)
        | McpHostError::InvalidProtocol
        | McpHostError::AuthorizationRequired
        | McpHostError::InvalidOAuthMetadata
        | McpHostError::OAuthAuthorizationServerSelectionRequired(_)
        | McpHostError::SessionExpired
        | McpHostError::HttpStatus(_)
        | McpHostError::ProcessFailed => {
            ReadToolError::Unavailable("MCP transport boundary is unavailable".to_owned())
        }
    }
}

#[derive(Debug)]
struct McpStdioEndpoint {
    bubblewrap_path: PathBuf,
    launcher_path: PathBuf,
    launcher_digest: String,
    executable_path: PathBuf,
    executable_digest: String,
    arguments: Vec<String>,
}

impl McpStdioEndpoint {
    fn new(
        bubblewrap_path: &Path,
        launcher_path: &Path,
        server_id: &str,
        executable_path: &Path,
        executable_digest: &str,
        arguments: &[String],
    ) -> Result<Self, McpHostError> {
        if !cfg!(target_os = "linux") {
            return Err(McpHostError::UnsupportedHost(
                "local MCP stdio isolation currently requires Linux Bubblewrap".to_owned(),
            ));
        }
        if server_id.is_empty()
            || server_id.len() > 32
            || server_id
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-' | b'.'))
            || !mealy_application::is_sha256_digest(executable_digest)
            || arguments.len() > mealy_application::MCP_MAXIMUM_ARGUMENTS
            || arguments.iter().any(|argument| {
                argument.len() > 4_096
                    || argument.contains('\0')
                    || argument.chars().any(char::is_control)
            })
        {
            return Err(McpHostError::InvalidConfiguration);
        }
        let bubblewrap_path = exact_canonical_file(bubblewrap_path)?;
        if !crate::is_trusted_system_executable(&bubblewrap_path) {
            return Err(McpHostError::UnsupportedHost(
                "Bubblewrap is not installed as a trusted system executable".to_owned(),
            ));
        }
        let launcher_path = exact_canonical_file(launcher_path)?;
        let launcher_digest = digest_executable(&launcher_path)?;
        let executable_path = exact_canonical_file(executable_path)?;
        if digest_executable(&executable_path)? != executable_digest {
            return Err(McpHostError::IdentityMismatch);
        }
        Ok(Self {
            bubblewrap_path,
            launcher_path,
            launcher_digest,
            executable_path,
            executable_digest: executable_digest.to_owned(),
            arguments: arguments.to_vec(),
        })
    }

    fn verify_identity(&self) -> Result<(), McpHostError> {
        if digest_executable(&self.launcher_path)? != self.launcher_digest
            || digest_executable(&self.executable_path)? != self.executable_digest
        {
            return Err(McpHostError::IdentityMismatch);
        }
        Ok(())
    }

    fn discover(
        &self,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<McpServerDiscovery, McpHostError> {
        self.verify_identity()?;
        let mut session = McpSession::spawn(self, cancellation, timeout)?;
        let discovery = session.initialize_and_discover(cancellation)?;
        session.shutdown()?;
        Ok(discovery)
    }

    fn call(
        &self,
        server: &McpServerConfig,
        grant: &McpToolGrant,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<Value, McpHostError> {
        self.verify_identity()?;
        let mut session = McpSession::spawn(self, cancellation, timeout)?;
        let discovery = session.initialize_and_discover(cancellation)?;
        verify_discovery(server, &discovery)?;
        let result = session.request(
            10_000,
            "tools/call",
            &json!({"name": grant.remote_name(), "arguments": arguments}),
            cancellation,
            true,
        )?;
        let normalized = normalize_tool_result(&result, server.server_id(), grant)?;
        session.shutdown()?;
        Ok(normalized)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.bubblewrap_path);
        command.env_clear().args([
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--hostname",
            "mealy-mcp",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/runtime",
            "--dir",
            "/mcp",
        ]);
        for (source, target) in runtime_directory_mounts() {
            command.arg("--ro-bind").arg(source).arg(target);
        }
        command
            .arg("--ro-bind")
            .arg(&self.launcher_path)
            .arg(MCP_SANDBOX_LAUNCHER)
            .arg("--ro-bind")
            .arg(&self.executable_path)
            .arg(MCP_SANDBOX_SERVER)
            .arg("--chdir")
            .arg("/tmp")
            .arg("--")
            .arg(MCP_SANDBOX_LAUNCHER)
            .arg(MCP_LAUNCHER_ARGUMENT)
            .args(&self.arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

fn runtime_directory_mounts() -> Vec<(PathBuf, PathBuf)> {
    ["/usr/lib", "/usr/lib64", "/lib", "/lib64"]
        .into_iter()
        .filter_map(|target| {
            let requested = Path::new(target);
            requested
                .exists()
                .then(|| fs::canonicalize(requested).ok())
                .flatten()
                .map(|source| (source, PathBuf::from(target)))
        })
        .collect()
}

struct McpSession {
    child: Child,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<ReaderEvent>,
    output_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    stderr_exceeded: Arc<AtomicBool>,
    stderr_failed: Arc<AtomicBool>,
    started: Instant,
    timeout: Duration,
    messages: usize,
}

impl McpSession {
    fn spawn(
        endpoint: &McpStdioEndpoint,
        cancellation: &dyn CancellationProbe,
        timeout: Duration,
    ) -> Result<Self, McpHostError> {
        if timeout.is_zero() || timeout > Duration::from_mins(1) {
            return Err(McpHostError::InvalidConfiguration);
        }
        if cancellation.is_cancelled() {
            return Err(McpHostError::Cancelled);
        }
        let started = Instant::now();
        let mut child = endpoint
            .command()
            .spawn()
            .map_err(|error| McpHostError::Io(format!("MCP sandbox spawn failed: {error}")))?;
        let (Some(input), Some(output), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            terminate_child(&mut child);
            return Err(McpHostError::Io("MCP process pipe is absent".to_owned()));
        };
        // The protocol reader has a hard aggregate byte bound, so an unbounded channel is still
        // memory-bounded. More importantly, it cannot deadlock process teardown if a hostile
        // server fills a small synchronous queue while the request path is already failing.
        let (sender, receiver) = mpsc::channel();
        let output_thread = match thread::Builder::new()
            .name("mealy-mcp-stdout".to_owned())
            .spawn(move || capture_protocol_lines(output, &sender))
        {
            Ok(handle) => handle,
            Err(error) => {
                terminate_child(&mut child);
                return Err(McpHostError::Io(format!(
                    "MCP stdout reader failed: {error}"
                )));
            }
        };
        let stderr_exceeded = Arc::new(AtomicBool::new(false));
        let stderr_failed = Arc::new(AtomicBool::new(false));
        let thread_exceeded = Arc::clone(&stderr_exceeded);
        let thread_failed = Arc::clone(&stderr_failed);
        let stderr_thread = match thread::Builder::new()
            .name("mealy-mcp-stderr".to_owned())
            .spawn(move || {
                let mut bytes = Vec::new();
                let result = stderr
                    .take(MCP_MAXIMUM_STDERR_BYTES.saturating_add(1))
                    .read_to_end(&mut bytes);
                if result.is_err() {
                    thread_failed.store(true, Ordering::Release);
                }
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MCP_MAXIMUM_STDERR_BYTES {
                    thread_exceeded.store(true, Ordering::Release);
                }
            }) {
            Ok(handle) => handle,
            Err(error) => {
                terminate_child(&mut child);
                drop(receiver);
                let _ = output_thread.join();
                return Err(McpHostError::Io(format!(
                    "MCP stderr reader failed: {error}"
                )));
            }
        };
        Ok(Self {
            child,
            input: Some(input),
            output: receiver,
            output_thread: Some(output_thread),
            stderr_thread: Some(stderr_thread),
            stderr_exceeded,
            stderr_failed,
            started,
            timeout,
            messages: 0,
        })
    }

    fn initialize_and_discover(
        &mut self,
        cancellation: &dyn CancellationProbe,
    ) -> Result<McpServerDiscovery, McpHostError> {
        let initialized = self.request(
            1,
            "initialize",
            &json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "mealy",
                    "title": "Mealy governed MCP client",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Schema-pinned read-only local stdio MCP boundary"
                }
            }),
            cancellation,
            false,
        )?;
        let protocol_version = initialized
            .get("protocolVersion")
            .and_then(Value::as_str)
            .filter(|version| *version == MCP_PROTOCOL_VERSION)
            .ok_or(McpHostError::InvalidProtocol)?
            .to_owned();
        if !initialized
            .get("capabilities")
            .and_then(|capabilities| capabilities.get("tools"))
            .is_some_and(Value::is_object)
        {
            return Err(McpHostError::InvalidProtocol);
        }
        let server_info = initialized
            .get("serverInfo")
            .filter(|value| value.is_object())
            .cloned()
            .ok_or(McpHostError::InvalidProtocol)?;
        self.notify("notifications/initialized", None)?;

        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut tools = Vec::new();
        for page in 0..MCP_MAXIMUM_LIST_PAGES {
            let id = u64::try_from(page).unwrap_or(u64::MAX).saturating_add(2);
            let params = cursor
                .as_ref()
                .map_or_else(|| json!({}), |value| json!({"cursor": value}));
            let listed = self.request(id, "tools/list", &params, cancellation, true)?;
            let page_tools = listed
                .get("tools")
                .and_then(Value::as_array)
                .ok_or(McpHostError::InvalidProtocol)?;
            if tools.len().saturating_add(page_tools.len()) > MCP_MAXIMUM_TOOLS_PER_SERVER {
                return Err(McpHostError::OutputLimitExceeded);
            }
            for definition in page_tools {
                tools.push(McpToolInspection {
                    definition: definition.clone(),
                    definition_digest: mcp_tool_definition_digest(definition)
                        .map_err(|_| McpHostError::InvalidProtocol)?,
                });
            }
            cursor = listed
                .get("nextCursor")
                .map(|value| {
                    value
                        .as_str()
                        .filter(|cursor| {
                            !cursor.is_empty()
                                && cursor.len() <= 1_024
                                && !cursor.chars().any(char::is_control)
                        })
                        .map(str::to_owned)
                        .ok_or(McpHostError::InvalidProtocol)
                })
                .transpose()?;
            let Some(next) = &cursor else {
                break;
            };
            if !seen_cursors.insert(next.clone()) || page + 1 == MCP_MAXIMUM_LIST_PAGES {
                return Err(McpHostError::InvalidProtocol);
            }
        }
        tools.sort_by(|left, right| {
            left.definition["name"]
                .as_str()
                .cmp(&right.definition["name"].as_str())
        });
        let discovery = McpServerDiscovery {
            protocol_version,
            server_info,
            tools,
        };
        discovery
            .validate()
            .map_err(|_| McpHostError::InvalidProtocol)?;
        Ok(discovery)
    }

    fn request(
        &mut self,
        id: u64,
        method: &str,
        params: &Value,
        cancellation: &dyn CancellationProbe,
        cancellable: bool,
    ) -> Result<Value, McpHostError> {
        self.write_message(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))?;
        self.wait_for_response(id, cancellation, cancellable)
    }

    fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), McpHostError> {
        let mut message = serde_json::Map::from_iter([
            ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
            ("method".to_owned(), Value::String(method.to_owned())),
        ]);
        if let Some(params) = params {
            message.insert("params".to_owned(), params);
        }
        self.write_message(&Value::Object(message))
    }

    fn write_message(&mut self, message: &Value) -> Result<(), McpHostError> {
        let mut bytes = serde_json::to_vec(message).map_err(|_| McpHostError::InvalidProtocol)?;
        if bytes.len() > MCP_MAXIMUM_MESSAGE_BYTES {
            return Err(McpHostError::OutputLimitExceeded);
        }
        bytes.push(b'\n');
        let input = self.input.as_mut().ok_or(McpHostError::ProcessFailed)?;
        input
            .write_all(&bytes)
            .and_then(|()| input.flush())
            .map_err(|_| McpHostError::ProcessFailed)
    }

    fn wait_for_response(
        &mut self,
        expected_id: u64,
        cancellation: &dyn CancellationProbe,
        cancellable: bool,
    ) -> Result<Value, McpHostError> {
        loop {
            if cancellation.is_cancelled() {
                if cancellable {
                    let _ = self.notify(
                        "notifications/cancelled",
                        Some(json!({"requestId": expected_id, "reason": "Mealy run cancelled"})),
                    );
                }
                return Err(McpHostError::Cancelled);
            }
            if self.started.elapsed() >= self.timeout {
                if cancellable {
                    let _ = self.notify(
                        "notifications/cancelled",
                        Some(json!({"requestId": expected_id, "reason": "Mealy deadline elapsed"})),
                    );
                }
                return Err(McpHostError::TimedOut);
            }
            if self.stderr_exceeded.load(Ordering::Acquire) {
                return Err(McpHostError::OutputLimitExceeded);
            }
            if self.stderr_failed.load(Ordering::Acquire) {
                return Err(McpHostError::ProcessFailed);
            }
            match self.output.recv_timeout(MCP_POLL_INTERVAL) {
                Ok(ReaderEvent::Line(bytes)) => {
                    self.messages = self.messages.saturating_add(1);
                    if self.messages > MCP_MAXIMUM_MESSAGES {
                        return Err(McpHostError::OutputLimitExceeded);
                    }
                    let message = serde_json::from_slice::<Value>(&bytes)
                        .map_err(|_| McpHostError::InvalidProtocol)?;
                    let object = message.as_object().ok_or(McpHostError::InvalidProtocol)?;
                    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                        return Err(McpHostError::InvalidProtocol);
                    }
                    if let Some(id) = object.get("id") {
                        if object.get("method").is_some() {
                            self.answer_server_request(object, id)?;
                            continue;
                        }
                        if id.as_u64() != Some(expected_id)
                            || object.get("result").is_some() == object.get("error").is_some()
                        {
                            return Err(McpHostError::InvalidProtocol);
                        }
                        if let Some(result) = object.get("result") {
                            return Ok(result.clone());
                        }
                        return Err(remote_error(object.get("error"))?);
                    }
                    let method = object
                        .get("method")
                        .and_then(Value::as_str)
                        .ok_or(McpHostError::InvalidProtocol)?;
                    if method == "notifications/tools/list_changed" {
                        return Err(McpHostError::InventoryDrift);
                    }
                    if !matches!(
                        method,
                        "notifications/message"
                            | "notifications/progress"
                            | "notifications/cancelled"
                    ) {
                        return Err(McpHostError::InvalidProtocol);
                    }
                }
                Ok(ReaderEvent::Limit) => return Err(McpHostError::OutputLimitExceeded),
                Ok(ReaderEvent::Malformed | ReaderEvent::Eof)
                | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(McpHostError::ProcessFailed);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self
                        .child
                        .try_wait()
                        .map_err(|error| McpHostError::Io(format!("MCP wait failed: {error}")))?
                        .is_some()
                    {
                        return Err(McpHostError::ProcessFailed);
                    }
                }
            }
        }
    }

    fn answer_server_request(
        &mut self,
        object: &serde_json::Map<String, Value>,
        id: &Value,
    ) -> Result<(), McpHostError> {
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .ok_or(McpHostError::InvalidProtocol)?;
        if method == "ping" {
            self.write_message(&json!({"jsonrpc": "2.0", "id": id, "result": {}}))
        } else {
            self.write_message(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "Client capability not negotiated"}
            }))
        }
    }

    fn shutdown(&mut self) -> Result<(), McpHostError> {
        self.input.take();
        let started = Instant::now();
        let clean_exit = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) if started.elapsed() < MCP_SHUTDOWN_GRACE => {
                    thread::sleep(MCP_POLL_INTERVAL);
                }
                Ok(None) | Err(_) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break false;
                }
            }
        };
        let output_reader_failed = self
            .output_thread
            .take()
            .is_some_and(|handle| handle.join().is_err());
        let stderr_reader_failed = self
            .stderr_thread
            .take()
            .is_some_and(|handle| handle.join().is_err());

        // A fast server can finish its valid protocol response before either reader thread gets
        // scheduled. Validate the final reader state only after both pipes have reached EOF so an
        // over-limit stderr stream or trailing malformed stdout can never win that race.
        if self.stderr_exceeded.load(Ordering::Acquire) {
            return Err(McpHostError::OutputLimitExceeded);
        }
        if output_reader_failed
            || stderr_reader_failed
            || self.stderr_failed.load(Ordering::Acquire)
        {
            return Err(McpHostError::ProcessFailed);
        }
        self.validate_trailing_output()?;
        if !clean_exit {
            return Err(McpHostError::ProcessFailed);
        }
        Ok(())
    }

    fn validate_trailing_output(&mut self) -> Result<(), McpHostError> {
        let mut reached_eof = false;
        loop {
            match self.output.try_recv() {
                Ok(_) if reached_eof => return Err(McpHostError::InvalidProtocol),
                Ok(ReaderEvent::Line(bytes)) => {
                    self.messages = self.messages.saturating_add(1);
                    if self.messages > MCP_MAXIMUM_MESSAGES {
                        return Err(McpHostError::OutputLimitExceeded);
                    }
                    let message = serde_json::from_slice::<Value>(&bytes)
                        .map_err(|_| McpHostError::InvalidProtocol)?;
                    let object = message.as_object().ok_or(McpHostError::InvalidProtocol)?;
                    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
                        || object.get("id").is_some()
                        || !matches!(
                            object.get("method").and_then(Value::as_str),
                            Some(
                                "notifications/message"
                                    | "notifications/progress"
                                    | "notifications/cancelled"
                            )
                        )
                    {
                        return Err(McpHostError::InvalidProtocol);
                    }
                }
                Ok(ReaderEvent::Limit) => return Err(McpHostError::OutputLimitExceeded),
                Ok(ReaderEvent::Malformed) => return Err(McpHostError::InvalidProtocol),
                Ok(ReaderEvent::Eof) => reached_eof = true,
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }
        if !reached_eof {
            return Err(McpHostError::ProcessFailed);
        }
        Ok(())
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn remote_error(value: Option<&Value>) -> Result<McpHostError, McpHostError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or(McpHostError::InvalidProtocol)?;
    let code = object
        .get("code")
        .and_then(Value::as_i64)
        .ok_or(McpHostError::InvalidProtocol)?;
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| message.len() <= 4_096 && !message.chars().any(char::is_control))
        .ok_or(McpHostError::InvalidProtocol)?;
    Ok(McpHostError::RemoteToolError(format!(
        "JSON-RPC {code}: {message}"
    )))
}

fn normalize_tool_result(
    result: &Value,
    server_id: &str,
    grant: &McpToolGrant,
) -> Result<Value, McpHostError> {
    let object = result.as_object().ok_or(McpHostError::InvalidProtocol)?;
    let content = object
        .get("content")
        .and_then(Value::as_array)
        .ok_or(McpHostError::InvalidProtocol)?;
    if content.len() > 128 || !content.iter().all(valid_content_item) {
        return Err(McpHostError::InvalidProtocol);
    }
    let is_error = match object.get("isError") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(McpHostError::InvalidProtocol),
    };
    let structured = object.get("structuredContent").cloned();
    if structured.as_ref().is_some_and(|value| !value.is_object()) {
        return Err(McpHostError::InvalidProtocol);
    }
    if let Some(output_schema) = grant.definition().get("outputSchema") {
        let Some(structured) = structured.as_ref() else {
            return Err(McpHostError::InvalidProtocol);
        };
        if !is_error
            && jsonschema::validator_for(output_schema)
                .map_err(|_| McpHostError::InvalidProtocol)?
                .validate(structured)
                .is_err()
        {
            return Err(McpHostError::InvalidProtocol);
        }
    }
    let mut normalized = json!({
        "serverId": server_id,
        "toolName": grant.remote_name(),
        "definitionDigest": grant.definition_digest(),
        "sourceLocator": format!("mcp://{server_id}/{}", grant.remote_name()),
        "isError": is_error,
        "content": content,
    });
    if let Some(structured) = structured {
        normalized["structuredContent"] = structured;
    }
    Ok(normalized)
}

fn valid_content_item(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let Some(kind) = object.get("type").and_then(Value::as_str) else {
        return false;
    };
    match kind {
        "text" => object.get("text").is_some_and(Value::is_string),
        "image" | "audio" => {
            object.get("data").is_some_and(Value::is_string)
                && object.get("mimeType").is_some_and(Value::is_string)
        }
        "resource_link" => {
            object.get("uri").is_some_and(Value::is_string)
                && object.get("name").is_some_and(Value::is_string)
        }
        "resource" => object.get("resource").is_some_and(Value::is_object),
        _ => false,
    }
}

enum ReaderEvent {
    Line(Vec<u8>),
    Limit,
    Malformed,
    Eof,
}

fn capture_protocol_lines(output: impl Read, sender: &mpsc::Sender<ReaderEvent>) {
    let mut reader = BufReader::new(output);
    let mut total = 0_usize;
    loop {
        match read_bounded_line(&mut reader, MCP_MAXIMUM_MESSAGE_BYTES) {
            Ok(Some(line)) => {
                total = total.saturating_add(line.len().saturating_add(1));
                if total > MCP_MAXIMUM_STDOUT_BYTES {
                    let _ = sender.send(ReaderEvent::Limit);
                    return;
                }
                if sender.send(ReaderEvent::Line(line)).is_err() {
                    return;
                }
            }
            Ok(None) => {
                let _ = sender.send(ReaderEvent::Eof);
                return;
            }
            Err(LineError::Limit) => {
                let _ = sender.send(ReaderEvent::Limit);
                return;
            }
            Err(LineError::Malformed) => {
                let _ = sender.send(ReaderEvent::Malformed);
                return;
            }
        }
    }
}

#[derive(Debug)]
enum LineError {
    Limit,
    Malformed,
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    maximum: usize,
) -> Result<Option<Vec<u8>>, LineError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|_| LineError::Malformed)?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(LineError::Malformed)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(consumed) > maximum.saturating_add(1) {
            return Err(LineError::Limit);
        }
        if let Some(position) = newline {
            line.extend_from_slice(&available[..position]);
            reader.consume(consumed);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() || line.len() > maximum {
                return Err(LineError::Malformed);
            }
            return Ok(Some(line));
        }
        line.extend_from_slice(available);
        reader.consume(consumed);
    }
}

fn exact_canonical_file(path: &Path) -> Result<PathBuf, McpHostError> {
    if !path.is_absolute() {
        return Err(McpHostError::InvalidConfiguration);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| McpHostError::Io(format!("cannot inspect executable: {error}")))?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| McpHostError::Io(format!("cannot canonicalize executable: {error}")))?;
    if canonical != path || metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(McpHostError::InvalidConfiguration);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(McpHostError::InvalidConfiguration);
        }
    }
    Ok(canonical)
}

fn digest_executable(path: &Path) -> Result<String, McpHostError> {
    let file = File::open(path)
        .map_err(|error| McpHostError::Io(format!("cannot open executable: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| McpHostError::Io(format!("cannot inspect executable: {error}")))?;
    if metadata.len() < 4 || metadata.len() > MCP_MAXIMUM_EXECUTABLE_BYTES {
        return Err(McpHostError::InvalidConfiguration);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MCP_MAXIMUM_EXECUTABLE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| McpHostError::Io(format!("cannot hash executable: {error}")))?;
    if bytes.len() < 4 || &bytes[..4] != b"\x7fELF" {
        return Err(McpHostError::InvalidConfiguration);
    }
    Ok(sha256_digest(&bytes))
}

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Enters the no-shell MCP target launcher after Bubblewrap has created the isolated namespace.
///
/// Applications embedding this helper must dispatch it before normal CLI parsing whenever their
/// first argument is `--mcp-stdio-launcher`. The function never returns on success because it
/// replaces the launcher process with the fixed `/mcp/server` executable.
#[cfg(target_os = "linux")]
#[must_use]
pub fn mcp_stdio_launcher_main() -> std::process::ExitCode {
    use rustix::process::{Resource, Rlimit, setrlimit};
    use std::os::unix::process::CommandExt as _;

    if std::env::args().nth(1).as_deref() != Some(MCP_LAUNCHER_ARGUMENT) {
        return std::process::ExitCode::from(64);
    }
    let limits = [
        (Resource::Core, 0),
        (Resource::Fsize, 16 * 1024 * 1024),
        (Resource::Nofile, 64),
        (Resource::Nproc, 1),
        (Resource::As, 512 * 1024 * 1024),
        (Resource::Cpu, 65),
    ];
    for (resource, maximum) in limits {
        if setrlimit(
            resource,
            Rlimit {
                current: Some(maximum),
                maximum: Some(maximum),
            },
        )
        .is_err()
        {
            return std::process::ExitCode::from(70);
        }
    }
    let error = Command::new(MCP_SANDBOX_SERVER)
        .args(std::env::args_os().skip(2))
        .env_clear()
        .current_dir("/tmp")
        .exec();
    drop(error);
    std::process::ExitCode::from(70)
}

/// Reports unsupported launcher use on non-Linux systems without executing untrusted code.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn mcp_stdio_launcher_main() -> std::process::ExitCode {
    std::process::ExitCode::from(69)
}

/// Failure at the governed local stdio MCP process boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum McpHostError {
    /// Non-secret server configuration is malformed or non-canonical.
    #[error("MCP server configuration is invalid")]
    InvalidConfiguration,
    /// Host cannot enforce the requested isolation boundary.
    #[error("MCP stdio host is unsupported: {0}")]
    UnsupportedHost(String),
    /// Exact launcher or MCP executable bytes changed.
    #[error("MCP executable identity changed")]
    IdentityMismatch,
    /// Initialization, JSON-RPC, pagination, capability, schema, or result framing is invalid.
    #[error("MCP protocol response is invalid")]
    InvalidProtocol,
    /// Complete advertised tool/catalog evidence no longer matches owner review.
    #[error("MCP advertised inventory changed")]
    InventoryDrift,
    /// Request exceeded its hard wall-clock limit.
    #[error("MCP request timed out")]
    TimedOut,
    /// Protected HTTP endpoint rejected the configured credential or requires owner authorization.
    #[error("MCP HTTP authorization is required")]
    AuthorizationRequired,
    /// Protected-resource or authorization-server metadata is malformed or unsafe.
    #[error("MCP OAuth metadata is invalid")]
    InvalidOAuthMetadata,
    /// More than one authorization server was advertised and owner selection is required.
    #[error("MCP OAuth authorization-server selection is required from {0:?}")]
    OAuthAuthorizationServerSelectionRequired(Vec<String>),
    /// Remote HTTP session no longer exists.
    #[error("MCP HTTP session expired")]
    SessionExpired,
    /// Remote endpoint returned a bounded non-success HTTP status.
    #[error("MCP HTTP endpoint returned status {0}")]
    HttpStatus(u16),
    /// Durable caller cancellation was observed and propagated.
    #[error("MCP request was cancelled")]
    Cancelled,
    /// Stdout, stderr, message count, or normalized result exceeded a hard bound.
    #[error("MCP process output exceeded its bound")]
    OutputLimitExceeded,
    /// Server returned a bounded JSON-RPC tool error.
    #[error("MCP server error: {0}")]
    RemoteToolError(String),
    /// Sandboxed process exited, closed a protocol pipe, or could not be terminated cleanly.
    #[error("MCP server process failed")]
    ProcessFailed,
    /// Trusted host-side process operation failed.
    #[error("MCP host I/O failed: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::{
        LineError, McpHostError, NeverCancelled, discover_mcp_http_server,
        inspect_mcp_http_endpoint, jsonrpc_result, load_mcp_http_read_tools, parse_sse_response,
        read_bounded_line,
    };
    use mealy_application::{
        MCP_PROTOCOL_VERSION, McpCatalogItemInspection, McpHttpAuthentication,
        McpHttpCatalogDiscovery, McpHttpEndpointConfig, McpHttpServerConfig, McpPromptGrant,
        McpResourceGrant, McpToolGrant, McpToolInspection, ReadOnlyTool,
    };
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        io::{Cursor, Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };
    use zeroize::Zeroizing;

    #[test]
    fn bounded_line_reader_requires_complete_nonempty_frames() {
        let mut valid = Cursor::new(b"{\"jsonrpc\":\"2.0\"}\n".as_slice());
        assert_eq!(
            read_bounded_line(&mut valid, 64).expect("line"),
            Some(b"{\"jsonrpc\":\"2.0\"}".to_vec())
        );
        let mut missing_newline = Cursor::new(b"{}".as_slice());
        assert!(matches!(
            read_bounded_line(&mut missing_newline, 64),
            Err(LineError::Malformed)
        ));
        let mut oversized = Cursor::new(b"12345\n".as_slice());
        assert!(matches!(
            read_bounded_line(&mut oversized, 4),
            Err(LineError::Limit | LineError::Malformed)
        ));
    }

    #[test]
    fn streamable_http_jsonrpc_and_sse_parsers_fail_closed() {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {"value": "bounded"}
        });
        assert_eq!(
            jsonrpc_result(&payload, 7).expect("JSON-RPC result"),
            Some(json!({"value": "bounded"}))
        );
        let sse = concat!(
            "id: prime\n",
            "data:\n\n",
            "event: message\n",
            "id: result-1\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"value\":\"bounded\"}}\n\n",
        );
        assert_eq!(
            parse_sse_response(sse.as_bytes(), 7).expect("SSE result"),
            json!({"value": "bounded"})
        );
        assert!(matches!(
            parse_sse_response(
                b"data: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"sampling/createMessage\",\"params\":{}}\n\n",
                7
            ),
            Err(McpHostError::InvalidProtocol)
        ));
        assert!(matches!(
            parse_sse_response(
                b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n",
                7
            ),
            Err(McpHostError::InventoryDrift)
        ));
    }

    #[test]
    fn streamable_http_discovery_binds_session_headers_bearer_and_sse_inventory() {
        let definition = json!({
            "name": "lookup",
            "description": "Returns one bounded fixture value",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {"key": {"type": "string"}},
                "required": ["key"]
            }
        });
        let grant = McpToolGrant::new(definition.clone(), 5_000, 64 * 1024).expect("grant");
        let expected = McpHttpCatalogDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "http-fixture", "version": "1"}),
            tools_capability: Some(json!({})),
            resources_capability: None,
            prompts_capability: None,
            tools: vec![McpToolInspection {
                definition: definition.clone(),
                definition_digest: grant.definition_digest().to_owned(),
            }],
            resources: Vec::new(),
            resource_templates: Vec::new(),
            prompts: Vec::new(),
        };
        let (endpoint, requests, server_thread) = spawn_http_fixture(vec![
            http_json_response(
                "200 OK",
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "http-fixture", "version": "1"}
                    }
                }),
                Some(("MCP-Session-Id", "fixture-session")),
            ),
            "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
            http_sse_response(&format!(
                "id: tools-1\ndata: {}\n\n",
                json!({
                    "jsonrpc": "2.0",
                    "id": 100,
                    "result": {"tools": [definition]}
                })
            )),
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned(),
        ]);
        let config = McpHttpServerConfig::new(
            "remote".to_owned(),
            endpoint,
            McpHttpAuthentication::Bearer {
                credential: mealy_application::ProviderCredentialReference::Broker {
                    secret_id: "mcp-http-fixture".to_owned(),
                },
            },
            expected.catalog_digest().expect("catalog digest"),
            true,
            vec![grant],
            Vec::new(),
            Vec::new(),
        )
        .expect("HTTP config");
        let discovery = discover_mcp_http_server(
            &config,
            Some(Zeroizing::new("fixture-bearer-secret".to_owned())),
        )
        .expect("HTTP discovery");
        assert_eq!(discovery, expected);
        server_thread.join().expect("fixture server");
        let requests = requests.lock().expect("fixture requests");
        assert_eq!(requests.len(), 4);
        for request in requests.iter() {
            let lowercase = request.to_ascii_lowercase();
            assert!(lowercase.contains("mcp-protocol-version: 2025-11-25"));
            assert!(lowercase.contains("authorization: bearer fixture-bearer-secret"));
        }
        assert!(!requests[0].to_ascii_lowercase().contains("mcp-session-id:"));
        for request in &requests[1..] {
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("mcp-session-id: fixture-session")
            );
        }
        assert!(requests[0].contains("\"method\":\"initialize\""));
        assert!(requests[1].contains("\"method\":\"notifications/initialized\""));
        assert!(requests[2].contains("\"method\":\"tools/list\""));
        assert!(requests[3].starts_with("DELETE /mcp HTTP/1.1"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn streamable_http_loaded_tool_revalidates_inventory_and_normalizes_one_call() {
        let definition = json!({
            "name": "lookup",
            "description": "Returns one bounded fixture value",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {"key": {"type": "string"}},
                "required": ["key"]
            },
            "outputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {"value": {"type": "string"}},
                "required": ["value"]
            }
        });
        let grant = McpToolGrant::new(definition.clone(), 5_000, 64 * 1024).expect("grant");
        let discovery = McpHttpCatalogDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "http-fixture", "version": "1"}),
            tools_capability: Some(json!({})),
            resources_capability: None,
            prompts_capability: None,
            tools: vec![McpToolInspection {
                definition: definition.clone(),
                definition_digest: grant.definition_digest().to_owned(),
            }],
            resources: Vec::new(),
            resource_templates: Vec::new(),
            prompts: Vec::new(),
        };
        let initialize = |session: &'static str| {
            http_json_response(
                "200 OK",
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "http-fixture", "version": "1"}
                    }
                }),
                Some(("MCP-Session-Id", session)),
            )
        };
        let tools = || {
            http_json_response(
                "200 OK",
                &json!({
                    "jsonrpc": "2.0",
                    "id": 100,
                    "result": {"tools": [definition.clone()]}
                }),
                None,
            )
        };
        let accepted =
            "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
        let deleted =
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned();
        let (endpoint, requests, server_thread) = spawn_http_fixture(vec![
            initialize("load-session"),
            accepted.clone(),
            tools(),
            deleted.clone(),
            initialize("call-session"),
            accepted,
            tools(),
            http_json_response(
                "200 OK",
                &json!({
                    "jsonrpc": "2.0",
                    "id": 10_000,
                    "result": {
                        "content": [{"type": "text", "text": "bounded"}],
                        "structuredContent": {"value": "bounded"},
                        "isError": false
                    }
                }),
                None,
            ),
            deleted,
        ]);
        let config = McpHttpServerConfig::new(
            "remote".to_owned(),
            endpoint,
            McpHttpAuthentication::Bearer {
                credential: mealy_application::ProviderCredentialReference::Broker {
                    secret_id: "mcp-http-fixture".to_owned(),
                },
            },
            discovery.catalog_digest().expect("catalog digest"),
            true,
            vec![grant],
            Vec::new(),
            Vec::new(),
        )
        .expect("HTTP config");
        let credentials = BTreeMap::from([(
            "remote".to_owned(),
            Zeroizing::new("fixture-bearer-secret".to_owned()),
        )]);
        let loaded = load_mcp_http_read_tools(&[config], credentials).expect("load HTTP MCP tool");
        assert_eq!(loaded.len(), 1);
        let output = loaded[0]
            .execute(&json!({"key": "alpha"}), &NeverCancelled)
            .expect("execute HTTP MCP tool");
        assert_eq!(output.source_locator, "mcp://remote/lookup");
        assert_eq!(output.media_type, "application/json");
        let normalized: Value = serde_json::from_slice(&output.bytes).expect("normalized JSON");
        assert_eq!(normalized["serverId"], "remote");
        assert_eq!(normalized["toolName"], "lookup");
        assert_eq!(normalized["structuredContent"]["value"], "bounded");
        server_thread.join().expect("fixture server");
        let requests = requests.lock().expect("fixture requests");
        assert_eq!(requests.len(), 9);
        assert!(requests[7].contains("\"method\":\"tools/call\""));
        assert!(requests[7].contains("\"arguments\":{\"key\":\"alpha\"}"));
        assert!(
            requests[7]
                .to_ascii_lowercase()
                .contains("mcp-session-id: call-session")
        );
        assert!(!requests[7].contains("load-session"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn streamable_http_resources_and_prompts_are_catalog_pinned_untrusted_evidence() {
        let resource_definition = json!({
            "uri": "fixture://docs/readme",
            "name": "readme",
            "description": "One bounded documentation resource",
            "mimeType": "text/markdown"
        });
        let template_definition = json!({
            "uriTemplate": "fixture://docs/{name}",
            "name": "document",
            "description": "Documentation template",
            "mimeType": "text/markdown"
        });
        let prompt_definition = json!({
            "name": "review",
            "description": "Returns an untrusted review prompt",
            "arguments": [
                {"name": "topic", "description": "Review topic", "required": true}
            ]
        });
        let resource_grant = McpResourceGrant::new(resource_definition.clone(), 5_000, 64 * 1_024)
            .expect("resource grant");
        let prompt_grant = McpPromptGrant::new(prompt_definition.clone(), 5_000, 64 * 1_024)
            .expect("prompt grant");
        let discovery = McpHttpCatalogDiscovery {
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            server_info: json!({"name": "catalog-fixture", "version": "1"}),
            tools_capability: None,
            resources_capability: Some(json!({"subscribe": false, "listChanged": true})),
            prompts_capability: Some(json!({"listChanged": true})),
            tools: Vec::new(),
            resources: vec![McpCatalogItemInspection {
                definition: resource_definition.clone(),
                definition_digest: resource_grant.definition_digest().to_owned(),
            }],
            resource_templates: vec![McpCatalogItemInspection {
                definition: template_definition.clone(),
                definition_digest: mealy_application::mcp_resource_template_definition_digest(
                    &template_definition,
                )
                .expect("template digest"),
            }],
            prompts: vec![McpCatalogItemInspection {
                definition: prompt_definition.clone(),
                definition_digest: prompt_grant.definition_digest().to_owned(),
            }],
        };
        let initialize = |session: &str| {
            http_json_response(
                "200 OK",
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {
                            "resources": {"subscribe": false, "listChanged": true},
                            "prompts": {"listChanged": true}
                        },
                        "serverInfo": {"name": "catalog-fixture", "version": "1"}
                    }
                }),
                Some(("MCP-Session-Id", session)),
            )
        };
        let accepted =
            "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
        let deleted =
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
        let catalog_responses = |session: &str| {
            vec![
                initialize(session),
                accepted.clone(),
                http_json_response(
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 1_000,
                        "result": {"resources": [resource_definition.clone()]}
                    }),
                    None,
                ),
                http_json_response(
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 2_000,
                        "result": {"resourceTemplates": [template_definition.clone()]}
                    }),
                    None,
                ),
                http_json_response(
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 3_000,
                        "result": {"prompts": [prompt_definition.clone()]}
                    }),
                    None,
                ),
            ]
        };
        let mut responses = catalog_responses("load-session");
        responses.push(deleted.clone());
        responses.extend(catalog_responses("resource-session"));
        responses.push(http_json_response(
            "200 OK",
            &json!({
                "jsonrpc": "2.0",
                "id": 20_000,
                "result": {
                    "contents": [{
                        "uri": "fixture://docs/readme",
                        "mimeType": "text/markdown",
                        "text": "# Untrusted fixture"
                    }]
                }
            }),
            None,
        ));
        responses.push(deleted.clone());
        responses.extend(catalog_responses("prompt-session"));
        responses.push(http_json_response(
            "200 OK",
            &json!({
                "jsonrpc": "2.0",
                "id": 30_000,
                "result": {
                    "description": "Fixture prompt result",
                    "messages": [{
                        "role": "user",
                        "content": {"type": "text", "text": "Review alpha"}
                    }]
                }
            }),
            None,
        ));
        responses.push(deleted);
        let (endpoint, requests, server_thread) = spawn_http_fixture(responses);
        let config = McpHttpServerConfig::new(
            "catalog".to_owned(),
            endpoint,
            McpHttpAuthentication::None,
            discovery.catalog_digest().expect("catalog digest"),
            true,
            Vec::new(),
            vec![resource_grant],
            vec![prompt_grant],
        )
        .expect("catalog config");
        let loaded =
            load_mcp_http_read_tools(&[config], BTreeMap::new()).expect("load catalog operations");
        assert_eq!(loaded.len(), 2);
        let resource = loaded
            .iter()
            .find(|tool| tool.descriptor().tool_id.contains(".resource."))
            .expect("resource operation");
        let resource_output = resource
            .execute(&json!({}), &NeverCancelled)
            .expect("read resource");
        let resource_json: Value =
            serde_json::from_slice(&resource_output.bytes).expect("resource JSON");
        assert_eq!(resource_json["contents"][0]["text"], "# Untrusted fixture");

        let prompt = loaded
            .iter()
            .find(|tool| tool.descriptor().tool_id == "mcp.catalog.prompt.review")
            .expect("prompt operation");
        let prompt_output = prompt
            .execute(&json!({"topic": "alpha"}), &NeverCancelled)
            .expect("get prompt");
        let prompt_json: Value = serde_json::from_slice(&prompt_output.bytes).expect("prompt JSON");
        assert_eq!(prompt_json["trust"], "untrusted_tool_evidence");
        assert_eq!(prompt_json["messages"][0]["role"], "user");

        server_thread.join().expect("catalog fixture server");
        let requests = requests.lock().expect("catalog requests");
        assert_eq!(requests.len(), 20);
        assert!(requests[11].contains("\"method\":\"resources/read\""));
        assert!(requests[18].contains("\"method\":\"prompts/get\""));
        assert!(requests[18].contains("\"arguments\":{\"topic\":\"alpha\"}"));
    }

    #[test]
    fn streamable_http_redirects_and_missing_credentials_fail_before_authority_expands() {
        let (endpoint, requests, server_thread) = spawn_http_fixture(vec![
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
        ]);
        let proposal = McpHttpEndpointConfig::new(
            "redirect".to_owned(),
            endpoint,
            McpHttpAuthentication::None,
        )
        .expect("proposal");
        assert!(matches!(
            inspect_mcp_http_endpoint(&proposal, None),
            Err(McpHostError::HttpStatus(307))
        ));
        server_thread.join().expect("redirect fixture server");
        let requests = requests.lock().expect("redirect requests");
        assert_eq!(requests.len(), 1);
        let lowercase = requests[0].to_ascii_lowercase();
        assert!(lowercase.contains("origin: http://127.0.0.1:"));
        assert!(lowercase.contains("accept: application/json, text/event-stream"));

        let definition = json!({
            "name": "lookup",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {}
            }
        });
        let grant = McpToolGrant::new(definition, 5_000, 64 * 1024).expect("grant");
        let protected = McpHttpServerConfig::new(
            "protected".to_owned(),
            "http://127.0.0.1:9/mcp".to_owned(),
            McpHttpAuthentication::Bearer {
                credential: mealy_application::ProviderCredentialReference::Broker {
                    secret_id: "missing".to_owned(),
                },
            },
            "a".repeat(64),
            true,
            vec![grant],
            Vec::new(),
            Vec::new(),
        )
        .expect("protected config");
        assert!(matches!(
            load_mcp_http_read_tools(&[protected], BTreeMap::new()),
            Err(McpHostError::InvalidConfiguration)
        ));
    }

    #[test]
    fn streamable_http_closes_an_established_session_after_discovery_failure() {
        let (endpoint, requests, server_thread) = spawn_http_fixture(vec![
            http_json_response(
                "200 OK",
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "http-fixture", "version": "1"}
                    }
                }),
                Some(("MCP-Session-Id", "failed-discovery-session")),
            ),
            "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
            http_json_response(
                "200 OK",
                &json!({
                    "jsonrpc": "2.0",
                    "id": 100,
                    "result": {"notTools": []}
                }),
                None,
            ),
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
        ]);
        let proposal = McpHttpEndpointConfig::new(
            "failed-discovery".to_owned(),
            endpoint,
            McpHttpAuthentication::None,
        )
        .expect("proposal");
        assert!(matches!(
            inspect_mcp_http_endpoint(&proposal, None),
            Err(McpHostError::InvalidProtocol)
        ));
        server_thread.join().expect("failure fixture server");
        let requests = requests.lock().expect("failure requests");
        assert_eq!(requests.len(), 4);
        assert!(requests[3].starts_with("DELETE /mcp HTTP/1.1"));
        assert!(
            requests[3]
                .to_ascii_lowercase()
                .contains("mcp-session-id: failed-discovery-session")
        );
    }

    fn spawn_http_fixture(
        responses: Vec<String>,
    ) -> (String, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP fixture");
        let address = listener.local_addr().expect("HTTP fixture address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let server = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept HTTP fixture request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("fixture read timeout");
                let request = read_http_request(&mut stream);
                captured.lock().expect("capture request").push(request);
                stream
                    .write_all(response.as_bytes())
                    .expect("write HTTP fixture response");
            }
        });
        (format!("http://{address}/mcp"), requests, server)
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4_096];
        let header_end = loop {
            let count = stream.read(&mut buffer).expect("read HTTP fixture request");
            assert_ne!(count, 0, "request closed before headers");
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
            assert!(
                bytes.len() <= 64 * 1024,
                "fixture request headers exceeded bound"
            );
        };
        let headers = std::str::from_utf8(&bytes[..header_end]).expect("UTF-8 request headers");
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
            })
            .unwrap_or(0);
        while bytes.len() < header_end.saturating_add(content_length) {
            let count = stream.read(&mut buffer).expect("read HTTP fixture body");
            assert_ne!(count, 0, "request closed before body");
            bytes.extend_from_slice(&buffer[..count]);
        }
        String::from_utf8(bytes).expect("UTF-8 fixture request")
    }

    fn http_json_response(
        status: &str,
        value: &Value,
        extra_header: Option<(&str, &str)>,
    ) -> String {
        let body = value.to_string();
        let extra = extra_header
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .unwrap_or_default();
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn http_sse_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }
}
