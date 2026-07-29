//! Secure typed Rust client for Mealy's authenticated owner API.
//!
//! The blocking client deliberately ignores ambient proxies, refuses redirects,
//! bounds response bodies, and validates the API version before returning any
//! protocol DTO. Clear-text HTTP is accepted only for literal loopback origins.
//!
//! # Example
//!
//! ```
//! use mealy_client::{
//!     ClientError, MealyClient,
//!     protocol::LocalConnectionInfo,
//! };
//!
//! fn daemon_is_ready(connection: &LocalConnectionInfo) -> Result<bool, ClientError> {
//!     let client = MealyClient::from_connection(connection)?;
//!     Ok(client.readiness()?.ready)
//! }
//! ```

use std::fmt;
use std::io::Read;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mealy_protocol::{
    API_VERSION, AdminStatusResponse, ApiErrorResponse, ApprovalResolutionReceipt,
    AutomationLifecycleRequest, AutomationResponse, AutomationRunsResponse, AutomationsResponse,
    CancelTaskRequest, ControlTaskRequest, CreateAutomationRequest, CreateDiscordChannelRequest,
    CreateSessionCheckpointRequest, CreateSessionRequest, CreateSessionResponse,
    CreateSlackChannelRequest, CreateTelegramChannelRequest, CreateWebhookChannelRequest,
    CreateWebhookChannelResponse, DiscordChannelResponse, DiscordChannelsResponse,
    EditAutomationRequest, EnableExtensionRequest, ExtensionInvocationResponse,
    ExtensionLifecycleRequest, ExtensionResponse, ExtensionsResponse, ForkSessionRequest,
    HealthResponse, InputAdmissionResponse, InstallExtensionRequest, InvokeExtensionRequest,
    LocalConnectionInfo, PendingApprovalsResponse, ProviderCatalogResponse, ReadinessResponse,
    ResolveApprovalRequest, RevokeDiscordChannelRequest, RevokeSlackChannelRequest,
    RevokeTelegramChannelRequest, RevokeWebhookChannelRequest, SessionCheckpointResponse,
    SessionCheckpointsResponse, SessionForkResponse, SessionProviderSelectionResponse,
    SessionSearchResponse, SessionStatusResponse, SessionTitleResponse, SessionsResponse,
    SlackChannelResponse, SlackChannelsResponse, StageExtensionManifestRequest,
    SubmitImageInputRequest, SubmitInputRequest, TaskCancellationReceipt, TaskControlReceipt,
    TaskReplayResponse, TaskResponse, TelegramChannelResponse, TelegramChannelsResponse,
    TimelineCursor, TimelinePageResponse, UpdateSessionProviderSelectionRequest,
    UpdateSessionTitleRequest, WebhookChannelResponse, WebhookChannelsResponse,
};
use reqwest::Method;
use reqwest::blocking::{Body, Client as HttpClient, RequestBuilder, Response};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

/// Versioned request and response DTOs used by this client.
pub use mealy_protocol as protocol;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_REQUEST_BYTES: usize = 8 * 1_024 * 1_024;
const DEFAULT_MAXIMUM_RESPONSE_BYTES: usize = 8 * 1_024 * 1_024;
const HARD_MAXIMUM_RESPONSE_BYTES: usize = 64 * 1_024 * 1_024;
const MAXIMUM_BEARER_TOKEN_BYTES: usize = 16 * 1_024;
const MAXIMUM_PATH_SEGMENT_BYTES: usize = 4_096;
const MAXIMUM_ERROR_CODE_BYTES: usize = 64;
const MAXIMUM_ERROR_MESSAGE_BYTES: usize = 4_096;

/// Failure returned by the typed Mealy client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The configured API origin is invalid or violates transport policy.
    #[error("invalid Mealy API base URL: {0}")]
    InvalidBaseUrl(&'static str),
    /// The bearer credential cannot be represented safely as an HTTP header.
    #[error("invalid Mealy bearer credential")]
    InvalidBearerToken,
    /// A builder setting is outside the SDK's safe bounds.
    #[error("invalid Mealy client configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// An opaque identifier cannot be represented as one unambiguous path segment.
    #[error("invalid Mealy API path identifier")]
    InvalidPathIdentifier,
    /// A typed request declares a version other than the SDK's version.
    #[error("request API version is incompatible with supported version `{expected}`")]
    RequestVersionMismatch {
        /// Version found in the request.
        actual: String,
        /// Version supported by this SDK.
        expected: &'static str,
    },
    /// A serialized typed command exceeded the fixed client-side request bound.
    #[error("Mealy API request exceeded the {limit}-byte client bound")]
    RequestTooLarge {
        /// Fixed maximum serialized request size.
        limit: usize,
    },
    /// The daemon response declares a version other than the SDK's version.
    #[error("response API version is incompatible with supported version `{expected}`")]
    ResponseVersionMismatch {
        /// Version found in the response.
        actual: String,
        /// Version supported by this SDK.
        expected: &'static str,
    },
    /// The daemon returned a versioned, owner-safe API error.
    #[error("Mealy API returned HTTP {status}: {} ({})", error.message, error.code)]
    Api {
        /// Numeric HTTP status.
        status: u16,
        /// Stable versioned error body.
        error: ApiErrorResponse,
    },
    /// The daemon returned a non-JSON or otherwise unexpected HTTP response.
    #[error("Mealy API returned an unexpected HTTP {status} response")]
    UnexpectedResponse {
        /// Numeric HTTP status.
        status: u16,
    },
    /// The daemon response exceeded the configured byte bound.
    #[error("Mealy API response exceeded the {limit}-byte client bound")]
    ResponseTooLarge {
        /// Configured maximum response size.
        limit: usize,
    },
    /// The daemon returned malformed JSON or omitted required version evidence.
    #[error("Mealy API returned malformed versioned JSON")]
    MalformedResponse,
    /// A request DTO could not be encoded as versioned JSON.
    #[error("Mealy API request could not be encoded")]
    RequestEncoding,
    /// A transport, TLS, timeout, or response-read failure occurred.
    #[error("Mealy API transport failed")]
    Transport {
        /// Underlying transport failure.
        #[source]
        source: reqwest::Error,
    },
    /// A bounded response body could not be read.
    #[error("Mealy API response body could not be read")]
    ResponseRead {
        /// Underlying body-read failure.
        #[source]
        source: std::io::Error,
    },
}

/// Builder for a secure [`MealyClient`].
pub struct MealyClientBuilder {
    base_url: Url,
    bearer_token: Zeroizing<String>,
    connect_timeout: Duration,
    request_timeout: Duration,
    maximum_response_bytes: usize,
}

impl fmt::Debug for MealyClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MealyClientBuilder")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"[REDACTED]")
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .finish()
    }
}

impl MealyClientBuilder {
    /// Overrides the TCP/TLS connection timeout.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Overrides the complete request timeout.
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Overrides the bounded JSON response size.
    ///
    /// Values must be between one byte and 64 MiB.
    #[must_use]
    pub fn maximum_response_bytes(mut self, maximum: usize) -> Self {
        self.maximum_response_bytes = maximum;
        self
    }

    /// Builds the authenticated client after validating every security bound.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when a timeout or size bound is invalid, the bearer
    /// token cannot form a header, or the underlying HTTP client cannot be built.
    pub fn build(self) -> Result<MealyClient, ClientError> {
        if self.connect_timeout.is_zero() {
            return Err(ClientError::InvalidConfiguration(
                "connect timeout must be positive",
            ));
        }
        if self.request_timeout.is_zero() {
            return Err(ClientError::InvalidConfiguration(
                "request timeout must be positive",
            ));
        }
        if self.maximum_response_bytes == 0
            || self.maximum_response_bytes > HARD_MAXIMUM_RESPONSE_BYTES
        {
            return Err(ClientError::InvalidConfiguration(
                "maximum response size must be between one byte and 64 MiB",
            ));
        }

        let mut authorization = Zeroizing::new(Vec::with_capacity(
            "Bearer ".len().saturating_add(self.bearer_token.len()),
        ));
        authorization.extend_from_slice(b"Bearer ");
        authorization.extend_from_slice(self.bearer_token.as_bytes());
        let mut authorization =
            HeaderValue::from_bytes(&authorization).map_err(|_| ClientError::InvalidBearerToken)?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let http = HttpClient::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers)
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .user_agent(concat!("mealy-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|source| ClientError::Transport { source })?;

        Ok(MealyClient {
            base_url: self.base_url,
            http,
            maximum_response_bytes: self.maximum_response_bytes,
        })
    }
}

/// Secure blocking client for Mealy's authenticated owner API.
#[derive(Clone)]
pub struct MealyClient {
    base_url: Url,
    http: HttpClient,
    maximum_response_bytes: usize,
}

impl fmt::Debug for MealyClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MealyClient")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"[REDACTED]")
            .field("http", &"[AUTHENTICATED CLIENT]")
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .finish()
    }
}

impl MealyClient {
    /// Creates a client with fail-closed transport and response defaults.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when the origin, credential, client configuration,
    /// or underlying HTTP client violates the SDK's security contract.
    pub fn new(
        base_url: impl AsRef<str>,
        bearer_token: impl Into<String>,
    ) -> Result<Self, ClientError> {
        Self::builder(base_url, bearer_token)?.build()
    }

    /// Creates a client from the OS-user-private descriptor emitted by `mealyd`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when the descriptor version is incompatible or its
    /// origin, credential, or client configuration violates the SDK contract.
    pub fn from_connection(connection: &LocalConnectionInfo) -> Result<Self, ClientError> {
        if connection.api_version != API_VERSION {
            return Err(ClientError::RequestVersionMismatch {
                actual: connection.api_version.clone(),
                expected: API_VERSION,
            });
        }
        let url = validate_base_url(&connection.base_url)?;
        if url.scheme() != "http"
            || url.port().is_none()
            || !url.host().is_some_and(|host| literal_loopback(&host))
        {
            return Err(ClientError::InvalidBaseUrl(
                "local descriptor must use loopback HTTP with an explicit port",
            ));
        }
        let mut decoded_token = Zeroizing::new([0_u8; 32]);
        if URL_SAFE_NO_PAD.decode_slice(&connection.bearer_token, decoded_token.as_mut()) != Ok(32)
        {
            return Err(ClientError::InvalidBearerToken);
        }
        Self::new(&connection.base_url, connection.bearer_token.clone())
    }

    /// Starts a client builder after validating the API origin.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when the origin is unsafe or malformed, or when the
    /// bearer token is empty.
    pub fn builder(
        base_url: impl AsRef<str>,
        bearer_token: impl Into<String>,
    ) -> Result<MealyClientBuilder, ClientError> {
        let base_url = validate_base_url(base_url.as_ref())?;
        let bearer_token = Zeroizing::new(bearer_token.into());
        if bearer_token.is_empty() || bearer_token.len() > MAXIMUM_BEARER_TOKEN_BYTES {
            return Err(ClientError::InvalidBearerToken);
        }
        Ok(MealyClientBuilder {
            base_url,
            bearer_token,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            maximum_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
        })
    }

    /// Returns the process liveness projection.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn liveness(&self) -> Result<HealthResponse, ClientError> {
        self.get(&["health", "live"])
    }

    /// Returns migration, recovery, and command-admission readiness.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn readiness(&self) -> Result<ReadinessResponse, ClientError> {
        self.get(&["health", "ready"])
    }

    /// Returns authenticated owner operational status.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn admin_status(&self) -> Result<AdminStatusResponse, ClientError> {
        self.get(&["v1", "admin", "status"])
    }

    /// Returns the exact configured provider/model catalog.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn provider_catalog(&self) -> Result<ProviderCatalogResponse, ClientError> {
        self.get(&["v1", "providers", "catalog"])
    }

    /// Creates one durable session.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn create_session(
        &self,
        request: &CreateSessionRequest,
    ) -> Result<CreateSessionResponse, ClientError> {
        self.post(&["v1", "sessions"], request, ResponseVersion::TopLevel)
    }

    /// Lists the most recently updated sessions.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn sessions(&self, limit: usize) -> Result<SessionsResponse, ClientError> {
        let mut url = self.endpoint(&["v1", "sessions"])?;
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
        self.get_url(url, ResponseVersion::TopLevel)
    }

    /// Searches canonical session transcripts.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn search_sessions(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<SessionSearchResponse, ClientError> {
        let mut url = self.endpoint(&["v1", "sessions", "search"])?;
        url.query_pairs_mut()
            .append_pair("query", query)
            .append_pair("limit", &limit.to_string());
        self.get_url(url, ResponseVersion::TopLevel)
    }

    /// Returns current durable session status.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn session_status(&self, session_id: &str) -> Result<SessionStatusResponse, ClientError> {
        self.get(&["v1", "sessions", path_identifier(session_id)?, "status"])
    }

    /// Updates one session's canonical title with an optimistic revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn update_session_title(
        &self,
        session_id: &str,
        request: &UpdateSessionTitleRequest,
    ) -> Result<SessionTitleResponse, ClientError> {
        self.patch(
            &["v1", "sessions", path_identifier(session_id)?],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Returns a session's durable provider/model default.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn session_provider_selection(
        &self,
        session_id: &str,
    ) -> Result<SessionProviderSelectionResponse, ClientError> {
        self.get(&[
            "v1",
            "sessions",
            path_identifier(session_id)?,
            "provider-selection",
        ])
    }

    /// Transactionally changes the provider/model default for future turns.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn update_session_provider_selection(
        &self,
        session_id: &str,
        request: &UpdateSessionProviderSelectionRequest,
    ) -> Result<SessionProviderSelectionResponse, ClientError> {
        self.patch(
            &[
                "v1",
                "sessions",
                path_identifier(session_id)?,
                "provider-selection",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Lists immutable checkpoints for one session.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn session_checkpoints(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<SessionCheckpointsResponse, ClientError> {
        let mut url = self.endpoint(&[
            "v1",
            "sessions",
            path_identifier(session_id)?,
            "checkpoints",
        ])?;
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
        self.get_url(url, ResponseVersion::TopLevel)
    }

    /// Creates an immutable session checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn create_session_checkpoint(
        &self,
        session_id: &str,
        request: &CreateSessionCheckpointRequest,
    ) -> Result<SessionCheckpointResponse, ClientError> {
        self.post(
            &[
                "v1",
                "sessions",
                path_identifier(session_id)?,
                "checkpoints",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Forks a fresh session from one immutable checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn fork_session(
        &self,
        session_id: &str,
        request: &ForkSessionRequest,
    ) -> Result<SessionForkResponse, ClientError> {
        self.post(
            &["v1", "sessions", path_identifier(session_id)?, "forks"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Returns one bounded page of the canonical durable timeline.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn timeline(
        &self,
        session_id: &str,
        after: Option<TimelineCursor>,
        limit: usize,
    ) -> Result<TimelinePageResponse, ClientError> {
        let mut url =
            self.endpoint(&["v1", "sessions", path_identifier(session_id)?, "timeline"])?;
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(after) = after {
                pairs.append_pair("after", &after.0.to_string());
            }
            pairs.append_pair("limit", &limit.to_string());
        }
        self.get_url(url, ResponseVersion::TopLevel)
    }

    /// Durably admits one idempotent text input to a session.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn submit_input(
        &self,
        session_id: &str,
        request: &SubmitInputRequest,
    ) -> Result<InputAdmissionResponse, ClientError> {
        self.post(
            &["v1", "sessions", path_identifier(session_id)?, "inputs"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Durably admits one bounded image-bearing input to an exact capable route.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn submit_image_input(
        &self,
        session_id: &str,
        request: &SubmitImageInputRequest,
    ) -> Result<InputAdmissionResponse, ClientError> {
        self.post(
            &[
                "v1",
                "sessions",
                path_identifier(session_id)?,
                "image-inputs",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Returns the current owner-authorized task projection.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn task(&self, task_id: &str) -> Result<TaskResponse, ClientError> {
        self.get(&["v1", "tasks", path_identifier(task_id)?])
    }

    /// Requests idempotent cooperative cancellation of one task.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn cancel_task(
        &self,
        task_id: &str,
        request: &CancelTaskRequest,
    ) -> Result<TaskCancellationReceipt, ClientError> {
        self.post(
            &["v1", "tasks", path_identifier(task_id)?, "cancel"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Pauses one task under an optimistic revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn pause_task(
        &self,
        task_id: &str,
        request: &ControlTaskRequest,
    ) -> Result<TaskControlReceipt, ClientError> {
        self.post(
            &["v1", "tasks", path_identifier(task_id)?, "pause"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Resumes one paused task under an optimistic revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn resume_task(
        &self,
        task_id: &str,
        request: &ControlTaskRequest,
    ) -> Result<TaskControlReceipt, ClientError> {
        self.post(
            &["v1", "tasks", path_identifier(task_id)?, "resume"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Reconstructs one task exclusively from recorded durable evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn task_replay(&self, task_id: &str) -> Result<TaskReplayResponse, ClientError> {
        self.get(&["v1", "tasks", path_identifier(task_id)?, "replay"])
    }

    /// Lists approval subjects awaiting an exact owner decision.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn pending_approvals(&self) -> Result<PendingApprovalsResponse, ClientError> {
        self.get(&["v1", "approvals"])
    }

    /// Resolves one exact approval subject using its digest and idempotency fence.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn resolve_approval(
        &self,
        approval_id: &str,
        request: &ResolveApprovalRequest,
    ) -> Result<ApprovalResolutionReceipt, ClientError> {
        self.post(
            &["v1", "approvals", path_identifier(approval_id)?, "resolve"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Lists owner-authorized one-shot and future-event automations.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn automations(&self) -> Result<AutomationsResponse, ClientError> {
        self.get(&["v1", "automations"])
    }

    /// Creates or reconciles one client-keyed automation.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn create_automation(
        &self,
        request: &CreateAutomationRequest,
    ) -> Result<AutomationResponse, ClientError> {
        self.post(&["v1", "automations"], request, ResponseVersion::TopLevel)
    }

    /// Returns one owner-authorized automation projection.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn automation(&self, automation_id: &str) -> Result<AutomationResponse, ClientError> {
        self.get(&["v1", "automations", path_identifier(automation_id)?])
    }

    /// Replaces one automation definition under its exact revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn edit_automation(
        &self,
        automation_id: &str,
        request: &EditAutomationRequest,
    ) -> Result<AutomationResponse, ClientError> {
        self.patch(
            &["v1", "automations", path_identifier(automation_id)?],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Pauses one active automation under its exact revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn pause_automation(
        &self,
        automation_id: &str,
        request: &AutomationLifecycleRequest,
    ) -> Result<AutomationResponse, ClientError> {
        self.post(
            &[
                "v1",
                "automations",
                path_identifier(automation_id)?,
                "pause",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Resumes one paused automation under its exact revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn resume_automation(
        &self,
        automation_id: &str,
        request: &AutomationLifecycleRequest,
    ) -> Result<AutomationResponse, ClientError> {
        self.post(
            &[
                "v1",
                "automations",
                path_identifier(automation_id)?,
                "resume",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Terminally cancels one automation under its exact revision fence.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn cancel_automation(
        &self,
        automation_id: &str,
        request: &AutomationLifecycleRequest,
    ) -> Result<AutomationResponse, ClientError> {
        self.post(
            &[
                "v1",
                "automations",
                path_identifier(automation_id)?,
                "cancel",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Returns bounded newest-first occurrence history for one automation.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn automation_runs(
        &self,
        automation_id: &str,
        limit: usize,
    ) -> Result<AutomationRunsResponse, ClientError> {
        let mut url =
            self.endpoint(&["v1", "automations", path_identifier(automation_id)?, "runs"])?;
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
        self.get_url(url, ResponseVersion::TopLevel)
    }

    /// Lists installed governed extensions.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn extensions(&self) -> Result<ExtensionsResponse, ClientError> {
        self.get(&["v1", "extensions"])
    }

    /// Returns one governed extension projection.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn extension(&self, extension_id: &str) -> Result<ExtensionResponse, ClientError> {
        self.get(&["v1", "extensions", path_identifier(extension_id)?])
    }

    /// Installs one new inert, digest-pinned extension.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn install_extension(
        &self,
        request: &InstallExtensionRequest,
    ) -> Result<ExtensionResponse, ClientError> {
        self.post(&["v1", "extensions"], request, ResponseVersion::TopLevel)
    }

    /// Stages a digest-pinned extension update or rollback and removes old authority.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn stage_extension(
        &self,
        extension_id: &str,
        request: &StageExtensionManifestRequest,
    ) -> Result<ExtensionResponse, ClientError> {
        self.post(
            &["v1", "extensions", path_identifier(extension_id)?, "stage"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Enables one exact extension revision under an explicit least-authority grant.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn enable_extension(
        &self,
        extension_id: &str,
        request: &EnableExtensionRequest,
    ) -> Result<ExtensionResponse, ClientError> {
        self.post(
            &["v1", "extensions", path_identifier(extension_id)?, "enable"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Disables an extension without deleting its immutable history.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn disable_extension(
        &self,
        extension_id: &str,
        request: &ExtensionLifecycleRequest,
    ) -> Result<ExtensionResponse, ClientError> {
        self.post(
            &[
                "v1",
                "extensions",
                path_identifier(extension_id)?,
                "disable",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Terminally revokes an extension.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn revoke_extension(
        &self,
        extension_id: &str,
        request: &ExtensionLifecycleRequest,
    ) -> Result<ExtensionResponse, ClientError> {
        self.post(
            &["v1", "extensions", path_identifier(extension_id)?, "revoke"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Invokes one currently granted read-only extension capability.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn invoke_extension(
        &self,
        extension_id: &str,
        request: &InvokeExtensionRequest,
    ) -> Result<ExtensionInvocationResponse, ClientError> {
        self.post(
            &["v1", "extensions", path_identifier(extension_id)?, "invoke"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Lists signed generic webhook channel bindings.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn webhook_channels(&self) -> Result<WebhookChannelsResponse, ClientError> {
        self.get(&["v1", "channels", "webhooks"])
    }

    /// Returns one signed generic webhook channel.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn webhook_channel(&self, binding_id: &str) -> Result<WebhookChannelResponse, ClientError> {
        self.get(&["v1", "channels", "webhooks", path_identifier(binding_id)?])
    }

    /// Creates a signed generic webhook channel.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn create_webhook_channel(
        &self,
        request: &CreateWebhookChannelRequest,
    ) -> Result<CreateWebhookChannelResponse, ClientError> {
        self.post(
            &["v1", "channels", "webhooks"],
            request,
            ResponseVersion::NestedChannel,
        )
    }

    /// Terminally revokes a signed generic webhook channel.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn revoke_webhook_channel(
        &self,
        binding_id: &str,
        request: &RevokeWebhookChannelRequest,
    ) -> Result<WebhookChannelResponse, ClientError> {
        self.post(
            &[
                "v1",
                "channels",
                "webhooks",
                path_identifier(binding_id)?,
                "revoke",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Lists Telegram channel bindings.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn telegram_channels(&self) -> Result<TelegramChannelsResponse, ClientError> {
        self.get(&["v1", "channels", "telegram"])
    }

    /// Returns one Telegram channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn telegram_channel(
        &self,
        binding_id: &str,
    ) -> Result<TelegramChannelResponse, ClientError> {
        self.get(&["v1", "channels", "telegram", path_identifier(binding_id)?])
    }

    /// Creates one exact Telegram bot/user/chat binding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn create_telegram_channel(
        &self,
        request: &CreateTelegramChannelRequest,
    ) -> Result<TelegramChannelResponse, ClientError> {
        self.post(
            &["v1", "channels", "telegram"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Terminally revokes a Telegram channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn revoke_telegram_channel(
        &self,
        binding_id: &str,
        request: &RevokeTelegramChannelRequest,
    ) -> Result<TelegramChannelResponse, ClientError> {
        self.post(
            &[
                "v1",
                "channels",
                "telegram",
                path_identifier(binding_id)?,
                "revoke",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Lists Discord direct-message channel bindings.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn discord_channels(&self) -> Result<DiscordChannelsResponse, ClientError> {
        self.get(&["v1", "channels", "discord"])
    }

    /// Returns one Discord direct-message channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn discord_channel(&self, binding_id: &str) -> Result<DiscordChannelResponse, ClientError> {
        self.get(&["v1", "channels", "discord", path_identifier(binding_id)?])
    }

    /// Creates one exact Discord bot/human/direct-message binding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn create_discord_channel(
        &self,
        request: &CreateDiscordChannelRequest,
    ) -> Result<DiscordChannelResponse, ClientError> {
        self.post(
            &["v1", "channels", "discord"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Terminally revokes a Discord channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn revoke_discord_channel(
        &self,
        binding_id: &str,
        request: &RevokeDiscordChannelRequest,
    ) -> Result<DiscordChannelResponse, ClientError> {
        self.post(
            &[
                "v1",
                "channels",
                "discord",
                path_identifier(binding_id)?,
                "revoke",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Lists Slack Socket Mode channel bindings.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn slack_channels(&self) -> Result<SlackChannelsResponse, ClientError> {
        self.get(&["v1", "channels", "slack"])
    }

    /// Returns one Slack Socket Mode channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn slack_channel(&self, binding_id: &str) -> Result<SlackChannelResponse, ClientError> {
        self.get(&["v1", "channels", "slack", path_identifier(binding_id)?])
    }

    /// Creates one exact Slack app/bot/member/conversation binding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn create_slack_channel(
        &self,
        request: &CreateSlackChannelRequest,
    ) -> Result<SlackChannelResponse, ClientError> {
        self.post(
            &["v1", "channels", "slack"],
            request,
            ResponseVersion::TopLevel,
        )
    }

    /// Terminally revokes a Slack channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when validation, transport, or versioned decoding fails.
    pub fn revoke_slack_channel(
        &self,
        binding_id: &str,
        request: &RevokeSlackChannelRequest,
    ) -> Result<SlackChannelResponse, ClientError> {
        self.post(
            &[
                "v1",
                "channels",
                "slack",
                path_identifier(binding_id)?,
                "revoke",
            ],
            request,
            ResponseVersion::TopLevel,
        )
    }

    fn get<T>(&self, path: &[&str]) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
    {
        self.get_url(self.endpoint(path)?, ResponseVersion::TopLevel)
    }

    fn get_url<T>(&self, url: Url, version: ResponseVersion) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
    {
        let request = self.http.request(Method::GET, url);
        self.send(request, version)
    }

    fn post<Q, T>(
        &self,
        path: &[&str],
        request: &Q,
        version: ResponseVersion,
    ) -> Result<T, ClientError>
    where
        Q: Serialize + VersionedRequest,
        T: DeserializeOwned,
    {
        self.send_json(Method::POST, path, request, version)
    }

    fn patch<Q, T>(
        &self,
        path: &[&str],
        request: &Q,
        version: ResponseVersion,
    ) -> Result<T, ClientError>
    where
        Q: Serialize + VersionedRequest,
        T: DeserializeOwned,
    {
        self.send_json(Method::PATCH, path, request, version)
    }

    fn send_json<Q, T>(
        &self,
        method: Method,
        path: &[&str],
        request: &Q,
        version: ResponseVersion,
    ) -> Result<T, ClientError>
    where
        Q: Serialize + VersionedRequest,
        T: DeserializeOwned,
    {
        validate_request_version(request.api_version())?;
        let body =
            Zeroizing::new(serde_json::to_vec(request).map_err(|_| ClientError::RequestEncoding)?);
        if body.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ClientError::RequestTooLarge {
                limit: MAXIMUM_REQUEST_BYTES,
            });
        }
        let body_length = u64::try_from(body.len()).map_err(|_| ClientError::RequestEncoding)?;
        let request = self
            .http
            .request(method, self.endpoint(path)?)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::sized(ZeroizingReader::new(body), body_length));
        self.send(request, version)
    }

    fn send<T>(
        &self,
        request: RequestBuilder,
        response_version: ResponseVersion,
    ) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
    {
        let response = request
            .send()
            .map_err(|source| ClientError::Transport { source })?;
        let status = response.status();
        let body = read_json_body(response, self.maximum_response_bytes)?;
        let value = serde_json::from_slice::<serde_json::Value>(&body).map_err(|_| {
            if status.is_success() {
                ClientError::MalformedResponse
            } else {
                ClientError::UnexpectedResponse {
                    status: status.as_u16(),
                }
            }
        })?;

        if !status.is_success() {
            let error = serde_json::from_value::<ApiErrorResponse>(value).map_err(|_| {
                ClientError::UnexpectedResponse {
                    status: status.as_u16(),
                }
            })?;
            validate_response_version(&error.api_version)?;
            if !valid_api_error(&error) {
                return Err(ClientError::UnexpectedResponse {
                    status: status.as_u16(),
                });
            }
            return Err(ClientError::Api {
                status: status.as_u16(),
                error,
            });
        }

        validate_response_value(&value, response_version)?;
        serde_json::from_value(value).map_err(|_| ClientError::MalformedResponse)
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, ClientError> {
        let mut url = self.base_url.clone();
        let mut path = url
            .path_segments_mut()
            .map_err(|()| ClientError::InvalidBaseUrl("origin cannot be a base URL"))?;
        path.clear();
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        Ok(url)
    }
}

#[derive(Clone, Copy)]
enum ResponseVersion {
    TopLevel,
    NestedChannel,
}

trait VersionedRequest {
    fn api_version(&self) -> &str;
}

macro_rules! versioned_requests {
    ($($request:ty),+ $(,)?) => {
        $(
            impl VersionedRequest for $request {
                fn api_version(&self) -> &str {
                    &self.api_version
                }
            }
        )+
    };
}

versioned_requests!(
    CreateSessionRequest,
    SubmitInputRequest,
    SubmitImageInputRequest,
    UpdateSessionTitleRequest,
    UpdateSessionProviderSelectionRequest,
    CreateSessionCheckpointRequest,
    ForkSessionRequest,
    CancelTaskRequest,
    ControlTaskRequest,
    ResolveApprovalRequest,
    CreateAutomationRequest,
    EditAutomationRequest,
    AutomationLifecycleRequest,
    InstallExtensionRequest,
    StageExtensionManifestRequest,
    EnableExtensionRequest,
    ExtensionLifecycleRequest,
    InvokeExtensionRequest,
    CreateWebhookChannelRequest,
    RevokeWebhookChannelRequest,
    CreateTelegramChannelRequest,
    RevokeTelegramChannelRequest,
    CreateDiscordChannelRequest,
    RevokeDiscordChannelRequest,
    CreateSlackChannelRequest,
    RevokeSlackChannelRequest,
);

struct ZeroizingReader {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}

impl ZeroizingReader {
    fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl Read for ZeroizingReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.bytes[self.offset..];
        let count = remaining.len().min(buffer.len());
        buffer[..count].copy_from_slice(&remaining[..count]);
        self.offset = self.offset.saturating_add(count);
        Ok(count)
    }
}

fn validate_base_url(value: &str) -> Result<Url, ClientError> {
    let url = Url::parse(value).map_err(|_| ClientError::InvalidBaseUrl("URL is malformed"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ClientError::InvalidBaseUrl(
            "embedded credentials are forbidden",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ClientError::InvalidBaseUrl(
            "query strings and fragments are forbidden",
        ));
    }
    if !matches!(url.path(), "" | "/") {
        return Err(ClientError::InvalidBaseUrl("base path must be empty"));
    }
    let host = url
        .host()
        .ok_or(ClientError::InvalidBaseUrl("host is required"))?;
    match url.scheme() {
        "https" => {}
        "http" if literal_loopback(&host) => {}
        "http" => {
            return Err(ClientError::InvalidBaseUrl(
                "clear-text HTTP requires a literal loopback address",
            ));
        }
        _ => {
            return Err(ClientError::InvalidBaseUrl(
                "only HTTPS or loopback HTTP is supported",
            ));
        }
    }
    Ok(url)
}

fn literal_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
        Host::Domain(_) => false,
    }
}

fn path_identifier(value: &str) -> Result<&str, ClientError> {
    if value.is_empty()
        || value.len() > MAXIMUM_PATH_SEGMENT_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | '?' | '#'))
    {
        return Err(ClientError::InvalidPathIdentifier);
    }
    Ok(value)
}

fn validate_request_version(actual: &str) -> Result<(), ClientError> {
    if actual != API_VERSION {
        return Err(ClientError::RequestVersionMismatch {
            actual: actual.to_owned(),
            expected: API_VERSION,
        });
    }
    Ok(())
}

fn validate_response_value(
    value: &serde_json::Value,
    location: ResponseVersion,
) -> Result<(), ClientError> {
    let actual = match location {
        ResponseVersion::TopLevel => value.get("apiVersion"),
        ResponseVersion::NestedChannel => value.pointer("/channel/apiVersion"),
    }
    .and_then(serde_json::Value::as_str)
    .ok_or(ClientError::MalformedResponse)?;
    validate_response_version(actual)
}

fn validate_response_version(actual: &str) -> Result<(), ClientError> {
    if actual.is_empty()
        || actual.len() > 32
        || !actual
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(ClientError::MalformedResponse);
    }
    if actual != API_VERSION {
        return Err(ClientError::ResponseVersionMismatch {
            actual: actual.to_owned(),
            expected: API_VERSION,
        });
    }
    Ok(())
}

fn valid_api_error(error: &ApiErrorResponse) -> bool {
    !error.code.is_empty()
        && error.code.len() <= MAXIMUM_ERROR_CODE_BYTES
        && error
            .code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !error.message.is_empty()
        && error.message.len() <= MAXIMUM_ERROR_MESSAGE_BYTES
        && error.message.trim() == error.message
        && !error.message.chars().any(char::is_control)
}

fn read_json_body(
    mut response: Response,
    maximum_response_bytes: usize,
) -> Result<Vec<u8>, ClientError> {
    let status = response.status();
    if !is_json_content_type(response.headers()) {
        return Err(ClientError::UnexpectedResponse {
            status: status.as_u16(),
        });
    }
    let mut content_lengths = response.headers().get_all(CONTENT_LENGTH).iter();
    if let Some(content_length) = content_lengths.next() {
        if content_lengths.next().is_some() {
            return Err(ClientError::UnexpectedResponse {
                status: status.as_u16(),
            });
        }
        let content_length = content_length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(ClientError::UnexpectedResponse {
                status: status.as_u16(),
            })?;
        if content_length > maximum_response_bytes {
            return Err(ClientError::ResponseTooLarge {
                limit: maximum_response_bytes,
            });
        }
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take(
            u64::try_from(maximum_response_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut body)
        .map_err(|source| ClientError::ResponseRead { source })?;
    if body.len() > maximum_response_bytes {
        return Err(ClientError::ResponseTooLarge {
            limit: maximum_response_bytes,
        });
    }
    Ok(body)
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpListener};
    use std::thread;

    use mealy_protocol::{
        API_VERSION, AutomationActionCommand, AutomationTriggerRequest, CreateAutomationRequest,
        CreateSessionRequest, DeliveryMode, LocalConnectionInfo, ProviderSelectionCommand,
        SubmitInputRequest, UpdateSessionTitleRequest,
    };

    use super::{ClientError, MealyClient, ResponseVersion, validate_response_value};

    fn serve_once(status: &str, body: String) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener");
        let address: SocketAddr = listener.local_addr().expect("listener address");
        let status = status.to_owned();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("test connection");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4_096];
            loop {
                let count = stream.read(&mut buffer).expect("request read");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if let Some(header_end) = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|offset| offset + 4)
                {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or_default();
                    if request.len() >= header_end.saturating_add(content_length) {
                        break;
                    }
                }
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("response write");
            String::from_utf8(request).expect("UTF-8 request")
        });
        (format!("http://{address}"), handle)
    }

    #[test]
    fn rejects_unsafe_origins() {
        for value in [
            "http://example.com",
            "http://localhost:37281",
            "http://user@example.com",
            "https://example.com/v1",
            "https://example.com?token=secret",
            "file:///tmp/mealy.sock",
        ] {
            assert!(matches!(
                MealyClient::new(value, "token"),
                Err(ClientError::InvalidBaseUrl(_))
            ));
        }
        assert!(MealyClient::new("http://127.0.0.1:37281", "token").is_ok());
        assert!(MealyClient::new("http://[::1]:37281", "token").is_ok());
        assert!(MealyClient::new("https://example.com", "token").is_ok());
        assert!(matches!(
            MealyClient::new("https://example.com", "x".repeat(16 * 1_024 + 1)),
            Err(ClientError::InvalidBearerToken)
        ));
    }

    #[test]
    fn debug_output_redacts_bearer_token() {
        let builder =
            MealyClient::builder("http://127.0.0.1:37281", "unmistakable-secret").unwrap();
        let debug = format!("{builder:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("unmistakable-secret"));

        let client = builder.build().unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("unmistakable-secret"));
    }

    #[test]
    fn creates_client_from_versioned_private_descriptor() {
        let connection = LocalConnectionInfo {
            api_version: API_VERSION.to_owned(),
            base_url: "http://127.0.0.1:37281".to_owned(),
            bearer_token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            principal_id: "principal".to_owned(),
            channel_binding_id: "binding".to_owned(),
        };
        assert!(MealyClient::from_connection(&connection).is_ok());
        assert!(matches!(
            MealyClient::from_connection(&LocalConnectionInfo {
                api_version: "v999".to_owned(),
                ..connection.clone()
            }),
            Err(ClientError::RequestVersionMismatch { actual, .. }) if actual == "v999"
        ));
        assert!(matches!(
            MealyClient::from_connection(&LocalConnectionInfo {
                base_url: "https://example.com".to_owned(),
                ..connection.clone()
            }),
            Err(ClientError::InvalidBaseUrl(_))
        ));
        assert!(matches!(
            MealyClient::from_connection(&LocalConnectionInfo {
                bearer_token: "not-32-random-bytes".to_owned(),
                ..connection
            }),
            Err(ClientError::InvalidBearerToken)
        ));
    }

    #[test]
    fn sends_authorization_and_decodes_versioned_response() {
        let (base_url, server) = serve_once(
            "200 OK",
            format!(r#"{{"apiVersion":"{API_VERSION}","live":true}}"#),
        );
        let client = MealyClient::new(base_url, "owner-token").unwrap();
        let response = client.liveness().unwrap();
        assert!(response.live);
        let request = server.join().unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get /health/live http/1.1\r\n"));
        assert!(request.contains("\r\nauthorization: bearer owner-token\r\n"));
        assert!(request.contains("\r\naccept: application/json\r\n"));
    }

    #[test]
    fn rejects_request_version_before_network_dispatch() {
        let request = CreateSessionRequest {
            api_version: "v999".to_owned(),
            provider_selection: None,
        };
        let client = MealyClient::new("http://127.0.0.1:9", "owner-token").unwrap();
        assert!(matches!(
            client.create_session(&request),
            Err(ClientError::RequestVersionMismatch {
                actual,
                expected: API_VERSION
            }) if actual == "v999"
        ));
    }

    #[test]
    fn rejects_oversized_request_before_network_dispatch() {
        let request = UpdateSessionTitleRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: 1,
            title: "x".repeat(8 * 1_024 * 1_024),
        };
        let client = MealyClient::new("http://127.0.0.1:9", "owner-token").unwrap();
        assert!(matches!(
            client.update_session_title("session-1", &request),
            Err(ClientError::RequestTooLarge { limit: 8_388_608 })
        ));
    }

    #[test]
    fn sends_typed_command_body_and_decodes_receipt() {
        let (base_url, server) = serve_once(
            "200 OK",
            format!(r#"{{"apiVersion":"{API_VERSION}","sessionId":"session-1"}}"#),
        );
        let client = MealyClient::new(base_url, "owner-token").unwrap();
        let response = client
            .create_session(&CreateSessionRequest {
                api_version: API_VERSION.to_owned(),
                provider_selection: Some(ProviderSelectionCommand::Automatic),
            })
            .unwrap();
        assert_eq!(response.session_id, "session-1");
        let request = server.join().unwrap();
        let lower = request.to_ascii_lowercase();
        assert!(lower.starts_with("post /v1/sessions http/1.1\r\n"));
        assert!(lower.contains("\r\ncontent-type: application/json\r\n"));
        let (_, body) = request.split_once("\r\n\r\n").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({
                "apiVersion": API_VERSION,
                "providerSelection": {"mode": "automatic"}
            })
        );
    }

    #[test]
    fn admits_typed_session_input_and_returns_durable_receipt() {
        let (base_url, server) = serve_once(
            "200 OK",
            format!(
                r#"{{"apiVersion":"{API_VERSION}","sessionId":"session-1","inboxEntryId":"inbox-1","inboxSequence":1,"deliveryMode":"queue","providerSelection":{{"mode":"automatic"}},"providerSelectionSource":"inherited","eventId":"event-1","outboxId":"outbox-1","acceptedAtMs":1,"duplicate":false,"cursor":7}}"#
            ),
        );
        let client = MealyClient::new(base_url, "owner-token").unwrap();
        let response = client
            .submit_input(
                "session-1",
                &SubmitInputRequest {
                    api_version: API_VERSION.to_owned(),
                    idempotency_key: "delivery-1".to_owned(),
                    delivery_mode: DeliveryMode::Queue,
                    content: "hello".to_owned(),
                    provider_selection: None,
                },
            )
            .unwrap();
        assert_eq!(response.inbox_sequence, 1);
        assert_eq!(response.cursor.0, 7);
        let request = server.join().unwrap();
        assert!(
            request
                .to_ascii_lowercase()
                .starts_with("post /v1/sessions/session-1/inputs http/1.1\r\n")
        );
        let (_, body) = request.split_once("\r\n\r\n").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({
                "apiVersion": API_VERSION,
                "idempotencyKey": "delivery-1",
                "deliveryMode": "queue",
                "content": "hello"
            })
        );
    }

    #[test]
    fn creates_and_inspects_typed_automation_history() {
        let (base_url, server) = serve_once(
            "200 OK",
            format!(
                r#"{{"apiVersion":"{API_VERSION}","automationId":"automation-1","name":"reminder","trigger":{{"kind":"one_shot","dueAtMs":20}},"action":{{"kind":"notify","targetSessionId":"session-1","message":"hello"}},"status":"active","revision":0,"createdAtMs":10,"updatedAtMs":10}}"#
            ),
        );
        let client = MealyClient::new(base_url, "owner-token").unwrap();
        let response = client
            .create_automation(&CreateAutomationRequest {
                api_version: API_VERSION.to_owned(),
                automation_id: "automation-1".to_owned(),
                name: "reminder".to_owned(),
                trigger: AutomationTriggerRequest::OneShot { due_at_ms: 20 },
                action: AutomationActionCommand::Notify {
                    target_session_id: "session-1".to_owned(),
                    message: "hello".to_owned(),
                },
            })
            .unwrap();
        assert_eq!(response.automation_id, "automation-1");
        let request = server.join().unwrap();
        assert!(
            request
                .to_ascii_lowercase()
                .starts_with("post /v1/automations http/1.1\r\n")
        );

        let (base_url, server) = serve_once(
            "200 OK",
            format!(r#"{{"apiVersion":"{API_VERSION}","automationId":"automation-1","runs":[]}}"#),
        );
        let client = MealyClient::new(base_url, "owner-token").unwrap();
        assert!(
            client
                .automation_runs("automation-1", 20)
                .unwrap()
                .runs
                .is_empty()
        );
        assert!(
            server
                .join()
                .unwrap()
                .to_ascii_lowercase()
                .starts_with("get /v1/automations/automation-1/runs?limit=20 http/1.1\r\n")
        );
    }

    #[test]
    fn rejects_ambiguous_path_identifier_before_dispatch() {
        let client = MealyClient::new("http://127.0.0.1:9", "owner-token").unwrap();
        assert!(matches!(
            client.session_status("session/other"),
            Err(ClientError::InvalidPathIdentifier)
        ));
    }

    #[test]
    fn rejects_incompatible_response_version() {
        let (base_url, server) =
            serve_once("200 OK", r#"{"apiVersion":"v999","live":true}"#.to_owned());
        let client = MealyClient::new(base_url, "owner-token").unwrap();
        assert!(matches!(
            client.liveness(),
            Err(ClientError::ResponseVersionMismatch {
                actual,
                expected: API_VERSION
            }) if actual == "v999"
        ));
        server.join().unwrap();

        let (base_url, server) = serve_once(
            "200 OK",
            r#"{"apiVersion":"v1\u001b[2J","live":true}"#.to_owned(),
        );
        let client = MealyClient::new(base_url, "owner-token").unwrap();
        assert!(matches!(
            client.liveness(),
            Err(ClientError::MalformedResponse)
        ));
        server.join().unwrap();
    }

    #[test]
    fn preserves_structured_api_errors() {
        let (base_url, server) = serve_once(
            "409 Conflict",
            format!(
                r#"{{"apiVersion":"{API_VERSION}","code":"revision_conflict","message":"revision changed","retryable":false}}"#
            ),
        );
        let client = MealyClient::new(base_url, "owner-token").unwrap();
        assert!(matches!(
            client.liveness(),
            Err(ClientError::Api { status: 409, error })
                if error.code == "revision_conflict" && !error.retryable
        ));
        server.join().unwrap();
    }

    #[test]
    fn rejects_terminal_unsafe_api_errors() {
        let (base_url, server) = serve_once(
            "400 Bad Request",
            format!(
                r#"{{"apiVersion":"{API_VERSION}","code":"INVALID CODE","message":"unsafe\u001b[2J","retryable":false}}"#
            ),
        );
        let client = MealyClient::new(base_url, "owner-token").unwrap();
        assert!(matches!(
            client.liveness(),
            Err(ClientError::UnexpectedResponse { status: 400 })
        ));
        server.join().unwrap();
    }

    #[test]
    fn bounds_response_bodies_even_when_content_length_is_present() {
        let (base_url, server) = serve_once(
            "200 OK",
            format!(
                r#"{{"apiVersion":"{API_VERSION}","state":"{}","ready":true}}"#,
                "x".repeat(1_024)
            ),
        );
        let client = MealyClient::builder(base_url, "owner-token")
            .unwrap()
            .maximum_response_bytes(128)
            .build()
            .unwrap();
        assert!(matches!(
            client.readiness(),
            Err(ClientError::ResponseTooLarge { limit: 128 })
        ));
        server.join().unwrap();
    }

    #[test]
    fn validates_nested_one_time_channel_response_version() {
        let good = serde_json::json!({
            "channel": {"apiVersion": API_VERSION},
            "signingSecret": "secret"
        });
        validate_response_value(&good, ResponseVersion::NestedChannel).unwrap();
        let bad = serde_json::json!({
            "channel": {"apiVersion": "v999"},
            "signingSecret": "secret"
        });
        assert!(matches!(
            validate_response_value(&bad, ResponseVersion::NestedChannel),
            Err(ClientError::ResponseVersionMismatch { actual, .. }) if actual == "v999"
        ));
    }
}
