use crate::mcp_oauth::pinned_client;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_application::{McpOAuthMetadataDiscovery, McpOAuthTokenGrant, valid_provider_secret_id};
use reqwest::{
    StatusCode,
    blocking::{Body, Response},
    header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, PRAGMA},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const MCP_OAUTH_TOKEN_TIMEOUT: Duration = Duration::from_secs(15);
const MCP_OAUTH_MAXIMUM_TOKEN_RESPONSE_BYTES: u64 = 256 * 1024;
const MCP_OAUTH_MAXIMUM_TOKEN_BYTES: usize = 16 * 1024;
const MCP_OAUTH_MAXIMUM_CODE_BYTES: usize = 8 * 1024;
const MCP_OAUTH_MAXIMUM_RECORD_BYTES: u64 = 64 * 1024;
const MCP_OAUTH_MAXIMUM_EXPIRES_IN_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;
const MCP_OAUTH_RECORD_FORMAT_VERSION: u64 = 1;

/// One in-memory, single-use OAuth authorization-code transaction.
///
/// State and PKCE verifier bytes are zeroized on drop and omitted from `Debug`.
pub struct McpOAuthAuthorizationTransaction {
    authorization_url: Zeroizing<String>,
    redirect_uri: String,
    client_id: String,
    token_set_id: String,
    resource: String,
    authorization_server: String,
    token_endpoint: String,
    requested_scopes: Vec<String>,
    metadata_digest: String,
    expected_state: Zeroizing<String>,
    code_verifier: Zeroizing<String>,
}

impl std::fmt::Debug for McpOAuthAuthorizationTransaction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpOAuthAuthorizationTransaction")
            .field("token_set_id", &self.token_set_id)
            .field("resource", &self.resource)
            .field("authorization_server", &self.authorization_server)
            .field("requested_scopes", &self.requested_scopes)
            .field("secret_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl McpOAuthAuthorizationTransaction {
    /// Owner-visible URL to open in a browser for this single transaction.
    #[must_use]
    pub fn authorization_url(&self) -> &str {
        self.authorization_url.as_str()
    }

    /// Exact loopback callback URI registered in the authorization request.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Exact scopes selected according to the stable MCP least-authority fallback.
    #[must_use]
    pub fn requested_scopes(&self) -> &[String] {
        &self.requested_scopes
    }

    /// Verifies a returned callback state without exposing the expected value.
    ///
    /// # Errors
    ///
    /// Returns [`McpOAuthTokenError::StateMismatch`] when the callback is not bound to this
    /// transaction.
    pub fn verify_returned_state(&self, returned_state: &str) -> Result<(), McpOAuthTokenError> {
        if constant_time_equal(self.expected_state.as_bytes(), returned_state.as_bytes()) {
            Ok(())
        } else {
            Err(McpOAuthTokenError::StateMismatch)
        }
    }
}

/// Prepares a single-use public-client authorization request using PKCE S256.
///
/// Scope selection follows stable MCP precedence: the exact challenge scopes when present,
/// otherwise the complete protected-resource `scopes_supported` set. The request always includes
/// the exact MCP `resource` audience.
///
/// # Errors
///
/// Returns [`McpOAuthTokenError`] for invalid metadata, client/redirect identity, unsupported
/// public-client authentication, reserved endpoint query parameters, or unavailable OS entropy.
pub fn prepare_mcp_oauth_authorization(
    discovery: &McpOAuthMetadataDiscovery,
    token_set_id: &str,
    client_id: &str,
    redirect_uri: &str,
) -> Result<McpOAuthAuthorizationTransaction, McpOAuthTokenError> {
    discovery
        .validate()
        .map_err(|_| McpOAuthTokenError::Invalid)?;
    if !valid_provider_secret_id(token_set_id)
        || !valid_client_id(client_id)
        || discovery
            .token_endpoint_auth_methods_supported()
            .binary_search_by(|value| value.as_str().cmp("none"))
            .is_err()
    {
        return Err(McpOAuthTokenError::Invalid);
    }
    validate_loopback_redirect_uri(redirect_uri)?;
    let requested_scopes = if discovery.challenge_scopes().is_empty() {
        discovery.scopes_supported().to_vec()
    } else {
        discovery.challenge_scopes().to_vec()
    };
    let metadata_digest = discovery
        .metadata_digest()
        .map_err(|_| McpOAuthTokenError::Invalid)?;
    McpOAuthTokenGrant::new(
        token_set_id.to_owned(),
        discovery.resource().to_owned(),
        discovery.selected_authorization_server().to_owned(),
        discovery.token_endpoint().to_owned(),
        client_id.to_owned(),
        requested_scopes.clone(),
        metadata_digest.clone(),
    )
    .map_err(|_| McpOAuthTokenError::Invalid)?;

    let expected_state = random_base64url::<32>()?;
    let code_verifier = random_base64url::<64>()?;
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let mut authorization_url =
        Url::parse(discovery.authorization_endpoint()).map_err(|_| McpOAuthTokenError::Invalid)?;
    let reserved = [
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
        "resource",
    ];
    if authorization_url
        .query_pairs()
        .any(|(name, _)| reserved.contains(&name.as_ref()))
    {
        return Err(McpOAuthTokenError::Invalid);
    }
    {
        let mut query = authorization_url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", expected_state.as_str())
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", discovery.resource());
        if !requested_scopes.is_empty() {
            query.append_pair("scope", &requested_scopes.join(" "));
        }
    }
    Ok(McpOAuthAuthorizationTransaction {
        authorization_url: Zeroizing::new(authorization_url.to_string()),
        redirect_uri: redirect_uri.to_owned(),
        client_id: client_id.to_owned(),
        token_set_id: token_set_id.to_owned(),
        resource: discovery.resource().to_owned(),
        authorization_server: discovery.selected_authorization_server().to_owned(),
        token_endpoint: discovery.token_endpoint().to_owned(),
        requested_scopes,
        metadata_digest,
        expected_state,
        code_verifier,
    })
}

/// Exchanges one callback code exactly once and returns an unstored token family.
///
/// The callback state is compared without early exit, and the token request repeats the exact
/// redirect URI, PKCE verifier, client identity, and MCP `resource` audience. Only bearer tokens
/// with equal-or-narrower scopes are accepted.
///
/// # Errors
///
/// Returns [`McpOAuthTokenError`] for state mismatch, malformed callback material, unsafe token
/// transport, rejection, malformed/broadened response, timeout, or unavailable I/O.
pub fn exchange_mcp_oauth_authorization_code(
    transaction: McpOAuthAuthorizationTransaction,
    returned_state: Zeroizing<String>,
    authorization_code: Zeroizing<String>,
    now: SystemTime,
) -> Result<McpOAuthTokenSet, McpOAuthTokenError> {
    transaction.verify_returned_state(&returned_state)?;
    drop(returned_state);
    validate_oauth_secret(&authorization_code, MCP_OAUTH_MAXIMUM_CODE_BYTES)?;
    let token_endpoint =
        Url::parse(&transaction.token_endpoint).map_err(|_| McpOAuthTokenError::Invalid)?;
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "authorization_code")
        .append_pair("client_id", transaction.client_id.as_str())
        .append_pair("code", authorization_code.as_str())
        .append_pair("code_verifier", transaction.code_verifier.as_str())
        .append_pair("redirect_uri", transaction.redirect_uri.as_str())
        .append_pair("resource", transaction.resource.as_str());
    let form = Zeroizing::new(form.finish());
    drop(authorization_code);
    let form_bytes = Zeroizing::new(form.as_bytes().to_vec());
    drop(form);
    let form_length =
        u64::try_from(form_bytes.len()).map_err(|_| McpOAuthTokenError::OutputLimitExceeded)?;
    let response = pinned_client(&token_endpoint)?
        .post(token_endpoint)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::sized(std::io::Cursor::new(form_bytes), form_length))
        .timeout(MCP_OAUTH_TOKEN_TIMEOUT)
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                McpOAuthTokenError::TimedOut
            } else {
                McpOAuthTokenError::Transport
            }
        })?;
    let token_response = parse_token_response(response, &transaction.requested_scopes, now)?;
    let grant = McpOAuthTokenGrant::new(
        transaction.token_set_id,
        transaction.resource,
        transaction.authorization_server,
        transaction.token_endpoint,
        transaction.client_id,
        token_response.granted_scopes,
        transaction.metadata_digest,
    )
    .map_err(|_| McpOAuthTokenError::Invalid)?;
    McpOAuthTokenSet::new(
        grant,
        1,
        token_response.expires_at_ms,
        token_response.access_token,
        token_response.refresh_token,
    )
}

struct ParsedTokenResponse {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    expires_at_ms: Option<i64>,
    granted_scopes: Vec<String>,
}

#[derive(Deserialize)]
struct RawTokenResponse {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

fn parse_token_response(
    response: Response,
    requested_scopes: &[String],
    now: SystemTime,
) -> Result<ParsedTokenResponse, McpOAuthTokenError> {
    if response.status() != StatusCode::OK {
        return Err(McpOAuthTokenError::TokenRejected(
            response.status().as_u16(),
        ));
    }
    if !response
        .headers()
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
    {
        return Err(McpOAuthTokenError::Invalid);
    }
    if !response
        .headers()
        .get_all(PRAGMA)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-cache"))
    {
        return Err(McpOAuthTokenError::Invalid);
    }
    let media_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if media_type != Some("application/json") {
        return Err(McpOAuthTokenError::Invalid);
    }
    let body = read_bounded_token_body(response)?;
    let raw = serde_json::from_slice::<RawTokenResponse>(&body)
        .map_err(|_| McpOAuthTokenError::Invalid)?;
    let access_token = Zeroizing::new(raw.access_token);
    validate_oauth_secret(&access_token, MCP_OAUTH_MAXIMUM_TOKEN_BYTES)?;
    if !raw.token_type.eq_ignore_ascii_case("Bearer") {
        return Err(McpOAuthTokenError::Invalid);
    }
    let refresh_token = raw.refresh_token.map(Zeroizing::new);
    if let Some(refresh_token) = &refresh_token {
        validate_oauth_secret(refresh_token, MCP_OAUTH_MAXIMUM_TOKEN_BYTES)?;
    }
    let expires_at_ms = raw
        .expires_in
        .map(|seconds| {
            (seconds > 0 && seconds <= MCP_OAUTH_MAXIMUM_EXPIRES_IN_SECONDS)
                .then_some(seconds)
                .ok_or(McpOAuthTokenError::Invalid)
                .and_then(|seconds| expiration_timestamp(now, seconds))
        })
        .transpose()?;
    let granted_scopes = raw
        .scope
        .as_deref()
        .map(parse_scope_string)
        .transpose()?
        .unwrap_or_else(|| requested_scopes.to_vec());
    if !is_scope_subset(&granted_scopes, requested_scopes) {
        return Err(McpOAuthTokenError::ScopeBroadened);
    }
    Ok(ParsedTokenResponse {
        access_token,
        refresh_token,
        expires_at_ms,
        granted_scopes,
    })
}

fn read_bounded_token_body(mut response: Response) -> Result<Vec<u8>, McpOAuthTokenError> {
    let mut body = Vec::new();
    response
        .by_ref()
        .take(MCP_OAUTH_MAXIMUM_TOKEN_RESPONSE_BYTES.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| McpOAuthTokenError::Transport)?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > MCP_OAUTH_MAXIMUM_TOKEN_RESPONSE_BYTES {
        return Err(McpOAuthTokenError::OutputLimitExceeded);
    }
    Ok(body)
}

fn parse_scope_string(value: &str) -> Result<Vec<String>, McpOAuthTokenError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut scopes = value.split(' ').map(str::to_owned).collect::<Vec<String>>();
    if scopes.iter().any(|scope| {
        scope.is_empty()
            || scope.len() > 256
            || scope.bytes().any(|byte| {
                byte != 0x21 && !(0x23..=0x5b).contains(&byte) && !(0x5d..=0x7e).contains(&byte)
            })
    }) {
        return Err(McpOAuthTokenError::Invalid);
    }
    scopes.sort();
    if scopes.windows(2).any(|window| window[0] == window[1]) {
        return Err(McpOAuthTokenError::Invalid);
    }
    Ok(scopes)
}

fn is_scope_subset(granted: &[String], requested: &[String]) -> bool {
    let requested = requested
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    granted
        .iter()
        .all(|scope| requested.contains(scope.as_str()))
}

fn expiration_timestamp(now: SystemTime, seconds: u64) -> Result<i64, McpOAuthTokenError> {
    let now_ms = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| McpOAuthTokenError::Invalid)?
        .as_millis();
    let expires_ms = now_ms
        .checked_add(u128::from(seconds).saturating_mul(1_000))
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(McpOAuthTokenError::Invalid)?;
    Ok(expires_ms)
}

fn valid_client_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_loopback_redirect_uri(value: &str) -> Result<(), McpOAuthTokenError> {
    let url = Url::parse(value).map_err(|_| McpOAuthTokenError::Invalid)?;
    if url.as_str() != value
        || url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none()
        || url.path() != "/callback"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(McpOAuthTokenError::Invalid);
    }
    Ok(())
}

fn random_base64url<const N: usize>() -> Result<Zeroizing<String>, McpOAuthTokenError> {
    let mut bytes = Zeroizing::new([0_u8; N]);
    getrandom::fill(bytes.as_mut()).map_err(|_| McpOAuthTokenError::RandomUnavailable)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

fn validate_oauth_secret(value: &str, maximum: usize) -> Result<(), McpOAuthTokenError> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'"' | b'\\'))
    {
        Err(McpOAuthTokenError::Invalid)
    } else {
        Ok(())
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let maximum = left.len().max(right.len());
    for index in 0..maximum {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

/// One validated OAuth access/refresh token family held only in secret-aware host memory.
pub struct McpOAuthTokenSet {
    grant: McpOAuthTokenGrant,
    generation: u64,
    expires_at_ms: Option<i64>,
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for McpOAuthTokenSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpOAuthTokenSet")
            .field("grant", &self.grant)
            .field("generation", &self.generation)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("secret_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl McpOAuthTokenSet {
    fn new(
        grant: McpOAuthTokenGrant,
        generation: u64,
        expires_at_ms: Option<i64>,
        access_token: Zeroizing<String>,
        refresh_token: Option<Zeroizing<String>>,
    ) -> Result<Self, McpOAuthTokenError> {
        grant.validate().map_err(|_| McpOAuthTokenError::Invalid)?;
        validate_oauth_secret(&access_token, MCP_OAUTH_MAXIMUM_TOKEN_BYTES)?;
        if let Some(refresh_token) = &refresh_token {
            validate_oauth_secret(refresh_token, MCP_OAUTH_MAXIMUM_TOKEN_BYTES)?;
        }
        if generation == 0 || expires_at_ms.is_some_and(|value| value <= 0) {
            return Err(McpOAuthTokenError::Invalid);
        }
        Ok(Self {
            grant,
            generation,
            expires_at_ms,
            access_token,
            refresh_token,
        })
    }

    /// Non-secret immutable OAuth authority.
    #[must_use]
    pub const fn grant(&self) -> &McpOAuthTokenGrant {
        &self.grant
    }

    /// Monotonic broker generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Absolute Unix expiration in milliseconds, when advertised.
    #[must_use]
    pub const fn expires_at_ms(&self) -> Option<i64> {
        self.expires_at_ms
    }

    /// Process-private bearer access token.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Process-private refresh token, when issued.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_ref().map(|value| value.as_str())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredMcpOAuthTokenSet {
    format_version: u64,
    grant: McpOAuthTokenGrant,
    generation: u64,
    expires_at_ms: Option<i64>,
    access_token: String,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredMcpOAuthTokenSetRef<'a> {
    format_version: u64,
    grant: &'a McpOAuthTokenGrant,
    generation: u64,
    expires_at_ms: Option<i64>,
    access_token: &'a str,
    refresh_token: Option<&'a str>,
}

impl StoredMcpOAuthTokenSet {
    fn as_serializable(token_set: &McpOAuthTokenSet) -> StoredMcpOAuthTokenSetRef<'_> {
        StoredMcpOAuthTokenSetRef {
            format_version: MCP_OAUTH_RECORD_FORMAT_VERSION,
            grant: &token_set.grant,
            generation: token_set.generation,
            expires_at_ms: token_set.expires_at_ms,
            access_token: token_set.access_token.as_str(),
            refresh_token: token_set.refresh_token.as_ref().map(|value| value.as_str()),
        }
    }

    fn into_runtime(self) -> Result<McpOAuthTokenSet, McpOAuthTokenError> {
        if self.format_version != MCP_OAUTH_RECORD_FORMAT_VERSION {
            return Err(McpOAuthTokenError::Invalid);
        }
        McpOAuthTokenSet::new(
            self.grant,
            self.generation,
            self.expires_at_ms,
            Zeroizing::new(self.access_token),
            self.refresh_token.map(Zeroizing::new),
        )
    }
}

/// Owner-private filesystem broker for rotating MCP OAuth token families.
pub struct FileMcpOAuthTokenStore {
    root: PathBuf,
}

impl FileMcpOAuthTokenStore {
    /// Creates or opens one no-symlink owner-private token directory.
    ///
    /// # Errors
    ///
    /// Returns [`McpOAuthTokenError`] when the directory cannot be created or is unsafe.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, McpOAuthTokenError> {
        let root = root.into();
        match fs::create_dir(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(error)),
        }
        let metadata = fs::symlink_metadata(&root).map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(McpOAuthTokenError::UnsafeStorage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        }
        Ok(Self { root })
    }

    /// Creates a new immutable generation-one token family.
    ///
    /// Repeating the exact record is idempotent; different material under the same identity fails
    /// closed. Rotation uses the separately fenced replace operation.
    ///
    /// # Errors
    ///
    /// Returns [`McpOAuthTokenError`] for malformed records, conflict, unsafe storage, or I/O.
    pub fn create(&self, token_set: &McpOAuthTokenSet) -> Result<(), McpOAuthTokenError> {
        if token_set.generation != 1 {
            return Err(McpOAuthTokenError::Invalid);
        }
        let stored = StoredMcpOAuthTokenSet::as_serializable(token_set);
        let bytes =
            Zeroizing::new(serde_json::to_vec(&stored).map_err(|_| McpOAuthTokenError::Invalid)?);
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MCP_OAUTH_MAXIMUM_RECORD_BYTES {
            return Err(McpOAuthTokenError::OutputLimitExceeded);
        }
        let path = self.path(token_set.grant.token_set_id())?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                let result = file
                    .write_all(&bytes)
                    .and_then(|()| file.flush())
                    .and_then(|()| file.sync_all());
                if let Err(error) = result {
                    let _ = fs::remove_file(path);
                    return Err(io_error(error));
                }
                sync_directory(&self.root).map_err(io_error)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = self.read(token_set.grant.token_set_id())?;
                if same_token_set(&existing, token_set) {
                    Ok(())
                } else {
                    Err(McpOAuthTokenError::Conflict)
                }
            }
            Err(error) => Err(io_error(error)),
        }
    }

    /// Loads and validates one bounded token family into zeroizing memory.
    ///
    /// # Errors
    ///
    /// Returns [`McpOAuthTokenError`] when absent, unsafe, malformed, oversized, or unreadable.
    pub fn read(&self, token_set_id: &str) -> Result<McpOAuthTokenSet, McpOAuthTokenError> {
        let path = self.path(token_set_id)?;
        let file = open_token_record(&path)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file() {
            return Err(McpOAuthTokenError::UnsafeStorage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(McpOAuthTokenError::UnsafeStorage);
            }
        }
        if metadata.len() == 0 || metadata.len() > MCP_OAUTH_MAXIMUM_RECORD_BYTES {
            return Err(McpOAuthTokenError::Invalid);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            usize::try_from(metadata.len()).map_err(|_| McpOAuthTokenError::Invalid)?,
        ));
        file.take(MCP_OAUTH_MAXIMUM_RECORD_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MCP_OAUTH_MAXIMUM_RECORD_BYTES {
            return Err(McpOAuthTokenError::OutputLimitExceeded);
        }
        let stored = serde_json::from_slice::<StoredMcpOAuthTokenSet>(&bytes)
            .map_err(|_| McpOAuthTokenError::Invalid)?;
        let token_set = stored.into_runtime()?;
        if token_set.grant.token_set_id() != token_set_id {
            return Err(McpOAuthTokenError::Invalid);
        }
        Ok(token_set)
    }

    fn path(&self, token_set_id: &str) -> Result<PathBuf, McpOAuthTokenError> {
        valid_provider_secret_id(token_set_id)
            .then(|| self.root.join(format!("{token_set_id}.json")))
            .ok_or(McpOAuthTokenError::Invalid)
    }
}

#[cfg(target_os = "linux")]
fn open_token_record(path: &Path) -> Result<File, McpOAuthTokenError> {
    use rustix::fs::{Mode, OFlags, open};

    match open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => Ok(File::from(file)),
        Err(error) if error == rustix::io::Errno::NOENT => Err(McpOAuthTokenError::NotFound),
        Err(error) if error == rustix::io::Errno::LOOP => Err(McpOAuthTokenError::UnsafeStorage),
        Err(_) => Err(McpOAuthTokenError::StorageUnavailable),
    }
}

#[cfg(not(target_os = "linux"))]
fn open_token_record(path: &Path) -> Result<File, McpOAuthTokenError> {
    match File::open(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(McpOAuthTokenError::NotFound)
        }
        Err(error) => Err(io_error(error)),
    }
}

fn same_token_set(left: &McpOAuthTokenSet, right: &McpOAuthTokenSet) -> bool {
    left.grant == right.grant
        && left.generation == right.generation
        && left.expires_at_ms == right.expires_at_ms
        && constant_time_equal(left.access_token.as_bytes(), right.access_token.as_bytes())
        && match (&left.refresh_token, &right.refresh_token) {
            (Some(left), Some(right)) => constant_time_equal(left.as_bytes(), right.as_bytes()),
            (None, None) => true,
            _ => false,
        }
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn io_error(_error: std::io::Error) -> McpOAuthTokenError {
    McpOAuthTokenError::StorageUnavailable
}

/// Failure at the owner-controlled MCP OAuth authorization/token boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum McpOAuthTokenError {
    /// Metadata, identity, callback, token, scope, or record evidence is invalid.
    #[error("MCP OAuth evidence is invalid")]
    Invalid,
    /// Callback state did not match the single-use authorization transaction.
    #[error("MCP OAuth callback state did not match")]
    StateMismatch,
    /// Token endpoint rejected the code or request.
    #[error("MCP OAuth token endpoint rejected the request with status {0}")]
    TokenRejected(u16),
    /// Token response attempted to broaden the owner-requested scope set.
    #[error("MCP OAuth token response broadened scopes")]
    ScopeBroadened,
    /// OS entropy was unavailable for state or PKCE generation.
    #[error("MCP OAuth secure randomness is unavailable")]
    RandomUnavailable,
    /// Authorization or token exchange exceeded its hard deadline.
    #[error("MCP OAuth request timed out")]
    TimedOut,
    /// Metadata or token endpoint transport failed without exposing response content.
    #[error("MCP OAuth transport failed")]
    Transport,
    /// A bounded response or broker record exceeded its hard limit.
    #[error("MCP OAuth output exceeded its bound")]
    OutputLimitExceeded,
    /// Token identity already contains different material.
    #[error("MCP OAuth token identity conflicts with existing broker state")]
    Conflict,
    /// Token family was not found.
    #[error("MCP OAuth token family was not found")]
    NotFound,
    /// Token directory, symlink, file type, or permissions are unsafe.
    #[error("MCP OAuth token storage is unsafe")]
    UnsafeStorage,
    /// Owner-private token storage is unavailable.
    #[error("MCP OAuth token storage is unavailable")]
    StorageUnavailable,
    /// Shared MCP host rejected an unsafe network destination or metadata boundary.
    #[error(transparent)]
    McpHost(#[from] crate::mcp::McpHostError),
}

#[cfg(test)]
mod tests {
    use super::{
        FileMcpOAuthTokenStore, McpOAuthTokenError, exchange_mcp_oauth_authorization_code,
        prepare_mcp_oauth_authorization,
    };
    use mealy_application::McpOAuthMetadataDiscovery;
    use serde_json::json;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        thread,
        time::{Duration, UNIX_EPOCH},
    };
    use zeroize::Zeroizing;

    #[test]
    fn authorization_request_uses_exact_state_pkce_resource_and_scope() {
        let discovery = discovery("http://127.0.0.1:9999");
        let transaction = prepare_mcp_oauth_authorization(
            &discovery,
            "remote.oauth",
            "mealy-native",
            "http://127.0.0.1:33445/callback",
        )
        .expect("authorization transaction");
        let url = url::Url::parse(transaction.authorization_url()).expect("authorization URL");
        let query = url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(query.get("response_type").map(AsRef::as_ref), Some("code"));
        assert_eq!(
            query.get("code_challenge_method").map(AsRef::as_ref),
            Some("S256")
        );
        assert_eq!(
            query.get("resource").map(AsRef::as_ref),
            Some("http://127.0.0.1:9999/mcp")
        );
        assert_eq!(query.get("scope").map(AsRef::as_ref), Some("read"));
        assert_eq!(
            query.get("code_challenge").map(|value| value.len()),
            Some(43)
        );
        assert!(!format!("{transaction:?}").contains(query.get("state").expect("state").as_ref()));
    }

    #[test]
    fn token_exchange_requires_exact_state_bounds_scope_and_persists_privately() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("token listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let discovery = discovery(&origin);
        let transaction = prepare_mcp_oauth_authorization(
            &discovery,
            "remote.oauth",
            "mealy-native",
            "http://127.0.0.1:33445/callback",
        )
        .expect("authorization transaction");
        let state = url::Url::parse(transaction.authorization_url())
            .expect("authorization URL")
            .query_pairs()
            .find(|(name, _)| name == "state")
            .map(|(_, value)| value.into_owned())
            .expect("state");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("token connection");
            let body = consume_request(&mut stream);
            assert!(body.contains("grant_type=authorization_code"));
            assert!(body.contains("resource=http%3A%2F%2F127.0.0.1"));
            assert!(body.contains("code_verifier="));
            respond(
                &mut stream,
                "200 OK",
                &[
                    ("Content-Type", "application/json"),
                    ("Cache-Control", "no-store"),
                    ("Pragma", "no-cache"),
                ],
                &json!({
                    "access_token": "access-secret",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "refresh-secret",
                    "scope": "read"
                })
                .to_string(),
            );
        });
        let token_set = exchange_mcp_oauth_authorization_code(
            transaction,
            Zeroizing::new(state),
            Zeroizing::new("single-use-code".to_owned()),
            UNIX_EPOCH + Duration::from_secs(10),
        )
        .expect("token set");
        assert_eq!(token_set.expires_at_ms(), Some(3_610_000));
        assert_eq!(token_set.grant().scopes(), ["read"]);
        assert!(!format!("{token_set:?}").contains("access-secret"));
        let directory = tempfile::tempdir().expect("token home");
        let store =
            FileMcpOAuthTokenStore::new(directory.path().join("tokens")).expect("token store");
        store.create(&token_set).expect("create token set");
        store.create(&token_set).expect("idempotent create");
        let loaded = store.read("remote.oauth").expect("read token set");
        assert_eq!(loaded.access_token(), "access-secret");
        assert_eq!(loaded.refresh_token(), Some("refresh-secret"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(directory.path().join("tokens/remote.oauth.json"))
                    .expect("token metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        server.join().expect("token server");
    }

    #[test]
    fn token_exchange_rejects_state_mismatch_without_network() {
        let discovery = discovery("http://127.0.0.1:9999");
        let transaction = prepare_mcp_oauth_authorization(
            &discovery,
            "remote.oauth",
            "mealy-native",
            "http://127.0.0.1:33445/callback",
        )
        .expect("transaction");
        assert!(matches!(
            exchange_mcp_oauth_authorization_code(
                transaction,
                Zeroizing::new("wrong-state".to_owned()),
                Zeroizing::new("unused-code".to_owned()),
                UNIX_EPOCH,
            ),
            Err(McpOAuthTokenError::StateMismatch)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn token_store_rejects_symlink_roots_and_records_without_following_them() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().expect("token storage fixture");
        let target = directory.path().join("target");
        std::fs::create_dir(&target).expect("target directory");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("target permissions");
        let linked_root = directory.path().join("linked-tokens");
        symlink(&target, &linked_root).expect("linked token root");
        assert!(matches!(
            FileMcpOAuthTokenStore::new(&linked_root),
            Err(McpOAuthTokenError::UnsafeStorage)
        ));
        assert_eq!(
            std::fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        let store =
            FileMcpOAuthTokenStore::new(directory.path().join("tokens")).expect("safe token store");
        let outside = directory.path().join("outside.json");
        std::fs::write(&outside, b"not a token").expect("outside record");
        symlink(&outside, directory.path().join("tokens/remote.oauth.json"))
            .expect("linked token record");
        assert!(matches!(
            store.read("remote.oauth"),
            Err(McpOAuthTokenError::UnsafeStorage)
        ));
    }

    fn discovery(origin: &str) -> McpOAuthMetadataDiscovery {
        McpOAuthMetadataDiscovery::new(
            format!("{origin}/mcp"),
            format!("{origin}/.well-known/oauth-protected-resource/mcp"),
            format!("{origin}/mcp"),
            vec![origin.to_owned()],
            origin.to_owned(),
            format!("{origin}/.well-known/oauth-authorization-server"),
            format!("{origin}/authorize"),
            format!("{origin}/token"),
            None,
            vec!["read".to_owned()],
            vec!["read".to_owned()],
            vec!["S256".to_owned()],
            vec!["none".to_owned()],
            false,
        )
        .expect("discovery")
    }

    fn consume_request(stream: &mut TcpStream) -> String {
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("request line");
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("header");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(value) = line
                .split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            {
                content_length = value;
            }
        }
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).expect("request body");
        String::from_utf8(body).expect("form body")
    }

    fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, &str)], body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        )
        .expect("status");
        for (name, value) in headers {
            write!(stream, "{name}: {value}\r\n").expect("header");
        }
        write!(stream, "\r\n{body}").expect("body");
        stream.flush().expect("flush");
    }
}
