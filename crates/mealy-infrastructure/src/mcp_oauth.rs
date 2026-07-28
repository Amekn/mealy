use crate::{mcp::McpHostError, web::resolve_pinned_web_destination};
use mealy_application::{
    MCP_OAUTH_MAXIMUM_AUTHORIZATION_SERVERS, MCP_OAUTH_MAXIMUM_METADATA_VALUES,
    MCP_OAUTH_MAXIMUM_SCOPES, McpHttpEndpointConfig, McpOAuthMetadataDiscovery, WebAccessConfig,
};
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, net::IpAddr, time::Duration};
use url::Url;

const MCP_OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MCP_OAUTH_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const MCP_OAUTH_MAXIMUM_BODY_BYTES: u64 = 256 * 1024;
const MCP_OAUTH_MAXIMUM_CHALLENGE_BYTES: usize = 8 * 1024;

/// Discovers and validates the stable-2025-11-25 OAuth boundary for one protected HTTP MCP server.
///
/// This operation is deliberately non-mutating and does not create a registration, launch a
/// browser, generate authorization material, exchange a code, or store a token. When the protected
/// resource advertises multiple authorization servers, `selected_authorization_server` is
/// mandatory so the client never silently chooses an identity provider.
///
/// # Errors
///
/// Returns [`McpHostError`] for an unsafe endpoint, malformed challenge or metadata, redirect,
/// private-network destination, missing PKCE S256 support, or ambiguous issuer selection.
pub fn discover_mcp_oauth_metadata(
    config: &McpHttpEndpointConfig,
    selected_authorization_server: Option<&str>,
) -> Result<McpOAuthMetadataDiscovery, McpHostError> {
    config
        .validate()
        .map_err(|_| McpHostError::InvalidConfiguration)?;
    if config.authentication().credential().is_some() {
        return Err(McpHostError::InvalidConfiguration);
    }
    let endpoint = safe_oauth_url(config.endpoint(), false)?;
    let challenge = request_protected_resource_challenge(&endpoint)?;
    let protected = discover_protected_resource(
        &endpoint,
        challenge.resource_metadata.as_deref(),
        selected_authorization_server,
    )?;
    let authorization = discover_authorization_server(&protected.selected_authorization_server)?;
    let mut challenge_scopes = challenge.scopes;
    validate_scopes(&challenge_scopes)?;
    challenge_scopes.sort();
    ensure_unique(&challenge_scopes)?;

    McpOAuthMetadataDiscovery::new(
        endpoint.to_string(),
        protected.resource_metadata_url.to_string(),
        protected.resource,
        protected.authorization_servers,
        protected.selected_authorization_server,
        authorization.metadata_url.to_string(),
        authorization.authorization_endpoint,
        authorization.token_endpoint,
        authorization.registration_endpoint,
        challenge_scopes,
        protected.scopes_supported,
        authorization.code_challenge_methods_supported,
        authorization.token_endpoint_auth_methods_supported,
        authorization.client_id_metadata_document_supported,
    )
    .map_err(|_| McpHostError::InvalidOAuthMetadata)
}

struct ProtectedResourceEvidence {
    resource_metadata_url: Url,
    resource: String,
    authorization_servers: Vec<String>,
    selected_authorization_server: String,
    scopes_supported: Vec<String>,
}

fn discover_protected_resource(
    endpoint: &Url,
    advertised_metadata: Option<&str>,
    selected_authorization_server: Option<&str>,
) -> Result<ProtectedResourceEvidence, McpHostError> {
    let candidates = resource_metadata_candidates(endpoint, advertised_metadata)?;
    let (resource_metadata_url, metadata) = first_metadata_document(&candidates)?;
    let resource = exact_string(&metadata, "resource", 4_096)?;
    if resource != endpoint.as_str() {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    let mut authorization_servers = string_array(
        &metadata,
        "authorization_servers",
        1,
        MCP_OAUTH_MAXIMUM_AUTHORIZATION_SERVERS,
        4_096,
    )?;
    for issuer in &authorization_servers {
        safe_oauth_issuer(issuer)?;
    }
    authorization_servers.sort();
    ensure_unique(&authorization_servers)?;
    let selected_authorization_server =
        select_authorization_server(&authorization_servers, selected_authorization_server)?;
    let mut scopes_supported =
        optional_string_array(&metadata, "scopes_supported", MCP_OAUTH_MAXIMUM_SCOPES, 256)?;
    validate_scopes(&scopes_supported)?;
    scopes_supported.sort();
    ensure_unique(&scopes_supported)?;
    Ok(ProtectedResourceEvidence {
        resource_metadata_url,
        resource,
        authorization_servers,
        selected_authorization_server,
        scopes_supported,
    })
}

struct AuthorizationServerEvidence {
    metadata_url: Url,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    client_id_metadata_document_supported: bool,
}

fn discover_authorization_server(
    selected_issuer: &str,
) -> Result<AuthorizationServerEvidence, McpHostError> {
    let issuer = safe_oauth_issuer(selected_issuer)?;
    let candidates = authorization_metadata_candidates(&issuer)?;
    let (metadata_url, metadata) = first_metadata_document(&candidates)?;
    if exact_string(&metadata, "issuer", 4_096)? != selected_issuer {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    let authorization_endpoint = exact_string(&metadata, "authorization_endpoint", 4_096)?;
    let token_endpoint = exact_string(&metadata, "token_endpoint", 4_096)?;
    validate_oauth_destination(&safe_oauth_url(&authorization_endpoint, true)?)?;
    validate_oauth_destination(&safe_oauth_url(&token_endpoint, true)?)?;
    let registration_endpoint = optional_string(&metadata, "registration_endpoint", 4_096)?;
    if let Some(endpoint) = &registration_endpoint {
        validate_oauth_destination(&safe_oauth_url(endpoint, true)?)?;
    }
    require_advertised_value(&metadata, "response_types_supported", "code", false)?;
    require_advertised_value(
        &metadata,
        "grant_types_supported",
        "authorization_code",
        true,
    )?;
    let mut code_challenge_methods_supported = string_array(
        &metadata,
        "code_challenge_methods_supported",
        1,
        MCP_OAUTH_MAXIMUM_METADATA_VALUES,
        256,
    )?;
    code_challenge_methods_supported.sort();
    ensure_unique(&code_challenge_methods_supported)?;
    if code_challenge_methods_supported
        .binary_search_by(|value| value.as_str().cmp("S256"))
        .is_err()
    {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    let mut token_endpoint_auth_methods_supported = optional_string_array(
        &metadata,
        "token_endpoint_auth_methods_supported",
        MCP_OAUTH_MAXIMUM_METADATA_VALUES,
        256,
    )?;
    if token_endpoint_auth_methods_supported.is_empty() {
        token_endpoint_auth_methods_supported.push("client_secret_basic".to_owned());
    }
    token_endpoint_auth_methods_supported.sort();
    ensure_unique(&token_endpoint_auth_methods_supported)?;
    let client_id_metadata_document_supported =
        match metadata.get("client_id_metadata_document_supported") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(McpHostError::InvalidOAuthMetadata),
        };
    Ok(AuthorizationServerEvidence {
        metadata_url,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        code_challenge_methods_supported,
        token_endpoint_auth_methods_supported,
        client_id_metadata_document_supported,
    })
}

fn require_advertised_value(
    metadata: &Value,
    field: &str,
    required: &str,
    absent_allowed: bool,
) -> Result<(), McpHostError> {
    let mut values =
        optional_string_array(metadata, field, MCP_OAUTH_MAXIMUM_METADATA_VALUES, 256)?;
    if values.is_empty() && absent_allowed && metadata.get(field).is_none() {
        return Ok(());
    }
    values.sort();
    ensure_unique(&values)?;
    if values
        .binary_search_by(|value| value.as_str().cmp(required))
        .is_err()
    {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    Ok(())
}

#[derive(Debug, Default)]
struct BearerChallenge {
    resource_metadata: Option<String>,
    scopes: Vec<String>,
}

fn request_protected_resource_challenge(endpoint: &Url) -> Result<BearerChallenge, McpHostError> {
    let client = pinned_client(endpoint)?;
    let response = client
        .post(endpoint.clone())
        .header(ACCEPT, "application/json, text/event-stream")
        .header(CONTENT_TYPE, "application/json")
        .header(ORIGIN, endpoint.origin().ascii_serialization())
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": mealy_application::MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mealy", "version": env!("CARGO_PKG_VERSION")}
            }
        }))
        .timeout(MCP_OAUTH_DISCOVERY_TIMEOUT)
        .send()
        .map_err(|error| map_oauth_http_error(&error))?;
    if response.status() != StatusCode::UNAUTHORIZED {
        return Err(McpHostError::HttpStatus(response.status().as_u16()));
    }
    parse_bearer_challenge(response.headers())
}

fn parse_bearer_challenge(
    headers: &reqwest::header::HeaderMap,
) -> Result<BearerChallenge, McpHostError> {
    let mut selected = None;
    for header in headers.get_all(WWW_AUTHENTICATE) {
        let value = header
            .to_str()
            .map_err(|_| McpHostError::InvalidOAuthMetadata)?;
        if value.len() > MCP_OAUTH_MAXIMUM_CHALLENGE_BYTES || value.chars().any(char::is_control) {
            return Err(McpHostError::InvalidOAuthMetadata);
        }
        if let Some(challenge) = parse_bearer_challenge_value(value)?
            && selected.replace(challenge).is_some()
        {
            return Err(McpHostError::InvalidOAuthMetadata);
        }
    }
    Ok(selected.unwrap_or_default())
}

fn parse_bearer_challenge_value(value: &str) -> Result<Option<BearerChallenge>, McpHostError> {
    let fields = split_quoted(value, b',')?;
    let mut active = false;
    let mut found = false;
    let mut parameters = BTreeMap::new();
    for field in fields {
        let field = field.trim();
        if field.is_empty() {
            return Err(McpHostError::InvalidOAuthMetadata);
        }
        let (prefix, parameter) = match field.find('=') {
            Some(equals) if field[..equals].trim().chars().any(char::is_whitespace) => {
                let separator = field
                    .find(char::is_whitespace)
                    .ok_or(McpHostError::InvalidOAuthMetadata)?;
                let (scheme, remainder) = field.split_at(separator);
                (
                    Some(scheme.eq_ignore_ascii_case("Bearer")),
                    Some(remainder.trim()),
                )
            }
            Some(_) => (None, Some(field)),
            None => (Some(field.eq_ignore_ascii_case("Bearer")), None),
        };
        if let Some(is_bearer) = prefix {
            active = is_bearer;
            if active {
                if found {
                    return Err(McpHostError::InvalidOAuthMetadata);
                }
                found = true;
            }
        }
        if active && let Some(parameter) = parameter.filter(|value| !value.is_empty()) {
            let (name, value) = parse_auth_parameter(parameter)?;
            if parameters.insert(name, value).is_some() {
                return Err(McpHostError::InvalidOAuthMetadata);
            }
        }
    }
    if !found {
        return Ok(None);
    }
    let resource_metadata = parameters.remove("resource_metadata");
    let scopes = parameters
        .remove("scope")
        .map(|scope| {
            scope
                .split(' ')
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(Some(BearerChallenge {
        resource_metadata,
        scopes,
    }))
}

fn parse_auth_parameter(value: &str) -> Result<(String, String), McpHostError> {
    let (name, raw) = value
        .split_once('=')
        .ok_or(McpHostError::InvalidOAuthMetadata)?;
    let name = name.trim().to_ascii_lowercase();
    let raw = raw.trim();
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    let decoded = if raw.starts_with('"') {
        decode_quoted_string(raw)?
    } else {
        if raw.is_empty()
            || raw
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b',' | b'"' | b'\\'))
        {
            return Err(McpHostError::InvalidOAuthMetadata);
        }
        raw.to_owned()
    };
    Ok((name, decoded))
}

fn decode_quoted_string(value: &str) -> Result<String, McpHostError> {
    if value.len() < 2 || !value.ends_with('"') {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    let mut decoded = String::new();
    let mut escaped = false;
    for byte in value.as_bytes()[1..value.len() - 1].iter().copied() {
        if escaped {
            if !matches!(byte, b'"' | b'\\') {
                return Err(McpHostError::InvalidOAuthMetadata);
            }
            decoded.push(char::from(byte));
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if !(0x20..=0x7e).contains(&byte) || byte == b'"' {
            return Err(McpHostError::InvalidOAuthMetadata);
        } else {
            decoded.push(char::from(byte));
        }
    }
    if escaped {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    Ok(decoded)
}

fn split_quoted(value: &str, delimiter: u8) -> Result<Vec<&str>, McpHostError> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == delimiter {
            fields.push(&value[start..index]);
            start = index.saturating_add(1);
        }
    }
    if quoted || escaped {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    fields.push(&value[start..]);
    Ok(fields)
}

fn resource_metadata_candidates(
    endpoint: &Url,
    advertised: Option<&str>,
) -> Result<Vec<Url>, McpHostError> {
    if let Some(advertised) = advertised {
        return Ok(vec![safe_oauth_url(advertised, true)?]);
    }
    let origin = endpoint.origin().ascii_serialization();
    let endpoint_path = endpoint.path().trim_start_matches('/');
    let path_scoped = safe_oauth_url(
        &format!("{origin}/.well-known/oauth-protected-resource/{endpoint_path}"),
        false,
    )?;
    let root = safe_oauth_url(
        &format!("{origin}/.well-known/oauth-protected-resource"),
        false,
    )?;
    let mut candidates = vec![path_scoped];
    if candidates[0] != root {
        candidates.push(root);
    }
    Ok(candidates)
}

fn authorization_metadata_candidates(issuer: &Url) -> Result<Vec<Url>, McpHostError> {
    let origin = issuer.origin().ascii_serialization();
    let issuer_path = issuer.path().trim_matches('/');
    let candidates = if issuer_path.is_empty() {
        vec![
            format!("{origin}/.well-known/oauth-authorization-server"),
            format!("{origin}/.well-known/openid-configuration"),
        ]
    } else {
        vec![
            format!("{origin}/.well-known/oauth-authorization-server/{issuer_path}"),
            format!("{origin}/.well-known/openid-configuration/{issuer_path}"),
            format!("{origin}/{issuer_path}/.well-known/openid-configuration"),
        ]
    };
    candidates
        .into_iter()
        .map(|candidate| safe_oauth_url(&candidate, false))
        .collect()
}

fn first_metadata_document(candidates: &[Url]) -> Result<(Url, Value), McpHostError> {
    for candidate in candidates {
        if let Some(document) = request_json_metadata(candidate)? {
            return Ok((candidate.clone(), document));
        }
    }
    Err(McpHostError::InvalidOAuthMetadata)
}

fn request_json_metadata(url: &Url) -> Result<Option<Value>, McpHostError> {
    let response = pinned_client(url)?
        .get(url.clone())
        .header(ACCEPT, "application/json")
        .timeout(MCP_OAUTH_DISCOVERY_TIMEOUT)
        .send()
        .map_err(|error| map_oauth_http_error(&error))?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if response.status() != StatusCode::OK {
        return Err(McpHostError::HttpStatus(response.status().as_u16()));
    }
    parse_json_metadata(response).map(Some)
}

fn parse_json_metadata(mut response: Response) -> Result<Value, McpHostError> {
    let media_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if media_type != Some("application/json") {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(MCP_OAUTH_MAXIMUM_BODY_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| McpHostError::Io(format!("MCP OAuth metadata read failed: {error}")))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MCP_OAUTH_MAXIMUM_BODY_BYTES {
        return Err(McpHostError::OutputLimitExceeded);
    }
    let value =
        serde_json::from_slice::<Value>(&bytes).map_err(|_| McpHostError::InvalidOAuthMetadata)?;
    value
        .as_object()
        .ok_or(McpHostError::InvalidOAuthMetadata)?;
    Ok(value)
}

fn pinned_client(url: &Url) -> Result<Client, McpHostError> {
    let sockets = validate_oauth_destination(url)?;
    let host = url.host_str().ok_or(McpHostError::InvalidConfiguration)?;
    Client::builder()
        .connect_timeout(MCP_OAUTH_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host, &sockets)
        .build()
        .map_err(|error| McpHostError::Io(format!("MCP OAuth client failed: {error}")))
}

fn validate_oauth_destination(url: &Url) -> Result<Vec<std::net::SocketAddr>, McpHostError> {
    let authority = WebAccessConfig {
        enabled: true,
        allow_public_internet: false,
        allowed_domains: Vec::new(),
        allowed_origins: vec![url.origin().ascii_serialization()],
        search: None,
    };
    authority
        .validate()
        .map_err(|_| McpHostError::InvalidConfiguration)?;
    resolve_pinned_web_destination(url, &authority).map_err(|_| McpHostError::InvalidConfiguration)
}

fn safe_oauth_issuer(value: &str) -> Result<Url, McpHostError> {
    let url = safe_oauth_url(value, false)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    Ok(url)
}

fn safe_oauth_url(value: &str, allow_query: bool) -> Result<Url, McpHostError> {
    if value.is_empty() || value.len() > 4_096 || value.trim() != value {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    let url = Url::parse(value).map_err(|_| McpHostError::InvalidOAuthMetadata)?;
    if !canonical_url_text_matches(value, &url)
        || !url.username().is_empty()
        || url.password().is_some()
        || (!allow_query && url.query().is_some())
        || url.fragment().is_some()
        || url.host_str().is_none()
        || url.path().is_empty()
    {
        return Err(McpHostError::InvalidOAuthMetadata);
    }
    let literal_address = url.host_str().and_then(|host| host.parse::<IpAddr>().ok());
    let literal_loopback = literal_address.is_some_and(|address| address.is_loopback());
    if url.scheme() == "https" && literal_address.is_none()
        || url.scheme() == "http" && literal_loopback
    {
        Ok(url)
    } else {
        Err(McpHostError::InvalidOAuthMetadata)
    }
}

fn canonical_url_text_matches(value: &str, url: &Url) -> bool {
    url.as_str() == value
        || (url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.as_str().strip_suffix('/') == Some(value))
}

fn select_authorization_server(
    advertised: &[String],
    selected: Option<&str>,
) -> Result<String, McpHostError> {
    match selected {
        Some(selected)
            if advertised
                .binary_search_by(|value| value.as_str().cmp(selected))
                .is_ok() =>
        {
            Ok(selected.to_owned())
        }
        Some(_) => Err(McpHostError::InvalidOAuthMetadata),
        None if advertised.len() == 1 => Ok(advertised[0].clone()),
        None => Err(McpHostError::OAuthAuthorizationServerSelectionRequired(
            advertised.to_vec(),
        )),
    }
}

fn exact_string(object: &Value, field: &str, maximum: usize) -> Result<String, McpHostError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
        .ok_or(McpHostError::InvalidOAuthMetadata)
}

fn optional_string(
    object: &Value,
    field: &str,
    maximum: usize,
) -> Result<Option<String>, McpHostError> {
    object
        .get(field)
        .map(|_| exact_string(object, field, maximum))
        .transpose()
}

fn string_array(
    object: &Value,
    field: &str,
    minimum: usize,
    maximum: usize,
    maximum_value_bytes: usize,
) -> Result<Vec<String>, McpHostError> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .filter(|values| values.len() >= minimum && values.len() <= maximum)
        .ok_or(McpHostError::InvalidOAuthMetadata)?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= maximum_value_bytes
                        && !value.chars().any(char::is_control)
                })
                .map(str::to_owned)
                .ok_or(McpHostError::InvalidOAuthMetadata)
        })
        .collect()
}

fn optional_string_array(
    object: &Value,
    field: &str,
    maximum: usize,
    maximum_value_bytes: usize,
) -> Result<Vec<String>, McpHostError> {
    object.get(field).map_or_else(
        || Ok(Vec::new()),
        |_| string_array(object, field, 0, maximum, maximum_value_bytes),
    )
}

fn validate_scopes(scopes: &[String]) -> Result<(), McpHostError> {
    if scopes.len() > MCP_OAUTH_MAXIMUM_SCOPES
        || scopes.iter().any(|scope| {
            scope.is_empty()
                || scope.len() > 256
                || scope.bytes().any(|byte| {
                    byte != 0x21 && !(0x23..=0x5b).contains(&byte) && !(0x5d..=0x7e).contains(&byte)
                })
        })
    {
        Err(McpHostError::InvalidOAuthMetadata)
    } else {
        Ok(())
    }
}

fn ensure_unique(values: &[String]) -> Result<(), McpHostError> {
    if values.windows(2).any(|window| window[0] == window[1]) {
        Err(McpHostError::InvalidOAuthMetadata)
    } else {
        Ok(())
    }
}

fn map_oauth_http_error(error: &reqwest::Error) -> McpHostError {
    if error.is_timeout() {
        McpHostError::TimedOut
    } else {
        McpHostError::Io(format!("MCP OAuth request failed: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        discover_mcp_oauth_metadata, parse_bearer_challenge_value, resource_metadata_candidates,
    };
    use crate::mcp::McpHostError;
    use mealy_application::{McpHttpAuthentication, McpHttpEndpointConfig};
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };
    use url::Url;

    #[test]
    fn challenge_parser_handles_multiple_schemes_and_quoted_commas() {
        let challenge = parse_bearer_challenge_value(
            r#"Basic realm="legacy", Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp", scope="files:read files:write", error_description="comma, retained""#,
        )
        .expect("challenge")
        .expect("bearer");
        assert_eq!(
            challenge.resource_metadata.as_deref(),
            Some("https://mcp.example/.well-known/oauth-protected-resource/mcp")
        );
        assert_eq!(challenge.scopes, ["files:read", "files:write"]);
        let bearer_first =
            parse_bearer_challenge_value(r#"Bearer scope="read", Basic realm="legacy""#)
                .expect("bearer then basic")
                .expect("bearer");
        assert_eq!(bearer_first.scopes, ["read"]);
        assert!(
            parse_bearer_challenge_value(
                r#"Bearer resource_metadata="https://one", resource_metadata="https://two""#
            )
            .is_err()
        );
    }

    #[test]
    fn endpoint_path_precedes_root_metadata_fallback() {
        let endpoint = Url::parse("https://mcp.example/public/mcp").expect("endpoint");
        let candidates = resource_metadata_candidates(&endpoint, None).expect("candidates");
        assert_eq!(
            candidates[0].as_str(),
            "https://mcp.example/.well-known/oauth-protected-resource/public/mcp"
        );
        assert_eq!(
            candidates[1].as_str(),
            "https://mcp.example/.well-known/oauth-protected-resource"
        );
        let escaped = Url::parse("https://mcp.example/a%2Fb").expect("escaped endpoint");
        assert_eq!(
            resource_metadata_candidates(&escaped, None).expect("escaped candidates")[0].as_str(),
            "https://mcp.example/.well-known/oauth-protected-resource/a%2Fb"
        );
    }

    #[test]
    fn discovery_validates_resource_issuer_and_pkce() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let endpoint = format!("{origin}/mcp");
        let origin_for_worker = origin.clone();
        let worker = thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().expect("fixture connection");
                serve_oauth_fixture(stream, &origin_for_worker);
            }
        });
        let config = McpHttpEndpointConfig::new(
            "oauth-fixture".to_owned(),
            endpoint,
            McpHttpAuthentication::None,
        )
        .expect("config");
        let discovery = discover_mcp_oauth_metadata(&config, None).expect("discovery");
        assert_eq!(discovery.selected_authorization_server(), origin);
        assert_eq!(discovery.challenge_scopes(), ["files:read"]);
        assert_eq!(discovery.scopes_supported(), ["files:read"]);
        assert!(discovery.client_id_metadata_document_supported());
        worker.join().expect("fixture worker");
    }

    #[test]
    fn multiple_issuers_require_explicit_selection_before_issuer_fetch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let endpoint = format!("{origin}/mcp");
        let origin_for_worker = origin.clone();
        let worker = thread::spawn(move || {
            for request in 0..2 {
                let (mut stream, _) = listener.accept().expect("fixture connection");
                consume_request(&mut stream);
                if request == 0 {
                    respond(
                        &mut stream,
                        "401 Unauthorized",
                        &[(
                            "WWW-Authenticate",
                            &format!("Bearer resource_metadata=\"{origin_for_worker}/metadata\""),
                        )],
                        "",
                    );
                } else {
                    let body = format!(
                        r#"{{"resource":"{origin_for_worker}/mcp","authorization_servers":["{origin_for_worker}/one","{origin_for_worker}/two"]}}"#
                    );
                    respond(
                        &mut stream,
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        &body,
                    );
                }
            }
        });
        let config = McpHttpEndpointConfig::new(
            "oauth-fixture".to_owned(),
            endpoint,
            McpHttpAuthentication::None,
        )
        .expect("config");
        assert!(matches!(
            discover_mcp_oauth_metadata(&config, None),
            Err(McpHostError::OAuthAuthorizationServerSelectionRequired(issuers))
                if issuers.len() == 2
        ));
        worker.join().expect("fixture worker");
    }

    fn serve_oauth_fixture(mut stream: TcpStream, origin: &str) {
        let path = consume_request(&mut stream);
        match path.as_str() {
            "/mcp" => respond(
                &mut stream,
                "401 Unauthorized",
                &[(
                    "WWW-Authenticate",
                    &format!(
                        "Bearer resource_metadata=\"{origin}/.well-known/oauth-protected-resource/mcp\", scope=\"files:read\""
                    ),
                )],
                "",
            ),
            "/.well-known/oauth-protected-resource/mcp" => {
                let body = format!(
                    r#"{{"resource":"{origin}/mcp","authorization_servers":["{origin}"],"scopes_supported":["files:read"]}}"#
                );
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Content-Type", "application/json")],
                    &body,
                );
            }
            "/.well-known/oauth-authorization-server" => {
                let body = format!(
                    r#"{{"issuer":"{origin}","authorization_endpoint":"{origin}/authorize","token_endpoint":"{origin}/token","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"client_id_metadata_document_supported":true}}"#
                );
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Content-Type", "application/json")],
                    &body,
                );
            }
            _ => respond(&mut stream, "404 Not Found", &[], ""),
        }
    }

    fn consume_request(stream: &mut TcpStream) -> String {
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("request line");
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_owned();
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
        path
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
