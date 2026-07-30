use crate::mcp::validated_mcp_http_endpoint;
use crate::{sha256_digest, valid_provider_secret_id};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Maximum number of authorization servers accepted from protected-resource metadata.
pub const MCP_OAUTH_MAXIMUM_AUTHORIZATION_SERVERS: usize = 8;
/// Maximum number of OAuth scopes accepted from one metadata document or challenge.
pub const MCP_OAUTH_MAXIMUM_SCOPES: usize = 128;
/// Maximum number of advertised values accepted for one OAuth capability.
pub const MCP_OAUTH_MAXIMUM_METADATA_VALUES: usize = 64;

/// Fully validated stable-2025-11-25 MCP OAuth discovery evidence.
///
/// Discovery is intentionally non-secret. It does not create a client registration, authorization
/// request, access token, or durable authority. An owner must separately approve those operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpOAuthMetadataDiscovery {
    endpoint: String,
    resource_metadata_url: String,
    resource: String,
    authorization_servers: Vec<String>,
    selected_authorization_server: String,
    authorization_server_metadata_url: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    challenge_scopes: Vec<String>,
    scopes_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    client_id_metadata_document_supported: bool,
}

impl McpOAuthMetadataDiscovery {
    /// Constructs validated discovery evidence.
    ///
    /// # Errors
    ///
    /// Returns [`McpOAuthMetadataError`] if an endpoint, issuer, scope, ordering invariant, or
    /// mandatory PKCE capability is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: String,
        resource_metadata_url: String,
        resource: String,
        authorization_servers: Vec<String>,
        selected_authorization_server: String,
        authorization_server_metadata_url: String,
        authorization_endpoint: String,
        token_endpoint: String,
        registration_endpoint: Option<String>,
        challenge_scopes: Vec<String>,
        scopes_supported: Vec<String>,
        code_challenge_methods_supported: Vec<String>,
        token_endpoint_auth_methods_supported: Vec<String>,
        client_id_metadata_document_supported: bool,
    ) -> Result<Self, McpOAuthMetadataError> {
        let discovery = Self {
            endpoint,
            resource_metadata_url,
            resource,
            authorization_servers,
            selected_authorization_server,
            authorization_server_metadata_url,
            authorization_endpoint,
            token_endpoint,
            registration_endpoint,
            challenge_scopes,
            scopes_supported,
            code_challenge_methods_supported,
            token_endpoint_auth_methods_supported,
            client_id_metadata_document_supported,
        };
        discovery.validate()?;
        Ok(discovery)
    }

    /// Exact protected Streamable HTTP MCP endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Exact protected-resource metadata URL used for discovery.
    #[must_use]
    pub fn resource_metadata_url(&self) -> &str {
        &self.resource_metadata_url
    }

    /// Exact audience passed as the OAuth `resource` parameter.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Complete bounded authorization-server list advertised by the resource.
    #[must_use]
    pub fn authorization_servers(&self) -> &[String] {
        &self.authorization_servers
    }

    /// Exact owner-selected authorization-server issuer.
    #[must_use]
    pub fn selected_authorization_server(&self) -> &str {
        &self.selected_authorization_server
    }

    /// Exact authorization endpoint from issuer metadata.
    #[must_use]
    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    /// Exact token endpoint from issuer metadata.
    #[must_use]
    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    /// Effective advertised token-endpoint client authentication methods.
    #[must_use]
    pub fn token_endpoint_auth_methods_supported(&self) -> &[String] {
        &self.token_endpoint_auth_methods_supported
    }

    /// Challenge scopes preferred for the initial least-authority request.
    #[must_use]
    pub fn challenge_scopes(&self) -> &[String] {
        &self.challenge_scopes
    }

    /// Protected-resource fallback scopes when the challenge did not advertise any.
    #[must_use]
    pub fn scopes_supported(&self) -> &[String] {
        &self.scopes_supported
    }

    /// Whether the issuer advertises Client ID Metadata Documents.
    #[must_use]
    pub const fn client_id_metadata_document_supported(&self) -> bool {
        self.client_id_metadata_document_supported
    }

    /// Returns a stable digest of all validated metadata evidence used to authorize a login.
    ///
    /// # Errors
    ///
    /// Returns [`McpOAuthMetadataError`] only if serialization unexpectedly fails.
    pub fn metadata_digest(&self) -> Result<String, McpOAuthMetadataError> {
        serde_json::to_vec(self)
            .map(|bytes| sha256_digest(&bytes))
            .map_err(|_| McpOAuthMetadataError::Invalid)
    }

    /// Validates deserialized or constructed discovery evidence.
    ///
    /// # Errors
    ///
    /// Returns [`McpOAuthMetadataError`] when the evidence is not canonical or safe to use.
    pub fn validate(&self) -> Result<(), McpOAuthMetadataError> {
        let endpoint =
            validated_mcp_http_endpoint(&self.endpoint).ok_or(McpOAuthMetadataError::Invalid)?;
        if canonical_oauth_url(&self.resource_metadata_url).is_none()
            || canonical_oauth_resource(&self.resource).is_none()
            || self.resource != endpoint.as_str()
            || self.authorization_servers.is_empty()
            || self.authorization_servers.len() > MCP_OAUTH_MAXIMUM_AUTHORIZATION_SERVERS
            || !strictly_sorted_unique(&self.authorization_servers)
            || !self
                .authorization_servers
                .iter()
                .all(|issuer| canonical_oauth_issuer(issuer).is_some())
            || self
                .authorization_servers
                .binary_search(&self.selected_authorization_server)
                .is_err()
            || canonical_oauth_url(&self.authorization_server_metadata_url).is_none()
            || canonical_oauth_url(&self.authorization_endpoint).is_none()
            || canonical_oauth_url(&self.token_endpoint).is_none()
            || self
                .registration_endpoint
                .as_deref()
                .is_some_and(|value| canonical_oauth_url(value).is_none())
            || !valid_scope_set(&self.challenge_scopes)
            || !valid_scope_set(&self.scopes_supported)
            || !valid_metadata_values(&self.code_challenge_methods_supported)
            || !strictly_sorted_unique(&self.code_challenge_methods_supported)
            || self
                .code_challenge_methods_supported
                .binary_search_by(|value| value.as_str().cmp("S256"))
                .is_err()
            || !valid_metadata_values(&self.token_endpoint_auth_methods_supported)
            || !strictly_sorted_unique(&self.token_endpoint_auth_methods_supported)
        {
            return Err(McpOAuthMetadataError::Invalid);
        }
        Ok(())
    }
}

/// Non-secret immutable authority bound to one brokered MCP OAuth token family.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpOAuthTokenGrant {
    token_set_id: String,
    resource: String,
    authorization_server: String,
    token_endpoint: String,
    client_id: String,
    scopes: Vec<String>,
    metadata_digest: String,
}

impl McpOAuthTokenGrant {
    /// Constructs one audience- and metadata-bound OAuth credential grant.
    ///
    /// # Errors
    ///
    /// Returns [`McpOAuthMetadataError`] when an identity, endpoint, client, scope, or digest is
    /// malformed.
    pub fn new(
        token_set_id: String,
        resource: String,
        authorization_server: String,
        token_endpoint: String,
        client_id: String,
        mut scopes: Vec<String>,
        metadata_digest: String,
    ) -> Result<Self, McpOAuthMetadataError> {
        scopes.sort();
        let grant = Self {
            token_set_id,
            resource,
            authorization_server,
            token_endpoint,
            client_id,
            scopes,
            metadata_digest,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Portable identity of the owner-private rotating token record.
    #[must_use]
    pub fn token_set_id(&self) -> &str {
        &self.token_set_id
    }

    /// Exact MCP audience used on authorization and token requests.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Exact authorization-server issuer selected by the owner.
    #[must_use]
    pub fn authorization_server(&self) -> &str {
        &self.authorization_server
    }

    /// Exact token endpoint discovered and reviewed for this grant.
    #[must_use]
    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    /// Exact preregistered public OAuth client identity.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Exact granted scopes in canonical order.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Digest of the complete discovery evidence used at authorization time.
    #[must_use]
    pub fn metadata_digest(&self) -> &str {
        &self.metadata_digest
    }

    /// Opaque token-broker reference bound into capability ceilings and descriptors.
    #[must_use]
    pub fn capability_reference(&self) -> String {
        format!("mcp_oauth_broker:{}", self.token_set_id)
    }

    /// Validates one loaded token grant without resolving any secret.
    ///
    /// # Errors
    ///
    /// Returns [`McpOAuthMetadataError`] for malformed or non-canonical grant evidence.
    pub fn validate(&self) -> Result<(), McpOAuthMetadataError> {
        if !valid_provider_secret_id(&self.token_set_id)
            || canonical_oauth_resource(&self.resource).is_none()
            || canonical_oauth_issuer(&self.authorization_server).is_none()
            || canonical_oauth_url(&self.token_endpoint).is_none()
            || self.client_id.is_empty()
            || self.client_id.len() > 1_024
            || self.client_id.trim() != self.client_id
            || self.client_id.chars().any(char::is_control)
            || !valid_scope_set(&self.scopes)
            || self.metadata_digest.len() != 64
            || self
                .metadata_digest
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(McpOAuthMetadataError::Invalid);
        }
        Ok(())
    }
}

fn canonical_oauth_resource(value: &str) -> Option<Url> {
    canonical_oauth_url(value)
}

fn canonical_oauth_issuer(value: &str) -> Option<Url> {
    let url = canonical_oauth_url(value)?;
    (url.query().is_none() && url.fragment().is_none()).then_some(url)
}

fn canonical_oauth_url(value: &str) -> Option<Url> {
    if value.is_empty() || value.len() > 4_096 || value.trim() != value {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if !canonical_url_text_matches(value, &url)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || url.path().is_empty()
    {
        return None;
    }
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    (url.scheme() == "https" && !loopback || url.scheme() == "http" && loopback).then_some(url)
}

fn canonical_url_text_matches(value: &str, url: &Url) -> bool {
    url.as_str() == value
        || (url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.as_str().strip_suffix('/') == Some(value))
}

fn valid_scope_set(values: &[String]) -> bool {
    values.len() <= MCP_OAUTH_MAXIMUM_SCOPES
        && strictly_sorted_unique(values)
        && values.iter().all(|scope| {
            !scope.is_empty()
                && scope.len() <= 256
                && scope.bytes().all(|byte| {
                    byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
                })
        })
}

fn valid_metadata_values(values: &[String]) -> bool {
    values.len() <= MCP_OAUTH_MAXIMUM_METADATA_VALUES
        && values.iter().all(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
        })
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values
        .windows(2)
        .all(|window| window[0].as_str() < window[1].as_str())
}

/// Invalid or unsafe MCP OAuth metadata evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpOAuthMetadataError {
    /// Metadata is malformed, non-canonical, unbounded, inconsistent, or lacks PKCE S256.
    #[error("MCP OAuth metadata is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::{McpOAuthMetadataDiscovery, McpOAuthMetadataError, McpOAuthTokenGrant};

    fn valid() -> McpOAuthMetadataDiscovery {
        McpOAuthMetadataDiscovery::new(
            "https://mcp.example.com/mcp".to_owned(),
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp".to_owned(),
            "https://mcp.example.com/mcp".to_owned(),
            vec!["https://auth.example.com".to_owned()],
            "https://auth.example.com".to_owned(),
            "https://auth.example.com/.well-known/oauth-authorization-server".to_owned(),
            "https://auth.example.com/authorize".to_owned(),
            "https://auth.example.com/token".to_owned(),
            None,
            vec!["files:read".to_owned()],
            vec!["files:read".to_owned()],
            vec!["S256".to_owned()],
            vec!["none".to_owned()],
            true,
        )
        .expect("valid metadata")
    }

    #[test]
    fn discovery_requires_exact_resource_and_pkce_s256() {
        let discovery = valid();
        assert_eq!(discovery.resource(), "https://mcp.example.com/mcp");
        let invalid = McpOAuthMetadataDiscovery::new(
            discovery.endpoint().to_owned(),
            discovery.resource_metadata_url().to_owned(),
            "https://mcp.example.com".to_owned(),
            discovery.authorization_servers().to_vec(),
            discovery.selected_authorization_server().to_owned(),
            "https://auth.example.com/.well-known/oauth-authorization-server".to_owned(),
            discovery.authorization_endpoint().to_owned(),
            discovery.token_endpoint().to_owned(),
            None,
            Vec::new(),
            Vec::new(),
            vec!["plain".to_owned()],
            Vec::new(),
            false,
        );
        assert_eq!(invalid, Err(McpOAuthMetadataError::Invalid));
    }

    #[test]
    fn discovery_rejects_non_loopback_cleartext_and_unsorted_scopes() {
        let mut scopes = vec!["write".to_owned(), "read".to_owned()];
        assert!(
            McpOAuthMetadataDiscovery::new(
                "http://192.0.2.1/mcp".to_owned(),
                "http://192.0.2.1/.well-known/oauth-protected-resource/mcp".to_owned(),
                "http://192.0.2.1/mcp".to_owned(),
                vec!["https://auth.example.com".to_owned()],
                "https://auth.example.com".to_owned(),
                "https://auth.example.com/.well-known/oauth-authorization-server".to_owned(),
                "https://auth.example.com/authorize".to_owned(),
                "https://auth.example.com/token".to_owned(),
                None,
                Vec::new(),
                std::mem::take(&mut scopes),
                vec!["S256".to_owned()],
                Vec::new(),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn token_grant_binds_audience_client_scopes_and_metadata() {
        let discovery = valid();
        let grant = McpOAuthTokenGrant::new(
            "mcp.remote".to_owned(),
            discovery.resource().to_owned(),
            discovery.selected_authorization_server().to_owned(),
            discovery.token_endpoint().to_owned(),
            "mealy-native".to_owned(),
            vec!["files:read".to_owned()],
            discovery.metadata_digest().expect("metadata digest"),
        )
        .expect("token grant");
        assert_eq!(grant.capability_reference(), "mcp_oauth_broker:mcp.remote");
        assert_eq!(grant.scopes(), ["files:read"]);
        assert_eq!(grant.metadata_digest().len(), 64);
    }
}
