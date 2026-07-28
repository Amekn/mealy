use crate::{is_sha256_digest, sha256_digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use mealy_domain::{
    EffectClass, ExtensionFilesystemAccess, ExtensionManifest, RiskClass, SkillManifest,
    SkillToolRequirement,
};
use serde::{
    Deserialize, Serialize,
    de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use url::Url;

/// Exact contract identifier for one signed registry snapshot payload.
pub const REGISTRY_SNAPSHOT_CONTRACT_VERSION: &str = "mealy.registry.snapshot.v1";
/// Exact contract identifier for one publisher-signed release payload.
pub const REGISTRY_RELEASE_CONTRACT_VERSION: &str = "mealy.registry.release.v1";
/// Envelope payload type for registry trust-root rotation.
pub const REGISTRY_ROOT_PAYLOAD_TYPE: &str = "application/vnd.mealy.registry.root.v1+json";
/// Envelope payload type for registry snapshots.
pub const REGISTRY_SNAPSHOT_PAYLOAD_TYPE: &str = "application/vnd.mealy.registry.snapshot.v1+json";
/// Media type of one complete signed snapshot envelope returned by a registry mirror.
pub const REGISTRY_SNAPSHOT_ENVELOPE_MEDIA_TYPE: &str =
    "application/vnd.mealy.registry.snapshot-envelope.v1+json";
/// Envelope payload type for package releases.
pub const REGISTRY_RELEASE_PAYLOAD_TYPE: &str = "application/vnd.mealy.registry.release.v1+json";
/// Media type of one signed release envelope referenced by a snapshot.
pub const REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE: &str =
    "application/vnd.mealy.registry.release-envelope.v1+json";
/// Extension manifest media type inside a release.
pub const REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE: &str =
    "application/vnd.mealy.extension-manifest.v1+json";
/// Skill manifest media type inside a release.
pub const REGISTRY_SKILL_MANIFEST_MEDIA_TYPE: &str = "application/vnd.mealy.skill-manifest.v1+json";
/// Immutable extension package media type.
pub const REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE: &str =
    "application/vnd.mealy.extension-package.v1+tar";
/// Immutable skill package media type.
pub const REGISTRY_SKILL_PACKAGE_MEDIA_TYPE: &str = "application/vnd.mealy.skill-package.v1+tar";

const SNAPSHOT_SIGNATURE_CONTEXT: &str = "MEALY-REGISTRY-SNAPSHOT-V1";
const RELEASE_SIGNATURE_CONTEXT: &str = "MEALY-REGISTRY-RELEASE-V1";
const ROOT_SIGNATURE_CONTEXT: &str = "MEALY-REGISTRY-ROOT-V1";
const MAXIMUM_ROOT_ENVELOPE_BYTES: usize = 256 * 1024;
const MAXIMUM_ROOT_PAYLOAD_BYTES: usize = 128 * 1024;
/// Hard ceiling for one complete signed snapshot envelope fetched from an untrusted mirror.
pub const REGISTRY_MAXIMUM_SNAPSHOT_ENVELOPE_BYTES: u64 = 4 * 1024 * 1024;
const MAXIMUM_SNAPSHOT_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_SNAPSHOT_PAYLOAD_BYTES: usize = 3 * 1024 * 1024;
const MAXIMUM_RELEASE_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_RELEASE_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAXIMUM_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAXIMUM_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_KEYS: usize = 32;
const MAXIMUM_PUBLISHERS: usize = 10_000;
const MAXIMUM_TARGETS: usize = 100_000;
const MAXIMUM_DEPENDENCIES: usize = 128;
const MAXIMUM_SNAPSHOT_LIFETIME_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
const MAXIMUM_CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;

#[derive(Clone, Copy)]
struct SignedEnvelopePolicy {
    maximum_envelope_bytes: usize,
    maximum_payload_bytes: usize,
    maximum_signatures: usize,
    payload_type: &'static str,
    signature_context: &'static str,
}

const ROOT_ENVELOPE_POLICY: SignedEnvelopePolicy = SignedEnvelopePolicy {
    maximum_envelope_bytes: MAXIMUM_ROOT_ENVELOPE_BYTES,
    maximum_payload_bytes: MAXIMUM_ROOT_PAYLOAD_BYTES,
    maximum_signatures: MAXIMUM_KEYS * 2,
    payload_type: REGISTRY_ROOT_PAYLOAD_TYPE,
    signature_context: ROOT_SIGNATURE_CONTEXT,
};
const SNAPSHOT_ENVELOPE_POLICY: SignedEnvelopePolicy = SignedEnvelopePolicy {
    maximum_envelope_bytes: MAXIMUM_SNAPSHOT_ENVELOPE_BYTES,
    maximum_payload_bytes: MAXIMUM_SNAPSHOT_PAYLOAD_BYTES,
    maximum_signatures: MAXIMUM_KEYS,
    payload_type: REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
    signature_context: SNAPSHOT_SIGNATURE_CONTEXT,
};
const RELEASE_ENVELOPE_POLICY: SignedEnvelopePolicy = SignedEnvelopePolicy {
    maximum_envelope_bytes: MAXIMUM_RELEASE_ENVELOPE_BYTES,
    maximum_payload_bytes: MAXIMUM_RELEASE_PAYLOAD_BYTES,
    maximum_signatures: MAXIMUM_KEYS,
    payload_type: REGISTRY_RELEASE_PAYLOAD_TYPE,
    signature_context: RELEASE_SIGNATURE_CONTEXT,
};

/// Package class advertised by registry metadata.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryPackageKind {
    /// Executable out-of-process extension package.
    Extension,
    /// Data-only instruction and passive-resource package.
    Skill,
}

impl RegistryPackageKind {
    const fn manifest_media_type(self) -> &'static str {
        match self {
            Self::Extension => REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE,
            Self::Skill => REGISTRY_SKILL_MANIFEST_MEDIA_TYPE,
        }
    }

    const fn package_media_type(self) -> &'static str {
        match self {
            Self::Extension => REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE,
            Self::Skill => REGISTRY_SKILL_PACKAGE_MEDIA_TYPE,
        }
    }
}

/// Digest-and-size identity for bytes retrieved from an untrusted mirror.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryContentDescriptor {
    /// Exact media type of the referenced bytes.
    pub media_type: String,
    /// Lowercase hexadecimal SHA-256 digest of the exact bytes.
    pub sha256_digest: String,
    /// Exact byte length checked before parsing or extraction.
    pub size_bytes: u64,
}

impl RegistryContentDescriptor {
    fn validate(&self, expected_media_type: &str, maximum_bytes: u64) -> Result<(), RegistryError> {
        if self.media_type != expected_media_type
            || !is_sha256_digest(&self.sha256_digest)
            || self.size_bytes == 0
            || self.size_bytes > maximum_bytes
        {
            return Err(RegistryError::InvalidDescriptor);
        }
        Ok(())
    }

    fn verify_bytes(&self, bytes: &[u8]) -> Result<(), RegistryError> {
        if u64::try_from(bytes.len()).ok() != Some(self.size_bytes)
            || sha256_digest(bytes) != self.sha256_digest
        {
            return Err(RegistryError::InvalidDescriptor);
        }
        Ok(())
    }

    fn validate_for_mirror(&self) -> Result<(), RegistryMirrorError> {
        let maximum_bytes = match self.media_type.as_str() {
            REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE => {
                u64::try_from(MAXIMUM_RELEASE_ENVELOPE_BYTES).unwrap_or(u64::MAX)
            }
            REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE | REGISTRY_SKILL_MANIFEST_MEDIA_TYPE => {
                MAXIMUM_MANIFEST_BYTES
            }
            REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE | REGISTRY_SKILL_PACKAGE_MEDIA_TYPE => {
                MAXIMUM_PACKAGE_BYTES
            }
            _ => return Err(RegistryMirrorError::InvalidRequest),
        };
        if !is_sha256_digest(&self.sha256_digest)
            || self.size_bytes == 0
            || self.size_bytes > maximum_bytes
        {
            return Err(RegistryMirrorError::InvalidRequest);
        }
        Ok(())
    }
}

/// One canonical, owner-selected HTTPS mirror for a locally trusted registry.
///
/// Mirror location is local policy, not a source of trust. Every accepted metadata or package
/// object remains authenticated by the out-of-band registry root and signed content descriptors.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryMirror {
    /// Stable registry identity which must match the locally trusted root.
    pub registry_id: String,
    /// Canonical HTTPS directory URL ending in `/`.
    pub base_url: String,
}

impl RegistryMirror {
    /// Validates canonical mirror identity and derives no network authority.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryMirrorError::InvalidMirror`] for ambiguous, non-HTTPS, credential-bearing,
    /// non-canonical, or path-unsafe mirror URLs.
    pub fn validate(&self) -> Result<(), RegistryMirrorError> {
        if !valid_identifier(&self.registry_id)
            || self.base_url.is_empty()
            || self.base_url.len() > 4_096
            || self.base_url.trim() != self.base_url
        {
            return Err(RegistryMirrorError::InvalidMirror);
        }
        let url = Url::parse(&self.base_url).map_err(|_| RegistryMirrorError::InvalidMirror)?;
        if url.as_str() != self.base_url
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none_or(|host| !valid_mirror_host(host))
            || !valid_mirror_base_path(url.path())
        {
            return Err(RegistryMirrorError::InvalidMirror);
        }
        Ok(())
    }

    fn object_url(&self, relative_path: &str) -> Result<Url, RegistryMirrorError> {
        self.validate()?;
        Url::parse(&self.base_url)
            .map_err(|_| RegistryMirrorError::InvalidMirror)?
            .join(relative_path)
            .map_err(|_| RegistryMirrorError::InvalidRequest)
    }
}

/// One transport-only, authority-free registry mirror read.
///
/// Callers cannot choose a free-form path. Constructors derive the fixed snapshot path or an
/// immutable content-addressed object path from authenticated metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryMirrorRequest {
    url: Url,
    expected_media_type: &'static str,
    maximum_bytes: u64,
    descriptor: Option<RegistryContentDescriptor>,
}

impl RegistryMirrorRequest {
    fn snapshot(mirror: &RegistryMirror) -> Result<Self, RegistryMirrorError> {
        Ok(Self {
            url: mirror.object_url("metadata/snapshot.json")?,
            expected_media_type: REGISTRY_SNAPSHOT_ENVELOPE_MEDIA_TYPE,
            maximum_bytes: REGISTRY_MAXIMUM_SNAPSHOT_ENVELOPE_BYTES,
            descriptor: None,
        })
    }

    fn content(
        mirror: &RegistryMirror,
        descriptor: &RegistryContentDescriptor,
    ) -> Result<Self, RegistryMirrorError> {
        descriptor.validate_for_mirror()?;
        Ok(Self {
            url: mirror.object_url(&format!("objects/sha256/{}", descriptor.sha256_digest))?,
            expected_media_type: match descriptor.media_type.as_str() {
                REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE => REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE,
                REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE => REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE,
                REGISTRY_SKILL_MANIFEST_MEDIA_TYPE => REGISTRY_SKILL_MANIFEST_MEDIA_TYPE,
                REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE => REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE,
                REGISTRY_SKILL_PACKAGE_MEDIA_TYPE => REGISTRY_SKILL_PACKAGE_MEDIA_TYPE,
                _ => return Err(RegistryMirrorError::InvalidRequest),
            },
            maximum_bytes: descriptor.size_bytes,
            descriptor: Some(descriptor.clone()),
        })
    }

    /// Exact canonical URL selected by the fixed registry layout.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Exact response media type accepted for this object.
    #[must_use]
    pub const fn expected_media_type(&self) -> &'static str {
        self.expected_media_type
    }

    /// Maximum response body bytes admitted before signature or archive parsing.
    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    fn verify_response(
        &self,
        response: RegistryMirrorResponse,
    ) -> Result<Vec<u8>, RegistryMirrorError> {
        if response.media_type != self.expected_media_type
            || response.bytes.is_empty()
            || u64::try_from(response.bytes.len())
                .ok()
                .is_none_or(|length| length > self.maximum_bytes)
        {
            return Err(RegistryMirrorError::InvalidResponse);
        }
        if let Some(descriptor) = &self.descriptor {
            descriptor
                .verify_bytes(&response.bytes)
                .map_err(|_| RegistryMirrorError::ContentMismatch)?;
        }
        Ok(response.bytes)
    }
}

/// Exact bounded bytes returned by a registry mirror adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryMirrorResponse {
    /// Normalized response media type without parameters.
    pub media_type: String,
    /// Complete response body retained only after the adapter's byte ceiling.
    pub bytes: Vec<u8>,
}

/// Fail-closed transport categories which never include a URL, body, credential, or peer detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryMirrorTransportError {
    /// DNS, TLS, connection, or response I/O failed.
    #[error("registry mirror transport is unavailable")]
    Unavailable,
    /// Destination, peer, status, header, or response framing violated transport policy.
    #[error("registry mirror transport rejected the response")]
    Rejected,
    /// The response exceeded the request's hard byte ceiling.
    #[error("registry mirror response exceeds its byte ceiling")]
    ResponseTooLarge,
}

/// Infrastructure boundary for one bounded, read-only registry mirror request.
pub trait RegistryMirrorTransport {
    /// Fetches one already validated fixed-layout request without following redirects.
    ///
    /// # Errors
    ///
    /// Returns a bounded transport category without exposing remote response content.
    fn fetch(
        &self,
        request: &RegistryMirrorRequest,
    ) -> Result<RegistryMirrorResponse, RegistryMirrorTransportError>;
}

/// Safe registry mirror request or response failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryMirrorError {
    /// Mirror identity or canonical HTTPS base URL is invalid.
    #[error("registry mirror configuration is invalid")]
    InvalidMirror,
    /// A content descriptor or derived mirror request is invalid.
    #[error("registry mirror request is invalid")]
    InvalidRequest,
    /// The bounded response has the wrong media type, is empty, or exceeds its ceiling.
    #[error("registry mirror response is invalid")]
    InvalidResponse,
    /// Exact response length or SHA-256 does not match authenticated metadata.
    #[error("registry mirror content does not match its signed descriptor")]
    ContentMismatch,
    /// The concrete network adapter failed closed.
    #[error(transparent)]
    Transport(#[from] RegistryMirrorTransportError),
}

/// Fetches one bounded signed snapshot envelope from the fixed mirror metadata path.
///
/// Returned bytes are still untrusted. The caller must pass them to
/// [`inspect_registry_snapshot`] or [`accept_registry_snapshot`] before using discovery metadata.
///
/// # Errors
///
/// Returns [`RegistryMirrorError`] for invalid mirror configuration, transport rejection, or a
/// malformed response boundary.
pub fn fetch_registry_snapshot_envelope(
    transport: &impl RegistryMirrorTransport,
    mirror: &RegistryMirror,
) -> Result<Vec<u8>, RegistryMirrorError> {
    let request = RegistryMirrorRequest::snapshot(mirror)?;
    let response = transport.fetch(&request)?;
    request.verify_response(response)
}

/// Fetches and authenticates one immutable object selected by a signed content descriptor.
///
/// # Errors
///
/// Returns [`RegistryMirrorError`] for invalid mirror/descriptor data, transport rejection, media
/// type drift, truncation, expansion, or digest mismatch.
pub fn fetch_registry_content(
    transport: &impl RegistryMirrorTransport,
    mirror: &RegistryMirror,
    descriptor: &RegistryContentDescriptor,
) -> Result<Vec<u8>, RegistryMirrorError> {
    let request = RegistryMirrorRequest::content(mirror, descriptor)?;
    let response = transport.fetch(&request)?;
    request.verify_response(response)
}

fn valid_mirror_base_path(path: &str) -> bool {
    if !path.starts_with('/') || !path.ends_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }
    let interior = &path[1..path.len() - 1];
    interior.is_empty()
        || interior.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                })
        })
}

fn valid_mirror_host(host: &str) -> bool {
    let literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if literal.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

/// Signature algorithm accepted by the v1 registry contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrySignatureAlgorithm {
    /// Strict RFC 8032 Ed25519 verification.
    Ed25519,
}

/// One key in an out-of-band registry root or registry-authorized publisher identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryPublicKey {
    /// SHA-256 digest of the raw public-key bytes.
    pub key_id: String,
    /// Exact signature algorithm.
    pub algorithm: RegistrySignatureAlgorithm,
    /// Canonical unpadded base64url raw public-key bytes.
    pub public_key_base64url: String,
}

/// Locally trusted, out-of-band registry root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryTrustRoot {
    /// Stable registry identity.
    pub registry_id: String,
    /// Monotonic root revision retained by configuration transactions.
    pub root_version: u64,
    /// Registry snapshot signing keys in ascending key-ID order.
    pub keys: Vec<RegistryPublicKey>,
    /// Number of distinct valid signatures required.
    pub threshold: u16,
    /// UTC expiry after which this root cannot authorize refresh.
    pub expires_at_ms: i64,
}

/// One detached signature over exact decoded envelope payload bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrySignature {
    /// Key identity selected from the relevant trusted key set.
    pub key_id: String,
    /// Canonical unpadded base64url 64-byte Ed25519 signature.
    pub signature_base64url: String,
}

/// Strict envelope that preserves exact signed payload bytes without JSON canonicalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrySignedEnvelope {
    /// Exact application payload type.
    pub payload_type: String,
    /// Canonical unpadded base64url exact JSON payload bytes.
    pub payload_base64url: String,
    /// Detached signatures in ascending key-ID order.
    pub signatures: Vec<RegistrySignature>,
}

/// Registry-authorized publisher identity and threshold policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryPublisher {
    /// Stable publisher identity.
    pub publisher_id: String,
    /// Publisher release keys in ascending key-ID order.
    pub keys: Vec<RegistryPublicKey>,
    /// Number of distinct publisher signatures required.
    pub threshold: u16,
}

/// Registry-signed withdrawal of one immutable release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryWithdrawal {
    /// UTC time the registry withdrew this target.
    pub withdrawn_at_ms: i64,
    /// Bounded operator-facing reason; it never becomes model instructions.
    pub reason: String,
}

/// One immutable publisher-signed release referenced by the registry snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryTarget {
    /// Stable package identity.
    pub package_id: String,
    /// Package class.
    pub kind: RegistryPackageKind,
    /// Exact immutable package version.
    pub version: String,
    /// Publisher whose keys must sign the release payload.
    pub publisher_id: String,
    /// Descriptor of the complete publisher-signed release envelope.
    pub release_envelope: RegistryContentDescriptor,
    /// Optional registry-level withdrawal. Withdrawn targets remain auditable but cannot install.
    pub withdrawal: Option<RegistryWithdrawal>,
}

/// Registry-signed, bounded, expiring discovery snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrySnapshot {
    /// Exact snapshot contract.
    pub contract_version: String,
    /// Stable registry identity matching the local trust root.
    pub registry_id: String,
    /// Strictly monotonic snapshot revision.
    pub version: u64,
    /// UTC generation time.
    pub generated_at_ms: i64,
    /// UTC expiry bounding freeze attacks.
    pub expires_at_ms: i64,
    /// Registry-authorized publisher identities in ascending publisher-ID order.
    pub publishers: Vec<RegistryPublisher>,
    /// Immutable release targets in ascending package-ID/version order.
    pub targets: Vec<RegistryTarget>,
}

impl RegistrySnapshot {
    /// Finds one exact package release without interpreting version ranges.
    #[must_use]
    pub fn target(&self, package_id: &str, version: &str) -> Option<&RegistryTarget> {
        self.targets
            .iter()
            .find(|target| target.package_id == package_id && target.version == version)
    }
}

/// Exact dependency release lock carried by publisher-signed metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryDependencyLock {
    /// Stable dependency package identity.
    pub package_id: String,
    /// Exact dependency class.
    pub kind: RegistryPackageKind,
    /// Exact immutable dependency version.
    pub version: String,
    /// SHA-256 digest of the dependency's complete signed release envelope.
    pub release_envelope_digest: String,
}

/// Publisher-signed metadata for one exact immutable package revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryRelease {
    /// Exact release contract.
    pub contract_version: String,
    /// Registry namespace this release is intended for.
    pub registry_id: String,
    /// Stable package identity.
    pub package_id: String,
    /// Package class.
    pub kind: RegistryPackageKind,
    /// Publisher identity selected from the signed snapshot.
    pub publisher_id: String,
    /// Exact immutable package version.
    pub version: String,
    /// Descriptor of the data-only package manifest.
    pub manifest: RegistryContentDescriptor,
    /// Descriptor of the complete immutable package bytes.
    pub package: RegistryContentDescriptor,
    /// Oldest compatible extension-host API revision.
    pub minimum_host_api: u32,
    /// Newest compatible extension-host API revision.
    pub maximum_host_api: u32,
    /// Complete exact dependency closure in ascending package-ID order.
    pub dependencies: Vec<RegistryDependencyLock>,
    /// UTC publisher release time.
    pub published_at_ms: i64,
}

/// Minimal monotonic state retained after accepting one registry snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrySnapshotState {
    /// Stable registry identity.
    pub registry_id: String,
    /// Trust-root revision that authorized this snapshot.
    pub root_version: u64,
    /// Accepted monotonic snapshot version.
    pub version: u64,
    /// Digest of the exact signed envelope bytes.
    pub envelope_digest: String,
    /// Accepted snapshot expiry.
    pub expires_at_ms: i64,
}

/// Minimal monotonic state retained after accepting one trust root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryTrustRootState {
    /// Stable registry identity.
    pub registry_id: String,
    /// Accepted monotonic root revision.
    pub root_version: u64,
    /// Digest of exact root JSON payload bytes.
    pub root_digest: String,
    /// Accepted root expiry.
    pub expires_at_ms: i64,
}

/// Strictly inspected out-of-band or dual-threshold-rotated trust root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedRegistryTrustRoot {
    /// Exact parsed trust-root policy.
    pub trust_root: RegistryTrustRoot,
    /// Exact root JSON payload bytes.
    pub root_bytes: Vec<u8>,
    /// SHA-256 digest of the exact root JSON payload bytes.
    pub root_digest: String,
}

impl InspectedRegistryTrustRoot {
    /// Returns the minimal monotonic state used to fence later rotation and snapshots.
    #[must_use]
    pub fn state(&self) -> RegistryTrustRootState {
        RegistryTrustRootState {
            registry_id: self.trust_root.registry_id.clone(),
            root_version: self.trust_root.root_version,
            root_digest: self.root_digest.clone(),
            expires_at_ms: self.trust_root.expires_at_ms,
        }
    }
}

/// Verified snapshot and exact-byte audit identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedRegistrySnapshot {
    /// Strict parsed snapshot.
    pub snapshot: RegistrySnapshot,
    /// Digest of exact decoded signed payload bytes.
    pub payload_digest: String,
    /// Digest of the exact outer envelope bytes.
    pub envelope_digest: String,
    /// Exact verified signed envelope bytes.
    pub envelope_bytes: Vec<u8>,
    /// Monotonic state suitable for the next refresh transaction.
    pub state: RegistrySnapshotState,
}

/// Verified publisher release and exact-byte audit identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedRegistryRelease {
    /// Strict parsed release metadata.
    pub release: RegistryRelease,
    /// Digest of exact decoded signed payload bytes.
    pub payload_digest: String,
    /// Digest of the exact outer envelope bytes.
    pub envelope_digest: String,
    /// Exact verified signed envelope bytes.
    pub envelope_bytes: Vec<u8>,
}

/// Atomic canonical commit of one initial or dual-threshold-rotated trust root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryTrustRootCommit {
    /// Fully inspected root and exact bytes.
    pub inspected: InspectedRegistryTrustRoot,
    /// Exact prior root state, or `None` only for initial out-of-band bootstrap.
    pub expected: Option<RegistryTrustRootState>,
    /// UTC time assigned to the canonical activation.
    pub activated_at_ms: i64,
}

/// Atomic canonical commit of one verified monotonic registry snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrySnapshotCommit {
    /// Fully verified snapshot and exact signed envelope.
    pub inspected: InspectedRegistrySnapshot,
    /// Exact prior snapshot state, or `None` for the first accepted snapshot.
    pub expected: Option<RegistrySnapshotState>,
    /// UTC time assigned to the canonical acceptance.
    pub accepted_at_ms: i64,
}

/// Safe failures from canonical registry metadata persistence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistryMetadataStoreError {
    /// The requested registry has no active trust root.
    #[error("registry trust root was not found")]
    TrustRootNotFound,
    /// Canonical root or snapshot state changed under the caller.
    #[error("registry metadata state conflicts with the expected revision")]
    Conflict,
    /// Persistence dependency failed.
    #[error("registry metadata store is unavailable: {0}")]
    Unavailable(String),
    /// Stored or proposed evidence violates the canonical contract.
    #[error("registry metadata store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Canonical persistence boundary for trust roots and anti-rollback snapshot state.
pub trait RegistryMetadataStore {
    /// Loads the exact active trust root, when configured.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryMetadataStoreError`] for corrupt or unavailable state.
    fn registry_trust_root(
        &self,
        registry_id: &str,
    ) -> Result<Option<InspectedRegistryTrustRoot>, RegistryMetadataStoreError>;

    /// Loads the current accepted snapshot anti-rollback fence.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryMetadataStoreError`] for corrupt or unavailable state.
    fn registry_snapshot_state(
        &self,
        registry_id: &str,
    ) -> Result<Option<RegistrySnapshotState>, RegistryMetadataStoreError>;

    /// Atomically activates one initial or rotated root under an exact prior-state fence.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryMetadataStoreError`] for conflicts, corruption, or persistence failure.
    fn commit_registry_trust_root(
        &mut self,
        commit: RegistryTrustRootCommit,
    ) -> Result<RegistryTrustRootState, RegistryMetadataStoreError>;

    /// Atomically retains exact snapshot evidence and advances its monotonic head.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryMetadataStoreError`] for conflicts, corruption, or persistence failure.
    fn commit_registry_snapshot(
        &mut self,
        commit: RegistrySnapshotCommit,
    ) -> Result<RegistrySnapshotState, RegistryMetadataStoreError>;
}

/// Registry verification or canonical persistence failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistryUseCaseError {
    /// Cryptographic or semantic verification rejected the supplied bytes.
    #[error(transparent)]
    Verification(#[from] RegistryError),
    /// Canonical persistence rejected the transition.
    #[error(transparent)]
    Store(#[from] RegistryMetadataStoreError),
}

/// Inspects one owner-supplied out-of-band trust root without deriving trust from the network.
///
/// The caller must acquire these exact bytes through an authenticated out-of-band path and retain
/// the returned digest in the stopped-home configuration transaction.
///
/// # Errors
///
/// Returns [`RegistryError`] for malformed, duplicate-key, expired, unordered, or oversized root
/// bytes.
pub fn inspect_initial_registry_trust_root(
    root_bytes: &[u8],
    now_ms: i64,
) -> Result<InspectedRegistryTrustRoot, RegistryError> {
    if root_bytes.is_empty() || root_bytes.len() > MAXIMUM_ROOT_PAYLOAD_BYTES {
        return Err(RegistryError::InvalidTrustRoot);
    }
    reject_duplicate_json_keys(root_bytes).map_err(|()| RegistryError::InvalidTrustRoot)?;
    let trust_root = serde_json::from_slice::<RegistryTrustRoot>(root_bytes)
        .map_err(|_| RegistryError::InvalidTrustRoot)?;
    validate_trust_root(&trust_root, now_ms)?;
    Ok(InspectedRegistryTrustRoot {
        trust_root,
        root_bytes: root_bytes.to_vec(),
        root_digest: sha256_digest(root_bytes),
    })
}

/// Verifies an exact next-version trust root under both current and candidate thresholds.
///
/// A rotation envelope is signed once over exact candidate-root JSON bytes. Its sorted signature
/// set must satisfy the current root threshold and the candidate root threshold independently.
/// This prevents either a compromised old threshold or an unproven new key set from rotating
/// alone.
///
/// # Errors
///
/// Returns [`RegistryError`] for an invalid current/candidate root, non-consecutive version,
/// registry substitution, envelope ambiguity, or failure of either signature threshold.
pub fn inspect_registry_root_rotation(
    envelope_bytes: &[u8],
    current_root: &RegistryTrustRoot,
    now_ms: i64,
) -> Result<InspectedRegistryTrustRoot, RegistryError> {
    validate_trust_root(current_root, now_ms)?;
    let payload = verify_signed_envelope(
        envelope_bytes,
        ROOT_ENVELOPE_POLICY,
        &current_root.keys,
        current_root.threshold,
    )?;
    reject_duplicate_json_keys(&payload).map_err(|()| RegistryError::InvalidRootRotation)?;
    let candidate = serde_json::from_slice::<RegistryTrustRoot>(&payload)
        .map_err(|_| RegistryError::InvalidRootRotation)?;
    validate_trust_root(&candidate, now_ms)?;
    if candidate.registry_id != current_root.registry_id
        || current_root.root_version.checked_add(1) != Some(candidate.root_version)
    {
        return Err(RegistryError::InvalidRootRotation);
    }
    let candidate_payload = verify_signed_envelope(
        envelope_bytes,
        ROOT_ENVELOPE_POLICY,
        &candidate.keys,
        candidate.threshold,
    )?;
    if candidate_payload != payload {
        return Err(RegistryError::InvalidRootRotation);
    }
    Ok(InspectedRegistryTrustRoot {
        trust_root: candidate,
        root_bytes: payload.clone(),
        root_digest: sha256_digest(&payload),
    })
}

/// Installs one first root obtained through the owner's out-of-band trust path.
///
/// # Errors
///
/// Returns [`RegistryUseCaseError`] when inspection or the atomic initial-state fence fails.
pub fn bootstrap_registry_trust_root(
    store: &mut impl RegistryMetadataStore,
    root_bytes: &[u8],
    now_ms: i64,
) -> Result<RegistryTrustRootState, RegistryUseCaseError> {
    let inspected = inspect_initial_registry_trust_root(root_bytes, now_ms)?;
    store
        .commit_registry_trust_root(RegistryTrustRootCommit {
            inspected,
            expected: None,
            activated_at_ms: now_ms,
        })
        .map_err(Into::into)
}

/// Rotates one configured root through an exact old-and-new-threshold envelope.
///
/// # Errors
///
/// Returns [`RegistryUseCaseError`] when the registry is absent, verification fails, or the
/// canonical root changes under the operation.
pub fn rotate_registry_trust_root(
    store: &mut impl RegistryMetadataStore,
    registry_id: &str,
    rotation_envelope_bytes: &[u8],
    now_ms: i64,
) -> Result<RegistryTrustRootState, RegistryUseCaseError> {
    if !valid_identifier(registry_id) {
        return Err(RegistryError::InvalidTrustRoot.into());
    }
    let current = store
        .registry_trust_root(registry_id)?
        .ok_or(RegistryMetadataStoreError::TrustRootNotFound)?;
    let candidate_payload = verify_signed_envelope(
        rotation_envelope_bytes,
        ROOT_ENVELOPE_POLICY,
        &current.trust_root.keys,
        current.trust_root.threshold,
    )?;
    if candidate_payload == current.root_bytes {
        return Ok(current.state());
    }
    let expected = current.state();
    let inspected =
        inspect_registry_root_rotation(rotation_envelope_bytes, &current.trust_root, now_ms)?;
    store
        .commit_registry_trust_root(RegistryTrustRootCommit {
            inspected,
            expected: Some(expected),
            activated_at_ms: now_ms,
        })
        .map_err(Into::into)
}

/// Verifies and atomically accepts one registry snapshot against durable anti-rollback state.
///
/// # Errors
///
/// Returns [`RegistryUseCaseError`] when the registry is absent, verification fails, or the
/// snapshot head changes under the operation.
pub fn accept_registry_snapshot(
    store: &mut impl RegistryMetadataStore,
    registry_id: &str,
    envelope_bytes: &[u8],
    now_ms: i64,
) -> Result<RegistrySnapshotState, RegistryUseCaseError> {
    if !valid_identifier(registry_id) {
        return Err(RegistryError::InvalidSnapshot.into());
    }
    let root = store
        .registry_trust_root(registry_id)?
        .ok_or(RegistryMetadataStoreError::TrustRootNotFound)?;
    let previous = store.registry_snapshot_state(registry_id)?;
    let inspected =
        inspect_registry_snapshot(envelope_bytes, &root.trust_root, previous.as_ref(), now_ms)?;
    store
        .commit_registry_snapshot(RegistrySnapshotCommit {
            inspected,
            expected: previous,
            accepted_at_ms: now_ms,
        })
        .map_err(Into::into)
}

/// Verifies a threshold-signed registry snapshot as inert data.
///
/// The locally configured root is the only initial trust source. An exact same-version envelope is
/// idempotent; a lower version or different bytes at an accepted version fails closed.
///
/// # Errors
///
/// Returns [`RegistryError`] for invalid roots, envelopes, signatures, expiry, rollback,
/// equivocation, bounds, ordering, or target metadata.
pub fn inspect_registry_snapshot(
    envelope_bytes: &[u8],
    trust_root: &RegistryTrustRoot,
    previous: Option<&RegistrySnapshotState>,
    now_ms: i64,
) -> Result<InspectedRegistrySnapshot, RegistryError> {
    validate_trust_root(trust_root, now_ms)?;
    let payload = verify_signed_envelope(
        envelope_bytes,
        SNAPSHOT_ENVELOPE_POLICY,
        &trust_root.keys,
        trust_root.threshold,
    )?;
    reject_duplicate_json_keys(&payload).map_err(|()| RegistryError::InvalidSnapshot)?;
    let snapshot = serde_json::from_slice::<RegistrySnapshot>(&payload)
        .map_err(|_| RegistryError::InvalidSnapshot)?;
    validate_snapshot(&snapshot, trust_root, now_ms)?;
    let envelope_digest = sha256_digest(envelope_bytes);
    if let Some(previous) = previous {
        if previous.registry_id != snapshot.registry_id
            || previous.root_version == 0
            || !is_sha256_digest(&previous.envelope_digest)
            || previous.version == 0
            || previous.expires_at_ms <= 0
        {
            return Err(RegistryError::InvalidSnapshot);
        }
        if trust_root.root_version < previous.root_version
            || (trust_root.root_version != previous.root_version
                && snapshot.version <= previous.version)
        {
            return Err(RegistryError::Rollback);
        }
        if snapshot.version < previous.version {
            return Err(RegistryError::Rollback);
        }
        if snapshot.version == previous.version && envelope_digest != previous.envelope_digest {
            return Err(RegistryError::Equivocation);
        }
    }
    Ok(InspectedRegistrySnapshot {
        payload_digest: sha256_digest(&payload),
        state: RegistrySnapshotState {
            registry_id: snapshot.registry_id.clone(),
            root_version: trust_root.root_version,
            version: snapshot.version,
            envelope_digest: envelope_digest.clone(),
            expires_at_ms: snapshot.expires_at_ms,
        },
        snapshot,
        envelope_digest,
        envelope_bytes: envelope_bytes.to_vec(),
    })
}

/// Verifies one publisher-signed release selected by an already verified snapshot.
///
/// This function verifies only inert metadata. It does not fetch package bytes, inspect an
/// extension/skill manifest, install files, stage a revision, or grant authority.
///
/// # Errors
///
/// Returns [`RegistryError`] for descriptor drift, withdrawal, missing publisher authority,
/// invalid signatures/metadata/dependency locks, or host incompatibility.
pub fn inspect_registry_release(
    envelope_bytes: &[u8],
    inspected_snapshot: &InspectedRegistrySnapshot,
    target: &RegistryTarget,
    host_api_version: u32,
) -> Result<InspectedRegistryRelease, RegistryError> {
    if inspected_snapshot
        .snapshot
        .target(&target.package_id, &target.version)
        != Some(target)
    {
        return Err(RegistryError::InvalidRelease);
    }
    target.release_envelope.validate(
        REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE,
        u64::try_from(MAXIMUM_RELEASE_ENVELOPE_BYTES).unwrap_or(u64::MAX),
    )?;
    target.release_envelope.verify_bytes(envelope_bytes)?;
    if target.withdrawal.is_some() {
        return Err(RegistryError::Withdrawn);
    }
    let publisher = inspected_snapshot
        .snapshot
        .publishers
        .iter()
        .find(|publisher| publisher.publisher_id == target.publisher_id)
        .ok_or(RegistryError::UnknownPublisher)?;
    let payload = verify_signed_envelope(
        envelope_bytes,
        RELEASE_ENVELOPE_POLICY,
        &publisher.keys,
        publisher.threshold,
    )?;
    reject_duplicate_json_keys(&payload).map_err(|()| RegistryError::InvalidRelease)?;
    let release = serde_json::from_slice::<RegistryRelease>(&payload)
        .map_err(|_| RegistryError::InvalidRelease)?;
    validate_release(
        &release,
        &inspected_snapshot.snapshot,
        target,
        host_api_version,
    )?;
    Ok(InspectedRegistryRelease {
        release,
        payload_digest: sha256_digest(&payload),
        envelope_digest: sha256_digest(envelope_bytes),
        envelope_bytes: envelope_bytes.to_vec(),
    })
}

/// Exact change to one logical extension filesystem permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionFilesystemPermissionChange {
    /// Stable logical mount name.
    pub name: String,
    /// Prior requested access, if any.
    pub before: Option<ExtensionFilesystemAccess>,
    /// Candidate requested access, if any.
    pub after: Option<ExtensionFilesystemAccess>,
}

/// Exact semantic change to one extension capability contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionCapabilityChange {
    /// Stable capability ID.
    pub capability_id: String,
    /// Digest of the prior complete capability contract.
    pub before_digest: String,
    /// Digest of the candidate complete capability contract.
    pub after_digest: String,
    /// Prior external-effect classification.
    pub before_effect_class: EffectClass,
    /// Candidate external-effect classification.
    pub after_effect_class: EffectClass,
    /// Prior risk classification.
    pub before_risk_class: RiskClass,
    /// Candidate risk classification.
    pub after_risk_class: RiskClass,
}

/// Complete review surface between an installed and candidate extension manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionPermissionDiff {
    /// Newly advertised capability IDs.
    pub added_capabilities: Vec<String>,
    /// Removed capability IDs.
    pub removed_capabilities: Vec<String>,
    /// Existing capabilities whose complete contracts changed.
    pub changed_capabilities: Vec<ExtensionCapabilityChange>,
    /// Added, removed, or access-changed logical filesystem requests.
    pub filesystem: Vec<ExtensionFilesystemPermissionChange>,
    /// Newly requested exact network destinations.
    pub added_network_destinations: Vec<String>,
    /// Removed exact network destinations.
    pub removed_network_destinations: Vec<String>,
    /// Newly requested opaque secret references.
    pub added_secret_references: Vec<String>,
    /// Removed opaque secret references.
    pub removed_secret_references: Vec<String>,
    /// Prior process-spawn request.
    pub process_spawn_before: bool,
    /// Candidate process-spawn request.
    pub process_spawn_after: bool,
}

impl ExtensionPermissionDiff {
    /// Returns whether any reviewed authority/capability surface changed.
    #[must_use]
    pub fn requires_fresh_approval(&self) -> bool {
        !self.added_capabilities.is_empty()
            || !self.removed_capabilities.is_empty()
            || !self.changed_capabilities.is_empty()
            || !self.filesystem.is_empty()
            || !self.added_network_destinations.is_empty()
            || !self.removed_network_destinations.is_empty()
            || !self.added_secret_references.is_empty()
            || !self.removed_secret_references.is_empty()
            || self.process_spawn_before != self.process_spawn_after
    }

    /// Returns whether the candidate might widen executable authority.
    ///
    /// Any changed capability is conservatively treated as widening until the owner reviews it.
    #[must_use]
    pub fn widens_authority(&self) -> bool {
        !self.added_capabilities.is_empty()
            || !self.changed_capabilities.is_empty()
            || self.filesystem.iter().any(|change| {
                matches!(
                    (change.before, change.after),
                    (None, Some(_))
                        | (
                            Some(ExtensionFilesystemAccess::ReadOnly),
                            Some(ExtensionFilesystemAccess::ReadWrite),
                        )
                )
            })
            || !self.added_network_destinations.is_empty()
            || !self.added_secret_references.is_empty()
            || !self.process_spawn_before && self.process_spawn_after
    }
}

/// Computes a deterministic complete permission/capability diff without executing either package.
///
/// # Errors
///
/// Returns [`RegistryError::InvalidPermissionDiff`] when either manifest is invalid, package
/// identity changes, or a complete capability contract cannot be serialized for exact comparison.
#[allow(clippy::too_many_lines)] // Keep every authority axis in one auditable symmetric comparison.
pub fn diff_extension_permissions(
    before: &ExtensionManifest,
    after: &ExtensionManifest,
) -> Result<ExtensionPermissionDiff, RegistryError> {
    before
        .validate()
        .map_err(|_| RegistryError::InvalidPermissionDiff)?;
    after
        .validate()
        .map_err(|_| RegistryError::InvalidPermissionDiff)?;
    if before.extension_id != after.extension_id
        || before.name != after.name
        || before.publisher != after.publisher
    {
        return Err(RegistryError::InvalidPermissionDiff);
    }
    let before_capabilities = before
        .capabilities
        .iter()
        .map(|capability| (capability.capability_id.as_str(), capability))
        .collect::<BTreeMap<_, _>>();
    let after_capabilities = after
        .capabilities
        .iter()
        .map(|capability| (capability.capability_id.as_str(), capability))
        .collect::<BTreeMap<_, _>>();
    let added_capabilities = after_capabilities
        .keys()
        .filter(|id| !before_capabilities.contains_key(**id))
        .map(|id| (*id).to_owned())
        .collect();
    let removed_capabilities = before_capabilities
        .keys()
        .filter(|id| !after_capabilities.contains_key(**id))
        .map(|id| (*id).to_owned())
        .collect();
    let mut changed_capabilities = Vec::new();
    for (id, before_capability) in &before_capabilities {
        if let Some(after_capability) = after_capabilities.get(id) {
            let before_bytes = serde_json::to_vec(before_capability)
                .map_err(|_| RegistryError::InvalidPermissionDiff)?;
            let after_bytes = serde_json::to_vec(after_capability)
                .map_err(|_| RegistryError::InvalidPermissionDiff)?;
            let before_digest = sha256_digest(&before_bytes);
            let after_digest = sha256_digest(&after_bytes);
            if before_digest != after_digest {
                changed_capabilities.push(ExtensionCapabilityChange {
                    capability_id: (*id).to_owned(),
                    before_digest,
                    after_digest,
                    before_effect_class: before_capability.effect_class,
                    after_effect_class: after_capability.effect_class,
                    before_risk_class: before_capability.risk_class,
                    after_risk_class: after_capability.risk_class,
                });
            }
        }
    }
    let before_filesystem = before
        .permissions
        .filesystem
        .iter()
        .map(|permission| (permission.name.as_str(), permission.access))
        .collect::<BTreeMap<_, _>>();
    let after_filesystem = after
        .permissions
        .filesystem
        .iter()
        .map(|permission| (permission.name.as_str(), permission.access))
        .collect::<BTreeMap<_, _>>();
    let filesystem_names = before_filesystem
        .keys()
        .chain(after_filesystem.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let filesystem = filesystem_names
        .into_iter()
        .filter_map(|name| {
            let before = before_filesystem.get(name).copied();
            let after = after_filesystem.get(name).copied();
            (before != after).then(|| ExtensionFilesystemPermissionChange {
                name: name.to_owned(),
                before,
                after,
            })
        })
        .collect();
    let before_network = before
        .permissions
        .network_destinations
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let after_network = after
        .permissions
        .network_destinations
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let before_secrets = before
        .permissions
        .secret_references
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let after_secrets = after
        .permissions
        .secret_references
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    Ok(ExtensionPermissionDiff {
        added_capabilities,
        removed_capabilities,
        changed_capabilities,
        filesystem,
        added_network_destinations: string_difference(&after_network, &before_network),
        removed_network_destinations: string_difference(&before_network, &after_network),
        added_secret_references: string_difference(&after_secrets, &before_secrets),
        removed_secret_references: string_difference(&before_secrets, &after_secrets),
        process_spawn_before: before.permissions.allow_process_spawn,
        process_spawn_after: after.permissions.allow_process_spawn,
    })
}

/// Review surface between installed and candidate data-only skill tool references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillPermissionDiff {
    /// Newly referenced separately governed tool contracts.
    pub added_required_tools: Vec<SkillToolRequirement>,
    /// No-longer-referenced separately governed tool contracts.
    pub removed_required_tools: Vec<SkillToolRequirement>,
}

impl SkillPermissionDiff {
    /// Returns whether owner review must acknowledge a changed tool reference set.
    #[must_use]
    pub fn requires_fresh_approval(&self) -> bool {
        !self.added_required_tools.is_empty() || !self.removed_required_tools.is_empty()
    }

    /// Returns whether the candidate references any additional governed tool.
    #[must_use]
    pub fn widens_authority(&self) -> bool {
        !self.added_required_tools.is_empty()
    }
}

/// Computes the exact governed-tool reference diff for a data-only skill update.
///
/// # Errors
///
/// Returns [`RegistryError::InvalidPermissionDiff`] when either skill manifest is invalid or the
/// candidate changes the stable skill identity.
pub fn diff_skill_permissions(
    before: &SkillManifest,
    after: &SkillManifest,
) -> Result<SkillPermissionDiff, RegistryError> {
    before
        .validate()
        .map_err(|_| RegistryError::InvalidPermissionDiff)?;
    after
        .validate()
        .map_err(|_| RegistryError::InvalidPermissionDiff)?;
    if before.skill_id != after.skill_id {
        return Err(RegistryError::InvalidPermissionDiff);
    }
    Ok(SkillPermissionDiff {
        added_required_tools: after
            .required_tools
            .difference(&before.required_tools)
            .cloned()
            .collect(),
        removed_required_tools: before
            .required_tools
            .difference(&after.required_tools)
            .cloned()
            .collect(),
    })
}

fn string_difference(left: &BTreeSet<&str>, right: &BTreeSet<&str>) -> Vec<String> {
    left.difference(right)
        .map(|value| (*value).to_owned())
        .collect()
}

fn validate_trust_root(root: &RegistryTrustRoot, now_ms: i64) -> Result<(), RegistryError> {
    if now_ms < 0
        || !valid_identifier(&root.registry_id)
        || root.root_version == 0
        || root.expires_at_ms <= now_ms
        || !valid_key_set(&root.keys, root.threshold)
    {
        return Err(RegistryError::InvalidTrustRoot);
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &RegistrySnapshot,
    root: &RegistryTrustRoot,
    now_ms: i64,
) -> Result<(), RegistryError> {
    if snapshot.contract_version != REGISTRY_SNAPSHOT_CONTRACT_VERSION
        || snapshot.registry_id != root.registry_id
        || snapshot.version == 0
        || snapshot.generated_at_ms < 0
        || snapshot.generated_at_ms > now_ms.saturating_add(MAXIMUM_CLOCK_SKEW_MS)
        || snapshot.expires_at_ms <= now_ms
        || snapshot.expires_at_ms <= snapshot.generated_at_ms
        || snapshot
            .expires_at_ms
            .saturating_sub(snapshot.generated_at_ms)
            > MAXIMUM_SNAPSHOT_LIFETIME_MS
        || snapshot.publishers.is_empty()
        || snapshot.publishers.len() > MAXIMUM_PUBLISHERS
        || snapshot.targets.len() > MAXIMUM_TARGETS
    {
        return Err(if snapshot.expires_at_ms <= now_ms {
            RegistryError::Expired
        } else {
            RegistryError::InvalidSnapshot
        });
    }
    let mut publisher_ids = BTreeSet::new();
    for publisher in &snapshot.publishers {
        if !valid_identifier(&publisher.publisher_id)
            || !publisher_ids.insert(publisher.publisher_id.as_str())
            || !valid_key_set(&publisher.keys, publisher.threshold)
        {
            return Err(RegistryError::InvalidSnapshot);
        }
    }
    if !snapshot
        .publishers
        .windows(2)
        .all(|pair| pair[0].publisher_id < pair[1].publisher_id)
    {
        return Err(RegistryError::InvalidSnapshot);
    }
    let mut target_keys = BTreeSet::new();
    for target in &snapshot.targets {
        if !valid_identifier(&target.package_id)
            || !valid_version(&target.version)
            || !publisher_ids.contains(target.publisher_id.as_str())
            || !target_keys.insert((target.package_id.as_str(), target.version.as_str()))
        {
            return Err(RegistryError::InvalidSnapshot);
        }
        target.release_envelope.validate(
            REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE,
            u64::try_from(MAXIMUM_RELEASE_ENVELOPE_BYTES).unwrap_or(u64::MAX),
        )?;
        if let Some(withdrawal) = &target.withdrawal
            && (withdrawal.withdrawn_at_ms < 0
                || withdrawal.withdrawn_at_ms > snapshot.generated_at_ms
                || !valid_text(&withdrawal.reason, 1_024))
        {
            return Err(RegistryError::InvalidSnapshot);
        }
    }
    if !snapshot.targets.windows(2).all(|pair| {
        (&pair[0].package_id, &pair[0].version) < (&pair[1].package_id, &pair[1].version)
    }) {
        return Err(RegistryError::InvalidSnapshot);
    }
    Ok(())
}

fn validate_release(
    release: &RegistryRelease,
    snapshot: &RegistrySnapshot,
    target: &RegistryTarget,
    host_api_version: u32,
) -> Result<(), RegistryError> {
    if release.contract_version != REGISTRY_RELEASE_CONTRACT_VERSION
        || release.registry_id != snapshot.registry_id
        || release.package_id != target.package_id
        || release.kind != target.kind
        || release.publisher_id != target.publisher_id
        || release.version != target.version
        || !valid_identifier(&release.package_id)
        || !valid_identifier(&release.publisher_id)
        || !valid_version(&release.version)
        || release.minimum_host_api == 0
        || release.minimum_host_api > release.maximum_host_api
        || release.dependencies.len() > MAXIMUM_DEPENDENCIES
        || release.published_at_ms < 0
        || release.published_at_ms
            > snapshot
                .generated_at_ms
                .saturating_add(MAXIMUM_CLOCK_SKEW_MS)
    {
        return Err(RegistryError::InvalidRelease);
    }
    if !(release.minimum_host_api..=release.maximum_host_api).contains(&host_api_version) {
        return Err(RegistryError::Incompatible);
    }
    release
        .manifest
        .validate(release.kind.manifest_media_type(), MAXIMUM_MANIFEST_BYTES)?;
    release
        .package
        .validate(release.kind.package_media_type(), MAXIMUM_PACKAGE_BYTES)?;
    let mut dependency_ids = BTreeSet::new();
    for dependency in &release.dependencies {
        if !valid_identifier(&dependency.package_id)
            || dependency.package_id == release.package_id
            || !valid_version(&dependency.version)
            || !is_sha256_digest(&dependency.release_envelope_digest)
            || !dependency_ids.insert(dependency.package_id.as_str())
        {
            return Err(RegistryError::InvalidRelease);
        }
        let Some(dependency_target) = snapshot.target(&dependency.package_id, &dependency.version)
        else {
            return Err(RegistryError::InvalidRelease);
        };
        if dependency_target.kind != dependency.kind
            || dependency_target.release_envelope.sha256_digest
                != dependency.release_envelope_digest
            || dependency_target.withdrawal.is_some()
        {
            return Err(RegistryError::InvalidRelease);
        }
    }
    if !release
        .dependencies
        .windows(2)
        .all(|pair| pair[0].package_id < pair[1].package_id)
    {
        return Err(RegistryError::InvalidRelease);
    }
    Ok(())
}

fn verify_signed_envelope(
    envelope_bytes: &[u8],
    policy: SignedEnvelopePolicy,
    keys: &[RegistryPublicKey],
    threshold: u16,
) -> Result<Vec<u8>, RegistryError> {
    if envelope_bytes.is_empty() || envelope_bytes.len() > policy.maximum_envelope_bytes {
        return Err(RegistryError::EnvelopeTooLarge);
    }
    reject_duplicate_json_keys(envelope_bytes).map_err(|()| RegistryError::InvalidEnvelope)?;
    let envelope = serde_json::from_slice::<RegistrySignedEnvelope>(envelope_bytes)
        .map_err(|_| RegistryError::InvalidEnvelope)?;
    if envelope.payload_type != policy.payload_type
        || envelope.signatures.is_empty()
        || envelope.signatures.len() > policy.maximum_signatures
        || !envelope
            .signatures
            .windows(2)
            .all(|pair| pair[0].key_id < pair[1].key_id)
    {
        return Err(RegistryError::InvalidEnvelope);
    }
    let payload = decode_canonical_base64url(&envelope.payload_base64url)
        .ok_or(RegistryError::InvalidEnvelope)?;
    if payload.is_empty() || payload.len() > policy.maximum_payload_bytes {
        return Err(RegistryError::InvalidEnvelope);
    }
    let key_map = verifying_keys(keys)?;
    let mut material = Vec::with_capacity(policy.signature_context.len() + 1 + payload.len());
    material.extend_from_slice(policy.signature_context.as_bytes());
    material.push(0);
    material.extend_from_slice(&payload);
    let mut verified = 0_u16;
    for signed in &envelope.signatures {
        if !valid_key_id(&signed.key_id) {
            return Err(RegistryError::InvalidEnvelope);
        }
        let Some(key) = key_map.get(signed.key_id.as_str()) else {
            continue;
        };
        let signature_bytes = decode_canonical_array::<64>(&signed.signature_base64url)
            .ok_or(RegistryError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        if key.verify_strict(&material, &signature).is_ok() {
            verified = verified.saturating_add(1);
        }
    }
    if verified < threshold {
        return Err(RegistryError::ThresholdNotMet);
    }
    Ok(payload)
}

fn valid_key_set(keys: &[RegistryPublicKey], threshold: u16) -> bool {
    if keys.is_empty()
        || keys.len() > MAXIMUM_KEYS
        || threshold == 0
        || usize::from(threshold) > keys.len()
        || !keys.windows(2).all(|pair| pair[0].key_id < pair[1].key_id)
    {
        return false;
    }
    verifying_keys(keys).is_ok()
}

fn verifying_keys(
    keys: &[RegistryPublicKey],
) -> Result<BTreeMap<&str, VerifyingKey>, RegistryError> {
    let mut verified = BTreeMap::new();
    for key in keys {
        if key.algorithm != RegistrySignatureAlgorithm::Ed25519 || !valid_key_id(&key.key_id) {
            return Err(RegistryError::InvalidTrustRoot);
        }
        let key_id = key.key_id.as_str();
        let bytes = decode_canonical_array::<32>(&key.public_key_base64url)
            .ok_or(RegistryError::InvalidTrustRoot)?;
        if sha256_digest(&bytes) != key_id {
            return Err(RegistryError::InvalidTrustRoot);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| RegistryError::InvalidTrustRoot)?;
        if verified.insert(key_id, verifying_key).is_some() {
            return Err(RegistryError::InvalidTrustRoot);
        }
    }
    Ok(verified)
}

fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<(), ()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    UniqueJsonSeed
        .deserialize(&mut deserializer)
        .map_err(|_| ())?;
    deserializer.end().map_err(|_| ())
}

struct UniqueJsonSeed;

impl<'de> DeserializeSeed<'de> for UniqueJsonSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(UniqueJsonSeed)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            object.next_value_seed(UniqueJsonSeed)?;
        }
        Ok(())
    }
}

fn decode_canonical_base64url(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.contains('=') {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    (URL_SAFE_NO_PAD.encode(&decoded) == value).then_some(decoded)
}

fn decode_canonical_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    let decoded = decode_canonical_base64url(value)?;
    decoded.try_into().ok()
}

fn valid_key_id(value: &str) -> bool {
    is_sha256_digest(value)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Safe registry inspection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    /// The out-of-band root is malformed, expired, or internally inconsistent.
    #[error("registry trust root is invalid or expired")]
    InvalidTrustRoot,
    /// A network-delivered root did not prove an exact next version under old and new thresholds.
    #[error("registry trust-root rotation is invalid")]
    InvalidRootRotation,
    /// The supplied signed envelope exceeds its hard byte ceiling.
    #[error("registry signed envelope exceeds its byte ceiling")]
    EnvelopeTooLarge,
    /// The strict envelope, payload type, encoding, ordering, or payload bounds are invalid.
    #[error("registry signed envelope is invalid")]
    InvalidEnvelope,
    /// A selected signature is malformed or fails strict verification.
    #[error("registry signature is invalid")]
    InvalidSignature,
    /// Fewer distinct trusted signatures verified than the configured threshold.
    #[error("registry signature threshold was not met")]
    ThresholdNotMet,
    /// Registry snapshot fields, ordering, bounds, publisher, or target metadata are invalid.
    #[error("registry snapshot is invalid")]
    InvalidSnapshot,
    /// Trusted root or snapshot expiry does not permit continued use.
    #[error("registry metadata is expired")]
    Expired,
    /// A lower snapshot version attempted to replace accepted state.
    #[error("registry snapshot rollback was rejected")]
    Rollback,
    /// Different bytes attempted to reuse an accepted snapshot version.
    #[error("registry snapshot equivocation was rejected")]
    Equivocation,
    /// Content media type, size, or digest is malformed or does not match the bytes.
    #[error("registry content descriptor is invalid")]
    InvalidDescriptor,
    /// Target publisher is absent from the verified snapshot.
    #[error("registry target publisher is not trusted by this snapshot")]
    UnknownPublisher,
    /// Registry metadata withdrew this immutable release.
    #[error("registry release is withdrawn")]
    Withdrawn,
    /// Publisher release identity, compatibility, descriptor, or dependency locks are invalid.
    #[error("registry release metadata is invalid")]
    InvalidRelease,
    /// This Mealy extension-host API is outside the release compatibility range.
    #[error("registry release is incompatible with this Mealy host")]
    Incompatible,
    /// Candidate manifests are invalid, change package identity, or cannot be diffed exactly.
    #[error("registry package permission diff is invalid")]
    InvalidPermissionDiff,
}

#[cfg(test)]
mod tests {
    use super::{
        REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE, REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE,
        REGISTRY_RELEASE_CONTRACT_VERSION, REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE,
        REGISTRY_RELEASE_PAYLOAD_TYPE, REGISTRY_ROOT_PAYLOAD_TYPE,
        REGISTRY_SKILL_MANIFEST_MEDIA_TYPE, REGISTRY_SKILL_PACKAGE_MEDIA_TYPE,
        REGISTRY_SNAPSHOT_CONTRACT_VERSION, REGISTRY_SNAPSHOT_ENVELOPE_MEDIA_TYPE,
        REGISTRY_SNAPSHOT_PAYLOAD_TYPE, RELEASE_SIGNATURE_CONTEXT, ROOT_SIGNATURE_CONTEXT,
        RegistryContentDescriptor, RegistryError, RegistryMirror, RegistryMirrorError,
        RegistryMirrorRequest, RegistryMirrorResponse, RegistryMirrorTransport,
        RegistryMirrorTransportError, RegistryPackageKind, RegistryPublicKey, RegistryPublisher,
        RegistryRelease, RegistrySignature, RegistrySignatureAlgorithm, RegistrySignedEnvelope,
        RegistrySnapshot, RegistrySnapshotState, RegistryTarget, RegistryTrustRoot,
        RegistryWithdrawal, SNAPSHOT_SIGNATURE_CONTEXT, diff_extension_permissions,
        diff_skill_permissions, fetch_registry_content, fetch_registry_snapshot_envelope,
        inspect_initial_registry_trust_root, inspect_registry_release,
        inspect_registry_root_rotation, inspect_registry_snapshot,
    };
    use crate::sha256_digest;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer as _, SigningKey};
    use mealy_domain::{
        EXTENSION_MANIFEST_SCHEMA_VERSION, EffectClass, ExtensionCapabilityKind,
        ExtensionCapabilityManifest, ExtensionCompatibility, ExtensionEntryPoint,
        ExtensionFieldSchema, ExtensionFilesystemAccess, ExtensionFilesystemPermission,
        ExtensionHealthCheck, ExtensionId, ExtensionKind, ExtensionManifest, ExtensionObjectSchema,
        ExtensionPermissions, ExtensionScalarType, ExtensionShutdownBehavior,
        ExtensionShutdownMode, RiskClass, SKILL_MANIFEST_CONTRACT_VERSION, SkillAsset,
        SkillManifest, SkillToolRequirement,
    };
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet},
    };

    const NOW_MS: i64 = 10_000;

    struct Fixture {
        registry_key: SigningKey,
        publisher_key: SigningKey,
        root: RegistryTrustRoot,
        snapshot: RegistrySnapshot,
        snapshot_envelope: Vec<u8>,
        release_envelope: Vec<u8>,
    }

    struct FixtureMirrorTransport {
        response: Result<RegistryMirrorResponse, RegistryMirrorTransportError>,
        requests: RefCell<Vec<RegistryMirrorRequest>>,
    }

    impl RegistryMirrorTransport for FixtureMirrorTransport {
        fn fetch(
            &self,
            request: &RegistryMirrorRequest,
        ) -> Result<RegistryMirrorResponse, RegistryMirrorTransportError> {
            self.requests.borrow_mut().push(request.clone());
            self.response.clone()
        }
    }

    fn fixture() -> Fixture {
        let registry_key = SigningKey::from_bytes(&[7; 32]);
        let publisher_key = SigningKey::from_bytes(&[9; 32]);
        let release = RegistryRelease {
            contract_version: REGISTRY_RELEASE_CONTRACT_VERSION.to_owned(),
            registry_id: "dev.mealy.registry".to_owned(),
            package_id: "dev.mealy.fixture".to_owned(),
            kind: RegistryPackageKind::Extension,
            publisher_id: "dev.mealy".to_owned(),
            version: "1.0.0".to_owned(),
            manifest: descriptor(
                REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE,
                b"extension manifest",
            ),
            package: descriptor(REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE, b"extension package"),
            minimum_host_api: 1,
            maximum_host_api: 1,
            dependencies: Vec::new(),
            published_at_ms: NOW_MS - 1_000,
        };
        let release_envelope = signed_envelope(
            REGISTRY_RELEASE_PAYLOAD_TYPE,
            RELEASE_SIGNATURE_CONTEXT,
            &release,
            &[&publisher_key],
        );
        let target = RegistryTarget {
            package_id: release.package_id.clone(),
            kind: release.kind,
            version: release.version.clone(),
            publisher_id: release.publisher_id.clone(),
            release_envelope: descriptor(REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE, &release_envelope),
            withdrawal: None,
        };
        let snapshot = RegistrySnapshot {
            contract_version: REGISTRY_SNAPSHOT_CONTRACT_VERSION.to_owned(),
            registry_id: release.registry_id,
            version: 1,
            generated_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 60_000,
            publishers: vec![publisher(&publisher_key)],
            targets: vec![target],
        };
        let snapshot_envelope = signed_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_SIGNATURE_CONTEXT,
            &snapshot,
            &[&registry_key],
        );
        let root = RegistryTrustRoot {
            registry_id: snapshot.registry_id.clone(),
            root_version: 1,
            keys: vec![public_key(&registry_key)],
            threshold: 1,
            expires_at_ms: NOW_MS + 120_000,
        };
        Fixture {
            registry_key,
            publisher_key,
            root,
            snapshot,
            snapshot_envelope,
            release_envelope,
        }
    }

    #[test]
    fn threshold_snapshot_and_publisher_release_verify_as_inert_exact_bytes() {
        let fixture = fixture();
        let snapshot =
            inspect_registry_snapshot(&fixture.snapshot_envelope, &fixture.root, None, NOW_MS)
                .expect("verified snapshot");
        assert_eq!(snapshot.snapshot, fixture.snapshot);
        assert_eq!(
            snapshot.envelope_digest,
            sha256_digest(&fixture.snapshot_envelope)
        );
        let release = inspect_registry_release(
            &fixture.release_envelope,
            &snapshot,
            &snapshot.snapshot.targets[0],
            1,
        )
        .expect("verified release");
        assert_eq!(release.release.package_id, "dev.mealy.fixture");
        assert_eq!(
            release.envelope_digest,
            sha256_digest(&fixture.release_envelope)
        );

        let mut forged_target = snapshot.snapshot.targets[0].clone();
        forged_target.release_envelope.sha256_digest = "f".repeat(64);
        assert_eq!(
            inspect_registry_release(&fixture.release_envelope, &snapshot, &forged_target, 1),
            Err(RegistryError::InvalidRelease)
        );
    }

    #[test]
    fn mirror_requests_are_https_fixed_layout_bounded_and_content_authenticated() {
        let fixture = fixture();
        let mirror = RegistryMirror {
            registry_id: fixture.root.registry_id.clone(),
            base_url: "https://registry.example.test/mealy/v1/".to_owned(),
        };
        let snapshot_transport = FixtureMirrorTransport {
            response: Ok(RegistryMirrorResponse {
                media_type: REGISTRY_SNAPSHOT_ENVELOPE_MEDIA_TYPE.to_owned(),
                bytes: fixture.snapshot_envelope.clone(),
            }),
            requests: RefCell::new(Vec::new()),
        };
        assert_eq!(
            fetch_registry_snapshot_envelope(&snapshot_transport, &mirror)
                .expect("bounded snapshot"),
            fixture.snapshot_envelope
        );
        let snapshot_requests = snapshot_transport.requests.borrow();
        assert_eq!(snapshot_requests.len(), 1);
        assert_eq!(
            snapshot_requests[0].url().as_str(),
            "https://registry.example.test/mealy/v1/metadata/snapshot.json"
        );

        let descriptor = descriptor(
            REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE,
            &fixture.release_envelope,
        );
        let content_transport = FixtureMirrorTransport {
            response: Ok(RegistryMirrorResponse {
                media_type: descriptor.media_type.clone(),
                bytes: fixture.release_envelope.clone(),
            }),
            requests: RefCell::new(Vec::new()),
        };
        assert_eq!(
            fetch_registry_content(&content_transport, &mirror, &descriptor)
                .expect("authenticated object"),
            fixture.release_envelope
        );
        assert_eq!(
            content_transport.requests.borrow()[0].url().as_str(),
            format!(
                "https://registry.example.test/mealy/v1/objects/sha256/{}",
                descriptor.sha256_digest
            )
        );

        let mut wrong_bytes = fixture.release_envelope.clone();
        wrong_bytes[0] ^= 1;
        let mismatch_transport = FixtureMirrorTransport {
            response: Ok(RegistryMirrorResponse {
                media_type: descriptor.media_type.clone(),
                bytes: wrong_bytes,
            }),
            requests: RefCell::new(Vec::new()),
        };
        assert_eq!(
            fetch_registry_content(&mismatch_transport, &mirror, &descriptor),
            Err(RegistryMirrorError::ContentMismatch)
        );
    }

    #[test]
    fn mirror_configuration_rejects_ambiguous_authority_and_paths() {
        for base_url in [
            "http://registry.example.test/",
            "https://owner:secret@registry.example.test/",
            "https://registry.example.test",
            "https://registry.example.test//v1/",
            "https://registry.example.test/v1/%2e%2e/",
            "https://registry.example.test/v1/?channel=stable",
            "https://registry.example.test/v1/#current",
            "https://registry.example.test./v1/",
            "https://registry..example.test/v1/",
            "https://-registry.example.test/v1/",
            "HTTPS://registry.example.test/v1/",
        ] {
            let mirror = RegistryMirror {
                registry_id: "dev.mealy.registry".to_owned(),
                base_url: base_url.to_owned(),
            };
            assert_eq!(
                mirror.validate(),
                Err(RegistryMirrorError::InvalidMirror),
                "accepted {base_url}"
            );
        }
    }

    #[test]
    fn trust_root_bootstrap_and_dual_threshold_rotation_are_exact() {
        let fixture = fixture();
        let initial_bytes = serde_json::to_vec(&fixture.root).expect("root");
        let initial =
            inspect_initial_registry_trust_root(&initial_bytes, NOW_MS).expect("out-of-band root");
        assert_eq!(initial.trust_root, fixture.root);
        assert_eq!(initial.root_digest, sha256_digest(&initial_bytes));

        let next_key = SigningKey::from_bytes(&[13; 32]);
        let candidate = RegistryTrustRoot {
            registry_id: fixture.root.registry_id.clone(),
            root_version: 2,
            keys: vec![public_key(&next_key)],
            threshold: 1,
            expires_at_ms: NOW_MS + 180_000,
        };
        let rotation = signed_envelope(
            REGISTRY_ROOT_PAYLOAD_TYPE,
            ROOT_SIGNATURE_CONTEXT,
            &candidate,
            &[&fixture.registry_key, &next_key],
        );
        let inspected = inspect_registry_root_rotation(&rotation, &fixture.root, NOW_MS)
            .expect("dual-threshold rotation");
        assert_eq!(inspected.trust_root, candidate);
        assert_eq!(
            inspected.root_digest,
            sha256_digest(&serde_json::to_vec(&candidate).expect("candidate"))
        );

        let old_only = signed_envelope(
            REGISTRY_ROOT_PAYLOAD_TYPE,
            ROOT_SIGNATURE_CONTEXT,
            &candidate,
            &[&fixture.registry_key],
        );
        assert_eq!(
            inspect_registry_root_rotation(&old_only, &fixture.root, NOW_MS),
            Err(RegistryError::ThresholdNotMet)
        );
        let mut skipped = candidate.clone();
        skipped.root_version = 3;
        let skipped_envelope = signed_envelope(
            REGISTRY_ROOT_PAYLOAD_TYPE,
            ROOT_SIGNATURE_CONTEXT,
            &skipped,
            &[&fixture.registry_key, &next_key],
        );
        assert_eq!(
            inspect_registry_root_rotation(&skipped_envelope, &fixture.root, NOW_MS),
            Err(RegistryError::InvalidRootRotation)
        );

        let duplicate_root = String::from_utf8(initial_bytes)
            .expect("UTF-8")
            .replace("\"rootVersion\":1", "\"rootVersion\":1,\"rootVersion\":1");
        assert_eq!(
            inspect_initial_registry_trust_root(duplicate_root.as_bytes(), NOW_MS),
            Err(RegistryError::InvalidTrustRoot)
        );
    }

    #[test]
    fn snapshot_signature_expiry_rollback_and_equivocation_fail_closed() {
        let fixture = fixture();
        assert_eq!(
            inspect_registry_snapshot(&fixture.snapshot_envelope, &fixture.root, None, -1),
            Err(RegistryError::InvalidTrustRoot)
        );
        let duplicate_envelope = String::from_utf8(fixture.snapshot_envelope.clone())
            .expect("UTF-8")
            .replacen(
                "\"payloadType\":",
                &format!("\"payloadType\":\"{REGISTRY_SNAPSHOT_PAYLOAD_TYPE}\",\"payloadType\":"),
                1,
            );
        assert_eq!(
            inspect_registry_snapshot(duplicate_envelope.as_bytes(), &fixture.root, None, NOW_MS),
            Err(RegistryError::InvalidEnvelope)
        );
        let mut envelope =
            serde_json::from_slice::<RegistrySignedEnvelope>(&fixture.snapshot_envelope)
                .expect("envelope");
        let mut payload = URL_SAFE_NO_PAD
            .decode(&envelope.payload_base64url)
            .expect("payload");
        let marker = payload
            .windows(b"\"version\":1".len())
            .position(|window| window == b"\"version\":1")
            .expect("version marker");
        payload[marker + b"\"version\":".len()] = b'2';
        envelope.payload_base64url = URL_SAFE_NO_PAD.encode(payload);
        let tampered = serde_json::to_vec(&envelope).expect("tampered envelope");
        assert_eq!(
            inspect_registry_snapshot(&tampered, &fixture.root, None, NOW_MS),
            Err(RegistryError::ThresholdNotMet)
        );
        assert_eq!(
            inspect_registry_snapshot(
                &fixture.snapshot_envelope,
                &fixture.root,
                None,
                fixture.snapshot.expires_at_ms
            ),
            Err(RegistryError::Expired)
        );
        let newer = RegistrySnapshotState {
            registry_id: fixture.root.registry_id.clone(),
            root_version: fixture.root.root_version,
            version: 2,
            envelope_digest: "e".repeat(64),
            expires_at_ms: fixture.snapshot.expires_at_ms,
        };
        assert_eq!(
            inspect_registry_snapshot(
                &fixture.snapshot_envelope,
                &fixture.root,
                Some(&newer),
                NOW_MS
            ),
            Err(RegistryError::Rollback)
        );
        let conflicting = RegistrySnapshotState {
            registry_id: fixture.root.registry_id.clone(),
            root_version: fixture.root.root_version,
            version: 1,
            envelope_digest: "e".repeat(64),
            expires_at_ms: fixture.snapshot.expires_at_ms,
        };
        assert_eq!(
            inspect_registry_snapshot(
                &fixture.snapshot_envelope,
                &fixture.root,
                Some(&conflicting),
                NOW_MS
            ),
            Err(RegistryError::Equivocation)
        );

        let canonical_payload = serde_json::to_vec(&fixture.snapshot).expect("snapshot payload");
        let duplicate_payload = String::from_utf8(canonical_payload)
            .expect("UTF-8")
            .replace("\"version\":1", "\"version\":1,\"version\":1")
            .into_bytes();
        let duplicate_envelope = signed_payload_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_SIGNATURE_CONTEXT,
            &duplicate_payload,
            &[&fixture.registry_key],
        );
        assert_eq!(
            inspect_registry_snapshot(&duplicate_envelope, &fixture.root, None, NOW_MS),
            Err(RegistryError::InvalidSnapshot)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One fixture proves threshold, withdrawal, compatibility, and locks together.
    fn threshold_withdrawal_compatibility_and_dependency_locks_are_enforced() {
        let mut fixture = fixture();
        let second_registry_key = SigningKey::from_bytes(&[11; 32]);
        fixture.root.keys.push(public_key(&second_registry_key));
        fixture
            .root
            .keys
            .sort_by(|left, right| left.key_id.cmp(&right.key_id));
        fixture.root.threshold = 2;
        assert_eq!(
            inspect_registry_snapshot(&fixture.snapshot_envelope, &fixture.root, None, NOW_MS),
            Err(RegistryError::ThresholdNotMet)
        );

        let mut withdrawn_snapshot = fixture.snapshot.clone();
        withdrawn_snapshot.targets[0].withdrawal = Some(RegistryWithdrawal {
            withdrawn_at_ms: NOW_MS,
            reason: "publisher incident".to_owned(),
        });
        let withdrawn_envelope = signed_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_SIGNATURE_CONTEXT,
            &withdrawn_snapshot,
            &[&fixture.registry_key],
        );
        let mut single_root = fixture.root.clone();
        single_root.keys = vec![public_key(&fixture.registry_key)];
        single_root.threshold = 1;
        let withdrawn = inspect_registry_snapshot(&withdrawn_envelope, &single_root, None, NOW_MS)
            .expect("withdrawn snapshot remains auditable");
        assert_eq!(
            inspect_registry_release(
                &fixture.release_envelope,
                &withdrawn,
                &withdrawn.snapshot.targets[0],
                1
            ),
            Err(RegistryError::Withdrawn)
        );

        let mut incompatible_release = RegistryRelease {
            contract_version: REGISTRY_RELEASE_CONTRACT_VERSION.to_owned(),
            registry_id: fixture.snapshot.registry_id.clone(),
            package_id: "dev.mealy.fixture".to_owned(),
            kind: RegistryPackageKind::Extension,
            publisher_id: "dev.mealy".to_owned(),
            version: "1.0.0".to_owned(),
            manifest: descriptor(
                REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE,
                b"extension manifest",
            ),
            package: descriptor(REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE, b"extension package"),
            minimum_host_api: 2,
            maximum_host_api: 2,
            dependencies: Vec::new(),
            published_at_ms: NOW_MS - 1_000,
        };
        let incompatible_envelope = signed_envelope(
            REGISTRY_RELEASE_PAYLOAD_TYPE,
            RELEASE_SIGNATURE_CONTEXT,
            &incompatible_release,
            &[&fixture.publisher_key],
        );
        let mut incompatible_snapshot = fixture.snapshot.clone();
        incompatible_snapshot.targets[0].release_envelope =
            descriptor(REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE, &incompatible_envelope);
        let incompatible_snapshot_envelope = signed_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_SIGNATURE_CONTEXT,
            &incompatible_snapshot,
            &[&fixture.registry_key],
        );
        let inspected =
            inspect_registry_snapshot(&incompatible_snapshot_envelope, &single_root, None, NOW_MS)
                .expect("compatible snapshot metadata");
        assert_eq!(
            inspect_registry_release(
                &incompatible_envelope,
                &inspected,
                &inspected.snapshot.targets[0],
                1
            ),
            Err(RegistryError::Incompatible)
        );

        incompatible_release.minimum_host_api = 1;
        incompatible_release.maximum_host_api = 1;
        incompatible_release.dependencies = vec![super::RegistryDependencyLock {
            package_id: "dev.mealy.missing".to_owned(),
            kind: RegistryPackageKind::Skill,
            version: "1.0.0".to_owned(),
            release_envelope_digest: "a".repeat(64),
        }];
        let orphan_envelope = signed_envelope(
            REGISTRY_RELEASE_PAYLOAD_TYPE,
            RELEASE_SIGNATURE_CONTEXT,
            &incompatible_release,
            &[&fixture.publisher_key],
        );
        let mut orphan_snapshot = fixture.snapshot;
        orphan_snapshot.targets[0].release_envelope =
            descriptor(REGISTRY_RELEASE_ENVELOPE_MEDIA_TYPE, &orphan_envelope);
        let orphan_snapshot_envelope = signed_envelope(
            REGISTRY_SNAPSHOT_PAYLOAD_TYPE,
            SNAPSHOT_SIGNATURE_CONTEXT,
            &orphan_snapshot,
            &[&fixture.registry_key],
        );
        let inspected =
            inspect_registry_snapshot(&orphan_snapshot_envelope, &single_root, None, NOW_MS)
                .expect("snapshot");
        assert_eq!(
            inspect_registry_release(
                &orphan_envelope,
                &inspected,
                &inspected.snapshot.targets[0],
                1
            ),
            Err(RegistryError::InvalidRelease)
        );
    }

    #[test]
    fn extension_and_skill_updates_expose_exact_permission_diffs() {
        let before = extension_manifest("1.0.0");
        let mut after = before.clone();
        after.version = "2.0.0".to_owned();
        after.permissions.filesystem[0].access = ExtensionFilesystemAccess::ReadWrite;
        after
            .permissions
            .network_destinations
            .push("api.example.test:443".to_owned());
        after
            .permissions
            .secret_references
            .push("service-token".to_owned());
        after.permissions.allow_process_spawn = true;
        after.capabilities.push(ExtensionCapabilityManifest {
            capability_id: "publish".to_owned(),
            kind: ExtensionCapabilityKind::Tool,
            effect_class: EffectClass::NonIdempotent,
            risk_class: RiskClass::High,
            input_schema: schema("text"),
            output_schema: schema("receipt"),
            timeout_ms: 1_000,
            maximum_output_bytes: 1_024,
        });
        let diff = diff_extension_permissions(&before, &after).expect("extension diff");
        assert_eq!(diff.added_capabilities, ["publish"]);
        assert_eq!(diff.filesystem.len(), 1);
        assert_eq!(diff.added_network_destinations, ["api.example.test:443"]);
        assert_eq!(diff.added_secret_references, ["service-token"]);
        assert!(diff.requires_fresh_approval());
        assert!(diff.widens_authority());

        let before_skill = skill_manifest("fixture.read");
        let after_skill = skill_manifest("fixture.write");
        let skill_diff = diff_skill_permissions(&before_skill, &after_skill).expect("skill diff");
        assert_eq!(skill_diff.added_required_tools[0].tool_id, "fixture.write");
        assert_eq!(skill_diff.removed_required_tools[0].tool_id, "fixture.read");
        assert!(skill_diff.requires_fresh_approval());
        assert!(skill_diff.widens_authority());
    }

    fn public_key(signing_key: &SigningKey) -> RegistryPublicKey {
        let bytes = signing_key.verifying_key().to_bytes();
        RegistryPublicKey {
            key_id: sha256_digest(&bytes),
            algorithm: RegistrySignatureAlgorithm::Ed25519,
            public_key_base64url: URL_SAFE_NO_PAD.encode(bytes),
        }
    }

    fn publisher(signing_key: &SigningKey) -> RegistryPublisher {
        RegistryPublisher {
            publisher_id: "dev.mealy".to_owned(),
            keys: vec![public_key(signing_key)],
            threshold: 1,
        }
    }

    fn descriptor(media_type: &str, bytes: &[u8]) -> RegistryContentDescriptor {
        RegistryContentDescriptor {
            media_type: media_type.to_owned(),
            sha256_digest: sha256_digest(bytes),
            size_bytes: u64::try_from(bytes.len()).expect("fixture size"),
        }
    }

    fn signed_envelope<T: serde::Serialize>(
        payload_type: &str,
        context: &str,
        payload: &T,
        keys: &[&SigningKey],
    ) -> Vec<u8> {
        let payload = serde_json::to_vec(payload).expect("payload");
        signed_payload_envelope(payload_type, context, &payload, keys)
    }

    fn signed_payload_envelope(
        payload_type: &str,
        context: &str,
        payload: &[u8],
        keys: &[&SigningKey],
    ) -> Vec<u8> {
        let mut material = Vec::from(context.as_bytes());
        material.push(0);
        material.extend_from_slice(payload);
        let mut signatures = keys
            .iter()
            .map(|key| {
                let public = public_key(key);
                RegistrySignature {
                    key_id: public.key_id,
                    signature_base64url: URL_SAFE_NO_PAD.encode(key.sign(&material).to_bytes()),
                }
            })
            .collect::<Vec<_>>();
        signatures.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        serde_json::to_vec(&RegistrySignedEnvelope {
            payload_type: payload_type.to_owned(),
            payload_base64url: URL_SAFE_NO_PAD.encode(payload),
            signatures,
        })
        .expect("envelope")
    }

    fn schema(field: &str) -> ExtensionObjectSchema {
        ExtensionObjectSchema {
            properties: BTreeMap::from([(
                field.to_owned(),
                ExtensionFieldSchema {
                    value_type: ExtensionScalarType::String,
                    maximum_length: Some(128),
                    minimum_integer: None,
                    maximum_integer: None,
                },
            )]),
            required: BTreeSet::from([field.to_owned()]),
            additional_properties: false,
            maximum_serialized_bytes: 256,
        }
    }

    fn extension_manifest(version: &str) -> ExtensionManifest {
        ExtensionManifest {
            schema_version: EXTENSION_MANIFEST_SCHEMA_VERSION,
            extension_id: ExtensionId::new(),
            name: "dev.mealy.fixture".to_owned(),
            publisher: "dev.mealy".to_owned(),
            version: version.to_owned(),
            kinds: BTreeSet::from([ExtensionKind::ToolService]),
            compatibility: ExtensionCompatibility {
                minimum_host_api: 1,
                maximum_host_api: 1,
            },
            entry_point: ExtensionEntryPoint {
                executable: "worker".to_owned(),
                executable_digest: "a".repeat(64),
                runtime_files: Vec::new(),
            },
            capabilities: vec![ExtensionCapabilityManifest {
                capability_id: "health".to_owned(),
                kind: ExtensionCapabilityKind::Health,
                effect_class: EffectClass::ReadOnly,
                risk_class: RiskClass::Low,
                input_schema: ExtensionObjectSchema {
                    properties: BTreeMap::new(),
                    required: BTreeSet::new(),
                    additional_properties: false,
                    maximum_serialized_bytes: 2,
                },
                output_schema: schema("status"),
                timeout_ms: 500,
                maximum_output_bytes: 1_024,
            }],
            permissions: ExtensionPermissions {
                filesystem: vec![ExtensionFilesystemPermission {
                    name: "documents".to_owned(),
                    access: ExtensionFilesystemAccess::ReadOnly,
                }],
                network_destinations: Vec::new(),
                secret_references: Vec::new(),
                allow_process_spawn: false,
            },
            health_check: ExtensionHealthCheck {
                capability_id: "health".to_owned(),
                timeout_ms: 500,
                interval_ms: 1_000,
            },
            migrations: Vec::new(),
            shutdown: ExtensionShutdownBehavior {
                mode: ExtensionShutdownMode::Terminate,
                capability_id: None,
                grace_period_ms: 1_000,
            },
        }
    }

    fn skill_manifest(tool_id: &str) -> SkillManifest {
        SkillManifest {
            contract_version: SKILL_MANIFEST_CONTRACT_VERSION.to_owned(),
            skill_id: "dev.mealy.review".to_owned(),
            version: "1.0.0".to_owned(),
            instructions: vec![SkillAsset {
                relative_path: "instructions/review.md".to_owned(),
                media_type: "text/markdown".to_owned(),
                content_digest: "a".repeat(64),
                size_bytes: 128,
            }],
            resources: Vec::new(),
            required_tools: BTreeSet::from([SkillToolRequirement {
                tool_id: tool_id.to_owned(),
                version: "1".to_owned(),
                input_schema_digest: "b".repeat(64),
            }]),
        }
    }

    #[test]
    fn package_kind_uses_distinct_manifest_and_archive_media_types() {
        assert_ne!(
            REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE,
            REGISTRY_SKILL_MANIFEST_MEDIA_TYPE
        );
        assert_ne!(
            REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE,
            REGISTRY_SKILL_PACKAGE_MEDIA_TYPE
        );
    }
}
