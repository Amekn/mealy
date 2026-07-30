use crate::{
    OwnershipContext, ProviderCredentialReference, TimelineCursor, is_sha256_digest, sha256_digest,
    validate_provider_base_url,
};
use mealy_domain::{
    CorrelationId, EventId, MemoryCategory, MemoryConfidence, MemoryId, MemoryMetadata,
    MemoryPromotionAuthorization, MemoryRetention, MemoryRevisionId, MemorySensitivity,
    MemoryStatus,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::SystemTime};
use thiserror::Error;

/// Stable policy bundle for governed memory promotion and retrieval.
pub const MEMORY_POLICY_VERSION: &str = "mealy.memory.v1";
/// Stable contract for optional derived semantic-memory vectors.
pub const MEMORY_EMBEDDING_POLICY_VERSION: &str = "mealy.memory-embedding.v1";
/// Maximum supported embedding dimensions.
pub const MAXIMUM_MEMORY_EMBEDDING_DIMENSIONS: u32 = 8_192;
/// Maximum texts sent in one embedding request.
pub const MAXIMUM_MEMORY_EMBEDDING_BATCH: usize = 32;
/// Maximum aggregate UTF-8 bytes sent in one embedding request.
pub const MAXIMUM_MEMORY_EMBEDDING_BATCH_BYTES: usize = 512 * 1_024;

/// Explicit non-secret policy for an optional OpenAI-compatible embedding endpoint.
///
/// Semantic vectors are always derived cache material. This configuration neither changes the
/// canonical memory lifecycle nor authorizes memory outside the existing owner, workspace, and
/// sensitivity boundaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryEmbeddingConfig {
    /// OpenAI-compatible API base ending at a version prefix such as `/v1`.
    base_url: String,
    /// Exact embedding model identity.
    model: String,
    /// Credential reference; optional only for literal-loopback endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential: Option<ProviderCredentialReference>,
    /// Owner-declared data residency recorded in index provenance.
    residency: String,
    /// Exact expected output dimensions; drift fails closed and leaves lexical retrieval intact.
    dimensions: u32,
    /// Optional model-specific prefix applied only to canonical memory documents.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    document_prefix: String,
    /// Optional model-specific prefix applied only to search queries.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    query_prefix: String,
    /// Per-request timeout.
    request_timeout_ms: u64,
}

impl MemoryEmbeddingConfig {
    /// Validates endpoint locality, credential policy, model identity, prefixes, and bounds.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError::InvalidContract`] without resolving or exposing credentials.
    pub fn validate(&self) -> Result<(), MemoryStoreError> {
        let local = validate_provider_base_url(&self.base_url)
            .map_err(|_| invalid_contract("memory embedding endpoint is invalid"))?;
        if !valid_embedding_label(&self.model)
            || !valid_embedding_label(&self.residency)
            || !(1..=MAXIMUM_MEMORY_EMBEDDING_DIMENSIONS).contains(&self.dimensions)
            || !(100..=300_000).contains(&self.request_timeout_ms)
            || !valid_embedding_prefix(&self.document_prefix)
            || !valid_embedding_prefix(&self.query_prefix)
            || self
                .credential
                .as_ref()
                .is_some_and(|reference| reference.validate().is_err())
            || (!local && self.credential.is_none())
        {
            return Err(invalid_contract(
                "memory embedding configuration is invalid",
            ));
        }
        Ok(())
    }

    /// OpenAI-compatible API base.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Exact embedding model.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Optional opaque credential reference.
    #[must_use]
    pub const fn credential(&self) -> Option<&ProviderCredentialReference> {
        self.credential.as_ref()
    }

    /// Owner-declared data residency.
    #[must_use]
    pub fn residency(&self) -> &str {
        &self.residency
    }

    /// Exact expected vector dimensions.
    #[must_use]
    pub const fn dimensions(&self) -> u32 {
        self.dimensions
    }

    /// Prefix used for indexed documents.
    #[must_use]
    pub fn document_prefix(&self) -> &str {
        &self.document_prefix
    }

    /// Prefix used for retrieval queries.
    #[must_use]
    pub fn query_prefix(&self) -> &str {
        &self.query_prefix
    }

    /// Bounded request timeout.
    #[must_use]
    pub const fn request_timeout_ms(&self) -> u64 {
        self.request_timeout_ms
    }

    /// Stable digest of the complete non-secret semantic-index identity and privacy policy.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError::InvalidContract`] when validation or canonical encoding fails.
    pub fn digest(&self) -> Result<String, MemoryStoreError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self)
            .map_err(|_| invalid_contract("memory embedding configuration cannot be encoded"))?;
        Ok(sha256_digest(&encoded))
    }

    /// Reports whether the configured endpoint is inside the literal-loopback boundary.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError::InvalidContract`] for an invalid endpoint.
    pub fn is_local(&self) -> Result<bool, MemoryStoreError> {
        validate_provider_base_url(&self.base_url)
            .map_err(|_| invalid_contract("memory embedding endpoint is invalid"))
    }
}

/// One immutable provenance link attached to a memory revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemorySource {
    /// Owner-inspectable safe logical locator.
    pub locator: String,
    /// Canonical digest of the cited source content.
    pub digest: String,
}

/// Complete proposal of a new logical memory and its first immutable revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposeMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Fresh logical memory identity.
    pub memory_id: MemoryId,
    /// Fresh immutable revision identity.
    pub revision_id: MemoryRevisionId,
    /// Bounded proposed content.
    pub content: String,
    /// Required namespace, provenance, policy, and timestamp metadata.
    pub metadata: MemoryMetadata,
    /// Paired immutable source links.
    pub sources: Vec<MemorySource>,
    /// `memory.proposed` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Proposal time.
    pub proposed_at: SystemTime,
}

/// Explicit promotion of one proposed memory revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromoteMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Exact proposed revision.
    pub revision_id: MemoryRevisionId,
    /// Explicit authorization when sensitive policy requires it.
    pub authorization: Option<MemoryPromotionAuthorization>,
    /// Journal event for owner policy or bound approval evidence.
    pub authorization_event_id: Option<EventId>,
    /// `memory.activated` journal fact.
    pub activation_event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Activation time.
    pub activated_at: SystemTime,
}

/// Atomic correction that preserves the prior revision and activates a replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrectMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory being corrected.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision of the logical memory.
    pub expected_revision: u64,
    /// Fresh replacement revision identity.
    pub revision_id: MemoryRevisionId,
    /// Corrected bounded content.
    pub content: String,
    /// Revised confidence.
    pub confidence: MemoryConfidence,
    /// Revised sensitivity.
    pub sensitivity: MemorySensitivity,
    /// Revised retention policy.
    pub retention: MemoryRetention,
    /// Immutable sources supporting the correction.
    pub sources: Vec<MemorySource>,
    /// Explicit authorization when the replacement is sensitive.
    pub authorization: Option<MemoryPromotionAuthorization>,
    /// `memory.revision_proposed` fact.
    pub revision_event_id: EventId,
    /// Owner authorization fact, when required.
    pub authorization_event_id: Option<EventId>,
    /// `memory.corrected` fact used as both replacement activation and aggregate update evidence.
    pub corrected_event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Correction and verification time.
    pub corrected_at: SystemTime,
}

/// Change to memory retention without mutating immutable revision content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetMemoryPinCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// Pin when true; restore standard retention when false.
    pub pinned: bool,
    /// Journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Update time.
    pub updated_at: SystemTime,
}

/// Explicitly removes an active memory from retrieval without scrubbing audit content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpireMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// Journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Expiry time.
    pub expired_at: SystemTime,
}

/// Explicitly rejects a proposed memory while retaining its immutable content and provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RejectMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// `memory.rejected` journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Rejection time.
    pub rejected_at: SystemTime,
}

/// Scrubs all revision content while retaining minimal lifecycle and digest tombstones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteMemoryCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Logical memory.
    pub memory_id: MemoryId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// Journal fact.
    pub event_id: EventId,
    /// End-to-end correlation identity.
    pub correlation_id: CorrelationId,
    /// Deletion time.
    pub deleted_at: SystemTime,
}

/// Deterministically filtered lexical retrieval query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemorySearchQuery {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Exact workspace namespace; evaluated before lexical relevance.
    pub workspace_identity: String,
    /// FTS5 lexical query. An empty query returns the newest active memories deterministically.
    pub query: String,
    /// Maximum sensitivity permitted by the current context policy.
    pub maximum_sensitivity: MemorySensitivity,
    /// Maximum number of results from one through 100.
    pub limit: usize,
}

/// One immutable memory revision in an owner-authorized inspection view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRevisionView {
    /// Stable revision identity.
    pub revision_id: MemoryRevisionId,
    /// One-based monotonic ordinal.
    pub ordinal: u64,
    /// Revision lifecycle status.
    pub status: MemoryStatus,
    /// Content is absent only after deletion.
    pub content: Option<String>,
    /// Canonical content digest retained in tombstones.
    pub content_digest: String,
    /// Confidence at revision creation.
    pub confidence: MemoryConfidence,
    /// Sensitivity at revision creation.
    pub sensitivity: MemorySensitivity,
    /// Retention at revision creation.
    pub retention: MemoryRetention,
    /// Prior revision corrected by this revision.
    pub supersedes_revision_id: Option<MemoryRevisionId>,
    /// Immutable provenance links.
    pub sources: Vec<MemorySource>,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: i64,
    /// Verification timestamp in Unix milliseconds.
    pub last_verified_at_ms: i64,
}

/// Complete owner-authorized logical memory and revision history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryView {
    /// Stable logical memory identity.
    pub memory_id: MemoryId,
    /// Exact principal/workspace namespace.
    pub principal_id: mealy_domain::PrincipalId,
    /// Stable logical workspace identity.
    pub workspace_identity: String,
    /// Logical lifecycle state.
    pub status: MemoryStatus,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Promotion-policy category.
    pub category: MemoryCategory,
    /// Current confidence.
    pub confidence: MemoryConfidence,
    /// Current sensitivity.
    pub sensitivity: MemorySensitivity,
    /// Current retention behavior.
    pub retention: MemoryRetention,
    /// Proposal timestamp in Unix milliseconds.
    pub created_at_ms: i64,
    /// Most recent verification timestamp in Unix milliseconds.
    pub last_verified_at_ms: i64,
    /// Immutable revision history in ascending ordinal order.
    pub revisions: Vec<MemoryRevisionView>,
}

/// Retrieved memory treated as untrusted cited evidence, never as hidden instruction text.
#[derive(Clone, Debug, PartialEq)]
pub struct MemorySearchHit {
    /// Owner-authorized logical memory and immutable citations.
    pub memory: MemoryView,
    /// FTS5 BM25 rank; lower values are more relevant.
    pub lexical_rank: f64,
}

/// Canonical active revision supplied to an out-of-transaction embedding adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryEmbeddingCandidate {
    /// Logical memory identity.
    pub memory_id: MemoryId,
    /// Exact active revision identity.
    pub revision_id: MemoryRevisionId,
    /// Canonical bounded content sent under the explicit embedding privacy policy.
    pub content: String,
    /// Canonical content digest used to fence an eventual index commit.
    pub content_digest: String,
}

/// One L2-normalized vector derived from an exact canonical active revision.
#[derive(Clone, Debug, PartialEq)]
pub struct MemorySemanticVector {
    /// Logical memory identity.
    pub memory_id: MemoryId,
    /// Exact active revision identity.
    pub revision_id: MemoryRevisionId,
    /// Canonical content digest observed before embedding.
    pub content_digest: String,
    /// Finite non-zero vector values.
    pub values: Vec<f32>,
}

/// Atomic replacement of one owner's complete derived semantic index.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplaceMemorySemanticIndexCommit {
    /// Authenticated owner and verified channel.
    pub ownership: OwnershipContext,
    /// Digest of the complete non-secret embedding model and privacy policy.
    pub config_digest: String,
    /// Exact configured vector dimensions.
    pub dimensions: u32,
    /// One vector for every currently active owner revision.
    pub vectors: Vec<MemorySemanticVector>,
    /// Rebuild completion time.
    pub rebuilt_at: SystemTime,
}

/// Health of one owner's optional derived semantic index.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySemanticIndexHealth {
    /// Every active owner revision is represented by the current configuration.
    Healthy,
    /// Canonical lifecycle changes invalidated the last complete index.
    Stale,
    /// The last explicit rebuild failed before a complete atomic replacement.
    Degraded,
}

/// Owner-inspectable provenance and health for the optional derived semantic index.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySemanticIndexView {
    /// Exact owner whose active revisions are covered.
    pub principal_id: mealy_domain::PrincipalId,
    /// Digest of the non-secret embedding model and privacy policy.
    pub config_digest: String,
    /// Current derived-index health.
    pub health: MemorySemanticIndexHealth,
    /// Exact vector dimensions.
    pub dimensions: u32,
    /// Number of indexed active revisions.
    pub indexed_revision_count: u64,
    /// Most recent successful rebuild time.
    pub last_rebuilt_at_ms: Option<i64>,
    /// Fixed safe failure classification, never downstream text.
    pub last_error_code: Option<String>,
}

/// Deterministically scoped semantic retrieval query over a complete healthy derived index.
#[derive(Clone, Debug, PartialEq)]
pub struct MemorySemanticSearchQuery {
    /// Existing owner, namespace, sensitivity, and limit policy.
    pub search: MemorySearchQuery,
    /// Exact current embedding configuration digest.
    pub config_digest: String,
    /// L2-normalized finite query vector.
    pub query_vector: Vec<f32>,
}

/// One semantic retrieval result retaining complete canonical citations.
#[derive(Clone, Debug, PartialEq)]
pub struct MemorySemanticSearchHit {
    /// Owner-authorized canonical memory and immutable citations.
    pub memory: MemoryView,
    /// Cosine similarity of normalized vectors, in the inclusive range -1 through 1.
    pub semantic_similarity: f64,
}

/// Outcome from rebuilding the derived lexical index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryIndexRebuildReceipt {
    /// Number of active revisions indexed.
    pub indexed_revision_count: u64,
    /// Rebuild completion time in Unix milliseconds.
    pub rebuilt_at_ms: i64,
}

/// Failure from governed memory persistence and retrieval.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MemoryStoreError {
    /// Memory is absent or deliberately hidden from the supplied owner/channel/namespace.
    #[error("memory was not found")]
    NotFound,
    /// Input violates lifecycle, metadata, source, or content bounds.
    #[error("memory contract is invalid: {0}")]
    InvalidContract(String),
    /// Sensitive material lacks exact owner policy or approval evidence.
    #[error("memory promotion was denied by policy")]
    PolicyDenied,
    /// Optimistic revision or immutable identity conflicts with current state.
    #[error("memory commit conflicted with current state")]
    Conflict,
    /// Lexical index is marked degraded; deterministic namespace-filtered fallback was used.
    #[error("memory lexical index is degraded: {0}")]
    IndexDegraded(String),
    /// Optional semantic index is absent, stale, degraded, incompatible, or exceeds scan bounds.
    #[error("memory semantic index is unavailable: {0}")]
    SemanticIndexUnavailable(String),
    /// Persistence could not complete the operation.
    #[error("memory store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical data violates an application invariant.
    #[error("memory store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for governed memory lifecycle, retrieval, inspection, export, and index maintenance.
pub trait MemoryStore {
    /// Atomically creates a proposed logical memory, immutable first revision, provenance, and fact.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, contract validation, or persistence fails.
    fn propose_memory(
        &mut self,
        commit: ProposeMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Promotes an exact proposed revision after policy and any explicit owner evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, lifecycle validation, or persistence fails.
    fn promote_memory(
        &mut self,
        commit: PromoteMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Atomically supersedes the active revision and activates a corrected replacement.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, concurrency, validation, or persistence
    /// fails.
    fn correct_memory(
        &mut self,
        commit: CorrectMemoryCommit,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Pins or unpins active memory retention under optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, lifecycle, concurrency, or persistence fails.
    fn set_memory_pin(
        &mut self,
        commit: SetMemoryPinCommit,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Expires an active memory and removes it from retrieval.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, lifecycle, concurrency, or persistence fails.
    fn expire_memory(&mut self, commit: ExpireMemoryCommit)
    -> Result<MemoryView, MemoryStoreError>;

    /// Rejects a proposed memory without discarding its immutable audit evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, lifecycle, concurrency, or persistence fails.
    fn reject_memory(&mut self, commit: RejectMemoryCommit)
    -> Result<MemoryView, MemoryStoreError>;

    /// Scrubs revision content and removes every derived index entry.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, lifecycle, concurrency, or persistence fails.
    fn delete_memory(&mut self, commit: DeleteMemoryCommit)
    -> Result<MemoryView, MemoryStoreError>;

    /// Inspects one memory and complete revision history through its namespace owner.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, stored evidence, or persistence fails.
    fn memory(
        &self,
        ownership: OwnershipContext,
        workspace_identity: &str,
        memory_id: MemoryId,
    ) -> Result<MemoryView, MemoryStoreError>;

    /// Lists namespace memories deterministically for inspection and export.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, stored evidence, or persistence fails.
    fn memories(
        &self,
        ownership: OwnershipContext,
        workspace_identity: &str,
        include_deleted: bool,
    ) -> Result<Vec<MemoryView>, MemoryStoreError>;

    /// Applies namespace, lifecycle, and sensitivity filters before lexical ranking.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, query validation, indexing, or persistence
    /// fails.
    fn search_memories(
        &self,
        query: MemorySearchQuery,
    ) -> Result<Vec<MemorySearchHit>, MemoryStoreError>;

    /// Rebuilds the FTS5 derived index solely from active canonical revisions.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, canonical evidence, or persistence fails.
    fn rebuild_memory_index(
        &mut self,
        ownership: OwnershipContext,
        rebuilt_at: SystemTime,
    ) -> Result<MemoryIndexRebuildReceipt, MemoryStoreError>;

    /// Loads the complete bounded active owner revision set for an out-of-transaction rebuild.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, active evidence, bounds, or persistence fails.
    fn memory_embedding_candidates(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<MemoryEmbeddingCandidate>, MemoryStoreError>;

    /// Atomically replaces one owner's derived vectors after rechecking the complete active set.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, configuration, vector, content-fence, or
    /// persistence validation fails. A failed commit leaves the prior index unchanged.
    fn replace_memory_semantic_index(
        &mut self,
        commit: ReplaceMemorySemanticIndexCommit,
    ) -> Result<MemorySemanticIndexView, MemoryStoreError>;

    /// Inspects one owner's optional derived semantic-index health and provenance.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when ownership, stored evidence, or persistence fails.
    fn memory_semantic_index(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Option<MemorySemanticIndexView>, MemoryStoreError>;

    /// Marks a failed rebuild with one fixed safe classification while retaining prior vectors.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, configuration, error code, or persistence
    /// validation fails.
    fn degrade_memory_semantic_index(
        &mut self,
        ownership: OwnershipContext,
        config_digest: &str,
        dimensions: u32,
        error_code: &str,
    ) -> Result<MemorySemanticIndexView, MemoryStoreError>;

    /// Searches a complete healthy owner index after canonical namespace/sensitivity filtering.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryStoreError`] when authorization, index health, vector validation, scan
    /// bounds, canonical citations, or persistence validation fails.
    fn search_memories_semantic(
        &self,
        query: MemorySemanticSearchQuery,
    ) -> Result<Vec<MemorySemanticSearchHit>, MemoryStoreError>;
}

/// Validates a proposal without performing storage I/O.
///
/// # Errors
///
/// Returns [`MemoryStoreError::InvalidContract`] for namespace, content, timestamp, or provenance
/// mismatches.
pub fn validate_memory_proposal(commit: &ProposeMemoryCommit) -> Result<(), MemoryStoreError> {
    commit
        .metadata
        .validate()
        .map_err(|error| invalid_contract(error.to_string()))?;
    if commit.metadata.namespace.principal_id != commit.ownership.principal_id()
        || commit.metadata.provenance.proposed_by_principal_id != commit.ownership.principal_id()
        || !valid_content(&commit.content)
    {
        return Err(invalid_contract(
            "proposal ownership, content, or provenance is invalid",
        ));
    }
    validate_sources(&commit.sources, &commit.metadata)?;
    Ok(())
}

/// Validates bounded paired source provenance and exact metadata sets.
///
/// # Errors
///
/// Returns [`MemoryStoreError::InvalidContract`] when sources are empty, duplicated, malformed,
/// or diverge from the domain metadata.
pub fn validate_sources(
    sources: &[MemorySource],
    metadata: &MemoryMetadata,
) -> Result<(), MemoryStoreError> {
    if sources.is_empty() || sources.len() > 64 {
        return Err(invalid_contract("memory sources are empty or unbounded"));
    }
    let locators = sources
        .iter()
        .map(|source| source.locator.clone())
        .collect::<BTreeSet<_>>();
    let digests = sources
        .iter()
        .map(|source| source.digest.clone())
        .collect::<BTreeSet<_>>();
    if locators.len() != sources.len()
        || sources.iter().any(|source| {
            source.locator.is_empty()
                || source.locator.len() > 4_096
                || source.locator.trim() != source.locator
                || source.locator.chars().any(char::is_control)
                || !is_sha256_digest(&source.digest)
        })
        || locators != metadata.provenance.source_locators
        || digests != metadata.provenance.source_digests
    {
        return Err(invalid_contract(
            "paired memory sources diverge from immutable provenance",
        ));
    }
    Ok(())
}

/// Validates lexical query bounds before storage access.
///
/// # Errors
///
/// Returns [`MemoryStoreError::InvalidContract`] for unsafe query or namespace bounds.
pub fn validate_memory_search(query: &MemorySearchQuery) -> Result<(), MemoryStoreError> {
    if query.workspace_identity.is_empty()
        || query.workspace_identity.len() > 1_024
        || query.workspace_identity.trim() != query.workspace_identity
        || query.query.len() > 4_096
        || query.query.chars().any(char::is_control)
        || !(1..=100).contains(&query.limit)
    {
        return Err(invalid_contract("memory search bounds are invalid"));
    }
    Ok(())
}

/// Validates a finite non-zero semantic vector and reports its dimensions.
///
/// # Errors
///
/// Returns [`MemoryStoreError::InvalidContract`] for empty, oversized, non-finite, or zero vectors.
pub fn validate_memory_embedding_vector(values: &[f32]) -> Result<u32, MemoryStoreError> {
    if values.is_empty()
        || values.len()
            > usize::try_from(MAXIMUM_MEMORY_EMBEDDING_DIMENSIONS)
                .map_err(|_| invalid_contract("memory embedding dimension bound is invalid"))?
        || values.iter().any(|value| !value.is_finite())
    {
        return Err(invalid_contract("memory embedding vector is invalid"));
    }
    let norm_squared = values
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>();
    if !norm_squared.is_finite() || norm_squared <= f64::EPSILON {
        return Err(invalid_contract("memory embedding vector is zero"));
    }
    u32::try_from(values.len())
        .map_err(|_| invalid_contract("memory embedding dimensions overflowed"))
}

/// Validates one safe fixed semantic-index failure classification.
#[must_use]
pub fn valid_memory_semantic_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Produces a context-safe logical locator for a cited memory revision.
#[must_use]
pub fn memory_context_locator(memory_id: MemoryId, revision_id: MemoryRevisionId) -> String {
    format!("memory://{memory_id}/revisions/{revision_id}")
}

/// Timeline cursor helper retained in the memory API for citation projections.
#[must_use]
pub const fn memory_event_cursor(cursor: u64) -> TimelineCursor {
    TimelineCursor(cursor)
}

fn valid_content(content: &str) -> bool {
    !content.is_empty() && content.len() <= 65_536 && !content.contains('\0')
}

fn valid_embedding_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_embedding_prefix(value: &str) -> bool {
    value.len() <= 256 && !value.contains('\0') && !value.chars().any(char::is_control)
}

fn invalid_contract(message: impl Into<String>) -> MemoryStoreError {
    MemoryStoreError::InvalidContract(message.into())
}

#[cfg(test)]
mod tests {
    use super::{
        MemoryEmbeddingConfig, MemorySource, ProposeMemoryCommit, validate_memory_proposal,
        validate_sources,
    };
    use crate::{OwnershipContext, ProviderCredentialReference};
    use mealy_domain::{
        ChannelBindingId, CorrelationId, EventId, MemoryCategory, MemoryConfidence, MemoryId,
        MemoryMetadata, MemoryNamespace, MemoryProvenance, MemoryRetention, MemoryRevisionId,
        MemorySensitivity, PrincipalId,
    };
    use std::{collections::BTreeSet, time::UNIX_EPOCH};

    #[test]
    fn proposal_requires_exact_paired_provenance_and_owner_namespace() {
        let principal_id = PrincipalId::new();
        let source = MemorySource {
            locator: "event://12".to_owned(),
            digest: "a".repeat(64),
        };
        let metadata = MemoryMetadata {
            namespace: MemoryNamespace {
                principal_id,
                workspace_identity: "workspace-a".to_owned(),
            },
            category: MemoryCategory::Fact,
            provenance: MemoryProvenance {
                proposed_by_principal_id: principal_id,
                source_locators: BTreeSet::from([source.locator.clone()]),
                source_digests: BTreeSet::from([source.digest.clone()]),
            },
            confidence: MemoryConfidence::new(9_000).expect("confidence"),
            sensitivity: MemorySensitivity::Internal,
            retention: MemoryRetention::Standard,
            created_at_ms: 0,
            last_verified_at_ms: 0,
        };
        let mut commit = ProposeMemoryCommit {
            ownership: OwnershipContext::new(principal_id, ChannelBindingId::new()),
            memory_id: MemoryId::new(),
            revision_id: MemoryRevisionId::new(),
            content: "The deployment window is Tuesday".to_owned(),
            metadata: metadata.clone(),
            sources: vec![source],
            event_id: EventId::new(),
            correlation_id: CorrelationId::new(),
            proposed_at: UNIX_EPOCH,
        };
        assert_eq!(validate_memory_proposal(&commit), Ok(()));
        commit.sources[0].digest = "b".repeat(64);
        assert!(validate_sources(&commit.sources, &metadata).is_err());
    }

    #[test]
    fn embedding_policy_requires_explicit_remote_credentials_and_stable_dimensions() {
        let local: MemoryEmbeddingConfig = serde_json::from_value(serde_json::json!({
            "baseUrl": "http://127.0.0.1:8080/v1",
            "model": "nomic-embed-text",
            "residency": "owner_host",
            "dimensions": 768,
            "documentPrefix": "search_document: ",
            "queryPrefix": "search_query: ",
            "requestTimeoutMs": 5_000
        }))
        .expect("local policy");
        assert_eq!(local.validate(), Ok(()));
        assert!(local.is_local().expect("locality"));
        assert_eq!(local.digest().expect("digest").len(), 64);

        let mut remote = local.clone();
        remote.base_url = "https://embeddings.example/v1".to_owned();
        assert!(remote.validate().is_err());
        remote.credential = Some(ProviderCredentialReference::Broker {
            secret_id: "memory-embedding".to_owned(),
        });
        assert_eq!(remote.validate(), Ok(()));
        assert!(!remote.is_local().expect("locality"));

        remote.dimensions = 0;
        assert!(remote.validate().is_err());
    }
}
