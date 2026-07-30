use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable external messaging platform identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelPlatform {
    /// Slack Events API plus Web API.
    Slack,
}

/// Canonical untrusted text admitted from one external channel delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelInboundMessage {
    /// Platform-specific stable delivery identity.
    pub delivery_id: String,
    /// Exact external workspace or tenant.
    pub workspace_id: String,
    /// Exact external conversation.
    pub conversation_id: String,
    /// Exact thread root when the platform supplied one.
    pub thread_id: Option<String>,
    /// Exact allowlisted sender.
    pub sender_id: String,
    /// Bounded normalized UTF-8 user content.
    pub text: String,
    /// Digest of the complete raw platform envelope.
    pub body_digest: String,
    /// Path-free citation locator.
    pub source_locator: String,
}

/// Durable action selected for one authenticated channel envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelInboundDisposition {
    /// Admit the normalized message through the ordinary session boundary.
    Admit(ChannelInboundMessage),
    /// Acknowledge but do not admit an unsupported or unauthorized message.
    Ignore(&'static str),
}

/// One platform envelope paired with the acknowledgement required by its transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelInboundReceipt {
    /// Transport acknowledgement identity.
    pub acknowledgement_id: String,
    /// Durable action to reserve before acknowledging.
    pub disposition: ChannelInboundDisposition,
}

/// Platform-neutral bounded outbound content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelOutboundContent<'a> {
    /// Durable Mealy outbox identity used for downstream deduplication.
    pub delivery_id: &'a str,
    /// Exact stored thread root for a reply, when the admitted input supplied one.
    pub thread_id: Option<&'a str>,
    /// Owner-visible notification text.
    pub text: &'a str,
}

/// Prepared external channel request with no credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelOutboundRequest {
    /// Exact destination conversation.
    pub conversation_id: String,
    /// Exact destination thread root, when configured.
    pub thread_id: Option<String>,
    /// Bounded platform-safe text.
    pub text: String,
    /// Stable downstream duplicate-suppression identity.
    pub client_message_id: String,
}

/// Pure protocol contract shared by built-in external channel adapters.
pub trait ChannelAdapter {
    /// Stable platform implemented by this adapter.
    fn platform(&self) -> ChannelPlatform;

    /// Normalizes one bounded authenticated transport envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelAdapterError`] before acknowledgement when the outer envelope is unsafe.
    fn normalize_inbound(&self, body: &[u8]) -> Result<ChannelInboundReceipt, ChannelAdapterError>;

    /// Renders one bounded mention-safe outbound request.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelAdapterError`] for malformed delivery identity or empty/unsafe content.
    fn prepare_outbound(
        &self,
        content: ChannelOutboundContent<'_>,
    ) -> Result<ChannelOutboundRequest, ChannelAdapterError>;
}

/// Fail-closed channel adapter validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ChannelAdapterError {
    /// Outer transport envelope exceeded its hard bound.
    #[error("channel envelope exceeds its hard byte bound")]
    EnvelopeTooLarge,
    /// Outer transport envelope was not valid canonical evidence.
    #[error("channel envelope is invalid")]
    InvalidEnvelope,
    /// Configured platform authority is malformed.
    #[error("channel adapter configuration is invalid")]
    InvalidConfiguration,
    /// Outbound content or downstream duplicate identity is malformed.
    #[error("channel outbound content is invalid")]
    InvalidOutbound,
}
