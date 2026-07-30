use crate::{
    ChannelAdapter, ChannelAdapterError, ChannelInboundDisposition, ChannelInboundMessage,
    ChannelInboundReceipt, ChannelOutboundContent, ChannelOutboundRequest, ChannelPlatform,
    sha256_digest,
};
use serde_json::Value;

/// Maximum accepted Slack Socket Mode envelope bytes.
pub const SLACK_MAXIMUM_ENVELOPE_BYTES: usize = 1024 * 1024;
/// Maximum normalized Slack message bytes.
pub const SLACK_MAXIMUM_INBOUND_TEXT_BYTES: usize = 32 * 1024;
/// Conservative top-level Slack message character limit.
pub const SLACK_MAXIMUM_OUTBOUND_CHARACTERS: usize = 4_000;

const MAXIMUM_SLACK_ID_BYTES: usize = 64;
const MAXIMUM_SLACK_EVENT_ID_BYTES: usize = 128;
const MAXIMUM_SLACK_ENVELOPE_ID_BYTES: usize = 128;

/// Exact least-authority Slack workspace/user/conversation binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackAdapter {
    team_id: String,
    allowed_user_id: String,
    channel_id: String,
    bot_user_id: String,
    require_mention: bool,
}

impl SlackAdapter {
    /// Constructs one exact Slack adapter authority.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelAdapterError::InvalidConfiguration`] for malformed or overlapping IDs.
    pub fn new(
        team_id: String,
        allowed_user_id: String,
        channel_id: String,
        bot_user_id: String,
        require_mention: bool,
    ) -> Result<Self, ChannelAdapterError> {
        let adapter = Self {
            team_id,
            allowed_user_id,
            channel_id,
            bot_user_id,
            require_mention,
        };
        if !valid_slack_id(&adapter.team_id, b'T')
            || !valid_slack_user_id(&adapter.allowed_user_id)
            || !valid_slack_channel_id(&adapter.channel_id)
            || !valid_slack_user_id(&adapter.bot_user_id)
            || adapter.allowed_user_id == adapter.bot_user_id
            || (adapter.channel_id.starts_with('D') && adapter.require_mention)
        {
            return Err(ChannelAdapterError::InvalidConfiguration);
        }
        Ok(adapter)
    }

    /// Exact Slack workspace identity.
    #[must_use]
    pub fn team_id(&self) -> &str {
        &self.team_id
    }

    /// Exact allowlisted Slack member.
    #[must_use]
    pub fn allowed_user_id(&self) -> &str {
        &self.allowed_user_id
    }

    /// Exact allowed Slack conversation.
    #[must_use]
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    /// Verified Slack bot member.
    #[must_use]
    pub fn bot_user_id(&self) -> &str {
        &self.bot_user_id
    }

    /// Whether a shared-surface input must mention the bot.
    #[must_use]
    pub const fn require_mention(&self) -> bool {
        self.require_mention
    }

    fn normalize_event(
        &self,
        acknowledgement_id: String,
        payload: &serde_json::Map<String, Value>,
        body: &[u8],
    ) -> ChannelInboundReceipt {
        if payload.get("team_id").and_then(Value::as_str) != Some(self.team_id.as_str()) {
            return ignored(acknowledgement_id, "workspace_not_allowed");
        }
        let Some(event_id) = payload
            .get("event_id")
            .and_then(Value::as_str)
            .filter(|value| valid_bounded_identifier(value, MAXIMUM_SLACK_EVENT_ID_BYTES))
        else {
            return ignored(acknowledgement_id, "invalid_event_identity");
        };
        let Some(event) = payload.get("event").and_then(Value::as_object) else {
            return ignored(acknowledgement_id, "invalid_event_payload");
        };
        if event.get("type").and_then(Value::as_str) != Some("message") {
            return ignored(acknowledgement_id, "unsupported_event_type");
        }
        if event.get("subtype").is_some()
            || event.get("bot_id").is_some()
            || event.get("hidden").and_then(Value::as_bool) == Some(true)
        {
            return ignored(acknowledgement_id, "unsupported_message_subtype");
        }
        if event.get("channel").and_then(Value::as_str) != Some(self.channel_id.as_str()) {
            return ignored(acknowledgement_id, "conversation_not_allowed");
        }
        if event.get("user").and_then(Value::as_str) != Some(self.allowed_user_id.as_str()) {
            return ignored(acknowledgement_id, "sender_not_allowed");
        }
        let Some(timestamp) = event
            .get("ts")
            .and_then(Value::as_str)
            .filter(|value| valid_slack_timestamp(value))
        else {
            return ignored(acknowledgement_id, "invalid_message_timestamp");
        };
        let thread_id = match event.get("thread_ts") {
            None => None,
            Some(Value::String(value)) if valid_slack_timestamp(value) => Some(value.clone()),
            Some(_) => return ignored(acknowledgement_id, "invalid_thread_timestamp"),
        };
        let Some(raw_text) = event
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| valid_raw_inbound_text(text))
        else {
            return ignored(acknowledgement_id, "invalid_message_text");
        };
        let raw_text = raw_text.trim();
        let mention = format!("<@{}>", self.bot_user_id);
        if self.require_mention && !raw_text.contains(&mention) {
            return ignored(acknowledgement_id, "mention_required");
        }
        let text = raw_text.replace(&mention, "").trim().to_owned();
        if !valid_inbound_text(&text) {
            return ignored(acknowledgement_id, "empty_message_after_mention");
        }
        ChannelInboundReceipt {
            acknowledgement_id,
            disposition: ChannelInboundDisposition::Admit(ChannelInboundMessage {
                delivery_id: event_id.to_owned(),
                workspace_id: self.team_id.clone(),
                conversation_id: self.channel_id.clone(),
                thread_id: thread_id.or_else(|| Some(timestamp.to_owned())),
                sender_id: self.allowed_user_id.clone(),
                text,
                body_digest: sha256_digest(body),
                source_locator: format!(
                    "slack://{}/{}/{}",
                    self.team_id, self.channel_id, event_id
                ),
            }),
        }
    }
}

impl ChannelAdapter for SlackAdapter {
    fn platform(&self) -> ChannelPlatform {
        ChannelPlatform::Slack
    }

    fn normalize_inbound(&self, body: &[u8]) -> Result<ChannelInboundReceipt, ChannelAdapterError> {
        if body.is_empty() || body.len() > SLACK_MAXIMUM_ENVELOPE_BYTES {
            return Err(ChannelAdapterError::EnvelopeTooLarge);
        }
        let envelope = serde_json::from_slice::<Value>(body)
            .map_err(|_| ChannelAdapterError::InvalidEnvelope)?;
        let envelope = envelope
            .as_object()
            .ok_or(ChannelAdapterError::InvalidEnvelope)?;
        let acknowledgement_id = envelope
            .get("envelope_id")
            .and_then(Value::as_str)
            .filter(|value| valid_bounded_identifier(value, MAXIMUM_SLACK_ENVELOPE_ID_BYTES))
            .ok_or(ChannelAdapterError::InvalidEnvelope)?
            .to_owned();
        if envelope.get("type").and_then(Value::as_str) != Some("events_api")
            || envelope
                .get("accepts_response_payload")
                .and_then(Value::as_bool)
                != Some(false)
        {
            return Ok(ChannelInboundReceipt {
                acknowledgement_id,
                disposition: ChannelInboundDisposition::Ignore("unsupported_envelope_type"),
            });
        }
        let Some(payload) = envelope.get("payload").and_then(Value::as_object) else {
            return Ok(ignored(acknowledgement_id, "invalid_event_payload"));
        };
        Ok(self.normalize_event(acknowledgement_id, payload, body))
    }

    fn prepare_outbound(
        &self,
        content: ChannelOutboundContent<'_>,
    ) -> Result<ChannelOutboundRequest, ChannelAdapterError> {
        if !valid_bounded_identifier(content.delivery_id, MAXIMUM_SLACK_EVENT_ID_BYTES)
            || content.text.is_empty()
            || content
                .thread_id
                .is_some_and(|thread_id| !valid_slack_timestamp(thread_id))
            || content
                .text
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return Err(ChannelAdapterError::InvalidOutbound);
        }
        let escaped = escape_slack_control_text(content.text);
        let text = truncate_slack_text(&escaped);
        if text.is_empty() {
            return Err(ChannelAdapterError::InvalidOutbound);
        }
        Ok(ChannelOutboundRequest {
            conversation_id: self.channel_id.clone(),
            thread_id: content.thread_id.map(str::to_owned),
            text,
            client_message_id: content.delivery_id.to_owned(),
        })
    }
}

fn ignored(acknowledgement_id: String, reason: &'static str) -> ChannelInboundReceipt {
    ChannelInboundReceipt {
        acknowledgement_id,
        disposition: ChannelInboundDisposition::Ignore(reason),
    }
}

/// Validates one stable Slack platform identity without trusting names.
#[must_use]
pub fn valid_slack_platform_id(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|prefix| matches!(prefix, b'T' | b'U' | b'W' | b'C' | b'G' | b'D'))
        && valid_slack_identifier(value)
}

fn valid_slack_identifier(value: &str) -> bool {
    value.len() >= 2
        && value.len() <= MAXIMUM_SLACK_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_slack_id(value: &str, prefix: u8) -> bool {
    value.as_bytes().first() == Some(&prefix) && valid_slack_identifier(value)
}

fn valid_slack_user_id(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|prefix| matches!(prefix, b'U' | b'W'))
        && valid_slack_platform_id(value)
}

fn valid_slack_channel_id(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|prefix| matches!(prefix, b'C' | b'G' | b'D'))
        && valid_slack_platform_id(value)
}

fn valid_bounded_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Validates a Socket Mode envelope acknowledgement identity.
#[must_use]
pub fn valid_slack_acknowledgement_id(value: &str) -> bool {
    valid_bounded_identifier(value, MAXIMUM_SLACK_ENVELOPE_ID_BYTES)
}

/// Validates a stable Slack Events API delivery identity.
#[must_use]
pub fn valid_slack_delivery_id(value: &str) -> bool {
    valid_bounded_identifier(value, MAXIMUM_SLACK_EVENT_ID_BYTES)
}

/// Validates a stable Slack application identity reported by `auth.test` and Socket Mode hello.
#[must_use]
pub fn valid_slack_app_id(value: &str) -> bool {
    valid_slack_id(value, b'A')
}

fn valid_slack_timestamp(value: &str) -> bool {
    let Some((seconds, micros)) = value.split_once('.') else {
        return false;
    };
    !seconds.is_empty()
        && seconds.len() <= 16
        && !micros.is_empty()
        && micros.len() <= 6
        && seconds.bytes().all(|byte| byte.is_ascii_digit())
        && micros.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_inbound_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= SLACK_MAXIMUM_INBOUND_TEXT_BYTES
        && value.trim() == value
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

fn valid_raw_inbound_text(value: &str) -> bool {
    value.len() <= SLACK_MAXIMUM_INBOUND_TEXT_BYTES
        && !value.trim().is_empty()
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

fn escape_slack_control_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn truncate_slack_text(value: &str) -> String {
    const MARKER: &str = "\n… [truncated; inspect the Mealy session timeline for the full result]";
    if value.chars().count() <= SLACK_MAXIMUM_OUTBOUND_CHARACTERS {
        return value.to_owned();
    }
    let retained = SLACK_MAXIMUM_OUTBOUND_CHARACTERS.saturating_sub(MARKER.chars().count());
    let mut output = value.chars().take(retained).collect::<String>();
    output.push_str(MARKER);
    output
}

#[cfg(test)]
mod tests {
    use super::{
        SLACK_MAXIMUM_OUTBOUND_CHARACTERS, SlackAdapter, valid_slack_app_id,
        valid_slack_platform_id,
    };
    use crate::{
        ChannelAdapter, ChannelInboundDisposition, ChannelOutboundContent, ChannelPlatform,
    };
    use serde_json::json;

    fn adapter() -> SlackAdapter {
        SlackAdapter::new(
            "T01234567".to_owned(),
            "U01234567".to_owned(),
            "C01234567".to_owned(),
            "U07654321".to_owned(),
            true,
        )
        .expect("Slack adapter")
    }

    fn envelope(text: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "envelope_id": "env-1",
            "type": "events_api",
            "accepts_response_payload": false,
            "payload": {
                "team_id": "T01234567",
                "event_id": "Ev01234567",
                "event": {
                    "type": "message",
                    "channel": "C01234567",
                    "user": "U01234567",
                    "text": text,
                    "ts": "1785254000.000100"
                }
            }
        }))
        .expect("Slack envelope")
    }

    #[test]
    fn slack_adapter_normalizes_only_the_exact_allowlisted_mentioned_message() {
        let adapter = adapter();
        assert_eq!(adapter.platform(), ChannelPlatform::Slack);
        let receipt = adapter
            .normalize_inbound(&envelope("<@U07654321> review the incident"))
            .expect("normalize Slack message");
        assert_eq!(receipt.acknowledgement_id, "env-1");
        let ChannelInboundDisposition::Admit(message) = receipt.disposition else {
            panic!("expected admitted Slack message");
        };
        assert_eq!(message.delivery_id, "Ev01234567");
        assert_eq!(message.text, "review the incident");
        assert_eq!(message.thread_id.as_deref(), Some("1785254000.000100"));
        assert_eq!(
            message.source_locator,
            "slack://T01234567/C01234567/Ev01234567"
        );

        let ignored = adapter
            .normalize_inbound(&envelope("review without a mention"))
            .expect("normalize unmentioned Slack message");
        assert_eq!(
            ignored.disposition,
            ChannelInboundDisposition::Ignore("mention_required")
        );
    }

    #[test]
    fn slack_adapter_rejects_spoofed_authority_and_escapes_outbound_mentions() {
        let adapter = adapter();
        let mut spoofed: serde_json::Value =
            serde_json::from_slice(&envelope("<@U07654321> unsafe")).expect("envelope JSON");
        spoofed["payload"]["event"]["user"] = json!("U99999999");
        let spoofed = serde_json::to_vec(&spoofed).expect("spoofed envelope");
        assert_eq!(
            adapter
                .normalize_inbound(&spoofed)
                .expect("normalize spoofed message")
                .disposition,
            ChannelInboundDisposition::Ignore("sender_not_allowed")
        );

        let outbound = adapter
            .prepare_outbound(ChannelOutboundContent {
                delivery_id: "outbox-1",
                thread_id: Some("1785254000.000100"),
                text: "<!channel> & <@U01234567>",
            })
            .expect("Slack outbound");
        assert_eq!(outbound.text, "&lt;!channel&gt; &amp; &lt;@U01234567&gt;");
        assert_eq!(outbound.client_message_id, "outbox-1");
        assert_eq!(outbound.thread_id.as_deref(), Some("1785254000.000100"));

        let long = "x".repeat(SLACK_MAXIMUM_OUTBOUND_CHARACTERS + 100);
        let truncated = adapter
            .prepare_outbound(ChannelOutboundContent {
                delivery_id: "outbox-2",
                thread_id: None,
                text: &long,
            })
            .expect("truncated outbound");
        assert_eq!(
            truncated.text.chars().count(),
            SLACK_MAXIMUM_OUTBOUND_CHARACTERS
        );
    }

    #[test]
    fn slack_adapter_accepts_workspace_member_ids_and_normalizes_outer_whitespace() {
        assert!(valid_slack_app_id("A01234567"));
        assert!(!valid_slack_platform_id("A01234567"));
        assert!(!valid_slack_platform_id("B01234567"));
        let adapter = SlackAdapter::new(
            "T01234567".to_owned(),
            "W01234567".to_owned(),
            "D01234567".to_owned(),
            "W07654321".to_owned(),
            false,
        )
        .expect("Slack direct-message adapter");
        let mut direct: serde_json::Value =
            serde_json::from_slice(&envelope("  review the incident\n")).expect("envelope JSON");
        direct["payload"]["event"]["channel"] = json!("D01234567");
        direct["payload"]["event"]["user"] = json!("W01234567");
        let direct = serde_json::to_vec(&direct).expect("direct envelope");
        let receipt = adapter
            .normalize_inbound(&direct)
            .expect("normalize direct message");
        let ChannelInboundDisposition::Admit(message) = receipt.disposition else {
            panic!("expected admitted direct message");
        };
        assert_eq!(message.text, "review the incident");

        assert!(
            adapter
                .prepare_outbound(ChannelOutboundContent {
                    delivery_id: "outbox-3",
                    thread_id: Some("not-a-slack-timestamp"),
                    text: "unsafe route",
                })
                .is_err()
        );
    }
}
