use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use mealy_application::{
    CancellationProbe, ImageGenerationConfig, ImageGenerationProtocol,
    MAXIMUM_PROVIDER_CREDENTIAL_BYTES, normalize_image_generation_arguments,
};
use reqwest::{
    Client, Response, StatusCode,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroizing;

const IMAGE_RESPONSE_ENVELOPE_BYTES: u64 = 64 * 1024;

/// Validated raw result from one exact buffered remote image-generation call.
///
/// The bytes remain untrusted until the daemon passes them through the isolated media normalizer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteGeneratedImage {
    bytes: Vec<u8>,
    request_id: Option<String>,
    reported_cost_microunits: Option<u64>,
    duration_ms: u64,
}

impl RemoteGeneratedImage {
    /// Untrusted provider bytes that claim to be JPEG.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Claimed media type selected by the immutable request contract.
    #[must_use]
    pub const fn claimed_media_type(&self) -> &'static str {
        "image/jpeg"
    }

    /// Bounded provider request identity, when returned.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Provider-reported charge converted to currency microunits, when present.
    #[must_use]
    pub const fn reported_cost_microunits(&self) -> Option<u64> {
        self.reported_cost_microunits
    }

    /// End-to-end buffered adapter duration.
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }
}

/// Exact no-redirect, no-proxy buffered image-generation transport.
pub struct ImageGenerationAdapter {
    config: ImageGenerationConfig,
    credential: Option<Zeroizing<String>>,
    client: Client,
}

impl std::fmt::Debug for ImageGenerationAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImageGenerationAdapter")
            .field("provider_id", &self.config.provider_id())
            .field("protocol", &self.config.protocol())
            .field("model", &self.config.model())
            .finish_non_exhaustive()
    }
}

impl ImageGenerationAdapter {
    /// Builds a transport only when non-secret configuration and resolved credential state match.
    ///
    /// # Errors
    ///
    /// Returns [`ImageGenerationAdapterError::InvalidConfiguration`] for unsafe authority,
    /// missing/unexpected credentials, oversized secrets, or HTTP client construction failure.
    pub fn new(
        config: ImageGenerationConfig,
        credential: Option<Zeroizing<String>>,
    ) -> Result<Self, ImageGenerationAdapterError> {
        config
            .validate()
            .map_err(|_| ImageGenerationAdapterError::InvalidConfiguration)?;
        if config.credential().is_some() != credential.is_some()
            || credential.as_ref().is_some_and(|secret| {
                secret.is_empty() || secret.len() > MAXIMUM_PROVIDER_CREDENTIAL_BYTES
            })
        {
            return Err(ImageGenerationAdapterError::InvalidConfiguration);
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_millis(config.timeout_ms()))
            .build()
            .map_err(|_| ImageGenerationAdapterError::InvalidConfiguration)?;
        Ok(Self {
            config,
            credential,
            client,
        })
    }

    /// Exact immutable non-secret configuration.
    #[must_use]
    pub const fn config(&self) -> &ImageGenerationConfig {
        &self.config
    }

    /// Sends one bounded non-streaming request and returns one validated raw JPEG envelope.
    ///
    /// Cancellation is checked immediately before the request is sent. Once dispatched, transport
    /// errors are classified as outcome-unknown because neither supported protocol exposes an
    /// idempotency or result-lookup contract.
    ///
    /// # Errors
    ///
    /// Returns [`ImageGenerationAdapterError`] for cancellation, argument drift, confirmed remote
    /// rejection, ambiguous transport failure, oversized responses, or invalid success evidence.
    pub fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<RemoteGeneratedImage, ImageGenerationAdapterError> {
        let normalized = normalize_image_generation_arguments(&self.config, arguments)
            .map_err(|_| ImageGenerationAdapterError::InvalidArguments)?;
        if cancellation.is_cancelled() {
            return Err(ImageGenerationAdapterError::CancelledBeforeDispatch);
        }
        let prompt = normalized
            .get("prompt")
            .and_then(Value::as_str)
            .ok_or(ImageGenerationAdapterError::InvalidArguments)?;
        let mut body = json!({
            "model": self.config.model(),
            "n": 1,
            "output_format": "jpeg",
            "prompt": prompt,
            "quality": self.config.quality(),
            "size": self.config.size(),
            "stream": false,
        });
        if self.config.protocol() == ImageGenerationProtocol::OpenRouterImages {
            body["provider"] = json!({"allow_fallbacks": false});
        }
        let endpoint = self
            .config
            .endpoint()
            .map_err(|_| ImageGenerationAdapterError::InvalidConfiguration)?;
        let mut request = self
            .client
            .post(endpoint)
            .header(CONTENT_TYPE, "application/json")
            .json(&body);
        if let Some(secret) = &self.credential {
            let mut authorization =
                HeaderValue::from_str(&format!("Bearer {}", secret.as_str()))
                    .map_err(|_| ImageGenerationAdapterError::InvalidConfiguration)?;
            authorization.set_sensitive(true);
            request = request.header(AUTHORIZATION, authorization);
        }
        let started = Instant::now();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ImageGenerationAdapterError::InvalidConfiguration)?;
        runtime.block_on(async {
            let response = request
                .send()
                .await
                .map_err(|_| ImageGenerationAdapterError::TransportOutcomeUnknown)?;
            self.parse_response(response, started).await
        })
    }

    async fn parse_response(
        &self,
        mut response: Response,
        started: Instant,
    ) -> Result<RemoteGeneratedImage, ImageGenerationAdapterError> {
        let status = response.status();
        let request_id = bounded_request_id(response.headers());
        let maximum_response_bytes = self
            .config
            .maximum_output_bytes()
            .saturating_mul(4)
            .div_ceil(3)
            .saturating_add(IMAGE_RESPONSE_ENVELOPE_BYTES);
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ImageGenerationAdapterError::TransportOutcomeUnknown)?
        {
            let next_size = u64::try_from(bytes.len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            if next_size > maximum_response_bytes {
                return Err(if status.is_success() {
                    ImageGenerationAdapterError::InvalidRemoteOutput
                } else if status.is_client_error() {
                    ImageGenerationAdapterError::ConfirmedRejected {
                        status: status.as_u16(),
                        code: None,
                    }
                } else {
                    ImageGenerationAdapterError::TransportOutcomeUnknown
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(classify_remote_error(status, &bytes));
        }
        let envelope = serde_json::from_slice::<ImageGenerationEnvelope>(&bytes)
            .map_err(|_| ImageGenerationAdapterError::InvalidRemoteOutput)?;
        if envelope.data.len() != 1 {
            return Err(ImageGenerationAdapterError::InvalidRemoteOutput);
        }
        let item = &envelope.data[0];
        if item
            .media_type
            .as_deref()
            .is_some_and(|media_type| !matches!(media_type, "image/jpeg" | "image/jpg"))
        {
            return Err(ImageGenerationAdapterError::InvalidRemoteOutput);
        }
        let image = BASE64_STANDARD
            .decode(&item.b64_json)
            .map_err(|_| ImageGenerationAdapterError::InvalidRemoteOutput)?;
        if BASE64_STANDARD.encode(&image) != item.b64_json
            || image.len() < 5
            || !image.starts_with(&[0xff, 0xd8, 0xff])
            || !image.ends_with(&[0xff, 0xd9])
            || u64::try_from(image.len()).unwrap_or(u64::MAX) > self.config.maximum_output_bytes()
        {
            return Err(ImageGenerationAdapterError::InvalidRemoteOutput);
        }
        let reported_cost_microunits = envelope
            .usage
            .and_then(|usage| usage.cost)
            .as_ref()
            .and_then(decimal_currency_to_microunits);
        if reported_cost_microunits.is_some_and(|cost| cost > self.config.maximum_cost_microunits())
        {
            return Err(ImageGenerationAdapterError::ReportedCostExceeded);
        }
        Ok(RemoteGeneratedImage {
            bytes: image,
            request_id,
            reported_cost_microunits,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

#[derive(Debug, Deserialize)]
struct ImageGenerationEnvelope {
    data: Vec<ImageGenerationItem>,
    #[serde(default)]
    usage: Option<ImageGenerationUsage>,
}

#[derive(Debug, Deserialize)]
struct ImageGenerationItem {
    b64_json: String,
    #[serde(default)]
    media_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImageGenerationUsage {
    #[serde(default)]
    cost: Option<Value>,
}

fn bounded_request_id(headers: &reqwest::header::HeaderMap) -> Option<String> {
    ["x-request-id", "request-id"]
        .into_iter()
        .filter_map(|name| headers.get(name))
        .find_map(|value| {
            value.to_str().ok().filter(|value| {
                !value.is_empty()
                    && value.len() <= 256
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
            })
        })
        .map(str::to_owned)
}

fn classify_remote_error(status: StatusCode, body: &[u8]) -> ImageGenerationAdapterError {
    if status.is_client_error() {
        ImageGenerationAdapterError::ConfirmedRejected {
            status: status.as_u16(),
            code: remote_error_code(body),
        }
    } else {
        ImageGenerationAdapterError::TransportOutcomeUnknown
    }
}

fn remote_error_code(body: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    value
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 128
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        .map(str::to_owned)
}

fn decimal_currency_to_microunits(value: &Value) -> Option<u64> {
    let text = match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        _ => return None,
    };
    if text.is_empty() || text.starts_with('-') || text.contains(['e', 'E']) {
        return None;
    }
    let (whole, fractional) = text.split_once('.').unwrap_or((&text, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > 6
    {
        return None;
    }
    let whole = whole.parse::<u64>().ok()?;
    let fractional = if fractional.is_empty() {
        0
    } else {
        let value = fractional.parse::<u64>().ok()?;
        value.checked_mul(10_u64.checked_pow(u32::try_from(6 - fractional.len()).ok()?)?)?
    };
    whole.checked_mul(1_000_000)?.checked_add(fractional)
}

/// Classified image-generation adapter failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ImageGenerationAdapterError {
    /// Adapter authority or credential state is invalid.
    #[error("image-generation adapter configuration is invalid")]
    InvalidConfiguration,
    /// Durable arguments do not match the configured generator.
    #[error("image-generation arguments are invalid")]
    InvalidArguments,
    /// Cancellation was observed before external dispatch.
    #[error("image generation was cancelled before dispatch")]
    CancelledBeforeDispatch,
    /// The remote service conclusively rejected the request without generating an image.
    #[error("image-generation provider rejected the request with HTTP {status}")]
    ConfirmedRejected {
        /// HTTP rejection status.
        status: u16,
        /// Stable provider error code, when safely available.
        code: Option<String>,
    },
    /// The external dispatch boundary may have been crossed without a provable result.
    #[error("image-generation transport outcome is unknown")]
    TransportOutcomeUnknown,
    /// A success response did not contain one bounded canonical JPEG envelope.
    #[error("image-generation provider returned invalid output")]
    InvalidRemoteOutput,
    /// A provider-reported charge exceeded the immutable approved ceiling.
    #[error("image-generation provider reported cost above the approved ceiling")]
    ReportedCostExceeded,
}

#[cfg(test)]
mod tests {
    use super::{
        ImageGenerationAdapter, ImageGenerationAdapterError, decimal_currency_to_microunits,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use mealy_application::{CancellationProbe, ImageGenerationConfig};
    use serde_json::{Value, json};
    use std::{
        io::{Read as _, Write as _},
        net::TcpListener,
        thread,
    };

    struct NeverCancelled;

    impl CancellationProbe for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    fn config(base_url: &str, protocol: &str) -> ImageGenerationConfig {
        serde_json::from_value(json!({
            "providerId": "local-images",
            "protocol": protocol,
            "baseUrl": base_url,
            "model": "fixture-image-model",
            "credential": null,
            "residency": "local",
            "size": "1024x1024",
            "quality": "low",
            "maximumCostMicrounits": 50_000,
            "maximumOutputBytes": 2_097_152,
            "timeoutMs": 5_000
        }))
        .expect("image config")
    }

    fn serve_once(response: String) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let address = listener.local_addr().expect("fixture address");
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4_096];
            loop {
                let read = socket.read(&mut buffer).expect("read request");
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    let header_end = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .expect("headers")
                        + 4;
                    if request.len() >= header_end + length {
                        break;
                    }
                }
            }
            socket
                .write_all(response.as_bytes())
                .expect("write response");
            String::from_utf8(request).expect("UTF-8 request")
        });
        (format!("http://{address}"), handle)
    }

    #[test]
    fn openrouter_request_is_pinned_and_success_is_bounded() {
        let jpeg = [0xff, 0xd8, 0xff, 0x00, 0xff, 0xd9];
        let body = json!({
            "data": [{
                "b64_json": BASE64_STANDARD.encode(jpeg),
                "media_type": "image/jpeg"
            }],
            "usage": {"cost": 0.04}
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-request-id: req_fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (base_url, server) = serve_once(response);
        let adapter = ImageGenerationAdapter::new(config(&base_url, "open_router_images"), None)
            .expect("adapter");
        let output = adapter
            .execute(&json!({"prompt": "A quiet harbor"}), &NeverCancelled)
            .expect("image response");
        assert_eq!(output.bytes(), jpeg);
        assert_eq!(output.request_id(), Some("req_fixture"));
        assert_eq!(output.reported_cost_microunits(), Some(40_000));
        let request = server.join().expect("server request");
        assert!(request.starts_with("POST /images HTTP/1.1\r\n"));
        assert!(request.contains("\"allow_fallbacks\":false"));
        assert!(request.contains("\"output_format\":\"jpeg\""));
        assert!(request.contains("\"stream\":false"));
    }

    #[test]
    fn confirmed_rejection_and_ambiguous_server_failure_are_distinct() {
        let rejected = json!({"error": {"code": "moderation_blocked"}}).to_string();
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{rejected}",
            rejected.len()
        );
        let (base_url, server) = serve_once(response);
        let adapter = ImageGenerationAdapter::new(config(&base_url, "open_ai_images"), None)
            .expect("adapter");
        assert_eq!(
            adapter.execute(&json!({"prompt": "A quiet harbor"}), &NeverCancelled),
            Err(ImageGenerationAdapterError::ConfirmedRejected {
                status: 400,
                code: Some("moderation_blocked".to_owned()),
            })
        );
        let _ = server.join().expect("rejection request");

        let response =
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (base_url, server) = serve_once(response.to_owned());
        let adapter = ImageGenerationAdapter::new(config(&base_url, "open_ai_images"), None)
            .expect("adapter");
        assert_eq!(
            adapter.execute(&json!({"prompt": "A quiet harbor"}), &NeverCancelled),
            Err(ImageGenerationAdapterError::TransportOutcomeUnknown)
        );
        let _ = server.join().expect("failure request");
    }

    #[test]
    fn decimal_cost_conversion_is_exact_and_bounded() {
        assert_eq!(decimal_currency_to_microunits(&json!(0.04)), Some(40_000));
        assert_eq!(
            decimal_currency_to_microunits(&Value::String("12.000001".to_owned())),
            Some(12_000_001)
        );
        assert_eq!(decimal_currency_to_microunits(&json!(1.000_000_1)), None);
        assert_eq!(decimal_currency_to_microunits(&json!(-1)), None);
    }
}
