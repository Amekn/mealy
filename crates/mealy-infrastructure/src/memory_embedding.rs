use mealy_application::{
    MAXIMUM_MEMORY_EMBEDDING_BATCH, MAXIMUM_MEMORY_EMBEDDING_BATCH_BYTES,
    MAXIMUM_MEMORY_EMBEDDING_DIMENSIONS, MemoryEmbeddingConfig,
};
use reqwest::{
    StatusCode, Url,
    blocking::{Client, Response},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    thread,
    time::Duration,
};
use thiserror::Error;
use zeroize::Zeroizing;

const MAXIMUM_EMBEDDING_RESPONSE_BYTES: usize = 8 * 1_024 * 1_024;
const MEMORY_EMBEDDING_WORK_QUEUE_CAPACITY: usize = 4;

/// Bounded normalized semantic vector produced by one exact embedding configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryEmbedding {
    values: Vec<f32>,
}

impl MemoryEmbedding {
    /// Returns the L2-normalized finite vector values.
    #[must_use]
    pub fn values(&self) -> &[f32] {
        &self.values
    }
}

/// OpenAI-compatible embedding transport failure with no response body or credential content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MemoryEmbeddingError {
    /// Non-secret endpoint policy, credential state, request bounds, or dimensions are invalid.
    #[error("memory embedding configuration or request is invalid")]
    InvalidConfiguration,
    /// The configured endpoint could not complete a bounded request.
    #[error("memory embedding endpoint is unavailable")]
    Unavailable,
    /// The endpoint rejected authentication.
    #[error("memory embedding credential was rejected")]
    Unauthorized,
    /// The endpoint imposed a rate limit.
    #[error("memory embedding endpoint is rate limited")]
    RateLimited,
    /// The endpoint returned an incompatible, oversized, or numerically unsafe response.
    #[error("memory embedding response is invalid")]
    InvalidResponse,
}

/// No-proxy, no-redirect OpenAI-compatible adapter for optional derived memory vectors.
pub struct OpenAiCompatibleMemoryEmbedder {
    worker: SyncSender<EmbeddingWorkerRequest>,
    config_digest: String,
    dimensions: usize,
    document_prefix: String,
    query_prefix: String,
}

struct EmbeddingWorkerRequest {
    input: Vec<String>,
    response: SyncSender<Result<Vec<MemoryEmbedding>, MemoryEmbeddingError>>,
}

struct EmbeddingWorkerConfig {
    endpoint: Url,
    model: String,
    credential: Option<Zeroizing<String>>,
    dimensions: usize,
    request_timeout: Duration,
}

impl OpenAiCompatibleMemoryEmbedder {
    /// Builds an adapter from validated non-secret policy and an already-resolved credential.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryEmbeddingError::InvalidConfiguration`] when policy and credential state do
    /// not agree, or [`MemoryEmbeddingError::Unavailable`] when the bounded client cannot be built.
    pub fn new(
        config: &MemoryEmbeddingConfig,
        credential: Option<Zeroizing<String>>,
    ) -> Result<Self, MemoryEmbeddingError> {
        config
            .validate()
            .map_err(|_| MemoryEmbeddingError::InvalidConfiguration)?;
        if credential.as_deref().is_some_and(|value| {
            value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control)
        }) || (!config
            .is_local()
            .map_err(|_| MemoryEmbeddingError::InvalidConfiguration)?
            && credential.is_none())
        {
            return Err(MemoryEmbeddingError::InvalidConfiguration);
        }
        let endpoint = embeddings_url(config.base_url())?;
        let config_digest = config
            .digest()
            .map_err(|_| MemoryEmbeddingError::InvalidConfiguration)?;
        let dimensions = usize::try_from(config.dimensions())
            .map_err(|_| MemoryEmbeddingError::InvalidConfiguration)?;
        let worker_config = EmbeddingWorkerConfig {
            endpoint,
            model: config.model().to_owned(),
            credential,
            dimensions,
            request_timeout: Duration::from_millis(config.request_timeout_ms()),
        };
        let (worker, requests) = sync_channel(MEMORY_EMBEDDING_WORK_QUEUE_CAPACITY);
        let (initialization, initialized) = sync_channel(1);
        thread::Builder::new()
            .name("mealy-memory-embedding".to_owned())
            .spawn(move || embedding_worker(worker_config, requests, initialization))
            .map_err(|_| MemoryEmbeddingError::Unavailable)?;
        initialized
            .recv()
            .map_err(|_| MemoryEmbeddingError::Unavailable)??;
        Ok(Self {
            worker,
            config_digest,
            dimensions,
            document_prefix: config.document_prefix().to_owned(),
            query_prefix: config.query_prefix().to_owned(),
        })
    }

    /// Digest of the complete non-secret model, endpoint, prefix, dimensions, and privacy policy.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// Exact expected vector dimensions.
    #[must_use]
    pub fn dimensions(&self) -> u32 {
        u32::try_from(self.dimensions).unwrap_or(MAXIMUM_MEMORY_EMBEDDING_DIMENSIONS)
    }

    /// Embeds canonical memory documents in stable request order.
    ///
    /// # Errors
    ///
    /// Returns a classified bounded transport or response error. No error includes request text,
    /// response bodies, endpoint URLs, or credentials.
    pub fn embed_documents(
        &self,
        documents: &[String],
    ) -> Result<Vec<MemoryEmbedding>, MemoryEmbeddingError> {
        self.embed(documents, &self.document_prefix)
    }

    /// Embeds one owner-supplied retrieval query.
    ///
    /// # Errors
    ///
    /// Returns a classified bounded transport or response error. No error includes query text,
    /// response bodies, endpoint URLs, or credentials.
    pub fn embed_query(&self, query: &str) -> Result<MemoryEmbedding, MemoryEmbeddingError> {
        if query.is_empty() || query.len() > 4_096 || query.contains('\0') {
            return Err(MemoryEmbeddingError::InvalidConfiguration);
        }
        self.embed(&[query.to_owned()], &self.query_prefix)?
            .into_iter()
            .next()
            .ok_or(MemoryEmbeddingError::InvalidResponse)
    }

    fn embed(
        &self,
        values: &[String],
        prefix: &str,
    ) -> Result<Vec<MemoryEmbedding>, MemoryEmbeddingError> {
        if values.is_empty()
            || values.len() > MAXIMUM_MEMORY_EMBEDDING_BATCH
            || values
                .iter()
                .any(|value| value.is_empty() || value.contains('\0'))
        {
            return Err(MemoryEmbeddingError::InvalidConfiguration);
        }
        let prefixed = values
            .iter()
            .map(|value| {
                prefix
                    .len()
                    .checked_add(value.len())
                    .filter(|length| *length <= 65_792)
                    .map(|_| format!("{prefix}{value}"))
                    .ok_or(MemoryEmbeddingError::InvalidConfiguration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let total_bytes = prefixed.iter().try_fold(0usize, |total, value| {
            total
                .checked_add(value.len())
                .ok_or(MemoryEmbeddingError::InvalidConfiguration)
        })?;
        if total_bytes > MAXIMUM_MEMORY_EMBEDDING_BATCH_BYTES {
            return Err(MemoryEmbeddingError::InvalidConfiguration);
        }
        let (response, result) = sync_channel(1);
        self.worker
            .send(EmbeddingWorkerRequest {
                input: prefixed,
                response,
            })
            .map_err(|_| MemoryEmbeddingError::Unavailable)?;
        result
            .recv()
            .map_err(|_| MemoryEmbeddingError::Unavailable)?
    }
}

// These values intentionally cross into and remain owned by the isolated worker. In particular,
// borrowing the zeroizing credential or receiver from asynchronous daemon state would recreate the
// lifetime boundary this worker is designed to remove.
#[allow(clippy::needless_pass_by_value)]
fn embedding_worker(
    config: EmbeddingWorkerConfig,
    requests: Receiver<EmbeddingWorkerRequest>,
    initialization: SyncSender<Result<(), MemoryEmbeddingError>>,
) {
    let Ok(client) = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(config.request_timeout)
        .build()
    else {
        let _ = initialization.send(Err(MemoryEmbeddingError::Unavailable));
        return;
    };
    if initialization.send(Ok(())).is_err() {
        return;
    }
    while let Ok(request) = requests.recv() {
        let result = send_embedding_request(&client, &config, &request.input);
        let _ = request.response.send(result);
    }
}

fn send_embedding_request(
    client: &Client,
    config: &EmbeddingWorkerConfig,
    input: &[String],
) -> Result<Vec<MemoryEmbedding>, MemoryEmbeddingError> {
    let request = EmbeddingRequest {
        model: &config.model,
        input,
        encoding_format: "float",
    };
    let mut builder = client
        .post(config.endpoint.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&request);
    if let Some(credential) = config.credential.as_deref() {
        builder = builder.bearer_auth(credential);
    }
    let response = builder
        .send()
        .map_err(|_| MemoryEmbeddingError::Unavailable)?;
    parse_response(response, input.len(), config.dimensions, &config.model)
}

#[derive(Serialize)]
struct EmbeddingRequest<'a> {
    model: &'a str,
    input: &'a [String],
    encoding_format: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    object: Option<String>,
    #[serde(default)]
    usage: Option<EmbeddingUsage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingData {
    embedding: Vec<f32>,
    index: usize,
    #[serde(default)]
    object: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    total_tokens: Option<u64>,
}

fn embeddings_url(base_url: &str) -> Result<Url, MemoryEmbeddingError> {
    let value = format!("{}/embeddings", base_url.trim_end_matches('/'));
    Url::parse(&value).map_err(|_| MemoryEmbeddingError::InvalidConfiguration)
}

fn parse_response(
    response: Response,
    expected_count: usize,
    expected_dimensions: usize,
    expected_model: &str,
) -> Result<Vec<MemoryEmbedding>, MemoryEmbeddingError> {
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            return Err(MemoryEmbeddingError::Unauthorized);
        }
        StatusCode::TOO_MANY_REQUESTS => return Err(MemoryEmbeddingError::RateLimited),
        _ => return Err(MemoryEmbeddingError::Unavailable),
    }
    let declared_length = response
        .content_length()
        .and_then(|value| usize::try_from(value).ok());
    if declared_length.is_some_and(|length| length > MAXIMUM_EMBEDDING_RESPONSE_BYTES) {
        return Err(MemoryEmbeddingError::InvalidResponse);
    }
    let mut bytes = Vec::new();
    response
        .take(
            u64::try_from(MAXIMUM_EMBEDDING_RESPONSE_BYTES + 1)
                .map_err(|_| MemoryEmbeddingError::InvalidResponse)?,
        )
        .read_to_end(&mut bytes)
        .map_err(|_| MemoryEmbeddingError::Unavailable)?;
    if bytes.len() > MAXIMUM_EMBEDDING_RESPONSE_BYTES {
        return Err(MemoryEmbeddingError::InvalidResponse);
    }
    let decoded: EmbeddingResponse =
        serde_json::from_slice(&bytes).map_err(|_| MemoryEmbeddingError::InvalidResponse)?;
    if decoded.data.len() != expected_count
        || decoded
            .model
            .as_deref()
            .is_some_and(|model| model != expected_model)
        || decoded
            .object
            .as_deref()
            .is_some_and(|object| object != "list")
        || decoded.usage.as_ref().is_some_and(|usage| {
            usage
                .prompt_tokens
                .zip(usage.total_tokens)
                .is_some_and(|(prompt, total)| prompt > total)
        })
    {
        return Err(MemoryEmbeddingError::InvalidResponse);
    }
    let mut ordered = vec![None; expected_count];
    for item in decoded.data {
        if item.index >= expected_count
            || ordered[item.index].is_some()
            || item.embedding.len() != expected_dimensions
            || expected_dimensions == 0
            || expected_dimensions
                > usize::try_from(MAXIMUM_MEMORY_EMBEDDING_DIMENSIONS)
                    .map_err(|_| MemoryEmbeddingError::InvalidResponse)?
            || item
                .object
                .as_deref()
                .is_some_and(|object| object != "embedding")
        {
            return Err(MemoryEmbeddingError::InvalidResponse);
        }
        let normalized = normalize(item.embedding)?;
        ordered[item.index] = Some(MemoryEmbedding { values: normalized });
    }
    ordered
        .into_iter()
        .map(|value| value.ok_or(MemoryEmbeddingError::InvalidResponse))
        .collect()
}

#[allow(clippy::cast_possible_truncation)]
fn normalize(mut values: Vec<f32>) -> Result<Vec<f32>, MemoryEmbeddingError> {
    if values.iter().any(|value| !value.is_finite()) {
        return Err(MemoryEmbeddingError::InvalidResponse);
    }
    let norm_squared = values.iter().try_fold(0.0_f64, |total, value| {
        let next = total + f64::from(*value) * f64::from(*value);
        next.is_finite()
            .then_some(next)
            .ok_or(MemoryEmbeddingError::InvalidResponse)
    })?;
    if norm_squared <= f64::EPSILON {
        return Err(MemoryEmbeddingError::InvalidResponse);
    }
    let norm = norm_squared.sqrt();
    for value in &mut values {
        *value = (f64::from(*value) / norm) as f32;
        if !value.is_finite() {
            return Err(MemoryEmbeddingError::InvalidResponse);
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::{MemoryEmbeddingError, OpenAiCompatibleMemoryEmbedder};
    use mealy_application::MemoryEmbeddingConfig;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    use zeroize::Zeroizing;

    fn config(base_url: &str) -> MemoryEmbeddingConfig {
        serde_json::from_value(json!({
            "baseUrl": base_url,
            "model": "fixture-embedding",
            "residency": "owner_host",
            "dimensions": 3,
            "documentPrefix": "document: ",
            "queryPrefix": "query: ",
            "requestTimeoutMs": 5_000
        }))
        .expect("configuration")
    }

    #[test]
    fn adapter_preserves_order_normalizes_vectors_and_sends_prefixes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut request = [0_u8; 8_192];
            let read = socket.read(&mut request).expect("read");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("POST /v1/embeddings HTTP/1.1"));
            assert!(request.contains("\"document: alpha\""));
            assert!(request.contains("\"document: beta\""));
            let body = json!({
                "object": "list",
                "model": "fixture-embedding",
                "data": [
                    {"object": "embedding", "index": 1, "embedding": [0.0, 3.0, 4.0]},
                    {"object": "embedding", "index": 0, "embedding": [2.0, 0.0, 0.0]}
                ],
                "usage": {"prompt_tokens": 2, "total_tokens": 2}
            })
            .to_string();
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("response");
        });
        let adapter =
            OpenAiCompatibleMemoryEmbedder::new(&config(&format!("http://{address}/v1")), None)
                .expect("adapter");
        let vectors = adapter
            .embed_documents(&["alpha".to_owned(), "beta".to_owned()])
            .expect("vectors");
        assert_eq!(vectors[0].values(), &[1.0, 0.0, 0.0]);
        assert_eq!(vectors[1].values(), &[0.0, 0.6, 0.8]);
        server.join().expect("server");
    }

    #[test]
    fn adapter_rejects_dimension_drift_and_never_echoes_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut request = [0_u8; 8_192];
            let _ = socket.read(&mut request).expect("read");
            let body = json!({
                "data": [{"index": 0, "embedding": [1.0, 2.0]}],
                "model": "fixture-embedding"
            })
            .to_string();
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("response");
        });
        let secret = "credential-canary";
        let adapter = OpenAiCompatibleMemoryEmbedder::new(
            &config(&format!("http://{address}/v1")),
            Some(Zeroizing::new(secret.to_owned())),
        )
        .expect("adapter");
        let error = adapter.embed_query("alpha").expect_err("dimension drift");
        assert_eq!(error, MemoryEmbeddingError::InvalidResponse);
        assert!(!error.to_string().contains(secret));
        server.join().expect("server");
    }
}
