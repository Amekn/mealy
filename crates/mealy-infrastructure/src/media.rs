use crate::is_trusted_system_executable;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use image::{
    DynamicImage, ImageDecoder as _, ImageFormat, ImageReader, Limits, codecs::jpeg::JpegEncoder,
    imageops::FilterType,
};
use mealy_application::MAXIMUM_PROVIDER_IMAGE_DIMENSION;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

const MEDIA_WORKER_ARGUMENT: &str = "--media-worker";
const MEDIA_SANDBOX_WORKER: &str = "/runtime/mealy-media-worker";
const MEDIA_PROTOCOL_VERSION: &str = "mealy.media-normalization.v1";
const MAXIMUM_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_CANONICAL_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_REQUEST_BYTES: usize = 3 * 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: usize = 3 * 1024 * 1024;
const MAXIMUM_STDERR_BYTES: usize = 8 * 1024;
const MAXIMUM_DIMENSION: u32 = 4_096;
const MAXIMUM_PIXELS: u64 = 16 * 1024 * 1024;
const MEDIA_WORKER_TIMEOUT: Duration = Duration::from_secs(20);
const MEDIA_WORKER_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// A metadata-free, content-addressed image produced by the isolated normalizer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalImage {
    media_type: String,
    width: u32,
    height: u32,
    sha256_digest: String,
    bytes: Vec<u8>,
}

impl CanonicalImage {
    /// Canonical provider-compatible media type.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Canonical decoded width.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Canonical decoded height.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// SHA-256 of the exact canonical bytes.
    #[must_use]
    pub fn sha256_digest(&self) -> &str {
        &self.sha256_digest
    }

    /// Exact canonical encoded bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Failure from the fail-closed media normalization boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MediaNormalizerError {
    /// The caller supplied an unsupported declaration or malformed/unsafe image.
    #[error("image input is invalid or unsupported")]
    InvalidInput,
    /// The isolated worker exceeded a hard resource or protocol bound.
    #[error("image normalization exceeded a resource bound")]
    ResourceLimitExceeded,
    /// The trusted worker, runtime, or sandbox identity is unavailable.
    #[error("isolated image normalizer is unavailable")]
    Unavailable,
    /// The operation exceeded its fixed deadline.
    #[error("image normalization timed out")]
    TimedOut,
}

/// Linux image normalizer that invokes an identity-pinned executable in a fresh Bubblewrap
/// namespace.
#[derive(Debug)]
pub struct LinuxBubblewrapMediaNormalizer {
    bubblewrap_path: PathBuf,
    worker_path: PathBuf,
    worker_digest: String,
    runtime_mounts: Vec<(PathBuf, PathBuf)>,
}

impl LinuxBubblewrapMediaNormalizer {
    /// Loads and probes an exact worker and trusted system Bubblewrap frontend.
    ///
    /// # Errors
    ///
    /// Returns [`MediaNormalizerError::Unavailable`] if either executable is redirected,
    /// untrusted, changes during construction, or cannot create the required empty-environment,
    /// no-network namespace.
    pub fn load(bubblewrap_path: &Path, worker_path: &Path) -> Result<Self, MediaNormalizerError> {
        if !cfg!(target_os = "linux") {
            return Err(MediaNormalizerError::Unavailable);
        }
        let bubblewrap_path = exact_canonical_file(bubblewrap_path)?;
        if !is_trusted_system_executable(&bubblewrap_path) {
            return Err(MediaNormalizerError::Unavailable);
        }
        let worker_path = exact_canonical_file(worker_path)?;
        let worker_digest = digest_file(&worker_path)?;
        let normalizer = Self {
            bubblewrap_path,
            worker_path,
            worker_digest,
            runtime_mounts: media_runtime_mounts(),
        };
        normalizer.probe()?;
        Ok(normalizer)
    }

    /// Normalizes one bounded PNG, JPEG, or WebP without decoding it in the daemon.
    ///
    /// The returned bytes are independently revalidated after the worker exits.
    ///
    /// # Errors
    ///
    /// Rejects unsupported media declarations, oversized or malformed inputs, animation,
    /// decompression hazards, worker identity drift, sandbox failure, and forged output.
    pub fn normalize(
        &self,
        claimed_media_type: &str,
        source: &[u8],
    ) -> Result<CanonicalImage, MediaNormalizerError> {
        validate_claimed_media_type(claimed_media_type)?;
        if source.is_empty() || source.len() > MAXIMUM_SOURCE_BYTES {
            return Err(MediaNormalizerError::ResourceLimitExceeded);
        }
        if digest_file(&self.worker_path)? != self.worker_digest {
            return Err(MediaNormalizerError::Unavailable);
        }
        let request = MediaWorkerRequest {
            protocol_version: MEDIA_PROTOCOL_VERSION.to_owned(),
            claimed_media_type: claimed_media_type.to_owned(),
            data_base64: BASE64_STANDARD.encode(source),
        };
        let request_bytes =
            serde_json::to_vec(&request).map_err(|_| MediaNormalizerError::Unavailable)?;
        if request_bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(MediaNormalizerError::ResourceLimitExceeded);
        }
        let mut child = self.spawn_worker()?;
        write_request(&mut child, &request_bytes)?;
        let output = wait_for_worker(child)?;
        validate_worker_response(&output)
    }

    fn probe(&self) -> Result<(), MediaNormalizerError> {
        let mut child = self.spawn_worker()?;
        write_request(&mut child, b"")?;
        let output = wait_for_worker(child)?;
        let response = serde_json::from_slice::<MediaWorkerResponse>(&output)
            .map_err(|_| MediaNormalizerError::Unavailable)?;
        if response.protocol_version == MEDIA_PROTOCOL_VERSION
            && response.result.is_none()
            && response.error == Some(MediaWorkerFailure::InvalidInput)
        {
            Ok(())
        } else {
            Err(MediaNormalizerError::Unavailable)
        }
    }

    fn spawn_worker(&self) -> Result<Child, MediaNormalizerError> {
        let mut command = Command::new(&self.bubblewrap_path);
        command.env_clear().args([
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--hostname",
            "mealy-media",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/runtime",
        ]);
        for (source, target) in &self.runtime_mounts {
            command.arg("--ro-bind").arg(source).arg(target);
        }
        command
            .arg("--ro-bind")
            .arg(&self.worker_path)
            .arg(MEDIA_SANDBOX_WORKER)
            .arg("--chdir")
            .arg("/tmp")
            .arg("--")
            .arg(MEDIA_SANDBOX_WORKER)
            .arg(MEDIA_WORKER_ARGUMENT)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| MediaNormalizerError::Unavailable)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MediaWorkerRequest {
    protocol_version: String,
    claimed_media_type: String,
    data_base64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MediaWorkerResponse {
    protocol_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<MediaWorkerResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<MediaWorkerFailure>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MediaWorkerResult {
    media_type: String,
    width: u32,
    height: u32,
    sha256_digest: String,
    size_bytes: usize,
    data_base64: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MediaWorkerFailure {
    InvalidInput,
    ResourceLimitExceeded,
    InternalFailure,
}

fn validate_worker_response(bytes: &[u8]) -> Result<CanonicalImage, MediaNormalizerError> {
    let response = serde_json::from_slice::<MediaWorkerResponse>(bytes)
        .map_err(|_| MediaNormalizerError::Unavailable)?;
    if response.protocol_version != MEDIA_PROTOCOL_VERSION {
        return Err(MediaNormalizerError::Unavailable);
    }
    match (response.result, response.error) {
        (None, Some(MediaWorkerFailure::InvalidInput)) => Err(MediaNormalizerError::InvalidInput),
        (None, Some(MediaWorkerFailure::ResourceLimitExceeded)) => {
            Err(MediaNormalizerError::ResourceLimitExceeded)
        }
        (Some(result), None) => validate_worker_result(result),
        _ => Err(MediaNormalizerError::Unavailable),
    }
}

fn validate_worker_result(
    result: MediaWorkerResult,
) -> Result<CanonicalImage, MediaNormalizerError> {
    if !matches!(result.media_type.as_str(), "image/png" | "image/jpeg")
        || result.width == 0
        || result.height == 0
        || result.width > MAXIMUM_PROVIDER_IMAGE_DIMENSION
        || result.height > MAXIMUM_PROVIDER_IMAGE_DIMENSION
        || result.size_bytes == 0
        || result.size_bytes > MAXIMUM_CANONICAL_BYTES
        || result.data_base64.len() > maximum_base64_length(MAXIMUM_CANONICAL_BYTES)
    {
        return Err(MediaNormalizerError::Unavailable);
    }
    let bytes = BASE64_STANDARD
        .decode(&result.data_base64)
        .map_err(|_| MediaNormalizerError::Unavailable)?;
    if bytes.len() != result.size_bytes
        || detect_media_type(&bytes).ok() != Some(result.media_type.as_str())
        || sha256_digest(&bytes) != result.sha256_digest
    {
        return Err(MediaNormalizerError::Unavailable);
    }
    let (width, height) = canonical_header_dimensions(&bytes, result.media_type.as_str())
        .ok_or(MediaNormalizerError::Unavailable)?;
    if width != result.width || height != result.height {
        return Err(MediaNormalizerError::Unavailable);
    }
    Ok(CanonicalImage {
        media_type: result.media_type,
        width,
        height,
        sha256_digest: result.sha256_digest,
        bytes,
    })
}

fn write_request(child: &mut Child, request: &[u8]) -> Result<(), MediaNormalizerError> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or(MediaNormalizerError::Unavailable)?;
    if stdin.write_all(request).is_err() {
        terminate_child(child);
        return Err(MediaNormalizerError::Unavailable);
    }
    drop(stdin);
    Ok(())
}

fn wait_for_worker(mut child: Child) -> Result<Vec<u8>, MediaNormalizerError> {
    let stdout = child
        .stdout
        .take()
        .ok_or(MediaNormalizerError::Unavailable)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(MediaNormalizerError::Unavailable)?;
    let stdout_thread = thread::spawn(move || read_bounded_stream(stdout, MAXIMUM_RESPONSE_BYTES));
    let stderr_thread = thread::spawn(move || read_bounded_stream(stderr, MAXIMUM_STDERR_BYTES));
    let started = Instant::now();
    let status = loop {
        if started.elapsed() >= MEDIA_WORKER_TIMEOUT {
            terminate_child(&mut child);
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(MediaNormalizerError::TimedOut);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(MEDIA_WORKER_POLL_INTERVAL),
            Err(_) => {
                terminate_child(&mut child);
                return Err(MediaNormalizerError::Unavailable);
            }
        }
    };
    let output = stdout_thread
        .join()
        .map_err(|_| MediaNormalizerError::Unavailable)??;
    let diagnostics = stderr_thread
        .join()
        .map_err(|_| MediaNormalizerError::Unavailable)??;
    if !status.success() || !diagnostics.is_empty() {
        return Err(MediaNormalizerError::Unavailable);
    }
    Ok(output)
}

fn read_bounded_stream(stream: impl Read, maximum: usize) -> Result<Vec<u8>, MediaNormalizerError> {
    let mut bytes = Vec::new();
    stream
        .take(u64::try_from(maximum.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| MediaNormalizerError::Unavailable)?;
    if bytes.len() > maximum {
        return Err(MediaNormalizerError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn exact_canonical_file(path: &Path) -> Result<PathBuf, MediaNormalizerError> {
    let canonical = fs::canonicalize(path).map_err(|_| MediaNormalizerError::Unavailable)?;
    let metadata =
        fs::symlink_metadata(&canonical).map_err(|_| MediaNormalizerError::Unavailable)?;
    if !metadata.is_file() {
        return Err(MediaNormalizerError::Unavailable);
    }
    Ok(canonical)
}

fn digest_file(path: &Path) -> Result<String, MediaNormalizerError> {
    let mut file = File::open(path).map_err(|_| MediaNormalizerError::Unavailable)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| MediaNormalizerError::Unavailable)?;
        if read == 0 {
            return Ok(encode_hex(&hasher.finalize()));
        }
        hasher.update(&buffer[..read]);
    }
}

fn media_runtime_mounts() -> Vec<(PathBuf, PathBuf)> {
    ["/usr/lib", "/usr/lib64", "/lib", "/lib64"]
        .into_iter()
        .filter_map(|target| {
            let requested = Path::new(target);
            requested
                .exists()
                .then(|| fs::canonicalize(requested).ok())
                .flatten()
                .map(|source| (source, PathBuf::from(target)))
        })
        .collect()
}

fn validate_claimed_media_type(media_type: &str) -> Result<(), MediaNormalizerError> {
    match media_type {
        "image/png" | "image/jpeg" | "image/webp" => Ok(()),
        _ => Err(MediaNormalizerError::InvalidInput),
    }
}

fn maximum_base64_length(bytes: usize) -> usize {
    bytes.saturating_add(2).saturating_div(3).saturating_mul(4)
}

fn sha256_digest(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Runs the isolated one-shot image normalization worker.
#[cfg(target_os = "linux")]
#[must_use]
pub fn media_worker_main() -> ExitCode {
    use rustix::process::{Resource, Rlimit, setrlimit};

    if std::env::args().nth(1).as_deref() != Some(MEDIA_WORKER_ARGUMENT) {
        return ExitCode::from(64);
    }
    std::panic::set_hook(Box::new(|_| {}));
    let limits = [
        (Resource::As, 256 * 1024 * 1024),
        (Resource::Core, 0),
        (Resource::Fsize, 0),
        (Resource::Nofile, 32),
        (Resource::Nproc, 1),
        (Resource::Cpu, 15),
    ];
    for (resource, maximum) in limits {
        if setrlimit(
            resource,
            Rlimit {
                current: Some(maximum),
                maximum: Some(maximum),
            },
        )
        .is_err()
        {
            return ExitCode::from(70);
        }
    }
    let outcome = std::panic::catch_unwind(run_media_worker)
        .unwrap_or(Err(MediaWorkerFailure::InternalFailure));
    let response = match outcome {
        Ok(result) => MediaWorkerResponse {
            protocol_version: MEDIA_PROTOCOL_VERSION.to_owned(),
            result: Some(result),
            error: None,
        },
        Err(error) => MediaWorkerResponse {
            protocol_version: MEDIA_PROTOCOL_VERSION.to_owned(),
            result: None,
            error: Some(error),
        },
    };
    let Ok(bytes) = serde_json::to_vec(&response) else {
        return ExitCode::from(70);
    };
    if bytes.len() > MAXIMUM_RESPONSE_BYTES
        || io::stdout().write_all(&bytes).is_err()
        || io::stdout().flush().is_err()
    {
        return ExitCode::from(70);
    }
    ExitCode::SUCCESS
}

/// Reports unsupported worker use outside the Linux production target.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn media_worker_main() -> ExitCode {
    ExitCode::from(69)
}

fn run_media_worker() -> Result<MediaWorkerResult, MediaWorkerFailure> {
    let mut input = Vec::new();
    io::stdin()
        .take(u64::try_from(MAXIMUM_REQUEST_BYTES.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut input)
        .map_err(|_| MediaWorkerFailure::InternalFailure)?;
    if input.is_empty() || input.len() > MAXIMUM_REQUEST_BYTES {
        return Err(if input.len() > MAXIMUM_REQUEST_BYTES {
            MediaWorkerFailure::ResourceLimitExceeded
        } else {
            MediaWorkerFailure::InvalidInput
        });
    }
    let request = serde_json::from_slice::<MediaWorkerRequest>(&input)
        .map_err(|_| MediaWorkerFailure::InvalidInput)?;
    if request.protocol_version != MEDIA_PROTOCOL_VERSION
        || validate_claimed_media_type(&request.claimed_media_type).is_err()
        || request.data_base64.len() > maximum_base64_length(MAXIMUM_SOURCE_BYTES)
    {
        return Err(MediaWorkerFailure::InvalidInput);
    }
    let source = BASE64_STANDARD
        .decode(request.data_base64)
        .map_err(|_| MediaWorkerFailure::InvalidInput)?;
    if source.is_empty() || source.len() > MAXIMUM_SOURCE_BYTES {
        return Err(MediaWorkerFailure::ResourceLimitExceeded);
    }
    normalize_image(&source, &request.claimed_media_type)
}

fn normalize_image(
    source: &[u8],
    claimed_media_type: &str,
) -> Result<MediaWorkerResult, MediaWorkerFailure> {
    let detected = detect_media_type(source).map_err(|_| MediaWorkerFailure::InvalidInput)?;
    if detected != claimed_media_type || contains_animation(source, detected)? {
        return Err(MediaWorkerFailure::InvalidInput);
    }
    let (width, height) =
        image_dimensions(source, detected).map_err(|_| MediaWorkerFailure::InvalidInput)?;
    if width == 0
        || height == 0
        || width > MAXIMUM_DIMENSION
        || height > MAXIMUM_DIMENSION
        || u64::from(width).saturating_mul(u64::from(height)) > MAXIMUM_PIXELS
    {
        return Err(MediaWorkerFailure::ResourceLimitExceeded);
    }
    let format = media_type_format(detected).ok_or(MediaWorkerFailure::InvalidInput)?;
    let mut reader = ImageReader::with_format(Cursor::new(source), format);
    reader.limits(decoder_limits());
    let decoded = reader
        .decode()
        .map_err(|_| MediaWorkerFailure::InvalidInput)?;
    let normalized =
        if width > MAXIMUM_PROVIDER_IMAGE_DIMENSION || height > MAXIMUM_PROVIDER_IMAGE_DIMENSION {
            decoded.resize(
                MAXIMUM_PROVIDER_IMAGE_DIMENSION,
                MAXIMUM_PROVIDER_IMAGE_DIMENSION,
                FilterType::Lanczos3,
            )
        } else {
            decoded
        };
    let canonical_width = normalized.width();
    let canonical_height = normalized.height();
    let (media_type, bytes) = encode_canonical(&normalized)?;
    if bytes.is_empty() || bytes.len() > MAXIMUM_CANONICAL_BYTES {
        return Err(MediaWorkerFailure::ResourceLimitExceeded);
    }
    Ok(MediaWorkerResult {
        media_type: media_type.to_owned(),
        width: canonical_width,
        height: canonical_height,
        sha256_digest: sha256_digest(&bytes),
        size_bytes: bytes.len(),
        data_base64: BASE64_STANDARD.encode(bytes),
    })
}

fn decoder_limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAXIMUM_DIMENSION);
    limits.max_image_height = Some(MAXIMUM_DIMENSION);
    limits.max_alloc = Some(96 * 1024 * 1024);
    limits
}

fn image_dimensions(bytes: &[u8], media_type: &str) -> Result<(u32, u32), image::ImageError> {
    let format = media_type_format(media_type).ok_or_else(|| {
        image::ImageError::Unsupported(image::error::UnsupportedError::from_format_and_kind(
            image::error::ImageFormatHint::Unknown,
            image::error::UnsupportedErrorKind::GenericFeature(
                "unsupported Mealy media type".to_owned(),
            ),
        ))
    })?;
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(decoder_limits());
    reader.into_decoder().map(|decoder| decoder.dimensions())
}

fn media_type_format(media_type: &str) -> Option<ImageFormat> {
    match media_type {
        "image/png" => Some(ImageFormat::Png),
        "image/jpeg" => Some(ImageFormat::Jpeg),
        "image/webp" => Some(ImageFormat::WebP),
        _ => None,
    }
}

fn detect_media_type(bytes: &[u8]) -> Result<&'static str, MediaWorkerFailure> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Ok("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Ok("image/jpeg")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Ok("image/webp")
    } else {
        Err(MediaWorkerFailure::InvalidInput)
    }
}

fn canonical_header_dimensions(bytes: &[u8], media_type: &str) -> Option<(u32, u32)> {
    match media_type {
        "image/png" => {
            if bytes.len() < 24
                || !bytes.starts_with(b"\x89PNG\r\n\x1a\n")
                || &bytes[8..12] != 13_u32.to_be_bytes().as_slice()
                || &bytes[12..16] != b"IHDR"
            {
                return None;
            }
            let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
            let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
            (width > 0 && height > 0).then_some((width, height))
        }
        "image/jpeg" => jpeg_header_dimensions(bytes),
        _ => None,
    }
}

fn jpeg_header_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if !bytes.starts_with(b"\xff\xd8\xff") {
        return None;
    }
    let mut offset = 2_usize;
    while offset < bytes.len() {
        if bytes[offset] != 0xff {
            return None;
        }
        while offset < bytes.len() && bytes[offset] == 0xff {
            offset = offset.checked_add(1)?;
        }
        let marker = *bytes.get(offset)?;
        offset = offset.checked_add(1)?;
        if marker == 0xd9 || marker == 0xda {
            return None;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length_end = offset.checked_add(2)?;
        let length = usize::from(u16::from_be_bytes(
            bytes.get(offset..length_end)?.try_into().ok()?,
        ));
        if length < 2 {
            return None;
        }
        let segment_end = offset.checked_add(length)?;
        if segment_end > bytes.len() {
            return None;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            if length < 7 {
                return None;
            }
            let height = u32::from(u16::from_be_bytes(
                bytes.get(offset + 3..offset + 5)?.try_into().ok()?,
            ));
            let width = u32::from(u16::from_be_bytes(
                bytes.get(offset + 5..offset + 7)?.try_into().ok()?,
            ));
            return (width > 0 && height > 0).then_some((width, height));
        }
        offset = segment_end;
    }
    None
}

fn contains_animation(bytes: &[u8], media_type: &str) -> Result<bool, MediaWorkerFailure> {
    match media_type {
        "image/png" => png_contains_animation(bytes),
        "image/webp" => webp_contains_animation(bytes),
        "image/jpeg" => Ok(false),
        _ => Err(MediaWorkerFailure::InvalidInput),
    }
}

fn png_contains_animation(bytes: &[u8]) -> Result<bool, MediaWorkerFailure> {
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(MediaWorkerFailure::InvalidInput);
    }
    let mut offset = 8_usize;
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .ok_or(MediaWorkerFailure::InvalidInput)?;
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| MediaWorkerFailure::InvalidInput)?,
        ) as usize;
        let kind = &bytes[offset + 4..header_end];
        let chunk_end = header_end
            .checked_add(length)
            .and_then(|end| end.checked_add(4))
            .filter(|end| *end <= bytes.len())
            .ok_or(MediaWorkerFailure::InvalidInput)?;
        if kind == b"acTL" {
            return Ok(true);
        }
        offset = chunk_end;
        if kind == b"IEND" {
            return Ok(false);
        }
    }
    Err(MediaWorkerFailure::InvalidInput)
}

fn webp_contains_animation(bytes: &[u8]) -> Result<bool, MediaWorkerFailure> {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return Err(MediaWorkerFailure::InvalidInput);
    }
    let declared = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| MediaWorkerFailure::InvalidInput)?,
    ) as usize;
    if declared.checked_add(8) != Some(bytes.len()) {
        return Err(MediaWorkerFailure::InvalidInput);
    }
    let mut offset = 12_usize;
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .ok_or(MediaWorkerFailure::InvalidInput)?;
        let kind = &bytes[offset..offset + 4];
        let length = u32::from_le_bytes(
            bytes[offset + 4..header_end]
                .try_into()
                .map_err(|_| MediaWorkerFailure::InvalidInput)?,
        ) as usize;
        let chunk_end = header_end
            .checked_add(length)
            .and_then(|end| end.checked_add(length % 2))
            .filter(|end| *end <= bytes.len())
            .ok_or(MediaWorkerFailure::InvalidInput)?;
        if kind == b"ANIM" || kind == b"ANMF" {
            return Ok(true);
        }
        if kind == b"VP8X" && length >= 1 && bytes[header_end] & 0x02 != 0 {
            return Ok(true);
        }
        offset = chunk_end;
    }
    Ok(false)
}

fn encode_canonical(image: &DynamicImage) -> Result<(&'static str, Vec<u8>), MediaWorkerFailure> {
    let mut bytes = Vec::new();
    if image.color().has_alpha() {
        image
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|_| MediaWorkerFailure::InternalFailure)?;
        Ok(("image/png", bytes))
    } else {
        JpegEncoder::new_with_quality(&mut bytes, 85)
            .encode_image(image)
            .map_err(|_| MediaWorkerFailure::InternalFailure)?;
        Ok(("image/jpeg", bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ExtendedColorType, ImageBuffer, Rgb, Rgba, codecs::webp::WebPEncoder};

    fn encode_png(width: u32, height: u32, alpha: bool) -> Vec<u8> {
        let image = if alpha {
            DynamicImage::ImageRgba8(ImageBuffer::from_pixel(
                width,
                height,
                Rgba([12, 34, 56, 128]),
            ))
        } else {
            DynamicImage::ImageRgb8(ImageBuffer::from_pixel(width, height, Rgb([12, 34, 56])))
        };
        let mut bytes = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .expect("PNG encodes");
        bytes
    }

    #[test]
    fn opaque_input_is_deterministic_metadata_free_jpeg() {
        let source = encode_png(2, 1, false);
        let first = normalize_image(&source, "image/png").expect("normalizes");
        let second = normalize_image(&source, "image/png").expect("normalizes");
        assert_eq!(first.sha256_digest, second.sha256_digest);
        assert_eq!(first.data_base64, second.data_base64);
        assert_eq!(first.media_type, "image/jpeg");
        assert_eq!((first.width, first.height), (2, 1));
        let canonical = BASE64_STANDARD
            .decode(&first.data_base64)
            .expect("canonical base64 decodes");
        assert_eq!(
            canonical_header_dimensions(&canonical, "image/jpeg"),
            Some((2, 1))
        );
    }

    #[test]
    fn still_webp_is_accepted_and_reencoded() {
        let mut source = Vec::new();
        WebPEncoder::new_lossless(&mut source)
            .encode(&[12, 34, 56], 1, 1, ExtendedColorType::Rgb8)
            .expect("WebP encodes");
        let result = normalize_image(&source, "image/webp").expect("normalizes");
        assert_eq!(result.media_type, "image/jpeg");
        assert_eq!((result.width, result.height), (1, 1));
    }

    #[test]
    fn alpha_input_remains_alpha_capable_png() {
        let source = encode_png(1, 1, true);
        let result = normalize_image(&source, "image/png").expect("normalizes");
        assert_eq!(result.media_type, "image/png");
        assert_eq!((result.width, result.height), (1, 1));
        let canonical = BASE64_STANDARD
            .decode(&result.data_base64)
            .expect("canonical base64 decodes");
        assert_eq!(
            canonical_header_dimensions(&canonical, "image/png"),
            Some((1, 1))
        );
    }

    #[test]
    fn declaration_mismatch_and_malformed_inputs_fail_closed() {
        let source = encode_png(1, 1, false);
        assert!(matches!(
            normalize_image(&source, "image/jpeg"),
            Err(MediaWorkerFailure::InvalidInput)
        ));
        assert!(matches!(
            normalize_image(b"not-an-image", "image/png"),
            Err(MediaWorkerFailure::InvalidInput)
        ));
    }

    #[test]
    fn apng_control_chunk_is_rejected_before_decode() {
        let source = encode_png(1, 1, true);
        let ihdr_end = 8 + 12 + 13;
        let mut crafted = source[..ihdr_end].to_vec();
        crafted.extend_from_slice(&8_u32.to_be_bytes());
        crafted.extend_from_slice(b"acTL");
        crafted.extend_from_slice(&1_u32.to_be_bytes());
        crafted.extend_from_slice(&0_u32.to_be_bytes());
        crafted.extend_from_slice(&0_u32.to_be_bytes());
        crafted.extend_from_slice(&source[ihdr_end..]);
        assert_eq!(
            png_contains_animation(&crafted),
            Ok(true),
            "animation is rejected before CRC/decode validation"
        );
    }

    #[test]
    fn animated_webp_flag_is_rejected_before_decode() {
        let mut crafted = Vec::new();
        crafted.extend_from_slice(b"RIFF");
        crafted.extend_from_slice(&22_u32.to_le_bytes());
        crafted.extend_from_slice(b"WEBPVP8X");
        crafted.extend_from_slice(&10_u32.to_le_bytes());
        crafted.extend_from_slice(&[0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(webp_contains_animation(&crafted), Ok(true));
    }

    #[test]
    fn jpeg_application_metadata_is_removed_by_reencoding() {
        let image = DynamicImage::ImageRgb8(ImageBuffer::from_pixel(1, 1, Rgb([12, 34, 56])));
        let mut encoded = Vec::new();
        JpegEncoder::new_with_quality(&mut encoded, 90)
            .encode_image(&image)
            .expect("JPEG encodes");
        let metadata = b"Exif\0\0private-location";
        let segment_length = u16::try_from(metadata.len() + 2).expect("metadata is bounded");
        let mut source = encoded[..2].to_vec();
        source.extend_from_slice(&[0xff, 0xe1]);
        source.extend_from_slice(&segment_length.to_be_bytes());
        source.extend_from_slice(metadata);
        source.extend_from_slice(&encoded[2..]);
        let result = normalize_image(&source, "image/jpeg").expect("normalizes");
        let canonical = BASE64_STANDARD
            .decode(result.data_base64)
            .expect("canonical base64 decodes");
        assert!(
            !canonical
                .windows(metadata.len())
                .any(|window| window == metadata)
        );
    }

    #[test]
    fn dimensions_are_bounded_before_full_decode() {
        let mut source = encode_png(1, 1, true);
        source[16..20].copy_from_slice(&4_097_u32.to_be_bytes());
        assert!(image_dimensions(&source, "image/png").is_err());
    }

    #[test]
    fn oversized_image_is_downscaled_to_canonical_boundary() {
        let source = encode_png(2_049, 1, false);
        let result = normalize_image(&source, "image/png").expect("normalizes");
        assert_eq!((result.width, result.height), (2_048, 1));
    }
}
