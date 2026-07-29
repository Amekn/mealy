//! Privacy-preserving, bounded OpenTelemetry export for Mealy.
//!
//! This crate intentionally does not bridge the general `tracing` stream.
//! Callers can record only the fixed event shapes exposed here, which prevents
//! prompts, responses, tool arguments, paths, errors, and arbitrary fields from
//! crossing the telemetry boundary.

use std::fmt;
use std::io::Read as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, MeterProvider as _};
use opentelemetry::trace::{Span as _, SpanKind, Status, Tracer as _, TracerProvider as _};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::transform::common::tonic::ResourceAttributesWithSchema;
use opentelemetry_proto::transform::trace::tonic::group_spans_by_resource_and_scope;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};
use opentelemetry_sdk::trace::{
    BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracer, SdkTracerProvider, SpanData,
    SpanExporter,
};
use prost::Message;
use reqwest::blocking::{Client as HttpClient, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::redirect::Policy as RedirectPolicy;
use thiserror::Error;
use url::{Host, Url};

const MINIMUM_EXPORT_INTERVAL: Duration = Duration::from_secs(1);
const MAXIMUM_EXPORT_INTERVAL: Duration = Duration::from_mins(5);
const MINIMUM_REQUEST_TIMEOUT: Duration = Duration::from_millis(100);
const MAXIMUM_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAXIMUM_IDENTIFIER_BYTES: usize = 128;
const MAXIMUM_EXPORT_BODY_BYTES: usize = 2 * 1_024 * 1_024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 64 * 1_024;
const TRACE_QUEUE_SIZE: usize = 1_024;
const TRACE_BATCH_SIZE: usize = 128;
const TELEMETRY_SCHEMA: &str = "mealy.telemetry.v1";
const PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";

/// Configuration failure or bounded exporter lifecycle failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TelemetryError {
    /// The OTLP root URL violates Mealy's transport policy.
    #[error("invalid OTLP endpoint: {0}")]
    InvalidEndpoint(&'static str),
    /// An interval or timeout is outside Mealy's fixed safety bounds.
    #[error("invalid telemetry configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// A canonical correlation identifier is malformed or unexpectedly large.
    #[error("invalid telemetry correlation identifier")]
    InvalidIdentifier,
    /// The bounded HTTP client could not be constructed.
    #[error("telemetry transport initialization failed")]
    TransportInitialization,
    /// A bounded flush or shutdown operation failed.
    #[error("telemetry lifecycle operation failed")]
    Lifecycle,
}

/// Explicit, environment-independent OTLP/HTTP configuration.
#[derive(Clone, Debug)]
pub struct TelemetryConfig {
    trace_endpoint: Url,
    metrics_endpoint: Url,
    export_interval: Duration,
    request_timeout: Duration,
}

impl TelemetryConfig {
    /// Validates an OTLP root and derives exact `/v1/traces` and `/v1/metrics` endpoints.
    ///
    /// Remote collectors require HTTPS. Clear-text HTTP is accepted only for a
    /// literal loopback IP with an explicit port.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] when the endpoint or numeric bounds are unsafe.
    pub fn new(
        endpoint: &str,
        export_interval: Duration,
        request_timeout: Duration,
    ) -> Result<Self, TelemetryError> {
        if !(MINIMUM_EXPORT_INTERVAL..=MAXIMUM_EXPORT_INTERVAL).contains(&export_interval) {
            return Err(TelemetryError::InvalidConfiguration(
                "export interval must be between 1 second and 5 minutes",
            ));
        }
        if !(MINIMUM_REQUEST_TIMEOUT..=MAXIMUM_REQUEST_TIMEOUT).contains(&request_timeout) {
            return Err(TelemetryError::InvalidConfiguration(
                "request timeout must be between 100 milliseconds and 30 seconds",
            ));
        }
        let root = validate_endpoint(endpoint)?;
        let trace_endpoint = root
            .join("v1/traces")
            .map_err(|_| TelemetryError::InvalidEndpoint("could not derive trace endpoint"))?;
        let metrics_endpoint = root
            .join("v1/metrics")
            .map_err(|_| TelemetryError::InvalidEndpoint("could not derive metrics endpoint"))?;
        Ok(Self {
            trace_endpoint,
            metrics_endpoint,
            export_interval,
            request_timeout,
        })
    }
}

/// Fixed result labels accepted by Mealy's agent-run telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AgentRunOutcome {
    /// One claimed execution slice reached a durable committed boundary.
    CommittedBoundary,
    /// The claimed execution slice observed and honored cancellation.
    Cancelled,
    /// The claimed execution slice failed.
    Failed,
}

impl AgentRunOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CommittedBoundary => "committed_boundary",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

/// Allowlisted correlation fields for one claimed agent-run execution slice.
///
/// The fields are private so future additions remain an explicit privacy and
/// compatibility decision.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct AgentRunContext {
    task_id: String,
    run_id: String,
    turn_id: String,
    session_id: String,
    correlation_id: String,
}

impl AgentRunContext {
    /// Constructs a context after validating every opaque identifier.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::InvalidIdentifier`] for control characters,
    /// whitespace, separators, non-ASCII text, or overlong values.
    pub fn new(
        task_id: impl Into<String>,
        run_id: impl Into<String>,
        turn_id: impl Into<String>,
        session_id: impl Into<String>,
        correlation_id: impl Into<String>,
    ) -> Result<Self, TelemetryError> {
        let context = Self {
            task_id: task_id.into(),
            run_id: run_id.into(),
            turn_id: turn_id.into(),
            session_id: session_id.into(),
            correlation_id: correlation_id.into(),
        };
        for value in [
            &context.task_id,
            &context.run_id,
            &context.turn_id,
            &context.session_id,
            &context.correlation_id,
        ] {
            validate_identifier(value)?;
        }
        Ok(context)
    }
}

/// Disabled or active bounded telemetry runtime.
pub struct TelemetryRuntime {
    state: TelemetryState,
}

enum TelemetryState {
    Disabled,
    Active(ActiveTelemetry),
}

struct ActiveTelemetry {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    tracer: SdkTracer,
    run_slices: Counter<u64>,
    run_slice_duration: Histogram<f64>,
}

impl fmt::Debug for TelemetryRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelemetryRuntime")
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

impl TelemetryRuntime {
    /// Returns a zero-I/O telemetry runtime.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            state: TelemetryState::Disabled,
        }
    }

    /// Builds bounded trace and metric pipelines from explicit configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] if the secure client cannot be initialized.
    pub fn new(config: &TelemetryConfig) -> Result<Self, TelemetryError> {
        let client = HttpClient::builder()
            .no_proxy()
            .redirect(RedirectPolicy::none())
            .connect_timeout(CONNECT_TIMEOUT.min(config.request_timeout))
            .timeout(config.request_timeout)
            .build()
            .map_err(|_| TelemetryError::TransportInitialization)?;

        let trace_exporter = SecureTraceExporter {
            transport: SecureOtlpTransport::new(client.clone(), config.trace_endpoint.clone()),
            resource: ResourceAttributesWithSchema::default(),
            shutdown: AtomicBool::new(false),
        };
        let batch_config = BatchConfigBuilder::default()
            .with_max_queue_size(TRACE_QUEUE_SIZE)
            .with_max_export_batch_size(TRACE_BATCH_SIZE)
            .with_max_concurrent_exports(1)
            .with_scheduled_delay(config.export_interval)
            .with_max_export_timeout(config.request_timeout)
            .build();
        let trace_processor = BatchSpanProcessor::builder(trace_exporter)
            .with_batch_config(batch_config)
            .build();
        let resource = telemetry_resource();
        let tracer_provider = SdkTracerProvider::builder()
            .with_sampler(Sampler::AlwaysOn)
            .with_span_processor(trace_processor)
            .with_resource(resource.clone())
            .build();
        let tracer = tracer_provider.tracer("mealy-observability");

        let metric_exporter = SecureMetricExporter {
            transport: SecureOtlpTransport::new(client, config.metrics_endpoint.clone()),
            shutdown: AtomicBool::new(false),
        };
        let metric_reader = PeriodicReader::builder(metric_exporter)
            .with_interval(config.export_interval)
            .build();
        let meter_provider = SdkMeterProvider::builder()
            .with_reader(metric_reader)
            .with_resource(resource)
            .build();
        let meter = meter_provider.meter("mealy-observability");
        let run_slices = meter
            .u64_counter("mealy.agent.run.slices")
            .with_description("Claimed agent-run execution slices by fixed outcome")
            .build();
        let run_slice_duration = meter
            .f64_histogram("mealy.agent.run.slice.duration")
            .with_description("Claimed agent-run execution slice duration")
            .with_unit("s")
            .build();

        Ok(Self {
            state: TelemetryState::Active(ActiveTelemetry {
                tracer_provider,
                meter_provider,
                tracer,
                run_slices,
                run_slice_duration,
            }),
        })
    }

    /// Reports whether an explicit exporter is active.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(self.state, TelemetryState::Active(_))
    }

    /// Records one allowlisted trace span and two low-cardinality measurements.
    ///
    /// No caller-provided text other than validated canonical IDs can enter the
    /// exporter. IDs are trace attributes only; metrics contain the fixed
    /// `outcome` label to avoid high-cardinality time series.
    pub fn record_agent_run(
        &self,
        context: &AgentRunContext,
        outcome: AgentRunOutcome,
        started_at: SystemTime,
        elapsed: Duration,
    ) {
        let TelemetryState::Active(active) = &self.state else {
            return;
        };
        let outcome_value = outcome.as_str();
        let mut span = active
            .tracer
            .span_builder("mealy.agent.run.slice")
            .with_kind(SpanKind::Internal)
            .with_start_time(started_at)
            .with_attributes([
                KeyValue::new("mealy.task.id", context.task_id.clone()),
                KeyValue::new("mealy.run.id", context.run_id.clone()),
                KeyValue::new("mealy.turn.id", context.turn_id.clone()),
                KeyValue::new("mealy.session.id", context.session_id.clone()),
                KeyValue::new("mealy.correlation.id", context.correlation_id.clone()),
                KeyValue::new("mealy.outcome", outcome_value),
            ])
            .start(&active.tracer);
        span.set_status(if outcome == AgentRunOutcome::Failed {
            Status::error("agent_run_failed")
        } else {
            Status::Ok
        });
        span.end_with_timestamp(
            started_at
                .checked_add(elapsed)
                .unwrap_or_else(SystemTime::now),
        );

        let labels = [KeyValue::new("outcome", outcome_value)];
        active.run_slices.add(1, &labels);
        active
            .run_slice_duration
            .record(elapsed.as_secs_f64(), &labels);
    }

    /// Forces pending traces and metrics through their bounded exporters.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Lifecycle`] if either pipeline cannot flush.
    pub fn force_flush(&self) -> Result<(), TelemetryError> {
        let TelemetryState::Active(active) = &self.state else {
            return Ok(());
        };
        active
            .tracer_provider
            .force_flush()
            .map_err(|_| TelemetryError::Lifecycle)?;
        active
            .meter_provider
            .force_flush()
            .map_err(|_| TelemetryError::Lifecycle)
    }

    /// Flushes and shuts down both bounded exporters.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Lifecycle`] if a provider cannot shut down.
    pub fn shutdown(&self) -> Result<(), TelemetryError> {
        let TelemetryState::Active(active) = &self.state else {
            return Ok(());
        };
        let trace_result = active
            .tracer_provider
            .shutdown_with_timeout(MAXIMUM_REQUEST_TIMEOUT);
        let metric_result = active
            .meter_provider
            .shutdown_with_timeout(MAXIMUM_REQUEST_TIMEOUT);
        if trace_result.is_err() || metric_result.is_err() {
            Err(TelemetryError::Lifecycle)
        } else {
            Ok(())
        }
    }
}

fn telemetry_resource() -> Resource {
    Resource::builder_empty()
        .with_attributes([
            KeyValue::new("service.name", "mealyd"),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("mealy.telemetry.schema", TELEMETRY_SCHEMA),
        ])
        .build()
}

fn validate_endpoint(endpoint: &str) -> Result<Url, TelemetryError> {
    let mut url = Url::parse(endpoint)
        .map_err(|_| TelemetryError::InvalidEndpoint("expected an absolute URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(TelemetryError::InvalidEndpoint(
            "URL credentials are forbidden",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(TelemetryError::InvalidEndpoint(
            "query and fragment components are forbidden",
        ));
    }
    if url.path() != "/" {
        return Err(TelemetryError::InvalidEndpoint(
            "configure the collector origin without a path",
        ));
    }
    let host = url
        .host()
        .ok_or(TelemetryError::InvalidEndpoint("host is required"))?;
    match url.scheme() {
        "https" => {}
        "http" => {
            let loopback = match host {
                Host::Ipv4(address) => address.is_loopback(),
                Host::Ipv6(address) => address.is_loopback(),
                Host::Domain(_) => false,
            };
            if !loopback {
                return Err(TelemetryError::InvalidEndpoint(
                    "clear-text HTTP requires a literal loopback IP",
                ));
            }
            if url.port().is_none() {
                return Err(TelemetryError::InvalidEndpoint(
                    "loopback HTTP requires an explicit port",
                ));
            }
        }
        _ => {
            return Err(TelemetryError::InvalidEndpoint(
                "only HTTPS and literal-loopback HTTP are supported",
            ));
        }
    }
    url.set_path("/");
    Ok(url)
}

fn validate_identifier(value: &str) -> Result<(), TelemetryError> {
    if value.is_empty()
        || value.len() > MAXIMUM_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(TelemetryError::InvalidIdentifier);
    }
    Ok(())
}

#[derive(Clone)]
struct SecureOtlpTransport {
    client: HttpClient,
    endpoint: Url,
}

impl fmt::Debug for SecureOtlpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecureOtlpTransport")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl SecureOtlpTransport {
    const fn new(client: HttpClient, endpoint: Url) -> Self {
        Self { client, endpoint }
    }

    fn send<M: OtlpResponse>(&self, body: Vec<u8>) -> OTelSdkResult {
        if body.len() > MAXIMUM_EXPORT_BODY_BYTES {
            return Err(sdk_error("export_body_limit"));
        }
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, PROTOBUF_CONTENT_TYPE)
            .header(ACCEPT, PROTOBUF_CONTENT_TYPE)
            .body(body)
            .send()
            .map_err(|_| sdk_error("transport"))?;
        decode_response::<M>(response)
    }
}

fn decode_response<M: OtlpResponse>(response: Response) -> OTelSdkResult {
    if !response.status().is_success() {
        return Err(sdk_error("collector_status"));
    }
    if let Some(length) = response.content_length()
        && length > u64::try_from(MAXIMUM_RESPONSE_BODY_BYTES).unwrap_or(u64::MAX)
    {
        return Err(sdk_error("response_body_limit"));
    }
    let content_type_is_protobuf = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        == Some(PROTOBUF_CONTENT_TYPE);
    let mut body = Vec::new();
    response
        .take(u64::try_from(MAXIMUM_RESPONSE_BODY_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut body)
        .map_err(|_| sdk_error("response_read"))?;
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(sdk_error("response_body_limit"));
    }
    if body.is_empty() {
        return Ok(());
    }
    if !content_type_is_protobuf {
        return Err(sdk_error("response_content_type"));
    }
    let decoded = M::decode(body.as_slice()).map_err(|_| sdk_error("response_protobuf"))?;
    if decoded.rejected_items() > 0 {
        return Err(sdk_error("collector_partial_rejection"));
    }
    Ok(())
}

fn sdk_error(code: &'static str) -> OTelSdkError {
    OTelSdkError::InternalFailure(code.to_owned())
}

trait OtlpResponse: Message + Default {
    fn rejected_items(&self) -> i64;
}

impl OtlpResponse for ExportTraceServiceResponse {
    fn rejected_items(&self) -> i64 {
        self.partial_success
            .as_ref()
            .map_or(0, |partial| partial.rejected_spans)
    }
}

impl OtlpResponse for ExportMetricsServiceResponse {
    fn rejected_items(&self) -> i64 {
        self.partial_success
            .as_ref()
            .map_or(0, |partial| partial.rejected_data_points)
    }
}

#[derive(Debug)]
struct SecureTraceExporter {
    transport: SecureOtlpTransport,
    resource: ResourceAttributesWithSchema,
    shutdown: AtomicBool,
}

impl SpanExporter for SecureTraceExporter {
    fn export(&self, batch: Vec<SpanData>) -> impl Future<Output = OTelSdkResult> + Send {
        let result = if self.shutdown.load(Ordering::Acquire) {
            Err(OTelSdkError::AlreadyShutdown)
        } else {
            let request = ExportTraceServiceRequest {
                resource_spans: group_spans_by_resource_and_scope(batch, &self.resource),
            };
            self.transport
                .send::<ExportTraceServiceResponse>(request.encode_to_vec())
        };
        std::future::ready(result)
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        self.shutdown.store(true, Ordering::Release);
        Ok(())
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.resource = resource.into();
    }
}

#[derive(Debug)]
struct SecureMetricExporter {
    transport: SecureOtlpTransport,
    shutdown: AtomicBool,
}

impl PushMetricExporter for SecureMetricExporter {
    fn export(&self, metrics: &ResourceMetrics) -> impl Future<Output = OTelSdkResult> + Send {
        let result = if self.shutdown.load(Ordering::Acquire) {
            Err(OTelSdkError::AlreadyShutdown)
        } else {
            let request = ExportMetricsServiceRequest::from(metrics);
            self.transport
                .send::<ExportMetricsServiceResponse>(request.encode_to_vec())
        };
        std::future::ready(result)
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        self.shutdown.store(true, Ordering::Release);
        Ok(())
    }

    fn temporality(&self) -> Temporality {
        Temporality::Cumulative
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    #[derive(Debug)]
    struct CapturedRequest {
        path: String,
        headers: String,
        body: Vec<u8>,
    }

    #[test]
    fn endpoint_policy_is_fail_closed() {
        for endpoint in [
            "http://localhost:4318",
            "http://127.0.0.1",
            "http://192.0.2.1:4318",
            "https://user:secret@example.com",
            "https://example.com/base",
            "https://example.com?header=secret",
            "file:///tmp/collector",
        ] {
            assert!(
                TelemetryConfig::new(endpoint, Duration::from_secs(10), Duration::from_secs(2),)
                    .is_err(),
                "{endpoint} should be rejected"
            );
        }
        for endpoint in [
            "http://127.0.0.1:4318",
            "http://[::1]:4318",
            "https://collector.example",
        ] {
            assert!(
                TelemetryConfig::new(endpoint, Duration::from_secs(10), Duration::from_secs(2),)
                    .is_ok(),
                "{endpoint} should be accepted"
            );
        }
    }

    #[test]
    fn identifiers_are_bounded_and_terminal_safe() {
        assert!(
            AgentRunContext::new("task_123", "run-123", "turn.123", "session:123", "corr_123",)
                .is_ok()
        );
        for invalid in ["", "contains space", "path/segment", "line\nbreak", "é"] {
            assert!(AgentRunContext::new(invalid, "run", "turn", "session", "corr").is_err());
        }
        assert!(
            AgentRunContext::new(
                "x".repeat(MAXIMUM_IDENTIFIER_BYTES + 1),
                "run",
                "turn",
                "session",
                "corr",
            )
            .is_err()
        );
    }

    #[test]
    fn disabled_runtime_has_no_lifecycle_or_recording_side_effects() {
        let runtime = TelemetryRuntime::disabled();
        let context =
            AgentRunContext::new("task", "run", "turn", "session", "corr").expect("valid context");
        runtime.record_agent_run(
            &context,
            AgentRunOutcome::CommittedBoundary,
            SystemTime::now(),
            Duration::from_millis(1),
        );
        runtime.force_flush().expect("disabled flush");
        runtime.shutdown().expect("disabled shutdown");
        assert!(!runtime.is_enabled());
    }

    #[test]
    fn wire_export_contains_only_allowlisted_data() {
        let (origin, receiver, server) = spawn_collector();
        let config = TelemetryConfig::new(&origin, Duration::from_mins(5), Duration::from_secs(2))
            .expect("valid collector");
        let runtime = TelemetryRuntime::new(&config).expect("telemetry runtime");
        let context = AgentRunContext::new(
            "task_safe",
            "run_safe",
            "turn_safe",
            "session_safe",
            "correlation_safe",
        )
        .expect("valid context");

        tracing::info!(
            private_canary = "PROMPT_CANARY_DO_NOT_EXPORT",
            "general tracing must stay outside the typed exporter"
        );
        runtime.record_agent_run(
            &context,
            AgentRunOutcome::CommittedBoundary,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            Duration::from_millis(25),
        );
        runtime.force_flush().expect("flush telemetry");
        runtime.shutdown().expect("shutdown telemetry");

        let requests = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("captured requests");
        server.join().expect("collector thread");
        assert!(requests.len() >= 2);
        let paths = requests
            .iter()
            .map(|request| request.path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(paths, BTreeSet::from(["/v1/metrics", "/v1/traces"]));
        for request in &requests {
            let lowercase_headers = request.headers.to_ascii_lowercase();
            assert!(lowercase_headers.contains("content-type: application/x-protobuf"));
            assert!(!lowercase_headers.contains("authorization:"));
            assert!(
                !request
                    .body
                    .windows(b"PROMPT_CANARY_DO_NOT_EXPORT".len())
                    .any(|window| window == b"PROMPT_CANARY_DO_NOT_EXPORT")
            );
        }

        let trace_request = requests
            .iter()
            .find(|request| request.path == "/v1/traces")
            .expect("trace request");
        let traces = ExportTraceServiceRequest::decode(trace_request.body.as_slice())
            .expect("trace protobuf");
        assert_eq!(traces.resource_spans.len(), 1);
        let resource_spans = &traces.resource_spans[0];
        let resource_keys = resource_spans
            .resource
            .as_ref()
            .expect("trace resource")
            .attributes
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            resource_keys,
            BTreeSet::from(["mealy.telemetry.schema", "service.name", "service.version",])
        );
        let spans = &resource_spans.scope_spans[0].spans;
        assert_eq!(spans.len(), 1);
        let attribute_keys = spans[0]
            .attributes
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            attribute_keys,
            BTreeSet::from([
                "mealy.correlation.id",
                "mealy.outcome",
                "mealy.run.id",
                "mealy.session.id",
                "mealy.task.id",
                "mealy.turn.id",
            ])
        );

        let metrics_request = requests
            .iter()
            .find(|request| request.path == "/v1/metrics")
            .expect("metrics request");
        let metrics = ExportMetricsServiceRequest::decode(metrics_request.body.as_slice())
            .expect("metrics protobuf");
        let metric_names = metrics.resource_metrics[0].scope_metrics[0]
            .metrics
            .iter()
            .map(|metric| metric.name.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            metric_names,
            BTreeSet::from(["mealy.agent.run.slice.duration", "mealy.agent.run.slices",])
        );
    }

    fn spawn_collector() -> (
        String,
        mpsc::Receiver<Vec<CapturedRequest>>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind collector");
        listener
            .set_nonblocking(true)
            .expect("nonblocking collector");
        let address = listener.local_addr().expect("collector address");
        let (sender, receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut last_request = Instant::now();
            let mut requests = Vec::new();
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        requests.push(read_request(stream));
                        last_request = Instant::now();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if requests.len() >= 2
                            && last_request.elapsed() >= Duration::from_millis(250)
                        {
                            break;
                        }
                        assert!(Instant::now() < deadline, "collector timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("collector accept failed: {error}"),
                }
            }
            sender.send(requests).expect("publish requests");
        });
        (format!("http://{address}"), receiver, server)
    }

    fn read_request(mut stream: TcpStream) -> CapturedRequest {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("request timeout");
        let mut request = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 4_096];
            let read = stream.read(&mut chunk).expect("read request");
            assert!(read > 0, "request ended before headers");
            request.extend_from_slice(&chunk[..read]);
            assert!(
                request.len() <= MAXIMUM_EXPORT_BODY_BYTES + 16 * 1_024,
                "request exceeded test bound"
            );
            if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers =
            String::from_utf8(request[..header_end].to_vec()).expect("ASCII request headers");
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
            .expect("content length header");
        while request.len() - header_end < content_length {
            let mut chunk = [0_u8; 4_096];
            let read = stream.read(&mut chunk).expect("read request body");
            assert!(read > 0, "request body ended early");
            request.extend_from_slice(&chunk[..read]);
        }
        let path = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("request path")
            .to_owned();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .expect("write response");
        CapturedRequest {
            path,
            headers,
            body: request[header_end..header_end + content_length].to_vec(),
        }
    }
}
