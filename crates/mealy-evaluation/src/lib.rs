//! Versioned, privacy-preserving public-API scenario evaluation for Mealy.
//!
//! The runner creates fresh sessions and observes canonical API projections. It
//! never reads daemon storage, resolves approvals, executes hidden provider
//! shortcuts, or copies prompt/response content into reports.

use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mealy_client::{ClientError, MealyClient};
use mealy_protocol::{
    API_VERSION, CreateSessionRequest, DeliveryMode, LocalConnectionInfo, ProviderSelectionCommand,
    SubmitInputRequest, TaskBudgetUsage, TaskResponse, TaskStatus, TimelineCursor, TimelineEvent,
    ValidationMethodResponse, ValidationOutcomeResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Accepted scenario-suite contract.
pub const EVALUATION_SUITE_VERSION: &str = "mealy.evaluation-suite.v1";
/// Emitted evaluation-report contract.
pub const EVALUATION_REPORT_VERSION: &str = "mealy.evaluation-report.v1";
/// Maximum UTF-8 bytes accepted for one scenario input.
pub const MAXIMUM_SCENARIO_INPUT_BYTES: usize = 256 * 1024;
/// Maximum number of cases in one suite.
pub const MAXIMUM_SCENARIO_CASES: usize = 128;
/// Maximum total timeline events retained while assessing one case.
pub const MAXIMUM_CASE_TIMELINE_EVENTS: usize = 50_000;

const MINIMUM_TIMEOUT_MS: u64 = 1_000;
const MAXIMUM_TIMEOUT_MS: u64 = 3_600_000;
const MINIMUM_POLL_INTERVAL_MS: u64 = 20;
const MAXIMUM_POLL_INTERVAL_MS: u64 = 5_000;
const MAXIMUM_IDENTIFIER_BYTES: usize = 128;
const MAXIMUM_DESCRIPTION_BYTES: usize = 4 * 1024;
const TIMELINE_PAGE_SIZE: usize = 1_000;

/// Strict versioned collection of public-API scenarios.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationSuite {
    /// Exact suite schema.
    pub contract_version: String,
    /// Stable bounded suite identity.
    pub suite_id: String,
    /// Optional operator-facing description; excluded from reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Ordered independent scenarios.
    pub cases: Vec<EvaluationCase>,
}

/// One independently isolated evaluation scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationCase {
    /// Stable identity unique within the suite.
    pub case_id: String,
    /// Private input admitted to a fresh session and never copied into the report.
    pub input: ScenarioInput,
    /// Expected canonical evidence and resource ceilings.
    pub expect: ScenarioExpectation,
    /// Maximum time to reach the expected settled state or any terminal state.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Bounded polling interval.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

/// One text input and optional exact provider/model selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScenarioInput {
    /// Non-empty bounded text sent through the normal input-admission API.
    pub content: String,
    /// Optional exact selection; omission uses the session's automatic route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_selection: Option<ProviderSelectionCommand>,
}

/// Assertions applied to canonical task and timeline evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScenarioExpectation {
    /// State at which the case may settle. Running/transitional states are invalid.
    #[serde(default = "default_terminal_status")]
    pub settled_status: TaskStatus,
    /// Optional private-content-safe final response assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_response: Option<FinalResponseExpectation>,
    /// Optional durable validation assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationExpectation>,
    /// Optional deterministic recorded-evidence replay assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayExpectation>,
    /// Event types that must occur within inclusive bounds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_events: Vec<EventCountExpectation>,
    /// Event types that must not occur.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_events: Vec<String>,
    /// Optional duration and usage ceilings.
    #[serde(default)]
    pub budgets: EvaluationBudgets,
}

/// Whether a canonical value must exist.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceExpectation {
    /// The value must be present.
    Present,
    /// The value must be absent.
    Absent,
}

/// Digest-only final response assertion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalResponseExpectation {
    /// Required response presence.
    pub presence: PresenceExpectation,
    /// Optional exact lowercase SHA-256 digest. Response text is never reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Expected durable validator projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidationExpectation {
    /// Whether a durable validation record must exist.
    pub presence: PresenceExpectation,
    /// Accepted outcomes when validation is present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<ValidationOutcomeResponse>,
    /// Accepted mechanisms when validation is present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<ValidationMethodResponse>,
}

/// Recorded-evidence replay assertions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayExpectation {
    /// Required value for replay evidence completeness.
    #[serde(default = "default_true")]
    pub evidence_complete: bool,
    /// Require replay to make zero live provider and tool calls.
    #[serde(default = "default_true")]
    pub zero_live_calls: bool,
    /// Require replay's final digest to equal the task projection.
    #[serde(default = "default_true")]
    pub final_digest_matches: bool,
}

/// Inclusive count bounds for one exact timeline event type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventCountExpectation {
    /// Exact stable event type.
    pub event_type: String,
    /// Inclusive minimum occurrence count.
    #[serde(default = "default_one")]
    pub minimum: u64,
    /// Optional inclusive maximum occurrence count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<u64>,
}

/// Optional regression ceilings. Omitted values are not asserted.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationBudgets {
    /// Maximum monotonic elapsed duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_duration_ms: Option<u64>,
    /// Maximum completed/charged model calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_model_calls: Option<u64>,
    /// Maximum prepared read-tool calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_tool_calls: Option<u64>,
    /// Maximum accepted delegated runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_delegated_runs: Option<u64>,
    /// Maximum classified retries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_retries: Option<u64>,
    /// Maximum recorded input tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_tokens: Option<u64>,
    /// Maximum recorded output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_output_tokens: Option<u64>,
    /// Maximum provider-neutral currency microunits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_cost_microunits: Option<u64>,
    /// Maximum recorded provider/tool output bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_output_bytes: Option<u64>,
}

/// Suite contract validation failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum SuiteValidationError {
    /// Contract version is not supported.
    #[error("unsupported evaluation suite contract version")]
    UnsupportedVersion,
    /// Suite or case identity is not safe and canonical.
    #[error("evaluation identifier is invalid")]
    InvalidIdentifier,
    /// Suite description is empty or oversized.
    #[error("evaluation suite description is invalid")]
    InvalidDescription,
    /// Case collection is empty, oversized, or contains duplicate identities.
    #[error("evaluation case collection is invalid")]
    InvalidCases,
    /// Scenario input violates the non-empty byte bound.
    #[error("evaluation scenario input is invalid")]
    InvalidInput,
    /// Timeout or polling interval violates fixed bounds.
    #[error("evaluation timing configuration is invalid")]
    InvalidTiming,
    /// Expected settled state is transient and cannot terminate a case.
    #[error("evaluation settled status is transient")]
    InvalidSettledStatus,
    /// A digest is not canonical lowercase SHA-256.
    #[error("evaluation response digest is invalid")]
    InvalidDigest,
    /// Validation presence and accepted values disagree.
    #[error("evaluation validation expectation is inconsistent")]
    InvalidValidationExpectation,
    /// Event name/count invariants are invalid or contradictory.
    #[error("evaluation event expectation is invalid")]
    InvalidEventExpectation,
    /// A duration ceiling exceeds the case timeout.
    #[error("evaluation duration budget exceeds the case timeout")]
    InvalidDurationBudget,
}

impl EvaluationSuite {
    /// Validates all semantic and resource bounds before any daemon call.
    ///
    /// # Errors
    ///
    /// Returns [`SuiteValidationError`] when the suite cannot be run safely.
    pub fn validate(&self) -> Result<(), SuiteValidationError> {
        if self.contract_version != EVALUATION_SUITE_VERSION {
            return Err(SuiteValidationError::UnsupportedVersion);
        }
        if !valid_identifier(&self.suite_id) {
            return Err(SuiteValidationError::InvalidIdentifier);
        }
        if self.description.as_ref().is_some_and(|description| {
            description.is_empty() || description.len() > MAXIMUM_DESCRIPTION_BYTES
        }) {
            return Err(SuiteValidationError::InvalidDescription);
        }
        if self.cases.is_empty() || self.cases.len() > MAXIMUM_SCENARIO_CASES {
            return Err(SuiteValidationError::InvalidCases);
        }
        let mut case_ids = BTreeSet::new();
        for case in &self.cases {
            if !valid_identifier(&case.case_id) {
                return Err(SuiteValidationError::InvalidIdentifier);
            }
            if !case_ids.insert(&case.case_id) {
                return Err(SuiteValidationError::InvalidCases);
            }
            validate_case(case)?;
        }
        Ok(())
    }

    /// Returns the SHA-256 digest of the validated typed suite.
    ///
    /// # Errors
    ///
    /// Returns a validation or serialization failure.
    pub fn digest(&self) -> Result<String, EvaluationError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        Ok(sha256_digest(&bytes))
    }
}

fn validate_case(case: &EvaluationCase) -> Result<(), SuiteValidationError> {
    if case.input.content.is_empty() || case.input.content.len() > MAXIMUM_SCENARIO_INPUT_BYTES {
        return Err(SuiteValidationError::InvalidInput);
    }
    if !(MINIMUM_TIMEOUT_MS..=MAXIMUM_TIMEOUT_MS).contains(&case.timeout_ms)
        || !(MINIMUM_POLL_INTERVAL_MS..=MAXIMUM_POLL_INTERVAL_MS).contains(&case.poll_interval_ms)
        || case.poll_interval_ms > case.timeout_ms
    {
        return Err(SuiteValidationError::InvalidTiming);
    }
    if matches!(
        case.expect.settled_status,
        TaskStatus::Queued | TaskStatus::Running | TaskStatus::Cancelling
    ) {
        return Err(SuiteValidationError::InvalidSettledStatus);
    }
    if let Some(expectation) = &case.expect.final_response {
        if expectation.presence == PresenceExpectation::Absent && expectation.sha256.is_some() {
            return Err(SuiteValidationError::InvalidDigest);
        }
        if expectation
            .sha256
            .as_deref()
            .is_some_and(|digest| !is_sha256_digest(digest))
        {
            return Err(SuiteValidationError::InvalidDigest);
        }
    }
    if let Some(expectation) = &case.expect.validation
        && expectation.presence == PresenceExpectation::Absent
        && (!expectation.outcomes.is_empty() || !expectation.methods.is_empty())
    {
        return Err(SuiteValidationError::InvalidValidationExpectation);
    }
    let mut required = BTreeSet::new();
    for event in &case.expect.required_events {
        if !valid_event_type(&event.event_type)
            || event.maximum.is_some_and(|maximum| maximum < event.minimum)
            || !required.insert(event.event_type.as_str())
        {
            return Err(SuiteValidationError::InvalidEventExpectation);
        }
    }
    let mut forbidden = BTreeSet::new();
    for event_type in &case.expect.forbidden_events {
        if !valid_event_type(event_type)
            || !forbidden.insert(event_type.as_str())
            || required.contains(event_type.as_str())
        {
            return Err(SuiteValidationError::InvalidEventExpectation);
        }
    }
    if case
        .expect
        .budgets
        .maximum_duration_ms
        .is_some_and(|maximum| maximum > case.timeout_ms)
    {
        return Err(SuiteValidationError::InvalidDurationBudget);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_event_type(value: &str) -> bool {
    valid_identifier(value)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn default_timeout_ms() -> u64 {
    120_000
}

const fn default_poll_interval_ms() -> u64 {
    100
}

const fn default_terminal_status() -> TaskStatus {
    TaskStatus::Succeeded
}

const fn default_true() -> bool {
    true
}

const fn default_one() -> u64 {
    1
}

/// Fixed pass/fail assertion emitted by the evaluator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationAssertion {
    /// Stable assertion identity.
    pub check: String,
    /// Whether observed canonical evidence satisfied the assertion.
    pub passed: bool,
    /// Fixed or numeric expected value.
    pub expected: Value,
    /// Fixed, numeric, digest, or absence marker. Never model-authored content.
    pub actual: Value,
}

/// Content-free citation for one observed event type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventEvidence {
    /// Occurrence count.
    pub count: u64,
    /// First matching canonical cursor.
    pub first_cursor: TimelineCursor,
    /// Last matching canonical cursor.
    pub last_cursor: TimelineCursor,
    /// First matching canonical event-envelope digest.
    pub first_digest: String,
    /// Last matching canonical event-envelope digest.
    pub last_digest: String,
}

/// Privacy-preserving evidence retained for one case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseEvidence {
    /// SHA-256 of private input bytes.
    pub input_digest: String,
    /// Fresh session created through the public API.
    pub session_id: String,
    /// Root task, if promotion became visible before timeout.
    pub task_id: Option<String>,
    /// Root run, if promotion became visible before timeout.
    pub run_id: Option<String>,
    /// Last observed task state.
    pub status: Option<TaskStatus>,
    /// Monotonic case duration.
    pub duration_ms: u64,
    /// Final response digest, never response text.
    pub final_digest: Option<String>,
    /// Durable success-criteria digest.
    pub success_criteria_digest: Option<String>,
    /// Durable validation identity.
    pub validation_id: Option<String>,
    /// Fresh validation context manifest.
    pub validation_context_manifest_id: Option<String>,
    /// Durable validation cursor.
    pub validation_cursor: Option<TimelineCursor>,
    /// Last observed structured usage.
    pub usage: Option<TaskBudgetUsage>,
    /// Highest fully read timeline cursor.
    pub timeline_high_watermark: TimelineCursor,
    /// Whether pagination reached a coherent end within the fixed event bound.
    pub timeline_complete: bool,
    /// Only event types referenced by the scenario, with payload-free citations.
    pub events: BTreeMap<String, EventEvidence>,
    /// Whether deterministic replay was available.
    pub replay_available: bool,
    /// Whether replay found complete recorded evidence.
    pub replay_evidence_complete: Option<bool>,
    /// Replay's final response digest.
    pub replay_final_digest: Option<String>,
    /// Live provider calls made by replay.
    pub replay_live_provider_calls: Option<u64>,
    /// Live tool calls made by replay.
    pub replay_live_tool_calls: Option<u64>,
}

/// Result of one scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationCaseReport {
    /// Stable suite-local identity.
    pub case_id: String,
    /// True only when every assertion passed.
    pub passed: bool,
    /// Ordered deterministic assertions.
    pub assertions: Vec<EvaluationAssertion>,
    /// Content-free canonical evidence.
    pub evidence: CaseEvidence,
}

/// Aggregate report counters.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationSummary {
    /// Total evaluated scenarios.
    pub total: u64,
    /// Scenarios whose assertions all passed.
    pub passed: u64,
    /// Scenarios with one or more failed assertions.
    pub failed: u64,
}

/// Versioned digest-bearing suite report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationReport {
    /// Exact report schema.
    pub contract_version: String,
    /// Stable evaluated suite identity.
    pub suite_id: String,
    /// SHA-256 of the validated typed suite, including private inputs.
    pub suite_digest: String,
    /// UTC start time in epoch milliseconds.
    pub started_at_ms: u64,
    /// UTC completion time in epoch milliseconds.
    pub completed_at_ms: u64,
    /// Ordered case reports.
    pub cases: Vec<EvaluationCaseReport>,
    /// Aggregate result.
    pub summary: EvaluationSummary,
    /// SHA-256 over all preceding typed report fields.
    pub report_digest: String,
}

/// Evaluation execution or report construction failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvaluationError {
    /// Suite failed strict preflight.
    #[error(transparent)]
    InvalidSuite(#[from] SuiteValidationError),
    /// Stable typed client failed.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// Clock cannot be represented by the report contract.
    #[error("system clock cannot be represented by the evaluation report")]
    Clock,
    /// Typed suite or report could not be serialized.
    #[error("evaluation contract serialization failed")]
    Serialization(#[from] serde_json::Error),
    /// Timeline exceeded the fixed evidence bound.
    #[error("evaluation timeline exceeded the fixed event bound")]
    TimelineTooLarge,
    /// Timeline pagination did not advance monotonically or contradicted its watermark.
    #[error("evaluation timeline pagination was inconsistent")]
    TimelineInconsistent,
}

/// Public-API runner bound to one already-authenticated typed client.
pub struct EvaluationRunner<'a> {
    client: &'a MealyClient,
}

impl<'a> EvaluationRunner<'a> {
    /// Constructs a runner. The caller retains credential ownership.
    #[must_use]
    pub const fn new(client: &'a MealyClient) -> Self {
        Self { client }
    }

    /// Runs all cases sequentially through fresh public sessions.
    ///
    /// The runner deliberately does not resolve approvals. A timeout or unexpected
    /// settled state becomes failed report evidence; transport and contract failures
    /// abort without fabricating results.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationError`] for invalid contracts, client failures, clock
    /// failure, oversized timelines, or report encoding failure.
    pub fn run(&self, suite: &EvaluationSuite) -> Result<EvaluationReport, EvaluationError> {
        suite.validate()?;
        let suite_digest = suite.digest()?;
        let started_at_ms = now_ms()?;
        let mut cases = Vec::with_capacity(suite.cases.len());
        for case in &suite.cases {
            cases.push(self.run_case(case, &suite_digest)?);
        }
        let completed_at_ms = now_ms()?;
        build_report(
            suite.suite_id.clone(),
            suite_digest,
            started_at_ms,
            completed_at_ms,
            cases,
        )
    }

    fn run_case(
        &self,
        case: &EvaluationCase,
        suite_digest: &str,
    ) -> Result<EvaluationCaseReport, EvaluationError> {
        let started = Instant::now();
        let session = self.client.create_session(&CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: case.input.provider_selection.clone(),
        })?;
        let input_digest = sha256_digest(case.input.content.as_bytes());
        let idempotency_key = format!(
            "eval:{}:{}",
            &suite_digest[..16],
            sha256_digest(case.case_id.as_bytes())[..16].to_owned()
        );
        let admission = self.client.submit_input(
            &session.session_id,
            &SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key,
                delivery_mode: DeliveryMode::Queue,
                content: case.input.content.clone(),
                provider_selection: case.input.provider_selection.clone(),
            },
        )?;
        let timeout = Duration::from_millis(case.timeout_ms);
        let poll = Duration::from_millis(case.poll_interval_ms);
        let mut task_id = None;
        let mut last_task = None;
        while started.elapsed() < timeout {
            if task_id.is_none() {
                let page = self.client.timeline(
                    &session.session_id,
                    Some(admission.cursor),
                    TIMELINE_PAGE_SIZE,
                )?;
                task_id = page
                    .events
                    .iter()
                    .find(|event| event.event_type == "task.created")
                    .map(|event| event.aggregate_id.clone());
            }
            if let Some(id) = task_id.as_deref() {
                let task = self.client.task(id)?;
                let settled = task.status == case.expect.settled_status
                    || matches!(
                        task.status,
                        TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled
                    );
                last_task = Some(task);
                if settled {
                    break;
                }
            }
            thread::sleep(poll);
        }
        if let Some(id) = task_id.as_deref()
            && last_task.is_none()
        {
            last_task = Some(self.client.task(id)?);
        }
        let (timeline_events, high_watermark, timeline_complete) =
            self.read_complete_timeline(&session.session_id, admission.cursor)?;
        let replay = if let Some(task) = &last_task
            && matches!(
                task.status,
                TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled
            ) {
            Some(self.client.task_replay(&task.task_id)?)
        } else {
            None
        };
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(evaluate_case(
            case,
            CaseObservation {
                input_digest,
                session_id: session.session_id,
                duration_ms,
                task: last_task,
                replay,
                timeline_events,
                timeline_high_watermark: high_watermark,
                timeline_complete,
            },
        ))
    }

    fn read_complete_timeline(
        &self,
        session_id: &str,
        after: TimelineCursor,
    ) -> Result<(Vec<TimelineEvent>, TimelineCursor, bool), EvaluationError> {
        let mut cursor = after;
        let mut events = Vec::new();
        loop {
            let page = self
                .client
                .timeline(session_id, Some(cursor), TIMELINE_PAGE_SIZE)?;
            if events.len().saturating_add(page.events.len()) > MAXIMUM_CASE_TIMELINE_EVENTS {
                return Err(EvaluationError::TimelineTooLarge);
            }
            if page.high_watermark < cursor
                || page
                    .events
                    .first()
                    .is_some_and(|event| event.cursor <= cursor)
                || page
                    .events
                    .windows(2)
                    .any(|pair| pair[0].cursor >= pair[1].cursor)
                || page
                    .events
                    .last()
                    .is_some_and(|event| event.cursor > page.high_watermark)
                || (page.has_more && page.events.is_empty())
            {
                return Err(EvaluationError::TimelineInconsistent);
            }
            if let Some(last) = page.events.last() {
                cursor = last.cursor;
            }
            events.extend(page.events);
            if !page.has_more {
                return Ok((events, page.high_watermark, true));
            }
        }
    }
}

/// Creates a secure typed client from one already-protected connection descriptor
/// and runs the suite.
///
/// This convenience boundary is suitable for a blocking worker thread. It keeps
/// construction and destruction of the blocking HTTP client outside async runtimes.
///
/// # Errors
///
/// Returns [`EvaluationError`] for client construction, contract, execution, or
/// report failures.
pub fn run_suite(
    connection: &LocalConnectionInfo,
    suite: &EvaluationSuite,
) -> Result<EvaluationReport, EvaluationError> {
    let client = MealyClient::from_connection(connection)?;
    EvaluationRunner::new(&client).run(suite)
}

struct CaseObservation {
    input_digest: String,
    session_id: String,
    duration_ms: u64,
    task: Option<TaskResponse>,
    replay: Option<mealy_protocol::TaskReplayResponse>,
    timeline_events: Vec<TimelineEvent>,
    timeline_high_watermark: TimelineCursor,
    timeline_complete: bool,
}

fn evaluate_case(case: &EvaluationCase, observation: CaseObservation) -> EvaluationCaseReport {
    let mut assertions = Vec::new();
    let task = observation.task.as_ref();
    push_assertion(
        &mut assertions,
        "task.settled_status",
        json!(case.expect.settled_status),
        task.map_or(Value::Null, |task| json!(task.status)),
        task.is_some_and(|task| task.status == case.expect.settled_status),
    );
    evaluate_final_response(case, task, &mut assertions);
    evaluate_validation(case, task, &mut assertions);
    evaluate_replay(case, task, observation.replay.as_ref(), &mut assertions);
    evaluate_events(case, &observation, &mut assertions);
    evaluate_budgets(
        &case.expect.budgets,
        observation.duration_ms,
        task.map(|task| &task.usage),
        &mut assertions,
    );
    let passed = assertions.iter().all(|assertion| assertion.passed);
    EvaluationCaseReport {
        case_id: case.case_id.clone(),
        passed,
        assertions,
        evidence: build_case_evidence(case, observation),
    }
}

fn evaluate_final_response(
    case: &EvaluationCase,
    task: Option<&TaskResponse>,
    assertions: &mut Vec<EvaluationAssertion>,
) {
    let Some(expectation) = &case.expect.final_response else {
        return;
    };
    let present = task.and_then(|task| task.final_digest.as_ref()).is_some();
    let expected_present = expectation.presence == PresenceExpectation::Present;
    push_assertion(
        assertions,
        "task.final_response_presence",
        json!(expected_present),
        json!(present),
        present == expected_present,
    );
    if let Some(expected_digest) = &expectation.sha256 {
        let actual = task.and_then(|task| task.final_digest.clone());
        push_assertion(
            assertions,
            "task.final_response_digest",
            json!(expected_digest),
            actual.as_ref().map_or(Value::Null, |digest| json!(digest)),
            actual.as_deref() == Some(expected_digest),
        );
    }
}

fn evaluate_events(
    case: &EvaluationCase,
    observation: &CaseObservation,
    assertions: &mut Vec<EvaluationAssertion>,
) {
    let event_counts = count_events(&observation.timeline_events);
    for expectation in &case.expect.required_events {
        let actual = event_counts
            .get(&expectation.event_type)
            .copied()
            .unwrap_or_default();
        let passed = actual >= expectation.minimum
            && expectation.maximum.is_none_or(|maximum| actual <= maximum);
        push_assertion(
            assertions,
            &format!("timeline.required:{}", expectation.event_type),
            json!({"minimum": expectation.minimum, "maximum": expectation.maximum}),
            json!(actual),
            passed,
        );
    }
    for event_type in &case.expect.forbidden_events {
        let actual = event_counts.get(event_type).copied().unwrap_or_default();
        push_assertion(
            assertions,
            &format!("timeline.forbidden:{event_type}"),
            json!(0),
            json!(actual),
            actual == 0,
        );
    }
    push_assertion(
        assertions,
        "timeline.complete",
        json!(true),
        json!(observation.timeline_complete),
        observation.timeline_complete,
    );
}

fn build_case_evidence(case: &EvaluationCase, observation: CaseObservation) -> CaseEvidence {
    let task = observation.task.as_ref();
    let relevant_event_types = case
        .expect
        .required_events
        .iter()
        .map(|event| event.event_type.as_str())
        .chain(case.expect.forbidden_events.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let events = relevant_event_types
        .into_iter()
        .filter_map(|event_type| {
            event_evidence(&observation.timeline_events, event_type)
                .map(|evidence| (event_type.to_owned(), evidence))
        })
        .collect();
    CaseEvidence {
        input_digest: observation.input_digest,
        session_id: observation.session_id,
        task_id: task.map(|task| task.task_id.clone()),
        run_id: task.map(|task| task.run_id.clone()),
        status: task.map(|task| task.status),
        duration_ms: observation.duration_ms,
        final_digest: task.and_then(|task| task.final_digest.clone()),
        success_criteria_digest: task.map(|task| task.success_criteria.criteria_digest.clone()),
        validation_id: task
            .and_then(|task| task.validation.as_ref())
            .map(|validation| validation.validation_id.clone()),
        validation_context_manifest_id: task
            .and_then(|task| task.validation.as_ref())
            .map(|validation| validation.context_manifest_id.clone()),
        validation_cursor: task
            .and_then(|task| task.validation.as_ref())
            .map(|validation| validation.cursor),
        usage: task.map(|task| task.usage),
        timeline_high_watermark: observation.timeline_high_watermark,
        timeline_complete: observation.timeline_complete,
        events,
        replay_available: observation.replay.is_some(),
        replay_evidence_complete: observation
            .replay
            .as_ref()
            .map(|replay| replay.evidence_complete),
        replay_final_digest: observation
            .replay
            .as_ref()
            .and_then(|replay| replay.final_digest.clone()),
        replay_live_provider_calls: observation
            .replay
            .as_ref()
            .map(|replay| replay.live_provider_calls),
        replay_live_tool_calls: observation
            .replay
            .as_ref()
            .map(|replay| replay.live_tool_calls),
    }
}

fn evaluate_validation(
    case: &EvaluationCase,
    task: Option<&TaskResponse>,
    assertions: &mut Vec<EvaluationAssertion>,
) {
    let Some(expectation) = &case.expect.validation else {
        return;
    };
    let validation = task.and_then(|task| task.validation.as_ref());
    let present = validation.is_some();
    let expected_present = expectation.presence == PresenceExpectation::Present;
    push_assertion(
        assertions,
        "validation.presence",
        json!(expected_present),
        json!(present),
        present == expected_present,
    );
    if !expectation.outcomes.is_empty() {
        let actual = validation.map(|validation| validation.outcome);
        push_assertion(
            assertions,
            "validation.outcome",
            json!(expectation.outcomes),
            actual.map_or(Value::Null, |outcome| json!(outcome)),
            actual.is_some_and(|outcome| expectation.outcomes.contains(&outcome)),
        );
    }
    if !expectation.methods.is_empty() {
        let actual = validation.map(|validation| validation.method);
        push_assertion(
            assertions,
            "validation.method",
            json!(expectation.methods),
            actual.map_or(Value::Null, |method| json!(method)),
            actual.is_some_and(|method| expectation.methods.contains(&method)),
        );
    }
}

fn evaluate_replay(
    case: &EvaluationCase,
    task: Option<&TaskResponse>,
    replay: Option<&mealy_protocol::TaskReplayResponse>,
    assertions: &mut Vec<EvaluationAssertion>,
) {
    let Some(expectation) = &case.expect.replay else {
        return;
    };
    push_assertion(
        assertions,
        "replay.available",
        json!(true),
        json!(replay.is_some()),
        replay.is_some(),
    );
    let Some(replay) = replay else {
        return;
    };
    push_assertion(
        assertions,
        "replay.evidence_complete",
        json!(expectation.evidence_complete),
        json!(replay.evidence_complete),
        replay.evidence_complete == expectation.evidence_complete,
    );
    if expectation.zero_live_calls {
        let actual = replay
            .live_provider_calls
            .saturating_add(replay.live_tool_calls);
        push_assertion(
            assertions,
            "replay.live_calls",
            json!(0),
            json!(actual),
            actual == 0,
        );
    }
    if expectation.final_digest_matches {
        let task_digest = task.and_then(|task| task.final_digest.as_deref());
        push_assertion(
            assertions,
            "replay.final_digest_matches",
            task_digest.map_or(Value::Null, |digest| json!(digest)),
            replay
                .final_digest
                .as_deref()
                .map_or(Value::Null, |digest| json!(digest)),
            task_digest == replay.final_digest.as_deref(),
        );
    }
}

fn evaluate_budgets(
    budgets: &EvaluationBudgets,
    duration_ms: u64,
    usage: Option<&TaskBudgetUsage>,
    assertions: &mut Vec<EvaluationAssertion>,
) {
    push_maximum(
        assertions,
        "budget.duration_ms",
        budgets.maximum_duration_ms,
        Some(duration_ms),
    );
    push_maximum(
        assertions,
        "budget.model_calls",
        budgets.maximum_model_calls,
        usage.map(|usage| usage.used_model_calls),
    );
    push_maximum(
        assertions,
        "budget.tool_calls",
        budgets.maximum_tool_calls,
        usage.map(|usage| usage.used_tool_calls),
    );
    push_maximum(
        assertions,
        "budget.delegated_runs",
        budgets.maximum_delegated_runs,
        usage.map(|usage| usage.used_delegated_runs),
    );
    push_maximum(
        assertions,
        "budget.retries",
        budgets.maximum_retries,
        usage.map(|usage| usage.used_retries),
    );
    push_maximum(
        assertions,
        "budget.input_tokens",
        budgets.maximum_input_tokens,
        usage.map(|usage| usage.used_input_tokens),
    );
    push_maximum(
        assertions,
        "budget.output_tokens",
        budgets.maximum_output_tokens,
        usage.map(|usage| usage.used_output_tokens),
    );
    push_maximum(
        assertions,
        "budget.cost_microunits",
        budgets.maximum_cost_microunits,
        usage.map(|usage| usage.used_cost_microunits),
    );
    push_maximum(
        assertions,
        "budget.output_bytes",
        budgets.maximum_output_bytes,
        usage.map(|usage| usage.used_output_bytes),
    );
}

fn push_maximum(
    assertions: &mut Vec<EvaluationAssertion>,
    check: &str,
    maximum: Option<u64>,
    actual: Option<u64>,
) {
    let Some(maximum) = maximum else {
        return;
    };
    push_assertion(
        assertions,
        check,
        json!({"maximum": maximum}),
        actual.map_or(Value::Null, |value| json!(value)),
        actual.is_some_and(|value| value <= maximum),
    );
}

fn push_assertion(
    assertions: &mut Vec<EvaluationAssertion>,
    check: &str,
    expected: Value,
    actual: Value,
    passed: bool,
) {
    assertions.push(EvaluationAssertion {
        check: check.to_owned(),
        passed,
        expected,
        actual,
    });
}

fn count_events(events: &[TimelineEvent]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for event in events {
        *counts.entry(event.event_type.clone()).or_default() += 1;
    }
    counts
}

fn event_evidence(events: &[TimelineEvent], event_type: &str) -> Option<EventEvidence> {
    let mut matching = events.iter().filter(|event| event.event_type == event_type);
    let first = matching.next()?;
    let mut last = first;
    let mut count = 1_u64;
    for event in matching {
        last = event;
        count = count.saturating_add(1);
    }
    Some(EventEvidence {
        count,
        first_cursor: first.cursor,
        last_cursor: last.cursor,
        first_digest: first.event_digest.clone(),
        last_digest: last.event_digest.clone(),
    })
}

fn build_report(
    suite_id: String,
    suite_digest: String,
    started_at_ms: u64,
    completed_at_ms: u64,
    cases: Vec<EvaluationCaseReport>,
) -> Result<EvaluationReport, EvaluationError> {
    let passed = u64::try_from(cases.iter().filter(|case| case.passed).count()).unwrap_or(u64::MAX);
    let total = u64::try_from(cases.len()).unwrap_or(u64::MAX);
    let summary = EvaluationSummary {
        total,
        passed,
        failed: total.saturating_sub(passed),
    };
    let digest_material = EvaluationReportDigestMaterial {
        contract_version: EVALUATION_REPORT_VERSION,
        suite_id: &suite_id,
        suite_digest: &suite_digest,
        started_at_ms,
        completed_at_ms,
        cases: &cases,
        summary,
    };
    let report_digest = sha256_digest(&serde_json::to_vec(&digest_material)?);
    Ok(EvaluationReport {
        contract_version: EVALUATION_REPORT_VERSION.to_owned(),
        suite_id,
        suite_digest,
        started_at_ms,
        completed_at_ms,
        cases,
        summary,
        report_digest,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvaluationReportDigestMaterial<'a> {
    contract_version: &'static str,
    suite_id: &'a str,
    suite_digest: &'a str,
    started_at_ms: u64,
    completed_at_ms: u64,
    cases: &'a [EvaluationCaseReport],
    summary: EvaluationSummary,
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn now_ms() -> Result<u64, EvaluationError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EvaluationError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| EvaluationError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mealy_protocol::{
        SuccessCriterionResponse, TaskReplayResponse, TaskRiskClass, TaskSuccessCriteriaResponse,
        TaskValidationResponse,
    };

    fn suite() -> EvaluationSuite {
        EvaluationSuite {
            contract_version: EVALUATION_SUITE_VERSION.to_owned(),
            suite_id: "ci.core".to_owned(),
            description: Some("Deterministic public API suite".to_owned()),
            cases: vec![EvaluationCase {
                case_id: "read.success".to_owned(),
                input: ScenarioInput {
                    content: "fixture.read alpha".to_owned(),
                    provider_selection: None,
                },
                expect: ScenarioExpectation {
                    settled_status: TaskStatus::Succeeded,
                    final_response: Some(FinalResponseExpectation {
                        presence: PresenceExpectation::Present,
                        sha256: Some("a".repeat(64)),
                    }),
                    validation: Some(ValidationExpectation {
                        presence: PresenceExpectation::Present,
                        outcomes: vec![ValidationOutcomeResponse::Passed],
                        methods: vec![ValidationMethodResponse::Deterministic],
                    }),
                    replay: Some(ReplayExpectation {
                        evidence_complete: true,
                        zero_live_calls: true,
                        final_digest_matches: true,
                    }),
                    required_events: vec![EventCountExpectation {
                        event_type: "task.succeeded".to_owned(),
                        minimum: 1,
                        maximum: Some(1),
                    }],
                    forbidden_events: vec!["effect.dispatched".to_owned()],
                    budgets: EvaluationBudgets {
                        maximum_duration_ms: Some(10_000),
                        maximum_model_calls: Some(2),
                        ..EvaluationBudgets::default()
                    },
                },
                timeout_ms: 20_000,
                poll_interval_ms: 20,
            }],
        }
    }

    fn event(cursor: u64, event_type: &str) -> TimelineEvent {
        TimelineEvent {
            cursor: TimelineCursor(cursor),
            event_id: format!("event-{cursor}"),
            aggregate_kind: "task".to_owned(),
            aggregate_id: "task-1".to_owned(),
            aggregate_sequence: cursor,
            event_type: event_type.to_owned(),
            event_version: 1,
            occurred_at_ms: 1_000,
            correlation_id: "correlation-1".to_owned(),
            causation_id: None,
            payload: json!({"private": "payload-canary-7c41"}),
            event_digest: format!("{cursor:064x}"),
        }
    }

    fn task() -> TaskResponse {
        TaskResponse {
            api_version: API_VERSION.to_owned(),
            task_id: "task-1".to_owned(),
            run_id: "run-1".to_owned(),
            status: TaskStatus::Succeeded,
            revision: 3,
            final_response: Some("private result".to_owned()),
            final_digest: Some("a".repeat(64)),
            usage: TaskBudgetUsage {
                used_model_calls: 1,
                ..TaskBudgetUsage::default()
            },
            success_criteria: TaskSuccessCriteriaResponse {
                objective: "private objective".to_owned(),
                criteria: vec![SuccessCriterionResponse {
                    criterion_id: "one".to_owned(),
                    requirement: "private criterion".to_owned(),
                }],
                no_objective_criteria_reason: None,
                risk_class: TaskRiskClass::Low,
                policy_version: "policy.v1".to_owned(),
                criteria_digest: "b".repeat(64),
            },
            validation: Some(TaskValidationResponse {
                validation_id: "validation-1".to_owned(),
                producer_run_id: "run-1".to_owned(),
                validator_run_id: None,
                context_manifest_id: "context-1".to_owned(),
                method: ValidationMethodResponse::Deterministic,
                outcome: ValidationOutcomeResponse::Passed,
                rubric: json!({"private": "rubric-canary-10d2"}),
                evidence: json!({"private": "validation-canary-b904"}),
                policy_version: "policy.v1".to_owned(),
                cursor: TimelineCursor(2),
            }),
            model_attempts: 1,
            tool_calls: 0,
        }
    }

    #[test]
    fn strict_suite_validates_and_has_stable_digest() {
        let suite = suite();
        suite.validate().expect("valid suite");
        assert_eq!(
            suite.digest().expect("digest"),
            suite.digest().expect("digest")
        );
    }

    #[test]
    fn transient_settled_state_is_rejected() {
        let mut suite = suite();
        suite.cases[0].expect.settled_status = TaskStatus::Running;
        assert_eq!(
            suite.validate(),
            Err(SuiteValidationError::InvalidSettledStatus)
        );
    }

    #[test]
    fn absent_response_cannot_require_a_digest() {
        let mut suite = suite();
        suite.cases[0].expect.final_response = Some(FinalResponseExpectation {
            presence: PresenceExpectation::Absent,
            sha256: Some("a".repeat(64)),
        });
        assert_eq!(suite.validate(), Err(SuiteValidationError::InvalidDigest));
    }

    #[test]
    fn event_expectations_cannot_contradict_each_other() {
        let mut suite = suite();
        suite.cases[0]
            .expect
            .forbidden_events
            .push("task.succeeded".to_owned());
        assert_eq!(
            suite.validate(),
            Err(SuiteValidationError::InvalidEventExpectation)
        );
    }

    #[test]
    fn evaluation_uses_digests_and_omits_private_content() {
        let suite = suite();
        let case = evaluate_case(
            &suite.cases[0],
            CaseObservation {
                input_digest: "c".repeat(64),
                session_id: "session-1".to_owned(),
                duration_ms: 100,
                task: Some(task()),
                replay: Some(TaskReplayResponse {
                    api_version: API_VERSION.to_owned(),
                    task_id: "task-1".to_owned(),
                    run_id: "run-1".to_owned(),
                    mode: "recorded".to_owned(),
                    evidence_complete: true,
                    final_response: Some("private result".to_owned()),
                    final_digest: Some("a".repeat(64)),
                    model_attempts: 1,
                    tool_calls: 0,
                    live_provider_calls: 0,
                    live_tool_calls: 0,
                }),
                timeline_events: vec![event(1, "task.succeeded")],
                timeline_high_watermark: TimelineCursor(1),
                timeline_complete: true,
            },
        );
        assert!(case.passed);
        let encoded = serde_json::to_string(&case).expect("serialize report case");
        for private in [
            "fixture.read alpha",
            "private result",
            "private objective",
            "private criterion",
            "rubric-canary-10d2",
            "validation-canary-b904",
            "payload-canary-7c41",
        ] {
            assert!(!encoded.contains(private), "leaked {private}");
        }
        assert_eq!(
            case.evidence.events["task.succeeded"].first_digest,
            format!("{:064x}", 1)
        );
    }

    #[test]
    fn failed_budget_is_reported_without_aborting() {
        let mut suite = suite();
        suite.cases[0].expect.budgets.maximum_model_calls = Some(0);
        let case = evaluate_case(
            &suite.cases[0],
            CaseObservation {
                input_digest: "c".repeat(64),
                session_id: "session-1".to_owned(),
                duration_ms: 100,
                task: Some(task()),
                replay: None,
                timeline_events: vec![event(1, "task.succeeded")],
                timeline_high_watermark: TimelineCursor(1),
                timeline_complete: true,
            },
        );
        assert!(!case.passed);
        assert!(
            case.assertions
                .iter()
                .any(|assertion| { assertion.check == "budget.model_calls" && !assertion.passed })
        );
    }

    #[test]
    fn report_digest_changes_with_evidence() {
        let case = EvaluationCaseReport {
            case_id: "one".to_owned(),
            passed: true,
            assertions: Vec::new(),
            evidence: CaseEvidence {
                input_digest: "a".repeat(64),
                session_id: "session".to_owned(),
                task_id: None,
                run_id: None,
                status: None,
                duration_ms: 1,
                final_digest: None,
                success_criteria_digest: None,
                validation_id: None,
                validation_context_manifest_id: None,
                validation_cursor: None,
                usage: None,
                timeline_high_watermark: TimelineCursor(0),
                timeline_complete: true,
                events: BTreeMap::new(),
                replay_available: false,
                replay_evidence_complete: None,
                replay_final_digest: None,
                replay_live_provider_calls: None,
                replay_live_tool_calls: None,
            },
        };
        let first = build_report("suite".to_owned(), "b".repeat(64), 1, 2, vec![case.clone()])
            .expect("first report");
        let mut changed = case;
        changed.evidence.duration_ms = 2;
        let second = build_report("suite".to_owned(), "b".repeat(64), 1, 2, vec![changed])
            .expect("second report");
        assert_ne!(first.report_digest, second.report_digest);
    }
}
