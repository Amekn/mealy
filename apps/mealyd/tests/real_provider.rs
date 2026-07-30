//! Public-process proof for the configurable Responses-compatible model-provider boundary.

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use image::{DynamicImage, ImageBuffer, Rgb, codecs::jpeg::JpegEncoder};
use mealy_application::{
    BROWSER_CDP_PROTOCOL_VERSION, BrowserConfig, DIRECT_PROVIDER_INPUT_TOKEN_OVERHEAD,
    MCP_PROTOCOL_VERSION, McpServerConfig, McpToolEffect, McpToolGrant, sha256_digest,
};
use mealy_domain::ArtifactId;
use mealy_infrastructure::{
    FileProviderSecretStore, discover_mcp_stdio_server, inspect_browser_bundle,
    inspect_skill_package, probe_browser_bundle_product, publish_browser_bundle,
    publish_skill_package,
};
use mealy_protocol::{
    API_VERSION, AdminStatusResponse, ApprovalDecisionCommand, ApprovalResolutionReceipt,
    ArtifactMetadataResponse, CancelTaskRequest, CompactionResponse, CreateCompactionRequest,
    CreateSessionCheckpointRequest, CreateSessionRequest, CreateSessionResponse,
    DelegationResponse, DelegationsResponse, DeliveryMode, DoctorResponse,
    EffectReconciliationReceipt, EffectResponse, EffectStatusResponse, ForkSessionRequest,
    InputAdmissionResponse, LocalConnectionInfo, PendingApprovalsResponse, ProviderCatalogResponse,
    ProviderSelectionCommand, ReadinessResponse, ReconcileEffectRequest,
    ReconciliationOutcomeCommand, ResolveApprovalRequest, SessionCheckpointResponse,
    SessionForkResponse, SessionProviderSelectionResponse, SessionSearchResponse,
    SessionStatusResponse, SessionTranscriptExport, SubmitImageInputRequest, SubmitInputRequest,
    SubmittedImageInput, TaskCancellationReceipt, TaskReplayResponse, TaskResponse, TaskStatus,
    TimelinePageResponse, UpdateSessionProviderSelectionRequest, ValidationMethodResponse,
    ValidationOutcomeResponse,
};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{net::TcpListener, task::JoinHandle, time::Instant, time::sleep};

const COMPLETION_TIMEOUT: Duration = Duration::from_secs(15);
const BROWSER_TASK_COMPLETION_TIMEOUT: Duration = Duration::from_secs(45);
const READY_TIMEOUT: Duration = Duration::from_secs(15);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path, safe_mode: bool) -> Self {
        Self::spawn_with_agent_interval(home, safe_mode, 25)
    }

    fn spawn_with_agent_interval(home: &Path, safe_mode: bool, agent_interval_ms: u64) -> Self {
        Self::spawn_configured(home, safe_mode, agent_interval_ms, 0)
    }

    fn spawn_with_effect_outcome_delay(home: &Path, effect_outcome_delay_ms: u64) -> Self {
        Self::spawn_configured(home, false, 25, effect_outcome_delay_ms)
    }

    fn spawn_configured(
        home: &Path,
        safe_mode: bool,
        agent_interval_ms: u64,
        effect_outcome_delay_ms: u64,
    ) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mealyd"));
        command
            .arg("--home")
            .arg(home)
            .arg("--promotion-delay-ms")
            .arg("0")
            .arg("--promotion-interval-ms")
            .arg("10")
            .arg("--agent-delay-ms")
            .arg("0")
            .arg("--agent-interval-ms")
            .arg(agent_interval_ms.to_string())
            .arg("--effect-outcome-delay-ms")
            .arg(effect_outcome_delay_ms.to_string())
            .arg("--outbox-delay-ms")
            .arg("0")
            .env(
                "RUST_LOG",
                std::env::var("MEALY_TEST_RUST_LOG").unwrap_or_else(|_| "error".to_owned()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if safe_mode {
            command.arg("--safe-mode");
        }
        Self {
            child: command.spawn().expect("mealyd process should start"),
        }
    }

    fn kill_and_wait(&mut self) {
        self.child.kill().expect("kill mealyd");
        self.child.wait().expect("wait for killed mealyd");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    authorization: Option<String>,
    body: Value,
}

#[derive(Default)]
struct MockProviderInner {
    requests: Vec<CapturedRequest>,
    image_requests: Vec<CapturedRequest>,
    transient_failures_remaining: usize,
    pending_tool_call: PendingToolCall,
    web_tool_steps_remaining: u8,
    web_origin: Option<String>,
    delegated_child_delay_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PendingToolCall {
    #[default]
    None,
    WorkspaceRead,
    WorkspaceCreate,
    WorkspaceReplace,
    WorkspaceManage,
    Process,
    SkillResource,
    Delegation,
    DelegationThenParallel,
    ParallelDelegation,
    ParallelAfterChild,
    Mcp,
    ImageGeneration,
    Browser,
    BrowserThenTransaction,
    BrowserTransactionAfterSnapshot,
}

#[derive(Clone, Default)]
struct MockProviderState(Arc<Mutex<MockProviderInner>>);

impl MockProviderState {
    fn with_transient_failures(count: usize) -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: count,
            pending_tool_call: PendingToolCall::None,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_workspace_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::WorkspaceRead,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_workspace_create_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::WorkspaceCreate,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_workspace_replace_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::WorkspaceReplace,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_workspace_manage_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::WorkspaceManage,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_process_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::Process,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_skill_resource_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::SkillResource,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_delegation_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::Delegation,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_parallel_delegation_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::ParallelDelegation,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_serial_then_over_budget_parallel_delegation() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::DelegationThenParallel,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_mcp_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::Mcp,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_image_generation_tool_call() -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::ImageGeneration,
            web_tool_steps_remaining: 0,
            web_origin: None,
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_browser_tool_call(web_origin: String) -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::Browser,
            web_tool_steps_remaining: 0,
            web_origin: Some(web_origin),
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_browser_transaction_tool_call(web_origin: String) -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::BrowserThenTransaction,
            web_tool_steps_remaining: 0,
            web_origin: Some(web_origin),
            delegated_child_delay_ms: 0,
        })))
    }

    fn with_delayed_delegation_tool_call(delay: Duration) -> Self {
        let state = Self::with_delegation_tool_call();
        state
            .0
            .lock()
            .expect("provider capture lock")
            .delegated_child_delay_ms =
            u64::try_from(delay.as_millis()).expect("test delay fits u64");
        state
    }

    fn with_delayed_parallel_delegation_tool_call(delay: Duration) -> Self {
        let state = Self::with_parallel_delegation_tool_call();
        state
            .0
            .lock()
            .expect("provider capture lock")
            .delegated_child_delay_ms =
            u64::try_from(delay.as_millis()).expect("test delay fits u64");
        state
    }

    fn with_web_tool_calls(web_origin: String) -> Self {
        Self(Arc::new(Mutex::new(MockProviderInner {
            requests: Vec::new(),
            image_requests: Vec::new(),
            transient_failures_remaining: 0,
            pending_tool_call: PendingToolCall::None,
            web_tool_steps_remaining: 2,
            web_origin: Some(web_origin),
            delegated_child_delay_ms: 0,
        })))
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.0
            .lock()
            .expect("provider capture lock")
            .requests
            .clone()
    }

    fn image_requests(&self) -> Vec<CapturedRequest> {
        self.0
            .lock()
            .expect("provider capture lock")
            .image_requests
            .clone()
    }
}

#[allow(clippy::too_many_lines)]
async fn responses_handler(
    State(state): State<MockProviderState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let delegated_child_request = body.to_string().contains("ISOLATED DELEGATED WORK PACKAGE")
        || body
            .to_string()
            .contains("ISOLATED PARALLEL DELEGATED WORK PACKAGE");
    let authorization = headers
        .get(reqwest::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let (
        fail_transiently,
        call_workspace_tool,
        call_workspace_create,
        call_workspace_replace,
        call_workspace_manage,
        call_process,
        call_skill_resource,
        call_delegation,
        call_parallel_delegation,
        call_mcp,
        call_image_generation,
        call_browser,
        call_browser_transaction_catalog,
        call_browser_transaction,
        web_tool_call,
        delegated_child_delay_ms,
    ) = {
        let mut state = state.0.lock().expect("provider capture lock");
        state.requests.push(CapturedRequest {
            authorization,
            body: body.clone(),
        });
        let fail = state.transient_failures_remaining > 0;
        state.transient_failures_remaining = state.transient_failures_remaining.saturating_sub(1);
        let pending_tool_call = if fail
            || delegated_child_request
                && state.pending_tool_call == PendingToolCall::ParallelAfterChild
        {
            PendingToolCall::None
        } else {
            std::mem::take(&mut state.pending_tool_call)
        };
        if pending_tool_call == PendingToolCall::DelegationThenParallel {
            state.pending_tool_call = PendingToolCall::ParallelAfterChild;
        } else if pending_tool_call == PendingToolCall::BrowserThenTransaction {
            state.pending_tool_call = PendingToolCall::BrowserTransactionAfterSnapshot;
        }
        let web_tool_call = if !fail && state.web_tool_steps_remaining > 0 {
            let step = state.web_tool_steps_remaining;
            state.web_tool_steps_remaining = state.web_tool_steps_remaining.saturating_sub(1);
            state.web_origin.clone().map(|origin| (step, origin))
        } else {
            None
        };
        let delegated_child_delay_ms = if delegated_child_request {
            state.delegated_child_delay_ms
        } else {
            0
        };
        (
            fail,
            pending_tool_call == PendingToolCall::WorkspaceRead,
            pending_tool_call == PendingToolCall::WorkspaceCreate,
            pending_tool_call == PendingToolCall::WorkspaceReplace,
            pending_tool_call == PendingToolCall::WorkspaceManage,
            pending_tool_call == PendingToolCall::Process,
            pending_tool_call == PendingToolCall::SkillResource,
            matches!(
                pending_tool_call,
                PendingToolCall::Delegation | PendingToolCall::DelegationThenParallel
            ),
            matches!(
                pending_tool_call,
                PendingToolCall::ParallelDelegation | PendingToolCall::ParallelAfterChild
            ),
            pending_tool_call == PendingToolCall::Mcp,
            pending_tool_call == PendingToolCall::ImageGeneration,
            matches!(
                pending_tool_call,
                PendingToolCall::Browser | PendingToolCall::BrowserThenTransaction
            ),
            pending_tool_call == PendingToolCall::BrowserThenTransaction,
            pending_tool_call == PendingToolCall::BrowserTransactionAfterSnapshot,
            web_tool_call,
            delegated_child_delay_ms,
        )
    };
    if fail_transiently {
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": {
                    "type": "rate_limit_error",
                    "message": "transient process-test rate limit"
                }
            })),
        )
            .into_response();
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("0"));
        response
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("req-rate-limited"));
        return response;
    }
    if call_workspace_tool {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"]
                        .as_str()
                        .is_some_and(|description| description.contains("workspace.read"))
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("workspace.read provider tool name");
        let mut response = Json(json!({
            "id": "resp-workspace-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-workspace-read",
                "name": tool_name,
                "arguments": "{\"workspaceId\":\"project\",\"path\":\"notes.txt\"}"
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-workspace-call"),
        );
        return response;
    }
    if call_workspace_create {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"].as_str().is_some_and(|description| {
                        description.contains("Creates one new bounded file")
                    })
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("workspace.create_file provider tool name");
        let mut response = Json(json!({
            "id": "resp-workspace-create-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-workspace-create",
                "name": tool_name,
                "arguments": serde_json::json!({
                    "workspaceId": "project",
                    "operation": "write_file",
                    "relativePath": "generated/approved.txt",
                    "content": "approved production action"
                }).to_string()
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-workspace-create-call"),
        );
        return response;
    }
    if call_workspace_replace {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"].as_str().is_some_and(|description| {
                        description.contains("Atomically replaces one existing bounded file")
                    })
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .unwrap_or_else(|| panic!("workspace.replace_file provider tool name: {body}"));
        let mut response = Json(json!({
            "id": "resp-workspace-replace-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-workspace-replace",
                "name": tool_name,
                "arguments": serde_json::json!({
                    "workspaceId": "project",
                    "operation": "replace_file",
                    "relativePath": "existing.txt",
                    "expectedCurrentDigest": sha256_digest(b"original production content"),
                    "replacements": [{
                        "oldText": "production",
                        "newText": "patched production-ready",
                        "expectedOccurrences": 1
                    }]
                }).to_string()
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-workspace-replace-call"),
        );
        return response;
    }
    if call_workspace_manage {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"].as_str().is_some_and(|description| {
                        description.contains("moves one digest-matched regular file")
                    })
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .unwrap_or_else(|| panic!("workspace.manage_path provider tool name: {body}"));
        let mut response = Json(json!({
            "id": "resp-workspace-manage-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-workspace-manage",
                "name": tool_name,
                "arguments": serde_json::json!({
                    "destinationPath": "archive/report.txt",
                    "expectedSourceDigest": sha256_digest(b"approved lifecycle report"),
                    "operation": "move_file",
                    "sourcePath": "drafts/report.txt",
                    "workspaceId": "project"
                }).to_string()
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-workspace-manage-call"),
        );
        return response;
    }
    if call_process {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"].as_str().is_some_and(|description| {
                        description.contains("Runs one digest-pinned configured executable")
                    })
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("process.run provider tool name");
        let mut response = Json(json!({
            "id": "resp-process-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-process-run",
                "name": tool_name,
                "arguments": serde_json::json!({
                    "operation": "run_process",
                    "commandId": "mkdir",
                    "workspaceId": "project",
                    "workingDirectory": "",
                    "arguments": ["generated-by-process"]
                }).to_string()
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("req-process-call"));
        return response;
    }
    if call_skill_resource {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"]
                        .as_str()
                        .is_some_and(|description| description.contains("passive resource"))
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("skill.read_resource provider tool name");
        let mut response = Json(json!({
            "id": "resp-skill-resource-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-skill-resource",
                "name": tool_name,
                "arguments": serde_json::json!({
                    "skillId": "mealy.fixture.continuity",
                    "path": "resources/private.txt"
                }).to_string()
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-skill-resource-call"),
        );
        return response;
    }
    if call_delegation {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"]
                        .as_str()
                        .is_some_and(|description| description.contains("isolated, budgeted"))
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("agent.delegate provider tool name");
        let mut response = Json(json!({
            "id": "resp-delegation-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-agent-delegate",
                "name": tool_name,
                "arguments": serde_json::json!({
                    "objective": "Independently assess the bounded delegation proof",
                    "instructions": "Return a concise assessment using only the explicit child package.",
                    "successCriteria": [
                        "State whether the isolated child execution completed",
                        "Return a result suitable for the waiting parent"
                    ],
                    "context": {"evidenceLabel": "durable-delegation-process-proof"}
                }).to_string()
            }],
            "usage": {"input_tokens": 12, "output_tokens": 12, "total_tokens": 24}
        }))
        .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-delegation-call"),
        );
        return response;
    }
    if call_parallel_delegation {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"]
                        .as_str()
                        .is_some_and(|description| description.contains("two to eight isolated"))
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("agent.delegate_parallel provider tool name");
        let mut response = Json(json!({
            "id": "resp-parallel-delegation-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-agent-delegate-parallel",
                "name": tool_name,
                "arguments": serde_json::json!({
                    "delegations": [{
                        "childKey": "first",
                        "objective": "Assess the first bounded proof",
                        "instructions": "Return the first concise isolated assessment.",
                        "successCriteria": ["Return the first keyed result"],
                        "context": {"evidenceLabel": "parallel-first"}
                    }, {
                        "childKey": "second",
                        "objective": "Assess the second bounded proof",
                        "instructions": "Return the second concise isolated assessment.",
                        "successCriteria": ["Return the second keyed result"],
                        "context": {"evidenceLabel": "parallel-second"}
                    }]
                }).to_string()
            }],
            "usage": {"input_tokens": 14, "output_tokens": 16, "total_tokens": 30}
        }))
        .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-parallel-delegation-call"),
        );
        return response;
    }
    if call_mcp {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"]
                        .as_str()
                        .is_some_and(|description| description.contains("MCP"))
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .unwrap_or_else(|| panic!("MCP provider tool name: {body}"));
        let mut response = Json(json!({
            "id": "resp-mcp-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-mcp-add",
                "name": tool_name,
                "arguments": "{\"left\":20,\"right\":22}"
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("req-mcp-call"));
        return response;
    }
    if call_image_generation {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"]
                        .as_str()
                        .is_some_and(|description| description.contains("Generates one JPEG"))
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .unwrap_or_else(|| panic!("image-generation provider tool name: {body}"));
        let mut response = Json(json!({
            "id": "resp-image-generation-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-image-generation",
                "name": tool_name,
                "arguments": "{\"prompt\":\"A quiet harbor at dawn\"}"
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-image-generation-call"),
        );
        return response;
    }
    if call_browser {
        let web_origin = state
            .0
            .lock()
            .expect("provider capture lock")
            .web_origin
            .clone()
            .expect("browser origin");
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"]
                        .as_str()
                        .is_some_and(|description| description.contains("fresh isolated browser"))
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("browser provider tool name");
        let mut arguments = json!({
            "url": if call_browser_transaction_catalog {
                format!("{web_origin}/transaction-page")
            } else {
                format!("{web_origin}/page")
            },
            "maximumTextBytes": 4096,
            "maximumElements": 16,
        });
        if !call_browser_transaction_catalog {
            arguments["captureScreenshot"] = Value::Bool(true);
            arguments["fillElement"] = json!({
                "role": "searchbox",
                "name": "Evidence query",
                "value": "durable browser evidence",
                "submitGetForm": true
            });
        }
        let mut response = Json(json!({
            "id": "resp-browser-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-browser-snapshot",
                "name": tool_name,
                "arguments": arguments.to_string()
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("req-browser-call"));
        return response;
    }
    if call_browser_transaction {
        let web_origin = state
            .0
            .lock()
            .expect("provider capture lock")
            .web_origin
            .clone()
            .expect("browser origin");
        let form_digest = find_string_field(&body, "formDigest")
            .filter(|digest| mealy_application::is_sha256_digest(digest))
            .expect("browser snapshot form digest");
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"].as_str().is_some_and(|description| {
                        description.contains("digest-matched same-origin POST")
                    })
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("browser transaction provider tool name");
        let mut response = Json(json!({
            "id": "resp-browser-transaction-call",
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call-browser-transaction",
                "name": tool_name,
                "arguments": json!({
                    "initialUrl": format!("{web_origin}/transaction-page"),
                    "formDigest": form_digest,
                    "fields": [{
                        "name": "message",
                        "value": "exact durable browser transaction"
                    }],
                    "submitter": {"name": "action", "value": "send"}
                }).to_string()
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-browser-transaction-call"),
        );
        return response;
    }
    if let Some((step, web_origin)) = web_tool_call {
        let requested_id = if step == 2 { "web.search" } else { "web.fetch" };
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"]
                        .as_str()
                        .is_some_and(|description| description.contains(requested_id))
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("web provider tool name");
        let arguments = if step == 2 {
            "{\"query\":\"production evidence\",\"maximumResults\":5}".to_owned()
        } else {
            serde_json::json!({"url": format!("{web_origin}/page")}).to_string()
        };
        let mut response = Json(json!({
            "id": format!("resp-web-call-{step}"),
            "object": "response",
            "model": body["model"].clone(),
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": format!("call-web-{step}"),
                "name": tool_name,
                "arguments": arguments
            }],
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }))
        .into_response();
        response
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("req-web-call"));
        return response;
    }
    if delegated_child_delay_ms > 0 {
        sleep(Duration::from_millis(delegated_child_delay_ms)).await;
    }
    let configured_web_origin = state
        .0
        .lock()
        .expect("provider capture lock")
        .web_origin
        .clone();
    let final_text = if body.to_string().contains("LARGE-TRANSCRIPT-ARTIFACT") {
        format!(
            "LARGE-TRANSCRIPT-ARTIFACT:{}",
            "verified-artifact-content-".repeat(96)
        )
    } else if let Some((observation, observation_text)) = find_effect_observation(&body) {
        let status = observation
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        format!(
            "The approved action reached durable effect state {status}; recorded observation sha256:{}",
            sha256_digest(observation_text.as_bytes())
        )
    } else if body.to_string().contains("delegation://group-result") {
        "The parent incorporated both ordered durable child results \
         (delegation://group-result)."
            .to_owned()
    } else if body.to_string().contains("delegation://result") {
        "The parent incorporated the durable isolated child result (delegation://result)."
            .to_owned()
    } else if body
        .to_string()
        .contains("ISOLATED PARALLEL DELEGATED WORK PACKAGE")
        && body.to_string().contains("\"childKey\":\"first\"")
    {
        "The first parallel isolated child completed.".to_owned()
    } else if body
        .to_string()
        .contains("ISOLATED PARALLEL DELEGATED WORK PACKAGE")
    {
        "The second parallel isolated child completed.".to_owned()
    } else if body.to_string().contains("ISOLATED DELEGATED WORK PACKAGE") {
        "The isolated child execution completed and returned a result suitable for the waiting parent."
            .to_owned()
    } else if body.to_string().contains("workspace://project/notes.txt") {
        "The note contains the production workspace evidence needle \
         (workspace://project/notes.txt)."
            .to_owned()
    } else if body.to_string().contains("HIDDEN-SKILL-RESOURCE") {
        "The enabled passive resource was read with citation \
         skill://mealy.fixture.continuity/resources/private.txt."
            .to_owned()
    } else if body.to_string().contains("mcp://fixture/add") {
        "The isolated MCP calculation returned 42 (mcp://fixture/add).".to_owned()
    } else if let Some(web_origin) = configured_web_origin
        .as_deref()
        .filter(|origin| body.to_string().contains(&format!("{origin}/page")))
    {
        format!("The current web evidence is verified ({web_origin}/page).")
    } else {
        "The real provider path completed safely.".to_owned()
    };
    let envelope = json!({
        "id": "resp-process-proof",
        "object": "response",
        "model": body["model"].clone(),
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "status": "completed",
            "content": [{
                "type": "output_text",
                "text": final_text
            }]
        }],
        "usage": {"input_tokens": 18, "output_tokens": 7, "total_tokens": 25}
    });
    if body["stream"] == true {
        let text = envelope["output"][0]["content"][0]["text"]
            .as_str()
            .expect("final response text");
        let delta = json!({"type": "response.output_text.delta", "delta": text});
        let completed = json!({"type": "response.completed", "response": envelope});
        let mut response = (
            [("content-type", "text/event-stream")],
            format!("event: response.output_text.delta\ndata: {delta}\n\nevent: response.completed\ndata: {completed}\n\ndata: [DONE]\n\n"),
        )
            .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("req-process-proof-stream"),
        );
        return response;
    }
    let mut response = Json(envelope).into_response();
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_static("req-process-proof"),
    );
    response
}

async fn image_generation_handler(
    State(state): State<MockProviderState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let authorization = headers
        .get(reqwest::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    state
        .0
        .lock()
        .expect("provider capture lock")
        .image_requests
        .push(CapturedRequest {
            authorization,
            body: body.clone(),
        });
    let image =
        DynamicImage::ImageRgb8(ImageBuffer::from_pixel(16, 16, Rgb([24_u8, 96_u8, 160_u8])));
    let mut jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg, 90)
        .encode_image(&image)
        .expect("encode mock generated JPEG");
    let mut response = Json(json!({
        "data": [{
            "b64_json": BASE64_STANDARD.encode(jpeg)
        }],
        "usage": {"cost": "0.012345"}
    }))
    .into_response();
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_static("req-image-generation-result"),
    );
    response
}

#[allow(clippy::too_many_lines)]
async fn anthropic_handler(
    State(state): State<MockProviderState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let api_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let pending_tool_call = {
        let mut state = state.0.lock().expect("provider capture lock");
        state.requests.push(CapturedRequest {
            authorization: api_key,
            body: body.clone(),
        });
        std::mem::take(&mut state.pending_tool_call)
    };
    if pending_tool_call == PendingToolCall::WorkspaceRead {
        let tool_name = body["tools"]
            .as_array()
            .and_then(|tools| {
                tools.iter().find(|tool| {
                    tool["description"]
                        .as_str()
                        .is_some_and(|description| description.contains("workspace.read"))
                })
            })
            .and_then(|tool| tool["name"].as_str())
            .expect("Anthropic workspace.read provider tool name");
        if body["stream"] == true {
            return anthropic_sse_response(&[
                json!({
                    "type": "message_start",
                    "message": {
                        "id": "msg-workspace-call",
                        "type": "message",
                        "role": "assistant",
                        "model": "process-fallback-model",
                        "content": [],
                        "stop_reason": null,
                        "usage": {"input_tokens": 18, "output_tokens": 0}
                    }
                }),
                json!({
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {
                        "type": "tool_use",
                        "id": "toolu-workspace-read",
                        "name": tool_name,
                        "input": {}
                    }
                }),
                json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": "{\"workspaceId\":\"project\",\"path\":\"notes.txt\"}"
                    }
                }),
                json!({"type": "content_block_stop", "index": 0}),
                json!({
                    "type": "message_delta",
                    "delta": {"stop_reason": "tool_use", "stop_sequence": null},
                    "usage": {"output_tokens": 8}
                }),
                json!({"type": "message_stop"}),
            ]);
        }
        let mut response = Json(json!({
            "id": "msg-workspace-call",
            "type": "message",
            "role": "assistant",
            "model": "process-fallback-model",
            "content": [{
                "type": "tool_use",
                "id": "toolu-workspace-read",
                "name": tool_name,
                "input": {"workspaceId": "project", "path": "notes.txt"}
            }],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 18, "output_tokens": 8}
        }))
        .into_response();
        response.headers_mut().insert(
            "request-id",
            HeaderValue::from_static("req-anthropic-workspace-call"),
        );
        return response;
    }
    let text = if body.to_string().contains("workspace://project/notes.txt") {
        "The note contains the production workspace evidence needle \
         (workspace://project/notes.txt)."
    } else {
        "The independent Anthropic provider path completed safely."
    };
    if body["stream"] == true {
        return anthropic_sse_response(&[
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg-process-proof",
                    "type": "message",
                    "role": "assistant",
                    "model": "process-fallback-model",
                    "content": [],
                    "stop_reason": null,
                    "usage": {"input_tokens": 18, "output_tokens": 0}
                }
            }),
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""}
            }),
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text}
            }),
            json!({"type": "content_block_stop", "index": 0}),
            json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"output_tokens": 9}
            }),
            json!({"type": "message_stop"}),
        ]);
    }
    let mut response = Json(json!({
        "id": "msg-process-proof",
        "type": "message",
        "role": "assistant",
        "model": "process-fallback-model",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {"input_tokens": 18, "output_tokens": 9}
    }))
    .into_response();
    response.headers_mut().insert(
        "request-id",
        HeaderValue::from_static("req-anthropic-process-proof"),
    );
    response
}

fn anthropic_sse_response(events: &[Value]) -> Response {
    let body = events.iter().fold(String::new(), |mut output, event| {
        use std::fmt::Write as _;
        writeln!(
            output,
            "event: {}\ndata: {event}\n",
            event["type"].as_str().unwrap_or("message")
        )
        .expect("encode Anthropic SSE");
        output
    });
    let mut response = ([("content-type", "text/event-stream")], body).into_response();
    response.headers_mut().insert(
        "request-id",
        HeaderValue::from_static("req-anthropic-process-proof"),
    );
    response
}

fn find_effect_observation(value: &Value) -> Option<(Value, String)> {
    match value {
        Value::String(text) => [
            text.as_str(),
            text.strip_prefix("[Recorded tool observation ")
                .and_then(|rest| rest.split_once('\n').map(|(_, content)| content))
                .unwrap_or(""),
        ]
        .into_iter()
        .find_map(|candidate_text| {
            serde_json::from_str::<Value>(candidate_text)
                .ok()
                .filter(|candidate| {
                    candidate.get("contractVersion").and_then(Value::as_str)
                        == Some(mealy_application::AGENT_EFFECT_OBSERVATION_CONTRACT_VERSION)
                })
                .map(|candidate| (candidate, candidate_text.to_owned()))
        }),
        Value::Array(values) => values.iter().find_map(find_effect_observation),
        Value::Object(values) => values.values().find_map(find_effect_observation),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

fn find_string_field(value: &Value, field: &str) -> Option<String> {
    match value {
        Value::Object(values) => values
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                values
                    .values()
                    .find_map(|value| find_string_field(value, field))
            }),
        Value::Array(values) => values
            .iter()
            .find_map(|value| find_string_field(value, field)),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .ok()
            .or_else(|| {
                text.find('{')
                    .and_then(|start| serde_json::from_str::<Value>(&text[start..]).ok())
            })
            .and_then(|decoded| find_string_field(&decoded, field)),
        _ => None,
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn subscription_provider_reserves_official_client_input_overhead() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = TempDir::new().expect("temporary subscription daemon home");
    write_provider_config(home.path(), "http://127.0.0.1:9/v1");
    let executable = home.path().join("codex-subscription-fixture");
    let fixture_body = concat!(
        "#!/bin/sh\n",
        "test -z \"${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}${OPENROUTER_API_KEY:-}${LOCAL_API_KEY:-}\" || exit 90\n",
        "cat >/dev/null\n",
        "printf '%s\\n' ",
        "'{\"type\":\"thread.started\",\"thread_id\":\"subscription-overhead-proof\"}' ",
        "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"{\\\"kind\\\":\\\"final\\\",\\\"text\\\":\\\"Subscription overhead settled safely.\\\",\\\"toolId\\\":null,\\\"arguments\\\":null}\"}}' ",
        "'{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":8000,\"output_tokens\":5}}'\n",
    );
    fs::write(&executable, fixture_body).expect("write subscription fixture");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make subscription fixture executable");
    let executable = executable
        .canonicalize()
        .expect("canonical subscription fixture");
    let config_path = home.path().join("config.json");
    let mut config: Value =
        serde_json::from_slice(&fs::read(&config_path).expect("read configured provider fixture"))
            .expect("configured provider JSON");
    config["provider"] = json!({
        "kind": "subscription_cli",
        "providerId": "openai.subscription",
        "client": "open_ai_codex",
        "executablePath": executable.to_str().expect("UTF-8 fixture path"),
        "executableSha256": sha256_digest(fixture_body.as_bytes()),
        "model": "fixture-model",
        "residency": "remote",
        "contextTokens": 32768,
        "maximumOutputTokens": 64,
        "estimatedLatencyMs": 1000
    });
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("encode subscription config"),
    )
    .expect("write subscription config");

    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "subscription-overhead-proof".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Return one short response.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(task.status, TaskStatus::Succeeded, "task: {task:?}");
    assert_eq!(task.usage.used_input_tokens, 8000);
    assert_eq!(
        task.final_response.as_deref(),
        Some("Subscription overhead settled safely.")
    );

    let database = rusqlite::Connection::open(home.path().join("mealy.sqlite3"))
        .expect("open subscription evidence database");
    let (reserved_input, normalized_input, capability_json) = database
        .query_row(
            "SELECT reservation.input_tokens, manifest.total_token_estimate, \
                    attempt.capability_snapshot_json \
             FROM model_attempt attempt \
             JOIN budget_reservation reservation USING(attempt_id) \
             JOIN context_manifest manifest ON manifest.id = attempt.context_manifest_id",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .expect("durable subscription reservation");
    assert_eq!(reserved_input, normalized_input + 16_384);
    let capabilities: Value =
        serde_json::from_str(&capability_json).expect("capability snapshot JSON");
    assert_eq!(capabilities["inputTokenOverhead"], 16_384);
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete, "replay: {replay:?}");
    assert_eq!(replay.live_provider_calls, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn configured_provider_completes_validates_and_replays_without_live_dispatch() {
    let state = MockProviderState::default();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    enable_provider_streaming(home.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let initial_status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(initial_status.provider_health, "configured_unprobed");
    assert_eq!(initial_status.provider_id, "process-proof.responses");
    assert_eq!(initial_status.provider_model_id, "process-proof-model");
    assert_eq!(initial_status.provider_residency, "local-test");
    assert!(initial_status.provider_local);
    assert_eq!(initial_status.provider_endpoints.len(), 1);
    assert_eq!(
        initial_status.provider_endpoints[0].health,
        "configured_unprobed"
    );
    assert!(initial_status.provider_endpoints[0].streaming);
    assert_eq!(initial_status.provider_endpoints[0].in_flight_requests, 0);
    assert_eq!(
        initial_status.provider_endpoints[0].maximum_concurrent_requests,
        1
    );
    assert_eq!(
        initial_status.provider_endpoints[0].requests_in_current_minute,
        0
    );
    assert_eq!(
        initial_status.provider_endpoints[0].requests_per_minute,
        600
    );
    assert!(
        initial_status.provider_endpoints[0]
            .last_success_at_ms
            .is_none()
    );
    assert!(
        initial_status.provider_endpoints[0]
            .last_failure_at_ms
            .is_none()
    );
    let doctor: DoctorResponse = authorized_get(&client, &connection, "/v1/admin/doctor").await;
    assert!(
        doctor.checks["configured_provider"]
            .contains("re-activate the provider without --skip-connectivity-test")
    );

    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-process-proof".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Give me one short, truthful response.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;

    assert_eq!(task.status, TaskStatus::Succeeded);
    assert_eq!(
        task.final_response.as_deref(),
        Some("The real provider path completed safely.")
    );
    assert_eq!(
        task.final_digest.as_deref(),
        Some(sha256_digest(b"The real provider path completed safely.").as_str())
    );
    assert_eq!(task.model_attempts, 1);
    assert_eq!(task.tool_calls, 0);
    assert_eq!(task.usage.used_input_tokens, 18);
    assert_eq!(task.usage.used_output_tokens, 7);
    assert_eq!(task.usage.used_cost_microunits, 25);
    assert_eq!(
        task.success_criteria
            .criteria
            .iter()
            .map(|criterion| criterion.criterion_id.as_str())
            .collect::<Vec<_>>(),
        ["response_present", "response_integrity"]
    );
    let validation = task.validation.expect("durable response validation");
    assert_eq!(validation.method, ValidationMethodResponse::Deterministic);
    assert_eq!(validation.outcome, ValidationOutcomeResponse::Passed);
    assert_eq!(validation.evidence["findings"]["noEffectAuthority"], true);
    let completed_status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(completed_status.provider_health, "healthy");
    assert_eq!(completed_status.provider_endpoints[0].invocation_count, 1);
    assert_eq!(completed_status.provider_endpoints[0].in_flight_requests, 0);
    assert_eq!(
        completed_status.provider_endpoints[0].requests_in_current_minute,
        1
    );
    assert!(
        completed_status.provider_endpoints[0]
            .last_success_at_ms
            .is_some()
    );
    assert!(
        completed_status.provider_endpoints[0]
            .last_failure_at_ms
            .is_none()
    );

    let requests = state.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer process-proof-secret")
    );
    assert_eq!(requests[0].body["model"], "process-proof-model");
    assert_eq!(requests[0].body["store"], false);
    assert_eq!(requests[0].body["stream"], true);
    assert_eq!(requests[0].body["parallel_tool_calls"], false);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(2));
    assert!(
        requests[0].body["tools"][0]["description"]
            .as_str()
            .is_some_and(|description| description.contains("agent.delegate"))
    );
    assert_eq!(requests[0].body["tool_choice"], "auto");
    assert_eq!(requests[0].body["input"][0]["role"], "developer");
    assert_eq!(requests[0].body["input"][1]["role"], "user");
    assert!(
        !requests[0]
            .body
            .to_string()
            .contains("process-proof-secret")
    );

    let database = rusqlite::Connection::open(home.path().join("mealy.sqlite3"))
        .expect("open direct-provider evidence database");
    let (reserved_input, normalized_input, capability_json) = database
        .query_row(
            "SELECT reservation.input_tokens, manifest.total_token_estimate, \
                    attempt.capability_snapshot_json \
             FROM model_attempt attempt \
             JOIN budget_reservation reservation USING(attempt_id) \
             JOIN context_manifest manifest ON manifest.id = attempt.context_manifest_id",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .expect("durable direct-provider reservation");
    assert_eq!(
        reserved_input,
        normalized_input + i64::try_from(DIRECT_PROVIDER_INPUT_TOKEN_OVERHEAD).unwrap()
    );
    let capabilities: Value =
        serde_json::from_str(&capability_json).expect("capability snapshot JSON");
    assert_eq!(
        capabilities["inputTokenOverhead"],
        DIRECT_PROVIDER_INPUT_TOKEN_OVERHEAD
    );

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let deltas = timeline
        .events
        .iter()
        .filter(|event| event.event_type == "model.output.delta")
        .collect::<Vec<_>>();
    assert_eq!(deltas.len(), 1);
    assert_eq!(
        deltas[0].payload["delta"],
        "The real provider path completed safely."
    );
    assert_eq!(deltas[0].payload["progress_sequence"], 0);
    assert_eq!(deltas[0].payload["authoritative"], false);
    assert_eq!(
        deltas[0].payload["cumulative_bytes"],
        "The real provider path completed safely.".len()
    );
    let completion = timeline
        .events
        .iter()
        .find(|event| event.event_type == "model.attempt.completed")
        .expect("terminal provider event");
    assert!(deltas[0].cursor.0 < completion.cursor.0);
    assert!(deltas[0].occurred_at_ms <= completion.occurred_at_ms);

    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(
        replay.evidence_complete,
        "streaming replay rejected timeline: {:#?}",
        timeline.events
    );
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
    sleep(Duration::from_millis(50)).await;
    assert_eq!(state.requests().len(), 1);
    rusqlite::Connection::open(home.path().join("mealy.sqlite3"))
        .expect("open progress corruption fixture")
        .execute(
            "UPDATE journal_event SET payload_json = json_set(payload_json, '$.delta', 'tampered') \
             WHERE event_type = 'model.output.delta'",
            [],
        )
        .expect("corrupt streamed progress evidence");
    let corrupted_replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(!corrupted_replay.evidence_complete);
    assert_eq!(state.requests().len(), 1);
    assert_eq!(
        fs::read(home.path().join("provider-secrets/process-proof.key"))
            .expect("brokered provider secret"),
        b"process-proof-secret"
    );
    assert!(!non_broker_state_contains(
        home.path(),
        b"process-proof-secret"
    ));
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn exact_image_input_normalizes_dispatches_exports_and_replays_without_live_redispatch() {
    const ONE_PIXEL_PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

    let state = MockProviderState::default();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    enable_provider_image_input(home.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("image HTTP client");
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let artifact_id = ArtifactId::new();
    let request = SubmitImageInputRequest {
        api_version: API_VERSION.to_owned(),
        idempotency_key: "process-image-input".to_owned(),
        delivery_mode: DeliveryMode::Queue,
        content: "Describe this canonical image.".to_owned(),
        provider_selection: ProviderSelectionCommand::Exact {
            provider_id: "process-proof.responses".to_owned(),
            model_id: "process-proof-model".to_owned(),
        },
        images: vec![SubmittedImageInput {
            artifact_id: artifact_id.to_string(),
            media_type: "image/png".to_owned(),
            data_base64: ONE_PIXEL_PNG.to_owned(),
        }],
    };
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/image-inputs", session.session_id),
        &request,
    )
    .await;
    assert_eq!(admission.image_artifact_ids, vec![artifact_id.to_string()]);
    assert!(!admission.duplicate);
    let duplicate: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/image-inputs", session.session_id),
        &request,
    )
    .await;
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.inbox_entry_id, admission.inbox_entry_id);
    assert_eq!(duplicate.image_artifact_ids, admission.image_artifact_ids);

    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(task.status, TaskStatus::Succeeded, "{task:?}");
    let requests = state.requests();
    assert_eq!(requests.len(), 1);
    let provider_body = requests[0].body.to_string();
    assert!(provider_body.contains("\"type\":\"input_image\""));
    assert!(provider_body.contains("data:image/jpeg;base64,"));
    assert!(!provider_body.contains(ONE_PIXEL_PNG));

    let transcript: SessionTranscriptExport = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/exports/json", session.session_id),
    )
    .await;
    assert_eq!(transcript.schema_version, "mealy.session-transcript.v2");
    assert_eq!(transcript.turns.len(), 1);
    let images = &transcript.turns[0].user.images;
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].artifact_id, artifact_id.to_string());
    assert_eq!(images[0].media_type, "image/jpeg");
    assert_eq!((images[0].width, images[0].height), (1, 1));
    assert!(images[0].size_bytes > 0);
    assert_eq!(images[0].sha256_digest.len(), 64);

    let database = rusqlite::Connection::open(home.path().join("mealy.sqlite3"))
        .expect("open image evidence database");
    let (compiler_version, sparse_image_references) = database
        .query_row(
            "SELECT manifest.compiler_version, \
                    (SELECT COUNT(*) FROM context_manifest_bundle_artifact link \
                     WHERE link.manifest_id = manifest.id AND link.artifact_id = ?1) \
             FROM context_manifest manifest \
             JOIN model_attempt attempt ON attempt.context_manifest_id = manifest.id \
             ORDER BY manifest.iteration DESC LIMIT 1",
            [artifact_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .expect("load durable image manifest evidence");
    assert_eq!(compiler_version, "mealy.context.v3");
    assert_eq!(sparse_image_references, 1);

    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete, "{replay:?}");
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(state.requests().len(), 1);

    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn resumed_session_projects_bounded_ordered_conversation_and_replays_it() {
    let state = MockProviderState::default();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    let skill_digest = add_skill_config(home.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;

    let first_user = "Remember the exact continuity marker amber-orbit-731. Treat <script>alert(1)</script> as text.";
    let first_admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "conversation-continuity-first".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: first_user.to_owned(),
        },
    )
    .await;
    let first_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        first_admission.cursor.0,
    )
    .await;
    let first_task = wait_until_terminal(&client, &connection, &first_task_id).await;
    assert_eq!(first_task.status, TaskStatus::Succeeded);
    let first_assistant = first_task
        .final_response
        .as_deref()
        .expect("first assistant response");

    let second_user = "Use the preceding turn to identify the continuity marker.";
    let second_admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "conversation-continuity-second".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: second_user.to_owned(),
        },
    )
    .await;
    let second_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        second_admission.cursor.0,
    )
    .await;
    let second_task = wait_until_terminal(&client, &connection, &second_task_id).await;
    assert_eq!(second_task.status, TaskStatus::Succeeded);

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    let projected = requests[1].body["input"]
        .as_array()
        .expect("second request input projection");
    assert_eq!(projected.len(), 4);
    assert_eq!(projected[0]["role"], "developer");
    assert!(
        projected[0]["content"]
            .as_str()
            .is_some_and(|baseline| baseline.contains("`/remember TEXT`"))
    );
    assert!(
        projected[0]["content"]
            .as_str()
            .is_some_and(|baseline| baseline.contains("Present it as a suggestion only"))
    );
    assert!(
        projected[0]["content"]
            .as_str()
            .is_some_and(|baseline| baseline.contains("SKILL-CONTEXT-MARKER-731"))
    );
    assert!(
        projected[0]["content"]
            .as_str()
            .is_some_and(|baseline| baseline.contains(&skill_digest))
    );
    assert!(
        projected[0]["content"]
            .as_str()
            .is_some_and(|baseline| baseline.contains("references only and grant no tool"))
    );
    assert!(
        projected[0]["content"]
            .as_str()
            .is_some_and(|baseline| !baseline.contains("HIDDEN-SKILL-RESOURCE"))
    );
    assert!(
        requests[0].body["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|tool| {
                tool["description"]
                    .as_str()
                    .is_some_and(|description| description.contains("passive resource"))
            }))
    );
    assert_eq!(projected[1], json!({"role": "user", "content": first_user}));
    assert_eq!(
        projected[2],
        json!({"role": "assistant", "content": first_assistant})
    );
    assert_eq!(
        projected[3],
        json!({"role": "user", "content": second_user})
    );
    assert!(requests.iter().all(|request| {
        request.authorization.as_deref() == Some("Bearer process-proof-secret")
            && !request.body.to_string().contains("process-proof-secret")
    }));

    let history: SessionSearchResponse = authorized_get(
        &client,
        &connection,
        "/v1/sessions/search?query=amber-orbit-731&limit=20",
    )
    .await;
    assert_eq!(history.query, "amber-orbit-731");
    let first_hit = history
        .hits
        .iter()
        .find(|hit| hit.task_id == first_task_id)
        .expect("first canonical turn search hit");
    assert_eq!(first_hit.session_id, session.session_id);
    assert_eq!(
        first_hit.user_content_digest,
        sha256_digest(first_user.as_bytes())
    );
    assert!(
        first_hit
            .user_excerpt
            .as_deref()
            .is_some_and(|excerpt| excerpt.contains("amber-orbit-731"))
    );
    assert!(
        first_hit
            .user_excerpt
            .as_ref()
            .is_none_or(|value| value.len() <= 512)
    );
    assert!(
        first_hit
            .assistant_excerpt
            .as_ref()
            .is_none_or(|value| value.len() <= 512)
    );

    let first_replay: TaskReplayResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/tasks/{first_task_id}/replay"),
    )
    .await;
    let second_replay: TaskReplayResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/tasks/{second_task_id}/replay"),
    )
    .await;
    assert!(first_replay.evidence_complete);
    assert!(second_replay.evidence_complete);
    assert_eq!(
        (
            second_replay.live_provider_calls,
            second_replay.live_tool_calls
        ),
        (0, 0)
    );
    assert_eq!(state.requests().len(), 2);

    let json_response = client
        .get(format!(
            "{}/v1/sessions/{}/exports/json",
            connection.base_url, session.session_id
        ))
        .bearer_auth(&connection.bearer_token)
        .send()
        .await
        .expect("session JSON export");
    assert_eq!(json_response.status(), StatusCode::OK);
    assert_eq!(
        json_response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/vnd.mealy.session-transcript+json; charset=utf-8")
    );
    let json_digest = json_response
        .headers()
        .get("x-mealy-content-sha256")
        .and_then(|value| value.to_str().ok())
        .expect("session JSON digest")
        .to_owned();
    let json_bytes = json_response.bytes().await.expect("session JSON bytes");
    assert_eq!(sha256_digest(&json_bytes), json_digest);
    assert!(
        !json_bytes
            .windows(b"process-proof-secret".len())
            .any(|window| { window == b"process-proof-secret" })
    );
    assert!(
        !json_bytes
            .windows(home.path().as_os_str().len())
            .any(|window| window == home.path().as_os_str().as_encoded_bytes())
    );
    let transcript: SessionTranscriptExport =
        serde_json::from_slice(&json_bytes).expect("session transcript JSON");
    assert_eq!(transcript.schema_version, "mealy.session-transcript.v2");
    assert_eq!(transcript.session_id, session.session_id);
    assert_eq!(transcript.bounds.total_eligible_turns, 2);
    assert_eq!(transcript.bounds.omitted_turns, 0);
    assert_eq!(transcript.turns.len(), 2);
    assert_eq!(transcript.turns[0].user.content, first_user);
    assert_eq!(transcript.turns[0].assistant.content, first_assistant);
    assert!(
        transcript
            .turns
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );
    assert!(
        transcript
            .turns
            .iter()
            .all(|turn| turn.user.citation.cursor < turn.completion.cursor)
    );
    assert!(transcript.redaction.transcript_content_verbatim);
    assert!(!transcript.redaction.automatic_secret_redaction_applied);

    let html_response = client
        .get(format!(
            "{}/v1/sessions/{}/exports/html",
            connection.base_url, session.session_id
        ))
        .bearer_auth(&connection.bearer_token)
        .send()
        .await
        .expect("session HTML export");
    assert_eq!(html_response.status(), StatusCode::OK);
    assert_eq!(
        html_response
            .headers()
            .get(reqwest::header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    );
    let html_digest = html_response
        .headers()
        .get("x-mealy-content-sha256")
        .and_then(|value| value.to_str().ok())
        .expect("session HTML digest")
        .to_owned();
    let html_bytes = html_response.bytes().await.expect("session HTML bytes");
    assert_eq!(sha256_digest(&html_bytes), html_digest);
    let html = std::str::from_utf8(&html_bytes).expect("session HTML UTF-8");
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.to_ascii_lowercase().contains("<script"));
    assert!(!html.contains("process-proof-secret"));
    assert!(!html.contains(&home.path().display().to_string()));

    let source_status: SessionStatusResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/status", session.session_id),
    )
    .await;
    let checkpoint: SessionCheckpointResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/checkpoints", session.session_id),
        &CreateSessionCheckpointRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: source_status.revision,
            label: Some("Continuity branch".to_owned()),
        },
    )
    .await;
    let fork: SessionForkResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/forks", session.session_id),
        &ForkSessionRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "conversation-continuity-fork".to_owned(),
            checkpoint_id: checkpoint.checkpoint_id.clone(),
        },
    )
    .await;
    assert_eq!(fork.source_session_id, session.session_id);
    assert_eq!(fork.source_checkpoint_id, checkpoint.checkpoint_id);
    assert_eq!(fork.referenced_turns, 2);
    assert!(!fork.duplicate);
    let fresh_fork_timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=100", fork.fork_session_id),
    )
    .await;
    assert_eq!(fresh_fork_timeline.events.len(), 1);
    assert_eq!(fresh_fork_timeline.events[0].event_type, "session.forked");

    let fork_user = "Continue from the fork and repeat the continuity marker.";
    let fork_admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", fork.fork_session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "conversation-continuity-fork-first".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: fork_user.to_owned(),
        },
    )
    .await;
    let fork_task_id = wait_for_task_id(
        &client,
        &connection,
        &fork.fork_session_id,
        fork_admission.cursor.0,
    )
    .await;
    let fork_task = wait_until_terminal(&client, &connection, &fork_task_id).await;
    assert_eq!(fork_task.status, TaskStatus::Succeeded);
    let requests = state.requests();
    assert_eq!(requests.len(), 3);
    let fork_projection = requests[2].body["input"]
        .as_array()
        .expect("fork request input projection");
    assert_eq!(fork_projection.len(), 6);
    assert_eq!(
        fork_projection[1],
        json!({"role": "user", "content": first_user})
    );
    assert_eq!(
        fork_projection[2],
        json!({"role": "assistant", "content": first_assistant})
    );
    assert_eq!(
        fork_projection[3],
        json!({"role": "user", "content": second_user})
    );
    assert_eq!(
        fork_projection[4],
        json!({
            "role": "assistant",
            "content": second_task.final_response.expect("second assistant response")
        })
    );
    assert_eq!(
        fork_projection[5],
        json!({"role": "user", "content": fork_user})
    );
    let fork_export: SessionTranscriptExport = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/exports/json", fork.fork_session_id),
    )
    .await;
    assert_eq!(fork_export.lineage.root_session_id, session.session_id);
    assert_eq!(
        fork_export.lineage.parent_session_id.as_deref(),
        Some(session.session_id.as_str())
    );
    assert_eq!(
        fork_export.lineage.parent_checkpoint_id.as_deref(),
        Some(checkpoint.checkpoint_id.as_str())
    );
    assert_eq!(fork_export.turns.len(), 1);
    assert_eq!(fork_export.turns[0].user.content, fork_user);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transcript_export_verifies_oversized_inline_final_messages() {
    let state = MockProviderState::default();
    let (base_url, provider_server) = spawn_provider(state).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "artifact-transcript-export".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Return the LARGE-TRANSCRIPT-ARTIFACT fixture.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(task.status, TaskStatus::Succeeded);
    assert!(task.final_response.is_some());

    let transcript: SessionTranscriptExport = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/exports/json", session.session_id),
    )
    .await;
    assert_eq!(transcript.turns.len(), 1);
    let assistant = &transcript.turns[0].assistant;
    assert_eq!(assistant.storage, "inline");
    assert!(assistant.artifact_id.is_none());
    assert!(assistant.content.starts_with("LARGE-TRANSCRIPT-ARTIFACT:"));
    assert!(assistant.byte_length > 1_024);
    assert_eq!(
        sha256_digest(assistant.content.as_bytes()),
        assistant.content_digest
    );

    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn enabled_skill_resource_is_bounded_cited_and_recorded_replayable() {
    let state = MockProviderState::with_skill_resource_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    add_skill_config(home.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(
        status.enabled_read_tools,
        [
            "agent.delegate",
            "agent.delegate_parallel",
            "skill.read_resource"
        ]
    );
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "skill-resource-process-proof".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Read the enabled skill's passive resource and cite it.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(task.status, TaskStatus::Succeeded, "skill task: {task:?}");
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.tool_calls, 1);
    assert!(task.final_response.as_deref().is_some_and(|response| {
        response.contains("skill://mealy.fixture.continuity/resources/private.txt")
    }));

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(3));
    assert!(requests[0].body.to_string().contains("skill.read_resource"));
    assert!(
        requests[1]
            .body
            .to_string()
            .contains("HIDDEN-SKILL-RESOURCE")
    );
    assert!(
        !requests[0]
            .body
            .to_string()
            .contains("HIDDEN-SKILL-RESOURCE")
    );

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let tool_result = timeline
        .events
        .iter()
        .find(|event| event.event_type == "tool.call.succeeded")
        .expect("skill resource timeline evidence");
    assert_eq!(
        tool_result.payload["source_locator"],
        "skill://mealy.fixture.continuity/resources/private.txt"
    );
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.model_attempts, 2);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.requests().len(), 2);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn provider_delegation_runs_isolated_child_and_resumes_parent_with_recorded_result() {
    let state = MockProviderState::with_delegation_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(
        status.enabled_read_tools,
        ["agent.delegate", "agent.delegate_parallel"]
    );

    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "durable-delegation-process-proof".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Use a bounded child to independently assess this delegation request."
                .to_owned(),
        },
    )
    .await;
    let parent_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let parent = wait_until_terminal(&client, &connection, &parent_task_id).await;
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let terminal_events = timeline
        .events
        .iter()
        .filter(|event| {
            matches!(
                event.event_type.as_str(),
                "run.failed" | "task.failed" | "turn.failed"
            )
        })
        .collect::<Vec<_>>();
    let prepared_event = timeline
        .events
        .iter()
        .find(|event| event.event_type == "delegation.prepared");
    let child_run_id = prepared_event.and_then(|event| event.payload["child_run_id"].as_str());
    let child_events = timeline
        .events
        .iter()
        .filter(|event| child_run_id == Some(event.aggregate_id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        parent.status,
        TaskStatus::Succeeded,
        "parent task: {parent:?}; terminal events: {terminal_events:?}; child events: {child_events:?}"
    );
    assert_eq!(parent.model_attempts, 2);
    assert_eq!(parent.tool_calls, 1);
    assert_eq!(parent.usage.used_delegated_runs, 1);
    assert_eq!(parent.usage.reserved_delegated_runs, 0);
    assert!(
        parent
            .final_response
            .as_deref()
            .is_some_and(|response| { response.contains("delegation://result") })
    );

    let prepared = timeline
        .events
        .iter()
        .find(|event| event.event_type == "delegation.prepared")
        .expect("delegation prepared event");
    let child_task_id = prepared.payload["child_task_id"]
        .as_str()
        .expect("child task ID");
    let child: TaskResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{child_task_id}")).await;
    assert_eq!(child.status, TaskStatus::Succeeded, "child task: {child:?}");
    assert_eq!(child.model_attempts, 1);
    assert_eq!(child.tool_calls, 0);
    let delegations: DelegationsResponse =
        authorized_get(&client, &connection, "/v1/delegations?limit=20").await;
    assert_eq!(delegations.delegations.len(), 1);
    let delegation = &delegations.delegations[0];
    assert_eq!(delegation.parent_run_id, parent.run_id);
    assert_eq!(delegation.child_task_id, child_task_id);
    assert_eq!(delegation.state, "succeeded");
    assert_eq!(delegation.effective_capabilities["maximumDelegatedRuns"], 0);
    assert_eq!(
        delegation
            .result
            .as_ref()
            .map(|value| &value["sourceLocator"]),
        Some(&json!("delegation://result"))
    );
    let delegation_status: DelegationResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/delegations/{}", delegation.delegation_id),
    )
    .await;
    assert_eq!(delegation_status, *delegation);
    assert!(timeline.events.iter().any(|event| {
        event.event_type == "delegation.succeeded"
            && event.payload["result_digest"].as_str().is_some()
    }));
    assert!(timeline.events.iter().any(|event| {
        event.event_type == "tool.call.succeeded"
            && event.payload["source_locator"] == "delegation://result"
    }));

    let requests = state.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].body.to_string().contains("agent.delegate"));
    assert!(
        requests[1]
            .body
            .to_string()
            .contains("ISOLATED DELEGATED WORK PACKAGE")
    );
    assert!(
        !requests[1]
            .body
            .to_string()
            .contains("Use a bounded child to independently assess this delegation request.")
    );
    assert_eq!(requests[1].body["tools"].as_array().map(Vec::len), Some(0));
    assert!(requests[2].body.to_string().contains("delegation://result"));
    assert!(requests[2].body.to_string().contains(
        "The isolated child execution completed and returned a result suitable for the waiting parent."
    ));

    let parent_replay: TaskReplayResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/tasks/{parent_task_id}/replay"),
    )
    .await;
    assert!(
        parent_replay.evidence_complete,
        "parent replay: {parent_replay:?}"
    );
    assert_eq!(parent_replay.tool_calls, 1);
    assert_eq!(
        (
            parent_replay.live_provider_calls,
            parent_replay.live_tool_calls
        ),
        (0, 0)
    );
    let child_replay: TaskReplayResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/tasks/{child_task_id}/replay"),
    )
    .await;
    assert!(
        child_replay.evidence_complete,
        "child replay: {child_replay:?}"
    );
    assert_eq!(
        (child_replay.model_attempts, child_replay.tool_calls),
        (1, 0)
    );
    assert_eq!(
        (
            child_replay.live_provider_calls,
            child_replay.live_tool_calls
        ),
        (0, 0)
    );
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn parallel_delegation_is_atomic_ordered_and_resumes_only_after_both_children() {
    let state = MockProviderState::with_parallel_delegation_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "parallel-delegation-process-proof".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Run two independent bounded checks concurrently and combine them.".to_owned(),
        },
    )
    .await;
    let parent_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let parent = wait_until_terminal(&client, &connection, &parent_task_id).await;
    assert_eq!(parent.status, TaskStatus::Succeeded, "parent: {parent:?}");
    assert_eq!((parent.model_attempts, parent.tool_calls), (2, 1));
    assert_eq!(
        (
            parent.usage.used_delegated_runs,
            parent.usage.reserved_delegated_runs
        ),
        (2, 0)
    );
    assert!(
        parent
            .final_response
            .as_deref()
            .is_some_and(|response| { response.contains("delegation://group-result") })
    );

    let delegations: DelegationsResponse =
        authorized_get(&client, &connection, "/v1/delegations?limit=20").await;
    assert_eq!(delegations.delegations.len(), 2);
    assert!(
        delegations
            .delegations
            .iter()
            .all(|delegation| delegation.state == "succeeded"),
        "delegations: {delegations:?}"
    );
    for delegation in &delegations.delegations {
        let child: TaskResponse = authorized_get(
            &client,
            &connection,
            &format!("/v1/tasks/{}", delegation.child_task_id),
        )
        .await;
        assert_eq!(child.status, TaskStatus::Succeeded, "child: {child:?}");
        let replay: TaskReplayResponse = authorized_get(
            &client,
            &connection,
            &format!("/v1/tasks/{}/replay", delegation.child_task_id),
        )
        .await;
        assert!(replay.evidence_complete, "child replay: {replay:?}");
    }

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "delegation_group.prepared")
            .count(),
        1
    );
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "delegation_group.settled")
            .count(),
        1
    );
    assert!(timeline.events.iter().any(|event| {
        event.event_type == "tool.call.succeeded"
            && event.payload["source_locator"] == "delegation://group-result"
    }));

    let requests = state.requests();
    assert_eq!(requests.len(), 4, "provider requests: {requests:?}");
    let child_requests = requests
        .iter()
        .filter(|request| {
            request
                .body
                .to_string()
                .contains("ISOLATED PARALLEL DELEGATED WORK PACKAGE")
        })
        .collect::<Vec<_>>();
    assert_eq!(child_requests.len(), 2);
    assert!(
        child_requests
            .iter()
            .any(|request| request.body.to_string().contains("parallel-first"))
    );
    assert!(
        child_requests
            .iter()
            .any(|request| request.body.to_string().contains("parallel-second"))
    );
    let parent_resume = requests
        .last()
        .expect("parent resume request")
        .body
        .to_string();
    let first_position = parent_resume
        .find("first")
        .expect("first ordered child result");
    let second_position = parent_resume
        .find("second")
        .expect("second ordered child result");
    assert!(first_position < second_position);
    assert!(parent_resume.contains("delegation://group-result"));

    let parent_replay: TaskReplayResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/tasks/{parent_task_id}/replay"),
    )
    .await;
    assert!(
        parent_replay.evidence_complete,
        "parent replay: {parent_replay:?}"
    );
    assert_eq!(
        (
            parent_replay.live_provider_calls,
            parent_replay.live_tool_calls
        ),
        (0, 0)
    );
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn queued_parallel_group_survives_an_abrupt_daemon_restart() {
    let state = MockProviderState::with_parallel_delegation_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();

    let (session_id, parent_task_id) = {
        // Keep the next worker claim far enough away to crash after the complete group commits but
        // before either child can acquire a lease.
        let _daemon = Daemon::spawn_with_agent_interval(home.path(), false, 5_000);
        let connection = wait_until_ready(&client, home.path()).await;
        let session: CreateSessionResponse = authorized_post(
            &client,
            &connection,
            "/v1/sessions",
            &CreateSessionRequest {
                api_version: API_VERSION.to_owned(),
                provider_selection: None,
            },
        )
        .await;
        let admission: InputAdmissionResponse = authorized_post(
            &client,
            &connection,
            &format!("/v1/sessions/{}/inputs", session.session_id),
            &SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                provider_selection: None,
                idempotency_key: "parallel-delegation-abrupt-restart".to_owned(),
                delivery_mode: DeliveryMode::Queue,
                content: "Commit two bounded children, then wait for their ordered result."
                    .to_owned(),
            },
        )
        .await;
        let parent_task_id = wait_for_task_id(
            &client,
            &connection,
            &session.session_id,
            admission.cursor.0,
        )
        .await;
        let group_deadline = Instant::now() + COMPLETION_TIMEOUT;
        let queued = loop {
            let delegations: DelegationsResponse =
                authorized_get(&client, &connection, "/v1/delegations?limit=20").await;
            if delegations.delegations.len() == 2 {
                break delegations;
            }
            assert!(
                Instant::now() < group_deadline,
                "parallel group was not durably admitted before restart"
            );
            sleep(Duration::from_millis(10)).await;
        };
        assert!(
            queued
                .delegations
                .iter()
                .all(|delegation| delegation.state == "queued"),
            "a child escaped the deliberately delayed claim boundary: {queued:?}"
        );
        assert_eq!(
            state.requests().len(),
            1,
            "a child provider request crossed the crash boundary"
        );
        (session.session_id, parent_task_id)
    };
    fs::remove_file(home.path().join("connection.json")).expect("remove stale descriptor");

    let _restarted = Daemon::spawn(home.path(), false);
    let restarted_connection = wait_until_ready(&client, home.path()).await;
    let parent = wait_until_terminal(&client, &restarted_connection, &parent_task_id).await;
    assert_eq!(parent.status, TaskStatus::Succeeded, "parent: {parent:?}");
    assert_eq!(
        (
            parent.usage.used_delegated_runs,
            parent.usage.reserved_delegated_runs
        ),
        (2, 0)
    );
    let delegations: DelegationsResponse =
        authorized_get(&client, &restarted_connection, "/v1/delegations?limit=20").await;
    assert_eq!(delegations.delegations.len(), 2);
    assert!(
        delegations
            .delegations
            .iter()
            .all(|delegation| delegation.state == "succeeded"),
        "recovered delegations: {delegations:?}"
    );
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &restarted_connection,
        &format!("/v1/sessions/{session_id}/timeline?limit=1000"),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "delegation_group.prepared")
            .count(),
        1
    );
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "delegation_group.settled")
            .count(),
        1
    );
    assert_eq!(
        state.requests().len(),
        4,
        "restart duplicated or skipped a provider boundary"
    );
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn over_budget_parallel_group_rolls_back_every_proposed_child() {
    let state = MockProviderState::with_serial_then_over_budget_parallel_delegation();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "parallel-delegation-atomic-budget-rejection".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Run one child, then attempt two more bounded children.".to_owned(),
        },
    )
    .await;
    let parent_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let request_deadline = Instant::now() + COMPLETION_TIMEOUT;
    while state.requests().len() < 3 {
        assert!(
            Instant::now() < request_deadline,
            "parent did not attempt its over-budget parallel group"
        );
        sleep(Duration::from_millis(10)).await;
    }
    // The model response has reached the daemon; allow its immediate writer transaction to
    // reject the second reservation and roll back the first proposed child.
    sleep(Duration::from_millis(250)).await;

    let parent: TaskResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{parent_task_id}")).await;
    assert_eq!(
        (
            parent.usage.used_delegated_runs,
            parent.usage.reserved_delegated_runs
        ),
        (1, 0),
        "partial child budget reservation escaped rollback: {parent:?}"
    );
    let delegations: DelegationsResponse =
        authorized_get(&client, &connection, "/v1/delegations?limit=20").await;
    assert_eq!(
        delegations.delegations.len(),
        1,
        "a proposed parallel child escaped rollback: {delegations:?}"
    );
    assert_eq!(delegations.delegations[0].state, "succeeded");

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "delegation_group.prepared")
            .count(),
        0,
        "failed parallel group published durable evidence: {:?}",
        timeline.events
    );
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn parent_cancellation_propagates_to_an_in_flight_delegated_child() {
    let state = MockProviderState::with_delayed_delegation_tool_call(Duration::from_millis(1_500));
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "delegation-parent-cancellation".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Delegate this bounded assessment, then await its result.".to_owned(),
        },
    )
    .await;
    let parent_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let request_deadline = Instant::now() + COMPLETION_TIMEOUT;
    while state.requests().len() < 2 {
        assert!(
            Instant::now() < request_deadline,
            "delegated child provider request did not begin"
        );
        sleep(Duration::from_millis(10)).await;
    }
    let running: DelegationsResponse =
        authorized_get(&client, &connection, "/v1/delegations?limit=20").await;
    let delegation = running
        .delegations
        .first()
        .expect("running delegation")
        .clone();
    assert_eq!(delegation.state, "running");

    let _: TaskCancellationReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/tasks/{parent_task_id}/cancel"),
        &CancelTaskRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "delegation-parent-cancellation-command".to_owned(),
            reason: "owner cancelled the parent while its child was running".to_owned(),
        },
    )
    .await;
    let parent = wait_until_terminal(&client, &connection, &parent_task_id).await;
    assert_eq!(parent.status, TaskStatus::Cancelled, "parent: {parent:?}");
    assert_eq!(parent.usage.reserved_delegated_runs, 0);
    assert_eq!(parent.usage.used_delegated_runs, 1);
    assert_eq!(parent.usage.reserved_tool_calls, 0);
    assert!(parent.final_response.is_none());

    let terminal: DelegationResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/delegations/{}", delegation.delegation_id),
    )
    .await;
    assert_eq!(terminal.state, "cancelled");
    assert_eq!(
        terminal.result.as_ref().map(|value| &value["status"]),
        Some(&json!("cancelled"))
    );
    let child: TaskResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/tasks/{}", delegation.child_task_id),
    )
    .await;
    assert_eq!(child.status, TaskStatus::Cancelled, "child: {child:?}");
    assert_eq!(child.usage.reserved_model_calls, 0);

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    for event_type in [
        "run.cancellation_waiting_for_delegation",
        "run.child_cancellations_requested",
        "task.child_cancellations_requested",
        "delegation.cancelled",
    ] {
        assert!(
            timeline
                .events
                .iter()
                .any(|event| event.event_type == event_type),
            "missing {event_type}: {:?}",
            timeline.events
        );
    }
    assert_eq!(state.requests().len(), 2);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn parent_cancellation_propagates_to_every_nonterminal_parallel_sibling() {
    let state =
        MockProviderState::with_delayed_parallel_delegation_tool_call(Duration::from_secs(3));
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "parallel-delegation-parent-cancellation".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Run two bounded checks, then await both results.".to_owned(),
        },
    )
    .await;
    let parent_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let request_deadline = Instant::now() + COMPLETION_TIMEOUT;
    while state.requests().len() < 3 {
        assert!(
            Instant::now() < request_deadline,
            "both parallel child provider requests did not begin"
        );
        sleep(Duration::from_millis(10)).await;
    }
    let running: DelegationsResponse =
        authorized_get(&client, &connection, "/v1/delegations?limit=20").await;
    assert_eq!(running.delegations.len(), 2);
    let running_ids = running
        .delegations
        .iter()
        .filter(|delegation| delegation.state == "running")
        .map(|delegation| delegation.delegation_id.clone())
        .collect::<Vec<_>>();
    assert!(
        !running_ids.is_empty()
            && running
                .delegations
                .iter()
                .all(|delegation| matches!(delegation.state.as_str(), "running" | "succeeded")),
        "running delegations: {running:?}"
    );

    let _: TaskCancellationReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/tasks/{parent_task_id}/cancel"),
        &CancelTaskRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "parallel-parent-cancellation-command".to_owned(),
            reason: "owner cancelled the parallel parent".to_owned(),
        },
    )
    .await;
    let parent = wait_until_terminal(&client, &connection, &parent_task_id).await;
    assert_eq!(parent.status, TaskStatus::Cancelled, "parent: {parent:?}");
    assert_eq!(
        (
            parent.usage.used_delegated_runs,
            parent.usage.reserved_delegated_runs,
            parent.usage.reserved_tool_calls
        ),
        (2, 0, 0)
    );
    assert!(parent.final_response.is_none());

    let terminal: DelegationsResponse =
        authorized_get(&client, &connection, "/v1/delegations?limit=20").await;
    assert_eq!(terminal.delegations.len(), 2);
    for delegation in &terminal.delegations {
        let expected = if running_ids.contains(&delegation.delegation_id) {
            "cancelled"
        } else {
            "succeeded"
        };
        assert_eq!(delegation.state, expected, "{delegation:?}");
        assert_eq!(
            delegation
                .result
                .as_ref()
                .and_then(|value| value["status"].as_str()),
            Some(expected)
        );
        let child: TaskResponse = authorized_get(
            &client,
            &connection,
            &format!("/v1/tasks/{}", delegation.child_task_id),
        )
        .await;
        assert_eq!(
            child.status,
            if expected == "cancelled" {
                TaskStatus::Cancelled
            } else {
                TaskStatus::Succeeded
            },
            "child: {child:?}"
        );
    }

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "delegation.cancelled")
            .count(),
        running_ids.len()
    );
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "run.child_cancellations_requested")
            .count(),
        1
    );
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "delegation_group.settled")
            .count(),
        1
    );
    assert_eq!(state.requests().len(), 3);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoint_dispatch_history_survives_a_daemon_restart_without_assuming_live_health() {
    let state = MockProviderState::default();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let first_history = {
        let _daemon = Daemon::spawn(home.path(), false);
        let connection = wait_until_ready(&client, home.path()).await;
        let session: CreateSessionResponse = authorized_post(
            &client,
            &connection,
            "/v1/sessions",
            &CreateSessionRequest {
                api_version: API_VERSION.to_owned(),
                provider_selection: None,
            },
        )
        .await;
        let admission: InputAdmissionResponse = authorized_post(
            &client,
            &connection,
            &format!("/v1/sessions/{}/inputs", session.session_id),
            &SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                provider_selection: None,
                idempotency_key: "provider-history-before-restart".to_owned(),
                delivery_mode: DeliveryMode::Queue,
                content: "Complete one bounded provider-history turn.".to_owned(),
            },
        )
        .await;
        let task_id = wait_for_task_id(
            &client,
            &connection,
            &session.session_id,
            admission.cursor.0,
        )
        .await;
        let task = wait_until_terminal(&client, &connection, &task_id).await;
        assert_eq!(task.status, TaskStatus::Succeeded);
        let status: AdminStatusResponse =
            authorized_get(&client, &connection, "/v1/admin/status").await;
        let endpoint = status.provider_endpoints.first().expect("primary endpoint");
        assert_eq!(endpoint.invocation_count, 1);
        assert_eq!(endpoint.health, "healthy");
        endpoint
            .last_success_at_ms
            .expect("durable provider success time")
    };
    fs::remove_file(home.path().join("connection.json")).expect("remove stale descriptor");

    {
        let _restarted = Daemon::spawn(home.path(), false);
        let connection = wait_until_ready(&client, home.path()).await;
        let status: AdminStatusResponse =
            authorized_get(&client, &connection, "/v1/admin/status").await;
        let endpoint = status.provider_endpoints.first().expect("primary endpoint");
        assert_eq!(endpoint.health, "configured_unprobed");
        assert_eq!(endpoint.invocation_count, 1);
        assert_eq!(endpoint.last_success_at_ms, Some(first_history));
        assert_eq!(endpoint.last_failure_at_ms, None);
        assert_eq!(endpoint.in_flight_requests, 0);
        assert_eq!(endpoint.requests_in_current_minute, 0);
    }
    assert_eq!(state.requests().len(), 1);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn configured_workspace_read_is_least_authority_cited_and_replayable() {
    let state = MockProviderState::with_workspace_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let workspace = TempDir::new().expect("granted workspace");
    fs::write(
        workspace.path().join("notes.txt"),
        format!(
            "{}\nproduction workspace evidence needle\n",
            "bounded-prefix ".repeat(128)
        ),
    )
    .expect("workspace note");
    write_provider_config(home.path(), &base_url);
    add_workspace_config(home.path(), "project", workspace.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(
        status.enabled_read_tools,
        [
            "agent.delegate",
            "agent.delegate_parallel",
            "workspace.list",
            "workspace.read",
            "workspace.search",
            "workspace.stat"
        ]
    );
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-workspace-read".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Read the granted project notes and answer from that evidence.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "workspace task: {task:?}"
    );
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.tool_calls, 1);
    assert!(
        task.final_response
            .as_deref()
            .is_some_and(|response| response.contains("workspace://project/notes.txt"))
    );

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(6));
    assert!(requests[0].body.to_string().contains("workspace.read"));
    assert!(
        requests[1]
            .body
            .to_string()
            .contains("production workspace evidence needle")
    );
    assert!(requests.iter().all(|request| {
        !request
            .body
            .to_string()
            .contains(&workspace.path().display().to_string())
    }));

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let tool_result = timeline
        .events
        .iter()
        .find(|event| event.event_type == "tool.call.succeeded")
        .expect("workspace result timeline evidence");
    assert_eq!(
        tool_result.payload["source_locator"],
        "workspace://project/notes.txt"
    );
    assert!(tool_result.payload["artifact_id"].as_str().is_some());
    assert!(!timeline.events.iter().any(|event| {
        event
            .payload
            .to_string()
            .contains(&workspace.path().display().to_string())
    }));
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.model_attempts, 2);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
    assert_eq!(state.requests().len(), 2);
    rusqlite::Connection::open(home.path().join("mealy.sqlite3"))
        .expect("open capability corruption fixture")
        .execute(
            "UPDATE run SET capability_ceiling_json = '{}' WHERE id = ?1",
            [task.run_id.as_str()],
        )
        .expect("corrupt immutable capability evidence");
    let corrupted_replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(!corrupted_replay.evidence_complete);
    assert_eq!(state.requests().len(), 2);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn configured_mcp_tool_is_sandboxed_model_visible_cited_and_replayable() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_mcp_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    let installed_mcp = add_mcp_config(home.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    // Startup performs an actual fresh-sandbox MCP handshake and complete tool-set verification.
    // Under the full process suite, concurrent daemon and Bubblewrap fixtures can legitimately use
    // more than the ordinary local-provider readiness budget without indicating a deadlock.
    let connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(
        status.enabled_read_tools,
        [
            "agent.delegate",
            "agent.delegate_parallel",
            "mcp.fixture.add"
        ]
    );

    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-mcp-read".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Use the isolated MCP calculator to add 20 and 22.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(task.status, TaskStatus::Succeeded, "MCP task: {task:?}");
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.tool_calls, 1);
    assert!(
        task.final_response
            .as_deref()
            .is_some_and(|response| response.contains("mcp://fixture/add"))
    );

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(3));
    assert!(requests[0].body.to_string().contains("mcp.fixture.add"));
    assert!(requests[1].body.to_string().contains("sum"));
    assert!(requests[1].body.to_string().contains("42"));
    assert!(requests[1].body.to_string().contains("mcp://fixture/add"));
    assert!(requests.iter().all(|request| {
        !request
            .body
            .to_string()
            .contains(&installed_mcp.display().to_string())
            && !request.body.to_string().contains("process-proof-secret")
    }));

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let tool_result = timeline
        .events
        .iter()
        .find(|event| event.event_type == "tool.call.succeeded")
        .expect("MCP result timeline evidence");
    assert_eq!(tool_result.payload["source_locator"], "mcp://fixture/add");
    assert!(tool_result.payload["output_digest"].as_str().is_some());

    fs::remove_file(&installed_mcp).expect("remove live MCP executable before replay");
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.model_attempts, 2);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
    assert_eq!(state.requests().len(), 2);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn owner_classified_mcp_effect_requires_exact_approval_dispatches_once_and_replays() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_mcp_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    let installed_mcp = add_mcp_effect_config(home.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(status.enabled_action_tools, ["mcp.fixture.add"]);
    assert_eq!(
        status.enabled_read_tools,
        ["agent.delegate", "agent.delegate_parallel"]
    );

    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-mcp-effect".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Invoke the reviewed MCP operation with 20 and 22.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("MCP effect must request approval");
    assert_eq!(approval.subject.tool_id, "mcp.fixture.add");
    assert_eq!(approval.subject.target_resources, ["mcp://fixture/add"]);
    assert!(
        approval
            .subject
            .capability_scope
            .starts_with("mcp.invoke:fixture:add:sha256:")
    );
    assert!(
        !approval
            .subject
            .capability_scope
            .contains(&installed_mcp.display().to_string())
    );
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-real-provider-mcp-effect".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let task =
        wait_until_terminal_with_timeout(&client, &connection, &task_id, Duration::from_secs(45))
            .await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "MCP effect task: {task:?}; provider requests: {:?}",
        state.requests()
    );
    assert_eq!((task.model_attempts, task.tool_calls), (2, 1));
    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(3));
    assert!(requests[0].body.to_string().contains("mcp.fixture.add"));
    assert!(requests[1].body.to_string().contains("effectRevision"));
    assert!(requests.iter().all(|request| {
        !request
            .body
            .to_string()
            .contains(&installed_mcp.display().to_string())
            && !request.body.to_string().contains("process-proof-secret")
    }));

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1
    );
    assert!(
        requests[1].body.to_string().contains("mcp://fixture/add"),
        "the second model call must contain only durable MCP outcome evidence"
    );

    fs::remove_file(&installed_mcp).expect("remove live MCP executable before replay");
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete, "replay: {replay:?}");
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.requests().len(), 2);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines, clippy::type_complexity)]
async fn image_generation_reserves_budget_requires_approval_commits_artifact_and_replays() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_image_generation_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    enable_image_generation(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(status.enabled_action_tools, ["image.generate"]);

    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-image-generation".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Generate one approved image of a quiet harbor at dawn.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let approval_deadline = Instant::now() + COMPLETION_TIMEOUT;
    let pending = loop {
        let pending: PendingApprovalsResponse =
            authorized_get(&client, &connection, "/v1/approvals").await;
        if !pending.approvals.is_empty() {
            break pending;
        }
        let current: TaskResponse =
            authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}")).await;
        if matches!(
            current.status,
            TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled
        ) {
            let timeline: TimelinePageResponse = authorized_get(
                &client,
                &connection,
                &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
            )
            .await;
            panic!(
                "image-generation task terminated before approval: {current:?}; requests: {:?}; \
                 timeline: {:?}",
                state.requests(),
                timeline.events
            );
        }
        assert!(
            Instant::now() < approval_deadline,
            "image-generation approval was not requested; task: {current:?}; requests: {:?}",
            state.requests()
        );
        sleep(Duration::from_millis(20)).await;
    };
    let approval = pending
        .approvals
        .first()
        .expect("image generation must request approval");
    assert_eq!(approval.subject.tool_id, "image.generate");
    assert_eq!(
        approval.subject.target_resources,
        ["image-provider://process-proof.images/model/process-proof-image-model"]
    );
    assert!(
        approval
            .subject
            .capability_scope
            .starts_with("media.image.generate:process-proof.images:process-proof-image-model:")
    );
    let waiting: TaskResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}")).await;
    assert_eq!(waiting.usage.reserved_cost_microunits, 50_000);
    assert_eq!(waiting.usage.reserved_output_bytes, 2_097_152);
    assert!(state.image_requests().is_empty());

    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-real-provider-image-generation".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let task =
        wait_until_terminal_with_timeout(&client, &connection, &task_id, Duration::from_secs(45))
            .await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "image-generation task: {task:?}; provider requests: {:?}; image requests: {:?}",
        state.requests(),
        state.image_requests()
    );
    assert_eq!((task.model_attempts, task.tool_calls), (2, 1));
    assert_eq!(task.usage.reserved_cost_microunits, 0);
    assert_eq!(task.usage.reserved_output_bytes, 0);
    assert!(task.usage.used_cost_microunits >= 12_345);
    assert!(task.usage.used_output_bytes > 0);

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].body.to_string().contains("image.generate"));
    assert!(requests[1].body.to_string().contains("artifactId"));
    assert!(requests.iter().all(|request| {
        !request.body.to_string().contains("process-proof-secret")
            && !request
                .body
                .to_string()
                .contains(&home.path().display().to_string())
    }));
    let image_requests = state.image_requests();
    assert_eq!(image_requests.len(), 1);
    assert_eq!(image_requests[0].authorization, None);
    assert_eq!(
        image_requests[0].body,
        json!({
            "model": "process-proof-image-model",
            "n": 1,
            "output_format": "jpeg",
            "prompt": "A quiet harbor at dawn",
            "quality": "low",
            "size": "1024x1024",
            "stream": false
        })
    );

    let database =
        rusqlite::Connection::open(home.path().join("mealy.sqlite3")).expect("open daemon store");
    let (
        reservation_state,
        maximum_cost,
        maximum_output,
        charged_cost,
        charged_output,
        artifact_id,
        artifact_digest,
        artifact_size,
        media_type,
        origin_kind,
        producer_kind,
        producer_id,
        owner_kind,
        relation,
        artifact_event_type,
    ): (
        String,
        i64,
        i64,
        i64,
        i64,
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ) = database
        .query_row(
            "SELECT reservation.state, reservation.maximum_cost_microunits, \
                    reservation.maximum_output_bytes, reservation.charged_cost_microunits, \
                    reservation.charged_output_bytes, artifact.id, artifact.blob_digest, \
                    blob.size_bytes, artifact.media_type, artifact.origin_kind, \
                    artifact.producer_kind, artifact.producer_id, reference.owner_kind, \
                    reference.relation, event.event_type \
             FROM agent_effect_budget_reservation reservation \
             JOIN artifact_reference reference \
               ON reference.owner_kind = 'effect' \
              AND reference.owner_id = reservation.effect_id \
             JOIN artifact ON artifact.id = reference.artifact_id \
             JOIN artifact_blob blob \
               ON blob.algorithm = artifact.blob_algorithm \
              AND blob.digest = artifact.blob_digest \
             JOIN journal_event event \
               ON event.aggregate_kind = 'artifact' \
              AND event.aggregate_id = artifact.id \
              AND event.event_type = 'artifact.committed' \
             WHERE reservation.effect_id = ?1",
            [approval.effect_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                ))
            },
        )
        .expect("settled image-generation artifact evidence");
    assert_eq!(reservation_state, "settled");
    assert_eq!((maximum_cost, maximum_output), (50_000, 2_097_152));
    assert_eq!(charged_cost, 12_345);
    assert_eq!(charged_output, artifact_size);
    assert!(artifact_size > 0 && artifact_size <= 2_097_152);
    assert_eq!(media_type, "image/jpeg");
    assert_eq!(origin_kind, "effect_attempt");
    assert_eq!(producer_kind, "builtin");
    assert_eq!(producer_id, "mealyd.image-generation.v1");
    assert_eq!(
        (owner_kind.as_str(), relation.as_str()),
        ("effect", "output")
    );
    assert_eq!(artifact_event_type, "artifact.committed");
    assert!(
        database
            .execute(
                "UPDATE agent_effect_budget_reservation \
                 SET charged_cost_microunits = charged_cost_microunits + 1 \
                 WHERE effect_id = ?1",
                [approval.effect_id.as_str()],
            )
            .is_err(),
        "settled financial evidence must be immutable"
    );
    assert!(
        database
            .execute(
                "DELETE FROM agent_effect_budget_reservation WHERE effect_id = ?1",
                [approval.effect_id.as_str()],
            )
            .is_err(),
        "settled financial evidence must not be deletable"
    );
    let artifact_path = home.path().join("artifacts/sha256").join(&artifact_digest);
    let artifact_bytes = fs::read(&artifact_path).expect("content-addressed generated artifact");
    assert_eq!(
        i64::try_from(artifact_bytes.len()).expect("artifact size"),
        artifact_size
    );
    assert!(artifact_bytes.starts_with(&[0xff, 0xd8, 0xff]));
    assert!(artifact_bytes.ends_with(&[0xff, 0xd9]));

    let metadata: ArtifactMetadataResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/artifacts/{artifact_id}"),
    )
    .await;
    assert_eq!(metadata.digest, artifact_digest);
    assert_eq!(metadata.size_bytes, u64::try_from(artifact_size).unwrap());
    assert_eq!(metadata.media_type, "image/jpeg");
    assert_eq!(metadata.origin_kind, "effect_attempt");
    assert_eq!(metadata.producer_id, "mealyd.image-generation.v1");
    let content_response = client
        .get(format!(
            "{}/v1/artifacts/{artifact_id}/content",
            connection.base_url
        ))
        .bearer_auth(&connection.bearer_token)
        .send()
        .await
        .expect("authorized artifact content");
    assert_eq!(content_response.status(), StatusCode::OK);
    assert_eq!(
        content_response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("image/jpeg")
    );
    assert_eq!(
        content_response
            .bytes()
            .await
            .expect("artifact bytes")
            .as_ref(),
        artifact_bytes
    );

    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete, "replay: {replay:?}");
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.requests().len(), 2);
    assert_eq!(state.image_requests().len(), 1);
    fs::remove_file(&artifact_path).expect("remove generated blob for replay corruption proof");
    let missing_blob_replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(!missing_blob_replay.evidence_complete);
    assert_eq!(state.requests().len(), 2);
    assert_eq!(state.image_requests().len(), 1);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn denied_image_generation_releases_budget_without_crossing_the_provider_boundary() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_image_generation_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    enable_image_generation(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "deny-real-provider-image-generation".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Propose one image, but do not dispatch it without my approval.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending.approvals.first().expect("image approval");
    assert_eq!(approval.subject.tool_id, "image.generate");
    let waiting: TaskResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}")).await;
    assert_eq!(waiting.usage.reserved_cost_microunits, 50_000);
    assert_eq!(waiting.usage.reserved_output_bytes, 2_097_152);
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "deny-image-generation-exact-subject".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Deny,
        },
    )
    .await;
    let task =
        wait_until_terminal_with_timeout(&client, &connection, &task_id, Duration::from_secs(45))
            .await;
    assert_eq!(task.status, TaskStatus::Succeeded, "denied task: {task:?}");
    assert_eq!(task.usage.reserved_cost_microunits, 0);
    assert_eq!(task.usage.reserved_output_bytes, 0);
    assert_eq!(state.image_requests().len(), 0);

    let database =
        rusqlite::Connection::open(home.path().join("mealy.sqlite3")).expect("open daemon store");
    let reservation: (String, i64, i64, Option<i64>) = database
        .query_row(
            "SELECT state, charged_cost_microunits, charged_output_bytes, settled_at_ms \
             FROM agent_effect_budget_reservation WHERE effect_id = ?1",
            [approval.effect_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("denied reservation settlement");
    assert_eq!(reservation.0, "settled");
    assert_eq!((reservation.1, reservation.2), (0, 0));
    assert!(reservation.3.is_some());
    let artifact_count: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM artifact_reference \
             WHERE owner_kind = 'effect' AND owner_id = ?1",
            [approval.effect_id.as_str()],
            |row| row.get(0),
        )
        .expect("denied artifact count");
    assert_eq!(artifact_count, 0);

    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete, "denied replay: {replay:?}");
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.image_requests().len(), 0);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn image_generation_dispatch_crash_never_retries_and_charges_the_full_reserved_cost() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_image_generation_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    enable_image_generation(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let mut first_daemon = Daemon::spawn_with_effect_outcome_delay(home.path(), 60_000);
    let first_connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "image-generation-dispatch-crash".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Generate one image after exact approval.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &first_connection).await;
    let approval = pending.approvals.first().expect("image approval");
    let effect_id = approval.effect_id.clone();
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-image-generation-dispatch-crash".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let dispatch_deadline = Instant::now() + Duration::from_secs(15);
    let attempt_id = loop {
        let timeline: TimelinePageResponse = authorized_get(
            &client,
            &first_connection,
            &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
        )
        .await;
        if state.image_requests().len() == 1
            && let Some(event) = timeline
                .events
                .iter()
                .find(|event| event.event_type == "effect.dispatched")
        {
            break event.payload["attempt_id"]
                .as_str()
                .expect("image dispatch attempt")
                .to_owned();
        }
        assert!(
            Instant::now() < dispatch_deadline,
            "image generation never crossed the durable dispatch boundary"
        );
        sleep(Duration::from_millis(10)).await;
    };
    first_daemon.kill_and_wait();

    let _recovered_daemon = Daemon::spawn(home.path(), false);
    let recovered_connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let unknown = wait_until_effect_status(
        &client,
        &recovered_connection,
        &effect_id,
        EffectStatusResponse::OutcomeUnknown,
    )
    .await;
    let parked: TaskResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/tasks/{task_id}"),
    )
    .await;
    assert_eq!(parked.status, TaskStatus::Waiting);
    assert_eq!(parked.usage.reserved_cost_microunits, 0);
    assert_eq!(parked.usage.reserved_output_bytes, 0);
    assert!(parked.usage.used_cost_microunits >= 50_000);
    assert_eq!(state.image_requests().len(), 1);
    let database = rusqlite::Connection::open(home.path().join("mealy.sqlite3"))
        .expect("open recovered store");
    let reservation: (String, i64, i64) = database
        .query_row(
            "SELECT state, charged_cost_microunits, charged_output_bytes \
             FROM agent_effect_budget_reservation WHERE effect_id = ?1",
            [effect_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("recovered image reservation");
    assert_eq!(reservation, ("settled".to_owned(), 50_000, 0));
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1,
        "never-retry image generation must not redispatch after recovery"
    );

    let receipt: EffectReconciliationReceipt = authorized_post(
        &client,
        &recovered_connection,
        &format!("/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile"),
        &ReconcileEffectRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "reconcile-image-generation-dispatch-crash".to_owned(),
            expected_effect_revision: unknown.revision,
            outcome: ReconciliationOutcomeCommand::Failed,
            evidence: json!({
                "basis": "owner could not establish a retrievable generated artifact",
                "providerRequestCount": 1,
            }),
        },
    )
    .await;
    assert_eq!(receipt.outcome, ReconciliationOutcomeCommand::Failed);
    let task = wait_until_terminal_with_timeout(
        &client,
        &recovered_connection,
        &task_id,
        Duration::from_secs(45),
    )
    .await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "reconciled task: {task:?}"
    );
    assert!(task.usage.used_cost_microunits >= 50_000);
    assert_eq!(state.image_requests().len(), 1);
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(replay.evidence_complete, "crash replay: {replay:?}");
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.image_requests().len(), 1);
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn idempotent_mcp_effect_retries_after_crash_at_dispatch_boundary_and_replays() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_mcp_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    add_mcp_effect_config(home.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let mut first_daemon = Daemon::spawn_with_effect_outcome_delay(home.path(), 60_000);
    let first_connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "mcp-effect-crash-recovery".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Invoke the reviewed idempotent MCP operation with 20 and 22.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &first_connection).await;
    let approval = pending.approvals.first().expect("MCP effect approval");
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-mcp-effect-crash-recovery".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let timeline: TimelinePageResponse = authorized_get(
            &client,
            &first_connection,
            &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
        )
        .await;
        if timeline
            .events
            .iter()
            .any(|event| event.event_type == "effect.dispatched")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "MCP effect never crossed the durable dispatch boundary"
        );
        sleep(Duration::from_millis(10)).await;
    }
    first_daemon.kill_and_wait();

    let _recovered_daemon = Daemon::spawn(home.path(), false);
    let recovered_connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let task = wait_until_terminal_with_timeout(
        &client,
        &recovered_connection,
        &task_id,
        Duration::from_secs(45),
    )
    .await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "recovered MCP effect task: {task:?}"
    );
    assert_eq!((task.model_attempts, task.tool_calls), (2, 1));
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        2,
        "an idempotent interrupted call must create one new fenced retry attempt"
    );
    assert_eq!(state.requests().len(), 2);
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(replay.evidence_complete, "recovered replay: {replay:?}");
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn non_idempotent_mcp_effect_parks_after_dispatch_crash_until_owner_reconciles() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_mcp_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    add_mcp_non_idempotent_effect_config(home.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let mut first_daemon = Daemon::spawn_with_effect_outcome_delay(home.path(), 60_000);
    let first_connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "mcp-non-idempotent-crash-recovery".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Invoke the reviewed non-idempotent MCP operation with 20 and 22.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &first_connection).await;
    let approval = pending.approvals.first().expect("MCP effect approval");
    let effect_id = approval.effect_id.clone();
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-mcp-non-idempotent-crash-recovery".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(15);
    let attempt_id = loop {
        let timeline: TimelinePageResponse = authorized_get(
            &client,
            &first_connection,
            &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
        )
        .await;
        if let Some(event) = timeline
            .events
            .iter()
            .find(|event| event.event_type == "effect.dispatched")
        {
            break event.payload["attempt_id"]
                .as_str()
                .expect("dispatch attempt id")
                .to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "non-idempotent MCP effect never crossed the durable dispatch boundary"
        );
        sleep(Duration::from_millis(10)).await;
    };
    first_daemon.kill_and_wait();

    let _recovered_daemon = Daemon::spawn(home.path(), false);
    let recovered_connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let unknown = wait_until_effect_status(
        &client,
        &recovered_connection,
        &effect_id,
        EffectStatusResponse::OutcomeUnknown,
    )
    .await;
    let parked: TaskResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/tasks/{task_id}"),
    )
    .await;
    assert_eq!(parked.status, TaskStatus::Waiting);
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1,
        "a non-idempotent interrupted call must never be retried automatically"
    );
    assert_eq!(
        state.requests().len(),
        1,
        "the model must remain parked until explicit reconciliation"
    );

    let receipt: EffectReconciliationReceipt = authorized_post(
        &client,
        &recovered_connection,
        &format!("/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile"),
        &ReconcileEffectRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "reconcile-mcp-non-idempotent-crash-recovery".to_owned(),
            expected_effect_revision: unknown.revision,
            outcome: ReconciliationOutcomeCommand::Succeeded,
            evidence: json!({
                "basis": "owner verified the remote MCP operation completed",
                "remoteReference": "fixture:add:20+22",
            }),
        },
    )
    .await;
    assert_eq!(receipt.effect_id, effect_id);
    assert_eq!(receipt.attempt_id, attempt_id);
    assert_eq!(receipt.outcome, ReconciliationOutcomeCommand::Succeeded);

    let task = wait_until_terminal_with_timeout(
        &client,
        &recovered_connection,
        &task_id,
        Duration::from_secs(45),
    )
    .await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "reconciled non-idempotent MCP effect task: {task:?}"
    );
    assert_eq!((task.model_attempts, task.tool_calls), (2, 1));
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1
    );
    assert_eq!(state.requests().len(), 2);
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(
        replay.evidence_complete,
        "reconciled non-idempotent replay: {replay:?}"
    );
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "set MEALY_BROWSER_BUNDLE to a reviewed Chrome Headless Shell bundle"]
#[allow(clippy::too_many_lines)]
async fn configured_browser_is_rendered_isolated_cited_and_replays_without_live_chrome() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let source = std::env::var_os("MEALY_BROWSER_BUNDLE")
        .map(std::path::PathBuf::from)
        .expect("reviewed browser bundle path");
    let (web_origin, web_requests, web_server) = spawn_web_server().await;
    let state = MockProviderState::with_browser_tool_call(web_origin.clone());
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    let browser_path = add_browser_config(home.path(), &source, &web_origin);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(
        status.enabled_read_tools,
        [
            "agent.delegate",
            "agent.delegate_parallel",
            "browser.snapshot",
            "web.fetch",
        ]
    );

    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-browser-snapshot".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Render the authorized page in the isolated browser and cite it.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal_with_timeout(
        &client,
        &connection,
        &task_id,
        BROWSER_TASK_COMPLETION_TIMEOUT,
    )
    .await;
    assert_eq!(task.status, TaskStatus::Succeeded, "browser task: {task:?}");
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.tool_calls, 1);
    assert!(
        task.final_response
            .as_deref()
            .is_some_and(|response| { response.contains(&format!("{web_origin}/page")) })
    );

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(4));
    assert!(requests[0].body.to_string().contains("browser.snapshot"));
    assert!(requests[0].body.to_string().contains("downloadLink"));
    assert!(
        requests[1]
            .body
            .to_string()
            .contains("web production evidence needle")
    );
    assert!(
        requests[1]
            .body
            .to_string()
            .contains("browser GET form evidence needle")
    );
    assert!(requests[1].body.to_string().contains("filledElement"));
    assert!(requests[1].body.to_string().contains("submittedUrl"));
    assert!(!requests[1].body.to_string().contains("must-not-submit"));
    assert!(requests[1].body.to_string().contains("image/png"));
    assert!(web_requests.load(Ordering::SeqCst) >= 1);

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let tool_result = timeline
        .events
        .iter()
        .find(|event| event.event_type == "tool.call.succeeded")
        .expect("browser result timeline evidence");
    assert_eq!(
        tool_result.payload["source_locator"],
        format!("{web_origin}/page")
    );
    assert!(tool_result.payload["artifact_id"].as_str().is_some());

    fs::remove_dir_all(&browser_path).expect("remove live browser bundle before replay");
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.model_attempts, 2);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.requests().len(), 2);
    provider_server.abort();
    web_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "set MEALY_BROWSER_BUNDLE to a reviewed Chrome Headless Shell bundle"]
#[allow(clippy::too_many_lines)]
async fn browser_transaction_dispatch_crash_never_retries_and_replays_after_reconciliation() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let source = std::env::var_os("MEALY_BROWSER_BUNDLE")
        .map(std::path::PathBuf::from)
        .expect("reviewed browser bundle path");
    let (web_origin, web_state, web_server) = spawn_browser_transaction_web_server().await;
    let state = MockProviderState::with_browser_transaction_tool_call(web_origin.clone());
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    let browser_path = add_transactional_browser_config(home.path(), &source, &web_origin);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let mut first_daemon = Daemon::spawn_with_effect_outcome_delay(home.path(), 60_000);
    let first_connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &first_connection, "/v1/admin/status").await;
    assert!(
        status
            .enabled_action_tools
            .iter()
            .any(|tool| tool == "browser.transact"),
        "transaction effect must be separately visible: {status:?}"
    );

    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "browser-transaction-dispatch-crash".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content:
                "Inspect the authorized form, then propose exactly one transaction for approval."
                    .to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let pending: PendingApprovalsResponse =
                authorized_get(&client, &first_connection, "/v1/approvals").await;
            if !pending.approvals.is_empty() {
                break pending;
            }
            let task: TaskResponse =
                authorized_get(&client, &first_connection, &format!("/v1/tasks/{task_id}")).await;
            if Instant::now() >= deadline
                || matches!(
                    task.status,
                    TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled
                )
            {
                let timeline: TimelinePageResponse = authorized_get(
                    &client,
                    &first_connection,
                    &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
                )
                .await;
                let failures = timeline
                    .events
                    .iter()
                    .filter(|event| event.event_type.ends_with(".failed"))
                    .map(|event| (&event.event_type, &event.payload))
                    .collect::<Vec<_>>();
                panic!(
                    "browser approval was not requested; task={task:?}; failures={failures:?}; provider_request_count={}",
                    state.requests().len()
                );
            }
            sleep(Duration::from_millis(20)).await;
        }
    };
    let approval = pending.approvals.first().expect("browser approval");
    assert_eq!(approval.subject.tool_id, "browser.transact");
    assert!(
        approval
            .subject
            .target_resources
            .iter()
            .any(|target| target == &format!("browser-transaction:{web_origin}"))
    );
    let effect_id = approval.effect_id.clone();
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-browser-transaction-dispatch-crash".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let dispatch_deadline = Instant::now() + Duration::from_secs(45);
    let attempt_id = loop {
        let timeline: TimelinePageResponse = authorized_get(
            &client,
            &first_connection,
            &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
        )
        .await;
        if web_state.posts.load(Ordering::SeqCst) == 1
            && let Some(event) = timeline
                .events
                .iter()
                .find(|event| event.event_type == "effect.dispatched")
        {
            break event.payload["attempt_id"]
                .as_str()
                .expect("browser dispatch attempt")
                .to_owned();
        }
        assert!(
            Instant::now() < dispatch_deadline,
            "browser transaction never crossed the durable dispatch boundary"
        );
        sleep(Duration::from_millis(10)).await;
    };
    first_daemon.kill_and_wait();

    let _recovered_daemon = Daemon::spawn(home.path(), false);
    let recovered_connection =
        wait_until_ready_with_timeout(&client, home.path(), Duration::from_secs(45)).await;
    let unknown = wait_until_effect_status(
        &client,
        &recovered_connection,
        &effect_id,
        EffectStatusResponse::OutcomeUnknown,
    )
    .await;
    let parked: TaskResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/tasks/{task_id}"),
    )
    .await;
    assert_eq!(parked.status, TaskStatus::Waiting);
    assert_eq!(web_state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(web_state.bodies.lock().expect("POST bodies").len(), 1);
    {
        let bodies = web_state.bodies.lock().expect("POST bodies");
        let body = &bodies[0];
        for expected in [
            b"csrf=private-fixture-csrf".as_slice(),
            b"message=exact+durable+browser+transaction".as_slice(),
            b"action=send".as_slice(),
        ] {
            assert!(
                body.windows(expected.len())
                    .any(|window| window == expected),
                "encoded transaction body omitted an approved component: {body:?}"
            );
        }
    }

    let receipt: EffectReconciliationReceipt = authorized_post(
        &client,
        &recovered_connection,
        &format!("/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile"),
        &ReconcileEffectRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "reconcile-browser-transaction-dispatch-crash".to_owned(),
            expected_effect_revision: unknown.revision,
            outcome: ReconciliationOutcomeCommand::Failed,
            evidence: json!({
                "basis": "owner verified the fixture transaction was intentionally treated as failed",
                "observedPostCount": 1,
            }),
        },
    )
    .await;
    assert_eq!(receipt.outcome, ReconciliationOutcomeCommand::Failed);
    let task = wait_until_terminal_with_timeout(
        &client,
        &recovered_connection,
        &task_id,
        Duration::from_secs(45),
    )
    .await;
    assert_eq!(task.status, TaskStatus::Succeeded, "browser task: {task:?}");
    assert_eq!(web_state.posts.load(Ordering::SeqCst), 1);
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1,
        "never-retry browser transaction must not redispatch after recovery"
    );
    fs::remove_dir_all(&browser_path).expect("remove live browser bundle before replay");
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &recovered_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(replay.evidence_complete, "browser crash replay: {replay:?}");
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(web_state.posts.load(Ordering::SeqCst), 1);
    provider_server.abort();
    web_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn explicit_action_creates_one_approved_file_and_replays_without_redispatch() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_workspace_create_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let workspace = TempDir::new().expect("granted writable workspace");
    fs::create_dir(workspace.path().join("generated")).expect("create target parent");
    write_provider_config(home.path(), &base_url);
    add_writable_workspace_config(home.path(), "project", workspace.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(
        status.enabled_action_tools,
        [
            "workspace.create_file",
            "workspace.manage_path",
            "workspace.replace_file"
        ]
    );
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-workspace-create".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "/act Create a new approved report in the project workspace.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("action must request exact owner approval");
    assert_eq!(approval.subject.tool_id, "workspace.create_file");
    assert_eq!(
        approval.subject.target_resources,
        ["workspace://project/generated/approved.txt"]
    );
    assert_eq!(approval.subject.capability_scope, "write:workspace:create");
    assert!(
        !approval
            .subject
            .target_resources
            .iter()
            .any(|target| target.contains(&workspace.path().display().to_string()))
    );
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-real-provider-workspace-create".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "action task: {task:?}; provider requests: {:?}",
        state.requests()
    );
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.tool_calls, 1);
    assert_eq!(
        fs::read_to_string(workspace.path().join("generated/approved.txt")).expect("approved file"),
        "approved production action"
    );
    let validation = task.validation.expect("fresh action validation");
    assert_eq!(
        validation.method,
        ValidationMethodResponse::FreshContextModel
    );
    assert_eq!(validation.outcome, ValidationOutcomeResponse::Passed);
    assert_eq!(validation.evidence["findings"]["approvalBinding"], true);
    assert_eq!(validation.evidence["findings"]["atMostOneDispatch"], true);

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(7));
    assert!(
        requests[0]
            .body
            .to_string()
            .contains("workspace.create_file")
    );
    assert!(requests[1].body.to_string().contains("effectRevision"));
    assert!(requests.iter().all(|request| {
        !request
            .body
            .to_string()
            .contains(&workspace.path().display().to_string())
    }));

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1
    );
    assert!(!timeline.events.iter().any(|event| {
        event
            .payload
            .to_string()
            .contains(&workspace.path().display().to_string())
    }));
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.requests().len(), 2);
    assert_eq!(
        fs::read_to_string(workspace.path().join("generated/approved.txt"))
            .expect("replay preserves file"),
        "approved production action"
    );
    provider_server.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn explicit_edit_applies_one_digest_pinned_patch_and_replays_without_redispatch() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_workspace_replace_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let workspace = TempDir::new().expect("granted writable workspace");
    let target = workspace.path().join("existing.txt");
    fs::write(&target, "original production content").expect("seed existing file");
    write_provider_config(home.path(), &base_url);
    add_writable_workspace_config(home.path(), "project", workspace.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-workspace-replace".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "/edit Replace the existing project file using fresh digest evidence."
                .to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("replacement must request exact owner approval");
    assert_eq!(approval.subject.tool_id, "workspace.replace_file");
    assert_eq!(
        approval.subject.target_resources,
        ["workspace://project/existing.txt"]
    );
    assert_eq!(approval.subject.capability_scope, "write:workspace:replace");
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-real-provider-workspace-replace".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "replacement task: {task:?}; provider requests: {:?}",
        state.requests()
    );
    assert_eq!((task.model_attempts, task.tool_calls), (2, 1));
    assert_eq!(
        fs::read_to_string(&target).expect("replaced file"),
        "original patched production-ready content"
    );
    let validation = task.validation.expect("fresh replacement validation");
    assert_eq!(validation.outcome, ValidationOutcomeResponse::Passed);
    assert_eq!(validation.evidence["findings"]["approvalBinding"], true);
    assert_eq!(validation.evidence["findings"]["atMostOneDispatch"], true);

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(7));
    assert!(
        requests[0]
            .body
            .to_string()
            .contains("workspace.replace_file")
    );
    assert!(
        !requests[0]
            .body
            .to_string()
            .contains("workspace.create_file")
    );
    assert!(
        requests[1]
            .body
            .to_string()
            .contains(&sha256_digest(b"original production content"))
    );
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1
    );
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete, "replacement replay: {replay:?}");
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.requests().len(), 2);
    assert_eq!(
        fs::read_to_string(&target).expect("replay preserves replacement"),
        "original patched production-ready content"
    );
    provider_server.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn explicit_manage_moves_one_digest_matched_file_and_replays_without_redispatch() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let state = MockProviderState::with_workspace_manage_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let workspace = TempDir::new().expect("granted writable workspace");
    fs::create_dir(workspace.path().join("drafts")).expect("draft parent");
    fs::create_dir(workspace.path().join("archive")).expect("archive parent");
    let source = workspace.path().join("drafts/report.txt");
    let destination = workspace.path().join("archive/report.txt");
    fs::write(&source, "approved lifecycle report").expect("seed lifecycle source");
    write_provider_config(home.path(), &base_url);
    add_writable_workspace_config(home.path(), "project", workspace.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-workspace-manage".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "/manage Move the approved report from drafts into archive.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("path lifecycle operation must request exact owner approval");
    assert_eq!(approval.subject.tool_id, "workspace.manage_path");
    assert_eq!(
        approval.subject.target_resources,
        [
            "workspace://project/archive/report.txt",
            "workspace://project/drafts/report.txt"
        ]
    );
    assert_eq!(approval.subject.capability_scope, "write:workspace:manage");
    assert!(
        approval
            .subject
            .target_resources
            .iter()
            .all(|target| { !target.contains(&workspace.path().display().to_string()) })
    );
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-real-provider-workspace-manage".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "manage task: {task:?}; provider requests: {:?}",
        state.requests()
    );
    assert_eq!((task.model_attempts, task.tool_calls), (2, 1));
    assert!(!source.exists());
    assert_eq!(
        fs::read_to_string(&destination).expect("moved lifecycle file"),
        "approved lifecycle report"
    );
    let validation = task.validation.expect("fresh manage validation");
    assert_eq!(
        validation.method,
        ValidationMethodResponse::FreshContextModel
    );
    assert_eq!(validation.outcome, ValidationOutcomeResponse::Passed);
    assert_eq!(validation.evidence["findings"]["approvalBinding"], true);
    assert_eq!(validation.evidence["findings"]["atMostOneDispatch"], true);

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(7));
    assert!(
        requests[0]
            .body
            .to_string()
            .contains("workspace.manage_path")
    );
    assert!(
        !requests[0]
            .body
            .to_string()
            .contains("workspace.create_file")
    );
    assert!(
        !requests[0]
            .body
            .to_string()
            .contains("workspace.replace_file")
    );
    assert!(requests.iter().all(|request| {
        !request
            .body
            .to_string()
            .contains(&workspace.path().display().to_string())
    }));

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1
    );
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete, "manage replay: {replay:?}");
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.requests().len(), 2);
    assert!(!source.exists());
    assert_eq!(
        fs::read_to_string(&destination).expect("replay preserves moved file"),
        "approved lifecycle report"
    );

    let follow_up: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "ordinary-turn-after-workspace-manage".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Summarize the prior result without performing another action.".to_owned(),
        },
    )
    .await;
    let follow_up_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        follow_up.cursor.0,
    )
    .await;
    let follow_up_task = wait_until_terminal(&client, &connection, &follow_up_task_id).await;
    assert_eq!(
        follow_up_task.status,
        TaskStatus::Succeeded,
        "ordinary follow-up after manage: {follow_up_task:?}"
    );
    assert_eq!(
        (follow_up_task.model_attempts, follow_up_task.tool_calls),
        (1, 0)
    );
    let requests_after_follow_up = state.requests();
    assert_eq!(requests_after_follow_up.len(), 3);
    assert!(
        !requests_after_follow_up[2].body["tools"]
            .to_string()
            .contains("workspace.manage_path")
    );
    provider_server.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn explicit_process_runs_one_pinned_command_and_replays_without_redispatch() {
    if !Path::new("/usr/bin/bwrap").is_file() || !Path::new("/usr/bin/mkdir").is_file() {
        return;
    }
    let state = MockProviderState::with_process_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let workspace = TempDir::new().expect("granted writable workspace");
    write_provider_config(home.path(), &base_url);
    add_writable_workspace_config(home.path(), "project", workspace.path());
    let (command_path, command_digest) =
        add_process_command_config(home.path(), "mkdir", Path::new("/usr/bin/mkdir"));
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(
        status.enabled_action_tools,
        [
            "process.run",
            "workspace.create_file",
            "workspace.manage_path",
            "workspace.replace_file"
        ]
    );

    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-process-run".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "/run Create the requested directory with the configured command.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("process must request exact owner approval");
    assert_eq!(approval.subject.tool_id, "process.run");
    assert_eq!(
        approval.subject.capability_scope,
        "execute:allowlisted-process"
    );
    assert_eq!(
        approval.subject.target_resources,
        [
            format!("command://mkdir@sha256:{command_digest}"),
            "workspace://project/".to_owned(),
        ]
    );
    assert!(approval.subject.target_resources.iter().all(|target| {
        !target.contains(&workspace.path().display().to_string())
            && !target.contains(&command_path.display().to_string())
    }));
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "approve-real-provider-process-run".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(
        task.status,
        TaskStatus::Succeeded,
        "process task: {task:?}; provider requests: {:?}",
        state.requests()
    );
    assert_eq!((task.model_attempts, task.tool_calls), (2, 1));
    assert!(workspace.path().join("generated-by-process").is_dir());
    let validation = task.validation.expect("fresh process validation");
    assert_eq!(
        validation.method,
        ValidationMethodResponse::FreshContextModel
    );
    assert_eq!(validation.outcome, ValidationOutcomeResponse::Passed);
    assert_eq!(validation.evidence["findings"]["approvalBinding"], true);
    assert_eq!(validation.evidence["findings"]["atMostOneDispatch"], true);

    let requests = state.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(7));
    assert!(requests[0].body.to_string().contains("process.run"));
    assert!(
        !requests[0]
            .body
            .to_string()
            .contains("workspace.create_file")
    );
    assert!(requests.iter().all(|request| {
        !request
            .body
            .to_string()
            .contains(&workspace.path().display().to_string())
            && !request
                .body
                .to_string()
                .contains(&command_path.display().to_string())
    }));

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1
    );
    assert!(timeline.events.iter().all(|event| {
        !event
            .payload
            .to_string()
            .contains(&workspace.path().display().to_string())
            && !event
                .payload
                .to_string()
                .contains(&command_path.display().to_string())
    }));
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete, "replay: {replay:?}");
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(state.requests().len(), 2);
    assert!(workspace.path().join("generated-by-process").is_dir());
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn workspace_revocation_rotates_context_and_removes_tool_authority_after_restart() {
    let state = MockProviderState::with_workspace_tool_call();
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let workspace = TempDir::new().expect("granted workspace");
    fs::write(
        workspace.path().join("notes.txt"),
        "production workspace evidence needle\n",
    )
    .expect("workspace note");
    write_provider_config(home.path(), &base_url);
    add_workspace_config(home.path(), "project", workspace.path());
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();

    let (session_id, first_task_id) = {
        let _daemon = Daemon::spawn(home.path(), false);
        let connection = wait_until_ready(&client, home.path()).await;
        let session: CreateSessionResponse = authorized_post(
            &client,
            &connection,
            "/v1/sessions",
            &CreateSessionRequest {
                api_version: API_VERSION.to_owned(),
                provider_selection: None,
            },
        )
        .await;
        let admission: InputAdmissionResponse = authorized_post(
            &client,
            &connection,
            &format!("/v1/sessions/{}/inputs", session.session_id),
            &SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                provider_selection: None,
                idempotency_key: "workspace-before-revocation".to_owned(),
                delivery_mode: DeliveryMode::Queue,
                content: "Read the granted note and cite it.".to_owned(),
            },
        )
        .await;
        let task_id = wait_for_task_id(
            &client,
            &connection,
            &session.session_id,
            admission.cursor.0,
        )
        .await;
        let task = wait_until_terminal(&client, &connection, &task_id).await;
        assert_eq!(task.status, TaskStatus::Succeeded);
        assert_eq!(task.tool_calls, 1);
        let timeline: TimelinePageResponse = authorized_get(
            &client,
            &connection,
            &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
        )
        .await;
        let first_source = timeline.events.first().expect("first compaction source");
        let cited_source = timeline.events.last().expect("last compaction source");
        let _: CompactionResponse = authorized_post(
            &client,
            &connection,
            &format!("/v1/sessions/{}/compactions", session.session_id),
            &CreateCompactionRequest {
                api_version: API_VERSION.to_owned(),
                source_first_cursor: first_source.cursor.0,
                source_last_cursor: cited_source.cursor.0,
                summary_text: "revoked-compaction-canary workspace://project/notes.txt".to_owned(),
                carry_forward: json!({
                    "currentGoals": [{
                        "itemKey": "goal:revocation-test",
                        "text": "Never restore revoked context implicitly",
                        "citations": [{
                            "eventId": cited_source.event_id,
                            "cursor": cited_source.cursor.0,
                            "eventDigest": cited_source.event_digest,
                        }],
                    }],
                    "safetyConstraints": [{
                        "itemKey": "constraint:revocation-test",
                        "text": "Context epoch revocation must fail closed",
                        "citations": [{
                            "eventId": cited_source.event_id,
                            "cursor": cited_source.cursor.0,
                            "eventDigest": cited_source.event_digest,
                        }],
                    }],
                }),
            },
        )
        .await;
        (session.session_id, task_id)
    };

    remove_workspace_config(home.path());

    {
        let _daemon = Daemon::spawn(home.path(), false);
        let connection = wait_until_ready(&client, home.path()).await;
        let admission: InputAdmissionResponse = authorized_post(
            &client,
            &connection,
            &format!("/v1/sessions/{session_id}/inputs"),
            &SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                provider_selection: None,
                idempotency_key: "workspace-after-revocation".to_owned(),
                delivery_mode: DeliveryMode::Queue,
                content: "Can you still read the previously granted note?".to_owned(),
            },
        )
        .await;
        let task_id = wait_for_task_id(&client, &connection, &session_id, admission.cursor.0).await;
        let task = wait_until_terminal(&client, &connection, &task_id).await;
        assert_eq!(task.status, TaskStatus::Succeeded, "revoked task: {task:?}");
        assert_eq!(task.tool_calls, 0);
        let replay: TaskReplayResponse =
            authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
        assert!(replay.evidence_complete);
        let followup: InputAdmissionResponse = authorized_post(
            &client,
            &connection,
            &format!("/v1/sessions/{session_id}/inputs"),
            &SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                provider_selection: None,
                idempotency_key: "workspace-after-revocation-followup".to_owned(),
                delivery_mode: DeliveryMode::Queue,
                content: "Confirm the revoked context remains unavailable.".to_owned(),
            },
        )
        .await;
        let followup_task_id =
            wait_for_task_id(&client, &connection, &session_id, followup.cursor.0).await;
        let followup_task = wait_until_terminal(&client, &connection, &followup_task_id).await;
        assert_eq!(followup_task.status, TaskStatus::Succeeded);
        assert_eq!(followup_task.tool_calls, 0);
        let followup_replay: TaskReplayResponse = authorized_get(
            &client,
            &connection,
            &format!("/v1/tasks/{followup_task_id}/replay"),
        )
        .await;
        assert!(followup_replay.evidence_complete);
        let first_replay: TaskReplayResponse = authorized_get(
            &client,
            &connection,
            &format!("/v1/tasks/{first_task_id}/replay"),
        )
        .await;
        assert!(first_replay.evidence_complete);

        let timeline: TimelinePageResponse = authorized_get(
            &client,
            &connection,
            &format!("/v1/sessions/{session_id}/timeline?limit=1000"),
        )
        .await;
        let epochs = timeline
            .events
            .iter()
            .filter(|event| event.event_type == "context.epoch.created")
            .collect::<Vec<_>>();
        assert_eq!(epochs.len(), 2);
        assert_eq!(
            epochs[0].payload["baseline_version"],
            "mealy.general-assistant.configured-read.v5"
        );
        assert_eq!(
            epochs[1].payload["baseline_version"],
            "mealy.general-assistant.configured-read.v5"
        );
    }

    let requests = state.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(6));
    assert_eq!(requests[1].body["tools"].as_array().map(Vec::len), Some(6));
    assert_eq!(requests[2].body["tools"].as_array().map(Vec::len), Some(2));
    assert_eq!(requests[3].body["tools"].as_array().map(Vec::len), Some(2));
    for request in &requests[2..] {
        assert!(!request.body.to_string().contains("workspace://project"));
        assert!(
            !request
                .body
                .to_string()
                .contains("revoked-compaction-canary")
        );
    }
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn configured_web_search_and_fetch_are_bounded_cited_secret_safe_and_replayable() {
    let (web_origin, web_requests, web_server) = spawn_web_server().await;
    let state = MockProviderState::with_web_tool_calls(web_origin.clone());
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    add_web_config(home.path(), &web_origin);
    let secrets = FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker");
    secrets
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    secrets
        .put("process-web", "process-web-secret")
        .expect("broker web secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(
        status.enabled_read_tools,
        [
            "agent.delegate",
            "agent.delegate_parallel",
            "web.fetch",
            "web.search"
        ]
    );
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-web-read".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Search for current production evidence, fetch it, and cite the source."
                .to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(task.status, TaskStatus::Succeeded, "web task: {task:?}");
    assert_eq!(task.model_attempts, 3);
    assert_eq!(task.tool_calls, 2);
    assert!(
        task.final_response
            .as_deref()
            .is_some_and(|response| response.contains(&format!("{web_origin}/page")))
    );
    assert_eq!(web_requests.load(Ordering::SeqCst), 2);

    let requests = state.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].body["tools"].as_array().map(Vec::len), Some(4));
    assert!(requests[0].body.to_string().contains("web.search"));
    assert!(requests[0].body.to_string().contains("web.fetch"));
    assert!(
        requests[1]
            .body
            .to_string()
            .contains(&format!("{web_origin}/page"))
    );
    assert!(
        requests[2]
            .body
            .to_string()
            .contains("web production evidence needle")
    );
    assert!(requests.iter().all(|request| {
        !request.body.to_string().contains("process-web-secret")
            && request.authorization.as_deref() == Some("Bearer process-proof-secret")
    }));

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let locators = timeline
        .events
        .iter()
        .filter(|event| event.event_type == "tool.call.succeeded")
        .filter_map(|event| event.payload["source_locator"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(locators.len(), 2);
    assert!(locators[0].starts_with("search://brave/"));
    assert_eq!(locators[1], format!("{web_origin}/page"));
    assert!(
        !timeline
            .events
            .iter()
            .any(|event| event.payload.to_string().contains("process-web-secret"))
    );
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
    assert_eq!(state.requests().len(), 3);
    assert_eq!(web_requests.load(Ordering::SeqCst), 2);
    provider_server.abort();
    web_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn transient_provider_failure_is_durably_retried_and_replay_verified() {
    let state = MockProviderState::with_transient_failures(1);
    let (base_url, provider_server) = spawn_provider(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), &base_url);
    FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker")
        .put("process-proof", "process-proof-secret")
        .expect("broker provider secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;

    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-durable-retry".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Recover from one transient provider failure.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;

    assert_eq!(task.status, TaskStatus::Succeeded);
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.usage.used_model_calls, 2);
    assert_eq!(task.usage.used_retries, 1);
    assert_eq!(task.usage.used_input_tokens, 18);
    assert_eq!(task.usage.used_output_tokens, 7);
    assert_eq!(task.usage.used_cost_microunits, 25);
    assert_eq!(state.requests().len(), 2);

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let failed = timeline
        .events
        .iter()
        .find(|event| event.event_type == "model.attempt.failed")
        .expect("provider failure must be visible in the durable timeline");
    assert_eq!(failed.payload["error_class"], "rate_limited");
    assert_eq!(failed.payload["retryable"], true);
    assert_eq!(failed.payload["retry_scheduled"], true);
    assert!(failed.payload["retry_at_ms"].as_i64().is_some());
    let requeued = timeline
        .events
        .iter()
        .find(|event| event.event_type == "run.requeued" && event.payload["reason"] == "retry")
        .expect("provider retry must requeue the run durably");
    assert!(failed.cursor.0 < requeued.cursor.0);
    assert_eq!(
        requeued.payload["next_attempt_at_ms"],
        failed.payload["retry_at_ms"]
    );

    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.model_attempts, 2);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
    sleep(Duration::from_millis(50)).await;
    assert_eq!(state.requests().len(), 2);
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(status.provider_health, "healthy");
    provider_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn retry_routes_across_explicit_same_boundary_provider_protocols_with_exact_evidence() {
    let primary_state = MockProviderState::with_transient_failures(1);
    let fallback_state = MockProviderState::with_workspace_tool_call();
    let (primary_url, primary_server) = spawn_provider(primary_state.clone()).await;
    let (fallback_url, fallback_server) = spawn_anthropic_provider(fallback_state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let workspace = TempDir::new().expect("granted workspace");
    fs::write(
        workspace.path().join("notes.txt"),
        "production workspace evidence needle\n",
    )
    .expect("workspace note");
    write_mixed_provider_chain_config(home.path(), &primary_url, &fallback_url);
    add_workspace_config(home.path(), "project", workspace.path());
    let secrets = FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker");
    secrets
        .put("process-proof", "primary-process-secret")
        .expect("primary secret");
    secrets
        .put("process-fallback", "fallback-process-secret")
        .expect("fallback secret");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;

    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "real-provider-explicit-fallback".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Use the declared fallback to read the granted project notes.".to_owned(),
        },
    )
    .await;
    let task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let task = wait_until_terminal(&client, &connection, &task_id).await;
    assert_eq!(task.status, TaskStatus::Succeeded);
    assert_eq!(task.model_attempts, 3);
    assert_eq!(task.tool_calls, 1);
    assert_eq!(task.usage.used_retries, 1);
    assert!(
        task.final_response
            .as_deref()
            .is_some_and(|response| response.contains("workspace://project/notes.txt"))
    );
    assert_eq!(primary_state.requests().len(), 1);
    assert_eq!(fallback_state.requests().len(), 2);
    assert_eq!(
        primary_state.requests()[0].authorization.as_deref(),
        Some("Bearer primary-process-secret")
    );
    assert_eq!(
        fallback_state
            .requests()
            .iter()
            .map(|request| request.authorization.as_deref())
            .collect::<Vec<_>>(),
        [
            Some("fallback-process-secret"),
            Some("fallback-process-secret")
        ]
    );
    assert_eq!(
        fallback_state.requests()[0].body["model"],
        "process-fallback-model"
    );
    assert_eq!(fallback_state.requests()[0].body["stream"], true);
    assert_eq!(
        fallback_state.requests()[0].body["messages"][0]["role"],
        "user"
    );
    assert!(fallback_state.requests()[0].body.get("input").is_none());
    assert!(fallback_state.requests()[0].body.get("store").is_none());
    assert!(
        fallback_state.requests()[1]
            .body
            .to_string()
            .contains("production workspace evidence needle")
    );

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    let prepared_providers = timeline
        .events
        .iter()
        .filter(|event| event.event_type == "model.attempt.prepared")
        .map(|event| event.payload["provider_id"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(
        prepared_providers,
        [
            "process-proof.responses",
            "process-fallback.anthropic",
            "process-fallback.anthropic"
        ]
    );
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.model_attempts, 3);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
    assert_eq!(primary_state.requests().len(), 1);
    assert_eq!(fallback_state.requests().len(), 2);
    let status: AdminStatusResponse =
        authorized_get(&client, &connection, "/v1/admin/status").await;
    assert_eq!(status.provider_health, "degraded");
    assert_eq!(status.provider_endpoints.len(), 2);
    assert_eq!(status.provider_endpoints[0].protocol, "openai_responses");
    assert_eq!(status.provider_endpoints[0].health, "rate_limited");
    assert_eq!(status.provider_endpoints[0].invocation_count, 1);
    assert!(status.provider_endpoints[0].last_failure_at_ms.is_some());
    assert_eq!(status.provider_endpoints[1].health, "healthy");
    assert_eq!(status.provider_endpoints[1].protocol, "anthropic_messages");
    assert_eq!(status.provider_endpoints[1].invocation_count, 2);
    assert!(status.provider_endpoints[1].last_success_at_ms.is_some());
    primary_server.abort();
    fallback_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn provider_catalog_and_scoped_selection_are_exact_durable_and_restart_safe() {
    let primary_state = MockProviderState::with_transient_failures(1);
    let fallback_state = MockProviderState::default();
    let (primary_url, primary_server) = spawn_provider(primary_state.clone()).await;
    let (fallback_url, fallback_server) = spawn_anthropic_provider(fallback_state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    write_mixed_provider_chain_config(home.path(), &primary_url, &fallback_url);
    let secrets = FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker");
    secrets
        .put("process-proof", "primary-process-secret")
        .expect("primary secret");
    secrets
        .put("process-fallback", "fallback-process-secret")
        .expect("fallback secret");
    let client = http_client();
    let daemon = Daemon::spawn(home.path(), false);
    let connection = wait_until_ready(&client, home.path()).await;

    let catalog: ProviderCatalogResponse =
        authorized_get(&client, &connection, "/v1/providers/catalog").await;
    assert_eq!(catalog.api_version, API_VERSION);
    assert_eq!(catalog.catalog_scope, "configured_route");
    assert!(catalog.automatic_fallback_enabled);
    assert_eq!(catalog.routes.len(), 2);
    assert_eq!(catalog.routes[0].route_ordinal, 0);
    assert_eq!(catalog.routes[0].route_role, "primary");
    assert_eq!(catalog.routes[0].protocol, "openai_responses");
    assert_eq!(catalog.routes[0].provider_id, "process-proof.responses");
    assert_eq!(catalog.routes[0].model_id, "process-proof-model");
    assert_eq!(catalog.routes[1].route_ordinal, 1);
    assert_eq!(catalog.routes[1].route_role, "fallback");
    assert_eq!(catalog.routes[1].protocol, "anthropic_messages");
    assert_eq!(catalog.routes[1].provider_id, "process-fallback.anthropic");
    assert_eq!(catalog.routes[1].model_id, "process-fallback-model");
    assert!(catalog.routes.iter().all(|route| route.selectable));
    assert!(
        catalog
            .routes
            .iter()
            .all(|route| !route.pricing_verified && !route.limits_operator_verified)
    );
    assert!(
        catalog
            .routes
            .iter()
            .all(|route| route.pricing_source == "active_configuration")
    );

    let fallback_selection = ProviderSelectionCommand::Exact {
        provider_id: "process-fallback.anthropic".to_owned(),
        model_id: "process-fallback-model".to_owned(),
    };
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: Some(fallback_selection.clone()),
        },
    )
    .await;
    let initial: SessionProviderSelectionResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/provider-selection", session.session_id),
    )
    .await;
    assert_eq!(initial.provider_selection, fallback_selection);
    assert_eq!(initial.revision, 0);
    assert_eq!(initial.applies_to, "future_new_turns");

    let fallback_admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: None,
            idempotency_key: "selected-fallback-turn".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Complete through the exact selected fallback model.".to_owned(),
        },
    )
    .await;
    assert_eq!(
        fallback_admission.provider_selection,
        ProviderSelectionCommand::Exact {
            provider_id: "process-fallback.anthropic".to_owned(),
            model_id: "process-fallback-model".to_owned(),
        }
    );
    assert_eq!(fallback_admission.provider_selection_source, "inherited");
    let fallback_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        fallback_admission.cursor.0,
    )
    .await;
    let fallback_task = wait_until_terminal(&client, &connection, &fallback_task_id).await;
    assert_eq!(fallback_task.status, TaskStatus::Succeeded);
    assert_eq!(primary_state.requests().len(), 0);
    assert_eq!(fallback_state.requests().len(), 1);

    let status: SessionStatusResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/status", session.session_id),
    )
    .await;
    let automatic: SessionProviderSelectionResponse = authorized_patch(
        &client,
        &connection,
        &format!("/v1/sessions/{}/provider-selection", session.session_id),
        &UpdateSessionProviderSelectionRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: status.revision,
            provider_selection: ProviderSelectionCommand::Automatic,
        },
    )
    .await;
    assert_eq!(
        automatic.provider_selection,
        ProviderSelectionCommand::Automatic
    );
    assert_eq!(automatic.revision, status.revision + 1);
    assert!(automatic.event_id.is_some());

    let primary_selection = ProviderSelectionCommand::Exact {
        provider_id: "process-proof.responses".to_owned(),
        model_id: "process-proof-model".to_owned(),
    };
    let primary_admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            provider_selection: Some(primary_selection.clone()),
            idempotency_key: "selected-primary-turn".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "Complete through the exact per-turn primary model.".to_owned(),
        },
    )
    .await;
    assert_eq!(primary_admission.provider_selection, primary_selection);
    assert_eq!(primary_admission.provider_selection_source, "exact");
    let primary_task_id = wait_for_task_id(
        &client,
        &connection,
        &session.session_id,
        primary_admission.cursor.0,
    )
    .await;
    let primary_task = wait_until_terminal(&client, &connection, &primary_task_id).await;
    assert_eq!(primary_task.status, TaskStatus::Succeeded);
    assert_eq!(primary_task.usage.used_retries, 1);
    assert_eq!(primary_state.requests().len(), 2);
    assert_eq!(fallback_state.requests().len(), 1);

    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert!(timeline.events.iter().any(|event| {
        event.event_type == "session.provider_selection_updated"
            && event.payload["mode"] == "automatic"
            && event.payload["applies_to"] == "future_new_turns"
    }));
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "model.attempt.prepared")
            .map(|event| event.payload["provider_id"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        [
            "process-fallback.anthropic",
            "process-proof.responses",
            "process-proof.responses"
        ]
    );

    drop(daemon);
    let _restarted = Daemon::spawn(home.path(), false);
    let restarted_connection = wait_until_ready(&client, home.path()).await;
    let persisted: SessionProviderSelectionResponse = authorized_get(
        &client,
        &restarted_connection,
        &format!("/v1/sessions/{}/provider-selection", session.session_id),
    )
    .await;
    assert_eq!(
        persisted.provider_selection,
        ProviderSelectionCommand::Automatic
    );
    let restarted_catalog: ProviderCatalogResponse =
        authorized_get(&client, &restarted_connection, "/v1/providers/catalog").await;
    assert_eq!(restarted_catalog.routes.len(), 2);
    let restarted_status: AdminStatusResponse =
        authorized_get(&client, &restarted_connection, "/v1/admin/status").await;
    assert_eq!(restarted_status.provider_endpoints[0].invocation_count, 2);
    assert_eq!(restarted_status.provider_endpoints[1].invocation_count, 1);
    assert_eq!(primary_state.requests().len(), 2);
    assert_eq!(fallback_state.requests().len(), 1);

    primary_server.abort();
    fallback_server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn safe_mode_starts_without_resolving_the_external_provider_credential() {
    let home = TempDir::new().expect("temporary daemon home");
    write_provider_config(home.path(), "http://127.0.0.1:9/v1");
    let client = http_client();
    let _daemon = Daemon::spawn(home.path(), true);
    let _connection = wait_until_ready(&client, home.path()).await;
}

async fn spawn_provider(state: MockProviderState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock provider");
    let address = listener.local_addr().expect("provider address");
    let app = Router::new()
        .route("/v1/responses", post(responses_handler))
        .route("/v1/images/generations", post(image_generation_handler))
        .with_state(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock provider server");
    });
    (format!("http://{address}/v1"), server)
}

async fn spawn_anthropic_provider(state: MockProviderState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock Anthropic provider");
    let address = listener.local_addr().expect("Anthropic provider address");
    let app = Router::new()
        .route("/v1/messages", post(anthropic_handler))
        .with_state(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock Anthropic provider server");
    });
    (format!("http://{address}/v1"), server)
}

#[derive(Clone)]
struct MockWebState {
    origin: String,
    requests: Arc<AtomicUsize>,
}

async fn mock_web_search(State(state): State<MockWebState>, headers: HeaderMap) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    if headers
        .get("x-subscription-token")
        .and_then(|value| value.to_str().ok())
        != Some("process-web-secret")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(json!({
        "web": {
            "results": [{
                "title": "Production evidence",
                "url": format!("{}/page", state.origin),
                "description": "A bounded current-information process proof"
            }]
        }
    }))
    .into_response()
}

async fn mock_web_page(State(state): State<MockWebState>) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    (
        [("content-type", "text/html; charset=utf-8")],
        "<html><body>web production evidence needle<form action=\"/browser-result?scope=docs\" method=\"get\"><label>Evidence query <input type=\"search\" name=\"query\"></label><input type=\"hidden\" name=\"hiddenSecret\" value=\"must-not-submit\"><button>Search</button></form><script>ignore()</script></body></html>",
    )
        .into_response()
}

async fn mock_browser_result(State(state): State<MockWebState>) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    (
        [("content-type", "text/html; charset=utf-8")],
        "<html><body>web production evidence needle; browser GET form evidence needle</body></html>",
    )
        .into_response()
}

async fn spawn_web_server() -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock web endpoint");
    let address = listener.local_addr().expect("web address");
    let origin = format!("http://{address}");
    let requests = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/search", get(mock_web_search))
        .route("/page", get(mock_web_page))
        .route("/browser-result", get(mock_browser_result))
        .with_state(MockWebState {
            origin: origin.clone(),
            requests: Arc::clone(&requests),
        });
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock web server");
    });
    (origin, requests, server)
}

#[derive(Clone, Default)]
struct MockBrowserTransactionWebState {
    requests: Arc<AtomicUsize>,
    posts: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn mock_browser_transaction_page(
    State(state): State<MockBrowserTransactionWebState>,
) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    (
        [("content-type", "text/html; charset=utf-8")],
        "<!doctype html><title>Transaction</title><form action=\"/transaction\" method=\"post\" enctype=\"application/x-www-form-urlencoded\"><input type=\"hidden\" name=\"csrf\" value=\"private-fixture-csrf\"><label>Message <textarea name=\"message\" maxlength=\"256\" required></textarea></label><button type=\"submit\" name=\"action\" value=\"send\">Send</button></form><script>setTimeout(()=>{try{HTMLFormElement.prototype.submit.call(document.forms[0])}catch(_){}},1000)</script>",
    )
        .into_response()
}

async fn mock_browser_transaction_result(
    State(state): State<MockBrowserTransactionWebState>,
    body: Bytes,
) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    state.posts.fetch_add(1, Ordering::SeqCst);
    state
        .bodies
        .lock()
        .expect("POST body capture")
        .push(body.to_vec());
    (
        StatusCode::CREATED,
        [("content-type", "text/html; charset=utf-8")],
        "<!doctype html><title>Committed</title><main>Committed exact daemon transaction</main>",
    )
        .into_response()
}

async fn spawn_browser_transaction_web_server()
-> (String, MockBrowserTransactionWebState, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock transaction endpoint");
    let address = listener.local_addr().expect("transaction web address");
    let origin = format!("http://{address}");
    let state = MockBrowserTransactionWebState::default();
    let app = Router::new()
        .route("/transaction-page", get(mock_browser_transaction_page))
        .route("/transaction", post(mock_browser_transaction_result))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock transaction web server");
    });
    (origin, state, server)
}

fn write_provider_config(home: &Path, base_url: &str) {
    fs::create_dir_all(home).expect("create daemon home");
    let config = json!({
        "formatVersion": 1,
        "drainDeadlineMs": 10_000,
        "maximumPendingInputsPerSession": 1_024,
        "agentLoopLimits": {
            "maximumModelCalls": 4,
            "maximumToolCalls": 2,
            "maximumRetries": 1,
            "maximumDelegatedRuns": 2,
            "maximumInputTokens": 32_768,
            "maximumOutputTokens": 4_096,
            "maximumCostMicrounits": 1_000_000,
            "maximumOutputBytes": 4_194_304,
            "maximumWallTimeMs": 120_000,
            "providerTimeoutMs": 5_000,
            "toolTimeoutMs": 5_000,
            "inlineOutputBytes": 1_024,
            "maximumArtifactBytes": 4_194_304
        },
        "concurrencyLimits": {
            "daemonAgentRuns": 1,
            "principalAgentRuns": 1,
            "sessionAgentRuns": 1,
            "providerRequests": 1,
            "providerRequestsPerMinute": 600,
            "extensionInvocations": 1,
            "agentRoleRuns": 1,
            "resourceClassInvocations": 1
        },
        "provider": {
            "kind": "open_ai_responses",
            "providerId": "process-proof.responses",
            "baseUrl": base_url,
            "model": "process-proof-model",
            "credential": {
                "source": "broker",
                "secretId": "process-proof"
            },
            "residency": "local-test",
            "contextTokens": 32_768,
            "maximumOutputTokens": 4_096,
            "inputMicrounitsPerMillionTokens": 1_000_000,
            "outputMicrounitsPerMillionTokens": 1_000_000,
            "estimatedLatencyMs": 10
        },
        "artifactGcMinimumAgeHours": 24,
        "forensicBackupOnOpenFailure": true,
        "retentionPolicy": {
            "dataClassMinimumAgeHours": {
                "canonical_audit": 87_600,
                "temporary_artifact": 24,
                "unreferenced_artifact": 24
            },
            "sensitivityMinimumAgeHours": {
                "internal": 720,
                "private": 8_760,
                "public": 24,
                "restricted": 87_600
            },
            "protectedPrincipalIds": [],
            "protectedTaskIds": [],
            "protectedChannelBindingIds": [],
            "legalHoldLabels": []
        }
    });
    fs::write(
        home.join("config.json"),
        serde_json::to_vec_pretty(&config).expect("encode provider config"),
    )
    .expect("write provider config");
}

fn enable_provider_streaming(home: &Path) {
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["provider"]["streaming"] = Value::Bool(true);
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode streaming provider config"),
    )
    .expect("write streaming provider config");
}

fn enable_provider_image_input(home: &Path) {
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["imageInputEnabled"] = Value::Bool(true);
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode image provider config"),
    )
    .expect("write image provider config");
}

fn enable_image_generation(home: &Path, base_url: &str) {
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["imageGeneration"] = json!({
        "providerId": "process-proof.images",
        "protocol": "open_ai_images",
        "baseUrl": base_url,
        "model": "process-proof-image-model",
        "residency": "local-test",
        "size": "1024x1024",
        "quality": "low",
        "maximumCostMicrounits": 50_000,
        "maximumOutputBytes": 2_097_152,
        "timeoutMs": 5_000
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode image-generation config"),
    )
    .expect("write image-generation config");
}

fn add_skill_config(home: &Path) -> String {
    let source = tempfile::tempdir().expect("skill source");
    fs::create_dir_all(source.path().join("instructions")).expect("instruction directory");
    fs::create_dir_all(source.path().join("resources")).expect("resource directory");
    let instruction = b"When relevant, retain SKILL-CONTEXT-MARKER-731 in the answer.";
    let resource = b"HIDDEN-SKILL-RESOURCE";
    fs::write(
        source.path().join("instructions/continuity.md"),
        instruction,
    )
    .expect("instruction");
    fs::write(source.path().join("resources/private.txt"), resource).expect("resource");
    let manifest = json!({
        "contractVersion": "mealy.skill.v1",
        "skillId": "mealy.fixture.continuity",
        "version": "1.0.0",
        "instructions": [{
            "relativePath": "instructions/continuity.md",
            "mediaType": "text/markdown",
            "contentDigest": sha256_digest(instruction),
            "sizeBytes": instruction.len()
        }],
        "resources": [{
            "relativePath": "resources/private.txt",
            "mediaType": "text/plain",
            "contentDigest": sha256_digest(resource),
            "sizeBytes": resource.len()
        }],
        "requiredTools": [{
            "toolId": "workspace.read",
            "version": "1",
            "inputSchemaDigest": "a".repeat(64)
        }]
    });
    let body = serde_json::to_vec_pretty(&manifest).expect("manifest bytes");
    fs::write(source.path().join("manifest.json"), &body).expect("manifest");
    let digest = sha256_digest(&body);
    let package = inspect_skill_package(
        &source.path().join("manifest.json"),
        source.path(),
        Some(&digest),
    )
    .expect("inspect skill");
    publish_skill_package(&package, &home.join("skills")).expect("publish skill");
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["skills"] = json!([{
        "skillId": "mealy.fixture.continuity",
        "version": "1.0.0",
        "manifestDigest": digest,
        "packagePath": format!("skills/{digest}"),
        "enabled": true
    }]);
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode skill config"),
    )
    .expect("write skill config");
    digest
}

fn write_mixed_provider_chain_config(home: &Path, primary_url: &str, fallback_url: &str) {
    write_provider_config(home, primary_url);
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read primary config"))
        .expect("decode primary config");
    config["providerFallbacks"] = json!([{
        "kind": "anthropic_messages",
        "providerId": "process-fallback.anthropic",
        "baseUrl": fallback_url,
        "model": "process-fallback-model",
        "credential": {
            "source": "broker",
            "secretId": "process-fallback"
        },
        "residency": "local-test",
        "contextTokens": 32_768,
        "maximumOutputTokens": 4_096,
        "streaming": true,
        "inputMicrounitsPerMillionTokens": 1_000_000,
        "outputMicrounitsPerMillionTokens": 1_000_000,
        "estimatedLatencyMs": 10
    }]);
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode fallback config"),
    )
    .expect("write fallback config");
}

fn add_workspace_config(home: &Path, workspace_id: &str, root: &Path) {
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["workspaceRoots"] = json!([{
        "workspaceId": workspace_id,
        "root": root
    }]);
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode workspace config"),
    )
    .expect("write workspace config");
}

fn add_mcp_config(home: &Path) -> std::path::PathBuf {
    add_mcp_config_with_effect(home, McpToolEffect::ReadOnly)
}

fn add_mcp_effect_config(home: &Path) -> std::path::PathBuf {
    add_mcp_config_with_effect(home, McpToolEffect::Idempotent)
}

fn add_mcp_non_idempotent_effect_config(home: &Path) -> std::path::PathBuf {
    add_mcp_config_with_effect(home, McpToolEffect::NonIdempotent)
}

fn add_mcp_config_with_effect(home: &Path, effect: McpToolEffect) -> std::path::PathBuf {
    let fixture = fs::canonicalize(env!("CARGO_BIN_EXE_mealyd-mcp-fixture-server"))
        .expect("canonical MCP fixture");
    let launcher =
        fs::canonicalize(env!("CARGO_BIN_EXE_mealyd")).expect("canonical mealyd launcher");
    let executable_bytes = fs::read(&fixture).expect("MCP fixture bytes");
    let executable_digest = sha256_digest(&executable_bytes);
    let discovery = discover_mcp_stdio_server(
        "/usr/bin/bwrap",
        launcher,
        "fixture",
        &fixture,
        &executable_digest,
        &["good".to_owned()],
    )
    .expect("discover MCP fixture");
    assert_eq!(discovery.protocol_version, MCP_PROTOCOL_VERSION);
    let add = discovery.tool("add").expect("MCP add definition");
    let grant = McpToolGrant::new_with_effect(add.definition.clone(), effect, 5_000, 128 * 1024)
        .expect("MCP add grant");
    let relative = format!("mcp-servers/{executable_digest}/server");
    let installed = home.join(&relative);
    fs::create_dir_all(installed.parent().expect("MCP install parent"))
        .expect("MCP install directory");
    fs::write(&installed, &executable_bytes).expect("install MCP fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o700))
            .expect("MCP fixture permissions");
    }
    let server = McpServerConfig::new(
        "fixture".to_owned(),
        relative,
        executable_digest,
        vec!["good".to_owned()],
        discovery.toolset_digest().expect("MCP toolset digest"),
        true,
        vec![grant],
    )
    .expect("MCP server config");
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["mcpServers"] = serde_json::to_value([server]).expect("encode MCP config");
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode MCP provider config"),
    )
    .expect("write MCP provider config");
    installed
}

fn add_browser_config(home: &Path, source: &Path, origin: &str) -> std::path::PathBuf {
    let inspection = inspect_browser_bundle(source, None).expect("inspect browser bundle");
    let probe = probe_browser_bundle_product(
        Path::new("/usr/bin/bwrap"),
        source,
        Some(inspection.bundle_digest()),
    )
    .expect("sandboxed browser probe");
    assert_eq!(probe.protocol_version(), BROWSER_CDP_PROTOCOL_VERSION);
    let installed = publish_browser_bundle(&inspection, &home.join("browser-runtimes"))
        .expect("publish browser bundle");
    let browser = BrowserConfig::new(
        true,
        format!("browser-runtimes/{}", inspection.bundle_digest()),
        inspection.bundle_digest().to_owned(),
        "chrome-headless-shell".to_owned(),
        inspection.executable_digest().to_owned(),
        probe.product().to_owned(),
        probe.protocol_version().to_owned(),
    )
    .expect("browser configuration");
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["agentLoopLimits"]["toolTimeoutMs"] = json!(30_000);
    config["webAccess"] = json!({
        "enabled": true,
        "allowPublicInternet": false,
        "allowedOrigins": [origin]
    });
    config["browser"] = serde_json::to_value(browser).expect("encode browser config");
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode browser provider config"),
    )
    .expect("write browser provider config");
    installed
}

fn add_transactional_browser_config(
    home: &Path,
    source: &Path,
    origin: &str,
) -> std::path::PathBuf {
    let installed = add_browser_config(home, source, origin);
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read browser config"))
        .expect("decode browser config");
    config["browser"]["transactionalEnabled"] = Value::Bool(true);
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode transactional browser config"),
    )
    .expect("write transactional browser config");
    installed
}

fn add_writable_workspace_config(home: &Path, workspace_id: &str, root: &Path) {
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["workspaceRoots"] = json!([{
        "workspaceId": workspace_id,
        "root": root,
        "writable": true
    }]);
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode writable workspace config"),
    )
    .expect("write writable workspace config");
}

fn add_process_command_config(
    home: &Path,
    command_id: &str,
    executable: &Path,
) -> (std::path::PathBuf, String) {
    let executable = fs::canonicalize(executable).expect("canonical process executable");
    let digest = sha256_digest(&fs::read(&executable).expect("read process executable"));
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["commandTools"] = json!([{
        "commandId": command_id,
        "executable": executable,
        "executableDigest": digest
    }]);
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode process config"),
    )
    .expect("write process config");
    (executable, digest)
}

fn remove_workspace_config(home: &Path) {
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config
        .as_object_mut()
        .expect("provider config object")
        .remove("workspaceRoots");
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode revoked workspace config"),
    )
    .expect("write revoked workspace config");
}

fn add_web_config(home: &Path, origin: &str) {
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).expect("read provider config"))
        .expect("decode provider config");
    config["webAccess"] = json!({
        "enabled": true,
        "allowPublicInternet": false,
        "allowedOrigins": [origin],
        "search": {
            "kind": "brave",
            "baseUrl": format!("{origin}/search"),
            "credential": {
                "source": "broker",
                "secretId": "process-web"
            }
        }
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&config).expect("encode web config"),
    )
    .expect("write web config");
}

fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client")
}

async fn wait_until_ready(client: &Client, home: &Path) -> LocalConnectionInfo {
    wait_until_ready_with_timeout(client, home, READY_TIMEOUT).await
}

async fn wait_until_ready_with_timeout(
    client: &Client,
    home: &Path,
    timeout: Duration,
) -> LocalConnectionInfo {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(bytes) = fs::read(home.join("connection.json"))
            && let Ok(connection) = serde_json::from_slice::<LocalConnectionInfo>(&bytes)
            && let Ok(response) = client
                .get(format!("{}/health/ready", connection.base_url))
                .bearer_auth(&connection.bearer_token)
                .send()
                .await
            && response.status().is_success()
            && let Ok(readiness) = response.json::<ReadinessResponse>().await
            && readiness.ready
        {
            return connection;
        }
        assert!(Instant::now() < deadline, "mealyd did not become ready");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_task_id(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
) -> String {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let page: TimelinePageResponse = authorized_get(
            client,
            connection,
            &format!("/v1/sessions/{session_id}/timeline?after={after}&limit=100"),
        )
        .await;
        if let Some(task) = page
            .events
            .iter()
            .find(|event| event.event_type == "task.created")
        {
            return task.aggregate_id.clone();
        }
        assert!(Instant::now() < deadline, "input was not promoted");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_terminal(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
) -> TaskResponse {
    wait_until_terminal_with_timeout(client, connection, task_id, COMPLETION_TIMEOUT).await
}

async fn wait_until_terminal_with_timeout(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
    timeout: Duration,
) -> TaskResponse {
    let deadline = Instant::now() + timeout;
    loop {
        let task: TaskResponse =
            authorized_get(client, connection, &format!("/v1/tasks/{task_id}")).await;
        if matches!(
            task.status,
            TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled
        ) {
            return task;
        }
        assert!(
            Instant::now() < deadline,
            "task did not terminate: {task:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_pending_approval(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> PendingApprovalsResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let pending: PendingApprovalsResponse =
            authorized_get(client, connection, "/v1/approvals").await;
        if !pending.approvals.is_empty() {
            return pending;
        }
        assert!(Instant::now() < deadline, "approval was not requested");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_effect_status(
    client: &Client,
    connection: &LocalConnectionInfo,
    effect_id: &str,
    expected: EffectStatusResponse,
) -> EffectResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let effect: EffectResponse =
            authorized_get(client, connection, &format!("/v1/effects/{effect_id}")).await;
        if effect.status == expected {
            return effect;
        }
        assert!(
            Instant::now() < deadline,
            "effect did not reach {expected:?}: {effect:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn authorized_get<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
) -> T {
    let response = client
        .get(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .send()
        .await
        .expect("authorized GET");
    let status = response.status();
    let body = response.bytes().await.expect("authorized GET body");
    assert_eq!(
        status,
        StatusCode::OK,
        "GET {path} failed: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).expect("valid response JSON")
}

async fn authorized_post<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
) -> T {
    let response = client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized POST");
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.expect("valid response JSON")
}

async fn authorized_patch<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
) -> T {
    let response = client
        .patch(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized PATCH");
    let status = response.status();
    let bytes = response.bytes().await.expect("authorized PATCH body");
    assert_eq!(
        status,
        StatusCode::OK,
        "PATCH {path} failed: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).expect("valid response JSON")
}

fn non_broker_state_contains(path: &Path, needle: &[u8]) -> bool {
    fs::read_dir(path).is_ok_and(|entries| {
        entries.filter_map(Result::ok).any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                path.file_name().and_then(|name| name.to_str()) != Some("provider-secrets")
                    && non_broker_state_contains(&path, needle)
            } else {
                fs::read(path)
                    .ok()
                    .is_some_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
            }
        })
    })
}
