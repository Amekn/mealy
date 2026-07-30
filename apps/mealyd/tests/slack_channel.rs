//! Public-process proof for Slack setup, Socket Mode crash recovery, exact-thread remote
//! continuation, proactive automation output, duplicate acknowledgement, exact allowlists,
//! credential revocation, and secret exclusion.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response as AxumResponse},
    routing::{get, post},
};
use futures_util::{SinkExt as _, StreamExt as _};
use mealy_domain::{AutomationId, RemoteContinuationId};
use mealy_protocol::{
    API_VERSION, AutomationActionCommand, AutomationActionResponse, AutomationResponse,
    AutomationTriggerRequest, CreateAutomationRequest, CreateSlackChannelRequest,
    CreateSlackRemoteContinuationRequest, DrainDaemonRequest, DrainDaemonResponse,
    LocalConnectionInfo, ReadinessResponse, RevokeSlackChannelRequest,
    RevokeSlackRemoteContinuationRequest, SlackChannelResponse, SlackChannelStatusResponse,
    SlackRemoteContinuationResponse, SlackRemoteContinuationStatusResponse,
    SlackRemoteContinuationsResponse,
};
use reqwest::Client;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tokio::{
    net::TcpListener,
    sync::Notify,
    task::JoinHandle,
    time::{Instant, sleep},
};
use tokio_tungstenite::{accept_async, tungstenite::Message as WebSocketMessage};

const APP_TOKEN: &str = "xapp-1-process-test-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const BOT_TOKEN: &str = "xoxb-process-test-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const TEAM_ID: &str = "T01234567";
const APP_ID: &str = "A01234567";
const BOT_USER_ID: &str = "U07654321";
const HUMAN_USER_ID: &str = "U01234567";
const CHANNEL_ID: &str = "C01234567";
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path, slack_api_base_url: &str, after_ack_delay_ms: u64) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .arg("--slack-api-base-url")
            .arg(slack_api_base_url)
            .arg("--slack-after-ack-delay-ms")
            .arg(after_ack_delay_ms.to_string())
            .arg("--promotion-delay-ms")
            .arg("0")
            .arg("--promotion-interval-ms")
            .arg("10")
            .arg("--agent-delay-ms")
            .arg("0")
            .arg("--outbox-delay-ms")
            .arg("0")
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("mealyd process should start");
        Self { child }
    }

    fn hard_kill(&mut self) {
        self.child.kill().expect("kill mealyd");
        assert!(!self.child.wait().expect("reap mealyd").success());
    }

    async fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll mealyd") {
                return status;
            }
            assert!(Instant::now() < deadline, "mealyd did not terminate");
            sleep(Duration::from_millis(20)).await;
        }
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

#[derive(Clone)]
struct SlackFixture(Arc<SlackFixtureInner>);

struct SlackFixtureInner {
    socket_url: String,
    envelopes: Mutex<VecDeque<Value>>,
    envelope_notify: Notify,
    acknowledgements: Mutex<Vec<String>>,
    sent_requests: Mutex<Vec<Value>>,
    rate_limits_remaining: AtomicUsize,
}

impl SlackFixture {
    fn new(socket_url: String) -> Self {
        Self(Arc::new(SlackFixtureInner {
            socket_url,
            envelopes: Mutex::new(VecDeque::new()),
            envelope_notify: Notify::new(),
            acknowledgements: Mutex::new(Vec::new()),
            sent_requests: Mutex::new(Vec::new()),
            rate_limits_remaining: AtomicUsize::new(1),
        }))
    }

    fn push_envelope(&self, envelope: Value) {
        self.0
            .envelopes
            .lock()
            .expect("envelope lock")
            .push_back(envelope);
        self.0.envelope_notify.notify_waiters();
    }

    async fn next_envelope(&self) -> Value {
        loop {
            let notified = self.0.envelope_notify.notified();
            if let Some(envelope) = self.0.envelopes.lock().expect("envelope lock").pop_front() {
                return envelope;
            }
            notified.await;
        }
    }

    fn acknowledgements(&self) -> Vec<String> {
        self.0
            .acknowledgements
            .lock()
            .expect("acknowledgement lock")
            .clone()
    }

    fn sent_requests(&self) -> Vec<Value> {
        self.0
            .sent_requests
            .lock()
            .expect("sent request lock")
            .clone()
    }
}

async fn auth_test(State(_state): State<SlackFixture>, headers: HeaderMap) -> AxumResponse {
    assert_bot_authorization(&headers);
    Json(json!({
        "ok": true,
        "team": "Mealy Test",
        "team_id": TEAM_ID,
        "user": "mealy",
        "user_id": BOT_USER_ID,
        "bot_id": "B01234567",
        "app_id": APP_ID
    }))
    .into_response()
}

async fn users_info(
    State(_state): State<SlackFixture>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> AxumResponse {
    assert_bot_authorization(&headers);
    assert_eq!(query.get("user").map(String::as_str), Some(HUMAN_USER_ID));
    Json(json!({
        "ok": true,
        "user": {
            "id": HUMAN_USER_ID,
            "team_id": TEAM_ID,
            "name": "owner",
            "deleted": false,
            "is_bot": false
        }
    }))
    .into_response()
}

async fn conversations_info(
    State(_state): State<SlackFixture>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> AxumResponse {
    assert_bot_authorization(&headers);
    assert_eq!(query.get("channel").map(String::as_str), Some(CHANNEL_ID));
    Json(json!({
        "ok": true,
        "channel": {
            "id": CHANNEL_ID,
            "is_archived": false,
            "is_member": true,
            "is_im": false
        }
    }))
    .into_response()
}

async fn open_connection(State(state): State<SlackFixture>, headers: HeaderMap) -> AxumResponse {
    assert_eq!(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some(format!("Bearer {APP_TOKEN}").as_str())
    );
    Json(json!({"ok": true, "url": state.0.socket_url})).into_response()
}

async fn post_message(
    State(state): State<SlackFixture>,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    assert_bot_authorization(&headers);
    let request: Value = serde_json::from_slice(&body).expect("Slack message request JSON");
    assert_eq!(request["channel"], CHANNEL_ID);
    assert_eq!(request["thread_ts"], "1785254000.000100");
    assert_eq!(request["mrkdwn"], false);
    assert_eq!(request["unfurl_links"], false);
    assert_eq!(request["unfurl_media"], false);
    assert!(
        request["client_msg_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    state
        .0
        .sent_requests
        .lock()
        .expect("sent request lock")
        .push(request);
    if state
        .0
        .rate_limits_remaining
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            Json(json!({"ok": false, "error": "ratelimited"})),
        )
            .into_response();
    }
    Json(json!({
        "ok": true,
        "channel": CHANNEL_ID,
        "ts": "1785254001.000200",
        "message": {"bot_id": "B01234567"}
    }))
    .into_response()
}

fn assert_bot_authorization(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some(format!("Bearer {BOT_TOKEN}").as_str())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn slack_socket_ack_is_crash_safe_threaded_rate_limited_and_revocable() {
    let socket_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Slack socket listener");
    let socket_url = format!(
        "ws://{}/socket",
        socket_listener.local_addr().expect("Slack socket address")
    );
    let state = SlackFixture::new(socket_url);
    let socket_server = spawn_slack_socket(socket_listener, state.clone());
    let (api_url, api_server) = spawn_slack_api(state.clone()).await;
    let home = TempDir::new().expect("temporary daemon home");
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("HTTP client");
    let mut daemon = Daemon::spawn(home.path(), &api_url, 2_000);
    let connection = wait_until_ready(&client, home.path()).await;
    let created: SlackChannelResponse = authorized_post(
        &client,
        &connection,
        "/v1/channels/slack",
        &CreateSlackChannelRequest {
            api_version: API_VERSION.to_owned(),
            app_token: APP_TOKEN.to_owned(),
            bot_token: BOT_TOKEN.to_owned(),
            slack_user_id: HUMAN_USER_ID.to_owned(),
            slack_channel_id: CHANNEL_ID.to_owned(),
            require_mention: true,
        },
    )
    .await;
    assert_eq!(created.status, SlackChannelStatusResponse::Active);
    assert_eq!(created.team_id, TEAM_ID);
    assert_eq!(created.app_id, APP_ID);
    assert_eq!(created.bot_user_id, BOT_USER_ID);
    assert!(!database_contains(home.path(), APP_TOKEN.as_bytes()));
    assert!(!database_contains(home.path(), BOT_TOKEN.as_bytes()));
    let app_secret = home
        .path()
        .join("provider-secrets")
        .join(format!("slack.app.{}.key", created.binding_id));
    let bot_secret = home
        .path()
        .join("provider-secrets")
        .join(format!("slack.bot.{}.key", created.binding_id));
    assert!(app_secret.is_file());
    assert!(bot_secret.is_file());

    let envelope = slack_message_envelope("env-1", "Ev01234567", HUMAN_USER_ID, "run the checks");
    state.push_envelope(envelope.clone());
    wait_for_acknowledgement(&state, "env-1").await;
    sleep(Duration::from_millis(100)).await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 0);
    daemon.hard_kill();
    fs::remove_file(home.path().join("connection.json")).expect("remove stale descriptor");

    let mut restarted_daemon = Daemon::spawn(home.path(), &api_url, 0);
    let restarted = wait_until_ready(&client, home.path()).await;
    wait_for_inbox_count(home.path(), &created.session_id, 1).await;
    wait_for_sent_text(&state, "Mealy accepted your message.").await;
    wait_for_retried_client_id(&state).await;
    let requests = state.sent_requests();
    assert!(
        requests.len() >= 2,
        "rate-limited Slack message was not retried"
    );
    let mut client_ids = BTreeMap::<String, usize>::new();
    for request in &requests {
        *client_ids
            .entry(
                request["client_msg_id"]
                    .as_str()
                    .expect("Slack client message ID")
                    .to_owned(),
            )
            .or_default() += 1;
    }
    assert!(
        client_ids.values().any(|count| *count >= 2),
        "retry must retain Slack duplicate-suppression identity"
    );

    state.push_envelope(envelope);
    wait_for_acknowledgement_count(&state, "env-1", 2).await;
    sleep(Duration::from_millis(250)).await;
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 1);

    state.push_envelope(slack_message_envelope(
        "env-2",
        "Ev07654321",
        "U09999999",
        "spoofed sender",
    ));
    wait_for_acknowledgement(&state, "env-2").await;
    assert_eq!(
        ignored_envelope_reason(home.path(), &created.binding_id, "env-2"),
        "sender_not_allowed"
    );
    assert_eq!(session_inbox_count(home.path(), &created.session_id), 1);

    let now_ms = current_epoch_ms();
    let remote_continuation_id = RemoteContinuationId::new().to_string();
    let continuation: SlackRemoteContinuationResponse = authorized_post(
        &client,
        &restarted,
        &format!(
            "/v1/channels/slack/{}/remote-continuations",
            created.binding_id
        ),
        &CreateSlackRemoteContinuationRequest {
            api_version: API_VERSION.to_owned(),
            remote_continuation_id: remote_continuation_id.clone(),
            thread_id: "1785254000.000100".to_owned(),
            expires_at_ms: now_ms + 60 * 60 * 1_000,
        },
    )
    .await;
    assert_eq!(
        continuation.status,
        SlackRemoteContinuationStatusResponse::Active
    );
    assert_eq!(continuation.thread_id, "1785254000.000100");
    let listed: SlackRemoteContinuationsResponse = authorized_get(
        &client,
        &restarted,
        &format!(
            "/v1/channels/slack/{}/remote-continuations",
            created.binding_id
        ),
    )
    .await;
    assert_eq!(listed.remote_continuations, vec![continuation.clone()]);
    let read: SlackRemoteContinuationResponse = authorized_get(
        &client,
        &restarted,
        &format!(
            "/v1/channels/slack/{}/remote-continuations/{remote_continuation_id}",
            created.binding_id
        ),
    )
    .await;
    assert_eq!(read, continuation);

    let automation: AutomationResponse = authorized_post(
        &client,
        &restarted,
        "/v1/automations",
        &CreateAutomationRequest {
            api_version: API_VERSION.to_owned(),
            automation_id: AutomationId::new().to_string(),
            name: "Exact Slack continuation".to_owned(),
            trigger: AutomationTriggerRequest::OneShot {
                due_at_ms: current_epoch_ms() + 1_000,
            },
            action: AutomationActionCommand::Notify {
                target_session_id: created.session_id.clone(),
                message: "The exact-thread continuation is active.".to_owned(),
                remote_continuation_id: Some(remote_continuation_id.clone()),
            },
        },
    )
    .await;
    assert!(matches!(
        automation.action,
        AutomationActionResponse::Notify {
            remote_continuation_id: Some(ref id),
            ..
        } if id == &remote_continuation_id
    ));
    wait_for_sent_text(
        &state,
        "Mealy automation:\nThe exact-thread continuation is active.",
    )
    .await;

    let revoked_continuation: SlackRemoteContinuationResponse = authorized_post(
        &client,
        &restarted,
        &format!(
            "/v1/channels/slack/{}/remote-continuations/{remote_continuation_id}/revoke",
            created.binding_id
        ),
        &RevokeSlackRemoteContinuationRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: 0,
        },
    )
    .await;
    assert_eq!(
        revoked_continuation.status,
        SlackRemoteContinuationStatusResponse::Revoked
    );
    assert_eq!(revoked_continuation.revision, 1);
    let rejected = authorized_post_response(
        &client,
        &restarted,
        "/v1/automations",
        &CreateAutomationRequest {
            api_version: API_VERSION.to_owned(),
            automation_id: AutomationId::new().to_string(),
            name: "Revoked Slack continuation".to_owned(),
            trigger: AutomationTriggerRequest::OneShot {
                due_at_ms: current_epoch_ms() + 1_000,
            },
            action: AutomationActionCommand::Notify {
                target_session_id: created.session_id.clone(),
                message: "This must not be delivered.".to_owned(),
                remote_continuation_id: Some(remote_continuation_id),
            },
        },
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::NOT_FOUND);

    let revoked: SlackChannelResponse = authorized_post(
        &client,
        &restarted,
        &format!("/v1/channels/slack/{}/revoke", created.binding_id),
        &RevokeSlackChannelRequest {
            api_version: API_VERSION.to_owned(),
            expected_revision: 0,
        },
    )
    .await;
    assert_eq!(revoked.status, SlackChannelStatusResponse::Revoked);
    assert_eq!(revoked.revision, 1);
    assert!(!app_secret.exists());
    assert!(!bot_secret.exists());

    let _: DrainDaemonResponse = authorized_post(
        &client,
        &restarted,
        "/v1/admin/drain",
        &DrainDaemonRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    assert!(restarted_daemon.wait().await.success());
    socket_server.abort();
    api_server.abort();
}

fn spawn_slack_socket(listener: TcpListener, state: SlackFixture) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept Slack socket");
            let connection_state = state.clone();
            tokio::spawn(async move {
                let Ok(mut socket) = accept_async(stream).await else {
                    return;
                };
                if socket
                    .send(WebSocketMessage::Text(
                        json!({
                            "type": "hello",
                            "num_connections": 1,
                            "connection_info": {"app_id": APP_ID}
                        })
                        .to_string()
                        .into(),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
                loop {
                    let envelope = connection_state.next_envelope().await;
                    if socket
                        .send(WebSocketMessage::Text(envelope.to_string().into()))
                        .await
                        .is_err()
                    {
                        connection_state.push_envelope(envelope);
                        return;
                    }
                    let Some(Ok(WebSocketMessage::Text(acknowledgement))) = socket.next().await
                    else {
                        connection_state.push_envelope(envelope);
                        return;
                    };
                    let Ok(acknowledgement) =
                        serde_json::from_slice::<Value>(acknowledgement.as_bytes())
                    else {
                        return;
                    };
                    let Some(envelope_id) = acknowledgement
                        .get("envelope_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                    else {
                        return;
                    };
                    connection_state
                        .0
                        .acknowledgements
                        .lock()
                        .expect("acknowledgement lock")
                        .push(envelope_id);
                }
            });
        }
    })
}

async fn spawn_slack_api(state: SlackFixture) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Slack API listener");
    let address = listener.local_addr().expect("Slack API address");
    let app = Router::new()
        .route("/auth.test", post(auth_test))
        .route("/users.info", get(users_info))
        .route("/conversations.info", get(conversations_info))
        .route("/apps.connections.open", post(open_connection))
        .route("/chat.postMessage", post(post_message))
        .with_state(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Slack API server");
    });
    (format!("http://{address}"), handle)
}

fn slack_message_envelope(envelope_id: &str, event_id: &str, user_id: &str, text: &str) -> Value {
    json!({
        "envelope_id": envelope_id,
        "type": "events_api",
        "accepts_response_payload": false,
        "payload": {
            "token": "verification-token-is-untrusted",
            "team_id": TEAM_ID,
            "api_app_id": APP_ID,
            "type": "event_callback",
            "event_id": event_id,
            "event_time": 1_785_254_000_i64,
            "event": {
                "type": "message",
                "user": user_id,
                "text": format!("<@{BOT_USER_ID}> {text}"),
                "channel": CHANNEL_ID,
                "ts": "1785254000.000100",
                "event_ts": "1785254000.000100",
                "channel_type": "channel"
            }
        }
    })
}

async fn wait_until_ready(client: &Client, home: &Path) -> LocalConnectionInfo {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(bytes) = fs::read(home.join("connection.json"))
            && let Ok(connection) = serde_json::from_slice::<LocalConnectionInfo>(&bytes)
            && let Ok(response) = client
                .get(format!("{}/health/ready", connection.base_url))
                .bearer_auth(&connection.bearer_token)
                .send()
                .await
            && response.status().is_success()
            && response
                .json::<ReadinessResponse>()
                .await
                .is_ok_and(|readiness| readiness.ready)
        {
            return connection;
        }
        assert!(Instant::now() < deadline, "mealyd did not become ready");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_acknowledgement(state: &SlackFixture, envelope_id: &str) {
    wait_for_acknowledgement_count(state, envelope_id, 1).await;
}

async fn wait_for_acknowledgement_count(state: &SlackFixture, envelope_id: &str, expected: usize) {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        if state
            .acknowledgements()
            .iter()
            .filter(|value| value.as_str() == envelope_id)
            .count()
            >= expected
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Slack envelope was not acknowledged"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_inbox_count(home: &Path, session_id: &str, expected: i64) {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        if session_inbox_count(home, session_id) == expected {
            return;
        }
        assert!(Instant::now() < deadline, "Slack input was not recovered");
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_sent_text(state: &SlackFixture, expected: &str) {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        let requests = state.sent_requests();
        if requests.len() >= 2
            && requests
                .iter()
                .any(|request| request.get("text").and_then(Value::as_str) == Some(expected))
        {
            return;
        }
        assert!(Instant::now() < deadline, "Slack message was not delivered");
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_retried_client_id(state: &SlackFixture) {
    let deadline = Instant::now() + CHANNEL_TIMEOUT;
    loop {
        let mut client_ids = BTreeMap::<String, usize>::new();
        for request in state.sent_requests() {
            if let Some(client_id) = request.get("client_msg_id").and_then(Value::as_str) {
                *client_ids.entry(client_id.to_owned()).or_default() += 1;
            }
        }
        if client_ids.values().any(|count| *count >= 2) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Slack rate-limited request was not retried"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

async fn authorized_post<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
) -> T {
    client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized POST")
        .error_for_status()
        .expect("successful POST")
        .json()
        .await
        .expect("POST response JSON")
}

async fn authorized_post_response(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
) -> reqwest::Response {
    client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized POST")
}

async fn authorized_get<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
) -> T {
    client
        .get(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .send()
        .await
        .expect("authorized GET")
        .error_for_status()
        .expect("successful GET")
        .json()
        .await
        .expect("GET response JSON")
}

fn current_epoch_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock after epoch")
            .as_millis(),
    )
    .expect("current epoch milliseconds fit i64")
}

fn session_inbox_count(home: &Path, session_id: &str) -> i64 {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("open database")
        .query_row(
            "SELECT COUNT(*) FROM session_inbox WHERE session_id = ?1",
            [session_id],
            |row| row.get(0),
        )
        .expect("session inbox count")
}

fn ignored_envelope_reason(home: &Path, binding_id: &str, acknowledgement_id: &str) -> String {
    rusqlite::Connection::open(home.join("mealy.sqlite3"))
        .expect("open database")
        .query_row(
            "SELECT ignore_reason FROM slack_envelope_receipt \
             WHERE binding_id = ?1 AND acknowledgement_id = ?2",
            rusqlite::params![binding_id, acknowledgement_id],
            |row| row.get(0),
        )
        .expect("ignored Slack envelope reason")
}

fn database_contains(home: &Path, needle: &[u8]) -> bool {
    fs::read(home.join("mealy.sqlite3"))
        .expect("read database")
        .windows(needle.len())
        .any(|window| window == needle)
}
