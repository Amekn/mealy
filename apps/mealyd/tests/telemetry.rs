//! Public-process proof for the optional privacy-preserving OTLP boundary.

use mealy_protocol::{
    API_VERSION, CreateSessionRequest, CreateSessionResponse, DeliveryMode, InputAdmissionResponse,
    LocalConnectionInfo, ReadinessResponse, SubmitInputRequest, TaskResponse, TaskStatus,
    TimelinePageResponse,
};
use reqwest::{Client, StatusCode};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(15);
const PRIVATE_PROMPT: &str = "PROMPT_CANARY_MUST_NOT_ENTER_OTLP";

struct Daemon {
    child: Child,
}

impl Daemon {
    fn spawn(home: &Path, collector_origin: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .arg("--promotion-delay-ms")
            .arg("0")
            .arg("--promotion-interval-ms")
            .arg("10")
            .arg("--outbox-delay-ms")
            .arg("0")
            .arg("--agent-delay-ms")
            .arg("0")
            .arg("--otlp-endpoint")
            .arg(collector_origin)
            .arg("--otlp-export-interval-ms")
            .arg("1000")
            .arg("--otlp-request-timeout-ms")
            .arg("1000")
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("mealyd process should start");
        Self { child }
    }

    fn hard_kill(&mut self) {
        self.child.kill().expect("mealyd should accept a hard kill");
        self.child.wait().expect("mealyd should be reaped");
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
    path: String,
    headers: String,
    body: Vec<u8>,
}

struct Collector {
    origin: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
}

impl Collector {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind collector");
        listener
            .set_nonblocking(true)
            .expect("nonblocking collector");
        let address = listener.local_addr().expect("collector address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let server_requests = Arc::clone(&requests);
        let server_stop = Arc::clone(&stop);
        let server = thread::spawn(move || {
            while !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => server_requests
                        .lock()
                        .expect("collector request lock")
                        .push(read_request(stream)),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("collector accept failed: {error}"),
                }
            }
        });
        Self {
            origin: format!("http://{address}"),
            requests,
            stop,
            server: Some(server),
        }
    }

    fn snapshot(&self) -> Vec<CapturedRequest> {
        self.requests
            .lock()
            .expect("collector request lock")
            .clone()
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            server.join().expect("collector thread should stop");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_exports_correlated_agent_signals_without_prompt_content() {
    let collector = Collector::spawn();
    let home = TempDir::new().expect("temporary daemon home");
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client");
    let mut daemon = Daemon::spawn(home.path(), &collector.origin);
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
            idempotency_key: "telemetry-private-prompt".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!("{PRIVATE_PROMPT}: read the fixture and finish."),
        },
    )
    .await;
    let (task_id, run_id) = wait_for_task_and_run(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    wait_until_task_succeeds(&client, &connection, &task_id).await;

    let requests = wait_for_signals(&collector, &task_id, &run_id).await;
    daemon.hard_kill();
    assert!(requests.iter().any(|request| request.path == "/v1/traces"));
    assert!(requests.iter().any(|request| request.path == "/v1/metrics"));
    assert!(
        requests
            .iter()
            .filter(|request| request.path == "/v1/traces")
            .any(|request| contains(&request.body, task_id.as_bytes())
                && contains(&request.body, run_id.as_bytes())
                && contains(&request.body, session.session_id.as_bytes()))
    );
    for request in &requests {
        assert!(!contains(&request.body, PRIVATE_PROMPT.as_bytes()));
        assert!(
            !request
                .headers
                .to_ascii_lowercase()
                .contains("authorization:")
        );
        if request.path == "/v1/metrics" {
            assert!(!contains(&request.body, task_id.as_bytes()));
            assert!(!contains(&request.body, run_id.as_bytes()));
        }
    }
}

async fn wait_for_signals(
    collector: &Collector,
    task_id: &str,
    run_id: &str,
) -> Vec<CapturedRequest> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let requests = collector.snapshot();
        let has_metrics = requests.iter().any(|request| request.path == "/v1/metrics");
        let has_correlated_trace = requests
            .iter()
            .filter(|request| request.path == "/v1/traces")
            .any(|request| {
                contains(&request.body, task_id.as_bytes())
                    && contains(&request.body, run_id.as_bytes())
            });
        if has_metrics && has_correlated_trace {
            return requests;
        }
        assert!(Instant::now() < deadline, "OTLP signals were not exported");
        sleep(Duration::from_millis(20)).await;
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn read_request(mut stream: TcpStream) -> CapturedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("collector read timeout");
    let mut request = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4_096];
        let read = stream.read(&mut chunk).expect("read OTLP request");
        assert!(read > 0, "request ended before headers");
        request.extend_from_slice(&chunk[..read]);
        assert!(request.len() <= 2 * 1_024 * 1_024 + 16 * 1_024);
        if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8(request[..header_end].to_vec()).expect("ASCII request headers");
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("content length"))
        })
        .expect("content length");
    while request.len() - header_end < content_length {
        let mut chunk = [0_u8; 4_096];
        let read = stream.read(&mut chunk).expect("read OTLP body");
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
        .expect("collector response");
    CapturedRequest {
        path,
        headers,
        body: request[header_end..header_end + content_length].to_vec(),
    }
}

async fn wait_until_ready(client: &Client, home: &Path) -> LocalConnectionInfo {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(bytes) = std::fs::read(home.join("connection.json"))
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

async fn wait_for_task_and_run(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
) -> (String, String) {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let page: TimelinePageResponse = authorized_get(
            client,
            connection,
            &format!("/v1/sessions/{session_id}/timeline?after={after}&limit=100"),
        )
        .await;
        let task = page
            .events
            .iter()
            .find(|event| event.event_type == "task.created");
        let run = page
            .events
            .iter()
            .find(|event| event.event_type == "run.created");
        if let (Some(task), Some(run)) = (task, run) {
            return (task.aggregate_id.clone(), run.aggregate_id.clone());
        }
        assert!(Instant::now() < deadline, "task and run were not created");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_task_succeeds(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
) {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let task: TaskResponse =
            authorized_get(client, connection, &format!("/v1/tasks/{task_id}")).await;
        match task.status {
            TaskStatus::Succeeded => return,
            TaskStatus::Failed | TaskStatus::Cancelled => {
                panic!("agent task reached unexpected terminal state: {task:?}")
            }
            _ => {}
        }
        assert!(Instant::now() < deadline, "agent task did not succeed");
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
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.expect("versioned JSON response")
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
    response.json().await.expect("versioned JSON response")
}
