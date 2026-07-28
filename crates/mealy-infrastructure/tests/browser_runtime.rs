//! Opt-in real Chrome Headless Shell process-boundary evidence.

use mealy_application::{
    BROWSER_CDP_PROTOCOL_VERSION, BrowserConfig, CancellationProbe, ReadOnlyTool, WebAccessConfig,
    sha256_digest,
};
use mealy_infrastructure::{
    BrowserReadTool, BrowserTransactionTool, BrowserTransactionUploadFile, inspect_browser_bundle,
    probe_browser_bundle_product, publish_browser_bundle,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tempfile::TempDir;

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct MockOrigin {
    address: std::net::SocketAddr,
    unsafe_requests: Arc<AtomicUsize>,
    transaction_requests: Arc<AtomicUsize>,
    transaction_body: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
}

impl MockOrigin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("local origin");
        listener.set_nonblocking(true).expect("nonblocking origin");
        let address = listener.local_addr().expect("origin address");
        let stop = Arc::new(AtomicBool::new(false));
        let unsafe_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let transaction_requests = Arc::new(AtomicUsize::new(0));
        let transaction_body = Arc::new(Mutex::new(Vec::new()));
        let server_stop = Arc::clone(&stop);
        let server_unsafe_requests = Arc::clone(&unsafe_requests);
        let server_transaction_requests = Arc::clone(&transaction_requests);
        let server_transaction_body = Arc::clone(&transaction_body);
        let server = thread::spawn(move || {
            let mut connections = Vec::new();
            while !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let connection_unsafe_requests = Arc::clone(&server_unsafe_requests);
                        let connection_transaction_requests =
                            Arc::clone(&server_transaction_requests);
                        let connection_transaction_body = Arc::clone(&server_transaction_body);
                        connections.push(thread::spawn(move || {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .expect("origin read timeout");
                            serve_page(
                                &mut stream,
                                &connection_unsafe_requests,
                                &connection_transaction_requests,
                                &connection_transaction_body,
                                address,
                            );
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("origin failed: {error}"),
                }
            }
            for connection in connections {
                connection.join().expect("join origin connection");
            }
        });
        Self {
            address,
            unsafe_requests,
            transaction_requests,
            transaction_body,
            stop,
            server: Some(server),
        }
    }
}

impl Drop for MockOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            server.join().expect("join origin");
        }
    }
}

fn serve_page(
    stream: &mut TcpStream,
    unsafe_requests: &AtomicUsize,
    transaction_requests: &AtomicUsize,
    transaction_body: &Mutex<Vec<u8>>,
    address: std::net::SocketAddr,
) {
    let mut request = Vec::with_capacity(8_192);
    while request.len() < 32 * 1_024 && !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0_u8; 1024];
        let Ok(read) = stream.read(&mut chunk) else {
            return;
        };
        if read == 0 {
            return;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    if !request.windows(4).any(|window| window == b"\r\n\r\n") {
        return;
    }
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header terminator")
        + 4;
    let header = String::from_utf8_lossy(&request[..header_end]).into_owned();
    let content_length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if content_length > 8 * 1_024 * 1_024 {
        return;
    }
    while request.len() < header_end.saturating_add(content_length) {
        let mut chunk = [0_u8; 8 * 1_024];
        let Ok(read) = stream.read(&mut chunk) else {
            return;
        };
        if read == 0 {
            return;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    if header.starts_with("POST /transaction ") {
        transaction_requests.fetch_add(1, Ordering::SeqCst);
        *transaction_body.lock().expect("transaction body") =
            request[header_end..header_end + content_length].to_vec();
        let body =
            "<!doctype html><title>Committed</title><main>Committed exact transaction</main>";
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("write transaction response");
        return;
    }
    if !header.starts_with("GET ") && !header.starts_with("HEAD ")
        || header.starts_with("GET /socket ")
    {
        unsafe_requests.fetch_add(1, Ordering::SeqCst);
    }
    if header.starts_with("GET /download ") {
        let body = b"bounded browser attachment evidence\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"evidence.bin\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write browser download headers");
        stream.write_all(body).expect("write browser download");
        return;
    }
    if header.starts_with("GET /download-large ") {
        let body = vec![b'x'; 512 * 1024 + 1];
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"large.bin\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write oversized browser download headers");
        stream
            .write_all(&body)
            .expect("write oversized browser download");
        return;
    }
    let body = if header.starts_with("GET /details ") {
        "<!doctype html><title>Details</title><main>Rendered detail evidence</main>"
    } else if header.starts_with("GET /search?scope=docs&query=durable+browser+evidence ") {
        "<!doctype html><title>Search</title><main>Rendered GET form evidence</main>"
    } else {
        return serve_start_page(stream, address);
    };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write browser response");
}

fn serve_start_page(stream: &mut TcpStream, address: std::net::SocketAddr) {
    let body = format!(
        "<!doctype html><title>Start</title><main>Rendered start evidence <a href=\"/details\">Details</a><a href=\"/download\">Download evidence</a><a href=\"/download-large\">Oversized download</a><output id=\"button-result\">Button not activated</output><button type=\"button\" onclick=\"document.getElementById('button-result').textContent='Rendered button evidence';fetch('/mutate',{{method:'POST',body:'forbidden'}}).catch(()=>{{}})\">Show button evidence</button><form action=\"/search?scope=docs\" method=\"get\"><label>Query <input type=\"search\" name=\"query\"></label><input type=\"hidden\" name=\"hiddenSecret\" value=\"must-not-submit\"><button>Search</button></form><form action=\"/transaction\" method=\"post\" enctype=\"multipart/form-data\"><input type=\"hidden\" name=\"csrf\" value=\"private-csrf-value\"><label>Message <textarea name=\"message\" maxlength=\"256\" required></textarea></label><label>Attachment <input type=\"file\" name=\"attachment\" accept=\"image/png\"></label><button type=\"submit\" name=\"action\" value=\"send\">Send transaction</button></form><label>Password <input type=\"password\" name=\"password\"></label></main><script>fetch('/mutate',{{method:'POST',body:'forbidden'}}).catch(()=>{{}});try{{new WebSocket('ws://{address}/socket')}}catch(_){{}};setTimeout(()=>{{try{{HTMLFormElement.prototype.submit.call(document.forms[1])}}catch(_){{}}}},500)</script>"
    );
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write start browser response");
}

fn configured_browser_tools() -> (
    TempDir,
    MockOrigin,
    BrowserReadTool,
    BrowserTransactionTool,
    String,
) {
    let source = PathBuf::from(std::env::var_os("MEALY_BROWSER_BUNDLE").expect("bundle path"));
    let inspected = inspect_browser_bundle(&source, None).expect("inspect browser bundle");
    let probe = probe_browser_bundle_product(
        std::path::Path::new("/usr/bin/bwrap"),
        &source,
        Some(inspected.bundle_digest()),
    )
    .expect("sandboxed browser probe");
    let product = probe.product().to_owned();
    let temporary = TempDir::new().expect("temporary home");
    let home = temporary.path().join("home");
    fs::create_dir(&home).expect("home");
    let destination =
        publish_browser_bundle(&inspected, &home.join("browser-runtimes")).expect("publish bundle");
    assert_eq!(
        destination,
        home.join("browser-runtimes")
            .join(inspected.bundle_digest())
    );
    let origin = MockOrigin::start();
    let config = BrowserConfig::new(
        true,
        format!("browser-runtimes/{}", inspected.bundle_digest()),
        inspected.bundle_digest().to_owned(),
        "chrome-headless-shell".to_owned(),
        inspected.executable_digest().to_owned(),
        product.clone(),
        BROWSER_CDP_PROTOCOL_VERSION.to_owned(),
    )
    .expect("browser config")
    .with_transactional_enabled(true);
    let web = WebAccessConfig {
        enabled: true,
        allow_public_internet: false,
        allowed_domains: Vec::new(),
        allowed_origins: vec![format!("http://{}", origin.address)],
        search: None,
    };
    let tool = BrowserReadTool::load(
        &home,
        std::path::Path::new("/usr/bin/bwrap"),
        std::path::Path::new(env!("CARGO_BIN_EXE_mealy-browser-worker")),
        config.clone(),
        web.clone(),
    )
    .expect("load browser tool");
    let transaction_tool = BrowserTransactionTool::load(
        &home,
        std::path::Path::new("/usr/bin/bwrap"),
        std::path::Path::new(env!("CARGO_BIN_EXE_mealy-browser-worker")),
        config,
        web,
    )
    .expect("load browser transaction tool");
    (temporary, origin, tool, transaction_tool, product)
}

/// Runs only in the explicit release environment because the reviewed browser bundle is hundreds
/// of megabytes and is not fetched implicitly by ordinary builds.
#[test]
#[ignore = "set MEALY_BROWSER_BUNDLE to a reviewed Chrome Headless Shell bundle"]
#[allow(clippy::too_many_lines)]
fn real_headless_shell_is_isolated_rendered_bounded_and_can_activate_read_only_elements() {
    let (_temporary, origin, tool, _transaction_tool, product) = configured_browser_tools();
    let address = origin.address;
    let output = tool
        .execute(
            &json!({
                "url": format!("http://{address}/"),
                "waitMs": 300,
                "maximumTextBytes": 4096,
                "maximumElements": 16,
                "captureScreenshot": true,
                "followLink": {"name": "Details"}
            }),
            &NeverCancelled,
        )
        .expect("render browser page");
    let result = serde_json::from_slice::<Value>(&output.bytes).expect("browser JSON");
    assert_eq!(result["browserProduct"], product);
    assert!(result["activatedElement"].is_null());
    assert_eq!(result["title"], "Details", "browser result: {result}");
    assert!(
        result["text"]
            .as_str()
            .expect("text")
            .contains("Rendered detail evidence")
    );
    assert_eq!(result["followedLink"]["name"], "Details");
    assert_eq!(result["screenshot"]["mediaType"], "image/png");

    let button_output = tool
        .execute(
            &json!({
                "url": format!("http://{address}/"),
                "waitMs": 300,
                "maximumTextBytes": 4096,
                "maximumElements": 16,
                "activateElement": {"role": "button", "name": "Show button evidence"}
            }),
            &NeverCancelled,
        )
        .expect("activate form-free button");
    let button_result =
        serde_json::from_slice::<Value>(&button_output.bytes).expect("button browser JSON");
    assert_eq!(button_result["activatedElement"]["role"], "button");
    assert_eq!(
        button_result["activatedElement"]["name"],
        "Show button evidence"
    );
    assert!(
        button_result["text"]
            .as_str()
            .expect("button text")
            .contains("Rendered button evidence")
    );
    assert_eq!(button_result["forms"].as_array().map(Vec::len), Some(1));
    assert!(
        button_result["forms"][0]["action"]
            .as_str()
            .expect("POST action")
            .ends_with("/transaction")
    );
    assert_eq!(
        button_result["forms"][0]["controls"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert!(!button_result.to_string().contains("private-csrf-value"));

    let fill_output = tool
        .execute(
            &json!({
                "url": format!("http://{address}/"),
                "waitMs": 300,
                "maximumTextBytes": 4096,
                "maximumElements": 16,
                "fillElement": {
                    "role": "searchbox",
                    "name": "Query",
                    "value": "durable browser evidence",
                    "submitGetForm": true
                }
            }),
            &NeverCancelled,
        )
        .expect("fill and submit exact GET form control");
    let fill_result =
        serde_json::from_slice::<Value>(&fill_output.bytes).expect("fill browser JSON");
    assert_eq!(fill_result["filledElement"]["role"], "searchbox");
    assert_eq!(fill_result["filledElement"]["submittedGetForm"], true);
    assert!(
        fill_result["filledElement"]["submittedUrl"]
            .as_str()
            .expect("submitted URL")
            .ends_with("/search?scope=docs&query=durable+browser+evidence")
    );
    assert!(
        fill_result["text"]
            .as_str()
            .expect("GET form text")
            .contains("Rendered GET form evidence")
    );
    assert!(!fill_result.to_string().contains("must-not-submit"));

    let download_output = tool
        .execute(
            &json!({
                "url": format!("http://{address}/"),
                "waitMs": 300,
                "maximumTextBytes": 4096,
                "maximumElements": 16,
                "downloadLink": {"name": "Download evidence"}
            }),
            &NeverCancelled,
        )
        .expect("capture bounded same-origin attachment");
    let download_result =
        serde_json::from_slice::<Value>(&download_output.bytes).expect("download browser JSON");
    let expected_download = b"bounded browser attachment evidence\n";
    assert_eq!(
        download_result["download"]["dataBase64"],
        "Ym91bmRlZCBicm93c2VyIGF0dGFjaG1lbnQgZXZpZGVuY2UK"
    );
    assert_eq!(
        download_result["download"]["sha256Digest"],
        sha256_digest(expected_download)
    );
    assert_eq!(
        download_result["download"]["sizeBytes"],
        expected_download.len()
    );
    assert!(
        download_result["download"]["url"]
            .as_str()
            .expect("download URL")
            .ends_with("/download")
    );
    let oversized_download = tool.execute(
        &json!({
            "url": format!("http://{address}/"),
            "waitMs": 300,
            "downloadLink": {"name": "Oversized download"}
        }),
        &NeverCancelled,
    );
    assert!(oversized_download.is_err());

    let submit = tool.execute(
        &json!({
            "url": format!("http://{address}/"),
            "waitMs": 300,
            "activateElement": {"role": "button", "name": "Send transaction"}
        }),
        &NeverCancelled,
    );
    assert!(submit.is_err());
    let post_form = tool.execute(
        &json!({
            "url": format!("http://{address}/"),
            "waitMs": 300,
            "fillElement": {
                "role": "textbox",
                "name": "Message",
                "value": "forbidden",
                "submitGetForm": true
            }
        }),
        &NeverCancelled,
    );
    assert!(post_form.is_err());
    let password = tool.execute(
        &json!({
            "url": format!("http://{address}/"),
            "waitMs": 300,
            "fillElement": {
                "role": "textbox",
                "name": "Password",
                "value": "forbidden"
            }
        }),
        &NeverCancelled,
    );
    assert!(password.is_err());
    assert_eq!(tool.invocation_count(), 8);
    assert_eq!(origin.unsafe_requests.load(Ordering::SeqCst), 0);
}

/// Proves the separately enabled one-shot profile submits exactly one approved POST with the
/// approved public field, hidden form value, upload bytes, and upload filename.
#[test]
#[ignore = "set MEALY_BROWSER_BUNDLE to a reviewed Chrome Headless Shell bundle"]
fn real_headless_shell_transaction_is_exact_one_shot_and_same_origin() {
    let (_temporary, origin, read_tool, transaction_tool, _product) = configured_browser_tools();
    let address = origin.address;
    let snapshot = read_tool
        .execute(
            &json!({
                "url": format!("http://{address}/"),
                "waitMs": 300,
                "maximumTextBytes": 4096,
                "maximumElements": 16
            }),
            &NeverCancelled,
        )
        .expect("catalog transaction form");
    let snapshot = serde_json::from_slice::<Value>(&snapshot.bytes).expect("snapshot JSON");
    let form = snapshot["forms"]
        .as_array()
        .and_then(|forms| forms.first())
        .expect("one transaction form");
    assert!(
        form["action"]
            .as_str()
            .expect("form action")
            .ends_with("/transaction")
    );
    let form_digest = form["formDigest"].as_str().expect("form digest");
    let upload_bytes = b"\x89PNG\r\n\x1a\nexact-owner-image";
    let upload_digest = sha256_digest(upload_bytes);
    let arguments = json!({
        "initialUrl": format!("http://{address}/"),
        "formDigest": form_digest,
        "fields": [{"name": "message", "value": "exact owner request"}],
        "submitter": {"name": "action", "value": "send"},
        "uploads": [{
            "controlName": "attachment",
            "artifactId": "artifact-owner-image",
            "artifactDigest": upload_digest,
            "fileName": "owner-image.png",
            "mediaType": "image/png",
            "sizeBytes": upload_bytes.len()
        }]
    });
    let upload = BrowserTransactionUploadFile::new(
        "attachment".to_owned(),
        "artifact-owner-image".to_owned(),
        upload_digest,
        "owner-image.png".to_owned(),
        "image/png".to_owned(),
        upload_bytes.to_vec(),
    );
    let executed = transaction_tool
        .execute(&arguments, &[upload], &NeverCancelled)
        .unwrap_or_else(|error| {
            panic!(
                "execute exact transaction: {error}; observed POSTs={}, unsafe={}",
                origin.transaction_requests.load(Ordering::SeqCst),
                origin.unsafe_requests.load(Ordering::SeqCst)
            )
        });
    assert!(executed.download.is_none());
    assert_eq!(executed.evidence["responseStatus"], 201);
    assert!(
        executed.evidence["text"]
            .as_str()
            .expect("response text")
            .contains("Committed exact transaction")
    );
    assert_eq!(origin.transaction_requests.load(Ordering::SeqCst), 1);
    assert_eq!(origin.unsafe_requests.load(Ordering::SeqCst), 0);
    let body = origin.transaction_body.lock().expect("transaction body");
    for expected in [
        b"private-csrf-value".as_slice(),
        b"exact owner request".as_slice(),
        b"owner-image.png".as_slice(),
        upload_bytes.as_slice(),
    ] {
        assert!(
            body.windows(expected.len())
                .any(|window| window == expected),
            "multipart body omitted approved bytes"
        );
    }
}
