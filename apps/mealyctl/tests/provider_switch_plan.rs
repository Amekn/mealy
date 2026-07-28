//! Public-process proof for the non-mutating provider-switch review boundary.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_protocol::{API_VERSION, LocalConnectionInfo};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    process::Command,
    thread,
    time::Duration,
};

#[test]
fn switch_plan_requires_exact_active_config_and_never_probes_or_mutates() {
    let home = private_temporary_home();
    let original = json!({
        "formatVersion": 1,
        "provider": local_provider("local.primary", "primary-model", 18080),
        "providerFallbacks": [
            local_provider("local.fallback", "fallback-model", 18081)
        ]
    });
    let config_path = home.path().join("config.json");
    let original_bytes = serde_json::to_vec_pretty(&original).expect("configuration");
    fs::write(&config_path, &original_bytes).expect("write configuration");
    private_file(&config_path);

    let catalog = json!({
        "apiVersion": API_VERSION,
        "catalogScope": "configured_route",
        "configDigest": "a".repeat(64),
        "automaticFallbackEnabled": true,
        "routes": [
            catalog_route("local.primary", "primary-model", 0),
            catalog_route("local.fallback", "fallback-model", 1)
        ]
    });
    let (base_url, request, server) = serve_catalog(catalog.to_string());
    write_connection(home.path(), &base_url);

    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "provider",
            "switch",
            "--provider-id",
            "local.fallback",
            "--model-id",
            "fallback-model",
        ])
        .output()
        .expect("run switch plan");
    assert!(
        output.status.success(),
        "switch plan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: Value = serde_json::from_slice(&output.stdout).expect("switch plan JSON");
    assert_eq!(plan["schemaVersion"], "mealy.provider-switch-plan.v1");
    assert_eq!(plan["actionRequired"], true);
    assert_eq!(plan["providerId"], "local.fallback");
    assert_eq!(plan["modelId"], "fallback-model");
    assert_eq!(plan["previousProviderId"], "local.primary");
    assert_eq!(plan["configuredRouteCount"], 2);
    assert_eq!(plan["probeRequired"], true);
    assert_eq!(plan["drainRequired"], true);
    assert_eq!(plan["restartRequired"], true);
    assert_eq!(plan["applySupported"], false);
    assert_eq!(
        fs::read(&config_path).expect("configuration after plan"),
        original_bytes,
        "review mode must not rewrite even formatting bytes"
    );
    assert!(!home.path().join("provider-switch-transactions").exists());

    let request = request.join().expect("catalog request");
    assert!(request.starts_with("GET /v1/providers/catalog HTTP/1.1\r\n"));
    let expected = format!("Bearer {}", URL_SAFE_NO_PAD.encode([7_u8; 32]));
    assert!(request.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value.trim() == expected
        })
    }));
    server.join().expect("catalog server");
}

fn local_provider(provider_id: &str, model: &str, port: u16) -> Value {
    json!({
        "kind": "open_ai_responses",
        "providerId": provider_id,
        "baseUrl": format!("http://127.0.0.1:{port}/v1"),
        "model": model,
        "credential": null,
        "residency": "owner-local",
        "contextTokens": 32768,
        "maximumOutputTokens": 4096,
        "streaming": false,
        "inputMicrounitsPerMillionTokens": 0,
        "outputMicrounitsPerMillionTokens": 0,
        "estimatedLatencyMs": 1000
    })
}

fn catalog_route(provider_id: &str, model_id: &str, ordinal: u64) -> Value {
    json!({
        "routeOrdinal": ordinal,
        "routeRole": if ordinal == 0 { "primary" } else { "fallback" },
        "protocol": "openai_responses",
        "providerId": provider_id,
        "modelId": model_id,
        "inputModalities": ["text"],
        "toolCalling": true,
        "structuredOutput": true,
        "reasoningControls": [],
        "streaming": false,
        "residency": "owner-local",
        "local": true,
        "contextTokens": 32768,
        "maximumOutputTokens": 4096,
        "inputTokenOverhead": 0,
        "limitsSource": "active_configuration",
        "limitsOperatorVerified": false,
        "inputMicrounitsPerMillionTokens": 0,
        "outputMicrounitsPerMillionTokens": 0,
        "pricingSource": "active_configuration",
        "pricingVerified": false,
        "health": "unknown",
        "estimatedLatencyMs": 1000,
        "inFlightRequests": 0,
        "maximumConcurrentRequests": 1,
        "requestsInCurrentMinute": 0,
        "requestsPerMinute": 60,
        "selectable": true
    })
}

fn private_temporary_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).expect("private home");
    }
    home
}

fn private_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file");
    }
}

fn write_connection(home: &std::path::Path, base_url: &str) {
    let descriptor = LocalConnectionInfo {
        api_version: API_VERSION.to_owned(),
        base_url: base_url.to_owned(),
        bearer_token: URL_SAFE_NO_PAD.encode([7_u8; 32]),
        principal_id: "principal-1".to_owned(),
        channel_binding_id: "binding-1".to_owned(),
    };
    let path = home.join("connection.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&descriptor).expect("connection descriptor"),
    )
    .expect("write connection descriptor");
    private_file(&path);
}

fn serve_catalog(body: String) -> (String, thread::JoinHandle<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind catalog server");
    let address = listener.local_addr().expect("catalog address");
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept catalog request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("request timeout");
        let mut raw = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let count = stream.read(&mut chunk).expect("read catalog request");
            assert!(count > 0, "catalog request ended before headers");
            raw.extend_from_slice(&chunk[..count]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        sender
            .send(String::from_utf8(raw).expect("catalog request UTF-8"))
            .expect("capture catalog request");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("write catalog response");
    });
    let request = thread::spawn(move || receiver.recv().expect("catalog capture"));
    (format!("http://{address}"), request, server)
}
