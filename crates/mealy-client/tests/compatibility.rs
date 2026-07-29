//! Frozen daemon-response compatibility proofs for the stable owner client.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;

use mealy_client::{ClientError, MealyClient};
use serde::Deserialize;

const FIXTURES: [&str; 4] = [
    include_str!("fixtures/v0.2.1.json"),
    include_str!("fixtures/v0.3.0.json"),
    include_str!("fixtures/v0.4.0.json"),
    include_str!("fixtures/v0.5.0.json"),
];

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DaemonFixture {
    schema_version: String,
    release_version: String,
    api_version: String,
    expected_session_title: String,
    expected_session_title_source: String,
    exchanges: Vec<Exchange>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Exchange {
    operation: String,
    request_line: String,
    status: u16,
    response_body: String,
}

#[test]
fn stable_client_decodes_frozen_v021_v03_v04_and_v05_daemon_contracts() {
    for source in FIXTURES {
        let fixture: DaemonFixture =
            serde_json::from_str(source).expect("valid frozen daemon fixture");
        assert_eq!(fixture.schema_version, "mealy.sdk-daemon-fixture.v1");
        assert_eq!(fixture.api_version, mealy_client::protocol::API_VERSION);
        assert!(matches!(
            fixture.release_version.as_str(),
            "0.2.1" | "0.3.0" | "0.4.0" | "0.5.0"
        ));
        assert_eq!(
            fixture
                .exchanges
                .iter()
                .map(|exchange| exchange.operation.as_str())
                .collect::<Vec<_>>(),
            ["liveness", "readiness", "sessions", "missing_task"]
        );

        let (origin, server) = serve_fixture(fixture.exchanges.clone());
        let client = MealyClient::new(origin, "compatibility-token").expect("fixture client");
        assert!(client.liveness().expect("frozen liveness").live);
        let readiness = client.readiness().expect("frozen readiness");
        assert!(readiness.ready);
        assert_eq!(readiness.state, "ready");
        let sessions = client.sessions(20).expect("frozen sessions");
        assert_eq!(sessions.sessions.len(), 1);
        assert_eq!(sessions.sessions[0].title, fixture.expected_session_title);
        assert_eq!(
            sessions.sessions[0].title_source,
            fixture.expected_session_title_source
        );
        match client.task("task-missing") {
            Err(ClientError::Api { status, error }) => {
                assert_eq!(status, 404);
                assert_eq!(error.code, "not_found");
                assert!(!error.retryable);
            }
            result => panic!("frozen structured error decoded unexpectedly: {result:?}"),
        }
        server.join().expect("fixture server");
    }
}

fn serve_fixture(exchanges: Vec<Exchange>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
    let address: SocketAddr = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || {
        for exchange in exchanges {
            let (mut stream, _) = listener.accept().expect("fixture connection");
            let request = read_request(&mut stream);
            let request_text = String::from_utf8(request).expect("UTF-8 fixture request");
            assert_eq!(
                request_text.lines().next(),
                Some(exchange.request_line.as_str()),
                "request line drifted for {}",
                exchange.operation
            );
            assert!(
                request_text.lines().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.eq_ignore_ascii_case("authorization")
                            && value.trim() == "Bearer compatibility-token"
                    })
                }),
                "authorization boundary drifted for {}",
                exchange.operation
            );
            serde_json::from_str::<serde_json::Value>(&exchange.response_body)
                .expect("fixture response is JSON");
            let reason = match exchange.status {
                200 => "OK",
                404 => "Not Found",
                status => panic!("unsupported fixture status: {status}"),
            };
            let response = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                exchange.status,
                reason,
                exchange.response_body.len(),
                exchange.response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("fixture response");
        }
    });
    (format!("http://{address}"), server)
}

fn read_request(stream: &mut impl Read) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4_096];
    loop {
        let count = stream.read(&mut buffer).expect("fixture request");
        assert!(count > 0, "fixture request ended before its headers");
        request.extend_from_slice(&buffer[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return request;
        }
        assert!(
            request.len() <= 64 * 1_024,
            "fixture request exceeded bound"
        );
    }
}
