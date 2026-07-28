//! Process-boundary proof for stopped-daemon MCP configuration lifecycle controls.

use mealy_application::{
    MCP_PROTOCOL_VERSION, McpHttpAuthentication, McpHttpServerConfig, McpServerConfig,
    McpServerDiscovery, McpToolGrant, McpToolInspection,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Command, Stdio},
    thread,
};
use url::Url;

#[test]
fn configured_mcp_authority_is_listable_disableable_and_revocable_with_explicit_approval() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    let server = fixture_config();
    let http_server = fixture_http_config();
    let mut config = default_config();
    config["mcpServers"] = serde_json::to_value([server]).expect("MCP config");
    config["mcpHttpServers"] = serde_json::to_value([http_server]).expect("HTTP MCP config");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&config).expect("config bytes"),
    )
    .expect("write config");

    let listed = command(home.path(), &["mcp-list"]);
    assert!(
        listed.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let response: Value = serde_json::from_slice(&listed.stdout).expect("list response");
    assert_eq!(response["servers"][0]["serverId"], "fixture");
    assert_eq!(response["servers"][0]["enabled"], true);
    assert_eq!(
        response["servers"][0]["tools"][0]["definition"]["name"],
        "add"
    );
    assert_eq!(response["httpServers"][0]["serverId"], "remote");
    assert_eq!(
        response["httpServers"][0]["endpoint"],
        "http://127.0.0.1:9/mcp"
    );

    let before = fs::read(home.path().join("config.json")).expect("config before denial");
    let denied = command(home.path(), &["mcp-disable", "fixture"]);
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("requires --approve"));
    assert_eq!(
        fs::read(home.path().join("config.json")).expect("config after denial"),
        before
    );

    let disabled = command(home.path(), &["mcp-disable", "fixture", "--approve"]);
    assert!(
        disabled.status.success(),
        "disable failed: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    let response: Value = serde_json::from_slice(&disabled.stdout).expect("disable response");
    assert_eq!(response["operation"], "disabled");
    assert_eq!(response["enabled"], false);
    assert_eq!(response["restartRequired"], true);
    assert_eq!(read_config(home.path())["mcpServers"][0]["enabled"], false);

    let http_disabled = command(home.path(), &["mcp-http", "disable", "remote", "--approve"]);
    assert!(
        http_disabled.status.success(),
        "HTTP disable failed: {}",
        String::from_utf8_lossy(&http_disabled.stderr)
    );
    let response: Value =
        serde_json::from_slice(&http_disabled.stdout).expect("HTTP disable response");
    assert_eq!(response["operation"], "disabled");
    assert_eq!(response["endpoint"], "http://127.0.0.1:9/mcp");
    assert_eq!(
        read_config(home.path())["mcpHttpServers"][0]["enabled"],
        false
    );

    let revoked = command(home.path(), &["mcp-revoke", "fixture", "--approve"]);
    assert!(
        revoked.status.success(),
        "revoke failed: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let response: Value = serde_json::from_slice(&revoked.stdout).expect("revoke response");
    assert_eq!(response["operation"], "revoked");
    assert_eq!(response["executableRetainedForRollback"], true);
    assert!(read_config(home.path()).get("mcpServers").is_none());
    let http_revoked = command(home.path(), &["mcp-http", "revoke", "remote", "--approve"]);
    assert!(
        http_revoked.status.success(),
        "HTTP revoke failed: {}",
        String::from_utf8_lossy(&http_revoked.stderr)
    );
    assert!(read_config(home.path()).get("mcpHttpServers").is_none());
    assert!(
        fs::read_dir(home.path().join("config-history"))
            .expect("history")
            .count()
            >= 2
    );
}

#[test]
fn mcp_add_parses_but_cannot_execute_or_mutate_without_approval() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("config bytes"),
    )
    .expect("write config");
    let before = fs::read(home.path().join("config.json")).expect("config before");
    let output = command(
        home.path(),
        &[
            "mcp-add",
            "fixture",
            "/definitely/not/executable",
            "--allow-tool",
            "add",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires --approve"));
    assert_eq!(
        fs::read(home.path().join("config.json")).expect("config after"),
        before
    );
    assert!(!home.path().join("mcp-servers").exists());

    let http_output = command(
        home.path(),
        &[
            "mcp-http",
            "add",
            "remote",
            "http://127.0.0.1:9/mcp",
            "--allow-tool",
            "lookup",
        ],
    );
    assert!(!http_output.status.success());
    assert!(String::from_utf8_lossy(&http_output.stderr).contains("requires --approve"));
    assert_eq!(
        fs::read(home.path().join("config.json")).expect("config after HTTP denial"),
        before
    );
}

#[test]
fn mcp_http_inspect_and_add_pin_one_live_reviewed_toolset() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("config bytes"),
    )
    .expect("write config");
    let definition = json!({
        "name": "lookup",
        "description": "Returns one fixture value",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {"key": {"type": "string"}},
            "required": ["key"]
        }
    });
    let (endpoint, server) = spawn_http_fixture(definition.clone(), 2);
    let inspected = command(
        home.path(),
        &["mcp-http", "inspect", "remote", endpoint.as_str()],
    );
    assert!(
        inspected.status.success(),
        "HTTP inspect failed: {}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let response: Value = serde_json::from_slice(&inspected.stdout).expect("inspect response");
    assert_eq!(
        response["transport"],
        "streamable_http_2025_11_25_fresh_session_redirect_free_dns_pinned"
    );
    assert_eq!(response["discovery"]["tools"][0]["definition"], definition);

    let added = command(
        home.path(),
        &[
            "mcp-http",
            "add",
            "remote",
            endpoint.as_str(),
            "--allow-tool",
            "lookup",
            "--approve",
        ],
    );
    assert!(
        added.status.success(),
        "HTTP add failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    let response: Value = serde_json::from_slice(&added.stdout).expect("add response");
    assert_eq!(response["operation"], "installed_and_enabled");
    assert_eq!(
        response["exposedToolIds"],
        json!(["mcp.remote.tool.lookup"])
    );
    assert_eq!(
        read_config(home.path())["mcpHttpServers"][0]["endpoint"],
        endpoint
    );
    assert!(
        read_config(home.path())["mcpHttpServers"][0]
            .get("credential")
            .is_none()
    );
    server.join().expect("HTTP fixture server");
}

#[test]
fn mcp_http_add_selects_exact_resources_and_prompts_from_the_complete_catalog() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("config bytes"),
    )
    .expect("write config");
    let resource = json!({
        "uri": "fixture://docs/readme",
        "name": "readme",
        "description": "One exact documentation resource",
        "mimeType": "text/markdown"
    });
    let prompt = json!({
        "name": "review",
        "description": "One exact prompt",
        "arguments": [{"name": "topic", "required": true}]
    });
    let (endpoint, server) = spawn_http_catalog_fixture(resource.clone(), prompt.clone(), 2);
    let inspected = command(
        home.path(),
        &["mcp-http", "inspect", "catalog", endpoint.as_str()],
    );
    assert!(
        inspected.status.success(),
        "HTTP catalog inspect failed: {}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let response: Value = serde_json::from_slice(&inspected.stdout).expect("inspect response");
    assert_eq!(
        response["discovery"]["resources"][0]["definition"],
        resource
    );
    assert_eq!(response["discovery"]["prompts"][0]["definition"], prompt);

    let added = command(
        home.path(),
        &[
            "mcp-http",
            "add",
            "catalog",
            endpoint.as_str(),
            "--allow-resource",
            "fixture://docs/readme",
            "--allow-prompt",
            "review",
            "--approve",
        ],
    );
    assert!(
        added.status.success(),
        "HTTP catalog add failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    let response: Value = serde_json::from_slice(&added.stdout).expect("add response");
    assert_eq!(response["exposedToolIds"], json!([]));
    assert_eq!(
        response["exposedPromptToolIds"],
        json!(["mcp.catalog.prompt.review"])
    );
    assert!(
        response["exposedResourceToolIds"][0]
            .as_str()
            .is_some_and(|value| value.starts_with("mcp.catalog.resource."))
    );
    assert!(
        response["catalogDigest"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)
    );
    let config = read_config(home.path());
    assert_eq!(
        config["mcpHttpServers"][0]["resources"][0]["definition"]["uri"],
        "fixture://docs/readme"
    );
    assert_eq!(
        config["mcpHttpServers"][0]["prompts"][0]["definition"]["name"],
        "review"
    );
    server.join().expect("HTTP catalog fixture server");
}

#[test]
fn mcp_http_oauth_inspect_is_non_mutating_and_reports_pinned_discovery() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    let config = serde_json::to_vec_pretty(&default_config()).expect("config bytes");
    fs::write(home.path().join("config.json"), &config).expect("write config");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind OAuth fixture");
    let address = listener.local_addr().expect("OAuth fixture address");
    let origin = format!("http://{address}");
    let endpoint = format!("{origin}/mcp");
    let origin_for_worker = origin.clone();
    let server = thread::spawn(move || {
        let responses = [
            format!(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer resource_metadata=\"{origin_for_worker}/.well-known/oauth-protected-resource/mcp\", scope=\"files:read\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            http_json_response(
                "200 OK",
                &json!({
                    "resource": format!("{origin_for_worker}/mcp"),
                    "authorization_servers": [origin_for_worker],
                    "scopes_supported": ["files:read"]
                }),
                None,
            ),
            http_json_response(
                "200 OK",
                &json!({
                    "issuer": origin_for_worker,
                    "authorization_endpoint": format!("{origin_for_worker}/authorize"),
                    "token_endpoint": format!("{origin_for_worker}/token"),
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["none"]
                }),
                None,
            ),
        ];
        for response in responses {
            let (mut stream, _) = listener.accept().expect("accept OAuth fixture request");
            read_http_request(&mut stream);
            stream
                .write_all(response.as_bytes())
                .expect("write OAuth fixture response");
        }
    });
    let inspected = command(
        home.path(),
        &["mcp-http", "oauth-inspect", "oauth", endpoint.as_str()],
    );
    assert!(
        inspected.status.success(),
        "OAuth inspect failed: {}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let response: Value = serde_json::from_slice(&inspected.stdout).expect("inspect response");
    assert_eq!(response["mutation"], "none_metadata_discovery_only");
    assert_eq!(response["discovery"]["resource"], endpoint);
    assert_eq!(response["discovery"]["selectedAuthorizationServer"], origin);
    assert_eq!(
        response["discovery"]["codeChallengeMethodsSupported"],
        json!(["S256"])
    );
    assert_eq!(
        fs::read(home.path().join("config.json")).expect("unchanged config"),
        config
    );
    assert!(!home.path().join("provider-secrets").exists());
    server.join().expect("OAuth fixture server");
}

#[test]
#[allow(clippy::too_many_lines)]
fn mcp_http_oauth_login_uses_loopback_pkce_and_privately_brokers_tokens() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    let config = serde_json::to_vec_pretty(&default_config()).expect("config bytes");
    fs::write(home.path().join("config.json"), &config).expect("write config");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind OAuth fixture");
    let address = listener.local_addr().expect("OAuth fixture address");
    let origin = format!("http://{address}");
    let endpoint = format!("{origin}/mcp");
    let origin_for_worker = origin.clone();
    let server = thread::spawn(move || {
        let discovery_responses = [
            format!(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer resource_metadata=\"{origin_for_worker}/.well-known/oauth-protected-resource/mcp\", scope=\"files:read\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            http_json_response(
                "200 OK",
                &json!({
                    "resource": format!("{origin_for_worker}/mcp"),
                    "authorization_servers": [origin_for_worker],
                    "scopes_supported": ["files:read"]
                }),
                None,
            ),
            http_json_response(
                "200 OK",
                &json!({
                    "issuer": origin_for_worker,
                    "authorization_endpoint": format!("{origin_for_worker}/authorize"),
                    "token_endpoint": format!("{origin_for_worker}/token"),
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["none"]
                }),
                None,
            ),
        ];
        for response in discovery_responses {
            let (mut stream, _) = listener.accept().expect("accept OAuth discovery request");
            read_http_request(&mut stream);
            stream
                .write_all(response.as_bytes())
                .expect("write OAuth discovery response");
        }
        let (mut stream, _) = listener.accept().expect("accept OAuth token request");
        let token_request = read_http_request(&mut stream);
        assert!(token_request.contains("grant_type=authorization_code"));
        assert!(token_request.contains("client_id=mealy-native"));
        assert!(token_request.contains("code=fixture-code"));
        assert!(token_request.contains("code_verifier="));
        assert!(token_request.contains("redirect_uri=http%3A%2F%2F127.0.0.1"));
        assert!(token_request.contains("resource=http%3A%2F%2F127.0.0.1"));
        let response = http_oauth_token_response(&json!({
            "access_token": "fixture-access-secret",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "fixture-refresh-secret",
            "scope": "files:read"
        }));
        stream
            .write_all(response.as_bytes())
            .expect("write OAuth token response");
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "mcp-http",
            "oauth-login",
            "oauth",
            endpoint.as_str(),
            "--oauth-client-id",
            "mealy-native",
            "--oauth-token-set-id",
            "oauth.fixture",
            "--oauth-timeout-seconds",
            "30",
            "--approve",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start OAuth login");
    let mut stderr = BufReader::new(child.stderr.take().expect("OAuth login stderr"));
    let authorization_url = loop {
        let mut line = String::new();
        let count = stderr.read_line(&mut line).expect("read authorization URL");
        assert_ne!(count, 0, "OAuth login exited before presenting a URL");
        if let Some((_, encoded)) = line.split_once("\"authorizationUrl\":") {
            let encoded = encoded.trim().trim_end_matches(',');
            break serde_json::from_str::<String>(encoded).expect("authorization URL JSON");
        }
    };
    let authorization_url = Url::parse(&authorization_url).expect("authorization URL");
    let query = authorization_url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("code_challenge_method").map(AsRef::as_ref),
        Some("S256")
    );
    assert_eq!(
        query.get("resource").map(AsRef::as_ref),
        Some(endpoint.as_str())
    );
    let state = query.get("state").expect("OAuth state").to_string();
    let redirect_uri = query
        .get("redirect_uri")
        .expect("OAuth redirect URI")
        .to_string();
    let mut callback_url = Url::parse(&redirect_uri).expect("callback URL");
    callback_url
        .query_pairs_mut()
        .append_pair("code", "fixture-code")
        .append_pair("state", &state);
    let mut callback = TcpStream::connect((
        callback_url.host_str().expect("callback host"),
        callback_url.port().expect("callback port"),
    ))
    .expect("connect OAuth callback");
    write!(
        callback,
        "GET {}?{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        callback_url.path(),
        callback_url.query().expect("callback query"),
        callback_url.port().expect("callback port")
    )
    .expect("send OAuth callback");
    let mut callback_response = String::new();
    callback
        .read_to_string(&mut callback_response)
        .expect("read OAuth callback response");
    assert!(callback_response.starts_with("HTTP/1.1 200 OK\r\n"));

    let mut remaining_stderr = String::new();
    stderr
        .read_to_string(&mut remaining_stderr)
        .expect("read remaining OAuth stderr");
    let output = child.wait_with_output().expect("finish OAuth login");
    assert!(
        output.status.success(),
        "OAuth login failed: {remaining_stderr}"
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("OAuth login response");
    assert_eq!(response["tokenSetId"], "oauth.fixture");
    assert_eq!(response["resource"], endpoint);
    assert_eq!(response["generation"], 1);
    assert_eq!(response["configurationChanged"], false);
    assert_eq!(response["authorityExposed"], false);
    assert_eq!(
        fs::read(home.path().join("config.json")).expect("unchanged config"),
        config
    );
    let token_path = home.path().join("mcp-oauth-tokens/oauth.fixture.json");
    let token_record: Value =
        serde_json::from_slice(&fs::read(&token_path).expect("brokered token record"))
            .expect("token record JSON");
    assert_eq!(token_record["accessToken"], "fixture-access-secret");
    assert_eq!(token_record["refreshToken"], "fixture-refresh-secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(token_path)
                .expect("token record metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    server.join().expect("OAuth fixture server");
}

fn fixture_config() -> McpServerConfig {
    let definition = json!({
        "name": "add",
        "description": "Adds two integers",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "left": {"type": "integer"},
                "right": {"type": "integer"}
            },
            "required": ["left", "right"]
        }
    });
    let grant = McpToolGrant::new(definition, 5_000, 64 * 1024).expect("grant");
    let discovery = McpServerDiscovery {
        protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
        server_info: json!({"name": "fixture", "version": "1"}),
        tools: vec![McpToolInspection {
            definition: grant.definition().clone(),
            definition_digest: grant.definition_digest().to_owned(),
        }],
    };
    let executable_digest = "a".repeat(64);
    McpServerConfig::new(
        "fixture".to_owned(),
        format!("mcp-servers/{executable_digest}/server"),
        executable_digest,
        Vec::new(),
        discovery.toolset_digest().expect("toolset digest"),
        true,
        vec![grant],
    )
    .expect("server")
}

fn fixture_http_config() -> McpHttpServerConfig {
    let definition = json!({
        "name": "lookup",
        "description": "Returns one fixture value",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {"key": {"type": "string"}},
            "required": ["key"]
        }
    });
    let grant = McpToolGrant::new(definition, 5_000, 64 * 1024).expect("grant");
    let discovery = McpServerDiscovery {
        protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
        server_info: json!({"name": "remote", "version": "1"}),
        tools: vec![McpToolInspection {
            definition: grant.definition().clone(),
            definition_digest: grant.definition_digest().to_owned(),
        }],
    };
    McpHttpServerConfig::new(
        "remote".to_owned(),
        "http://127.0.0.1:9/mcp".to_owned(),
        McpHttpAuthentication::None,
        discovery.toolset_digest().expect("toolset digest"),
        true,
        vec![grant],
        Vec::new(),
        Vec::new(),
    )
    .expect("HTTP server")
}

fn spawn_http_fixture(definition: Value, discoveries: usize) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = thread::spawn(move || {
        for _ in 0..discoveries {
            let responses = [
                http_json_response(
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "cli-fixture", "version": "1"}
                        }
                    }),
                    Some(("MCP-Session-Id", "cli-session")),
                ),
                "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned(),
                http_json_response(
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 100,
                        "result": {"tools": [definition.clone()]}
                    }),
                    None,
                ),
                "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned(),
            ];
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept fixture request");
                read_http_request(&mut stream);
                stream
                    .write_all(response.as_bytes())
                    .expect("write fixture response");
            }
        }
    });
    (format!("http://{address}/mcp"), server)
}

fn spawn_http_catalog_fixture(
    resource: Value,
    prompt: Value,
    discoveries: usize,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP catalog fixture");
    let address = listener.local_addr().expect("catalog fixture address");
    let server = thread::spawn(move || {
        for _ in 0..discoveries {
            let responses = [
                http_json_response(
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "capabilities": {
                                "resources": {"subscribe": false},
                                "prompts": {}
                            },
                            "serverInfo": {"name": "cli-catalog-fixture", "version": "1"}
                        }
                    }),
                    Some(("MCP-Session-Id", "cli-catalog-session")),
                ),
                "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned(),
                http_json_response(
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 1_000,
                        "result": {"resources": [resource.clone()]}
                    }),
                    None,
                ),
                http_json_response(
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 2_000,
                        "result": {"resourceTemplates": []}
                    }),
                    None,
                ),
                http_json_response(
                    "200 OK",
                    &json!({
                        "jsonrpc": "2.0",
                        "id": 3_000,
                        "result": {"prompts": [prompt.clone()]}
                    }),
                    None,
                ),
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned(),
            ];
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept catalog fixture request");
                read_http_request(&mut stream);
                stream
                    .write_all(response.as_bytes())
                    .expect("write catalog fixture response");
            }
        }
    });
    (format!("http://{address}/mcp"), server)
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4_096];
    let header_end = loop {
        let count = stream.read(&mut buffer).expect("read fixture request");
        assert_ne!(count, 0);
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).expect("request headers");
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
        })
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let count = stream.read(&mut buffer).expect("read fixture body");
        assert_ne!(count, 0);
        bytes.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8(bytes).expect("fixture request UTF-8")
}

fn http_json_response(status: &str, value: &Value, extra_header: Option<(&str, &str)>) -> String {
    let body = value.to_string();
    let extra = extra_header
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .unwrap_or_default();
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn http_oauth_token_response(value: &Value) -> String {
    let body = value.to_string();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn command(home: &Path, arguments: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command.arg("--home").arg(home);
    if arguments.first().copied() != Some("mcp-http") {
        command.arg("config");
    }
    command
        .args(arguments)
        .output()
        .expect("run mealyctl configuration command")
}

fn read_config(home: &Path) -> Value {
    serde_json::from_slice(&fs::read(home.join("config.json")).expect("read config"))
        .expect("config JSON")
}

fn default_config() -> Value {
    json!({
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
        "provider": {"kind": "builtin_fixture"},
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
    })
}
