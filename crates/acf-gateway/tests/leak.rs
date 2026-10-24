//! Canary leak harness.
//!
//! Runs the real `acf-gateway` binary with a canary credential supplied
//! through its environment, drives every kind of request through it, and
//! scans every output surface for the canary:
//!
//! - HTTP response bodies and headers,
//! - the gateway's stdout and stderr,
//! - the audit log.
//!
//! The upstream deliberately echoes the credential, once into a field that is
//! not allowlisted and once into one that is. There is no metrics surface yet;
//! when one is added, it must be scanned here too.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CANARY: &str = "ACF-CANARY-leak-harness-7b3d9e";

/// Answers `/profile` normally and `/echo` with the credential in an
/// allowlisted field; both also echo it in a body field and a header that
/// are not allowlisted.
async fn echoing_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buffer).to_string();
                let target = head.split(' ').nth(1).unwrap_or_default().to_owned();
                let authorization = head
                    .split("\r\n")
                    .filter_map(|l| l.split_once(": "))
                    .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
                    .map(|(_, v)| v.to_owned())
                    .unwrap_or_default();
                let user = if target.starts_with("/echo") {
                    authorization.clone()
                } else {
                    "demo".to_owned()
                };
                let body = json!({ "user": user, "authenticated": true, "debug": authorization })
                    .to_string();
                let mut reply = String::new();
                let _ = write!(
                    reply,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Echo: {authorization}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    port
}

const BUNDLE: &str = r#"
schema: acf.config/v1
deployment: { profile: development, environment: development }
secret_providers:
  development: { type: in-memory }
profiles:
  - schema: acf.profile/v1
    connector: example-api
    revision: 1
    base_url: {ORIGIN}
    authentication: { strategy: bearer }
    actions:
      example.profile.get:
        method: GET
        path: /profile
        credential_slot: read
        classification: read
        params:
          view: { location: query, type: string }
        response: { fields: [user, authenticated] }
        audit: { record: [view] }
      example.echo.get:
        method: GET
        path: /echo
        credential_slot: read
        classification: read
        response: { fields: [user] }
      example.records.create:
        method: POST
        path: /records
        credential_slot: read
        classification: mutate
        params:
          name: { location: body, type: string, required: true }
        response: { fields: [id] }
resources:
  "example-api:development":
    connector: example-api
    environment: development
    credentials:
      read: secret://development/example-api/read
secrets:
  "secret://development/example-api/read":
    use_binding: { connectors: [example-api], origins: ["{ORIGIN}"], auth_slot: read, environment: development }
"#;

const POLICY: &str = r"
schema: acf.policy/v1
version: leak.1
rules:
  - id: dev-agent
    effect: allow
    principals: [dev-agent]
    actions: [example.profile.get, example.echo.get, example.records.create]
    resources: ['example-api:development']
";

fn scratch_dir() -> PathBuf {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).unwrap();
    let suffix: String = bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    let dir = std::env::temp_dir().join(format!("acf-leak-{suffix}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn action(name: &str, params: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "requestId": format!("req-{}", name.replace('.', "-")),
        "timestamp": "2026-10-24T18:00:00Z",
        "taskId": "leak-task",
        "action": name,
        "resource": "example-api:development",
        "parameters": params,
    }))
    .unwrap()
}

/// Starts the gateway binary with the canary in its environment and waits
/// until it answers. Returns the process, its base URL, and the audit log path.
async fn spawn_gateway(upstream: u16) -> (Child, String, PathBuf, PathBuf) {
    let dir = scratch_dir();
    let config = dir.join("config.yaml");
    let policy = dir.join("policy.yaml");
    let audit = dir.join("audit.jsonl");
    std::fs::write(
        &config,
        BUNDLE.replace("{ORIGIN}", &format!("http://127.0.0.1:{upstream}")),
    )
    .unwrap();
    std::fs::write(&policy, POLICY).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let gateway = Command::new(env!("CARGO_BIN_EXE_acf-gateway"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--policy", policy.to_str().unwrap()])
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .args(["--audit-log", audit.to_str().unwrap()])
        .args([
            "--secret-env",
            "secret://development/example-api/read=ACF_LEAK_CANARY",
        ])
        .env("ACF_LEAK_CANARY", CANARY)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..100 {
        if client.get(format!("{base}/healthz")).send().await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "gateway did not start");

    (gateway, base, audit, dir)
}

/// Sends every kind of request. Returns the concatenated response headers and
/// bodies, and `(name, expected, actual)` statuses.
async fn drive(base: &str) -> (String, Vec<(&'static str, u16, u16)>) {
    let client = reqwest::Client::new();
    let requests: Vec<(&str, Vec<u8>, u16)> = vec![
        (
            "allowed",
            action("example.profile.get", &json!({ "view": "full" })),
            200,
        ),
        ("reflected", action("example.echo.get", &json!({})), 502),
        (
            "unknown action",
            action("example.profile.delete", &json!({})),
            403,
        ),
        (
            "invalid parameters",
            action(
                "example.profile.get",
                &json!({ "url": "http://evil.example" }),
            ),
            403,
        ),
        (
            "approval required",
            action("example.records.create", &json!({ "name": "n" })),
            403,
        ),
        (
            "malformed",
            b"{\"requestId\": \"x\", \"secretRef\": \"secret://development/example-api/read\"}"
                .to_vec(),
            400,
        ),
    ];
    let mut surfaces = String::new();
    let mut statuses = Vec::new();
    for (name, body, expected) in requests {
        let response = client
            .post(format!("{base}/v1/actions/execute"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        statuses.push((name, expected, response.status().as_u16()));
        let _ = writeln!(surfaces, "[{name} headers] {:?}", response.headers());
        let _ = writeln!(surfaces, "[{name} body] {}", response.text().await.unwrap());
    }
    (surfaces, statuses)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_canary_never_reaches_any_output_surface() {
    let upstream = echoing_upstream().await;
    let (mut gateway, base, audit, dir) = spawn_gateway(upstream).await;
    let (surfaces, statuses) = drive(&base).await;

    gateway.kill().unwrap();
    let output = gateway.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let audit_log = std::fs::read_to_string(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    for (surface, text) in [
        ("HTTP responses", surfaces.as_str()),
        ("stdout", &stdout),
        ("stderr", &stderr),
        ("audit log", audit_log.as_str()),
    ] {
        assert!(
            !text.contains(CANARY),
            "canary leaked to {surface}:\n{text}"
        );
    }

    // Only after the leak scan: the harness must actually have exercised the
    // credential and the audit path, or the absence of the canary proves
    // nothing.
    for (name, expected, actual) in statuses {
        assert_eq!(actual, expected, "{name}");
    }
    assert!(surfaces.contains("\"authenticated\":true"), "{surfaces}");
    assert!(surfaces.contains("credential_reflected"), "{surfaces}");
    let events: Vec<Value> = audit_log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let verdicts: Vec<&str> = events
        .iter()
        .map(|e| e["verdict"].as_str().unwrap())
        .collect();
    assert_eq!(
        verdicts,
        [
            "allowed",
            "completed",
            "allowed",
            "failed",
            "denied",
            "denied",
            "denied"
        ]
    );
    assert!(events.iter().all(|e| e["principal"] == "dev-agent"));
}
