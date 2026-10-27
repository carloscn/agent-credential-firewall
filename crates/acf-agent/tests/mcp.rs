//! The MCP adapter's protocol handling against a real daemon socket. The
//! gateway is unreachable here; `acf-e2e` runs the tools end to end.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../acf-gateway/tests/support/pki.rs"]
mod pki;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use acf_agent::daemon;
use acf_agent::gateway::{GatewayClient, client_config};
use acf_agent::mcp::{PROTOCOL_VERSIONS, serve};
use serde_json::{Value, json};

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Daemon {
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Daemon {
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "acf-mcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = pki::Pki::new("acf-test-ca");
        let client = ca.client("vps-17");
        let tls = client_config(
            client.certificate_pem.as_bytes(),
            client.key_pem.as_bytes(),
            ca.ca_pem().as_bytes(),
        )
        .unwrap();
        // Port 1 on loopback refuses connections.
        let gateway = GatewayClient::new("https://127.0.0.1:1", tls).unwrap();
        let socket = daemon::bind(&dir.join("acf.sock"), daemon::DEFAULT_SOCKET_MODE).unwrap();
        let allowed = BTreeSet::from([socket.owner()]);
        tokio::spawn(daemon::serve(
            socket,
            allowed,
            daemon::router(gateway, None),
        ));
        Self { dir }
    }

    /// Sends `messages` (one per line) and returns every response line.
    async fn session(&self, messages: &[Value]) -> Vec<Value> {
        let mut input = Vec::new();
        for message in messages {
            input.extend_from_slice(message.to_string().as_bytes());
            input.push(b'\n');
        }
        let mut output = Vec::new();
        serve(self.dir.join("acf.sock"), &input[..], &mut output)
            .await
            .unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    async fn call(&self, tool: &str, arguments: Value) -> Value {
        let responses = self
            .session(&[json!({
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": { "name": tool, "arguments": arguments }
            })])
            .await;
        responses[0]["result"].clone()
    }
}

#[tokio::test]
async fn initialize_negotiates_and_lists_three_tools() {
    let daemon = Daemon::start();
    let responses = daemon
        .session(&[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": { "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": { "name": "t", "version": "1" } } }),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            json!({ "jsonrpc": "2.0", "id": "two", "method": "tools/list" }),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "initialize", "params": { "protocolVersion": "1999-01-01" } }),
            json!({ "jsonrpc": "2.0", "id": 4, "method": "ping" }),
        ])
        .await;
    assert_eq!(responses.len(), 4, "the notification gets no response");
    assert_eq!(responses[0]["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(responses[0]["result"]["serverInfo"]["name"], "acf");
    assert!(responses[0]["result"]["capabilities"]["tools"].is_object());
    assert_eq!(responses[1]["id"], "two");
    let names: Vec<&str> = responses[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "acf_request_task",
            "acf_get_task_status",
            "acf_execute_action"
        ]
    );
    assert_eq!(
        responses[2]["result"]["protocolVersion"],
        PROTOCOL_VERSIONS[0]
    );
    assert_eq!(responses[3]["result"], json!({}));
}

#[tokio::test]
async fn protocol_errors_use_json_rpc_codes() {
    let daemon = Daemon::start();
    let mut input = b"not json\n".to_vec();
    for message in [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list" }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "acf_get_secret", "arguments": {} } }),
        json!([1, 2]),
    ] {
        input.extend_from_slice(message.to_string().as_bytes());
        input.push(b'\n');
    }
    let mut output = Vec::new();
    serve(daemon.dir.join("acf.sock"), &input[..], &mut output)
        .await
        .unwrap();
    let codes: Vec<i64> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["error"]["code"]
                .as_i64()
                .unwrap()
        })
        .collect();
    assert_eq!(codes, [-32700, -32601, -32602, -32600]);
}

#[tokio::test]
async fn tools_forward_to_the_daemon_and_report_refusals_as_tool_errors() {
    let daemon = Daemon::start();
    // This daemon has no authority, so only an unscoped task can be opened.
    let task = daemon
        .call("acf_request_task", json!({ "taskId": "t1" }))
        .await;
    assert_eq!(task["isError"], false, "{task}");
    let handle = task["structuredContent"]["taskHandle"]
        .as_str()
        .unwrap()
        .to_owned();

    let status = daemon
        .call("acf_get_task_status", json!({ "taskHandle": handle }))
        .await;
    assert_eq!(status["structuredContent"]["taskId"], "t1");

    let result = daemon
        .call(
            "acf_execute_action",
            json!({ "taskHandle": handle, "action": "example.profile.get",
                    "resource": "example-api:development", "parameters": { "view": "full" } }),
        )
        .await;
    assert_eq!(result["isError"], true);
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("gateway_unavailable"),
        "{result}"
    );

    // Arguments outside the schema, such as a capability, are refused.
    for (tool, arguments) in [
        (
            "acf_execute_action",
            json!({ "taskHandle": handle, "action": "a.b", "resource": "r", "capability": "eyJ" }),
        ),
        (
            "acf_request_task",
            json!({ "taskId": "t2", "job": "j", "scheduler": true }),
        ),
        ("acf_get_task_status", json!({})),
    ] {
        let result = daemon.call(tool, arguments).await;
        assert_eq!(result["isError"], true, "{tool}: {result}");
    }
    let unknown = daemon
        .call("acf_get_task_status", json!({ "taskHandle": "th-unknown" }))
        .await;
    assert!(
        unknown["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown_task")
    );
}
