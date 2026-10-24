//! Runs the built `acf-agent` binary against a mock gateway.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::post;
use serde_json::{Value, json};

type Seen = Arc<Mutex<Vec<Value>>>;

async fn mock_gateway(reply: Value) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let app = Router::new()
        .route(
            "/v1/actions/execute",
            post(
                |State((seen, reply)): State<(Seen, Value)>, body: Bytes| async move {
                    seen.lock()
                        .unwrap()
                        .push(serde_json::from_slice(&body).unwrap());
                    reply.to_string()
                },
            ),
        )
        .with_state((Arc::clone(&seen), reply));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), seen)
}

async fn run(args: Vec<String>) -> (Option<i32>, String) {
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_acf-agent"))
            .args(args)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
    )
}

fn args(gateway: &str, extra: &[&str]) -> Vec<String> {
    let mut all = vec![
        "action",
        "execute",
        "--gateway",
        gateway,
        "--action",
        "example.profile.get",
        "--resource",
        "example-api:development",
    ];
    all.extend_from_slice(extra);
    all.into_iter().map(str::to_owned).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_a_semantic_request_and_prints_the_response() {
    let reply = json!({ "status": "completed", "requestId": "req-x", "result": { "status": 200, "body": { "user": "demo" } } });
    let (gateway, seen) = mock_gateway(reply.clone()).await;
    let (code, stdout) = run(args(
        &gateway,
        &["--param", "view=summary", "--param", "limit=5"],
    ))
    .await;
    assert_eq!(code, Some(0));
    assert_eq!(serde_json::from_str::<Value>(&stdout).unwrap(), reply);

    let [request] = seen.lock().unwrap().clone().try_into().unwrap();
    assert_eq!(request["action"], "example.profile.get");
    assert_eq!(request["resource"], "example-api:development");
    assert_eq!(request["taskId"], "dev-task");
    assert_eq!(
        request["parameters"],
        json!({ "view": "summary", "limit": 5 })
    );
    assert!(request["requestId"].as_str().unwrap().starts_with("req-"));
    let mut keys: Vec<&str> = request
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "action",
            "parameters",
            "requestId",
            "resource",
            "taskId",
            "timestamp"
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn denials_exit_with_status_two() {
    let (gateway, _) = mock_gateway(
        json!({ "status": "denied", "requestId": "req-x", "reason": "policy_denied" }),
    )
    .await;
    let (code, stdout) = run(args(&gateway, &[])).await;
    assert_eq!(code, Some(2));
    assert!(stdout.contains("policy_denied"));
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_errors_exit_with_status_one() {
    let (code, _) = run(args("http://127.0.0.1:9", &["--param", "no-equals-sign"])).await;
    assert_eq!(code, Some(1));
    let (code, _) = run(args("ftp://127.0.0.1", &[])).await;
    assert_eq!(code, Some(1));
}
