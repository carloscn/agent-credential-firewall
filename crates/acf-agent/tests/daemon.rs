//! The daemon's socket, peer-credential checks, and task handles. The
//! gateway is unreachable here; `acf-gateway`'s `tls` tests run the daemon
//! against a real mTLS gateway.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../acf-gateway/tests/support/pki.rs"]
mod pki;

use std::collections::BTreeSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use acf_agent::daemon::{self, DaemonError};
use acf_agent::gateway::{GatewayClient, client_config};
use acf_agent::{AgentError, build_local_request, local};
use acf_protocol::{LocalErrorCode, TaskHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

static NEXT: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "acf-daemon-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("acf.sock")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn unreachable_gateway() -> GatewayClient {
    let ca = pki::Pki::new("acf-test-ca");
    let client = ca.client("vps-17");
    let tls = client_config(
        client.certificate_pem.as_bytes(),
        client.key_pem.as_bytes(),
        ca.ca_pem().as_bytes(),
    )
    .unwrap();
    // Port 1 on loopback refuses connections.
    GatewayClient::new("https://127.0.0.1:1", tls).unwrap()
}

/// Starts a daemon; `allowed` defaults to the socket owner.
fn start(dir: &TempDir, allowed: Option<BTreeSet<u32>>) -> PathBuf {
    let socket = daemon::bind(&dir.socket(), daemon::DEFAULT_SOCKET_MODE).unwrap();
    let allowed = allowed.unwrap_or_else(|| BTreeSet::from([socket.owner()]));
    let path = socket.path().to_owned();
    tokio::spawn(daemon::serve(
        socket,
        allowed,
        daemon::router(unreachable_gateway(), None),
    ));
    path
}

async fn raw(socket: &Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn the_socket_is_created_with_the_requested_mode() {
    let dir = TempDir::new();
    let socket = daemon::bind(&dir.socket(), 0o660).unwrap();
    let metadata = std::fs::metadata(socket.path()).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    assert_eq!(socket.owner(), metadata.uid());
    drop(socket);

    for mode in [0o666, 0o661, 0o1660] {
        assert!(matches!(
            daemon::bind(&dir.0.join("other.sock"), mode),
            Err(DaemonError::SocketMode(_))
        ));
    }
}

#[tokio::test]
async fn stale_sockets_are_replaced_but_live_ones_and_files_are_not() {
    let dir = TempDir::new();
    // A socket nobody listens on any more.
    drop(daemon::bind(&dir.socket(), 0o600).unwrap());
    assert!(dir.socket().exists());
    let live = daemon::bind(&dir.socket(), 0o600).unwrap();
    assert!(matches!(
        daemon::bind(&dir.socket(), 0o600),
        Err(DaemonError::AlreadyRunning(_))
    ));
    drop(live);

    let file = dir.0.join("not-a-socket");
    std::fs::write(&file, b"keep me").unwrap();
    assert!(matches!(
        daemon::bind(&file, 0o600),
        Err(DaemonError::NotASocket(_))
    ));
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
}

#[tokio::test]
async fn tasks_open_and_resolve_for_their_owner() {
    let dir = TempDir::new();
    let socket = start(&dir, None);
    let status = local::create_task(&socket, "task-1", None).await.unwrap();
    assert_eq!(status.task_id.as_str(), "task-1");
    assert_eq!(
        local::task_status(&socket, &status.task_handle)
            .await
            .unwrap(),
        status
    );
    let unknown = TaskHandle::new("th-unknown").unwrap();
    assert!(matches!(
        local::task_status(&socket, &unknown).await,
        Err(AgentError::Daemon(LocalErrorCode::UnknownTask))
    ));
}

#[tokio::test]
async fn pid_bound_handles_are_unknown_to_other_processes() {
    let dir = TempDir::new();
    let socket = start(&dir, None);
    // PID 1 is never this test process.
    let status = local::create_task(&socket, "task-1", Some(1))
        .await
        .unwrap();
    assert!(matches!(
        local::task_status(&socket, &status.task_handle).await,
        Err(AgentError::Daemon(LocalErrorCode::UnknownTask))
    ));
    let request = build_local_request(
        "example.profile.get",
        "example-api:development",
        status.task_handle.as_str(),
        &[],
    )
    .unwrap();
    assert!(matches!(
        local::execute(&socket, &request).await,
        Err(AgentError::Daemon(LocalErrorCode::UnknownTask))
    ));

    let mine = local::create_task(&socket, "task-2", Some(std::process::id()))
        .await
        .unwrap();
    assert!(local::task_status(&socket, &mine.task_handle).await.is_ok());
}

#[tokio::test]
async fn connections_from_other_uids_are_closed() {
    let dir = TempDir::new();
    let socket = start(&dir, Some(BTreeSet::from([u32::MAX - 1])));
    assert!(matches!(
        local::create_task(&socket, "task-1", None).await,
        Err(AgentError::DaemonUnreachable)
    ));
}

#[tokio::test]
async fn malformed_and_daemon_owned_fields_are_rejected() {
    let dir = TempDir::new();
    let socket = start(&dir, None);
    let status = local::create_task(&socket, "task-1", None).await.unwrap();
    for body in [
        "{}".to_owned(),
        format!(
            r#"{{"taskHandle":"{}","action":"example.profile.get","resource":"r","requestId":"req-chosen"}}"#,
            status.task_handle
        ),
        format!(
            r#"{{"taskHandle":"{}","action":"example.profile.get","resource":"r","taskId":"someone-elses"}}"#,
            status.task_handle
        ),
    ] {
        let response = raw(
            &socket,
            &format!(
                "POST /v1/actions/execute HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(
            response.ends_with(r#"{"error":"invalid_request"}"#),
            "{response}"
        );
    }
}

#[tokio::test]
async fn an_unreachable_gateway_is_reported_without_detail() {
    let dir = TempDir::new();
    let socket = start(&dir, None);
    let status = local::create_task(&socket, "task-1", None).await.unwrap();
    let request = build_local_request(
        "example.profile.get",
        "example-api:development",
        status.task_handle.as_str(),
        &[],
    )
    .unwrap();
    assert!(matches!(
        local::execute(&socket, &request).await,
        Err(AgentError::Daemon(LocalErrorCode::GatewayUnavailable))
    ));
}

#[tokio::test]
async fn a_client_that_never_sends_headers_is_disconnected() {
    let dir = TempDir::new();
    let socket = start(&dir, None);
    let mut idle = UnixStream::connect(&socket).await.unwrap();
    let started = std::time::Instant::now();
    let mut buffer = [0u8; 64];
    let read = tokio::time::timeout(
        acf_identity::HEADER_READ_TIMEOUT + std::time::Duration::from_secs(5),
        idle.read(&mut buffer),
    )
    .await
    .expect("the daemon must close an idle connection");
    assert_eq!(read.unwrap(), 0, "closed without a response");
    assert!(
        started.elapsed() + std::time::Duration::from_secs(1) >= acf_identity::HEADER_READ_TIMEOUT
    );
    // The daemon still serves others.
    assert!(local::create_task(&socket, "after", None).await.is_ok());
}
