//! Client for the daemon local API over its Unix socket.

use std::path::Path;

use acf_protocol::{
    ActionResponse, CreateTaskRequest, LocalActionRequest, LocalError, TaskHandle, TaskId,
    TaskStatus,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request, header};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;

use crate::AgentError;
use crate::gateway::MAX_RESPONSE_BYTES;

async fn call(
    socket: &Path,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Bytes), AgentError> {
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|_| AgentError::DaemonUnreachable)?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| AgentError::DaemonUnreachable)?;
    tokio::spawn(connection);
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| AgentError::DaemonUnreachable)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| AgentError::DaemonUnreachable)?;
    let status = response.status().as_u16();
    let bytes = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|_| AgentError::UnexpectedResponse(status))?
        .to_bytes();
    Ok((status, bytes))
}

fn decode<T: DeserializeOwned>(status: u16, bytes: &[u8]) -> Result<T, AgentError> {
    if let Ok(value) = serde_json::from_slice(bytes) {
        return Ok(value);
    }
    match serde_json::from_slice::<LocalError>(bytes) {
        Ok(local) => Err(AgentError::Daemon(local.error)),
        Err(_) => Err(AgentError::UnexpectedResponse(status)),
    }
}

/// Opens an unscoped task; `pid` restricts the handle to that process.
///
/// # Errors
///
/// Returns [`AgentError`] if the daemon is unreachable or refuses.
pub async fn create_task(
    socket: &Path,
    task: &str,
    pid: Option<u32>,
) -> Result<TaskStatus, AgentError> {
    let request = CreateTaskRequest {
        task_id: TaskId::new(task)?,
        pid,
        basis: None,
        grants: Vec::new(),
        ttl_secs: None,
    };
    propose_task(socket, &request).await
}

/// Opens a task as described by `request`. With an authority behind the
/// daemon, the scope in `request` is a proposal the authority narrows.
///
/// # Errors
///
/// Returns [`AgentError`] if the daemon is unreachable or refuses.
pub async fn propose_task(
    socket: &Path,
    request: &CreateTaskRequest,
) -> Result<TaskStatus, AgentError> {
    let body = serde_json::to_vec(request).map_err(|_| AgentError::InvalidParam)?;
    let (status, bytes) = call(socket, Method::POST, "/v1/tasks", body).await?;
    decode(status, &bytes)
}

/// Looks up a task by handle.
///
/// # Errors
///
/// Returns [`AgentError`] if the daemon is unreachable or does not know the
/// handle for this caller.
pub async fn task_status(socket: &Path, handle: &TaskHandle) -> Result<TaskStatus, AgentError> {
    let (status, bytes) = call(
        socket,
        Method::GET,
        &format!("/v1/tasks/{handle}"),
        Vec::new(),
    )
    .await?;
    decode(status, &bytes)
}

/// Executes a semantic action through the daemon.
///
/// # Errors
///
/// Returns [`AgentError`] if the daemon is unreachable or refuses the call
/// itself. Gateway denials and failures are `Ok` action responses.
pub async fn execute(
    socket: &Path,
    request: &LocalActionRequest,
) -> Result<ActionResponse, AgentError> {
    let body = serde_json::to_vec(request).map_err(|_| AgentError::InvalidParam)?;
    let (status, bytes) = call(socket, Method::POST, "/v1/actions/execute", body).await?;
    decode(status, &bytes)
}
