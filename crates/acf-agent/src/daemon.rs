//! The local daemon: a permissioned Unix socket in front of the mTLS gateway
//! connection (design §7.3, ADR 0002).
//!
//! Every connection's UID, GID, and PID come from the kernel
//! (`SO_PEERCRED`). They prove operating-system provenance, not intent: any
//! process running as a permitted UID can use that UID's handles, and
//! commands an authorized agent runs stay within that agent's authority.
//! Task scope, policy, constraints, and approvals bound what they can do.

use std::collections::BTreeSet;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use acf_protocol::{
    ActionRequest, CreateTaskRequest, LocalActionRequest, LocalError, LocalErrorCode, TaskHandle,
    TaskProposal,
};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as UrlPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use serde::Serialize;
use time::OffsetDateTime;
use tokio::net::UnixListener;

use crate::gateway::{AuthorityClient, GatewayClient};
use crate::new_request_id;
use crate::tasks::{Peer, TaskError, TaskRegistry};

/// Default socket mode: owner and group may connect.
pub const DEFAULT_SOCKET_MODE: u32 = 0o660;

/// Largest local request body.
pub const MAX_LOCAL_BODY_BYTES: usize = 64 * 1024;

/// Most local connections served at once.
pub const MAX_LOCAL_CONNECTIONS: usize = 256;

/// Why the daemon could not start.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// Another daemon answers on the socket path.
    #[error("another daemon is listening on {0}")]
    AlreadyRunning(String),
    /// Something other than a socket exists at the path.
    #[error("{0} exists and is not a socket")]
    NotASocket(String),
    /// The socket mode grants access to others.
    #[error("socket mode {0:o} must not grant access to others")]
    SocketMode(u32),
    /// Binding or setting permissions failed.
    #[error("cannot create socket {0}: {1}")]
    Bind(String, std::io::Error),
}

/// A bound, permissioned socket, ready to serve.
#[derive(Debug)]
pub struct BoundSocket {
    listener: UnixListener,
    path: PathBuf,
    owner: u32,
}

impl BoundSocket {
    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// UID that owns the socket: the daemon's effective UID.
    #[must_use]
    pub fn owner(&self) -> u32 {
        self.owner
    }
}

/// Creates the socket at `path` with `mode`. A stale socket left by a dead
/// daemon is replaced; a live one, or any other file, is an error.
///
/// Create the socket in a directory only the daemon can write to: the mode
/// is applied right after `bind`, and the directory closes that window.
///
/// # Errors
///
/// Returns [`DaemonError`] as described above.
pub fn bind(path: &Path, mode: u32) -> Result<BoundSocket, DaemonError> {
    let name = path.display().to_string();
    if mode & !0o777 != 0 || mode & 0o007 != 0 {
        return Err(DaemonError::SocketMode(mode));
    }
    if let Ok(existing) = std::fs::symlink_metadata(path) {
        if !existing.file_type().is_socket() {
            return Err(DaemonError::NotASocket(name));
        }
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(DaemonError::AlreadyRunning(name));
        }
        std::fs::remove_file(path).map_err(|e| DaemonError::Bind(name.clone(), e))?;
    }
    let listener = UnixListener::bind(path).map_err(|e| DaemonError::Bind(name.clone(), e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| DaemonError::Bind(name.clone(), e))?;
    let owner = std::fs::metadata(path)
        .map_err(|e| DaemonError::Bind(name, e))?
        .uid();
    Ok(BoundSocket {
        listener,
        path: path.to_owned(),
        owner,
    })
}

struct AppState {
    tasks: TaskRegistry,
    gateway: GatewayClient,
    authority: Option<AuthorityClient>,
}

fn json(status: StatusCode, body: &impl Serialize) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn error(status: StatusCode, code: LocalErrorCode) -> Response {
    json(status, &LocalError { error: code })
}

async fn create_task(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<Peer>,
    body: Bytes,
) -> Response {
    let Ok(request) = serde_json::from_slice::<CreateTaskRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, LocalErrorCode::InvalidRequest);
    };
    // With an authority, the scope is a proposal it must sign. Without one,
    // a scope cannot be honored, so asking for one is refused rather than
    // silently ignored.
    let issued = match (&state.authority, request.basis) {
        (Some(authority), Some(basis)) => {
            let proposal = TaskProposal {
                task_id: request.task_id.clone(),
                basis,
                grants: request.grants,
                ttl_secs: request.ttl_secs,
            };
            match authority.propose(&proposal).await {
                Ok(Ok(issued)) if issued.task_id == request.task_id => Some(issued),
                Ok(Ok(_)) | Err(_) => {
                    return error(
                        StatusCode::BAD_GATEWAY,
                        LocalErrorCode::AuthorityUnavailable,
                    );
                }
                Ok(Err(_)) => return error(StatusCode::FORBIDDEN, LocalErrorCode::TaskDenied),
            }
        }
        (None, None) if request.grants.is_empty() && request.ttl_secs.is_none() => None,
        _ => return error(StatusCode::BAD_REQUEST, LocalErrorCode::InvalidRequest),
    };
    match state
        .tasks
        .create(peer, request.task_id, request.pid, issued)
    {
        Ok(status) => json(StatusCode::CREATED, &status),
        Err(TaskError::TooMany) => {
            error(StatusCode::TOO_MANY_REQUESTS, LocalErrorCode::TooManyTasks)
        }
        Err(TaskError::Random) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn task_status(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<Peer>,
    UrlPath(handle): UrlPath<String>,
) -> Response {
    TaskHandle::new(handle)
        .ok()
        .and_then(|handle| state.tasks.get(peer, &handle))
        .map_or_else(
            || error(StatusCode::NOT_FOUND, LocalErrorCode::UnknownTask),
            |status| json(StatusCode::OK, &status),
        )
}

async fn execute(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<Peer>,
    body: Bytes,
) -> Response {
    let Ok(local) = serde_json::from_slice::<LocalActionRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, LocalErrorCode::InvalidRequest);
    };
    let Some(task) = state.tasks.resolve(peer, &local.task_handle) else {
        return error(StatusCode::NOT_FOUND, LocalErrorCode::UnknownTask);
    };
    let Ok(request_id) = new_request_id() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let request = ActionRequest {
        request_id,
        timestamp: OffsetDateTime::now_utc(),
        task_id: task.task_id.clone(),
        action: local.action,
        resource: local.resource,
        parameters: local.parameters,
        idempotency_key: local.idempotency_key,
        approval_id: local.approval_id,
    };
    match state.gateway.execute(&request, task.capability()).await {
        // Re-serialized from the typed model: nothing outside it reaches
        // the agent.
        Ok((status, response)) => json(
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            &response,
        ),
        Err(_) => error(StatusCode::BAD_GATEWAY, LocalErrorCode::GatewayUnavailable),
    }
}

/// The local API. With an `authority`, every task must be authorized by it
/// and requests carry the resulting capability.
pub fn router(gateway: GatewayClient, authority: Option<AuthorityClient>) -> Router {
    Router::new()
        .route("/v1/tasks", post(create_task))
        .route("/v1/tasks/{handle}", get(task_status))
        .route("/v1/actions/execute", post(execute))
        .layer(DefaultBodyLimit::max(MAX_LOCAL_BODY_BYTES))
        .with_state(Arc::new(AppState {
            tasks: TaskRegistry::default(),
            gateway,
            authority,
        }))
}

/// Serves `router` on `socket`. Connections from UIDs outside `allowed` are
/// closed before any HTTP is read; at most [`MAX_LOCAL_CONNECTIONS`] are
/// served at once, and a client that stops sending headers is disconnected
/// after [`acf_identity::HEADER_READ_TIMEOUT`].
pub async fn serve(socket: BoundSocket, allowed: BTreeSet<u32>, router: Router) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_LOCAL_CONNECTIONS));
    loop {
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        let Ok((stream, _)) = socket.listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(credentials) = stream.peer_cred() else {
            continue;
        };
        if !allowed.contains(&credentials.uid()) {
            continue;
        }
        let peer = Peer {
            uid: credentials.uid(),
            gid: credentials.gid(),
            pid: credentials.pid().and_then(|pid| u32::try_from(pid).ok()),
        };
        let service = TowerToHyperService::new(router.clone().layer(Extension(peer)));
        tokio::spawn(async move {
            let _ = acf_identity::http1()
                .serve_connection(TokioIo::new(stream), service)
                .await;
            drop(slot);
        });
    }
}
