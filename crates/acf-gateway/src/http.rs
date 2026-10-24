//! HTTP surface: `GET /healthz` and `POST /v1/actions/execute`.
//!
//! Request bodies are parsed by the handler, not by an extractor, so a
//! malformed request gets a fixed error body that never echoes its input.

use std::sync::Arc;
use std::time::Duration;

use acf_identity::ConnectionInfo;
use acf_protocol::{ActionRequest, ActionResponse, DenialReason, FailureReason};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::pipeline::Gateway;

/// HTTP-level limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerLimits {
    /// Largest accepted request body.
    pub max_body_bytes: usize,
    /// Whole-request time limit, including the downstream call.
    pub request_timeout: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
            request_timeout: Duration::from_secs(60),
        }
    }
}

#[derive(Clone)]
struct AppState {
    gateway: Arc<Gateway>,
    limits: ServerLimits,
}

/// Builds the router.
pub fn router(gateway: Arc<Gateway>, limits: ServerLimits) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/actions/execute", post(execute))
        .layer(DefaultBodyLimit::max(limits.max_body_bytes))
        .with_state(AppState { gateway, limits })
}

fn json_response(status: StatusCode, body: &impl serde::Serialize) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn healthz() -> Response {
    json_response(StatusCode::OK, &serde_json::json!({ "status": "ok" }))
}

async fn execute(State(state): State<AppState>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<ActionRequest>(&body) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": "invalid_request" }),
        );
    };
    let request_id = request.request_id.clone();
    // M0 listens on plaintext loopback; TLS client identity arrives with WP-08.
    let connection = ConnectionInfo::default();
    let response = tokio::time::timeout(
        state.limits.request_timeout,
        state.gateway.execute(&connection, request),
    )
    .await
    .unwrap_or(ActionResponse::Failed {
        request_id,
        reason: FailureReason::GatewayTimeout,
    });
    json_response(status_for(&response), &response)
}

fn status_for(response: &ActionResponse) -> StatusCode {
    match response {
        ActionResponse::Completed { .. } | ActionResponse::ApprovalRequired { .. } => {
            StatusCode::OK
        }
        ActionResponse::Denied {
            reason: DenialReason::Unauthenticated,
            ..
        } => StatusCode::UNAUTHORIZED,
        ActionResponse::Denied { .. } => StatusCode::FORBIDDEN,
        ActionResponse::Failed {
            reason: FailureReason::DownstreamTimeout | FailureReason::GatewayTimeout,
            ..
        } => StatusCode::GATEWAY_TIMEOUT,
        ActionResponse::Failed { .. } => StatusCode::BAD_GATEWAY,
    }
}
