//! HTTP surface: `GET /healthz` and `POST /v1/actions/execute`.
//!
//! A task capability arrives in the `ACF-Capability` header (ADR 0003).
//!
//! Request bodies are parsed by the handler, not by an extractor, so a
//! malformed request gets a fixed error body that never echoes its input.

use std::sync::Arc;
use std::time::Duration;

use acf_identity::ConnectionInfo;
use acf_protocol::{
    ActionRequest, ActionResponse, CAPABILITY_HEADER, DenialReason, FailureReason,
    MAX_CAPABILITY_BYTES,
};
use axum::Extension;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
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

async fn execute(
    State(state): State<AppState>,
    connection: Option<Extension<ConnectionInfo>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let invalid = || {
        json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": "invalid_request" }),
        )
    };
    let Ok(request) = serde_json::from_slice::<ActionRequest>(&body) else {
        return invalid();
    };
    let mut presented = headers.get_all(CAPABILITY_HEADER).iter();
    let capability = match (presented.next(), presented.next()) {
        (None, _) => None,
        (Some(value), None) if value.len() <= MAX_CAPABILITY_BYTES => match value.to_str() {
            Ok(token) => Some(token.to_owned()),
            Err(_) => return invalid(),
        },
        _ => return invalid(),
    };
    let request_id = request.request_id.clone();
    // Set by the TLS listener from the verified client certificate; absent
    // on the plaintext development listener. Never derived from headers.
    let connection = connection.map(|Extension(c)| c).unwrap_or_default();
    let response = tokio::time::timeout(
        state.limits.request_timeout,
        state
            .gateway
            .execute_with_capability(&connection, capability.as_deref(), request),
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
