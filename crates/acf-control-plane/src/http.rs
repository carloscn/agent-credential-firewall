//! Authority HTTP surface: `POST /v1/tasks` over mTLS.

use std::sync::Arc;

use acf_identity::{ConnectionInfo, IdentityContextProvider};
use acf_protocol::{AuthorityError, AuthorityErrorCode, TaskProposal};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;

use crate::authority::Authority;

/// Largest accepted proposal.
pub const MAX_PROPOSAL_BYTES: usize = 64 * 1024;

struct AppState {
    authority: Authority,
    identity: Arc<dyn IdentityContextProvider>,
}

fn json_response(status: StatusCode, body: &impl Serialize) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn refuse(code: AuthorityErrorCode) -> Response {
    let status = match code {
        AuthorityErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
        AuthorityErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
        AuthorityErrorCode::BasisRejected | AuthorityErrorCode::ScopeEmpty => StatusCode::FORBIDDEN,
        AuthorityErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    };
    json_response(status, &AuthorityError { error: code })
}

/// One JSON line per decision on stderr. Never includes the token.
#[expect(clippy::print_stderr, reason = "authority decision log")]
fn log(event: &serde_json::Value) {
    eprintln!("{event}");
}

async fn propose(
    State(state): State<Arc<AppState>>,
    connection: Option<Extension<ConnectionInfo>>,
    body: Bytes,
) -> Response {
    // Set by the TLS listener only; never derived from headers.
    let connection = connection.map(|Extension(c)| c).unwrap_or_default();
    let Ok(caller) = state.identity.resolve(&connection).await else {
        log(&json!({ "event": "task_denied", "reason": "unauthenticated" }));
        return refuse(AuthorityErrorCode::Unauthenticated);
    };
    let Ok(proposal) = serde_json::from_slice::<TaskProposal>(&body) else {
        return refuse(AuthorityErrorCode::InvalidRequest);
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    match state.authority.issue(&caller, &proposal, now) {
        Ok(issuance) => {
            log(&json!({
                "event": "capability_issued",
                "jti": issuance.jti,
                "sub": caller.principal,
                "device": caller.device,
                "task": proposal.task_id,
                "basis": proposal.basis,
                "grants": issuance.issued.grants.iter()
                    .map(|g| format!("{} {}", g.action, g.resource))
                    .collect::<Vec<_>>(),
                "exp": issuance.issued.expires_at.unix_timestamp(),
            }));
            json_response(StatusCode::CREATED, &issuance.issued)
        }
        Err(code) => {
            log(&json!({
                "event": "task_denied",
                "sub": caller.principal,
                "task": proposal.task_id,
                "reason": code,
            }));
            refuse(code)
        }
    }
}

async fn healthz() -> Response {
    json_response(StatusCode::OK, &json!({ "status": "ok" }))
}

/// Builds the router.
pub fn router(authority: Authority, identity: Arc<dyn IdentityContextProvider>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/tasks", post(propose))
        .layer(DefaultBodyLimit::max(MAX_PROPOSAL_BYTES))
        .with_state(Arc::new(AppState {
            authority,
            identity,
        }))
}
