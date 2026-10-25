//! Endpoint and VPS daemon and its CLI.
//!
//! - [`daemon`]: the local daemon. It serves agents on a permissioned Unix
//!   socket and forwards their semantic requests to the gateway over mTLS
//!   (ADR 0002).
//! - [`local`]: the client side of that socket, used by the CLI.
//! - [`send`]: the Milestone 0 development path straight to a plaintext
//!   loopback gateway.
//!
//! An agent can name only an action, a resource, a task, and parameter
//! values; no request model has a field for a URL, method, header, or
//! secret.

pub mod daemon;
pub mod gateway;
pub mod local;
pub mod tasks;

use std::fmt::Write as _;

use acf_protocol::{
    ActionName, ActionRequest, ActionResponse, ConstraintSet, Grant, IdError, LocalActionRequest,
    LocalErrorCode, RequestId, ResourceId, TaskHandle, TaskId,
};
use serde_json::{Map, Value};
use time::OffsetDateTime;

/// CLI and transport failures. Never include response bodies.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// An identifier argument is malformed.
    #[error("invalid {0}")]
    InvalidId(#[from] IdError),
    /// A `--param` argument is not `key=value`.
    #[error("parameters must be KEY=VALUE")]
    InvalidParam,
    /// A `--grant` argument is not `ACTION@RESOURCE`.
    #[error("grants must be ACTION@RESOURCE")]
    InvalidGrant,
    /// A parameter name appears twice.
    #[error("parameter `{0}` given more than once")]
    DuplicateParam(String),
    /// The gateway URL is malformed or not http(s).
    #[error("gateway URL must be an http(s) URL")]
    InvalidGateway,
    /// No random source for request identifiers.
    #[error("no secure random source available")]
    Random,
    /// The gateway could not be reached.
    #[error("gateway unreachable")]
    Transport,
    /// The gateway or daemon answered with something unexpected.
    #[error("unexpected response (HTTP {0})")]
    UnexpectedResponse(u16),
    /// The daemon socket could not be reached.
    #[error("daemon unreachable")]
    DaemonUnreachable,
    /// The daemon refused the call.
    #[error("daemon refused the call: {}", code_name(*.0))]
    Daemon(LocalErrorCode),
}

fn code_name(code: LocalErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Parses `key=value`. The value is JSON if it parses as JSON, otherwise a
/// string: `ttl=300` is the integer 300 and `name=api` is the string `"api"`.
///
/// # Errors
///
/// Returns [`AgentError::InvalidParam`] if there is no `=` or the key is empty.
pub fn parse_param(argument: &str) -> Result<(String, Value), AgentError> {
    let (key, raw) = argument.split_once('=').ok_or(AgentError::InvalidParam)?;
    if key.is_empty() {
        return Err(AgentError::InvalidParam);
    }
    let value = serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()));
    Ok((key.to_owned(), value))
}

/// Parses `ACTION@RESOURCE` into a grant without constraints.
///
/// # Errors
///
/// Returns [`AgentError::InvalidGrant`] if there is no `@`, or
/// [`AgentError::InvalidId`] for a malformed action or resource.
pub fn parse_grant(argument: &str) -> Result<Grant, AgentError> {
    let (action, resource) = argument.split_once('@').ok_or(AgentError::InvalidGrant)?;
    Ok(Grant {
        action: ActionName::new(action)?,
        resource: ResourceId::new(resource)?,
        constraints: ConstraintSet::default(),
    })
}

/// A fresh, unpredictable request identifier.
///
/// # Errors
///
/// Returns [`AgentError::Random`] if the OS random source fails.
pub fn new_request_id() -> Result<RequestId, AgentError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| AgentError::Random)?;
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(RequestId::new(format!("req-{hex}"))?)
}

fn parse_params(params: &[String]) -> Result<Map<String, Value>, AgentError> {
    let mut parameters = Map::new();
    for argument in params {
        let (key, value) = parse_param(argument)?;
        if parameters.insert(key.clone(), value).is_some() {
            return Err(AgentError::DuplicateParam(key));
        }
    }
    Ok(parameters)
}

/// Builds a semantic action request for the daemon.
///
/// # Errors
///
/// Returns [`AgentError`] for malformed identifiers or parameters.
pub fn build_local_request(
    action: &str,
    resource: &str,
    task_handle: &str,
    params: &[String],
) -> Result<LocalActionRequest, AgentError> {
    Ok(LocalActionRequest {
        task_handle: TaskHandle::new(task_handle)?,
        action: ActionName::new(action)?,
        resource: ResourceId::new(resource)?,
        parameters: parse_params(params)?,
        idempotency_key: None,
        approval_id: None,
    })
}

/// Builds a semantic action request for a development gateway.
///
/// # Errors
///
/// Returns [`AgentError`] for malformed identifiers, parameters, or randomness.
pub fn build_request(
    action: &str,
    resource: &str,
    task: &str,
    params: &[String],
) -> Result<ActionRequest, AgentError> {
    let parameters = parse_params(params)?;
    Ok(ActionRequest {
        request_id: new_request_id()?,
        timestamp: OffsetDateTime::now_utc(),
        task_id: TaskId::new(task)?,
        action: ActionName::new(action)?,
        resource: ResourceId::new(resource)?,
        parameters,
        idempotency_key: None,
        approval_id: None,
    })
}

/// Sends `request` to `gateway` (for example `http://127.0.0.1:8443`).
///
/// # Errors
///
/// Returns [`AgentError`] if the gateway is unreachable or does not answer
/// with an action response.
pub async fn send(gateway: &str, request: &ActionRequest) -> Result<ActionResponse, AgentError> {
    let base = reqwest::Url::parse(gateway).map_err(|_| AgentError::InvalidGateway)?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(AgentError::InvalidGateway);
    }
    let url = base
        .join("/v1/actions/execute")
        .map_err(|_| AgentError::InvalidGateway)?;
    let body = serde_json::to_vec(request).map_err(|_| AgentError::InvalidParam)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .map_err(|_| AgentError::Transport)?;
    let response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| AgentError::Transport)?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await.map_err(|_| AgentError::Transport)?;
    serde_json::from_slice(&bytes).map_err(|_| AgentError::UnexpectedResponse(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn params_are_json_or_strings() {
        assert_eq!(
            parse_param("ttl=300").unwrap(),
            ("ttl".to_owned(), json!(300))
        );
        assert_eq!(
            parse_param("proxied=true").unwrap(),
            ("proxied".to_owned(), json!(true))
        );
        assert_eq!(
            parse_param("name=api.example.com").unwrap(),
            ("name".to_owned(), json!("api.example.com"))
        );
        assert_eq!(
            parse_param("note=a=b").unwrap(),
            ("note".to_owned(), json!("a=b"))
        );
        assert!(parse_param("novalue").is_err());
        assert!(parse_param("=x").is_err());
    }

    #[test]
    fn request_ids_are_unique_and_valid() {
        let a = new_request_id().unwrap();
        let b = new_request_id().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 36);
    }

    #[test]
    fn requests_carry_only_semantic_fields() {
        let request = build_request(
            "example.profile.get",
            "example-api:development",
            "dev-task",
            &["view=full".to_owned()],
        )
        .unwrap();
        let value = serde_json::to_value(&request).unwrap();
        let mut keys: Vec<&str> = value
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
        assert!(build_request("x.y", "r", "t", &["a=1".to_owned(), "a=2".to_owned()]).is_err());
    }
}
