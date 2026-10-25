//! Daemon local API models (design §18, ADR 0002).
//!
//! Agents talk to the daemon over a Unix socket. They name a task handle,
//! never a task capability, request identifier, or timestamp: the daemon
//! fills those in before forwarding to the gateway.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::ids::{ActionName, ApprovalId, IdempotencyKey, ResourceId, TaskHandle, TaskId};

/// `POST /v1/tasks`: opens a task and returns its handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateTaskRequest {
    /// Task identifier the agent proposes.
    pub task_id: TaskId,
    /// Restricts the handle to this process, for a launcher that registers
    /// the agent it is about to run. Hygiene, not process authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// Lifecycle of a task as the daemon sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    /// The handle can be used.
    Active,
}

/// Answer to `POST /v1/tasks` and `GET /v1/tasks/{handle}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskStatus {
    /// Opaque handle for later calls.
    pub task_handle: TaskHandle,
    /// Task the handle stands for.
    pub task_id: TaskId,
    /// Current state.
    pub state: TaskState,
}

/// `POST /v1/actions/execute` on the daemon. Like
/// [`ActionRequest`](crate::ActionRequest) without the fields the daemon owns.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalActionRequest {
    /// Handle from `POST /v1/tasks`.
    pub task_handle: TaskHandle,
    /// Semantic action.
    pub action: ActionName,
    /// Registered resource.
    pub resource: ResourceId,
    /// Parameters, validated by the gateway against the action contract.
    #[serde(default)]
    pub parameters: Map<String, Value>,
    /// Required for mutations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<IdempotencyKey>,
    /// Present when resubmitting an approved mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
}

/// Why the daemon itself refused a local call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalErrorCode {
    /// Malformed body or path.
    InvalidRequest,
    /// No such handle for this caller. Foreign handles look the same.
    UnknownTask,
    /// The caller holds too many open tasks.
    TooManyTasks,
    /// The gateway could not be reached or answered unexpectedly.
    GatewayUnavailable,
}

/// Error body returned by the daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalError {
    /// Error code.
    pub error: LocalErrorCode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn local_requests_cannot_carry_daemon_owned_fields() {
        for field in ["requestId", "timestamp", "taskId", "capability"] {
            let mut body = json!({
                "taskHandle": "th-1",
                "action": "example.profile.get",
                "resource": "example-api:development",
            });
            body[field] = json!("x");
            assert!(
                serde_json::from_value::<LocalActionRequest>(body).is_err(),
                "{field} must be rejected"
            );
        }
    }
}
