//! Read-only MCP adapter over the daemon local API (WP-18, design §7.1).
//!
//! `acf-agent mcp` speaks the Model Context Protocol (JSON-RPC 2.0, one
//! message per line on stdin and stdout) and forwards three tools to the
//! daemon socket:
//!
//! - `acf_request_task` proposes a task and returns its opaque handle.
//! - `acf_get_task_status` shows a task's grants, limits, and expiry.
//! - `acf_execute_action` runs one semantic action through a handle.
//!
//! The adapter is a workflow layer, not an authorization boundary. It holds
//! no key, capability, or credential, and returns only what the local API
//! returns. Gateway denials, including the refusal of every mutation in
//! v1.0, come back unchanged as tool errors. Tasks it opens are bound to its
//! own process, so other local processes cannot use their handles.

use std::path::{Path, PathBuf};

use acf_protocol::{
    ActionName, ActionResponse, BasisRequest, CreateTaskRequest, Grant, JobId, LocalActionRequest,
    ResourceId, TaskHandle, TaskId,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::{AgentError, local};

/// MCP protocol revisions this adapter speaks, newest first.
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Version of the tool schemas; follows the daemon local API (`/v1`).
pub const TOOLS_VERSION: &str = "v1";

const INSTRUCTIONS: &str = "ACF runs semantic actions on registered resources without ever giving you a credential. \
First call acf_request_task with a job (or as a scheduler) to get a task handle, then acf_execute_action with that handle. \
This version is read-only: mutations are refused. Never ask for tokens, keys, or secrets; ACF will not return them.";

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// Serves MCP on `input`/`output` until `input` ends, forwarding tool calls
/// to the daemon at `socket`.
///
/// # Errors
///
/// Returns an I/O error if reading or writing the transport fails.
pub async fn serve<R, W>(socket: PathBuf, input: R, mut output: W) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = input.lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = handle(&socket, &line).await {
            let mut bytes = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
            bytes.push(b'\n');
            output.write_all(&bytes).await?;
            output.flush().await?;
        }
    }
    Ok(())
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Handles one message; `None` for notifications and client responses.
async fn handle(socket: &Path, line: &str) -> Option<Value> {
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return Some(rpc_error(&Value::Null, PARSE_ERROR, "parse error"));
    };
    let Some(object) = message.as_object() else {
        return Some(rpc_error(&Value::Null, INVALID_REQUEST, "invalid request"));
    };
    let id = object.get("id").cloned();
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        // A response to a request we never send, or garbage with an id.
        return match id {
            Some(id) if !object.contains_key("result") && !object.contains_key("error") => {
                Some(rpc_error(&id, INVALID_REQUEST, "invalid request"))
            }
            _ => None,
        };
    };
    let id = id?;
    let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
    Some(match dispatch(socket, method, &params).await {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, text)) => rpc_error(&id, code, text),
    })
}

async fn dispatch(
    socket: &Path,
    method: &str,
    params: &Value,
) -> Result<Value, (i64, &'static str)> {
    match method {
        "initialize" => {
            let requested = params.get("protocolVersion").and_then(Value::as_str);
            let version = requested
                .filter(|v| PROTOCOL_VERSIONS.contains(v))
                .unwrap_or(PROTOCOL_VERSIONS[0]);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "acf", "version": env!("CARGO_PKG_VERSION") },
                "instructions": INSTRUCTIONS,
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => call(socket, params).await,
        _ => Err((METHOD_NOT_FOUND, "method not found")),
    }
}

/// The tool definitions.
#[must_use]
pub fn tools() -> Value {
    json!([
        {
            "name": "acf_request_task",
            "title": "Request an ACF task",
            "description": "Propose a task to the ACF Capability Authority under a signed job definition (or as a configured scheduler). Returns an opaque task handle with the grants the authority actually allowed, which may be fewer than proposed. Never returns a credential or capability.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "taskId": { "type": "string", "description": "Your identifier for this task." },
                    "job": { "type": "string", "description": "Signed job definition to run under." },
                    "scheduler": { "type": "boolean", "description": "Request as a configured scheduler instead of a job." },
                    "grants": {
                        "type": "array",
                        "description": "Proposed action/resource pairs; omit for the job's whole scope.",
                        "items": {
                            "type": "object",
                            "properties": { "action": { "type": "string" }, "resource": { "type": "string" } },
                            "required": ["action", "resource"],
                            "additionalProperties": false
                        }
                    },
                    "ttlSecs": { "type": "integer", "minimum": 1, "description": "Proposed lifetime." }
                },
                "required": ["taskId"],
                "additionalProperties": false
            },
            "_meta": { "acf/toolsVersion": TOOLS_VERSION }
        },
        {
            "name": "acf_get_task_status",
            "title": "Get ACF task status",
            "description": "Show a task's state, granted actions, usage limits, and expiry.",
            "inputSchema": {
                "type": "object",
                "properties": { "taskHandle": { "type": "string" } },
                "required": ["taskHandle"],
                "additionalProperties": false
            },
            "_meta": { "acf/toolsVersion": TOOLS_VERSION }
        },
        {
            "name": "acf_execute_action",
            "title": "Execute an ACF action",
            "description": "Run one semantic action (for example cloudflare.dns.records.list) on a registered resource through a task handle. ACF supplies the credential; you receive only the allowlisted result fields. Read-only in this version: mutations are refused.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "taskHandle": { "type": "string" },
                    "action": { "type": "string" },
                    "resource": { "type": "string" },
                    "parameters": { "type": "object", "description": "Action parameters, validated by the gateway." }
                },
                "required": ["taskHandle", "action", "resource"],
                "additionalProperties": false
            },
            "_meta": { "acf/toolsVersion": TOOLS_VERSION }
        }
    ])
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantArg {
    action: ActionName,
    resource: ResourceId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestTaskArgs {
    task_id: TaskId,
    #[serde(default)]
    job: Option<JobId>,
    #[serde(default)]
    scheduler: bool,
    #[serde(default)]
    grants: Vec<GrantArg>,
    #[serde(default)]
    ttl_secs: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskStatusArgs {
    task_handle: TaskHandle,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecuteArgs {
    task_handle: TaskHandle,
    action: ActionName,
    resource: ResourceId,
    #[serde(default)]
    parameters: Map<String, Value>,
}

/// A tool result: the value as text and as structured content.
fn tool_result(value: &Value, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(value).unwrap_or_default() }],
        "structuredContent": value,
        "isError": is_error,
    })
}

fn tool_error(message: &str) -> Value {
    tool_result(&json!({ "error": message }), true)
}

fn agent_error(error: &AgentError) -> Value {
    tool_error(&error.to_string())
}

fn arguments<T: serde::de::DeserializeOwned>(params: &Value) -> Result<T, Value> {
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    serde_json::from_value(arguments)
        .map_err(|_| tool_error("invalid arguments: check the tool's input schema"))
}

async fn call(socket: &Path, params: &Value) -> Result<Value, (i64, &'static str)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((INVALID_PARAMS, "missing tool name"))?;
    Ok(match name {
        "acf_request_task" => request_task(socket, params).await,
        "acf_get_task_status" => match arguments::<TaskStatusArgs>(params) {
            Ok(args) => match local::task_status(socket, &args.task_handle).await {
                Ok(status) => tool_result(&serde_json::to_value(status).unwrap_or_default(), false),
                Err(error) => agent_error(&error),
            },
            Err(error) => error,
        },
        "acf_execute_action" => execute(socket, params).await,
        _ => return Err((INVALID_PARAMS, "unknown tool")),
    })
}

async fn request_task(socket: &Path, params: &Value) -> Value {
    let args = match arguments::<RequestTaskArgs>(params) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let basis = match (args.job, args.scheduler) {
        (Some(job), false) => Some(BasisRequest::Job { job }),
        (None, true) => Some(BasisRequest::Scheduler),
        (None, false) => None,
        (Some(_), true) => return tool_error("give either `job` or `scheduler`, not both"),
    };
    let request = CreateTaskRequest {
        task_id: args.task_id,
        // Only this adapter process may use the handle.
        pid: Some(std::process::id()),
        basis,
        grants: args
            .grants
            .into_iter()
            .map(|g| Grant {
                action: g.action,
                resource: g.resource,
                constraints: acf_protocol::ConstraintSet::default(),
            })
            .collect(),
        ttl_secs: args.ttl_secs,
    };
    match local::propose_task(socket, &request).await {
        Ok(status) => tool_result(&serde_json::to_value(status).unwrap_or_default(), false),
        Err(error) => agent_error(&error),
    }
}

async fn execute(socket: &Path, params: &Value) -> Value {
    let args = match arguments::<ExecuteArgs>(params) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let request = LocalActionRequest {
        task_handle: args.task_handle,
        action: args.action,
        resource: args.resource,
        parameters: args.parameters,
        idempotency_key: None,
        approval_id: None,
    };
    match local::execute(socket, &request).await {
        Ok(response) => {
            let failed = matches!(
                response,
                ActionResponse::Denied { .. } | ActionResponse::Failed { .. }
            );
            tool_result(&serde_json::to_value(response).unwrap_or_default(), failed)
        }
        Err(error) => agent_error(&error),
    }
}
