//! Action request and response models.
//!
//! An agent selects only a semantic action, a registered resource, and
//! parameters. There is deliberately no field for a URL, HTTP method, path,
//! header, credential slot, authentication strategy, or secret reference;
//! `deny_unknown_fields` rejects a request that tries to supply one.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::digest::Sha256Digest;
use crate::ids::{
    ActionName, ApprovalId, IdempotencyKey, OperationId, RequestId, ResourceId, TaskId,
};
use crate::operation::OperationStatus;

/// A semantic action request from the daemon to the gateway.
///
/// The task capability travels alongside the request and is not part of this
/// model; the agent never sees it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionRequest {
    /// Unique per call; checked against the replay cache.
    pub request_id: RequestId,
    /// Client time of the call; checked against the freshness window.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Task the request belongs to.
    pub task_id: TaskId,
    /// Semantic action.
    pub action: ActionName,
    /// Registered resource.
    pub resource: ResourceId,
    /// Agent-supplied parameters, validated against the action contract.
    #[serde(default)]
    pub parameters: Map<String, Value>,
    /// Required for mutations; stable across approval and resubmission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<IdempotencyKey>,
    /// Present when resubmitting an approved mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
}

/// The gateway's answer to an [`ActionRequest`].
///
/// This crate does not depend on `acf-secrets`, so no variant can hold
/// secret material.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ActionResponse {
    /// The action ran; `result` holds only profile-allowlisted fields.
    Completed {
        /// Request this answers.
        request_id: RequestId,
        /// Filtered business result.
        result: Value,
        /// Present for mutations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation: Option<OperationStatus>,
    },
    /// The mutation needs a human approval before it can run.
    ApprovalRequired {
        /// Request this answers.
        request_id: RequestId,
        /// Journal record for the mutation.
        operation_id: OperationId,
        /// Pending approval.
        approval_id: ApprovalId,
        /// Digest of the canonical approval object.
        approval_digest: Sha256Digest,
        /// Gateway-rendered description of the exact change.
        change: Value,
        /// When the pending approval expires.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// The request was refused.
    Denied {
        /// Request this answers.
        request_id: RequestId,
        /// Machine-readable reason.
        reason: DenialReason,
    },
    /// The request was authorized, but executing it failed.
    Failed {
        /// Request this answers.
        request_id: RequestId,
        /// Machine-readable reason.
        reason: FailureReason,
    },
}

/// Machine-readable execution failures. Like denials, they carry no detail
/// that could echo agent input, configuration, or credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// The secret provider could not supply the credential.
    CredentialUnavailable,
    /// The credential cannot be used for this destination or encoding.
    CredentialUnusable,
    /// The destination was refused by the network policy.
    DestinationRefused,
    /// The request could not be built from the action contract.
    RequestInvalid,
    /// The downstream service timed out. For a mutation, the outcome is unknown.
    DownstreamTimeout,
    /// The downstream service could not be reached.
    DownstreamUnavailable,
    /// The downstream response was too large, not JSON, or a redirect.
    DownstreamResponseInvalid,
    /// The downstream response contained the credential and was discarded.
    CredentialReflected,
    /// The gateway did not finish within its time limit.
    GatewayTimeout,
    /// A required audit event could not be recorded, so the action did not run.
    AuditUnavailable,
}

/// Machine-readable denial reasons.
///
/// Denials carry a code only. Free-text detail could echo agent input or
/// internal configuration, so it belongs in the audit log, not the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// Connection identity could not be established.
    Unauthenticated,
    /// The capability is missing, malformed, or has a bad signature.
    CapabilityInvalid,
    /// The capability is outside its validity window.
    CapabilityExpired,
    /// The capability was revoked.
    CapabilityRevoked,
    /// The capability's `cnf` claim does not match the client certificate.
    CertificateMismatch,
    /// The `requestId` was already used, or the timestamp is stale.
    Replay,
    /// Policy denied the request.
    PolicyDenied,
    /// A parameter violated a constraint.
    ConstraintViolation,
    /// A quota or rate limit was exceeded.
    QuotaExceeded,
    /// The action is not registered.
    UnknownAction,
    /// The resource is not registered.
    UnknownResource,
    /// Parameters failed validation.
    InvalidParameters,
    /// The approval receipt is missing, expired, consumed, or does not match.
    ApprovalInvalid,
    /// A mutation precondition no longer holds.
    PreconditionFailed,
    /// A required dependency is unavailable; the gateway failed closed.
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request_json() -> Value {
        json!({
            "requestId": "req-001",
            "timestamp": "2026-10-24T17:50:03Z",
            "taskId": "dns-change-892",
            "action": "cloudflare.dns.records.list",
            "resource": "cloudflare-zone:example.com",
            "parameters": { "name": "api.example.com", "type": "A" }
        })
    }

    #[test]
    fn parses_design_example() {
        let request: ActionRequest = serde_json::from_value(request_json()).unwrap();
        assert_eq!(request.action.as_str(), "cloudflare.dns.records.list");
        assert!(request.idempotency_key.is_none());
    }

    #[test]
    fn rejects_transport_level_fields() {
        for field in [
            "url",
            "method",
            "path",
            "headers",
            "secretRef",
            "credentialSlot",
            "authorization",
        ] {
            let mut value = request_json();
            value[field] = json!("anything");
            assert!(
                serde_json::from_value::<ActionRequest>(value).is_err(),
                "{field} must be rejected"
            );
        }
    }

    #[test]
    fn response_is_tagged_by_status() {
        let response = ActionResponse::Denied {
            request_id: RequestId::new("req-001").unwrap(),
            reason: DenialReason::CertificateMismatch,
        };
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({ "status": "denied", "requestId": "req-001", "reason": "certificate_mismatch" })
        );
    }
}
