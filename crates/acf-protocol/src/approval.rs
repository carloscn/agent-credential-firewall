//! Approval object (design §10.1).
//!
//! The gateway builds this object from the normalized request; it is the only
//! source of truth for what a human approves. RFC 8785 canonicalization and
//! digest computation arrive with WP-14.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::digest::Sha256Digest;
use crate::ids::{ActionName, CapabilityId, IdempotencyKey, ResourceId, TaskId};

/// Current approval-object format version.
pub const APPROVAL_OBJECT_VERSION: u32 = 1;

/// The exact mutation a human is asked to approve.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalObject {
    /// Format version; currently [`APPROVAL_OBJECT_VERSION`].
    pub version: u32,
    /// Task the mutation belongs to.
    pub task_id: TaskId,
    /// Capability under which the mutation was requested.
    pub capability_jti: CapabilityId,
    /// Semantic action.
    pub action: ActionName,
    /// Target resource.
    pub resource: ResourceId,
    /// Parameters after connector normalization.
    pub normalized_params: Map<String, Value>,
    /// Conditions re-checked at execution time.
    pub preconditions: Map<String, Value>,
    /// Digest of the connector profile in force.
    pub profile_digest: Sha256Digest,
    /// Policy version in force.
    pub policy_version: String,
    /// Logical mutation identity.
    pub idempotency_key: IdempotencyKey,
    /// Approval deadline.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_design_example() {
        let value = json!({
            "version": 1,
            "taskId": "dns-change-892",
            "capabilityJti": "cap-01JB",
            "action": "cloudflare.dns.records.create",
            "resource": "cloudflare-zone:example.com",
            "normalizedParams": { "type": "A", "name": "api.example.com", "content": "203.0.113.10", "ttl": 300, "proxied": true },
            "preconditions": { "existing_records": { "name": "api.example.com", "type": "A", "count": 0 } },
            "profileDigest": format!("sha256:{}", "0f".repeat(32)),
            "policyVersion": "policy-2026-10-24.3",
            "idempotencyKey": "op-01JB",
            "expiresAt": "2026-10-24T18:10:00Z"
        });
        let object: ApprovalObject = serde_json::from_value(value).unwrap();
        assert_eq!(object.version, APPROVAL_OBJECT_VERSION);
    }
}
