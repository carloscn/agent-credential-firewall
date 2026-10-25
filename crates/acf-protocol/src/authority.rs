//! Capability Authority API models (design §7.2.1, §18; ADR 0003).
//!
//! The daemon proposes a task over mTLS. The proposal is only a proposal:
//! the authority intersects it with the caller's entitlements, the scope of
//! the named authorization basis, and the registered resources, and signs
//! the result.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::capability::{Grant, Limits};
use crate::ids::{JobId, TaskId};

/// The trusted path the caller asks the authority to authorize under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BasisRequest {
    /// An administrator-signed job definition the caller may run.
    Job {
        /// Job definition identifier.
        job: JobId,
    },
    /// The caller is a scheduler with preconfigured authority.
    Scheduler,
}

/// `POST /v1/tasks` on the authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskProposal {
    /// Task identifier.
    pub task_id: TaskId,
    /// Requested authorization basis.
    pub basis: BasisRequest,
    /// Proposed grants. Empty proposes the basis's whole scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
    /// Proposed lifetime in seconds; capped by the basis and the authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u32>,
}

/// The authority's answer: a signed capability and what it grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskIssued {
    /// Task identifier.
    pub task_id: TaskId,
    /// Compact JWS (ADR 0003). For the daemon only; never shown to agents.
    pub capability: String,
    /// Expiry.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Effective grants after intersection.
    pub grants: Vec<Grant>,
    /// Usage limits.
    pub limits: Limits,
}

/// Why the authority refused a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityErrorCode {
    /// Malformed body.
    InvalidRequest,
    /// The client certificate is not enrolled.
    Unauthenticated,
    /// The caller may not use the requested basis, or it does not exist.
    BasisRejected,
    /// Nothing is left after intersection.
    ScopeEmpty,
    /// The authority could not sign.
    Unavailable,
}

/// Error body returned by the authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityError {
    /// Error code.
    pub error: AuthorityErrorCode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proposals_cannot_name_a_human_or_custom_basis() {
        for basis in [
            json!({ "type": "human", "approver": "alice" }),
            json!({ "type": "agent" }),
            json!({ "type": "job", "job": "j", "digest": "x" }),
        ] {
            let proposal = json!({ "taskId": "t", "basis": basis });
            assert!(serde_json::from_value::<TaskProposal>(proposal).is_err());
        }
        let ok = json!({ "taskId": "t", "basis": { "type": "job", "job": "nightly" } });
        assert!(serde_json::from_value::<TaskProposal>(ok).is_ok());
    }
}
