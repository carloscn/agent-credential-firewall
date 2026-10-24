//! Task capability claims (design §8.2).
//!
//! The wire encoding and signature format are fixed in a later ADR (WP-09).
//! This module defines only the claims.
//!
//! Grants have no `constraints` field yet. WP-02 adds the typed constraint
//! language. Until then `deny_unknown_fields` makes a capability that carries
//! constraints fail to parse, so the claims fail closed rather than silently
//! dropping a restriction.

use serde::{Deserialize, Serialize};

use crate::digest::{CertificateThumbprint, Sha256Digest};
use crate::ids::{ActionName, AudienceId, CapabilityId, IssuerId, PrincipalId, ResourceId, TaskId};

/// Claims of a certificate-bound task capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCapabilityClaims {
    /// Issuing Capability Authority.
    pub iss: IssuerId,
    /// Gateway security domain the capability is valid for.
    pub aud: AudienceId,
    /// Principal the task acts for.
    pub sub: PrincipalId,
    /// Capability identifier. Reusable within the TTL; used for revocation
    /// and usage accounting, never as a single-use nonce.
    pub jti: CapabilityId,
    /// Issued-at time, in seconds since the Unix epoch.
    pub iat: i64,
    /// Not-before time, in seconds since the Unix epoch.
    pub nbf: i64,
    /// Expiry time, in seconds since the Unix epoch.
    pub exp: i64,
    /// Binds the capability to the daemon's mTLS certificate.
    pub cnf: Confirmation,
    /// Task metadata.
    pub task: TaskInfo,
    /// Permitted action/resource pairs.
    pub grants: Vec<Grant>,
    /// Usage limits.
    #[serde(default)]
    pub limits: Limits,
}

/// RFC 8705 certificate confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    /// SHA-256 thumbprint of the daemon's client certificate.
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: CertificateThumbprint,
}

/// Task identifier and the basis on which it was authorized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskInfo {
    /// Task identifier.
    pub id: TaskId,
    /// Trusted authorization path that approved the scope.
    pub basis: AuthorizationBasis,
}

/// How the task scope was authorized. Agent input alone is never a basis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthorizationBasis {
    /// A human confirmed the scope in the control-plane UI.
    Human {
        /// Confirming human.
        approver: PrincipalId,
        /// Authentication method used.
        method: HumanAuthMethod,
    },
    /// An administrator-approved job definition.
    JobDefinition {
        /// Digest of the signed job definition.
        definition_digest: Sha256Digest,
    },
    /// A trusted scheduler under preconfigured policy.
    Scheduler {
        /// Requesting scheduler.
        scheduler: PrincipalId,
    },
}

/// Human authentication methods accepted for task confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanAuthMethod {
    /// WebAuthn with user verification.
    Webauthn,
}

/// One permitted action on one resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Permitted action.
    pub action: ActionName,
    /// Resource the action may target.
    pub resource: ResourceId,
}

/// Usage limits. An absent limit means the capability adds no limit of its
/// own; gateway quotas still apply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    /// Maximum number of requests under this capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u32>,
    /// Maximum number of mutations under this capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mutations: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn design_example() -> Value {
        json!({
            "iss": "acf-authority-prod",
            "aud": "acf-gateway-prod-eu",
            "sub": "user:alice@example.com/device:laptop-0142",
            "jti": "cap-01JB",
            "iat": 1_792_863_900,
            "nbf": 1_792_863_900,
            "exp": 1_792_865_700,
            "cnf": { "x5t#S256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" },
            "task": {
                "id": "dns-change-892",
                "basis": { "type": "human", "approver": "alice@example.com", "method": "webauthn" }
            },
            "grants": [
                { "action": "cloudflare.dns.records.list", "resource": "cloudflare-zone:example.com" }
            ],
            "limits": { "maxRequests": 50, "maxMutations": 1 }
        })
    }

    #[test]
    fn parses_design_example_without_constraints() {
        let claims: TaskCapabilityClaims = serde_json::from_value(design_example()).unwrap();
        assert_eq!(claims.limits.max_mutations, Some(1));
        assert!(matches!(
            claims.task.basis,
            AuthorizationBasis::Human { .. }
        ));
    }

    #[test]
    fn constraints_fail_closed_until_wp02() {
        let mut value = design_example();
        value["grants"][0]["constraints"] = json!({ "params.name": { "in": ["api.example.com"] } });
        assert!(serde_json::from_value::<TaskCapabilityClaims>(value).is_err());
    }

    #[test]
    fn missing_confirmation_is_rejected() {
        let mut value = design_example();
        value.as_object_mut().unwrap().remove("cnf");
        assert!(serde_json::from_value::<TaskCapabilityClaims>(value).is_err());
    }

    #[test]
    fn agent_basis_is_not_representable() {
        let mut value = design_example();
        value["task"]["basis"] = json!({ "type": "agent", "agent": "acf-agent-123" });
        assert!(serde_json::from_value::<TaskCapabilityClaims>(value).is_err());
    }
}
