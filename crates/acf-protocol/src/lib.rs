//! API, task, approval, and operation models shared by the daemon, gateway,
//! and control plane.
//!
//! This crate does not depend on `acf-secrets`, so none of its types can hold
//! secret material. `deny.toml` keeps that dependency out.

mod action;
mod approval;
mod capability;
mod constraints;
mod digest;
mod ids;
mod operation;

pub use action::{ActionRequest, ActionResponse, DenialReason, FailureReason};
pub use approval::{APPROVAL_OBJECT_VERSION, ApprovalObject};
pub use capability::{
    AuthorizationBasis, Confirmation, Grant, HumanAuthMethod, Limits, TaskCapabilityClaims,
    TaskInfo,
};
pub use constraints::{
    ConstraintError, ConstraintSet, ConstraintViolation, DnsZone, FieldConstraint, GlobPattern,
    IntRange, ParamName, Quotas, Scalar, ViolationKind,
};
pub use digest::{CertificateThumbprint, DigestError, Sha256Digest};
pub use ids::{
    ActionName, AgentId, ApprovalId, ApprovalNonce, AudienceId, CapabilityId, DeviceId, IdError,
    IdempotencyKey, IssuerId, MAX_ID_LEN, OperationId, PrincipalId, RequestId, ResourceId, TaskId,
};
pub use operation::{OperationState, OperationStatus};
