//! API, task, approval, and operation models shared by the daemon, gateway,
//! and control plane.
//!
//! This crate does not depend on `acf-secrets`, so none of its types can hold
//! secret material. `deny.toml` keeps that dependency out.

mod action;
mod approval;
mod authority;
mod capability;
mod constraints;
mod digest;
mod ids;
mod local;
mod operation;
mod token;

pub use action::{ActionRequest, ActionResponse, DenialReason, FailureReason};
pub use approval::{APPROVAL_OBJECT_VERSION, ApprovalObject};
pub use authority::{AuthorityError, AuthorityErrorCode, BasisRequest, TaskIssued, TaskProposal};
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
    IdempotencyKey, IssuerId, JobId, KeyId, MAX_ID_LEN, OperationId, PrincipalId, RequestId,
    ResourceId, TaskHandle, TaskId,
};
pub use local::{
    CreateTaskRequest, LocalActionRequest, LocalError, LocalErrorCode, TaskState, TaskStatus,
};
pub use operation::{OperationState, OperationStatus};
pub use token::{
    CAPABILITY_HEADER, CAPABILITY_TYPE, CapabilityHeader, MAX_CAPABILITY_BYTES, SignatureAlgorithm,
    TokenError, UnverifiedCapability, base64url_decode, base64url_encode, encode_capability,
    parse_claims, split_capability,
};
