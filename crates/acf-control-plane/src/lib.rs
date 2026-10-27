//! Capability Authority (WP-09). The Approval Service arrives with WP-13.
//!
//! - [`Authority`] intersects a daemon's task proposal with the caller's
//!   entitlements, the scope of a trusted authorization basis (a signed job
//!   definition or a configured scheduler), and the registered actions, then
//!   signs a certificate-bound capability (ADR 0003).
//! - [`router`] serves `POST /v1/tasks`; the caller's identity comes from
//!   its verified client certificate (ADR 0002).
//!
//! - [`checkpoint_router`] serves `POST /v1/audit/checkpoints`, the external
//!   append-only anchor for gateway audit logs (ADR 0005).
//!
//! This is the only crate that can sign capabilities. Gateways verify them
//! with public keys alone, and `deny.toml` keeps them from linking this
//! crate.

mod authority;
mod collector;
mod config;
mod http;
mod keys;

pub use acf_identity::{KeyFileError, generate_pem, parse_key_pair, public_key, read_key_pair};
pub use authority::{Authority, Issuance};
pub use collector::{
    Accepted, CheckpointStore, CollectorError, MAX_CHECKPOINT_BYTES, checkpoint_router,
    read_stored, statement_of,
};
pub use config::{
    AUTHORITY_SCHEMA, AuthorityConfig, AuthorityConfigError, AuthorityPolicy, Entitlement,
    JOB_SCHEMA, JobDefinition, JobFile, JobSigner, MAX_TTL_SECS, Scheduler, SignedJob, read_jobs,
    sha256,
};
pub use http::{MAX_PROPOSAL_BYTES, router};
pub use keys::{CapabilitySigner, DetachedSignature, sign_detached, verify_detached};
