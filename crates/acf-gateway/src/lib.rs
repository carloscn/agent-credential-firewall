//! Credential Gateway data-plane request lifecycle.
//!
//! - [`Gateway`] runs one request through identity, authorization, secret
//!   retrieval, and the connector.
//! - [`router`] exposes it over HTTP.
//!
//! The binary serves TLS 1.3 with client certificates (ADR 0002) and
//! verifies task capabilities (ADR 0003). A plaintext loopback listener with
//! a development identity remains for the `development` feature. Approvals
//! arrive in later work packages; see `docs/implementation-plan.md`.

mod checkpoint;
mod encrypted;
mod files;
mod http;
mod pipeline;
mod startup;
mod state;

pub use acf_identity::{HANDSHAKE_TIMEOUT, TlsError, serve_tls, server_config};
pub use checkpoint::HttpCheckpointPublisher;
pub use encrypted::EncryptedStore;
pub use files::{load_config, profile_sources, read, read_bytes, source, text};
pub use http::{ServerLimits, router};
pub use pipeline::{AuditSettings, Gateway, GatewayError, ProviderRegistry};
pub use startup::{BUILD_FLAVOR, StartupFacts, production_refusals};
pub use state::{
    DEFAULT_CLOCK_SKEW_SECS, DEFAULT_FRESHNESS_SECS, DEFAULT_TASK_COUNTER_TTL_SECS, RateLimits,
    StateSettings,
};
