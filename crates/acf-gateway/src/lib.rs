//! Credential Gateway data-plane request lifecycle.
//!
//! - [`Gateway`] runs one request through identity, authorization, secret
//!   retrieval, and the connector.
//! - [`router`] exposes it over HTTP.
//!
//! Milestone 0 serves plaintext loopback with a development identity, the
//! in-memory provider, and unscoped development tasks. TLS client identity,
//! capabilities, replay protection, and approvals arrive in later work
//! packages; see `docs/implementation-plan.md`.

mod http;
mod pipeline;

pub use http::{ServerLimits, router};
pub use pipeline::{Gateway, GatewayError, ProviderRegistry};
