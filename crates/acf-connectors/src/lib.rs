//! Semantic action connectors, authentication strategies, and domain types.
//!
//! - [`normalize_params`] canonicalizes parameters by domain type before
//!   authorization.
//! - [`HttpConnector`] executes declarative-profile actions over a restricted
//!   HTTP client: fixed origin, method, and path template; credential injected
//!   only after the use binding is re-checked; no proxy, redirects, or
//!   retries; destinations filtered by [`NetworkPolicy`]; responses projected
//!   to the profile allowlist.

mod domain;
mod http;
mod network;
mod projection;

pub use domain::{DomainError, DomainErrorKind, normalize_params};
pub use http::{
    ActionConnector, ConnectorCall, ConnectorError, ConnectorOutput, HttpConnector, HttpLimits,
};
pub use network::{ForbiddenAddress, HostResolver, NetworkPolicy, SystemResolver};
pub use projection::project;
