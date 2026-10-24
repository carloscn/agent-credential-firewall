//! Runtime `SecretProvider` and administrative `SecretAdmin` traits,
//! protected secret types, and the in-memory provider.
//!
//! Only `acf-config`, `acf-connectors`, `acf-provider-local`, and
//! `acf-gateway` may depend on this crate (enforced in `deny.toml`). The
//! daemon, control plane, policy, state, audit, and protocol crates never
//! link secret material.
//!
//! Features:
//!
//! - `in-memory`: [`InMemoryProvider`], for tests and the `development`
//!   deployment profile only.
//! - `conformance`: the reusable provider conformance suite.

mod binding;
mod material;
mod provider;
mod reference;

#[cfg(feature = "conformance")]
pub mod conformance;
#[cfg(feature = "in-memory")]
mod in_memory;

pub use binding::{AuthSlot, BindingError, ConnectorName, Environment, Origin, SecretUseBinding};
#[cfg(feature = "in-memory")]
pub use in_memory::InMemoryProvider;
pub use material::{ResolvedSecret, SecretMaterial};
pub use provider::{SecretAdmin, SecretError, SecretMetadata, SecretProvider, SecretVersion};
pub use reference::{Namespace, ReferenceError, SecretRef, SecretScope};
