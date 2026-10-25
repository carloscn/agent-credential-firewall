//! Small encrypted local provider demonstration.
//!
//! The crate implements the provider-neutral [`acf_secrets::SecretProvider`]
//! and [`acf_secrets::SecretAdmin`] contracts. Each logical reference maps to
//! one independently encrypted record. See [`DemoLocalProvider`] for the
//! deliberately limited security scope.

mod crypto;
mod provider;

pub use provider::{DemoLocalProvider, LocalProviderConfigError, LocalStoreKey};
