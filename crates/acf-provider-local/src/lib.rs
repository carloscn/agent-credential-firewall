//! Small encrypted local provider demonstration.
//!
//! The crate implements the provider-neutral [`acf_secrets::SecretProvider`]
//! and [`acf_secrets::SecretAdmin`] contracts. Each logical reference maps to
//! one independently encrypted record. See [`DemoLocalProvider`] for the
//! deliberately limited security scope. [`StoreKeySource`] loads the root key
//! from a systemd credential or a protected file.

mod crypto;
mod key_source;
mod provider;

pub use key_source::{CREDENTIALS_DIRECTORY, KeySourceError, StoreKeySource};
pub use provider::{DemoLocalProvider, LocalProviderConfigError, LocalStoreKey};
