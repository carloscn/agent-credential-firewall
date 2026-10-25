//! Optional Bitwarden Secrets Manager adapter.
//!
//! ACF's stable boundary is [`acf_secrets::SecretProvider`]. This crate is a
//! leaf adapter: it translates exact logical references into administrator-
//! configured Bitwarden UUIDs and keeps all SDK-specific types on this side of
//! the boundary. Core gateway, policy, protocol, and connector crates do not
//! depend on Bitwarden.

mod backend;
mod config;
mod provider;
mod sdk;

pub use backend::{BitwardenBackend, BitwardenBackendError, BitwardenRecord};
pub use config::{
    BitwardenConfigError, BitwardenLocator, BitwardenSecretId, BitwardenSettings, SecretMapping,
};
pub use provider::BitwardenProvider;
pub use sdk::{BitwardenConnectError, SdkBitwardenBackend};
