//! Narrow boundary around the vendor SDK.

use acf_secrets::{SecretMaterial, SecretVersion};
use async_trait::async_trait;

use crate::BitwardenLocator;

/// A secret fetched and decrypted by a Bitwarden backend.
///
/// SDK response objects are converted into this protected representation
/// immediately. No Bitwarden SDK type crosses into the provider-neutral ACF
/// interface.
#[derive(Debug)]
pub struct BitwardenRecord {
    /// Plaintext secret material, redacted on `Debug` and zeroized on drop.
    pub material: SecretMaterial,
    /// Monotonic revision marker derived from Bitwarden's revision timestamp.
    pub version: SecretVersion,
}

/// Sanitized backend failures.
///
/// Variants deliberately contain no SDK error string, response body, secret
/// UUID, access token, or plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BitwardenBackendError {
    /// The mapped secret no longer exists or is inaccessible.
    #[error("Bitwarden secret was not found")]
    NotFound,
    /// The authenticated SDK session is absent, expired, or invalid.
    #[error("Bitwarden authentication failed")]
    AuthenticationFailed,
    /// Bitwarden or the network is unavailable.
    #[error("Bitwarden is unavailable")]
    Unavailable,
    /// A tracing filter would expose SDK authentication material.
    #[error("Bitwarden SDK sensitive logging is enabled")]
    UnsafeLoggingConfiguration,
    /// The operation exceeded its deadline.
    #[error("Bitwarden request timed out")]
    Timeout,
    /// Decryption, organization, project, or response integrity validation failed.
    #[error("Bitwarden response failed integrity validation")]
    Corrupted,
}

/// Minimal SDK-facing operation needed by the ACF runtime provider.
///
/// This is not ACF's provider abstraction; [`acf_secrets::SecretProvider`] is.
/// It exists to quarantine the vendor SDK and make the adapter testable without
/// live credentials.
#[async_trait]
pub trait BitwardenBackend: Send + Sync {
    /// Fetches and decrypts one explicitly mapped secret.
    ///
    /// # Errors
    ///
    /// Returns only sanitized [`BitwardenBackendError`] variants.
    async fn fetch(
        &self,
        locator: BitwardenLocator,
    ) -> Result<BitwardenRecord, BitwardenBackendError>;
}
