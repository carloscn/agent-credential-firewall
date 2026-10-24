//! Runtime and administrative provider traits.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::binding::SecretUseBinding;
use crate::material::{ResolvedSecret, SecretMaterial};
use crate::reference::{SecretRef, SecretScope};

/// Monotonic version of a stored secret, starting at 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SecretVersion(u64);

impl SecretVersion {
    /// The first version of a secret.
    pub const FIRST: Self = Self(1);

    /// Wraps a raw version number. Returns `None` for 0.
    #[must_use]
    pub fn new(value: u64) -> Option<Self> {
        (value > 0).then_some(Self(value))
    }

    /// Returns the raw version number.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }

    /// Returns the next version, or `None` on overflow.
    #[must_use]
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for SecretVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Provider failures.
///
/// Variants carry at most the logical reference, which is permitted in audit
/// records. They never carry plaintext, keys, ciphertext, or storage paths.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    /// No secret exists at this exact reference.
    #[error("secret not found: {reference}")]
    NotFound {
        /// Requested reference.
        reference: SecretRef,
    },
    /// The reference's namespace is not served by this provider.
    #[error("namespace not assigned to this provider: {reference}")]
    NotAssigned {
        /// Requested reference.
        reference: SecretRef,
    },
    /// The provider is locked; its key source has not been unlocked.
    #[error("secret provider is locked")]
    Locked,
    /// The provider's backend is unreachable.
    #[error("secret provider is unavailable")]
    Unavailable,
    /// The provider did not answer in time.
    #[error("secret provider timed out")]
    Timeout,
    /// Stored data failed integrity checks.
    #[error("secret store integrity check failed")]
    Corrupted,
    /// The provider's own bootstrap authentication failed.
    #[error("secret provider authentication failed")]
    AuthenticationFailed,
    /// A version counter would overflow.
    #[error("secret version overflow: {reference}")]
    VersionOverflow {
        /// Affected reference.
        reference: SecretRef,
    },
}

/// Runtime secret retrieval, linked into the gateway request path.
///
/// Exact-reference lookup only. There is no enumeration, write, or export
/// operation here; those live on [`SecretAdmin`].
#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// Retrieves the secret at exactly `reference`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::NotFound`] for a missing reference,
    /// [`SecretError::NotAssigned`] for a namespace this provider does not
    /// serve, and an operational variant when the provider cannot answer.
    async fn get(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretError>;
}

/// Metadata about a stored secret. Contains no secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMetadata {
    /// Logical reference.
    pub reference: SecretRef,
    /// Current version.
    pub version: SecretVersion,
    /// Stored use binding.
    pub binding: SecretUseBinding,
}

/// Administrative secret management.
///
/// Used only by root-controlled administrative tooling. Never exposed to the
/// agent-facing API, MCP tools, the gateway runtime identity, or connectors.
#[async_trait]
pub trait SecretAdmin: Send + Sync {
    /// Stores a new version of the secret at `reference`, creating it if
    /// needed, and returns the new version.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::NotAssigned`] for a namespace this provider does
    /// not serve, or an operational variant.
    async fn put(
        &self,
        reference: &SecretRef,
        material: SecretMaterial,
        binding: SecretUseBinding,
    ) -> Result<SecretVersion, SecretError>;

    /// Deletes the secret at `reference`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::NotFound`] if nothing is stored there.
    async fn delete(&self, reference: &SecretRef) -> Result<(), SecretError>;

    /// Lists metadata for every secret in `scope`, sorted by reference.
    ///
    /// # Errors
    ///
    /// Returns an operational variant when the provider cannot answer.
    async fn list_metadata(&self, scope: &SecretScope) -> Result<Vec<SecretMetadata>, SecretError>;
}
