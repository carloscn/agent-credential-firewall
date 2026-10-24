//! Connection identity and local peer identity providers.
//!
//! An [`IdentityContextProvider`] derives identity only from authenticated
//! connection state in [`ConnectionInfo`]. `ConnectionInfo` has no field for
//! request headers or agent-supplied claims, so an agent cannot assert its own
//! identity.
//!
//! The mTLS provider arrives with WP-08. The `development` feature provides
//! [`DevelopmentIdentityProvider`], which returns a fixed identity with
//! [`IdentityAssurance::Development`]; the authorizer refuses that assurance
//! level under the `production` deployment profile.

use std::collections::BTreeSet;
use std::fmt;

use acf_protocol::{CertificateThumbprint, DeviceId, IssuerId, PrincipalId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

const MAX_LABEL_LEN: usize = 63;

/// How much an identity can be trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAssurance {
    /// Fixed or self-asserted identity for development only.
    Development,
    /// Derived from authenticated connection state or signed assertions.
    Production,
}

/// A device or workload label, for example `agent` or `production`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Label(String);

/// A malformed label. Never echoes the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("labels must be 1-63 characters of [a-z0-9_.:-], starting with a letter or digit")]
pub struct LabelError;

impl Label {
    /// Validates a label.
    ///
    /// # Errors
    ///
    /// Returns [`LabelError`] if the label is malformed.
    pub fn new(value: impl Into<String>) -> Result<Self, LabelError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_LABEL_LEN
            && value
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && value.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'_' | b'.' | b':' | b'-')
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(LabelError)
        }
    }

    /// Returns the label as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Label {
    type Error = LabelError;

    fn try_from(value: String) -> Result<Self, LabelError> {
        Self::new(value)
    }
}

impl From<Label> for String {
    fn from(label: Label) -> Self {
        label.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Authenticated connection state, filled in by the transport layer.
///
/// Deliberately has no field for HTTP headers or anything else the client
/// can choose.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// SHA-256 thumbprint of the client certificate the TLS layer verified.
    pub verified_client_certificate: Option<CertificateThumbprint>,
}

/// Trusted identity of the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityContext {
    /// Authenticated principal, for example `workload:agent-prod-17`.
    pub principal: PrincipalId,
    /// Device identity, when known.
    pub device: Option<DeviceId>,
    /// Trusted labels.
    pub labels: BTreeSet<Label>,
    /// Client certificate thumbprint verified on this connection. Compared
    /// with the capability's `cnf.x5t#S256`.
    pub certificate: Option<CertificateThumbprint>,
    /// Who vouched for this identity.
    pub issuer: IssuerId,
    /// Assurance level.
    pub assurance: IdentityAssurance,
}

/// Identity resolution failures. Never contains connection secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// No authenticated identity is available on this connection.
    #[error("connection is not authenticated")]
    Unauthenticated,
    /// The identity is known but not permitted to use the gateway.
    #[error("identity is not recognized")]
    Unrecognized,
    /// The identity source is unavailable.
    #[error("identity provider is unavailable")]
    Unavailable,
}

/// Resolves a trusted identity from authenticated connection state.
#[async_trait]
pub trait IdentityContextProvider: Send + Sync {
    /// The assurance level of every identity this provider returns.
    fn assurance(&self) -> IdentityAssurance;

    /// Resolves the caller's identity.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when no trusted identity can be established.
    async fn resolve(&self, connection: &ConnectionInfo) -> Result<IdentityContext, IdentityError>;
}

#[cfg(feature = "development")]
mod development;
#[cfg(feature = "development")]
pub use development::DevelopmentIdentityProvider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_validated() {
        assert!(Label::new("production").is_ok());
        assert!(Label::new("region:eu").is_ok());
        for bad in ["", "Prod", "-x", "has space", &"a".repeat(64)] {
            assert_eq!(Label::new(bad), Err(LabelError), "{bad}");
        }
    }
}
