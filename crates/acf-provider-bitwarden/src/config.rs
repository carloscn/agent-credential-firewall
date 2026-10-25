//! Validated Bitwarden-specific configuration.

use std::fmt;

use acf_secrets::SecretRef;
use url::Url;
use uuid::Uuid;

/// Configuration errors that never include credentials or response bodies.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BitwardenConfigError {
    /// A configured endpoint is not an HTTPS origin/base URL.
    #[error("{kind} must be an HTTPS URL without user info, query, or fragment")]
    InvalidEndpoint {
        /// Which endpoint failed validation.
        kind: &'static str,
    },
    /// A Bitwarden identifier is not a UUID.
    #[error("Bitwarden secret identifier must be a UUID")]
    InvalidSecretId,
    /// A mapping points outside the provider's assigned namespace.
    #[error("mapping is outside the assigned namespace: {reference}")]
    NamespaceMismatch {
        /// Logical ACF reference; never secret material.
        reference: SecretRef,
    },
    /// A logical reference was configured more than once.
    #[error("duplicate Bitwarden mapping: {reference}")]
    DuplicateMapping {
        /// Duplicated logical ACF reference.
        reference: SecretRef,
    },
}

/// Bitwarden secret UUID.
///
/// The identifier is not a credential, but its formatting is redacted to keep
/// vendor identifiers out of ordinary errors and logs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitwardenSecretId(Uuid);

impl BitwardenSecretId {
    /// Parses a canonical or simple UUID.
    ///
    /// # Errors
    ///
    /// Returns [`BitwardenConfigError::InvalidSecretId`] without echoing input.
    pub fn parse(value: &str) -> Result<Self, BitwardenConfigError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| BitwardenConfigError::InvalidSecretId)
    }

    pub(crate) const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl From<Uuid> for BitwardenSecretId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl fmt::Debug for BitwardenSecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BitwardenSecretId([REDACTED])")
    }
}

/// Exact vendor location selected by administrator configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitwardenLocator {
    /// Secret UUID accepted by the Bitwarden SDK.
    pub secret_id: BitwardenSecretId,
    /// Optional project pin checked against the decrypted response.
    pub expected_project_id: Option<Uuid>,
}

/// One exact logical-reference to Bitwarden-UUID mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMapping {
    /// Provider-neutral ACF reference.
    pub reference: SecretRef,
    /// Administrator-selected Bitwarden location.
    pub locator: BitwardenLocator,
}

impl SecretMapping {
    /// Creates an exact mapping.
    #[must_use]
    pub const fn new(reference: SecretRef, locator: BitwardenLocator) -> Self {
        Self { reference, locator }
    }
}

/// Network and tenant settings for an SDK session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitwardenSettings {
    api_url: String,
    identity_url: String,
    organization_id: Uuid,
}

impl BitwardenSettings {
    /// Creates validated cloud or self-hosted endpoint settings.
    ///
    /// Paths such as `/api` and `/identity` are allowed for self-hosted
    /// installations. User info, query strings, fragments, and non-HTTPS
    /// schemes are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`BitwardenConfigError::InvalidEndpoint`] for an invalid URL.
    pub fn new(
        api_url: impl Into<String>,
        identity_url: impl Into<String>,
        organization_id: Uuid,
    ) -> Result<Self, BitwardenConfigError> {
        let api_url = api_url.into();
        let identity_url = identity_url.into();
        validate_endpoint(&api_url, "api_url")?;
        validate_endpoint(&identity_url, "identity_url")?;
        Ok(Self {
            api_url,
            identity_url,
            organization_id,
        })
    }

    /// Bitwarden public cloud settings for one organization.
    #[must_use]
    pub fn cloud(organization_id: Uuid) -> Self {
        Self {
            api_url: "https://api.bitwarden.com".to_owned(),
            identity_url: "https://identity.bitwarden.com".to_owned(),
            organization_id,
        }
    }

    /// Validated Secrets Manager API base URL.
    #[must_use]
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// Validated Identity API base URL.
    #[must_use]
    pub fn identity_url(&self) -> &str {
        &self.identity_url
    }

    /// Organization every fetched response must belong to.
    #[must_use]
    pub const fn organization_id(&self) -> Uuid {
        self.organization_id
    }
}

fn validate_endpoint(value: &str, kind: &'static str) -> Result<(), BitwardenConfigError> {
    let url = Url::parse(value).map_err(|_| BitwardenConfigError::InvalidEndpoint { kind })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(BitwardenConfigError::InvalidEndpoint { kind });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_cloud_and_self_hosted_paths() {
        let organization = Uuid::from_u128(1);
        assert!(
            BitwardenSettings::new(
                "https://vault.example.com/api",
                "https://vault.example.com/identity",
                organization,
            )
            .is_ok()
        );
        assert_eq!(
            BitwardenSettings::cloud(organization).api_url(),
            "https://api.bitwarden.com"
        );
    }

    #[test]
    fn rejects_unsafe_endpoints_without_echoing_them() {
        let organization = Uuid::from_u128(1);
        for endpoint in [
            "http://vault.example.com",
            "https://user:password@vault.example.com",
            "https://vault.example.com?token=canary",
            "not-a-url",
        ] {
            let error =
                BitwardenSettings::new(endpoint, "https://identity.example.com", organization)
                    .unwrap_err();
            assert!(!error.to_string().contains(endpoint));
            assert!(!format!("{error:?}").contains("password"));
            assert!(!format!("{error:?}").contains("canary"));
        }
    }
}
