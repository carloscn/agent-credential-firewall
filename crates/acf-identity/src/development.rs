//! Fixed development identity.

use std::collections::BTreeSet;

use acf_protocol::{CertificateThumbprint, DeviceId, IssuerId, PrincipalId};
use async_trait::async_trait;

use crate::{
    ConnectionInfo, IdentityAssurance, IdentityContext, IdentityContextProvider, IdentityError,
    Label,
};

/// Returns the same identity for every connection, with
/// [`IdentityAssurance::Development`].
///
/// For local development and tests only. The authorizer denies requests
/// carrying this assurance level under the `production` deployment profile.
pub struct DevelopmentIdentityProvider {
    identity: IdentityContext,
}

impl DevelopmentIdentityProvider {
    /// Creates a provider that always returns `principal` with `labels`.
    ///
    /// `certificate` is reported as the connection's verified certificate so
    /// development capabilities can exercise the `cnf` binding.
    #[must_use]
    pub fn new(
        principal: PrincipalId,
        device: Option<DeviceId>,
        labels: BTreeSet<Label>,
        certificate: Option<CertificateThumbprint>,
    ) -> Self {
        // A constant, known-valid identifier.
        let issuer = IssuerId::new("acf-development-identity").unwrap_or_else(|_| unreachable!());
        Self {
            identity: IdentityContext {
                principal,
                device,
                labels,
                certificate,
                issuer,
                assurance: IdentityAssurance::Development,
            },
        }
    }
}

#[async_trait]
impl IdentityContextProvider for DevelopmentIdentityProvider {
    fn assurance(&self) -> IdentityAssurance {
        IdentityAssurance::Development
    }

    async fn resolve(
        &self,
        _connection: &ConnectionInfo,
    ) -> Result<IdentityContext, IdentityError> {
        Ok(self.identity.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn always_development_assurance() {
        let provider = DevelopmentIdentityProvider::new(
            PrincipalId::new("dev-agent").unwrap(),
            None,
            BTreeSet::new(),
            None,
        );
        let identity = provider.resolve(&ConnectionInfo::default()).await.unwrap();
        assert_eq!(identity.assurance, IdentityAssurance::Development);
        assert_eq!(provider.assurance(), IdentityAssurance::Development);
    }
}
