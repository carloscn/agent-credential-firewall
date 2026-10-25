//! Provider-neutral implementation backed by a Bitwarden client boundary.

use std::collections::BTreeMap;

use acf_secrets::{Namespace, ResolvedSecret, SecretError, SecretProvider, SecretRef};
use async_trait::async_trait;

use crate::{
    BitwardenBackend, BitwardenBackendError, BitwardenConfigError, BitwardenLocator, SecretMapping,
};

/// Exact-reference Bitwarden implementation of ACF's runtime provider.
///
/// It intentionally does not implement `SecretAdmin`: creation, mutation,
/// enumeration, machine-account management, and token issuance stay in
/// Bitwarden's administrative plane.
pub struct BitwardenProvider<B> {
    namespace: Namespace,
    mappings: BTreeMap<SecretRef, BitwardenLocator>,
    backend: B,
}

impl<B> BitwardenProvider<B> {
    /// Creates a provider for one namespace and a set of exact mappings.
    ///
    /// # Errors
    ///
    /// Rejects references outside `namespace` and duplicate logical mappings.
    pub fn new(
        namespace: Namespace,
        mappings: impl IntoIterator<Item = SecretMapping>,
        backend: B,
    ) -> Result<Self, BitwardenConfigError> {
        let mut exact = BTreeMap::new();
        for mapping in mappings {
            if mapping.reference.namespace() != namespace.as_str() {
                return Err(BitwardenConfigError::NamespaceMismatch {
                    reference: mapping.reference,
                });
            }
            if exact
                .insert(mapping.reference.clone(), mapping.locator)
                .is_some()
            {
                return Err(BitwardenConfigError::DuplicateMapping {
                    reference: mapping.reference,
                });
            }
        }
        Ok(Self {
            namespace,
            mappings: exact,
            backend,
        })
    }

    /// Returns the assigned ACF namespace.
    #[must_use]
    pub const fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// Returns the number of explicitly configured mappings.
    #[must_use]
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

#[async_trait]
impl<B: BitwardenBackend> SecretProvider for BitwardenProvider<B> {
    async fn get(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretError> {
        if reference.namespace() != self.namespace.as_str() {
            return Err(SecretError::NotAssigned {
                reference: reference.clone(),
            });
        }

        let locator =
            self.mappings
                .get(reference)
                .copied()
                .ok_or_else(|| SecretError::NotFound {
                    reference: reference.clone(),
                })?;

        let record = self
            .backend
            .fetch(locator)
            .await
            .map_err(|error| map_backend_error(reference, error))?;

        Ok(ResolvedSecret {
            material: record.material,
            version: record.version,
            // Bitwarden does not authenticate ACF's connector/origin binding.
            // The signed Config Registry remains authoritative.
            attested_binding: None,
        })
    }
}

fn map_backend_error(reference: &SecretRef, error: BitwardenBackendError) -> SecretError {
    match error {
        BitwardenBackendError::NotFound => SecretError::NotFound {
            reference: reference.clone(),
        },
        BitwardenBackendError::AuthenticationFailed => SecretError::AuthenticationFailed,
        BitwardenBackendError::Unavailable | BitwardenBackendError::UnsafeLoggingConfiguration => {
            SecretError::Unavailable
        }
        BitwardenBackendError::Timeout => SecretError::Timeout,
        BitwardenBackendError::Corrupted => SecretError::Corrupted,
    }
}

#[cfg(test)]
mod tests {
    use acf_secrets::Namespace;
    use uuid::Uuid;

    use super::*;

    struct UnusedBackend;

    #[async_trait]
    impl BitwardenBackend for UnusedBackend {
        async fn fetch(
            &self,
            _locator: BitwardenLocator,
        ) -> Result<crate::BitwardenRecord, BitwardenBackendError> {
            Err(BitwardenBackendError::Unavailable)
        }
    }

    fn mapping(reference: &str) -> SecretMapping {
        SecretMapping::new(
            SecretRef::parse(reference).unwrap(),
            BitwardenLocator {
                secret_id: Uuid::from_u128(1).into(),
                expected_project_id: None,
            },
        )
    }

    #[test]
    fn rejects_cross_namespace_mapping() {
        let error = BitwardenProvider::new(
            Namespace::new("enterprise").unwrap(),
            [mapping("secret://production/example/read")],
            UnusedBackend,
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            BitwardenConfigError::NamespaceMismatch { .. }
        ));
    }

    #[test]
    fn rejects_duplicate_logical_mapping() {
        let error = BitwardenProvider::new(
            Namespace::new("enterprise").unwrap(),
            [
                mapping("secret://enterprise/example/read"),
                mapping("secret://enterprise/example/read"),
            ],
            UnusedBackend,
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            BitwardenConfigError::DuplicateMapping { .. }
        ));
    }
}
