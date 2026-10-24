//! In-memory provider for tests and the `development` deployment profile.
//!
//! Never production persistence. Release builds do not enable the
//! `in-memory` feature (design §13.4).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use async_trait::async_trait;

use crate::binding::SecretUseBinding;
use crate::material::{ResolvedSecret, SecretMaterial};
use crate::provider::{SecretAdmin, SecretError, SecretMetadata, SecretProvider, SecretVersion};
use crate::reference::{Namespace, SecretRef, SecretScope};

struct StoredSecret {
    material: SecretMaterial,
    version: SecretVersion,
    binding: SecretUseBinding,
}

/// A provider that keeps secrets in process memory.
///
/// It serves only the namespaces it was created with. Process memory is the
/// provider's own trusted storage, so it attests the stored use binding.
pub struct InMemoryProvider {
    namespaces: BTreeSet<Namespace>,
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<SecretRef, StoredSecret>,
    // Kept after delete so a re-created secret never reuses a version number.
    last_versions: BTreeMap<SecretRef, SecretVersion>,
}

impl InMemoryProvider {
    /// Creates an empty provider serving `namespaces`.
    #[must_use]
    pub fn new(namespaces: impl IntoIterator<Item = Namespace>) -> Self {
        Self {
            namespaces: namespaces.into_iter().collect(),
            state: RwLock::new(State::default()),
        }
    }

    fn check_assigned(&self, reference: &SecretRef) -> Result<(), SecretError> {
        if self
            .namespaces
            .iter()
            .any(|ns| ns.as_str() == reference.namespace())
        {
            Ok(())
        } else {
            Err(SecretError::NotAssigned {
                reference: reference.clone(),
            })
        }
    }
}

#[async_trait]
impl SecretProvider for InMemoryProvider {
    async fn get(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretError> {
        self.check_assigned(reference)?;
        // A poisoned lock means a writer panicked mid-update; fail closed.
        let state = self.state.read().map_err(|_| SecretError::Unavailable)?;
        let stored = state
            .entries
            .get(reference)
            .ok_or_else(|| SecretError::NotFound {
                reference: reference.clone(),
            })?;
        // `to_vec` allocates exactly `len` bytes, so `from_bytes` takes the
        // buffer without reallocating; the copy is zeroized when dropped.
        Ok(ResolvedSecret {
            material: SecretMaterial::from_bytes(stored.material.expose_secret().to_vec()),
            version: stored.version,
            attested_binding: Some(stored.binding.clone()),
        })
    }
}

#[async_trait]
impl SecretAdmin for InMemoryProvider {
    async fn put(
        &self,
        reference: &SecretRef,
        material: SecretMaterial,
        binding: SecretUseBinding,
    ) -> Result<SecretVersion, SecretError> {
        self.check_assigned(reference)?;
        let mut state = self.state.write().map_err(|_| SecretError::Unavailable)?;
        let version = match state.last_versions.get(reference) {
            None => SecretVersion::FIRST,
            Some(last) => last.next().ok_or_else(|| SecretError::VersionOverflow {
                reference: reference.clone(),
            })?,
        };
        state.last_versions.insert(reference.clone(), version);
        state.entries.insert(
            reference.clone(),
            StoredSecret {
                material,
                version,
                binding,
            },
        );
        Ok(version)
    }

    async fn delete(&self, reference: &SecretRef) -> Result<(), SecretError> {
        self.check_assigned(reference)?;
        let mut state = self.state.write().map_err(|_| SecretError::Unavailable)?;
        state
            .entries
            .remove(reference)
            .map(drop)
            .ok_or_else(|| SecretError::NotFound {
                reference: reference.clone(),
            })
    }

    async fn list_metadata(&self, scope: &SecretScope) -> Result<Vec<SecretMetadata>, SecretError> {
        let state = self.state.read().map_err(|_| SecretError::Unavailable)?;
        Ok(state
            .entries
            .iter()
            .filter(|(reference, _)| scope.contains(reference))
            .map(|(reference, stored)| SecretMetadata {
                reference: reference.clone(),
                version: stored.version,
                binding: stored.binding.clone(),
            })
            .collect())
    }
}
