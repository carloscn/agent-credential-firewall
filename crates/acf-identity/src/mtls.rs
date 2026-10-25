//! Certificate-based identity (ADR 0002).
//!
//! The TLS layer verifies the client chain against the configured client CA;
//! this provider then maps the verified leaf's SHA-256 thumbprint to an
//! enrolled device. Certificate names never grant identity.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use acf_protocol::{CertificateThumbprint, DeviceId, IssuerId, PrincipalId};
use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    ConnectionInfo, IdentityAssurance, IdentityContext, IdentityContextProvider, IdentityError,
    Label,
};

/// Schema identifier for device registries.
pub const DEVICE_REGISTRY_SCHEMA: &str = "acf.devices/v1";

/// The `x5t#S256` thumbprint of a DER certificate: unpadded base64url of its
/// SHA-256 digest.
#[must_use]
pub fn thumbprint(certificate_der: &[u8]) -> CertificateThumbprint {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let digest = ring::digest::digest(&ring::digest::SHA256, certificate_der);
    let bytes = digest.as_ref();
    let mut encoded = String::with_capacity(43);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let symbols = chunk.len() + 1;
        for i in 0..symbols {
            let index = (n >> (18 - 6 * i)) & 0x3f;
            encoded.push(char::from(ALPHABET[index as usize]));
        }
    }
    // 32 bytes always encode to a well-formed 43-character thumbprint.
    CertificateThumbprint::parse(encoded).unwrap_or_else(|_| unreachable!())
}

/// One enrolled device.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceEntry {
    /// Device identifier.
    pub device: DeviceId,
    /// Principal the device acts as.
    pub principal: PrincipalId,
    /// Trusted labels.
    #[serde(default)]
    pub labels: BTreeSet<Label>,
    /// Enrolled certificate thumbprints. More than one during rotation.
    pub certificates: BTreeSet<CertificateThumbprint>,
}

/// The device registry document.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistry {
    /// Must be [`DEVICE_REGISTRY_SCHEMA`].
    pub schema: String,
    /// Enrolled devices.
    pub devices: Vec<DeviceEntry>,
}

/// Why a registry was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// Wrong schema identifier.
    #[error("device registry schema must be `{DEVICE_REGISTRY_SCHEMA}`")]
    Schema,
    /// A device appears twice.
    #[error("device `{0}` is enrolled twice")]
    DuplicateDevice(String),
    /// A certificate is enrolled for more than one device.
    #[error("a certificate is enrolled for more than one device")]
    SharedCertificate,
    /// A device has no certificate.
    #[error("device `{0}` has no certificate")]
    NoCertificate(String),
}

type Index = BTreeMap<CertificateThumbprint, Arc<DeviceEntry>>;

fn index(registry: DeviceRegistry) -> Result<Index, RegistryError> {
    if registry.schema != DEVICE_REGISTRY_SCHEMA {
        return Err(RegistryError::Schema);
    }
    let mut devices = BTreeSet::new();
    let mut index = Index::new();
    for entry in registry.devices {
        if !devices.insert(entry.device.clone()) {
            return Err(RegistryError::DuplicateDevice(entry.device.to_string()));
        }
        if entry.certificates.is_empty() {
            return Err(RegistryError::NoCertificate(entry.device.to_string()));
        }
        let entry = Arc::new(entry);
        for certificate in &entry.certificates {
            if index
                .insert(certificate.clone(), Arc::clone(&entry))
                .is_some()
            {
                return Err(RegistryError::SharedCertificate);
            }
        }
    }
    Ok(index)
}

/// Resolves identity from the TLS-verified client certificate.
pub struct MtlsIdentityProvider {
    issuer: IssuerId,
    index: RwLock<Arc<Index>>,
}

impl MtlsIdentityProvider {
    /// Builds a provider from a validated registry.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] if the registry is inconsistent.
    pub fn new(issuer: IssuerId, registry: DeviceRegistry) -> Result<Self, RegistryError> {
        Ok(Self {
            issuer,
            index: RwLock::new(Arc::new(index(registry)?)),
        })
    }

    /// Replaces the registry, for certificate rotation and revocation of
    /// enrollment. An inconsistent registry is rejected and the current one
    /// stays in force.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] if the new registry is inconsistent.
    pub fn replace(&self, registry: DeviceRegistry) -> Result<(), RegistryError> {
        let next = Arc::new(index(registry)?);
        // A poisoned lock can only hold a complete index; recover it.
        let mut current = self
            .index
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = next;
        Ok(())
    }
}

#[async_trait]
impl IdentityContextProvider for MtlsIdentityProvider {
    fn assurance(&self) -> IdentityAssurance {
        IdentityAssurance::Production
    }

    async fn resolve(&self, connection: &ConnectionInfo) -> Result<IdentityContext, IdentityError> {
        let certificate = connection
            .verified_client_certificate
            .as_ref()
            .ok_or(IdentityError::Unauthenticated)?;
        let index = Arc::clone(
            &self
                .index
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let entry = index.get(certificate).ok_or(IdentityError::Unrecognized)?;
        Ok(IdentityContext {
            principal: entry.principal.clone(),
            device: Some(entry.device.clone()),
            labels: entry.labels.clone(),
            certificate: Some(certificate.clone()),
            issuer: self.issuer.clone(),
            assurance: IdentityAssurance::Production,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA256: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    fn registry(entries: Vec<DeviceEntry>) -> DeviceRegistry {
        DeviceRegistry {
            schema: DEVICE_REGISTRY_SCHEMA.to_owned(),
            devices: entries,
        }
    }

    fn entry(device: &str, certs: &[&str]) -> DeviceEntry {
        DeviceEntry {
            device: DeviceId::new(device).unwrap(),
            principal: PrincipalId::new(format!("workload:{device}")).unwrap(),
            labels: BTreeSet::new(),
            certificates: certs
                .iter()
                .map(|c| CertificateThumbprint::parse(*c).unwrap())
                .collect(),
        }
    }

    fn connection(thumbprint: &str) -> ConnectionInfo {
        ConnectionInfo {
            verified_client_certificate: Some(CertificateThumbprint::parse(thumbprint).unwrap()),
        }
    }

    #[test]
    fn thumbprint_matches_rfc8705_encoding() {
        assert_eq!(thumbprint(b"").as_str(), EMPTY_SHA256);
    }

    #[tokio::test]
    async fn resolves_enrolled_certificates_only() {
        let other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let provider = MtlsIdentityProvider::new(
            IssuerId::new("acf-gateway").unwrap(),
            registry(vec![entry("vps-17", &[EMPTY_SHA256])]),
        )
        .unwrap();
        let identity = provider.resolve(&connection(EMPTY_SHA256)).await.unwrap();
        assert_eq!(identity.principal.as_str(), "workload:vps-17");
        assert_eq!(identity.assurance, IdentityAssurance::Production);
        assert_eq!(
            provider.resolve(&connection(other)).await,
            Err(IdentityError::Unrecognized)
        );
        assert_eq!(
            provider.resolve(&ConnectionInfo::default()).await,
            Err(IdentityError::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn rotation_accepts_both_certificates_until_the_old_one_is_removed() {
        let new = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
        let provider = MtlsIdentityProvider::new(
            IssuerId::new("acf-gateway").unwrap(),
            registry(vec![entry("vps-17", &[EMPTY_SHA256, new])]),
        )
        .unwrap();
        assert!(provider.resolve(&connection(EMPTY_SHA256)).await.is_ok());
        assert!(provider.resolve(&connection(new)).await.is_ok());
        provider
            .replace(registry(vec![entry("vps-17", &[new])]))
            .unwrap();
        assert_eq!(
            provider.resolve(&connection(EMPTY_SHA256)).await,
            Err(IdentityError::Unrecognized)
        );
        assert!(provider.resolve(&connection(new)).await.is_ok());
    }

    #[test]
    fn inconsistent_registries_are_rejected() {
        assert_eq!(
            index(registry(vec![
                entry("a", &[EMPTY_SHA256]),
                entry("b", &[EMPTY_SHA256])
            ]))
            .unwrap_err(),
            RegistryError::SharedCertificate
        );
        assert_eq!(
            index(registry(vec![entry("a", &[EMPTY_SHA256]), entry("a", &[])])).unwrap_err(),
            RegistryError::DuplicateDevice("a".to_owned())
        );
        assert_eq!(
            index(registry(vec![entry("a", &[])])).unwrap_err(),
            RegistryError::NoCertificate("a".to_owned())
        );
        let wrong = DeviceRegistry {
            schema: "acf.devices/v2".to_owned(),
            devices: vec![],
        };
        assert_eq!(index(wrong).unwrap_err(), RegistryError::Schema);
    }
}
