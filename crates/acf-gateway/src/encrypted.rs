//! Opens configured encrypted local stores (encrypted-local.md) for the
//! gateway and the `acf-store` administration tool.
//!
//! The store provides integrity and per-record encryption, not rollback
//! resistance: no rollback anchor is implemented, so a configured anchor is
//! refused rather than silently ignored (design §14.2).

use std::path::PathBuf;

use acf_config::{KeySourceKind, SecretProviderConfig};
use acf_provider_local::{DemoLocalProvider, LocalProviderConfigError, StoreKeySource};
use acf_secrets::Namespace;

/// The store location and key source for one encrypted-local namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedStore {
    /// Namespace the store serves.
    pub namespace: Namespace,
    /// Store directory.
    pub path: PathBuf,
    /// Where the root key comes from.
    pub key: StoreKeySource,
}

impl EncryptedStore {
    /// Resolves `provider` for `namespace`. Refuses what this build cannot
    /// honor: rollback anchors and the TPM, KMS, and interactive key sources.
    ///
    /// # Errors
    ///
    /// Returns a message naming the namespace and the unsupported setting.
    pub fn from_config(
        namespace: &Namespace,
        provider: &SecretProviderConfig,
    ) -> Result<Self, String> {
        let SecretProviderConfig::EncryptedLocal {
            path,
            key_source,
            key_location,
            rollback_anchor,
            ..
        } = provider
        else {
            return Err(format!(
                "secret_providers.{namespace} is not an encrypted-local provider"
            ));
        };
        if rollback_anchor.is_some() {
            return Err(format!(
                "secret_providers.{namespace}: rollback anchors are not implemented; the store provides integrity only. Acknowledge with `rollback_resistance: none`"
            ));
        }
        let location = key_location.clone();
        let key = match key_source {
            KeySourceKind::SystemdCredential => StoreKeySource::SystemdCredential {
                name: location.unwrap_or_else(|| format!("acf-store-{namespace}")),
            },
            KeySourceKind::MountedFile => StoreKeySource::MountedFile {
                path: location.unwrap_or_default().into(),
            },
            KeySourceKind::InsecureDevelopment => StoreKeySource::InsecureFile {
                path: location.unwrap_or_default().into(),
            },
            KeySourceKind::Tpm | KeySourceKind::Kms | KeySourceKind::Interactive => {
                return Err(format!(
                    "secret_providers.{namespace}: key source {key_source:?} is not implemented in this build"
                ));
            }
        };
        Ok(Self {
            namespace: namespace.clone(),
            path: PathBuf::from(path),
            key,
        })
    }

    /// Opens an existing store.
    ///
    /// # Errors
    ///
    /// Returns a message if the key cannot be loaded or the store is
    /// missing, unsafe, or does not accept the key.
    pub fn open(&self) -> Result<DemoLocalProvider, String> {
        let key = self
            .key
            .load()
            .map_err(|e| format!("secret_providers.{}: {e}", self.namespace))?;
        DemoLocalProvider::open(&self.path, self.namespace.clone(), key).map_err(|e| match e {
            LocalProviderConfigError::NotInitialized => format!(
                "secret_providers.{}: no store at {}; create it with `acf-store init`",
                self.namespace,
                self.path.display()
            ),
            other => format!("secret_providers.{}: {other}", self.namespace),
        })
    }

    /// Creates the store.
    ///
    /// # Errors
    ///
    /// Returns a message if the key cannot be loaded or the directory
    /// already exists or cannot be created.
    pub fn initialize(&self) -> Result<DemoLocalProvider, String> {
        let key = self
            .key
            .load()
            .map_err(|e| format!("secret_providers.{}: {e}", self.namespace))?;
        DemoLocalProvider::initialize(&self.path, self.namespace.clone(), key)
            .map_err(|e| format!("{}: {e}", self.path.display()))
    }

    /// One line for the startup log.
    #[must_use]
    pub fn describe(&self) -> String {
        let key = match &self.key {
            StoreKeySource::SystemdCredential { name } => format!("systemd credential `{name}`"),
            StoreKeySource::MountedFile { path } => format!("mounted file {}", path.display()),
            StoreKeySource::InsecureFile { path } => {
                format!("INSECURE development file {}", path.display())
            }
        };
        format!(
            "secret provider `{}`: encrypted-local at {} (key: {key}); integrity only, no rollback resistance",
            self.namespace,
            self.path.display()
        )
    }
}
