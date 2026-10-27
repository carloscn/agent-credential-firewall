//! Where the store root key comes from (encrypted-local.md §5).
//!
//! Implemented sources deliver the 256-bit root key from a file that only
//! the gateway's service account can read: a systemd credential, or a file
//! mounted from a separately protected volume. TPM, KMS, and interactive
//! unlock are not implemented and are refused by the gateway.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use acf_secrets::SecretMaterial;
use zeroize::Zeroizing;

use crate::provider::LocalStoreKey;

/// Environment variable systemd sets for a service's credentials.
pub const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";

/// A configured source of the store root key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreKeySource {
    /// `$CREDENTIALS_DIRECTORY/<name>`, as provided by systemd
    /// `LoadCredential=` or `LoadCredentialEncrypted=`.
    SystemdCredential {
        /// Credential name.
        name: String,
    },
    /// A root-only file on a separately protected volume.
    MountedFile {
        /// Absolute path.
        path: PathBuf,
    },
    /// Any readable file. Development only: the file's permissions are not
    /// checked.
    InsecureFile {
        /// Path.
        path: PathBuf,
    },
}

/// Why the key could not be loaded. Never includes key bytes.
#[derive(Debug, thiserror::Error)]
pub enum KeySourceError {
    /// `CREDENTIALS_DIRECTORY` is not set: not running under systemd with a
    /// credential.
    #[error("{CREDENTIALS_DIRECTORY} is not set; load the key with systemd LoadCredential=")]
    NoCredentialsDirectory,
    /// The credential name is not a plain file name.
    #[error("credential name `{0}` must be a plain file name")]
    InvalidName(String),
    /// The path is not absolute.
    #[error("key file path must be absolute")]
    RelativePath,
    /// The file cannot be read.
    #[error("cannot read key file {0}")]
    Read(String),
    /// Not a regular file, or reachable through a symlink.
    #[error("key file {0} is not a regular file")]
    NotRegular(String),
    /// Group or others can access it.
    #[error("key file {0} must not be accessible by group or others (chmod 400)")]
    Permissions(String),
    /// Not exactly 32 bytes.
    #[error("key file {0} must hold exactly 32 bytes")]
    Length(String),
}

fn read_key_file(path: &Path, check_mode: bool) -> Result<LocalStoreKey, KeySourceError> {
    let name = path.display().to_string();
    let link = std::fs::symlink_metadata(path).map_err(|_| KeySourceError::Read(name.clone()))?;
    if !link.file_type().is_file() {
        return Err(KeySourceError::NotRegular(name));
    }
    let mut file = File::open(path).map_err(|_| KeySourceError::Read(name.clone()))?;
    let metadata = file
        .metadata()
        .map_err(|_| KeySourceError::Read(name.clone()))?;
    if check_mode && metadata.permissions().mode() & 0o077 != 0 {
        return Err(KeySourceError::Permissions(name));
    }
    if metadata.len() != 32 {
        return Err(KeySourceError::Length(name));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(32));
    file.read_to_end(&mut bytes)
        .map_err(|_| KeySourceError::Read(name.clone()))?;
    LocalStoreKey::from_material(SecretMaterial::from_bytes(bytes.to_vec()))
        .map_err(|_| KeySourceError::Length(name))
}

impl StoreKeySource {
    /// Loads the root key.
    ///
    /// # Errors
    ///
    /// Returns [`KeySourceError`] if the source is unavailable, the file is
    /// not a private regular file, or it does not hold exactly 32 bytes.
    pub fn load(&self) -> Result<LocalStoreKey, KeySourceError> {
        match self {
            Self::SystemdCredential { name } => {
                if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                    return Err(KeySourceError::InvalidName(name.clone()));
                }
                let directory = std::env::var_os(CREDENTIALS_DIRECTORY)
                    .map(PathBuf::from)
                    .filter(|dir| dir.is_absolute())
                    .ok_or(KeySourceError::NoCredentialsDirectory)?;
                read_key_file(&directory.join(name), true)
            }
            Self::MountedFile { path } => {
                if !path.is_absolute() {
                    return Err(KeySourceError::RelativePath);
                }
                read_key_file(path, true)
            }
            Self::InsecureFile { path } => read_key_file(path, false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    fn write(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        use std::io::Write as _;
        let path = dir.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn mounted_files_must_be_private_32_byte_regular_files() {
        let dir = std::env::temp_dir().join(format!("acf-keysource-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let good = write(&dir, "good.key", &[7; 32], 0o400);
        assert!(
            StoreKeySource::MountedFile { path: good.clone() }
                .load()
                .is_ok()
        );

        let readable = write(&dir, "readable.key", &[7; 32], 0o440);
        assert!(matches!(
            StoreKeySource::MountedFile {
                path: readable.clone()
            }
            .load(),
            Err(KeySourceError::Permissions(_))
        ));
        // The development source skips the mode check, nothing else.
        assert!(
            StoreKeySource::InsecureFile { path: readable }
                .load()
                .is_ok()
        );

        let short = write(&dir, "short.key", &[7; 31], 0o400);
        assert!(matches!(
            StoreKeySource::MountedFile { path: short }.load(),
            Err(KeySourceError::Length(_))
        ));
        let link = dir.join("link.key");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(matches!(
            StoreKeySource::MountedFile { path: link }.load(),
            Err(KeySourceError::NotRegular(_))
        ));
        assert!(matches!(
            StoreKeySource::MountedFile {
                path: PathBuf::from("relative.key")
            }
            .load(),
            Err(KeySourceError::RelativePath)
        ));
        for name in ["../good.key", "a/b", ".."] {
            assert!(matches!(
                StoreKeySource::SystemdCredential {
                    name: name.to_owned()
                }
                .load(),
                Err(KeySourceError::InvalidName(_))
            ));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
