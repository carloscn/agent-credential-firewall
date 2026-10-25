//! Filesystem-backed encrypted provider demo.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use acf_secrets::{
    Namespace, ResolvedSecret, SecretAdmin, SecretError, SecretMaterial, SecretMetadata,
    SecretProvider, SecretRef, SecretScope, SecretUseBinding, SecretVersion,
};
use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{DerivedKeys, FORMAT_VERSION, NONCE_LEN, RecordEnvelope, RecordMetadata};

const HEADER_FILE: &str = "store.acf";
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// A 256-bit demo store root key.
///
/// The key is accepted only as protected [`SecretMaterial`], is redacted on
/// `Debug`, and is zeroized on drop. Production deployments should unwrap an
/// equivalent key through a dedicated key source rather than constructing it
/// inside an agent-visible process.
pub struct LocalStoreKey(Zeroizing<[u8; 32]>);

impl LocalStoreKey {
    /// Consumes exactly 32 bytes of protected key material.
    ///
    /// # Errors
    ///
    /// Returns [`LocalProviderConfigError::InvalidKeyLength`] for any other
    /// size without reporting the supplied length.
    #[allow(clippy::needless_pass_by_value)] // callers relinquish the bootstrap plaintext
    pub fn from_material(material: SecretMaterial) -> Result<Self, LocalProviderConfigError> {
        if material.expose_secret().len() != 32 {
            return Err(LocalProviderConfigError::InvalidKeyLength);
        }
        let mut bytes = Zeroizing::new([0_u8; 32]);
        bytes.copy_from_slice(material.expose_secret());
        Ok(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for LocalStoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalStoreKey([REDACTED])")
    }
}

/// Safe-to-report initialization and open errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LocalProviderConfigError {
    /// The supplied root key is not 256 bits.
    #[error("local store key must be 32 bytes")]
    InvalidKeyLength,
    /// Initialization requires a new directory.
    #[error("local store directory already exists")]
    AlreadyExists,
    /// The store directory or header is absent.
    #[error("local store is not initialized")]
    NotInitialized,
    /// A symlink, non-directory, non-file, or broad Unix mode was found.
    #[error("local store filesystem permissions or object type are unsafe")]
    UnsafeFilesystem,
    /// The header is malformed or belongs to another namespace.
    #[error("local store header is invalid")]
    InvalidHeader,
    /// The key cannot authenticate this store.
    #[error("local store key was rejected")]
    KeyRejected,
    /// The filesystem operation failed; paths are deliberately omitted.
    #[error("local store filesystem operation failed")]
    Unavailable,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreHeader {
    format_version: u8,
    namespace: Namespace,
    key_check: Vec<u8>,
}

/// Simple encrypted local provider for demonstrations and integration tests.
///
/// Each record uses AES-256-GCM with a random 96-bit nonce. Logical references
/// are converted to HMAC-derived opaque filenames. Version and use-binding
/// metadata are plaintext but authenticated; secret values are encrypted.
/// Writes use an in-process mutex and atomic rename.
///
/// This is **not** the production provider described in the design document:
/// it has one process-held root key instead of KEK/per-record DEKs, no external
/// rollback anchor, no cross-process writer lock, and no durable directory
/// recovery protocol. It must not be represented as rollback-resistant.
pub struct DemoLocalProvider {
    root: PathBuf,
    namespace: Namespace,
    keys: DerivedKeys,
    writer: Mutex<()>,
}

impl DemoLocalProvider {
    /// Creates a new mode-0700 store and authenticated header.
    ///
    /// # Errors
    ///
    /// Fails if `root` already exists or cannot be created safely.
    pub fn initialize(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: LocalStoreKey,
    ) -> Result<Self, LocalProviderConfigError> {
        let root = root.as_ref();
        create_store_directory(root)?;
        let keys = DerivedKeys::new(key, namespace.as_str());
        let header = StoreHeader {
            format_version: FORMAT_VERSION,
            namespace: namespace.clone(),
            key_check: keys.key_check(namespace.as_str()),
        };
        write_new_file(&root.join(HEADER_FILE), &serialize(&header)?)?;
        sync_directory(root).map_err(|_| LocalProviderConfigError::Unavailable)?;
        Ok(Self {
            root: root.to_path_buf(),
            namespace,
            keys,
            writer: Mutex::new(()),
        })
    }

    /// Opens an initialized store and authenticates its key and namespace.
    ///
    /// # Errors
    ///
    /// Rejects unsafe filesystem objects, malformed headers, and wrong keys.
    pub fn open(
        root: impl AsRef<Path>,
        namespace: Namespace,
        key: LocalStoreKey,
    ) -> Result<Self, LocalProviderConfigError> {
        let root = root.as_ref();
        validate_store_directory(root)?;
        let header_path = root.join(HEADER_FILE);
        validate_regular_file(&header_path)?;
        let bytes = fs::read(&header_path).map_err(|error| map_config_io(&error))?;
        let header: StoreHeader =
            serde_json::from_slice(&bytes).map_err(|_| LocalProviderConfigError::InvalidHeader)?;
        if header.format_version != FORMAT_VERSION || header.namespace != namespace {
            return Err(LocalProviderConfigError::InvalidHeader);
        }
        let keys = DerivedKeys::new(key, namespace.as_str());
        keys.verify_key_check(namespace.as_str(), &header.key_check)
            .map_err(|_| LocalProviderConfigError::KeyRejected)?;
        Ok(Self {
            root: root.to_path_buf(),
            namespace,
            keys,
            writer: Mutex::new(()),
        })
    }

    fn record_path(&self, reference: &SecretRef) -> PathBuf {
        self.root.join(self.keys.record_name(reference))
    }

    fn ensure_namespace(&self, reference: &SecretRef) -> Result<(), SecretError> {
        if reference.namespace() == self.namespace.as_str() {
            Ok(())
        } else {
            Err(SecretError::NotAssigned {
                reference: reference.clone(),
            })
        }
    }

    fn read_verified(&self, path: &Path) -> Result<RecordEnvelope, ReadError> {
        let metadata = fs::symlink_metadata(path).map_err(|error| ReadError::from_io(&error))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(ReadError::Corrupted);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ReadError::Corrupted);
            }
        }
        let bytes = fs::read(path).map_err(|error| ReadError::from_io(&error))?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ReadError::Corrupted);
        }
        let envelope: RecordEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| ReadError::Corrupted)?;
        self.keys
            .verify(&envelope)
            .map_err(|_| ReadError::Corrupted)?;
        Ok(envelope)
    }

    fn write_envelope(&self, path: &Path, envelope: &RecordEnvelope) -> Result<(), SecretError> {
        let bytes = serde_json::to_vec(envelope).map_err(|_| SecretError::Corrupted)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(SecretError::Corrupted);
        }
        atomic_replace(&self.root, path, &bytes).map_err(|_| SecretError::Unavailable)
    }
}

#[async_trait]
impl SecretProvider for DemoLocalProvider {
    async fn get(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretError> {
        self.ensure_namespace(reference)?;
        let envelope = self
            .read_verified(&self.record_path(reference))
            .map_err(|error| error.for_reference(reference))?;
        if envelope.metadata.reference != *reference {
            return Err(SecretError::Corrupted);
        }
        if envelope.metadata.deleted {
            return Err(SecretError::NotFound {
                reference: reference.clone(),
            });
        }
        let version = envelope.metadata.version;
        let binding = envelope.metadata.binding.clone();
        let plaintext = self
            .keys
            .open(envelope)
            .map_err(|_| SecretError::Corrupted)?;
        Ok(ResolvedSecret {
            material: SecretMaterial::from_bytes(plaintext),
            version,
            attested_binding: Some(binding),
        })
    }
}

#[async_trait]
impl SecretAdmin for DemoLocalProvider {
    async fn put(
        &self,
        reference: &SecretRef,
        material: SecretMaterial,
        binding: SecretUseBinding,
    ) -> Result<SecretVersion, SecretError> {
        self.ensure_namespace(reference)?;
        if material.expose_secret().len() > MAX_SECRET_BYTES {
            return Err(SecretError::Corrupted);
        }
        let _guard = self.writer.lock().map_err(|_| SecretError::Corrupted)?;
        let path = self.record_path(reference);
        let version = match self.read_verified(&path) {
            Ok(old) => {
                if old.metadata.reference != *reference {
                    return Err(SecretError::Corrupted);
                }
                old.metadata
                    .version
                    .next()
                    .ok_or_else(|| SecretError::VersionOverflow {
                        reference: reference.clone(),
                    })?
            }
            Err(ReadError::Missing) => SecretVersion::FIRST,
            Err(error) => return Err(error.for_reference(reference)),
        };
        let metadata = RecordMetadata {
            format_version: FORMAT_VERSION,
            reference: reference.clone(),
            version,
            binding,
            deleted: false,
        };
        let mut nonce = [0_u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SecretError::Unavailable)?;
        let envelope = self
            .keys
            .seal(metadata, material.expose_secret(), nonce)
            .map_err(|_| SecretError::Corrupted)?;
        self.write_envelope(&path, &envelope)?;
        Ok(version)
    }

    async fn delete(&self, reference: &SecretRef) -> Result<(), SecretError> {
        self.ensure_namespace(reference)?;
        let _guard = self.writer.lock().map_err(|_| SecretError::Corrupted)?;
        let path = self.record_path(reference);
        let envelope = self
            .read_verified(&path)
            .map_err(|error| error.for_reference(reference))?;
        if envelope.metadata.reference != *reference {
            return Err(SecretError::Corrupted);
        }
        if envelope.metadata.deleted {
            return Err(SecretError::NotFound {
                reference: reference.clone(),
            });
        }
        let tombstone = self
            .keys
            .tombstone(envelope.metadata)
            .map_err(|_| SecretError::Corrupted)?;
        self.write_envelope(&path, &tombstone)
    }

    async fn list_metadata(&self, scope: &SecretScope) -> Result<Vec<SecretMetadata>, SecretError> {
        let mut result = Vec::new();
        let entries = fs::read_dir(&self.root).map_err(|_| SecretError::Unavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| SecretError::Unavailable)?;
            let name = entry.file_name();
            if !name.to_string_lossy().ends_with(".acf-record") {
                continue;
            }
            let envelope = self
                .read_verified(&entry.path())
                .map_err(ReadError::for_listing)?;
            if !envelope.metadata.deleted && scope.contains(&envelope.metadata.reference) {
                result.push(SecretMetadata {
                    reference: envelope.metadata.reference,
                    version: envelope.metadata.version,
                    binding: envelope.metadata.binding,
                });
            }
        }
        result.sort_by(|left, right| left.reference.cmp(&right.reference));
        Ok(result)
    }
}

#[derive(Clone, Copy)]
enum ReadError {
    Missing,
    Unavailable,
    Corrupted,
}

impl ReadError {
    fn from_io(error: &io::Error) -> Self {
        if error.kind() == io::ErrorKind::NotFound {
            Self::Missing
        } else {
            Self::Unavailable
        }
    }

    fn for_reference(self, reference: &SecretRef) -> SecretError {
        match self {
            Self::Missing => SecretError::NotFound {
                reference: reference.clone(),
            },
            Self::Unavailable => SecretError::Unavailable,
            Self::Corrupted => SecretError::Corrupted,
        }
    }

    fn for_listing(self) -> SecretError {
        match self {
            Self::Missing | Self::Corrupted => SecretError::Corrupted,
            Self::Unavailable => SecretError::Unavailable,
        }
    }
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, LocalProviderConfigError> {
    serde_json::to_vec(value).map_err(|_| LocalProviderConfigError::InvalidHeader)
}

fn map_config_io(error: &io::Error) -> LocalProviderConfigError {
    if error.kind() == io::ErrorKind::NotFound {
        LocalProviderConfigError::NotInitialized
    } else {
        LocalProviderConfigError::Unavailable
    }
}

#[cfg(unix)]
fn create_store_directory(path: &Path) -> Result<(), LocalProviderConfigError> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            LocalProviderConfigError::AlreadyExists
        } else {
            LocalProviderConfigError::Unavailable
        }
    })
}

#[cfg(not(unix))]
fn create_store_directory(path: &Path) -> Result<(), LocalProviderConfigError> {
    fs::create_dir(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            LocalProviderConfigError::AlreadyExists
        } else {
            LocalProviderConfigError::Unavailable
        }
    })
}

fn validate_store_directory(path: &Path) -> Result<(), LocalProviderConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| map_config_io(&error))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(LocalProviderConfigError::UnsafeFilesystem);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(LocalProviderConfigError::UnsafeFilesystem);
        }
    }
    Ok(())
}

fn validate_regular_file(path: &Path) -> Result<(), LocalProviderConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| map_config_io(&error))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(LocalProviderConfigError::UnsafeFilesystem);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(LocalProviderConfigError::UnsafeFilesystem);
        }
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), LocalProviderConfigError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| LocalProviderConfigError::Unavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| LocalProviderConfigError::Unavailable)
}

fn atomic_replace(root: &Path, destination: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut random = [0_u8; 8];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("random source unavailable"))?;
    let mut suffix = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(&mut suffix, "{byte:02x}").map_err(io::Error::other)?;
    }
    let temporary = root.join(format!(".record-{suffix}.tmp"));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    sync_directory(root)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
