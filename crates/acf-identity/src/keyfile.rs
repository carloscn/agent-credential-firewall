//! Ed25519 private key files (PKCS#8 PEM), shared by every component that
//! signs: the Capability Authority (ADR 0003), configuration admission
//! (ADR 0004), and gateway audit checkpoints (ADR 0005). Keys are read only
//! from files that group and others cannot access.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use acf_protocol::base64url_encode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";

/// Why a key file could not be loaded or a key generated.
#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    /// The key file could not be read.
    #[error("cannot read {0}")]
    Read(String),
    /// The key file is accessible by group or others.
    #[error("{0} must not be accessible by group or others (chmod 600)")]
    Permissions(String),
    /// Not an Ed25519 PKCS#8 PEM private key.
    #[error("{0} is not an Ed25519 PKCS#8 PEM private key")]
    Format(String),
    /// No random source.
    #[error("no secure random source available")]
    Random,
}

/// Reads a private key file, refusing one that group or others can access.
/// The mode is checked on the open handle.
///
/// # Errors
///
/// Returns [`KeyFileError`] if the file is unreadable, too permissive, or not an
/// Ed25519 PKCS#8 PEM key.
pub fn read_key_pair(path: &Path) -> Result<Ed25519KeyPair, KeyFileError> {
    let name = path.display().to_string();
    let mut file = File::open(path).map_err(|_| KeyFileError::Read(name.clone()))?;
    let metadata = file
        .metadata()
        .map_err(|_| KeyFileError::Read(name.clone()))?;
    if !metadata.is_file() {
        return Err(KeyFileError::Read(name));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(KeyFileError::Permissions(name));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|_| KeyFileError::Read(name.clone()))?;
    parse_key_pair(&text).ok_or(KeyFileError::Format(name))
}

/// Parses an Ed25519 PKCS#8 (v1 or v2) PEM private key.
#[must_use]
pub fn parse_key_pair(pem: &str) -> Option<Ed25519KeyPair> {
    let body = pem
        .trim()
        .strip_prefix(PEM_BEGIN)?
        .strip_suffix(PEM_END)?
        .split_whitespace()
        .collect::<String>();
    let der = STANDARD.decode(body).ok()?;
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).ok()
}

/// Generates a new Ed25519 key as PKCS#8 PEM.
///
/// # Errors
///
/// Returns [`KeyFileError::Random`] if the random source fails.
pub fn generate_pem() -> Result<String, KeyFileError> {
    let document =
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| KeyFileError::Random)?;
    let encoded = STANDARD.encode(document.as_ref());
    let mut pem = String::from(PEM_BEGIN);
    pem.push('\n');
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str(PEM_END);
    pem.push('\n');
    Ok(pem)
}

/// The unpadded base64url raw public key of `pair`.
#[must_use]
pub fn public_key(pair: &Ed25519KeyPair) -> String {
    base64url_encode(pair.public_key().as_ref())
}
