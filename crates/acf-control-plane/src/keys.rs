//! Ed25519 keys: the authority's capability signer and job-definition
//! signatures (ADR 0003).

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use acf_identity::AuthorityKey;
use acf_protocol::{
    CAPABILITY_TYPE, CapabilityHeader, IssuerId, KeyId, SignatureAlgorithm, TaskCapabilityClaims,
    TokenError, base64url_decode, base64url_encode, encode_capability,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";

/// Why a key could not be loaded or used.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
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
    /// The capability could not be encoded.
    #[error("capability encoding failed: {0}")]
    Token(TokenError),
}

/// Reads a private key file, refusing one that group or others can access.
/// The mode is checked on the open handle.
///
/// # Errors
///
/// Returns [`KeyError`] if the file is unreadable, too permissive, or not an
/// Ed25519 PKCS#8 PEM key.
pub fn read_key_pair(path: &Path) -> Result<Ed25519KeyPair, KeyError> {
    let name = path.display().to_string();
    let mut file = File::open(path).map_err(|_| KeyError::Read(name.clone()))?;
    let metadata = file.metadata().map_err(|_| KeyError::Read(name.clone()))?;
    if !metadata.is_file() {
        return Err(KeyError::Read(name));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(KeyError::Permissions(name));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|_| KeyError::Read(name.clone()))?;
    parse_key_pair(&text).ok_or(KeyError::Format(name))
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
/// Returns [`KeyError::Random`] if the random source fails.
pub fn generate_pem() -> Result<String, KeyError> {
    let document =
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| KeyError::Random)?;
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

/// Signs capabilities for one issuer with one key.
pub struct CapabilitySigner {
    issuer: IssuerId,
    kid: KeyId,
    pair: Ed25519KeyPair,
}

impl std::fmt::Debug for CapabilitySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilitySigner")
            .field("issuer", &self.issuer)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl CapabilitySigner {
    /// A signer for `issuer` using `pair` under `kid`.
    #[must_use]
    pub fn new(issuer: IssuerId, kid: KeyId, pair: Ed25519KeyPair) -> Self {
        Self { issuer, kid, pair }
    }

    /// The issuer this signer signs for.
    #[must_use]
    pub fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// The trust-store entry gateways need to verify this signer.
    #[must_use]
    pub fn trust_entry(&self) -> AuthorityKey {
        AuthorityKey {
            kid: self.kid.clone(),
            issuer: self.issuer.clone(),
            alg: SignatureAlgorithm::EdDsa,
            public_key: public_key(&self.pair),
        }
    }

    /// Signs `claims`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Token`] if the claims cannot be encoded.
    pub fn sign(&self, claims: &TaskCapabilityClaims) -> Result<String, KeyError> {
        let header = CapabilityHeader {
            alg: SignatureAlgorithm::EdDsa,
            typ: CAPABILITY_TYPE.to_owned(),
            kid: self.kid.clone(),
        };
        encode_capability(&header, claims, |input| {
            self.pair.sign(input).as_ref().to_vec()
        })
        .map_err(KeyError::Token)
    }
}

/// A detached job-definition signature (`<file>.sig`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    /// Signing key.
    pub kid: KeyId,
    /// Unpadded base64url Ed25519 signature over the exact file bytes.
    pub signature: String,
}

/// Signs `bytes` with `pair` under `kid`.
#[must_use]
pub fn sign_detached(kid: KeyId, pair: &Ed25519KeyPair, bytes: &[u8]) -> DetachedSignature {
    DetachedSignature {
        kid,
        signature: base64url_encode(pair.sign(bytes).as_ref()),
    }
}

/// Whether `signature` is a valid signature of `bytes` by `public_key`
/// (unpadded base64url, 32 bytes).
#[must_use]
pub fn verify_detached(public_key: &str, bytes: &[u8], signature: &DetachedSignature) -> bool {
    let (Ok(key), Ok(signature)) = (
        base64url_decode(public_key),
        base64url_decode(&signature.signature),
    ) else {
        return false;
    };
    key.len() == 32
        && UnparsedPublicKey::new(&ED25519, key)
            .verify(bytes, &signature)
            .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip_through_pem() {
        let pem = generate_pem().unwrap();
        let pair = parse_key_pair(&pem).unwrap();
        assert_eq!(public_key(&pair).len(), 43);
        assert!(parse_key_pair(&pem.replace("PRIVATE KEY", "PUBLIC KEY")).is_none());
        assert!(parse_key_pair("garbage").is_none());
    }

    #[test]
    fn detached_signatures_cover_the_exact_bytes() {
        let pair = parse_key_pair(&generate_pem().unwrap()).unwrap();
        let kid = KeyId::new("admin").unwrap();
        let signature = sign_detached(kid, &pair, b"job: a\n");
        assert!(verify_detached(&public_key(&pair), b"job: a\n", &signature));
        assert!(!verify_detached(
            &public_key(&pair),
            b"job: b\n",
            &signature
        ));
        let other = parse_key_pair(&generate_pem().unwrap()).unwrap();
        assert!(!verify_detached(
            &public_key(&other),
            b"job: a\n",
            &signature
        ));
    }
}
