//! Digest and thumbprint value types.

use std::fmt;

use serde::{Deserialize, Serialize};

const SHA256_PREFIX: &str = "sha256:";
const SHA256_HEX_LEN: usize = 64;
/// Unpadded base64url encoding of 32 bytes.
const THUMBPRINT_LEN: usize = 43;

/// A malformed digest or thumbprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    /// Not of the form `sha256:` followed by 64 lowercase hex digits.
    #[error("digest must be `sha256:` followed by 64 lowercase hex digits")]
    InvalidSha256,
    /// Not an unpadded base64url SHA-256 thumbprint.
    #[error("thumbprint must be 43 unpadded base64url characters")]
    InvalidThumbprint,
}

/// A SHA-256 digest written as `sha256:<64 lowercase hex digits>`.
///
/// Used for profile digests, approval digests, and job-definition digests.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Parses a digest string.
    ///
    /// # Errors
    ///
    /// Returns [`DigestError::InvalidSha256`] if the value is not well formed.
    pub fn parse(value: impl Into<String>) -> Result<Self, DigestError> {
        let value = value.into();
        let hex = value
            .strip_prefix(SHA256_PREFIX)
            .ok_or(DigestError::InvalidSha256)?;
        if hex.len() == SHA256_HEX_LEN
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value))
        } else {
            Err(DigestError::InvalidSha256)
        }
    }

    /// Returns the digest in its `sha256:` form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = DigestError;

    fn try_from(value: String) -> Result<Self, DigestError> {
        Self::parse(value)
    }
}

impl From<Sha256Digest> for String {
    fn from(digest: Sha256Digest) -> Self {
        digest.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// SHA-256 thumbprint of a DER-encoded X.509 certificate, unpadded base64url,
/// as used by the RFC 8705 `x5t#S256` confirmation claim.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CertificateThumbprint(String);

impl CertificateThumbprint {
    /// Parses a thumbprint string.
    ///
    /// # Errors
    ///
    /// Returns [`DigestError::InvalidThumbprint`] if the value is not well formed.
    pub fn parse(value: impl Into<String>) -> Result<Self, DigestError> {
        let value = value.into();
        // 43 characters encode 258 bits; the final character carries only
        // 4 significant bits, so its low 2 bits must be zero.
        let well_formed = value.len() == THUMBPRINT_LEN
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && value
                .bytes()
                .last()
                .and_then(base64url_value)
                .is_some_and(|v| v.trailing_zeros() >= 2);
        if well_formed {
            Ok(Self(value))
        } else {
            Err(DigestError::InvalidThumbprint)
        }
    }

    /// Returns the thumbprint string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn base64url_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

impl TryFrom<String> for CertificateThumbprint {
    type Error = DigestError;

    fn try_from(value: String) -> Result<Self, DigestError> {
        Self::parse(value)
    }
}

impl From<CertificateThumbprint> for String {
    fn from(thumbprint: CertificateThumbprint) -> Self {
        thumbprint.0
    }
}

impl fmt::Display for CertificateThumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_digest_validation() {
        let good = format!("sha256:{}", "ab01".repeat(16));
        assert!(Sha256Digest::parse(good).is_ok());
        for bad in [
            "sha256:".to_owned(),
            format!("sha256:{}", "AB01".repeat(16)),
            format!("sha512:{}", "ab01".repeat(16)),
            format!("sha256:{}", "ab01".repeat(15)),
            "ab01".repeat(16),
        ] {
            assert_eq!(Sha256Digest::parse(bad), Err(DigestError::InvalidSha256));
        }
    }

    #[test]
    fn thumbprint_validation() {
        // base64url(SHA-256("")) without padding.
        assert!(
            CertificateThumbprint::parse("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU").is_ok()
        );
        for bad in [
            "",
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFV",
        ] {
            assert_eq!(
                CertificateThumbprint::parse(bad),
                Err(DigestError::InvalidThumbprint),
                "{bad}"
            );
        }
    }
}
