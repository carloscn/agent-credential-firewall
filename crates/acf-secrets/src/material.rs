//! Protected secret material.

use std::fmt;

use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretBox};

use crate::binding::SecretUseBinding;
use crate::provider::SecretVersion;

/// Plaintext secret bytes.
///
/// The buffer is zeroized on drop. `Debug` prints a fixed redaction marker and
/// never the value or its length. The type deliberately does not implement
/// `Clone`, `Display`, or `Serialize`:
///
/// ```compile_fail,E0277
/// fn require_clone<T: Clone>() {}
/// require_clone::<acf_secrets::SecretMaterial>();
/// ```
///
/// ```compile_fail,E0277
/// let material = acf_secrets::SecretMaterial::from_bytes(b"x".to_vec());
/// let _ = format!("{material}");
/// ```
///
/// ```compile_fail,E0277
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<acf_secrets::SecretMaterial>();
/// ```
///
/// A serializable response type therefore cannot contain secret material:
///
/// ```compile_fail,E0277
/// #[derive(serde::Serialize)]
/// struct LeakyResponse {
///     body: acf_secrets::SecretMaterial,
/// }
/// ```
pub struct SecretMaterial(SecretBox<[u8]>);

impl SecretMaterial {
    /// Takes ownership of plaintext bytes.
    ///
    /// If the vector has spare capacity, the bytes are copied into an exactly
    /// sized buffer and the original allocation is zeroized, so no plaintext
    /// is left behind in freed memory.
    #[must_use]
    pub fn from_bytes(mut bytes: Vec<u8>) -> Self {
        let boxed: Box<[u8]> = if bytes.len() == bytes.capacity() {
            bytes.into_boxed_slice()
        } else {
            let exact = Box::<[u8]>::from(bytes.as_slice());
            bytes.zeroize();
            exact
        };
        Self(SecretBox::new(boxed))
    }

    /// Takes ownership of a plaintext string.
    #[must_use]
    pub fn from_string(value: String) -> Self {
        Self::from_bytes(value.into_bytes())
    }

    /// Borrows the plaintext bytes.
    ///
    /// Every call site is a plaintext boundary and should be easy to find by
    /// searching for `expose_secret`.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretMaterial([REDACTED])")
    }
}

/// The result of a runtime secret lookup.
///
/// Like [`SecretMaterial`], it is neither `Clone` nor `Serialize`:
///
/// ```compile_fail,E0277
/// fn require_clone<T: Clone>() {}
/// require_clone::<acf_secrets::ResolvedSecret>();
/// ```
#[derive(Debug)]
pub struct ResolvedSecret {
    /// The secret value.
    pub material: SecretMaterial,
    /// Version of the stored secret.
    pub version: SecretVersion,
    /// Present only when the provider stores authenticated use-binding
    /// metadata. The gateway requires it to be within the registry binding.
    pub attested_binding: Option<SecretUseBinding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "ACF-CANARY-5d1e0b7c";

    #[test]
    fn debug_is_redacted() {
        let material = SecretMaterial::from_string(CANARY.to_owned());
        let debug = format!("{material:?}");
        assert_eq!(debug, "SecretMaterial([REDACTED])");
        assert!(!debug.contains(CANARY));
    }

    #[test]
    fn round_trips_bytes() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(CANARY.as_bytes());
        let material = SecretMaterial::from_bytes(bytes);
        assert_eq!(material.expose_secret(), CANARY.as_bytes());

        let exact = SecretMaterial::from_bytes(CANARY.as_bytes().to_vec());
        assert_eq!(exact.expose_secret(), CANARY.as_bytes());
    }
}
