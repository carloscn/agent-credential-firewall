//! Logical secret references.
//!
//! A reference names a secret; it never contains one. Its `Display` form is
//! the `secret://` URI, which is visibly different from the redaction marker
//! printed for [`SecretMaterial`](crate::SecretMaterial).

use std::fmt;

use serde::{Deserialize, Serialize};

const SCHEME: &str = "secret://";
const MAX_NAMESPACE_LEN: usize = 63;
const MAX_REFERENCE_LEN: usize = 256;

/// Why a reference, namespace, or scope was rejected. Never echoes the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReferenceError {
    /// Missing the `secret://` scheme.
    #[error("secret reference must start with `secret://`")]
    MissingScheme,
    /// The namespace is empty, too long, or uses invalid characters.
    #[error("namespace must be 1-63 characters of [a-z0-9-], starting with a letter or digit")]
    InvalidNamespace,
    /// The path is empty or has an empty, `.`, `..`, or invalid segment.
    #[error("secret path segments must be non-empty [A-Za-z0-9._-] and not `.` or `..`")]
    InvalidPath,
    /// The reference exceeds the maximum length.
    #[error("secret reference exceeds {MAX_REFERENCE_LEN} bytes")]
    TooLong,
}

/// Provider namespace: the first component of a `secret://` reference, which
/// the provider registry maps to one provider.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Namespace(String);

impl Namespace {
    /// Validates a namespace.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceError::InvalidNamespace`] if the value is malformed.
    pub fn new(value: impl Into<String>) -> Result<Self, ReferenceError> {
        let value = value.into();
        if is_valid_namespace(&value) {
            Ok(Self(value))
        } else {
            Err(ReferenceError::InvalidNamespace)
        }
    }

    /// Returns the namespace as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Namespace {
    type Error = ReferenceError;

    fn try_from(value: String) -> Result<Self, ReferenceError> {
        Self::new(value)
    }
}

impl From<Namespace> for String {
    fn from(namespace: Namespace) -> Self {
        namespace.0
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAMESPACE_LEN
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A logical secret reference: `secret://<namespace>/<path>`.
///
/// Matching is exact and case-sensitive. A reference is never resolved by
/// prefix.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretRef {
    uri: String,
    /// Byte offset where the path starts (just after `namespace/`).
    path_start: usize,
}

impl SecretRef {
    /// Parses a `secret://` URI.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceError`] if the URI is malformed.
    pub fn parse(value: impl Into<String>) -> Result<Self, ReferenceError> {
        let uri = value.into();
        if uri.len() > MAX_REFERENCE_LEN {
            return Err(ReferenceError::TooLong);
        }
        let rest = uri
            .strip_prefix(SCHEME)
            .ok_or(ReferenceError::MissingScheme)?;
        let (namespace, path) = rest.split_once('/').ok_or(ReferenceError::InvalidPath)?;
        if !is_valid_namespace(namespace) {
            return Err(ReferenceError::InvalidNamespace);
        }
        if !path.split('/').all(is_valid_segment) {
            return Err(ReferenceError::InvalidPath);
        }
        let path_start = SCHEME.len() + namespace.len() + 1;
        Ok(Self { uri, path_start })
    }

    /// Returns the namespace component.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.uri[SCHEME.len()..self.path_start - 1]
    }

    /// Returns the path after the namespace, for example
    /// `cloudflare/example.com/dns-read`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.uri[self.path_start..]
    }

    /// Returns the full `secret://` URI.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.uri
    }
}

impl TryFrom<String> for SecretRef {
    type Error = ReferenceError;

    fn try_from(value: String) -> Result<Self, ReferenceError> {
        Self::parse(value)
    }
}

impl From<SecretRef> for String {
    fn from(reference: SecretRef) -> Self {
        reference.uri
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

/// Selects secrets for administrative metadata listing: one namespace,
/// optionally narrowed to a whole-segment path prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretScope {
    namespace: Namespace,
    prefix: Vec<String>,
}

impl SecretScope {
    /// Every secret in one namespace.
    #[must_use]
    pub fn namespace(namespace: Namespace) -> Self {
        Self {
            namespace,
            prefix: Vec::new(),
        }
    }

    /// Secrets whose path starts with `prefix`, compared segment by segment,
    /// so `cloudflare/ex` does not match `cloudflare/example.com/...`.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceError::InvalidPath`] if a prefix segment is malformed.
    pub fn with_prefix(namespace: Namespace, prefix: &str) -> Result<Self, ReferenceError> {
        let segments: Vec<String> = prefix.split('/').map(str::to_owned).collect();
        if !segments.iter().all(|s| is_valid_segment(s)) {
            return Err(ReferenceError::InvalidPath);
        }
        Ok(Self {
            namespace,
            prefix: segments,
        })
    }

    /// Returns whether `reference` falls inside this scope.
    #[must_use]
    pub fn contains(&self, reference: &SecretRef) -> bool {
        if reference.namespace() != self.namespace.as_str() {
            return false;
        }
        let mut path = reference.path().split('/');
        self.prefix
            .iter()
            .all(|expected| path.next() == Some(expected.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_design_example() {
        let reference =
            SecretRef::parse("secret://production/cloudflare/example.com/dns-read").unwrap();
        assert_eq!(reference.namespace(), "production");
        assert_eq!(reference.path(), "cloudflare/example.com/dns-read");
        assert_eq!(
            reference.to_string(),
            "secret://production/cloudflare/example.com/dns-read"
        );
    }

    #[test]
    fn rejects_malformed_references() {
        for (value, expected) in [
            ("production/cloudflare", ReferenceError::MissingScheme),
            ("secret://production", ReferenceError::InvalidPath),
            ("secret://production/", ReferenceError::InvalidPath),
            ("secret://production/a//b", ReferenceError::InvalidPath),
            ("secret://production/a/../b", ReferenceError::InvalidPath),
            ("secret://production/./b", ReferenceError::InvalidPath),
            ("secret://production/a/b/", ReferenceError::InvalidPath),
            ("secret://production/a%2Fb", ReferenceError::InvalidPath),
            ("secret://Production/a", ReferenceError::InvalidNamespace),
            ("secret://-prod/a", ReferenceError::InvalidNamespace),
            ("secret:///a", ReferenceError::InvalidNamespace),
        ] {
            assert_eq!(SecretRef::parse(value), Err(expected), "{value}");
        }
        let long = format!("secret://p/{}", "a".repeat(MAX_REFERENCE_LEN));
        assert_eq!(SecretRef::parse(long), Err(ReferenceError::TooLong));
    }

    #[test]
    fn scope_matches_whole_segments() {
        let ns = Namespace::new("production").unwrap();
        let scope = SecretScope::with_prefix(ns.clone(), "cloudflare/ex").unwrap();
        let reference =
            SecretRef::parse("secret://production/cloudflare/example.com/dns-read").unwrap();
        assert!(!scope.contains(&reference));

        let scope = SecretScope::with_prefix(ns.clone(), "cloudflare/example.com").unwrap();
        assert!(scope.contains(&reference));
        assert!(SecretScope::namespace(ns).contains(&reference));

        let other = SecretScope::namespace(Namespace::new("enterprise").unwrap());
        assert!(!other.contains(&reference));
    }
}
