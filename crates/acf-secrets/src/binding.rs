//! Secret use bindings (design §8.4).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

const MAX_NAME_LEN: usize = 63;

/// Why a use binding or one of its parts was rejected. Never echoes input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    /// A connector, slot, or environment name is malformed.
    #[error("{kind} must be 1-63 characters of [a-z0-9_-], starting with a letter")]
    InvalidName {
        /// Name kind.
        kind: &'static str,
    },
    /// An origin is not `http(s)://host[:port]` with no path or user info.
    #[error("origin must be `http://` or `https://` followed by a host and optional port only")]
    InvalidOrigin,
    /// A binding listed no connectors or no origins.
    #[error("a use binding needs at least one connector and one origin")]
    Empty,
}

fn is_valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_LEN
        && value.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

macro_rules! define_name {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates a name.
            ///
            /// # Errors
            ///
            /// Returns [`BindingError::InvalidName`] if the value is malformed.
            pub fn new(value: impl Into<String>) -> Result<Self, BindingError> {
                let value = value.into();
                if is_valid_name(&value) {
                    Ok(Self(value))
                } else {
                    Err(BindingError::InvalidName { kind: stringify!($name) })
                }
            }

            /// Returns the name as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = BindingError;

            fn try_from(value: String) -> Result<Self, BindingError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(name: $name) -> Self {
                name.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

define_name!(
    /// Connector name, for example `cloudflare`.
    ConnectorName
);
define_name!(
    /// Credential slot, for example `read` or `write`.
    AuthSlot
);
define_name!(
    /// Deployment environment, for example `production`.
    Environment
);

/// A canonical web origin: lowercase scheme and host, explicit port only when
/// it is not the scheme's default.
///
/// `HTTPS://API.Cloudflare.com:443` and `https://api.cloudflare.com` are the
/// same origin.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Origin(String);

impl Origin {
    /// Parses and canonicalizes an origin.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError::InvalidOrigin`] if the value is not a bare
    /// `http(s)://host[:port]` origin.
    pub fn parse(value: &str) -> Result<Self, BindingError> {
        let (scheme, rest) = value.split_once("://").ok_or(BindingError::InvalidOrigin)?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "https" => 443,
            "http" => 80,
            _ => return Err(BindingError::InvalidOrigin),
        };
        if rest.is_empty()
            || rest
                .bytes()
                .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\'))
        {
            return Err(BindingError::InvalidOrigin);
        }

        let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
            let (inner, after) = bracketed
                .split_once(']')
                .ok_or(BindingError::InvalidOrigin)?;
            if inner.is_empty()
                || !inner
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
            {
                return Err(BindingError::InvalidOrigin);
            }
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':').ok_or(BindingError::InvalidOrigin)?),
            };
            (format!("[{}]", inner.to_ascii_lowercase()), port)
        } else {
            let (host, port) = match rest.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (rest, None),
            };
            let host = host.to_ascii_lowercase();
            let valid_host = !host.is_empty()
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                });
            if !valid_host {
                return Err(BindingError::InvalidOrigin);
            }
            (host, port)
        };

        let port = match port {
            None => None,
            Some(p) => {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(BindingError::InvalidOrigin);
                }
                let number: u16 = p.parse().map_err(|_| BindingError::InvalidOrigin)?;
                if number == 0 {
                    return Err(BindingError::InvalidOrigin);
                }
                (number != default_port).then_some(number)
            }
        };

        Ok(Self(match port {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}"),
        }))
    }

    /// Returns the canonical origin string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Origin {
    type Error = BindingError;

    fn try_from(value: String) -> Result<Self, BindingError> {
        Self::parse(&value)
    }
}

impl From<Origin> for String {
    fn from(origin: Origin) -> Self {
        origin.0
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a secret may be used: which connectors, which destination origins,
/// which credential slot, and which environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawUseBinding")]
pub struct SecretUseBinding {
    connectors: BTreeSet<ConnectorName>,
    origins: BTreeSet<Origin>,
    auth_slot: AuthSlot,
    environment: Environment,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUseBinding {
    connectors: BTreeSet<ConnectorName>,
    origins: BTreeSet<Origin>,
    auth_slot: AuthSlot,
    environment: Environment,
}

impl TryFrom<RawUseBinding> for SecretUseBinding {
    type Error = BindingError;

    fn try_from(raw: RawUseBinding) -> Result<Self, BindingError> {
        Self::new(raw.connectors, raw.origins, raw.auth_slot, raw.environment)
    }
}

impl SecretUseBinding {
    /// Builds a binding.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError::Empty`] if no connector or no origin is given.
    pub fn new(
        connectors: BTreeSet<ConnectorName>,
        origins: BTreeSet<Origin>,
        auth_slot: AuthSlot,
        environment: Environment,
    ) -> Result<Self, BindingError> {
        if connectors.is_empty() || origins.is_empty() {
            return Err(BindingError::Empty);
        }
        Ok(Self {
            connectors,
            origins,
            auth_slot,
            environment,
        })
    }

    /// Connectors allowed to receive the secret.
    #[must_use]
    pub fn connectors(&self) -> &BTreeSet<ConnectorName> {
        &self.connectors
    }

    /// Origins the secret may be sent to.
    #[must_use]
    pub fn origins(&self) -> &BTreeSet<Origin> {
        &self.origins
    }

    /// Credential slot the secret fills.
    #[must_use]
    pub fn auth_slot(&self) -> &AuthSlot {
        &self.auth_slot
    }

    /// Environment the secret belongs to.
    #[must_use]
    pub fn environment(&self) -> &Environment {
        &self.environment
    }

    /// Returns whether this binding is equal to or narrower than
    /// `authoritative`: every connector and origin it allows is also allowed
    /// there, and the slot and environment are identical.
    ///
    /// The gateway applies this to a provider-attested binding, with the
    /// Config Registry binding as `authoritative`.
    #[must_use]
    pub fn is_within(&self, authoritative: &Self) -> bool {
        self.connectors.is_subset(&authoritative.connectors)
            && self.origins.is_subset(&authoritative.origins)
            && self.auth_slot == authoritative.auth_slot
            && self.environment == authoritative.environment
    }

    /// Returns whether a credential may be injected for `connector` sending
    /// to `origin` in `slot`.
    #[must_use]
    pub fn permits(&self, connector: &ConnectorName, origin: &Origin, slot: &AuthSlot) -> bool {
        self.connectors.contains(connector)
            && self.origins.contains(origin)
            && &self.auth_slot == slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding(connectors: &[&str], origins: &[&str], slot: &str) -> SecretUseBinding {
        SecretUseBinding::new(
            connectors
                .iter()
                .map(|c| ConnectorName::new(*c).unwrap())
                .collect(),
            origins.iter().map(|o| Origin::parse(o).unwrap()).collect(),
            AuthSlot::new(slot).unwrap(),
            Environment::new("production").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn origins_are_canonical() {
        assert_eq!(
            Origin::parse("HTTPS://API.Cloudflare.com:443")
                .unwrap()
                .as_str(),
            "https://api.cloudflare.com"
        );
        assert_eq!(
            Origin::parse("http://127.0.0.1:8080").unwrap().as_str(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            Origin::parse("http://[::1]:80").unwrap().as_str(),
            "http://[::1]"
        );
    }

    #[test]
    fn origins_reject_anything_but_scheme_host_port() {
        for value in [
            "api.cloudflare.com",
            "ftp://example.com",
            "https://",
            "https://example.com/",
            "https://example.com/client/v4",
            "https://user@example.com",
            "https://example.com?x=1",
            "https://example.com#frag",
            "https://example.com:0",
            "https://example.com:65536",
            "https://example.com:",
            "https://exa_mple.com",
            "https://-example.com",
            "https://example..com",
            "https://example.com\\@evil.com",
        ] {
            assert_eq!(
                Origin::parse(value),
                Err(BindingError::InvalidOrigin),
                "{value}"
            );
        }
    }

    #[test]
    fn narrower_binding_is_within() {
        let registry = binding(&["cloudflare"], &["https://api.cloudflare.com"], "read");
        assert!(registry.is_within(&registry));

        let broader = binding(
            &["cloudflare", "http"],
            &["https://api.cloudflare.com"],
            "read",
        );
        assert!(!broader.is_within(&registry));
        assert!(registry.is_within(&broader));

        let other_slot = binding(&["cloudflare"], &["https://api.cloudflare.com"], "write");
        assert!(!other_slot.is_within(&registry));
    }

    #[test]
    fn permits_checks_connector_origin_and_slot() {
        let b = binding(&["cloudflare"], &["https://api.cloudflare.com"], "read");
        let cf = ConnectorName::new("cloudflare").unwrap();
        let origin = Origin::parse("https://api.cloudflare.com").unwrap();
        let read = AuthSlot::new("read").unwrap();
        assert!(b.permits(&cf, &origin, &read));
        assert!(!b.permits(&cf, &Origin::parse("https://evil.example").unwrap(), &read));
        assert!(!b.permits(&ConnectorName::new("github").unwrap(), &origin, &read));
        assert!(!b.permits(&cf, &origin, &AuthSlot::new("write").unwrap()));
    }

    #[test]
    fn deserializes_design_yaml_shape() {
        let parsed: SecretUseBinding = serde_json::from_value(json!({
            "connectors": ["cloudflare"],
            "origins": ["https://api.cloudflare.com"],
            "auth_slot": "write",
            "environment": "production"
        }))
        .unwrap();
        assert_eq!(parsed.auth_slot().as_str(), "write");

        let empty = serde_json::from_value::<SecretUseBinding>(json!({
            "connectors": [],
            "origins": ["https://api.cloudflare.com"],
            "auth_slot": "write",
            "environment": "production"
        }));
        assert!(empty.is_err());
    }
}
