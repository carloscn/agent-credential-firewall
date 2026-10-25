//! Strongly typed identifiers.
//!
//! Every identifier kind is a distinct type, so a capability `jti` cannot be
//! passed where a `requestId` or an `idempotencyKey` is expected:
//!
//! ```compile_fail,E0308
//! use acf_protocol::{IdempotencyKey, RequestId};
//!
//! fn record(_: &IdempotencyKey) {}
//! let request = RequestId::new("req-001").unwrap();
//! record(&request);
//! ```
//!
//! Validation errors never echo the rejected input, because agents control
//! these values and could place secret material in them.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Maximum length, in bytes, of any identifier.
pub const MAX_ID_LEN: usize = 128;

/// Why an identifier was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// The identifier was empty.
    #[error("{kind} must not be empty")]
    Empty {
        /// Identifier kind.
        kind: &'static str,
    },
    /// The identifier exceeded [`MAX_ID_LEN`] bytes.
    #[error("{kind} exceeds {MAX_ID_LEN} bytes")]
    TooLong {
        /// Identifier kind.
        kind: &'static str,
    },
    /// The identifier contained a character outside the permitted set.
    #[error("{kind} contains a character outside the permitted set")]
    InvalidCharacter {
        /// Identifier kind.
        kind: &'static str,
    },
    /// The identifier did not match the structure required for its kind.
    #[error("{kind} is malformed")]
    Malformed {
        /// Identifier kind.
        kind: &'static str,
    },
}

/// Opaque identifiers use ASCII alphanumerics and `-_.:@/`.
fn validate_opaque(value: &str, kind: &'static str) -> Result<(), IdError> {
    check_length(value, kind)?;
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'@' | b'/'))
    {
        Ok(())
    } else {
        Err(IdError::InvalidCharacter { kind })
    }
}

fn check_length(value: &str, kind: &'static str) -> Result<(), IdError> {
    if value.is_empty() {
        Err(IdError::Empty { kind })
    } else if value.len() > MAX_ID_LEN {
        Err(IdError::TooLong { kind })
    } else {
        Ok(())
    }
}

/// Action names are dot-separated lowercase segments with at least two
/// segments, for example `cloudflare.dns.records.list`.
fn validate_action_name(value: &str, kind: &'static str) -> Result<(), IdError> {
    check_length(value, kind)?;
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.'))
    {
        return Err(IdError::InvalidCharacter { kind });
    }
    let mut segments = 0;
    for segment in value.split('.') {
        if !segment
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase())
        {
            return Err(IdError::Malformed { kind });
        }
        segments += 1;
    }
    if segments < 2 {
        return Err(IdError::Malformed { kind });
    }
    Ok(())
}

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident, $validate:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates and wraps an identifier.
            ///
            /// # Errors
            ///
            /// Returns [`IdError`] if the value is empty, too long, or not
            /// well formed for this identifier kind.
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                $validate(&value, stringify!($name))?;
                Ok(Self(value))
            }

            /// Returns the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;

            fn try_from(value: String) -> Result<Self, IdError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

define_id!(
    /// Unique identifier of one daemon-to-gateway call. Checked against the replay cache.
    RequestId,
    validate_opaque
);
define_id!(
    /// Identifier of one task.
    TaskId,
    validate_opaque
);
define_id!(
    /// Opaque daemon-issued handle for one task. Bound to the caller's UID
    /// and, optionally, a PID; meaningless to the gateway.
    TaskHandle,
    validate_opaque
);
define_id!(
    /// Signing key identifier (JWS `kid`).
    KeyId,
    validate_opaque
);
define_id!(
    /// Administrator-approved job definition.
    JobId,
    validate_opaque
);
define_id!(
    /// Capability `jti`. Identifies one task authorization; reusable within its TTL.
    CapabilityId,
    validate_opaque
);
define_id!(
    /// Identifier of one pending or decided approval.
    ApprovalId,
    validate_opaque
);
define_id!(
    /// One-time nonce carried by an approval receipt.
    ApprovalNonce,
    validate_opaque
);
define_id!(
    /// Identifies one logical mutation across retries and approval.
    IdempotencyKey,
    validate_opaque
);
define_id!(
    /// Journal record for one mutation.
    OperationId,
    validate_opaque
);
define_id!(
    /// Registered resource, for example `cloudflare-zone:example.com`.
    ResourceId,
    validate_opaque
);
define_id!(
    /// Semantic action name, for example `cloudflare.dns.records.list`.
    ActionName,
    validate_action_name
);
define_id!(
    /// Agent identity.
    AgentId,
    validate_opaque
);
define_id!(
    /// Device identity.
    DeviceId,
    validate_opaque
);
define_id!(
    /// Authenticated principal, for example `user:alice@example.com`.
    PrincipalId,
    validate_opaque
);
define_id!(
    /// Token issuer, for example `acf-authority-prod`.
    IssuerId,
    validate_opaque
);
define_id!(
    /// Intended token audience, for example `acf-gateway-prod-eu`.
    AudienceId,
    validate_opaque
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_ids_accept_design_examples() {
        for value in [
            "req-001",
            "dns-change-892",
            "cloudflare-zone:example.com",
            "repo:example/backend",
            "user:alice@example.com/device:laptop-0142",
        ] {
            assert!(ResourceId::new(value).is_ok(), "{value}");
        }
    }

    #[test]
    fn opaque_ids_reject_bad_input() {
        assert_eq!(
            RequestId::new(""),
            Err(IdError::Empty { kind: "RequestId" })
        );
        assert_eq!(
            RequestId::new("a".repeat(MAX_ID_LEN + 1)),
            Err(IdError::TooLong { kind: "RequestId" })
        );
        for value in ["has space", "new\nline", "quote\"", "percent%2F", "ünicode"] {
            assert_eq!(
                RequestId::new(value),
                Err(IdError::InvalidCharacter { kind: "RequestId" }),
                "{value}"
            );
        }
    }

    #[test]
    fn action_names_are_structured() {
        assert!(ActionName::new("cloudflare.dns.records.list").is_ok());
        assert!(ActionName::new("example.profile.get").is_ok());
        for value in [
            "single",
            ".leading",
            "trailing.",
            "a..b",
            "Upper.case",
            "x.1digit",
        ] {
            assert!(ActionName::new(value).is_err(), "{value}");
        }
    }

    #[test]
    fn errors_do_not_echo_input() {
        let canary = "CANARY-7f3a secret value";
        let error = TaskId::new(canary).unwrap_err();
        assert!(!error.to_string().contains("CANARY"));
        assert!(!format!("{error:?}").contains("CANARY"));
    }

    #[test]
    fn serde_round_trip_validates() {
        let id: RequestId = serde_json::from_str("\"req-001\"").unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"req-001\"");
        assert!(serde_json::from_str::<RequestId>("\"bad value\"").is_err());
    }
}
