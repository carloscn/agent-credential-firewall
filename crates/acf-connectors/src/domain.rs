//! Domain-type normalization.
//!
//! Runs after structural validation and before authorization, so constraints
//! always see canonical values. Only reviewed Rust normalizers exist; a
//! profile cannot define new ones.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use acf_config::{ParamSpec, ParamType};
use acf_protocol::ParamName;
use serde_json::{Map, Value};

/// Why a parameter could not be normalized. Carries no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DomainErrorKind {
    /// The value is not valid for its domain type.
    #[error("is not a valid value for its type")]
    Invalid,
    /// The domain type has no normalizer yet; such parameters are refused.
    #[error("uses a domain type that is not supported yet")]
    Unsupported,
}

/// A parameter failed normalization.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("parameter `{param}` {kind}")]
pub struct DomainError {
    /// Parameter name.
    pub param: String,
    /// Reason.
    pub kind: DomainErrorKind,
}

fn normalize_value(ty: ParamType, value: &Value) -> Result<Value, DomainErrorKind> {
    match ty {
        ParamType::String | ParamType::Integer | ParamType::Boolean => Ok(value.clone()),
        // `Ipv4Addr` rejects leading zeros, so `010.0.0.1` cannot be read
        // as octal by a downstream parser.
        ParamType::Ipv4 => value
            .as_str()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .map(|ip| Value::String(ip.to_string()))
            .ok_or(DomainErrorKind::Invalid),
        // `Display` gives the RFC 5952 canonical form.
        ParamType::Ipv6 => value
            .as_str()
            .and_then(|s| s.parse::<Ipv6Addr>().ok())
            .map(|ip| Value::String(ip.to_string()))
            .ok_or(DomainErrorKind::Invalid),
        // Normalizers arrive with WP-15.
        ParamType::DnsName | ParamType::DnsRecordContent => Err(DomainErrorKind::Unsupported),
    }
}

/// Normalizes structurally valid parameters by their declared types.
///
/// # Errors
///
/// Returns [`DomainError`] for an undeclared parameter, an invalid value, or
/// a type without a normalizer.
pub fn normalize_params(
    specs: &BTreeMap<ParamName, ParamSpec>,
    params: &Map<String, Value>,
) -> Result<Map<String, Value>, DomainError> {
    let mut normalized = Map::new();
    for (name, value) in params {
        let error = |kind| DomainError {
            param: name.chars().take(32).collect(),
            kind,
        };
        let spec = specs
            .iter()
            .find(|(declared, _)| declared.as_str() == name)
            .map(|(_, spec)| spec)
            .ok_or_else(|| error(DomainErrorKind::Invalid))?;
        normalized.insert(
            name.clone(),
            normalize_value(spec.ty, value).map_err(error)?,
        );
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ip_addresses_are_canonical() {
        assert_eq!(
            normalize_value(ParamType::Ipv4, &json!("203.0.113.10")),
            Ok(json!("203.0.113.10"))
        );
        assert_eq!(
            normalize_value(ParamType::Ipv6, &json!("2001:DB8:0:0:0:0:0:1")),
            Ok(json!("2001:db8::1"))
        );
        for bad in [
            json!("010.0.0.1"),
            json!("1.2.3"),
            json!("256.1.1.1"),
            json!(" 1.2.3.4"),
            json!(16_909_060),
        ] {
            assert_eq!(
                normalize_value(ParamType::Ipv4, &bad),
                Err(DomainErrorKind::Invalid),
                "{bad}"
            );
        }
    }

    #[test]
    fn dns_types_fail_closed_until_implemented() {
        assert_eq!(
            normalize_value(ParamType::DnsName, &json!("api.example.com")),
            Err(DomainErrorKind::Unsupported)
        );
    }
}
