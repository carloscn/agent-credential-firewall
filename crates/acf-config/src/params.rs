//! Parameter schemas and structural validation.
//!
//! Structural validation checks presence, JSON type, enumerations, integer
//! bounds, and string length. Domain types (`dns_name`, `ipv4`, ...) are only
//! type-checked as strings here; the connector's domain-type normalizers
//! (WP-04, WP-15) validate and canonicalize them before constraints run.

use std::collections::BTreeMap;

use acf_protocol::{ParamName, Scalar};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Default and upper bound for string parameter length.
pub const DEFAULT_MAX_LENGTH: usize = 1024;
/// Hard cap on any configured `max_length`.
pub const MAX_MAX_LENGTH: usize = 65_536;

/// Where a parameter goes in the downstream request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamLocation {
    /// URL query string.
    Query,
    /// JSON request body.
    Body,
    /// A `{params.<name>}` path segment.
    Path,
}

/// Parameter value types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    /// Free-form string, bounded by `max_length`.
    String,
    /// Signed 64-bit integer.
    Integer,
    /// Boolean.
    Boolean,
    /// DNS name (domain type).
    DnsName,
    /// DNS record content, validated by record type (domain type).
    DnsRecordContent,
    /// IPv4 address (domain type).
    Ipv4,
    /// IPv6 address (domain type).
    Ipv6,
}

impl ParamType {
    fn is_string_like(self) -> bool {
        !matches!(self, Self::Integer | Self::Boolean)
    }
}

/// Schema of one parameter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    /// Where the value goes.
    pub location: ParamLocation,
    /// Value type.
    #[serde(rename = "type")]
    pub ty: ParamType,
    /// Whether the agent must supply it. Path parameters are always required.
    #[serde(default)]
    pub required: bool,
    /// Allowed values (string and integer types only).
    #[serde(default, rename = "enum", skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<Scalar>>,
    /// Minimum value (integer only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    /// Maximum value (integer only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    /// Maximum string length in bytes (string-like types only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    /// For `dns_record_content`: the parameter holding the record type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_type_param: Option<ParamName>,
}

impl ParamSpec {
    /// Checks the spec's internal consistency. `siblings` are the other
    /// parameters of the same action.
    pub(crate) fn problems(&self, siblings: &BTreeMap<ParamName, ParamSpec>) -> Vec<String> {
        let mut problems = Vec::new();
        if self.location == ParamLocation::Path && !self.required {
            problems.push("path parameters must be `required: true`".to_owned());
        }
        if self.location == ParamLocation::Path
            && !matches!(self.ty, ParamType::String | ParamType::Integer)
        {
            problems.push("path parameters must be `string` or `integer`".to_owned());
        }
        if let Some(allowed) = &self.allowed {
            if allowed.is_empty() {
                problems.push("`enum` must not be empty".to_owned());
            }
            let type_ok = match self.ty {
                ParamType::String => allowed.iter().all(|v| matches!(v, Scalar::String(_))),
                ParamType::Integer => allowed.iter().all(|v| matches!(v, Scalar::Integer(_))),
                _ => false,
            };
            if !type_ok {
                problems.push(
                    "`enum` is only for `string` or `integer`, with values of that type".to_owned(),
                );
            }
        }
        if (self.min.is_some() || self.max.is_some()) && self.ty != ParamType::Integer {
            problems.push("`min`/`max` apply only to `integer`".to_owned());
        }
        if let (Some(min), Some(max)) = (self.min, self.max)
            && min > max
        {
            problems.push("`min` must not exceed `max`".to_owned());
        }
        if let Some(max_length) = self.max_length {
            if !self.ty.is_string_like() {
                problems.push("`max_length` applies only to string-like types".to_owned());
            }
            if max_length == 0 || max_length > MAX_MAX_LENGTH {
                problems.push(format!("`max_length` must be 1-{MAX_MAX_LENGTH}"));
            }
        }
        match (self.ty, &self.record_type_param) {
            (ParamType::DnsRecordContent, None) => {
                problems.push("`dns_record_content` needs `record_type_param`".to_owned());
            }
            (ParamType::DnsRecordContent, Some(name)) => match siblings.get(name) {
                Some(spec) if spec.ty == ParamType::String && spec.allowed.is_some() && spec.required => {}
                _ => problems.push(format!(
                    "`record_type_param` must name a required `string` parameter with an `enum`; `{name}` is not one"
                )),
            },
            (_, Some(_)) => problems.push("`record_type_param` applies only to `dns_record_content`".to_owned()),
            (_, None) => {}
        }
        problems
    }

    fn check(&self, value: &Value) -> Result<(), ParamErrorKind> {
        match self.ty {
            ParamType::Boolean => {
                if !value.is_boolean() {
                    return Err(ParamErrorKind::WrongType);
                }
            }
            ParamType::Integer => {
                let n = value.as_i64().ok_or(ParamErrorKind::WrongType)?;
                if self.min.is_some_and(|min| n < min) || self.max.is_some_and(|max| n > max) {
                    return Err(ParamErrorKind::OutOfRange);
                }
            }
            _ => {
                let s = value.as_str().ok_or(ParamErrorKind::WrongType)?;
                if s.len() > self.max_length.unwrap_or(DEFAULT_MAX_LENGTH) {
                    return Err(ParamErrorKind::TooLong);
                }
            }
        }
        if let Some(allowed) = &self.allowed
            && !allowed.iter().any(|a| a.matches(value))
        {
            return Err(ParamErrorKind::NotInEnum);
        }
        Ok(())
    }
}

/// Why a parameter failed structural validation. Carries no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParamErrorKind {
    /// The action does not declare this parameter.
    #[error("is not a parameter of this action")]
    Unknown,
    /// A required parameter is absent.
    #[error("is required")]
    Missing,
    /// Wrong JSON type.
    #[error("has the wrong type")]
    WrongType,
    /// Outside `min`/`max`.
    #[error("is out of range")]
    OutOfRange,
    /// Longer than `max_length`.
    #[error("is too long")]
    TooLong,
    /// Not one of the `enum` values.
    #[error("is not an allowed value")]
    NotInEnum,
}

/// A parameter failed structural validation.
///
/// For [`ParamErrorKind::Unknown`] the name is the agent's input, truncated
/// and filtered to safe characters before it is reported.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("parameter `{param}` {kind}")]
pub struct ParamError {
    /// Parameter name.
    pub param: String,
    /// Reason.
    pub kind: ParamErrorKind,
}

fn sanitize_unknown_name(name: &str) -> String {
    name.chars()
        .take(32)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Validates agent parameters against an action's parameter schemas.
///
/// # Errors
///
/// Returns the first problem: unknown parameters first, then each declared
/// parameter in name order.
pub fn validate_params(
    specs: &BTreeMap<ParamName, ParamSpec>,
    params: &Map<String, Value>,
) -> Result<(), ParamError> {
    if let Some(unknown) = params
        .keys()
        .find(|k| !specs.keys().any(|name| name.as_str() == k.as_str()))
    {
        return Err(ParamError {
            param: sanitize_unknown_name(unknown),
            kind: ParamErrorKind::Unknown,
        });
    }
    for (name, spec) in specs {
        match params.get(name.as_str()) {
            None if spec.required => {
                return Err(ParamError {
                    param: name.to_string(),
                    kind: ParamErrorKind::Missing,
                });
            }
            None => {}
            // `null` is rejected as a wrong type rather than treated as absent,
            // so it cannot slip past checks that only run on present values.
            Some(value) => spec.check(value).map_err(|kind| ParamError {
                param: name.to_string(),
                kind,
            })?,
        }
    }
    Ok(())
}
