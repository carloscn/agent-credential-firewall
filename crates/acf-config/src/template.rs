//! Base URLs and path templates.
//!
//! A path template has two placeholder namespaces:
//!
//! - `{resource.<name>}` is filled only from trusted resource bindings.
//! - `{params.<name>}` is filled only from validated agent parameters.
//!
//! Each placeholder is a whole path segment, and a filled value must itself be
//! a single segment of unreserved characters. A parameter can never supply a
//! resource binding, a `/`, a percent escape, or a `.`/`..` segment.

use std::collections::BTreeMap;
use std::fmt;

use acf_protocol::ParamName;
use acf_secrets::Origin;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const MAX_SEGMENT_LEN: usize = 256;

/// Why a template, binding, or base URL was rejected, or why rendering failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    /// Malformed base URL.
    #[error("base_url must be an http(s) origin plus an optional path of unreserved segments")]
    InvalidBaseUrl,
    /// Malformed path template.
    #[error("path template is malformed: {0}")]
    InvalidTemplate(&'static str),
    /// A binding name is malformed.
    #[error("binding names must be 1-63 characters of [a-z0-9_], starting with a letter")]
    InvalidBindingName,
    /// A binding value or parameter value is not one safe path segment.
    #[error("`{0}` must be a single path segment of unreserved characters")]
    UnsafeSegment(String),
    /// No value was available for a placeholder.
    #[error("no value for `{0}`")]
    Unfilled(String),
}

/// A literal path segment, binding value, or rendered parameter value: 1-256
/// unreserved characters (RFC 3986 `ALPHA DIGIT - . _ ~`), not `.` or `..`.
fn is_safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SEGMENT_LEN
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Name of a trusted resource binding, for example `zone_id`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BindingName(String);

impl BindingName {
    /// Validates a binding name.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::InvalidBindingName`] if the name is malformed.
    pub fn new(value: impl Into<String>) -> Result<Self, TemplateError> {
        let value = value.into();
        // Same shape as parameter names.
        if ParamName::new(value.clone()).is_ok() {
            Ok(Self(value))
        } else {
            Err(TemplateError::InvalidBindingName)
        }
    }

    /// Returns the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BindingName {
    type Error = TemplateError;

    fn try_from(value: String) -> Result<Self, TemplateError> {
        Self::new(value)
    }
}

impl From<BindingName> for String {
    fn from(name: BindingName) -> Self {
        name.0
    }
}

impl fmt::Display for BindingName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A trusted resource binding value: one safe path segment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BindingValue(String);

impl BindingValue {
    /// Validates a binding value.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::UnsafeSegment`] if the value is not one safe segment.
    pub fn new(value: impl Into<String>) -> Result<Self, TemplateError> {
        let value = value.into();
        if is_safe_segment(&value) {
            Ok(Self(value))
        } else {
            Err(TemplateError::UnsafeSegment("binding value".to_owned()))
        }
    }

    /// Returns the value as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BindingValue {
    type Error = TemplateError;

    fn try_from(value: String) -> Result<Self, TemplateError> {
        Self::new(value)
    }
}

impl From<BindingValue> for String {
    fn from(value: BindingValue) -> Self {
        value.0
    }
}

/// A connector's fixed base URL: an origin plus an optional fixed path prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BaseUrl {
    origin: Origin,
    prefix: Vec<String>,
}

impl BaseUrl {
    /// Parses a base URL such as `https://api.cloudflare.com/client/v4`.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::InvalidBaseUrl`] if it is malformed.
    pub fn parse(value: &str) -> Result<Self, TemplateError> {
        let after_scheme = value
            .find("://")
            .map(|i| i + 3)
            .ok_or(TemplateError::InvalidBaseUrl)?;
        let (origin, path) = match value[after_scheme..].find('/') {
            Some(i) => value.split_at(after_scheme + i),
            None => (value, ""),
        };
        let origin = Origin::parse(origin).map_err(|_| TemplateError::InvalidBaseUrl)?;
        let prefix = match path.strip_prefix('/') {
            None if path.is_empty() => Vec::new(),
            Some(rest) if rest.split('/').all(is_safe_segment) => {
                rest.split('/').map(str::to_owned).collect()
            }
            _ => return Err(TemplateError::InvalidBaseUrl),
        };
        Ok(Self { origin, prefix })
    }

    /// The origin credentials are sent to.
    #[must_use]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Fixed path prefix segments.
    #[must_use]
    pub fn prefix(&self) -> &[String] {
        &self.prefix
    }
}

impl TryFrom<String> for BaseUrl {
    type Error = TemplateError;

    fn try_from(value: String) -> Result<Self, TemplateError> {
        Self::parse(&value)
    }
}

impl From<BaseUrl> for String {
    fn from(url: BaseUrl) -> Self {
        let mut s = url.origin.as_str().to_owned();
        for segment in url.prefix {
            s.push('/');
            s.push_str(&segment);
        }
        s
    }
}

/// One path segment of a template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    /// Fixed text.
    Literal(String),
    /// Filled from a trusted resource binding.
    Resource(BindingName),
    /// Filled from a validated agent parameter.
    Param(ParamName),
}

/// A parsed path template such as `/zones/{resource.zone_id}/dns_records`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PathTemplate {
    segments: Vec<Segment>,
}

impl PathTemplate {
    /// Parses a template.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::InvalidTemplate`] describing the problem.
    pub fn parse(value: &str) -> Result<Self, TemplateError> {
        let rest = value
            .strip_prefix('/')
            .ok_or(TemplateError::InvalidTemplate("must start with `/`"))?;
        if rest.is_empty() {
            return Ok(Self {
                segments: Vec::new(),
            });
        }
        let mut segments = Vec::new();
        for raw in rest.split('/') {
            let segment =
                if let Some(inner) = raw.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
                    if let Some(name) = inner.strip_prefix("resource.") {
                        Segment::Resource(BindingName::new(name).map_err(|_| {
                            TemplateError::InvalidTemplate("invalid resource binding name")
                        })?)
                    } else if let Some(name) = inner.strip_prefix("params.") {
                        Segment::Param(ParamName::new(name).map_err(|_| {
                            TemplateError::InvalidTemplate("invalid parameter name")
                        })?)
                    } else {
                        return Err(TemplateError::InvalidTemplate(
                            "placeholders must be `{resource.<name>}` or `{params.<name>}`",
                        ));
                    }
                } else if is_safe_segment(raw) {
                    Segment::Literal(raw.to_owned())
                } else {
                    return Err(TemplateError::InvalidTemplate(
                        "segments must be unreserved characters or one whole placeholder",
                    ));
                };
            segments.push(segment);
        }
        Ok(Self { segments })
    }

    /// The template's segments.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Resource bindings the template uses.
    pub fn resource_bindings(&self) -> impl Iterator<Item = &BindingName> {
        self.segments.iter().filter_map(|s| match s {
            Segment::Resource(name) => Some(name),
            _ => None,
        })
    }

    /// Parameters the template uses.
    pub fn params(&self) -> impl Iterator<Item = &ParamName> {
        self.segments.iter().filter_map(|s| match s {
            Segment::Param(name) => Some(name),
            _ => None,
        })
    }

    /// Renders the path below `base`. Resource placeholders read only
    /// `bindings`; parameter placeholders read only `params`, which must be
    /// strings or integers forming one safe segment.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::Unfilled`] or [`TemplateError::UnsafeSegment`].
    pub fn render(
        &self,
        base: &BaseUrl,
        bindings: &BTreeMap<BindingName, BindingValue>,
        params: &Map<String, Value>,
    ) -> Result<String, TemplateError> {
        let mut path = String::new();
        for segment in base.prefix() {
            path.push('/');
            path.push_str(segment);
        }
        for segment in &self.segments {
            path.push('/');
            match segment {
                Segment::Literal(text) => path.push_str(text),
                Segment::Resource(name) => {
                    let value = bindings
                        .get(name)
                        .ok_or_else(|| TemplateError::Unfilled(format!("resource.{name}")))?;
                    path.push_str(value.as_str());
                }
                Segment::Param(name) => {
                    let placeholder = format!("params.{name}");
                    let rendered = match params.get(name.as_str()) {
                        Some(Value::String(s)) => s.clone(),
                        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.to_string(),
                        Some(_) => return Err(TemplateError::UnsafeSegment(placeholder)),
                        None => return Err(TemplateError::Unfilled(placeholder)),
                    };
                    if !is_safe_segment(&rendered) {
                        return Err(TemplateError::UnsafeSegment(placeholder));
                    }
                    path.push_str(&rendered);
                }
            }
        }
        if path.is_empty() {
            path.push('/');
        }
        Ok(path)
    }
}

impl TryFrom<String> for PathTemplate {
    type Error = TemplateError;

    fn try_from(value: String) -> Result<Self, TemplateError> {
        Self::parse(&value)
    }
}

impl From<PathTemplate> for String {
    fn from(template: PathTemplate) -> Self {
        if template.segments.is_empty() {
            return "/".to_owned();
        }
        let mut s = String::new();
        for segment in template.segments {
            s.push('/');
            match segment {
                Segment::Literal(text) => s.push_str(&text),
                Segment::Resource(name) => {
                    s.push_str("{resource.");
                    s.push_str(name.as_str());
                    s.push('}');
                }
                Segment::Param(name) => {
                    s.push_str("{params.");
                    s.push_str(name.as_str());
                    s.push('}');
                }
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bindings() -> BTreeMap<BindingName, BindingValue> {
        [(
            BindingName::new("zone_id").unwrap(),
            BindingValue::new("023e105f4ecef8ad9ca31a8372d0c353").unwrap(),
        )]
        .into()
    }

    #[test]
    fn renders_cloudflare_paths() {
        let base = BaseUrl::parse("https://api.cloudflare.com/client/v4").unwrap();
        let template =
            PathTemplate::parse("/zones/{resource.zone_id}/dns_records/{params.record_id}")
                .unwrap();
        let params = json!({ "record_id": "372e67954025e0ba6aaa6d586b9e0b59" });
        assert_eq!(
            template
                .render(&base, &bindings(), params.as_object().unwrap())
                .unwrap(),
            "/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records/372e67954025e0ba6aaa6d586b9e0b59"
        );
    }

    #[test]
    fn params_cannot_fill_resource_bindings() {
        let base = BaseUrl::parse("https://api.cloudflare.com/client/v4").unwrap();
        let template = PathTemplate::parse("/zones/{resource.zone_id}/dns_records").unwrap();
        let attacker = json!({ "zone_id": "attacker-zone", "resource.zone_id": "attacker-zone" });
        let rendered = template
            .render(&base, &bindings(), attacker.as_object().unwrap())
            .unwrap();
        assert!(!rendered.contains("attacker"));

        // With no trusted binding, rendering fails rather than falling back to params.
        let err = template
            .render(&base, &BTreeMap::new(), attacker.as_object().unwrap())
            .unwrap_err();
        assert_eq!(err, TemplateError::Unfilled("resource.zone_id".to_owned()));
    }

    #[test]
    fn param_values_must_be_one_safe_segment() {
        let base = BaseUrl::parse("https://api.example.test").unwrap();
        let template = PathTemplate::parse("/records/{params.id}").unwrap();
        for bad in [
            json!("../admin"),
            json!("a/b"),
            json!(".."),
            json!("%2e%2e"),
            json!("a b"),
            json!(""),
            json!(true),
            json!(1.5),
        ] {
            let params = json!({ "id": bad });
            assert_eq!(
                template.render(&base, &BTreeMap::new(), params.as_object().unwrap()),
                Err(TemplateError::UnsafeSegment("params.id".to_owned())),
                "{bad}"
            );
        }
        let ok = json!({ "id": 42 });
        assert_eq!(
            template
                .render(&base, &BTreeMap::new(), ok.as_object().unwrap())
                .unwrap(),
            "/records/42"
        );
    }

    #[test]
    fn rejects_malformed_templates() {
        for bad in [
            "zones",
            "/zones/{zone_id}",
            "/zones/{secret.ref}",
            "/zones/v{params.v}",
            "/zones/{params.v}x",
            "/zones//records",
            "/zones/../admin",
            "/zones/./x",
            "/zones/%2e",
            "/zones?x=1",
            "/zones/",
            "/zones/{resource.Zone}",
        ] {
            assert!(PathTemplate::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(String::from(PathTemplate::parse("/").unwrap()), "/");
    }

    #[test]
    fn base_urls_are_origin_plus_fixed_prefix() {
        let url = BaseUrl::parse("HTTPS://API.cloudflare.com:443/client/v4").unwrap();
        assert_eq!(url.origin().as_str(), "https://api.cloudflare.com");
        assert_eq!(String::from(url), "https://api.cloudflare.com/client/v4");
        for bad in [
            "api.cloudflare.com/client",
            "https://api.cloudflare.com/client/",
            "https://api.cloudflare.com/client/../v4",
            "https://api.cloudflare.com/client?x=1",
            "https://user@api.cloudflare.com",
            "ftp://api.cloudflare.com",
        ] {
            assert!(BaseUrl::parse(bad).is_err(), "{bad}");
        }
    }
}
