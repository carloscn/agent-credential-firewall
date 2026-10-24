//! Connector profiles: the reviewed, declarative description of a service's
//! semantic actions (design §7.8.1).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use acf_protocol::{ActionName, ParamName};
use acf_secrets::{AuthSlot, ConnectorName};
use serde::{Deserialize, Serialize};

use crate::params::{ParamLocation, ParamSpec};
use crate::template::{BaseUrl, PathTemplate, Segment};

/// Schema identifier for connector profiles.
pub const PROFILE_SCHEMA: &str = "acf.profile/v1";

const MAX_HEADER_NAME_LEN: usize = 64;
const MAX_FIELD_PATH_LEN: usize = 256;
/// Headers a profile may never name, in request or response.
const FORBIDDEN_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "set-cookie",
    "transfer-encoding",
];

/// An HTTP header name, stored lowercase.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HeaderName(String);

impl HeaderName {
    /// Validates a header name.
    ///
    /// # Errors
    ///
    /// Returns a description if the name is malformed or forbidden.
    pub fn new(value: &str) -> Result<Self, &'static str> {
        let lower = value.to_ascii_lowercase();
        if lower.is_empty()
            || lower.len() > MAX_HEADER_NAME_LEN
            || !lower
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("header names must be 1-64 characters of [A-Za-z0-9-]");
        }
        if FORBIDDEN_HEADERS.contains(&lower.as_str()) {
            return Err("this header cannot be configured");
        }
        Ok(Self(lower))
    }

    /// Returns the lowercase name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HeaderName {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, &'static str> {
        Self::new(&value)
    }
}

impl From<HeaderName> for String {
    fn from(name: HeaderName) -> Self {
        name.0
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A response field path such as `result.id`. Arrays along the path are
/// traversed element by element.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FieldPath(String);

impl FieldPath {
    /// Validates a field path.
    ///
    /// # Errors
    ///
    /// Returns a description if the path is malformed.
    pub fn new(value: &str) -> Result<Self, &'static str> {
        let valid = !value.is_empty()
            && value.len() <= MAX_FIELD_PATH_LEN
            && value.split('.').all(|seg| {
                !seg.is_empty()
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            });
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err("field paths are dot-separated segments of [A-Za-z0-9_-]")
        }
    }

    /// Path segments.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }

    /// Returns the path as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FieldPath {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, &'static str> {
        Self::new(&value)
    }
}

impl From<FieldPath> for String {
    fn from(path: FieldPath) -> Self {
        path.0
    }
}

/// How credentials are presented downstream. One strategy per profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authentication {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// `<header>: <secret>`.
    HeaderApiKey {
        /// Header that carries the key.
        header: HeaderName,
    },
    /// `Authorization: Basic <secret>`, where the secret is `user:password`.
    Basic,
}

/// HTTP methods a profile may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// PATCH.
    Patch,
    /// DELETE.
    Delete,
}

/// Whether an action changes downstream state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Reads only.
    Read,
    /// Changes state.
    Mutate,
}

/// Explicit approval setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Each request needs a transaction approval.
    Required,
    /// No per-request approval. Not allowed for `mutate` actions.
    None,
}

/// Which response data may cross the gateway boundary. Everything not listed
/// is dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSpec {
    /// Allowlisted body fields. Required; an explicit empty list returns no
    /// business payload.
    pub fields: Vec<FieldPath>,
    /// Allowlisted response headers. Default: none.
    #[serde(default)]
    pub headers: Vec<HeaderName>,
}

/// How a request parameter appears in audit events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuditClass {
    /// The normalized value is recorded.
    Record,
    /// A keyed hash of the value is recorded.
    Hash,
    /// The parameter is left out.
    Omit,
}

/// Per-parameter audit classification. Unlisted parameters are omitted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSpec {
    /// Parameters recorded verbatim (after normalization).
    #[serde(default)]
    pub record: BTreeSet<ParamName>,
    /// Parameters recorded as a keyed hash.
    #[serde(default)]
    pub hash: BTreeSet<ParamName>,
}

impl AuditSpec {
    /// Classifies a parameter.
    #[must_use]
    pub fn classify(&self, param: &ParamName) -> AuditClass {
        if self.record.contains(param) {
            AuditClass::Record
        } else if self.hash.contains(param) {
            AuditClass::Hash
        } else {
            AuditClass::Omit
        }
    }
}

/// One semantic action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    /// Fixed HTTP method.
    pub method: HttpMethod,
    /// Fixed path template below the base URL.
    pub path: PathTemplate,
    /// Credential slot the action uses.
    pub credential_slot: AuthSlot,
    /// Read or mutate.
    pub classification: Classification,
    /// Explicit approval setting. Absent: required for `mutate`, none for `read`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalMode>,
    /// Parameters the agent may supply.
    #[serde(default)]
    pub params: BTreeMap<ParamName, ParamSpec>,
    /// Response allowlist. Required.
    pub response: ResponseSpec,
    /// Audit classification of parameters.
    #[serde(default)]
    pub audit: AuditSpec,
}

impl ActionSpec {
    /// Whether every request needs a transaction approval. Always true for
    /// `mutate`; a profile cannot weaken that default.
    #[must_use]
    pub fn approval_required(&self) -> bool {
        self.classification == Classification::Mutate
            || self.approval == Some(ApprovalMode::Required)
    }

    /// Whether the action declares `param`.
    #[must_use]
    pub fn declares(&self, param: &ParamName) -> bool {
        self.params.contains_key(param)
    }

    pub(crate) fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.classification == Classification::Mutate
            && self.approval == Some(ApprovalMode::None)
        {
            problems.push("`mutate` actions cannot set `approval: none`".to_owned());
        }
        for (name, spec) in &self.params {
            problems.extend(
                spec.problems(&self.params)
                    .into_iter()
                    .map(|p| format!("params.{name}: {p}")),
            );
            if spec.location == ParamLocation::Body
                && matches!(self.method, HttpMethod::Get | HttpMethod::Delete)
            {
                problems.push(format!(
                    "params.{name}: GET and DELETE actions cannot have body parameters"
                ));
            }
        }

        let mut template_params = BTreeSet::new();
        for segment in self.path.segments() {
            if let Segment::Param(name) = segment {
                if !template_params.insert(name) {
                    problems.push(format!("path uses `{{params.{name}}}` more than once"));
                }
                match self.params.get(name) {
                    Some(spec) if spec.location == ParamLocation::Path => {}
                    _ => problems.push(format!(
                        "path uses `{{params.{name}}}`, but `{name}` is not declared with `location: path`"
                    )),
                }
            }
        }
        for (name, spec) in &self.params {
            if spec.location == ParamLocation::Path && !template_params.contains(name) {
                problems.push(format!(
                    "params.{name}: declared `location: path` but not used in the path"
                ));
            }
        }

        let mut seen_fields = BTreeSet::new();
        for field in &self.response.fields {
            if !seen_fields.insert(field) {
                problems.push(format!("response.fields lists `{}` twice", field.as_str()));
            }
        }
        for name in self.audit.record.iter().chain(&self.audit.hash) {
            if !self.params.contains_key(name) {
                problems.push(format!(
                    "audit names `{name}`, which is not a declared parameter"
                ));
            }
        }
        for name in self.audit.record.intersection(&self.audit.hash) {
            problems.push(format!(
                "audit lists `{name}` under both `record` and `hash`"
            ));
        }
        problems
    }
}

/// A reviewed connector profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorProfile {
    /// Must be [`PROFILE_SCHEMA`].
    pub schema: String,
    /// Connector this profile defines.
    pub connector: ConnectorName,
    /// Profile content revision.
    pub revision: u32,
    /// Fixed base URL. Its origin is where credentials are sent.
    pub base_url: BaseUrl,
    /// Credential presentation.
    pub authentication: Authentication,
    /// Semantic actions.
    pub actions: BTreeMap<ActionName, ActionSpec>,
}

impl ConnectorProfile {
    /// Credential slots used by any action.
    #[must_use]
    pub fn credential_slots(&self) -> BTreeSet<&AuthSlot> {
        self.actions.values().map(|a| &a.credential_slot).collect()
    }

    /// Whether any action declares `param`.
    #[must_use]
    pub fn declares_param(&self, param: &ParamName) -> bool {
        self.actions.values().any(|a| a.declares(param))
    }

    pub(crate) fn problems(&self) -> Vec<(String, String)> {
        let mut problems = Vec::new();
        if self.schema != PROFILE_SCHEMA {
            problems.push(("schema".to_owned(), format!("must be `{PROFILE_SCHEMA}`")));
        }
        if self.actions.is_empty() {
            problems.push((
                "actions".to_owned(),
                "a profile needs at least one action".to_owned(),
            ));
        }
        for (name, action) in &self.actions {
            for problem in action.problems() {
                problems.push((format!("actions.{name}"), problem));
            }
        }
        problems
    }
}
