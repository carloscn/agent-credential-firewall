//! Profile, resource, secret-registration, and deployment-profile schemas with
//! fail-closed validation.
//!
//! [`load_yaml`] is the only way to obtain a [`ValidatedConfig`]. It rejects
//! unknown fields, duplicate keys, YAML merge keys, unsupported tags, and alias
//! expansion beyond a small budget, and it validates every cross-reference
//! before returning. A bundle with any issue is rejected as a whole.
//!
//! Signed and pinned bundles and `production` startup validation arrive with
//! WP-11.

mod bundle;
mod params;
mod profile;
mod template;

pub use bundle::{
    CONFIG_SCHEMA, ConfigError, ConfigIssue, Deployment, DeploymentProfile, KeySourceKind,
    MAX_CONFIG_BYTES, ResolvedAction, ResourceRegistration, RollbackAnchorKind, RollbackResistance,
    SecretProviderConfig, SecretRegistration, ValidatedConfig, load_yaml, parse_yaml,
};
pub use params::{
    DEFAULT_MAX_LENGTH, MAX_MAX_LENGTH, ParamError, ParamErrorKind, ParamLocation, ParamSpec,
    ParamType, validate_params,
};
pub use profile::{
    ActionSpec, ApprovalMode, AuditClass, AuditSpec, Authentication, Classification,
    ConnectorProfile, FieldPath, HeaderName, HttpMethod, PROFILE_SCHEMA, ResponseSpec,
};
pub use template::{BaseUrl, BindingName, BindingValue, PathTemplate, Segment, TemplateError};
