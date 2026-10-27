//! Profile, resource, secret-registration, and deployment-profile schemas with
//! fail-closed validation.
//!
//! [`load_yaml`] is the only way to obtain a [`ValidatedConfig`]. It rejects
//! unknown fields, duplicate keys, YAML merge keys, unsupported tags, and alias
//! expansion beyond a small budget, and it validates every cross-reference
//! before returning. A bundle with any issue is rejected as a whole.
//!
//! [`load_bundle`] also takes connector profiles stored as separate
//! documents. [`ConfigTrust::admit`] admits each document for its role by a
//! signature or a pinned digest, and [`production_issues`] lists what the
//! `production` profile refuses (ADR 0004).

mod admission;
mod bundle;
mod params;
mod production;
mod profile;
mod template;

pub use admission::{
    AdmissionError, CONFIG_TRUST_SCHEMA, ConfigRole, ConfigSignature, ConfigTrust, SourceFile,
    config_digest, sha256, signing_message,
};
pub use production::{destination_problem, production_issues};

pub use bundle::{
    CONFIG_SCHEMA, ConfigError, ConfigIssue, Deployment, DeploymentProfile, KeySourceKind,
    MAX_CONFIG_BYTES, ResolvedAction, ResourceRegistration, RollbackAnchorKind, RollbackResistance,
    SecretProviderConfig, SecretRegistration, ValidatedConfig, check_document, load_bundle,
    load_yaml, parse_yaml,
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
