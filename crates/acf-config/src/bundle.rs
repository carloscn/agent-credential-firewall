//! Configuration bundle schema, fail-closed loading, and cross-reference
//! validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use acf_protocol::{ActionName, ConstraintSet, ResourceId};
use acf_secrets::{AuthSlot, ConnectorName, Environment, Namespace, SecretRef, SecretUseBinding};
use serde::{Deserialize, Serialize};
use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy};

use crate::profile::{ActionSpec, ConnectorProfile};
use crate::template::{BindingName, BindingValue};

/// Schema identifier for configuration bundles.
pub const CONFIG_SCHEMA: &str = "acf.config/v1";
/// Largest accepted configuration document.
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// Substrings that may not appear in external-adapter setting names, because
/// provider bootstrap credentials must stay out of configuration files.
const CREDENTIAL_SETTING_WORDS: &[&str] = &[
    "token", "password", "secret", "apikey", "api_key", "private",
];

/// One validation problem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigIssue {
    /// Where in the bundle, for example `resources.cloudflare-zone:example.com.credentials.write`.
    pub location: String,
    /// What is wrong.
    pub problem: String,
}

impl fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.problem)
    }
}

/// Why a bundle was rejected. Loading never yields a partially valid config.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The document is larger than [`MAX_CONFIG_BYTES`].
    #[error("configuration exceeds {MAX_CONFIG_BYTES} bytes")]
    TooLarge,
    /// The document is not well-formed for the schema: syntax, unknown or
    /// duplicate keys, wrong types, or a malformed value.
    #[error("configuration could not be parsed: {0}")]
    Parse(String),
    /// The document parsed but failed validation.
    #[error("configuration is invalid ({} issues):\n{}", .0.len(), format_issues(.0))]
    Invalid(Vec<ConfigIssue>),
}

fn format_issues(issues: &[ConfigIssue]) -> String {
    issues
        .iter()
        .map(|i| format!("  - {i}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Runtime deployment profile (design §13.4). Production-specific startup
/// validation arrives with WP-11.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentProfile {
    /// Development; permits development-only components.
    Development,
    /// Production.
    Production,
}

/// Deployment settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    /// Deployment profile.
    pub profile: DeploymentProfile,
    /// The one environment this gateway serves. Every resource and secret
    /// registration must belong to it.
    pub environment: Environment,
}

/// Key sources for the encrypted local provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeySourceKind {
    /// Operating-system credential facility (systemd credentials).
    SystemdCredential,
    /// TPM sealing.
    Tpm,
    /// Cloud KMS or HSM wrapping.
    Kms,
    /// Root-only file on a separately protected volume.
    MountedFile,
    /// Interactive operator unlock.
    Interactive,
    /// Insecure key source for development only.
    InsecureDevelopment,
}

/// Rollback anchors for the encrypted local provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollbackAnchorKind {
    /// TPM NV monotonic counter.
    TpmNv,
    /// KMS-held generation state.
    Kms,
    /// Remotely stored signed checkpoint.
    RemoteCheckpoint,
    /// Separately protected local state file.
    ProtectedFile,
}

/// Explicit acknowledgement that a store has no rollback resistance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackResistance {
    /// No rollback resistance.
    None,
}

/// A configured secret provider for one namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SecretProviderConfig {
    /// In-memory provider (development only).
    InMemory,
    /// Encrypted local provider.
    EncryptedLocal {
        /// Absolute store directory.
        path: String,
        /// Key source.
        key_source: KeySourceKind,
        /// Rollback anchor, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rollback_anchor: Option<RollbackAnchorKind>,
        /// Explicit `none` acknowledgement, if no anchor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rollback_resistance: Option<RollbackResistance>,
    },
    /// External provider adapter.
    External {
        /// Adapter name, for example `bitwarden`.
        adapter: ConnectorName,
        /// Non-secret adapter settings.
        #[serde(default)]
        settings: BTreeMap<String, String>,
        /// Logical secret path to the vault's own identifier.
        #[serde(default)]
        mappings: BTreeMap<String, String>,
    },
}

impl SecretProviderConfig {
    fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        match self {
            Self::InMemory => {}
            Self::EncryptedLocal {
                path,
                rollback_anchor,
                rollback_resistance,
                ..
            } => {
                if !path.starts_with('/') || path.split('/').any(|s| s == "..") {
                    problems.push("`path` must be absolute and must not contain `..`".to_owned());
                }
                if rollback_anchor.is_some() && rollback_resistance.is_some() {
                    problems.push(
                        "set `rollback_anchor` or `rollback_resistance: none`, not both".to_owned(),
                    );
                }
            }
            Self::External {
                settings, mappings, ..
            } => {
                for path in mappings.keys() {
                    if SecretRef::parse(format!("secret://namespace/{path}")).is_err() {
                        problems.push(format!("mapping key `{path}` is not a valid secret path"));
                    }
                }
                for key in settings.keys() {
                    let lower = key.to_ascii_lowercase();
                    if CREDENTIAL_SETTING_WORDS.iter().any(|w| lower.contains(w)) {
                        problems.push(format!(
                            "setting `{key}` looks like a credential; bootstrap credentials must come from a credential source, not configuration"
                        ));
                    }
                }
            }
        }
        problems
    }
}

/// A registered resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRegistration {
    /// Connector profile serving this resource.
    pub connector: ConnectorName,
    /// Environment the resource belongs to.
    pub environment: Environment,
    /// Trusted values for `{resource.<name>}` placeholders.
    #[serde(default)]
    pub bindings: BTreeMap<BindingName, BindingValue>,
    /// Logical secret reference for each credential slot.
    pub credentials: BTreeMap<AuthSlot, SecretRef>,
    /// Resource-level constraints.
    #[serde(default)]
    pub constraints: ConstraintSet,
}

/// A registered secret and where it may be used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRegistration {
    /// Authoritative use binding (design §8.4).
    pub use_binding: SecretUseBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBundle {
    schema: String,
    deployment: Deployment,
    secret_providers: BTreeMap<Namespace, SecretProviderConfig>,
    profiles: Vec<ConnectorProfile>,
    #[serde(default)]
    resources: BTreeMap<ResourceId, ResourceRegistration>,
    #[serde(default)]
    secrets: BTreeMap<SecretRef, SecretRegistration>,
}

/// Everything the gateway needs to serve one resource action.
#[derive(Clone, Copy, Debug)]
pub struct ResolvedAction<'a> {
    /// Resource registration.
    pub resource: &'a ResourceRegistration,
    /// Connector profile.
    pub profile: &'a ConnectorProfile,
    /// Action specification.
    pub action: &'a ActionSpec,
    /// Secret reference for the action's credential slot.
    pub secret_ref: &'a SecretRef,
    /// Registration of that secret.
    pub secret: &'a SecretRegistration,
}

/// A fully validated configuration. It can only be obtained by loading a
/// bundle that passed every check.
#[derive(Clone, Debug)]
pub struct ValidatedConfig {
    deployment: Deployment,
    providers: BTreeMap<Namespace, SecretProviderConfig>,
    profiles: BTreeMap<ConnectorName, ConnectorProfile>,
    resources: BTreeMap<ResourceId, ResourceRegistration>,
    secrets: BTreeMap<SecretRef, SecretRegistration>,
}

impl ValidatedConfig {
    /// Deployment settings.
    #[must_use]
    pub fn deployment(&self) -> &Deployment {
        &self.deployment
    }

    /// Provider for a namespace.
    #[must_use]
    pub fn provider(&self, namespace: &Namespace) -> Option<&SecretProviderConfig> {
        self.providers.get(namespace)
    }

    /// Connector profile.
    #[must_use]
    pub fn profile(&self, connector: &ConnectorName) -> Option<&ConnectorProfile> {
        self.profiles.get(connector)
    }

    /// Resource registration.
    #[must_use]
    pub fn resource(&self, id: &ResourceId) -> Option<&ResourceRegistration> {
        self.resources.get(id)
    }

    /// Secret registration.
    #[must_use]
    pub fn secret(&self, reference: &SecretRef) -> Option<&SecretRegistration> {
        self.secrets.get(reference)
    }

    /// Resolves an action on a resource. Returns `None` if the resource is not
    /// registered or its connector has no such action.
    #[must_use]
    pub fn action(&self, resource: &ResourceId, action: &ActionName) -> Option<ResolvedAction<'_>> {
        let registration = self.resources.get(resource)?;
        let profile = self.profiles.get(&registration.connector)?;
        let spec = profile.actions.get(action)?;
        // Validation guarantees both lookups below succeed.
        let secret_ref = registration.credentials.get(&spec.credential_slot)?;
        let secret = self.secrets.get(secret_ref)?;
        Some(ResolvedAction {
            resource: registration,
            profile,
            action: spec,
            secret_ref,
            secret,
        })
    }
}

fn parse_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        duplicate_keys: DuplicateKeyPolicy::Error,
        // Merge keys can hide or override keys out of sight of a reviewer.
        merge_keys: MergeKeyPolicy::Error,
        // `yes`/`no`/`on`/`off` are strings, not booleans.
        strict_booleans: true,
        reject_unsupported_tags: true,
        // Do not echo configuration text in error messages.
        with_snippet: false,
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: 10_000,
            max_replay_stack_depth: 16,
            max_alias_expansions_per_anchor: 64,
        },
    }
}

/// Parses a YAML document with the hardened parser settings used for all
/// ACF configuration: size cap, duplicate keys rejected, merge keys rejected,
/// strict booleans, unsupported tags rejected, no input echoed in errors, and
/// a small alias-expansion budget.
///
/// # Errors
///
/// Returns [`ConfigError::TooLarge`] or [`ConfigError::Parse`].
pub fn parse_yaml<T: serde::de::DeserializeOwned>(input: &str) -> Result<T, ConfigError> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }
    serde_saphyr::from_str_with_options(input, parse_options())
        .map_err(|e| ConfigError::Parse(e.to_string()))
}

/// Parses and validates a YAML configuration bundle.
///
/// # Errors
///
/// Returns [`ConfigError`] if the document is too large, malformed, or
/// fails any validation check. All validation issues are reported together.
pub fn load_yaml(input: &str) -> Result<ValidatedConfig, ConfigError> {
    validate(parse_yaml::<RawBundle>(input)?)
}

struct Issues(Vec<ConfigIssue>);

impl Issues {
    fn push(&mut self, location: impl Into<String>, problem: impl Into<String>) {
        self.0.push(ConfigIssue {
            location: location.into(),
            problem: problem.into(),
        });
    }
}

fn validate(raw: RawBundle) -> Result<ValidatedConfig, ConfigError> {
    let mut issues = Issues(Vec::new());
    if raw.schema != CONFIG_SCHEMA {
        issues.push("schema", format!("must be `{CONFIG_SCHEMA}`"));
    }
    for (namespace, provider) in &raw.secret_providers {
        for problem in provider.problems() {
            issues.push(format!("secret_providers.{namespace}"), problem);
        }
    }

    let mut profiles = BTreeMap::new();
    for profile in raw.profiles {
        let location = format!("profiles[{}]", profile.connector);
        for (sub, problem) in profile.problems() {
            issues.push(format!("{location}.{sub}"), problem);
        }
        if profiles.contains_key(&profile.connector) {
            issues.push(location, "duplicate connector profile");
        } else {
            profiles.insert(profile.connector.clone(), profile);
        }
    }

    let has_provider = |reference: &SecretRef| {
        raw.secret_providers
            .keys()
            .any(|ns| ns.as_str() == reference.namespace())
    };

    for (id, resource) in &raw.resources {
        validate_resource(
            &mut issues,
            &format!("resources.{id}"),
            resource,
            &raw.deployment,
            &profiles,
            &raw.secrets,
            &has_provider,
        );
    }

    for (reference, registration) in &raw.secrets {
        let location = format!("secrets.{reference}");
        if !has_provider(reference) {
            issues.push(
                &location,
                "no secret provider is configured for this namespace",
            );
        }
        if registration.use_binding.environment() != &raw.deployment.environment {
            issues.push(
                location,
                "use binding environment differs from the deployment environment",
            );
        }
    }

    if issues.0.is_empty() {
        Ok(ValidatedConfig {
            deployment: raw.deployment,
            providers: raw.secret_providers,
            profiles,
            resources: raw.resources,
            secrets: raw.secrets,
        })
    } else {
        Err(ConfigError::Invalid(issues.0))
    }
}

fn validate_resource(
    issues: &mut Issues,
    location: &str,
    resource: &ResourceRegistration,
    deployment: &Deployment,
    profiles: &BTreeMap<ConnectorName, ConnectorProfile>,
    secrets: &BTreeMap<SecretRef, SecretRegistration>,
    has_provider: &dyn Fn(&SecretRef) -> bool,
) {
    if resource.environment != deployment.environment {
        issues.push(
            location,
            "environment differs from the deployment environment",
        );
    }
    let Some(profile) = profiles.get(&resource.connector) else {
        issues.push(
            location,
            format!("no profile for connector `{}`", resource.connector),
        );
        return;
    };

    let used_bindings: BTreeSet<&BindingName> = profile
        .actions
        .values()
        .flat_map(|a| a.path.resource_bindings())
        .collect();
    for name in &used_bindings {
        if !resource.bindings.contains_key(*name) {
            issues.push(
                format!("{location}.bindings"),
                format!("missing binding `{name}`"),
            );
        }
    }
    for name in resource.bindings.keys() {
        if !used_bindings.contains(name) {
            issues.push(
                format!("{location}.bindings"),
                format!("binding `{name}` is not used by any action"),
            );
        }
    }

    validate_credentials(issues, location, resource, profile, secrets, has_provider);

    for param in resource.constraints.constrained_params() {
        if !profile.declares_param(param) {
            issues.push(
                format!("{location}.constraints"),
                format!(
                    "`params.{param}` is not a parameter of any `{}` action",
                    resource.connector
                ),
            );
        }
    }
    for action in resource.constraints.denied_actions() {
        if !profile.actions.contains_key(action) {
            issues.push(
                format!("{location}.constraints"),
                format!(
                    "denied action `{action}` is not a `{}` action",
                    resource.connector
                ),
            );
        }
    }
}

fn validate_credentials(
    issues: &mut Issues,
    location: &str,
    resource: &ResourceRegistration,
    profile: &ConnectorProfile,
    secrets: &BTreeMap<SecretRef, SecretRegistration>,
    has_provider: &dyn Fn(&SecretRef) -> bool,
) {
    let slots = profile.credential_slots();
    for slot in &slots {
        if !resource.credentials.contains_key(*slot) {
            issues.push(
                format!("{location}.credentials"),
                format!("missing credential slot `{slot}`"),
            );
        }
    }
    for (slot, reference) in &resource.credentials {
        let slot_location = format!("{location}.credentials.{slot}");
        if !slots.contains(slot) {
            issues.push(&slot_location, "slot is not used by any action");
            continue;
        }
        if !has_provider(reference) {
            issues.push(
                &slot_location,
                "no secret provider is configured for this namespace",
            );
        }
        let Some(registration) = secrets.get(reference) else {
            issues.push(
                &slot_location,
                format!("`{reference}` has no secret registration"),
            );
            continue;
        };
        let binding = &registration.use_binding;
        if !binding.permits(&resource.connector, profile.base_url.origin(), slot) {
            issues.push(
                &slot_location,
                format!(
                    "use binding of `{reference}` does not permit connector `{}`, origin `{}`, slot `{slot}`",
                    resource.connector,
                    profile.base_url.origin()
                ),
            );
        }
        if binding.environment() != &resource.environment {
            issues.push(
                &slot_location,
                format!("use binding of `{reference}` is for a different environment"),
            );
        }
    }
}
