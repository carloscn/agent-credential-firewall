//! Typed, deny-by-default gateway policy (`acf.policy/v1`).
//!
//! ```yaml
//! schema: acf.policy/v1
//! version: policy-2026-10-24.1
//! rules:
//!   - id: dns-operators
//!     effect: allow
//!     principals: [workload:agent-prod-17]
//!     actions: [cloudflare.dns.records.list, cloudflare.dns.records.create]
//!     resources: ["cloudflare-zone:example.com"]
//!     constraints:
//!       params.name: { dns_within: example.com }
//!   - id: no-production-mutations-from-laptops
//!     effect: deny
//!     labels: [laptop]
//!     actions: [cloudflare.dns.records.create]
//!     resources: ["cloudflare-zone:example.com"]
//! ```
//!
//! Semantics:
//!
//! - With no matching rule, the request is denied.
//! - Any matching `deny` rule denies, whatever else matches.
//! - Otherwise the request is allowed if at least one matching `allow` rule's
//!   constraints pass.
//! - `approval: required` on any matching allow rule requires approval. There
//!   is no way to write `approval: none`, so policy cannot weaken a default.
//! - A rule's subject matches when the caller is one of `principals` (if
//!   given) and carries every label in `labels` (if given). Each rule must
//!   give at least one of the two.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use acf_config::{ConfigError, ConfigIssue, ValidatedConfig, parse_yaml};
use acf_identity::{IdentityContext, Label};
use acf_protocol::{
    ActionName, ConstraintSet, ConstraintViolation, ParamName, PrincipalId, Quotas, ResourceId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema identifier for policy documents.
pub const POLICY_SCHEMA: &str = "acf.policy/v1";

const MAX_NAME_LEN: usize = 64;

fn is_policy_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

macro_rules! define_name {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates the value.
            ///
            /// # Errors
            ///
            /// Returns a description if the value is malformed.
            pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
                let value = value.into();
                if is_policy_name(&value) {
                    Ok(Self(value))
                } else {
                    Err(concat!($what, " must be 1-64 characters of [A-Za-z0-9-_.:]"))
                }
            }

            /// Returns the value as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = &'static str;

            fn try_from(value: String) -> Result<Self, &'static str> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
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
    /// Policy version, recorded in audit events and approval objects.
    PolicyVersion,
    "policy version"
);
define_name!(
    /// Rule identifier.
    RuleId,
    "rule id"
);

/// Rule effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Allows matching requests whose constraints pass.
    Allow,
    /// Denies matching requests unconditionally.
    Deny,
}

/// The only approval setting a rule can express.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleApproval {
    /// Matching requests need a transaction approval.
    Required,
}

/// One policy rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Unique rule identifier.
    pub id: RuleId,
    /// Allow or deny.
    pub effect: Effect,
    /// Matching principals. Empty means "any principal with the labels".
    #[serde(default)]
    pub principals: BTreeSet<PrincipalId>,
    /// Labels the caller must all carry.
    #[serde(default)]
    pub labels: BTreeSet<Label>,
    /// Actions the rule covers. Exact names only.
    pub actions: BTreeSet<ActionName>,
    /// Resources the rule covers. Exact identifiers only.
    pub resources: BTreeSet<ResourceId>,
    /// Constraints for `allow` rules.
    #[serde(default)]
    pub constraints: ConstraintSet,
    /// Approval requirement for `allow` rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<RuleApproval>,
}

impl PolicyRule {
    fn matches(
        &self,
        identity: &IdentityContext,
        action: &ActionName,
        resource: &ResourceId,
    ) -> bool {
        (self.principals.is_empty() || self.principals.contains(&identity.principal))
            && self.labels.is_subset(&identity.labels)
            && self.actions.contains(action)
            && self.resources.contains(resource)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    schema: String,
    version: PolicyVersion,
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

/// A loaded policy, validated against one [`ValidatedConfig`].
#[derive(Clone, Debug)]
pub struct Policy {
    version: PolicyVersion,
    rules: Vec<PolicyRule>,
}

/// Why policy refused a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDenial {
    /// No rule matched.
    NoMatchingRule,
    /// A `deny` rule matched.
    DeniedByRule(RuleId),
    /// Allow rules matched, but none of their constraints passed. Carries
    /// the first matching rule's violation.
    Constraint(RuleId, ConstraintViolation),
}

/// What policy granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyGrant {
    /// Allow rules whose constraints passed.
    pub rules: Vec<RuleId>,
    /// Whether a matching allow rule requires approval.
    pub approval_required: bool,
    /// Smallest quotas among the passing rules.
    pub quotas: Quotas,
}

impl Policy {
    /// The policy version.
    #[must_use]
    pub fn version(&self) -> &PolicyVersion {
        &self.version
    }

    /// The rules, in document order.
    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Evaluates the policy. `declared` reports which parameters the action
    /// declares; `params` must already be normalized.
    ///
    /// # Errors
    ///
    /// Returns the [`PolicyDenial`].
    pub fn evaluate(
        &self,
        identity: &IdentityContext,
        action: &ActionName,
        resource: &ResourceId,
        declared: impl Fn(&ParamName) -> bool,
        params: &Map<String, Value>,
    ) -> Result<PolicyGrant, PolicyDenial> {
        let matching: Vec<&PolicyRule> = self
            .rules
            .iter()
            .filter(|r| r.matches(identity, action, resource))
            .collect();
        if let Some(deny) = matching.iter().find(|r| r.effect == Effect::Deny) {
            return Err(PolicyDenial::DeniedByRule(deny.id.clone()));
        }
        let allows: Vec<&PolicyRule> = matching
            .into_iter()
            .filter(|r| r.effect == Effect::Allow)
            .collect();
        if allows.is_empty() {
            return Err(PolicyDenial::NoMatchingRule);
        }

        let mut first_violation = None;
        let mut passing = Vec::new();
        for rule in &allows {
            let result = rule
                .constraints
                .check_action(action)
                .and_then(|()| rule.constraints.check_params(&declared, params));
            match result {
                Ok(()) => passing.push(*rule),
                Err(violation) => {
                    first_violation.get_or_insert_with(|| (rule.id.clone(), violation));
                }
            }
        }
        if passing.is_empty() {
            // Every allow rule recorded a violation; the fallback keeps the
            // impossible case closed rather than panicking.
            return Err(match first_violation {
                Some((rule, violation)) => PolicyDenial::Constraint(rule, violation),
                None => PolicyDenial::NoMatchingRule,
            });
        }

        let quotas = passing
            .iter()
            .map(|r| r.constraints.clone())
            .reduce(|a, b| a.intersect(&b))
            .map(|c| c.quotas())
            .unwrap_or_default();
        Ok(PolicyGrant {
            rules: passing.iter().map(|r| r.id.clone()).collect(),
            approval_required: allows
                .iter()
                .any(|r| r.approval == Some(RuleApproval::Required)),
            quotas,
        })
    }
}

/// Parses a policy document and validates it against `config`.
///
/// # Errors
///
/// Returns [`ConfigError`] if the document is malformed or refers to
/// resources, actions, or parameters `config` does not define.
pub fn load_policy_yaml(input: &str, config: &ValidatedConfig) -> Result<Policy, ConfigError> {
    let raw: RawPolicy = parse_yaml(input)?;
    let mut issues = Vec::new();
    let mut issue =
        |location: String, problem: String| issues.push(ConfigIssue { location, problem });

    if raw.schema != POLICY_SCHEMA {
        issue("schema".to_owned(), format!("must be `{POLICY_SCHEMA}`"));
    }
    let mut seen = BTreeMap::new();
    for (index, rule) in raw.rules.iter().enumerate() {
        let location = format!("rules[{index}] ({})", rule.id);
        if seen.insert(rule.id.clone(), index).is_some() {
            issue(location.clone(), "duplicate rule id".to_owned());
        }
        if rule.principals.is_empty() && rule.labels.is_empty() {
            issue(
                location.clone(),
                "a rule must name `principals` or `labels`".to_owned(),
            );
        }
        if rule.actions.is_empty() || rule.resources.is_empty() {
            issue(
                location.clone(),
                "`actions` and `resources` must not be empty".to_owned(),
            );
        }
        if rule.effect == Effect::Deny && (!rule.constraints.is_empty() || rule.approval.is_some())
        {
            issue(
                location.clone(),
                "`deny` rules apply unconditionally; remove `constraints` and `approval`"
                    .to_owned(),
            );
        }
        for resource in &rule.resources {
            for action in &rule.actions {
                if config.action(resource, action).is_none() {
                    issue(
                        location.clone(),
                        format!("`{action}` on `{resource}` is not a registered resource action"),
                    );
                }
            }
        }
        for param in rule.constraints.constrained_params() {
            let declared = rule.resources.iter().any(|resource| {
                rule.actions.iter().any(|action| {
                    config
                        .action(resource, action)
                        .is_some_and(|resolved| resolved.action.declares(param))
                })
            });
            if !declared {
                issue(
                    location.clone(),
                    format!("`params.{param}` is not a parameter of any listed action"),
                );
            }
        }
    }

    if issues.is_empty() {
        Ok(Policy {
            version: raw.version,
            rules: raw.rules,
        })
    } else {
        Err(ConfigError::Invalid(issues))
    }
}
