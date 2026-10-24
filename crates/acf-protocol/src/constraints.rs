//! Typed constraint language (design §8.3).
//!
//! Resource registrations, task capabilities, and gateway policy all use this
//! language. It is deterministic, does no I/O, and is not Turing-complete.
//!
//! # Semantics
//!
//! - Constraints evaluate **normalized** values. Connector domain types
//!   normalize first; a DNS value that is not already canonical is rejected
//!   rather than normalized here.
//! - A field constraint applies to an action only if the action declares that
//!   parameter. When it applies, an absent value is a violation, so omitting
//!   an optional parameter cannot widen a request.
//! - Composition is conjunction. [`ConstraintSet::intersect`] keeps every
//!   field constraint from both inputs, unions denied actions, and takes the
//!   smaller quota. A value passes the intersection exactly when it passes
//!   both inputs, so intersection never broadens either one.
//!
//! # Format
//!
//! ```yaml
//! params.type: { in: [A, AAAA, CNAME, TXT] }
//! params.name: { dns_within: example.com, not_in: [example.com], allow_wildcard: false }
//! params.ttl: { range: [60, 86400] }
//! actions: { deny: [cloudflare.dns.records.delete] }
//! quotas: { mutations_per_task: 5 }
//! ```
//!
//! After an intersection, one field may carry several constraints; they are
//! then written as a list: `params.name: [{ ... }, { ... }]`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::ids::ActionName;

const PARAMS_PREFIX: &str = "params.";
const MAX_PARAM_NAME_LEN: usize = 63;
const MAX_GLOB_LEN: usize = 128;

/// A malformed constraint. Never echoes the rejected input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConstraintError {
    /// A parameter name is malformed.
    #[error("parameter names must be 1-63 characters of [a-z0-9_], starting with a letter")]
    InvalidParamName,
    /// A field constraint has no operator.
    #[error("a field constraint needs at least one operator")]
    NoOperator,
    /// An `in`, `not_in`, or `glob` list is empty.
    #[error("`in`, `not_in`, and `glob` lists must not be empty")]
    EmptyList,
    /// `range` has `min > max`.
    #[error("`range` must be [min, max] with min <= max")]
    InvalidRange,
    /// `allow_wildcard` without `dns_within`.
    #[error("`allow_wildcard` requires `dns_within`")]
    WildcardWithoutZone,
    /// A `dns_within` zone is not a canonical DNS name.
    #[error("`dns_within` must be a lowercase DNS name without a trailing dot or wildcard")]
    InvalidZone,
    /// A glob pattern is malformed.
    #[error("glob patterns use [A-Za-z0-9-_.:@/] and `*`, up to 128 bytes")]
    InvalidGlob,
}

/// A parameter name, for example `name` or `ttl`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ParamName(String);

impl ParamName {
    /// Validates a parameter name.
    ///
    /// # Errors
    ///
    /// Returns [`ConstraintError::InvalidParamName`] if the name is malformed.
    pub fn new(value: impl Into<String>) -> Result<Self, ConstraintError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_PARAM_NAME_LEN
            && value.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if valid {
            Ok(Self(value))
        } else {
            Err(ConstraintError::InvalidParamName)
        }
    }

    /// Returns the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ParamName {
    type Error = ConstraintError;

    fn try_from(value: String) -> Result<Self, ConstraintError> {
        Self::new(value)
    }
}

impl From<ParamName> for String {
    fn from(name: ParamName) -> Self {
        name.0
    }
}

impl fmt::Display for ParamName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A scalar constraint operand. Comparison is type-strict: the string `"300"`
/// never equals the integer `300`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    /// A boolean.
    Bool(bool),
    /// A signed integer.
    Integer(i64),
    /// A string.
    String(String),
}

impl Scalar {
    /// Returns whether `value` is this exact scalar.
    #[must_use]
    pub fn matches(&self, value: &Value) -> bool {
        match (self, value) {
            (Self::Bool(a), Value::Bool(b)) => a == b,
            (Self::Integer(a), Value::Number(n)) => n.as_i64() == Some(*a),
            (Self::String(a), Value::String(b)) => a == b,
            _ => false,
        }
    }
}

/// Inclusive integer range, written `[min, max]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "[i64; 2]", into = "[i64; 2]")]
pub struct IntRange {
    min: i64,
    max: i64,
}

impl IntRange {
    /// Builds a range.
    ///
    /// # Errors
    ///
    /// Returns [`ConstraintError::InvalidRange`] if `min > max`.
    pub fn new(min: i64, max: i64) -> Result<Self, ConstraintError> {
        if min <= max {
            Ok(Self { min, max })
        } else {
            Err(ConstraintError::InvalidRange)
        }
    }

    /// Lower bound.
    #[must_use]
    pub fn min(self) -> i64 {
        self.min
    }

    /// Upper bound.
    #[must_use]
    pub fn max(self) -> i64 {
        self.max
    }
}

impl TryFrom<[i64; 2]> for IntRange {
    type Error = ConstraintError;

    fn try_from([min, max]: [i64; 2]) -> Result<Self, ConstraintError> {
        Self::new(min, max)
    }
}

impl From<IntRange> for [i64; 2] {
    fn from(range: IntRange) -> Self {
        [range.min, range.max]
    }
}

fn is_ldh_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A canonical DNS zone: lowercase LDH labels, no trailing dot, no wildcard.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsZone(String);

impl DnsZone {
    /// Validates a zone.
    ///
    /// # Errors
    ///
    /// Returns [`ConstraintError::InvalidZone`] if the zone is not canonical.
    pub fn new(value: impl Into<String>) -> Result<Self, ConstraintError> {
        let value = value.into();
        if value.len() <= 253 && value.split('.').all(is_ldh_label) {
            Ok(Self(value))
        } else {
            Err(ConstraintError::InvalidZone)
        }
    }

    /// Returns the zone as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DnsZone {
    type Error = ConstraintError;

    fn try_from(value: String) -> Result<Self, ConstraintError> {
        Self::new(value)
    }
}

impl From<DnsZone> for String {
    fn from(zone: DnsZone) -> Self {
        zone.0
    }
}

/// A glob over identifier strings. `*` matches any run of characters except
/// `/`, so `repo:example/*` matches `repo:example/backend` but not
/// `repo:example/backend/extra`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GlobPattern(String);

impl GlobPattern {
    /// Validates a pattern.
    ///
    /// # Errors
    ///
    /// Returns [`ConstraintError::InvalidGlob`] if the pattern is malformed.
    pub fn new(value: impl Into<String>) -> Result<Self, ConstraintError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_GLOB_LEN
            && value.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'-' | b'_' | b'.' | b':' | b'@' | b'/' | b'*')
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(ConstraintError::InvalidGlob)
        }
    }

    /// Returns whether `candidate` matches the whole pattern.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        // matched[j]: pattern[..i] matches candidate[..j]. O(len(p) * len(c)).
        let pattern = self.0.as_bytes();
        let text = candidate.as_bytes();
        let mut matched = vec![false; text.len() + 1];
        matched[0] = true;
        for &p in pattern {
            let mut next = vec![false; text.len() + 1];
            if p == b'*' {
                next[0] = matched[0];
                for j in 1..=text.len() {
                    next[j] = matched[j] || (next[j - 1] && text[j - 1] != b'/');
                }
            } else {
                for j in 1..=text.len() {
                    next[j] = matched[j - 1] && text[j - 1] == p;
                }
            }
            matched = next;
        }
        matched[text.len()]
    }
}

impl TryFrom<String> for GlobPattern {
    type Error = ConstraintError;

    fn try_from(value: String) -> Result<Self, ConstraintError> {
        Self::new(value)
    }
}

impl From<GlobPattern> for String {
    fn from(pattern: GlobPattern) -> Self {
        pattern.0
    }
}

/// Why a value failed a constraint. Carries no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ViolationKind {
    /// A constrained parameter was absent.
    #[error("required by a constraint but absent")]
    Missing,
    /// The value has the wrong type, or is not in canonical form.
    #[error("has the wrong type or is not normalized")]
    TypeMismatch,
    /// Not in the `in` list.
    #[error("is not an allowed value")]
    NotAllowed,
    /// In the `not_in` list.
    #[error("is an excluded value")]
    Excluded,
    /// Outside `range`.
    #[error("is outside the allowed range")]
    OutOfRange,
    /// Not inside the `dns_within` zone.
    #[error("is outside the allowed DNS zone")]
    OutsideZone,
    /// A wildcard name where wildcards are not allowed.
    #[error("is a wildcard name, which is not allowed")]
    WildcardDenied,
    /// Matches no `glob` pattern.
    #[error("matches no allowed pattern")]
    NoGlobMatch,
    /// The action is denied.
    #[error("action is denied")]
    ActionDenied,
}

/// A failed constraint: which parameter (or the action) and why.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{subject} {kind}")]
pub struct ConstraintViolation {
    /// `params.<name>` or `action`.
    pub subject: String,
    /// Reason.
    pub kind: ViolationKind,
}

/// Constraints on one parameter. All present operators must hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawFieldConstraint")]
pub struct FieldConstraint {
    #[serde(rename = "in", skip_serializing_if = "Option::is_none")]
    one_of: Option<BTreeSet<Scalar>>,
    #[serde(rename = "not_in", skip_serializing_if = "Option::is_none")]
    none_of: Option<BTreeSet<Scalar>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<IntRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_within: Option<DnsZone>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_wildcard: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    glob: Option<Vec<GlobPattern>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFieldConstraint {
    #[serde(rename = "in")]
    one_of: Option<BTreeSet<Scalar>>,
    #[serde(rename = "not_in")]
    none_of: Option<BTreeSet<Scalar>>,
    range: Option<IntRange>,
    dns_within: Option<DnsZone>,
    allow_wildcard: Option<bool>,
    glob: Option<Vec<GlobPattern>>,
}

impl TryFrom<RawFieldConstraint> for FieldConstraint {
    type Error = ConstraintError;

    fn try_from(raw: RawFieldConstraint) -> Result<Self, ConstraintError> {
        let constraint = Self {
            one_of: raw.one_of,
            none_of: raw.none_of,
            range: raw.range,
            dns_within: raw.dns_within,
            allow_wildcard: raw.allow_wildcard,
            glob: raw.glob,
        };
        constraint.validate()?;
        Ok(constraint)
    }
}

impl FieldConstraint {
    /// Value must equal one of `values`.
    ///
    /// # Errors
    ///
    /// Returns [`ConstraintError::EmptyList`] if `values` is empty.
    pub fn one_of(values: impl IntoIterator<Item = Scalar>) -> Result<Self, ConstraintError> {
        let constraint = Self {
            one_of: Some(values.into_iter().collect()),
            ..Self::empty()
        };
        constraint.validate()?;
        Ok(constraint)
    }

    /// Value must be an integer in `range`.
    #[must_use]
    pub fn in_range(range: IntRange) -> Self {
        Self {
            range: Some(range),
            ..Self::empty()
        }
    }

    /// Value must be a DNS name inside `zone`; wildcard names only when
    /// `allow_wildcard` is true.
    #[must_use]
    pub fn dns_within(zone: DnsZone, allow_wildcard: bool) -> Self {
        Self {
            dns_within: Some(zone),
            allow_wildcard: Some(allow_wildcard),
            ..Self::empty()
        }
    }

    fn empty() -> Self {
        Self {
            one_of: None,
            none_of: None,
            range: None,
            dns_within: None,
            allow_wildcard: None,
            glob: None,
        }
    }

    fn validate(&self) -> Result<(), ConstraintError> {
        if self.one_of.is_none()
            && self.none_of.is_none()
            && self.range.is_none()
            && self.dns_within.is_none()
            && self.glob.is_none()
        {
            return Err(ConstraintError::NoOperator);
        }
        if self.one_of.as_ref().is_some_and(BTreeSet::is_empty)
            || self.none_of.as_ref().is_some_and(BTreeSet::is_empty)
            || self.glob.as_ref().is_some_and(Vec::is_empty)
        {
            return Err(ConstraintError::EmptyList);
        }
        if self.allow_wildcard.is_some() && self.dns_within.is_none() {
            return Err(ConstraintError::WildcardWithoutZone);
        }
        Ok(())
    }

    /// Checks one parameter value.
    ///
    /// # Errors
    ///
    /// Returns the first [`ViolationKind`] found.
    pub fn check(&self, value: Option<&Value>) -> Result<(), ViolationKind> {
        let value = value.ok_or(ViolationKind::Missing)?;
        if let Some(allowed) = &self.one_of
            && !allowed.iter().any(|s| s.matches(value))
        {
            return Err(ViolationKind::NotAllowed);
        }
        if let Some(excluded) = &self.none_of
            && excluded.iter().any(|s| s.matches(value))
        {
            return Err(ViolationKind::Excluded);
        }
        if let Some(range) = self.range {
            let n = value.as_i64().ok_or(ViolationKind::TypeMismatch)?;
            if n < range.min || n > range.max {
                return Err(ViolationKind::OutOfRange);
            }
        }
        if let Some(zone) = &self.dns_within {
            let name = value.as_str().ok_or(ViolationKind::TypeMismatch)?;
            check_dns_within(name, zone, self.allow_wildcard.unwrap_or(false))?;
        }
        if let Some(patterns) = &self.glob {
            let text = value.as_str().ok_or(ViolationKind::TypeMismatch)?;
            if !patterns.iter().any(|p| p.matches(text)) {
                return Err(ViolationKind::NoGlobMatch);
            }
        }
        Ok(())
    }
}

fn check_dns_within(name: &str, zone: &DnsZone, allow_wildcard: bool) -> Result<(), ViolationKind> {
    // Values must already be canonical; anything else means normalization
    // was skipped, so fail closed instead of normalizing here.
    let mut labels = name.split('.');
    let first = labels.next().ok_or(ViolationKind::TypeMismatch)?;
    let wildcard = first == "*";
    if !(wildcard || is_ldh_label(first)) || !labels.all(is_ldh_label) || name.len() > 253 {
        return Err(ViolationKind::TypeMismatch);
    }
    let zone = zone.as_str();
    let inside = name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'));
    if !inside {
        return Err(ViolationKind::OutsideZone);
    }
    if wildcard && !allow_wildcard {
        return Err(ViolationKind::WildcardDenied);
    }
    Ok(())
}

/// Per-task usage quotas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quotas {
    /// Maximum requests per task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_task: Option<u32>,
    /// Maximum mutations per task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutations_per_task: Option<u32>,
}

impl Quotas {
    fn intersect(self, other: Self) -> Self {
        fn min(a: Option<u32>, b: Option<u32>) -> Option<u32> {
            match (a, b) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        }
        Self {
            requests_per_task: min(self.requests_per_task, other.requests_per_task),
            mutations_per_task: min(self.mutations_per_task, other.mutations_per_task),
        }
    }

    fn is_empty(self) -> bool {
        self.requests_per_task.is_none() && self.mutations_per_task.is_none()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionsConstraint {
    deny: BTreeSet<ActionName>,
}

/// A set of constraints from one source, or the intersection of several.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConstraintSet {
    fields: BTreeMap<ParamName, Vec<FieldConstraint>>,
    denied_actions: BTreeSet<ActionName>,
    quotas: Quotas,
}

impl ConstraintSet {
    /// Returns whether the set constrains nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.denied_actions.is_empty() && self.quotas.is_empty()
    }

    /// Adds a constraint on `param`.
    #[must_use]
    pub fn with_field(mut self, param: ParamName, constraint: FieldConstraint) -> Self {
        self.fields.entry(param).or_default().push(constraint);
        self
    }

    /// Denies `action`.
    #[must_use]
    pub fn with_denied_action(mut self, action: ActionName) -> Self {
        self.denied_actions.insert(action);
        self
    }

    /// Sets quotas.
    #[must_use]
    pub fn with_quotas(mut self, quotas: Quotas) -> Self {
        self.quotas = quotas;
        self
    }

    /// The conjunction of `self` and `other`.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        let mut fields = self.fields.clone();
        for (param, constraints) in &other.fields {
            fields
                .entry(param.clone())
                .or_default()
                .extend(constraints.iter().cloned());
        }
        Self {
            fields,
            denied_actions: self
                .denied_actions
                .union(&other.denied_actions)
                .cloned()
                .collect(),
            quotas: self.quotas.intersect(other.quotas),
        }
    }

    /// Parameters this set constrains.
    pub fn constrained_params(&self) -> impl Iterator<Item = &ParamName> {
        self.fields.keys()
    }

    /// Actions this set denies.
    #[must_use]
    pub fn denied_actions(&self) -> &BTreeSet<ActionName> {
        &self.denied_actions
    }

    /// Quotas.
    #[must_use]
    pub fn quotas(&self) -> Quotas {
        self.quotas
    }

    /// Checks that `action` is not denied.
    ///
    /// # Errors
    ///
    /// Returns a [`ViolationKind::ActionDenied`] violation.
    pub fn check_action(&self, action: &ActionName) -> Result<(), ConstraintViolation> {
        if self.denied_actions.contains(action) {
            Err(ConstraintViolation {
                subject: "action".to_owned(),
                kind: ViolationKind::ActionDenied,
            })
        } else {
            Ok(())
        }
    }

    /// Checks normalized parameters. Constraints on parameters for which
    /// `declared` returns false do not apply to this action.
    ///
    /// # Errors
    ///
    /// Returns the first violation, in parameter-name order.
    pub fn check_params(
        &self,
        declared: impl Fn(&ParamName) -> bool,
        params: &Map<String, Value>,
    ) -> Result<(), ConstraintViolation> {
        for (param, constraints) in &self.fields {
            if !declared(param) {
                continue;
            }
            let value = params.get(param.as_str());
            for constraint in constraints {
                constraint
                    .check(value)
                    .map_err(|kind| ConstraintViolation {
                        subject: format!("{PARAMS_PREFIX}{param}"),
                        kind,
                    })?;
            }
        }
        Ok(())
    }
}

impl Serialize for ConstraintSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (param, constraints) in &self.fields {
            let key = format!("{PARAMS_PREFIX}{param}");
            if let [single] = constraints.as_slice() {
                map.serialize_entry(&key, single)?;
            } else {
                map.serialize_entry(&key, constraints)?;
            }
        }
        if !self.denied_actions.is_empty() {
            map.serialize_entry(
                "actions",
                &ActionsConstraint {
                    deny: self.denied_actions.clone(),
                },
            )?;
        }
        if !self.quotas.is_empty() {
            map.serialize_entry("quotas", &self.quotas)?;
        }
        map.end()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(FieldConstraint),
    Many(Vec<FieldConstraint>),
}

impl<'de> Deserialize<'de> for ConstraintSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SetVisitor;

        impl<'de> Visitor<'de> for SetVisitor {
            type Value = ConstraintSet;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of `params.<name>`, `actions`, and `quotas` constraints")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ConstraintSet, A::Error> {
                let mut set = ConstraintSet::default();
                let mut seen = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate constraint key"));
                    }
                    if key == "actions" {
                        set.denied_actions = map.next_value::<ActionsConstraint>()?.deny;
                    } else if key == "quotas" {
                        set.quotas = map.next_value()?;
                    } else if let Some(name) = key.strip_prefix(PARAMS_PREFIX) {
                        let param = ParamName::new(name).map_err(de::Error::custom)?;
                        let constraints = match map.next_value::<OneOrMany>()? {
                            OneOrMany::One(c) => vec![c],
                            OneOrMany::Many(cs) if !cs.is_empty() => cs,
                            OneOrMany::Many(_) => {
                                return Err(de::Error::custom(ConstraintError::EmptyList));
                            }
                        };
                        set.fields.insert(param, constraints);
                    } else {
                        return Err(de::Error::custom(
                            "unknown constraint key; expected `params.<name>`, `actions`, or `quotas`",
                        ));
                    }
                }
                Ok(set)
            }
        }

        deserializer.deserialize_map(SetVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn set(value: Value) -> ConstraintSet {
        serde_json::from_value(value).unwrap()
    }

    fn all_params(_: &ParamName) -> bool {
        true
    }

    fn params(value: &Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn design_resource_constraints() -> ConstraintSet {
        set(json!({
            "params.type": { "in": ["A", "AAAA", "CNAME", "TXT"] },
            "params.name": {
                "dns_within": "example.com",
                "not_in": ["example.com", "mail.example.com"],
                "allow_wildcard": false
            },
            "params.ttl": { "range": [60, 86400] },
            "actions": { "deny": ["cloudflare.dns.records.delete"] },
            "quotas": { "mutations_per_task": 5 }
        }))
    }

    #[test]
    fn design_example_accepts_and_rejects() {
        let c = design_resource_constraints();
        let ok = params(&json!({ "type": "A", "name": "api.example.com", "ttl": 300 }));
        assert_eq!(c.check_params(all_params, &ok), Ok(()));

        for (bad, kind) in [
            (
                json!({ "type": "MX", "name": "api.example.com", "ttl": 300 }),
                ViolationKind::NotAllowed,
            ),
            (
                json!({ "type": "A", "name": "mail.example.com", "ttl": 300 }),
                ViolationKind::Excluded,
            ),
            (
                json!({ "type": "A", "name": "api.evil.com", "ttl": 300 }),
                ViolationKind::OutsideZone,
            ),
            (
                json!({ "type": "A", "name": "notexample.com", "ttl": 300 }),
                ViolationKind::OutsideZone,
            ),
            (
                json!({ "type": "A", "name": "*.example.com", "ttl": 300 }),
                ViolationKind::WildcardDenied,
            ),
            (
                json!({ "type": "A", "name": "API.example.com", "ttl": 300 }),
                ViolationKind::TypeMismatch,
            ),
            (
                json!({ "type": "A", "name": "api.example.com.", "ttl": 300 }),
                ViolationKind::TypeMismatch,
            ),
            (
                json!({ "type": "A", "name": "api.example.com", "ttl": 30 }),
                ViolationKind::OutOfRange,
            ),
            (
                json!({ "type": "A", "name": "api.example.com", "ttl": "300" }),
                ViolationKind::TypeMismatch,
            ),
            (
                json!({ "type": "A", "name": "api.example.com" }),
                ViolationKind::Missing,
            ),
        ] {
            let error = c.check_params(all_params, &params(&bad)).unwrap_err();
            assert_eq!(error.kind, kind, "{bad}");
        }

        let delete = ActionName::new("cloudflare.dns.records.delete").unwrap();
        assert_eq!(
            c.check_action(&delete).unwrap_err().kind,
            ViolationKind::ActionDenied
        );
    }

    #[test]
    fn constraints_on_undeclared_params_do_not_apply() {
        let c = design_resource_constraints();
        let list_declares = |p: &ParamName| matches!(p.as_str(), "name" | "type");
        let list = params(&json!({ "type": "A", "name": "api.example.com" }));
        assert_eq!(c.check_params(list_declares, &list), Ok(()));
    }

    #[test]
    fn omitting_a_declared_param_cannot_widen_a_request() {
        let capability = set(json!({ "params.name": { "in": ["api.example.com"] } }));
        let error = capability
            .check_params(all_params, &params(&json!({})))
            .unwrap_err();
        assert_eq!(error.kind, ViolationKind::Missing);
    }

    #[test]
    fn intersection_never_broadens_either_input() {
        let resource = design_resource_constraints();
        let capability = set(json!({
            "params.name": { "in": ["api.example.com", "www.example.com", "api.evil.com"] },
            "params.type": { "in": ["A", "MX"] },
            "quotas": { "mutations_per_task": 9, "requests_per_task": 50 }
        }));
        let both = resource.intersect(&capability);

        let names = [
            "api.example.com",
            "www.example.com",
            "api.evil.com",
            "mail.example.com",
            "*.example.com",
        ];
        let types = ["A", "AAAA", "MX", "TXT"];
        let ttls = [59, 60, 300, 86400, 86401];
        for name in names {
            for record_type in types {
                for ttl in ttls {
                    let p = params(&json!({ "name": name, "type": record_type, "ttl": ttl }));
                    let a = resource.check_params(all_params, &p).is_ok();
                    let b = capability.check_params(all_params, &p).is_ok();
                    let ab = both.check_params(all_params, &p).is_ok();
                    assert_eq!(ab, a && b, "{p:?}");
                }
            }
        }
        assert_eq!(both.quotas().mutations_per_task, Some(5));
        assert_eq!(both.quotas().requests_per_task, Some(50));
        assert!(
            both.denied_actions()
                .contains(&ActionName::new("cloudflare.dns.records.delete").unwrap())
        );
    }

    #[test]
    fn intersection_round_trips_through_serde() {
        let both = design_resource_constraints().intersect(&set(
            json!({ "params.name": { "in": ["api.example.com"] } }),
        ));
        let encoded = serde_json::to_value(&both).unwrap();
        assert!(encoded["params.name"].is_array());
        let decoded: ConstraintSet = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, both);
    }

    #[test]
    fn malformed_constraints_are_rejected() {
        for bad in [
            json!({ "params.name": {} }),
            json!({ "params.name": { "in": [] } }),
            json!({ "params.name": [] }),
            json!({ "params.name": { "regex": ".*" } }),
            json!({ "params.ttl": { "range": [10, 1] } }),
            json!({ "params.name": { "allow_wildcard": true } }),
            json!({ "params.name": { "dns_within": "Example.com" } }),
            json!({ "params.name": { "dns_within": "*.example.com" } }),
            json!({ "params.Name": { "in": ["x"] } }),
            json!({ "params.a.b": { "in": ["x"] } }),
            json!({ "name": { "in": ["x"] } }),
            json!({ "actions": { "allow": ["x.y"] } }),
            json!({ "quotas": { "per_minute": 5 } }),
            json!({ "params.ttl": { "in": [1.5] } }),
        ] {
            assert!(
                serde_json::from_value::<ConstraintSet>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let raw = r#"{ "params.name": { "in": ["a"] }, "params.name": { "in": ["b"] } }"#;
        assert!(serde_json::from_str::<ConstraintSet>(raw).is_err());
    }

    #[test]
    fn glob_star_does_not_cross_slash() {
        let glob = GlobPattern::new("repo:example/*").unwrap();
        assert!(glob.matches("repo:example/backend"));
        assert!(glob.matches("repo:example/"));
        assert!(!glob.matches("repo:example/backend/extra"));
        assert!(!glob.matches("repo:example"));
        assert!(GlobPattern::new("a*b*c").unwrap().matches("aXXbYc"));
        assert!(!GlobPattern::new("a*b*c").unwrap().matches("aXXbY"));
    }

    #[test]
    fn scalars_are_type_strict() {
        assert!(!Scalar::Integer(300).matches(&json!("300")));
        assert!(!Scalar::String("true".into()).matches(&json!(true)));
        assert!(Scalar::Integer(300).matches(&json!(300)));
    }
}
