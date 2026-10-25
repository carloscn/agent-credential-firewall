//! Authorization composition. A baseline request passes every layer; each
//! denial case changes exactly one input, so no other layer's allow can mask
//! the denial.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use acf_config::{ConfigError, load_yaml};
use acf_identity::{IdentityAssurance, IdentityContext, Label};
use acf_policy::{
    AuthorizationRequest, Authorizer, AuthorizerSettings, ConstraintLayer, DecisionReason, Permit,
    TaskAuthorization,
};
use acf_protocol::{
    ActionName, AudienceId, CertificateThumbprint, DenialReason, IssuerId, PrincipalId, ResourceId,
    TaskCapabilityClaims, TaskId,
};
use serde_json::{Map, Value, json};

const PRODUCTION: &str = include_str!("../../acf-config/tests/fixtures/cloudflare-production.yaml");
const DEVELOPMENT: &str = include_str!("../../acf-config/tests/fixtures/example-development.yaml");
const THUMBPRINT: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
const OTHER_THUMBPRINT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const LIST: &str = "cloudflare.dns.records.list";
const CREATE: &str = "cloudflare.dns.records.create";
const ZONE: &str = "cloudflare-zone:example.com";

const POLICY: &str = r#"
schema: acf.policy/v1
version: policy-test.1
rules:
  - id: dns-agent
    effect: allow
    principals: [workload:agent-prod-17]
    actions: [cloudflare.dns.records.list, cloudflare.dns.records.create]
    resources: ["cloudflare-zone:example.com"]
    constraints:
      params.type: { in: [A, AAAA, MX] }
      quotas: { mutations_per_task: 3 }
  - id: no-laptop-mutations
    effect: deny
    labels: [laptop]
    actions: [cloudflare.dns.records.create]
    resources: ["cloudflare-zone:example.com"]
"#;

fn settings() -> AuthorizerSettings {
    AuthorizerSettings {
        audience: AudienceId::new("acf-gateway-prod-eu").unwrap(),
        clock_skew_secs: 30,
    }
}

fn authorizer() -> Authorizer {
    Authorizer::new(load_yaml(PRODUCTION).unwrap(), POLICY, settings()).unwrap()
}

fn identity() -> IdentityContext {
    IdentityContext {
        principal: PrincipalId::new("workload:agent-prod-17").unwrap(),
        device: None,
        labels: ["agent", "production"]
            .into_iter()
            .map(|l| Label::new(l).unwrap())
            .collect(),
        certificate: Some(CertificateThumbprint::parse(THUMBPRINT).unwrap()),
        issuer: IssuerId::new("test-identity").unwrap(),
        assurance: IdentityAssurance::Production,
    }
}

fn claims() -> TaskCapabilityClaims {
    serde_json::from_value(json!({
        "iss": "acf-authority-prod",
        "aud": "acf-gateway-prod-eu",
        "sub": "user:alice@example.com",
        "jti": "cap-1",
        "iat": 1000, "nbf": 1000, "exp": 2000,
        "cnf": { "x5t#S256": THUMBPRINT },
        "task": { "id": "dns-change-892", "basis": { "type": "human", "approver": "alice@example.com", "method": "webauthn" } },
        "grants": [
            { "action": LIST, "resource": ZONE, "constraints": { "params.name": { "in": ["api.example.com"] } } },
            { "action": CREATE, "resource": ZONE, "constraints": { "params.name": { "in": ["api.example.com"] } } }
        ],
        "limits": { "maxRequests": 50, "maxMutations": 1 }
    }))
    .unwrap()
}

/// Inputs to one authorization, owned so each case can change one field.
struct Case {
    identity: IdentityContext,
    claims: Option<TaskCapabilityClaims>,
    task_id: TaskId,
    action: ActionName,
    resource: ResourceId,
    params: Map<String, Value>,
    now: i64,
}

impl Case {
    fn list() -> Self {
        Self {
            identity: identity(),
            claims: Some(claims()),
            task_id: TaskId::new("dns-change-892").unwrap(),
            action: ActionName::new(LIST).unwrap(),
            resource: ResourceId::new(ZONE).unwrap(),
            params: json!({ "name": "api.example.com", "type": "A" })
                .as_object()
                .unwrap()
                .clone(),
            now: 1500,
        }
    }

    fn create() -> Self {
        Self {
            action: ActionName::new(CREATE).unwrap(),
            params: json!({ "type": "A", "name": "api.example.com", "content": "203.0.113.10", "ttl": 300 })
                .as_object()
                .unwrap()
                .clone(),
            ..Self::list()
        }
    }

    fn run(&self, authorizer: &Authorizer) -> Result<Permit, DecisionReason> {
        authorizer.authorize(&AuthorizationRequest {
            identity: &self.identity,
            task: self.claims.as_ref().map_or(
                TaskAuthorization::DevelopmentUnscoped,
                TaskAuthorization::Verified,
            ),
            task_id: &self.task_id,
            action: &self.action,
            resource: &self.resource,
            params: &self.params,
            now_unix: self.now,
        })
    }
}

/// Changes exactly one input of a [`Case`].
type Mutation = fn(&mut Case);

fn param(case: &mut Case, name: &str, value: Value) {
    case.params.insert(name.to_owned(), value);
}

#[test]
fn baseline_requests_are_allowed() {
    let authorizer = authorizer();

    let list = Case::list().run(&authorizer).unwrap();
    assert!(!list.approval_required);
    assert_eq!(list.policy_rules.len(), 1);
    assert_eq!(list.policy_version.as_str(), "policy-test.1");

    let create = Case::create().run(&authorizer).unwrap();
    assert!(create.approval_required, "mutate always requires approval");
    assert_eq!(
        create.quotas.mutations_per_task,
        Some(3),
        "min(resource 5, policy 3)"
    );
    assert_eq!(create.capability_limits.max_mutations, Some(1));
}

#[test]
fn each_layer_denies_on_its_own() {
    let authorizer = authorizer();
    let cases: Vec<(&str, Mutation, DecisionReason)> = vec![
        (
            "development identity in production",
            |c| c.identity.assurance = IdentityAssurance::Development,
            DecisionReason::IdentityAssuranceRejected,
        ),
        (
            "unscoped task in production",
            |c| c.claims = None,
            DecisionReason::DevelopmentTaskRejected,
        ),
        (
            "not yet valid",
            |c| c.now = 900,
            DecisionReason::CapabilityNotYetValid,
        ),
        (
            "expired",
            |c| c.now = 2030,
            DecisionReason::CapabilityExpired,
        ),
        (
            "wrong audience",
            |c| c.claims.as_mut().unwrap().aud = AudienceId::new("acf-gateway-dev").unwrap(),
            DecisionReason::CapabilityWrongAudience,
        ),
        (
            "other certificate",
            |c| {
                c.identity.certificate =
                    Some(CertificateThumbprint::parse(OTHER_THUMBPRINT).unwrap());
            },
            DecisionReason::CertificateMismatch,
        ),
        (
            "no certificate",
            |c| c.identity.certificate = None,
            DecisionReason::CertificateMismatch,
        ),
        (
            "other task",
            |c| c.task_id = TaskId::new("other-task").unwrap(),
            DecisionReason::CapabilityTaskMismatch,
        ),
        (
            "action not granted",
            |c| {
                c.claims
                    .as_mut()
                    .unwrap()
                    .grants
                    .retain(|g| g.action.as_str() != LIST);
            },
            DecisionReason::CapabilityNotGranted,
        ),
        (
            "ambiguous grants",
            |c| {
                let g = c.claims.as_ref().unwrap().grants[0].clone();
                c.claims.as_mut().unwrap().grants.push(g);
            },
            DecisionReason::CapabilityAmbiguousGrant,
        ),
        (
            "unregistered resource",
            |c| {
                let other = ResourceId::new("cloudflare-zone:other.com").unwrap();
                c.claims.as_mut().unwrap().grants[0].resource = other.clone();
                c.resource = other;
            },
            DecisionReason::UnknownResource,
        ),
        (
            "undefined action",
            |c| {
                let delete = ActionName::new("cloudflare.dns.records.delete").unwrap();
                c.claims.as_mut().unwrap().grants[0].action = delete.clone();
                c.action = delete;
            },
            DecisionReason::UnknownAction,
        ),
        (
            "policy has no rule for the caller",
            |c| c.identity.principal = PrincipalId::new("workload:other").unwrap(),
            DecisionReason::PolicyNoMatchingRule,
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut case = Case::list();
        mutate(&mut case);
        match case.run(&authorizer) {
            Err(reason) => assert_eq!(reason, expected, "{name}"),
            Ok(permit) => panic!("{name}: expected {expected:?}, got {permit:?}"),
        }
    }
}

#[test]
fn clock_skew_boundaries_are_explicit() {
    // nbf = 1000, exp = 2000, skew = 30: valid for now in [970, 2030).
    let authorizer = authorizer();
    for (now, expected) in [
        (969, Err(DecisionReason::CapabilityNotYetValid)),
        (970, Ok(())),
        (2029, Ok(())),
        (2030, Err(DecisionReason::CapabilityExpired)),
    ] {
        let mut case = Case::list();
        case.now = now;
        assert_eq!(case.run(&authorizer).map(drop), expected, "now = {now}");
    }
}

#[test]
fn constraint_layers_deny_independently() {
    let authorizer = authorizer();

    // MX passes the capability (no type constraint) and policy (allows MX),
    // but the resource allows only A/AAAA/CNAME/TXT.
    let mut case = Case::list();
    param(&mut case, "type", json!("MX"));
    assert!(matches!(
        case.run(&authorizer).unwrap_err(),
        DecisionReason::ConstraintViolation(ConstraintLayer::Resource, _)
    ));

    // www passes the resource (inside example.com) and policy, but the
    // capability allows only api.example.com.
    let mut case = Case::list();
    param(&mut case, "name", json!("www.example.com"));
    assert!(matches!(
        case.run(&authorizer).unwrap_err(),
        DecisionReason::ConstraintViolation(ConstraintLayer::Capability, _)
    ));

    // CNAME passes the resource and capability, but policy allows only A/AAAA/MX.
    let mut case = Case::list();
    param(&mut case, "type", json!("CNAME"));
    assert!(matches!(
        case.run(&authorizer).unwrap_err(),
        DecisionReason::ConstraintViolation(ConstraintLayer::Policy, _)
    ));

    // Omitting a constrained parameter cannot widen the request.
    let mut case = Case::list();
    case.params.remove("name");
    assert!(matches!(
        case.run(&authorizer).unwrap_err(),
        DecisionReason::ConstraintViolation(ConstraintLayer::Resource, _)
    ));
}

#[test]
fn malformed_parameters_are_denied() {
    let authorizer = authorizer();
    let mut case = Case::list();
    param(&mut case, "zone_id", json!("attacker-zone"));
    assert!(matches!(
        case.run(&authorizer).unwrap_err(),
        DecisionReason::InvalidParameters(_)
    ));
}

#[test]
fn a_deny_rule_overrides_a_matching_allow_rule() {
    let authorizer = authorizer();
    let mut case = Case::create();
    case.identity.labels.insert(Label::new("laptop").unwrap());
    assert_eq!(
        case.run(&authorizer).unwrap_err(),
        DecisionReason::PolicyDeniedByRule(acf_policy::RuleId::new("no-laptop-mutations").unwrap())
    );
    // The same identity can still list: the deny rule covers create only.
    let mut list = Case::list();
    list.identity.labels.insert(Label::new("laptop").unwrap());
    list.run(&authorizer).unwrap();
}

#[test]
fn an_empty_policy_denies_everything() {
    let empty = "schema: acf.policy/v1\nversion: empty.1\n";
    let authorizer = Authorizer::new(load_yaml(PRODUCTION).unwrap(), empty, settings()).unwrap();
    assert_eq!(
        Case::list().run(&authorizer).unwrap_err(),
        DecisionReason::PolicyNoMatchingRule
    );
}

#[test]
fn policy_can_require_approval_for_reads() {
    let policy = POLICY.replace(
        "      quotas: { mutations_per_task: 3 }",
        "      quotas: { mutations_per_task: 3 }\n    approval: required",
    );
    let authorizer = Authorizer::new(load_yaml(PRODUCTION).unwrap(), &policy, settings()).unwrap();
    assert!(Case::list().run(&authorizer).unwrap().approval_required);
}

#[test]
fn policy_cannot_weaken_approval() {
    let policy = POLICY.replace(
        "      quotas: { mutations_per_task: 3 }",
        "      quotas: { mutations_per_task: 3 }\n    approval: none",
    );
    match Authorizer::new(load_yaml(PRODUCTION).unwrap(), &policy, settings()) {
        Err(ConfigError::Parse(message)) => {
            assert!(message.contains("unknown variant"), "{message}");
        }
        other => panic!("expected a parse error, got {other:?}"),
    }
}

fn policy_issues(policy: &str) -> Vec<String> {
    match Authorizer::new(load_yaml(PRODUCTION).unwrap(), policy, settings()) {
        Err(ConfigError::Invalid(issues)) => issues.iter().map(ToString::to_string).collect(),
        other => panic!("expected validation issues, got {other:?}"),
    }
}

#[test]
fn policy_is_validated_against_configuration() {
    for (from, to, needle) in [
        (
            "resources: [\"cloudflare-zone:example.com\"]\n    constraints",
            "resources: [\"cloudflare-zone:typo.com\"]\n    constraints",
            "is not a registered resource action",
        ),
        (
            "actions: [cloudflare.dns.records.list, cloudflare.dns.records.create]",
            "actions: [cloudflare.dns.records.list, cloudflare.dns.records.purge]",
            "`cloudflare.dns.records.purge` on",
        ),
        (
            "params.type: { in: [A, AAAA, MX] }",
            "params.tpye: { in: [A] }",
            "`params.tpye` is not a parameter",
        ),
        (
            "    principals: [workload:agent-prod-17]\n",
            "",
            "must name `principals` or `labels`",
        ),
        (
            "    effect: deny\n",
            "    effect: deny\n    approval: required\n",
            "`deny` rules apply unconditionally",
        ),
        (
            "  - id: no-laptop-mutations",
            "  - id: dns-agent",
            "duplicate rule id",
        ),
        (
            "schema: acf.policy/v1",
            "schema: acf.policy/v2",
            "must be `acf.policy/v1`",
        ),
    ] {
        assert!(POLICY.contains(from), "{from}");
        let issues = policy_issues(&POLICY.replacen(from, to, 1));
        assert!(
            issues.iter().any(|i| i.contains(needle)),
            "`{needle}` not in {issues:#?}"
        );
    }
}

#[test]
fn unscoped_tasks_need_the_development_profile() {
    let policy = r"
schema: acf.policy/v1
version: dev.1
rules:
  - id: dev
    effect: allow
    principals: [dev-agent]
    actions: [example.profile.get]
    resources: ['example-api:development']
";
    let settings = AuthorizerSettings {
        audience: AudienceId::new("acf-gateway-dev").unwrap(),
        clock_skew_secs: 30,
    };
    let authorizer = Authorizer::new(load_yaml(DEVELOPMENT).unwrap(), policy, settings).unwrap();
    let mut dev_identity = identity();
    dev_identity.principal = PrincipalId::new("dev-agent").unwrap();
    dev_identity.labels = BTreeSet::new();
    dev_identity.certificate = None;
    dev_identity.assurance = IdentityAssurance::Development;

    let request = |identity: &IdentityContext| {
        authorizer.authorize(&AuthorizationRequest {
            identity,
            task: TaskAuthorization::DevelopmentUnscoped,
            task_id: &TaskId::new("dev-task").unwrap(),
            action: &ActionName::new("example.profile.get").unwrap(),
            resource: &ResourceId::new("example-api:development").unwrap(),
            params: &Map::new(),
            now_unix: 0,
        })
    };
    request(&dev_identity).unwrap();

    // In the development profile an mTLS (production-assurance) identity may
    // also use unscoped tasks; the production profile refuses them (see
    // `each_layer_denies_on_its_own`).
    let mut prod_identity = dev_identity.clone();
    prod_identity.assurance = IdentityAssurance::Production;
    request(&prod_identity).unwrap();

    // Policy still applies to unscoped development tasks.
    let mut stranger = dev_identity;
    stranger.principal = PrincipalId::new("someone-else").unwrap();
    assert_eq!(
        request(&stranger).unwrap_err(),
        DecisionReason::PolicyNoMatchingRule
    );
}

#[test]
fn production_refuses_development_identity_providers() {
    let authorizer = authorizer();
    assert_eq!(
        authorizer.check_identity_provider(IdentityAssurance::Development),
        Err(DecisionReason::IdentityAssuranceRejected)
    );
    authorizer
        .check_identity_provider(IdentityAssurance::Production)
        .unwrap();
}

#[test]
fn denials_map_to_agent_facing_codes() {
    assert_eq!(
        DecisionReason::CertificateMismatch.denial(),
        DenialReason::CertificateMismatch
    );
    assert_eq!(
        DecisionReason::CapabilityExpired.denial(),
        DenialReason::CapabilityExpired
    );
    // Not-granted and policy denials look the same to the agent.
    assert_eq!(
        DecisionReason::CapabilityNotGranted.denial(),
        DenialReason::PolicyDenied
    );
    assert_eq!(
        DecisionReason::PolicyNoMatchingRule.denial(),
        DenialReason::PolicyDenied
    );
}
