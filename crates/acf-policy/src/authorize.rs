//! Authorization composition (design §8).
//!
//! ```text
//! EffectivePermission =
//!   DeviceIdentity ∩ TaskCapability ∩ GatewayPolicy ∩ ResourceConstraints ∩ ConnectorContract
//! approval required   = strictest requirement of any layer
//! any deny, error, or missing input = deny
//! ```
//!
//! [`Authorizer::authorize`] runs every layer in a fixed order and stops at
//! the first denial. Each layer can only deny or narrow; none can grant what
//! another refused.
//!
//! Inputs must already be authenticated and normalized: capability claims are
//! signature-verified (WP-09) and parameters have passed the connector's
//! domain-type normalization (WP-04). Quotas and capability limits are
//! returned for the state layer (WP-10) to enforce.

use acf_config::{ConfigError, DeploymentProfile, ParamError, ValidatedConfig};
use acf_identity::{IdentityAssurance, IdentityContext};
use acf_protocol::{
    ActionName, AudienceId, ConstraintSet, ConstraintViolation, DenialReason, Grant, Limits,
    Quotas, ResourceId, TaskCapabilityClaims, TaskId,
};
use serde_json::{Map, Value};

use crate::policy::{Policy, PolicyDenial, PolicyVersion, RuleId, load_policy_yaml};

/// Gateway-specific authorization settings.
#[derive(Clone, Debug)]
pub struct AuthorizerSettings {
    /// This gateway's audience; capabilities must name it in `aud`.
    pub audience: AudienceId,
    /// Allowed clock skew when checking `nbf` and `exp`, in seconds.
    pub clock_skew_secs: i64,
}

/// How the request's task was authorized.
#[derive(Clone, Copy, Debug)]
pub enum TaskAuthorization<'a> {
    /// A signature-verified capability.
    Verified(&'a TaskCapabilityClaims),
    /// No capability. Accepted only under the `development` deployment
    /// profile with a development identity; policy still applies.
    DevelopmentUnscoped,
}

/// One request to authorize.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationRequest<'a> {
    /// Trusted caller identity.
    pub identity: &'a IdentityContext,
    /// Task authorization.
    pub task: TaskAuthorization<'a>,
    /// Task named in the request.
    pub task_id: &'a TaskId,
    /// Requested action.
    pub action: &'a ActionName,
    /// Requested resource.
    pub resource: &'a ResourceId,
    /// Normalized parameters.
    pub params: &'a Map<String, Value>,
    /// Current time, in seconds since the Unix epoch.
    pub now_unix: i64,
}

/// Which layer's constraints failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstraintLayer {
    /// Resource registration.
    Resource,
    /// Task capability grant.
    Capability,
    /// Gateway policy rule.
    Policy,
}

/// Why a request was denied, for audit. [`DecisionReason::denial`] maps it to
/// the coarser code returned to the agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionReason {
    /// A development identity under the `production` profile.
    IdentityAssuranceRejected,
    /// An unscoped development task outside the `development` profile or
    /// without a development identity.
    DevelopmentTaskRejected,
    /// `nbf` is in the future.
    CapabilityNotYetValid,
    /// `exp` has passed.
    CapabilityExpired,
    /// `aud` is not this gateway.
    CapabilityWrongAudience,
    /// `cnf.x5t#S256` does not match the connection's certificate.
    CertificateMismatch,
    /// The request names a different task than the capability.
    CapabilityTaskMismatch,
    /// No grant covers this action on this resource.
    CapabilityNotGranted,
    /// More than one grant covers this action on this resource.
    CapabilityAmbiguousGrant,
    /// The resource is not registered.
    UnknownResource,
    /// The resource's connector has no such action.
    UnknownAction,
    /// Parameters failed structural validation.
    InvalidParameters(ParamError),
    /// A constraint failed.
    ConstraintViolation(ConstraintLayer, ConstraintViolation),
    /// A policy `deny` rule matched.
    PolicyDeniedByRule(RuleId),
    /// No policy rule matched.
    PolicyNoMatchingRule,
}

impl DecisionReason {
    /// The code returned to the agent.
    #[must_use]
    pub fn denial(&self) -> DenialReason {
        match self {
            Self::IdentityAssuranceRejected => DenialReason::Unauthenticated,
            Self::DevelopmentTaskRejected => DenialReason::CapabilityInvalid,
            Self::CapabilityNotYetValid | Self::CapabilityExpired => {
                DenialReason::CapabilityExpired
            }
            Self::CapabilityWrongAudience | Self::CapabilityAmbiguousGrant => {
                DenialReason::CapabilityInvalid
            }
            Self::CertificateMismatch => DenialReason::CertificateMismatch,
            Self::CapabilityTaskMismatch
            | Self::CapabilityNotGranted
            | Self::PolicyDeniedByRule(_)
            | Self::PolicyNoMatchingRule => DenialReason::PolicyDenied,
            Self::UnknownResource => DenialReason::UnknownResource,
            Self::UnknownAction => DenialReason::UnknownAction,
            Self::InvalidParameters(_) => DenialReason::InvalidParameters,
            Self::ConstraintViolation(..) => DenialReason::ConstraintViolation,
        }
    }
}

/// An allowed request and the obligations that come with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permit {
    /// Whether a transaction approval is required before execution.
    pub approval_required: bool,
    /// Smallest quotas across resource, capability grant, and policy.
    pub quotas: Quotas,
    /// Capability usage limits; default when the task is unscoped.
    pub capability_limits: Limits,
    /// Policy version that allowed the request.
    pub policy_version: PolicyVersion,
    /// Policy rules that allowed the request.
    pub policy_rules: Vec<RuleId>,
}

/// Composes every authorization layer for one gateway.
#[derive(Clone, Debug)]
pub struct Authorizer {
    config: ValidatedConfig,
    policy: Policy,
    settings: AuthorizerSettings,
}

impl Authorizer {
    /// Builds an authorizer. The policy is validated against `config`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the policy is malformed or inconsistent
    /// with `config`.
    pub fn new(
        config: ValidatedConfig,
        policy_yaml: &str,
        settings: AuthorizerSettings,
    ) -> Result<Self, ConfigError> {
        let policy = load_policy_yaml(policy_yaml, &config)?;
        Ok(Self {
            config,
            policy,
            settings,
        })
    }

    /// The configuration in force.
    #[must_use]
    pub fn config(&self) -> &ValidatedConfig {
        &self.config
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Startup check: whether an identity provider with `assurance` may serve
    /// this deployment.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionReason::IdentityAssuranceRejected`] for a
    /// development provider under the `production` profile.
    pub fn check_identity_provider(
        &self,
        assurance: IdentityAssurance,
    ) -> Result<(), DecisionReason> {
        if self.is_production() && assurance != IdentityAssurance::Production {
            Err(DecisionReason::IdentityAssuranceRejected)
        } else {
            Ok(())
        }
    }

    fn is_production(&self) -> bool {
        self.config.deployment().profile == DeploymentProfile::Production
    }

    /// Runs only the identity and task-capability layers, which never look at
    /// configuration. The gateway calls this before it looks up the action to
    /// normalize parameters, so an unauthorized caller cannot probe which
    /// resources exist. `request.params` is ignored.
    ///
    /// # Errors
    ///
    /// Returns the identity or capability [`DecisionReason`].
    pub fn pre_authorize(&self, request: &AuthorizationRequest<'_>) -> Result<(), DecisionReason> {
        self.check_identity_provider(request.identity.assurance)?;
        self.check_task(request).map(drop)
    }

    /// Authorizes one request.
    ///
    /// # Errors
    ///
    /// Returns the first layer's [`DecisionReason`] that denies.
    pub fn authorize(&self, request: &AuthorizationRequest<'_>) -> Result<Permit, DecisionReason> {
        // 1. Identity.
        self.check_identity_provider(request.identity.assurance)?;

        // 2. Task capability. Checked before resource lookup so an
        //    unauthorized caller cannot probe which resources exist.
        let grant = self.check_task(request)?;

        // 3. Connector contract: the action exists and parameters are well formed.
        let resolved = self
            .config
            .resource(request.resource)
            .ok_or(DecisionReason::UnknownResource)
            .and_then(|_| {
                self.config
                    .action(request.resource, request.action)
                    .ok_or(DecisionReason::UnknownAction)
            })?;
        acf_config::validate_params(&resolved.action.params, request.params)
            .map_err(DecisionReason::InvalidParameters)?;
        let declared = |p: &acf_protocol::ParamName| resolved.action.declares(p);

        // 4. Resource and capability constraints.
        check_constraints(
            ConstraintLayer::Resource,
            &resolved.resource.constraints,
            request,
            &declared,
        )?;
        let grant_constraints = grant.map(|g| &g.constraints);
        if let Some(constraints) = grant_constraints {
            check_constraints(ConstraintLayer::Capability, constraints, request, &declared)?;
        }

        // 5. Gateway policy.
        let policy_grant = self
            .policy
            .evaluate(
                request.identity,
                request.action,
                request.resource,
                declared,
                request.params,
            )
            .map_err(|denial| match denial {
                PolicyDenial::NoMatchingRule => DecisionReason::PolicyNoMatchingRule,
                PolicyDenial::DeniedByRule(rule) => DecisionReason::PolicyDeniedByRule(rule),
                PolicyDenial::Constraint(_, violation) => {
                    DecisionReason::ConstraintViolation(ConstraintLayer::Policy, violation)
                }
            })?;

        // 6. Obligations: strictest approval, smallest quotas.
        let mut quotas = resolved.resource.constraints.clone();
        if let Some(constraints) = grant_constraints {
            quotas = quotas.intersect(constraints);
        }
        let quotas = quotas
            .intersect(&ConstraintSet::default().with_quotas(policy_grant.quotas))
            .quotas();
        Ok(Permit {
            approval_required: resolved.action.approval_required()
                || policy_grant.approval_required,
            quotas,
            capability_limits: match request.task {
                TaskAuthorization::Verified(claims) => claims.limits,
                TaskAuthorization::DevelopmentUnscoped => Limits::default(),
            },
            policy_version: self.policy.version().clone(),
            policy_rules: policy_grant.rules,
        })
    }

    /// Validates the task authorization and returns the matching grant, if
    /// the task is capability-scoped.
    fn check_task<'a>(
        &self,
        request: &AuthorizationRequest<'a>,
    ) -> Result<Option<&'a Grant>, DecisionReason> {
        let claims = match request.task {
            TaskAuthorization::DevelopmentUnscoped => {
                if self.is_production()
                    || request.identity.assurance != IdentityAssurance::Development
                {
                    return Err(DecisionReason::DevelopmentTaskRejected);
                }
                return Ok(None);
            }
            TaskAuthorization::Verified(claims) => claims,
        };
        let skew = self.settings.clock_skew_secs;
        if request.now_unix.saturating_add(skew) < claims.nbf {
            return Err(DecisionReason::CapabilityNotYetValid);
        }
        if request.now_unix.saturating_sub(skew) >= claims.exp {
            return Err(DecisionReason::CapabilityExpired);
        }
        if claims.aud != self.settings.audience {
            return Err(DecisionReason::CapabilityWrongAudience);
        }
        if request.identity.certificate.as_ref() != Some(&claims.cnf.x5t_s256) {
            return Err(DecisionReason::CertificateMismatch);
        }
        if &claims.task.id != request.task_id {
            return Err(DecisionReason::CapabilityTaskMismatch);
        }
        let mut grants = claims
            .grants
            .iter()
            .filter(|g| &g.action == request.action && &g.resource == request.resource);
        let grant = grants.next().ok_or(DecisionReason::CapabilityNotGranted)?;
        if grants.next().is_some() {
            return Err(DecisionReason::CapabilityAmbiguousGrant);
        }
        Ok(Some(grant))
    }
}

fn check_constraints(
    layer: ConstraintLayer,
    constraints: &ConstraintSet,
    request: &AuthorizationRequest<'_>,
    declared: &impl Fn(&acf_protocol::ParamName) -> bool,
) -> Result<(), DecisionReason> {
    constraints
        .check_action(request.action)
        .and_then(|()| constraints.check_params(declared, request.params))
        .map_err(|violation| DecisionReason::ConstraintViolation(layer, violation))
}
