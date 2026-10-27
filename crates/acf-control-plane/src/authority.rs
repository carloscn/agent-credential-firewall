//! Capability issuance (design §7.2.1).
//!
//! ```text
//! effective grants = proposal ∩ caller entitlement ∩ basis scope ∩ registered actions
//! ```
//!
//! A grant survives only if every set contains its action/resource pair;
//! its constraints are the intersection of every set's constraints. The
//! proposal can only narrow: an empty proposal asks for the basis scope, and
//! nothing the caller proposes can add a pair or loosen a constraint.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use acf_config::ValidatedConfig;
use acf_identity::IdentityContext;
use acf_protocol::{
    AuthorityErrorCode, AuthorizationBasis, BasisRequest, CapabilityId, Confirmation, Grant,
    Limits, PrincipalId, TaskCapabilityClaims, TaskInfo, TaskIssued, TaskProposal,
};
use time::OffsetDateTime;

use crate::config::AuthorityPolicy;
use crate::keys::CapabilitySigner;

/// Issues capabilities.
#[derive(Debug)]
pub struct Authority {
    policy: AuthorityPolicy,
    bundle: ValidatedConfig,
    signer: CapabilitySigner,
}

/// What the authority decided, for its own log. Never includes the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issuance {
    /// The answer for the caller.
    pub issued: TaskIssued,
    /// Capability identifier.
    pub jti: CapabilityId,
}

/// A resolved authorization basis.
struct Basis<'a> {
    scope: &'a [Grant],
    claim: AuthorizationBasis,
    ttl_secs: Option<u32>,
    limits: Limits,
}

fn find<'a>(grants: &'a [Grant], wanted: &Grant) -> Option<&'a Grant> {
    grants
        .iter()
        .find(|g| g.action == wanted.action && g.resource == wanted.resource)
}

fn new_jti() -> Result<CapabilityId, AuthorityErrorCode> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| AuthorityErrorCode::Unavailable)?;
    let mut text = String::from("cap-");
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    CapabilityId::new(text).map_err(|_| AuthorityErrorCode::Unavailable)
}

impl Authority {
    /// Builds an authority. The signer's issuer must be the configured one.
    ///
    /// # Errors
    ///
    /// Returns a message if the signer's issuer differs from the policy's.
    pub fn new(
        policy: AuthorityPolicy,
        bundle: ValidatedConfig,
        signer: CapabilitySigner,
    ) -> Result<Self, String> {
        if signer.issuer() != &policy.config.issuer {
            return Err("signer issuer differs from the configured issuer".to_owned());
        }
        Ok(Self {
            policy,
            bundle,
            signer,
        })
    }

    /// Decides one proposal from an authenticated caller.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityErrorCode`] if the caller has no certificate, the
    /// basis is not available to it, nothing survives intersection, or the
    /// proposal repeats a pair.
    pub fn issue(
        &self,
        caller: &IdentityContext,
        proposal: &TaskProposal,
        now: i64,
    ) -> Result<Issuance, AuthorityErrorCode> {
        let certificate = caller
            .certificate
            .clone()
            .ok_or(AuthorityErrorCode::Unauthenticated)?;
        let principal = &caller.principal;
        let config = &self.policy.config;

        let basis = self.basis(principal, &proposal.basis)?;
        let grants = self.intersect(principal, &basis, &proposal.grants)?;

        let ttl = [
            Some(proposal.ttl_secs.unwrap_or(config.default_ttl_secs)),
            basis.ttl_secs,
            Some(config.max_ttl_secs),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(config.default_ttl_secs);
        if ttl == 0 {
            return Err(AuthorityErrorCode::InvalidRequest);
        }
        let exp = now + i64::from(ttl);
        let jti = new_jti()?;
        let claims = TaskCapabilityClaims {
            iss: config.issuer.clone(),
            aud: config.audience.clone(),
            sub: principal.clone(),
            jti: jti.clone(),
            iat: now,
            nbf: now,
            exp,
            cnf: Confirmation {
                x5t_s256: certificate,
            },
            task: TaskInfo {
                id: proposal.task_id.clone(),
                basis: basis.claim,
            },
            grants: grants.clone(),
            limits: basis.limits,
        };
        let capability = self
            .signer
            .sign(&claims)
            .map_err(|_| AuthorityErrorCode::Unavailable)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(exp)
            .map_err(|_| AuthorityErrorCode::Unavailable)?;
        Ok(Issuance {
            issued: TaskIssued {
                task_id: proposal.task_id.clone(),
                capability,
                expires_at,
                grants,
                limits: basis.limits,
            },
            jti,
        })
    }

    /// The scope, basis claim, TTL cap, and limits of the requested basis,
    /// if the caller may use it.
    fn basis(
        &self,
        principal: &PrincipalId,
        request: &BasisRequest,
    ) -> Result<Basis<'_>, AuthorityErrorCode> {
        match request {
            BasisRequest::Job { job } => {
                let job = self
                    .policy
                    .jobs
                    .get(job)
                    .filter(|job| job.definition.principals.contains(principal))
                    .ok_or(AuthorityErrorCode::BasisRejected)?;
                Ok(Basis {
                    scope: &job.definition.grants,
                    claim: AuthorizationBasis::JobDefinition {
                        definition_digest: job.digest.clone(),
                    },
                    ttl_secs: job.definition.ttl_secs,
                    limits: job.definition.limits,
                })
            }
            BasisRequest::Scheduler => {
                let scheduler = self
                    .policy
                    .schedulers
                    .get(principal)
                    .ok_or(AuthorityErrorCode::BasisRejected)?;
                Ok(Basis {
                    scope: &scheduler.grants,
                    claim: AuthorizationBasis::Scheduler {
                        scheduler: principal.clone(),
                    },
                    ttl_secs: scheduler.max_ttl_secs,
                    limits: scheduler.limits,
                })
            }
        }
    }

    /// proposal ∩ entitlement ∩ basis scope ∩ registered actions.
    fn intersect(
        &self,
        principal: &PrincipalId,
        basis: &Basis<'_>,
        proposed: &[Grant],
    ) -> Result<Vec<Grant>, AuthorityErrorCode> {
        let entitled: &[Grant] = self
            .policy
            .entitlements
            .get(principal)
            .map_or(&[], Vec::as_slice);
        let requested = if proposed.is_empty() {
            basis.scope
        } else {
            proposed
        };
        let mut seen = BTreeSet::new();
        let mut grants = Vec::new();
        for wanted in requested {
            if !seen.insert((&wanted.action, &wanted.resource)) {
                return Err(AuthorityErrorCode::InvalidRequest);
            }
            let (Some(in_scope), Some(in_entitlement)) =
                (find(basis.scope, wanted), find(entitled, wanted))
            else {
                continue;
            };
            if self
                .bundle
                .action(&wanted.resource, &wanted.action)
                .is_none()
            {
                continue;
            }
            grants.push(Grant {
                action: wanted.action.clone(),
                resource: wanted.resource.clone(),
                constraints: wanted
                    .constraints
                    .intersect(&in_scope.constraints)
                    .intersect(&in_entitlement.constraints),
            });
        }
        if grants.is_empty() {
            return Err(AuthorityErrorCode::ScopeEmpty);
        }
        Ok(grants)
    }
}
