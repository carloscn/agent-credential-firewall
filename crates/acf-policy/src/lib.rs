//! Authorization decisions and constraint composition.
//!
//! - [`policy`]: the typed, deny-by-default gateway policy (`acf.policy/v1`).
//! - [`Authorizer`]: composes identity, task capability, connector contract,
//!   resource constraints, and policy into one decision.

mod authorize;
pub mod policy;

pub use authorize::{
    AuthorizationRequest, Authorizer, AuthorizerSettings, ConstraintLayer, DecisionReason, Permit,
    TaskAuthorization,
};
pub use policy::{Policy, PolicyVersion, RuleId, load_policy_yaml};
