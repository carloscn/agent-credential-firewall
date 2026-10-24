//! The request lifecycle.
//!
//! ```text
//! identity → pre-authorize (identity, task) → validate + normalize params
//!          → authorize (all layers) → approval gate → retrieve secret
//!          → connector → filtered result
//! ```
//!
//! Authorization always completes before the secret provider is called, and
//! the provider is called only after an allow. No step spawns a background
//! task, so a cancelled request drops every in-flight future, including the
//! downstream call and the credential.
//!
//! Milestone 0 limits:
//! - Tasks are [`TaskAuthorization::DevelopmentUnscoped`]; the capability
//!   transport arrives with WP-09.
//! - Requests that need approval are denied; the approval flow arrives with
//!   WP-13 and WP-14.
//! - Replay, freshness, quotas, and rate limits arrive with WP-10.

use std::collections::BTreeMap;
use std::sync::Arc;

use acf_config::{ValidatedConfig, validate_params};
use acf_connectors::{ActionConnector, ConnectorCall, ConnectorError, normalize_params};
use acf_identity::{ConnectionInfo, IdentityContextProvider};
use acf_policy::{AuthorizationRequest, Authorizer, DecisionReason, TaskAuthorization};
use acf_protocol::{ActionRequest, ActionResponse, DenialReason, FailureReason};
use acf_secrets::{ResolvedSecret, SecretError, SecretProvider, SecretRef};
use serde_json::{Value, json};
use time::OffsetDateTime;

/// Runtime secret providers by namespace.
#[derive(Clone, Default)]
pub struct ProviderRegistry {
    providers: BTreeMap<String, Arc<dyn SecretProvider>>,
}

impl ProviderRegistry {
    /// Registers `provider` for `namespace`.
    #[must_use]
    pub fn with(mut self, namespace: &str, provider: Arc<dyn SecretProvider>) -> Self {
        self.providers.insert(namespace.to_owned(), provider);
        self
    }

    async fn get(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretError> {
        let provider =
            self.providers
                .get(reference.namespace())
                .ok_or_else(|| SecretError::NotAssigned {
                    reference: reference.clone(),
                })?;
        provider.get(reference).await
    }
}

/// Why the gateway refused to start.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GatewayError {
    /// The identity provider's assurance is not allowed for this deployment.
    #[error("identity provider is not allowed for this deployment profile")]
    IdentityProviderRejected,
    /// A configured secret namespace has no runtime provider.
    #[error("no runtime secret provider for namespace `{0}`")]
    MissingProvider(String),
}

/// The gateway data plane.
pub struct Gateway {
    authorizer: Authorizer,
    identity: Arc<dyn IdentityContextProvider>,
    providers: ProviderRegistry,
    connector: Arc<dyn ActionConnector>,
}

impl Gateway {
    /// Assembles a gateway.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError`] if the identity provider is not allowed for
    /// the deployment profile or a configured namespace has no provider.
    pub fn new(
        authorizer: Authorizer,
        identity: Arc<dyn IdentityContextProvider>,
        providers: ProviderRegistry,
        connector: Arc<dyn ActionConnector>,
    ) -> Result<Self, GatewayError> {
        authorizer
            .check_identity_provider(identity.assurance())
            .map_err(|_| GatewayError::IdentityProviderRejected)?;
        for (namespace, _) in authorizer.config().providers() {
            if !providers.providers.contains_key(namespace.as_str()) {
                return Err(GatewayError::MissingProvider(namespace.to_string()));
            }
        }
        Ok(Self {
            authorizer,
            identity,
            providers,
            connector,
        })
    }

    fn config(&self) -> &ValidatedConfig {
        self.authorizer.config()
    }

    /// Handles one action request.
    pub async fn execute(
        &self,
        connection: &ConnectionInfo,
        request: ActionRequest,
    ) -> ActionResponse {
        let request_id = request.request_id.clone();
        let denied = |reason: DenialReason| ActionResponse::Denied {
            request_id: request_id.clone(),
            reason,
        };
        let failed = |reason: FailureReason| ActionResponse::Failed {
            request_id: request_id.clone(),
            reason,
        };

        let Ok(identity) = self.identity.resolve(connection).await else {
            return denied(DenialReason::Unauthenticated);
        };
        let mut authorization = AuthorizationRequest {
            identity: &identity,
            task: TaskAuthorization::DevelopmentUnscoped,
            task_id: &request.task_id,
            action: &request.action,
            resource: &request.resource,
            params: &request.parameters,
            now_unix: OffsetDateTime::now_utc().unix_timestamp(),
        };
        if let Err(reason) = self.authorizer.pre_authorize(&authorization) {
            return denied(reason.denial());
        }

        // Constraints must see normalized values. Unknown actions skip
        // normalization; `authorize` denies them below.
        let normalized = match self.config().action(&request.resource, &request.action) {
            Some(resolved) => {
                if validate_params(&resolved.action.params, &request.parameters).is_err() {
                    return denied(DenialReason::InvalidParameters);
                }
                match normalize_params(&resolved.action.params, &request.parameters) {
                    Ok(normalized) => normalized,
                    Err(_) => return denied(DenialReason::InvalidParameters),
                }
            }
            None => request.parameters.clone(),
        };
        authorization.params = &normalized;
        let permit = match self.authorizer.authorize(&authorization) {
            Ok(permit) => permit,
            Err(reason) => return denied(reason.denial()),
        };
        if permit.approval_required {
            return denied(DenialReason::ApprovalInvalid);
        }

        // `authorize` succeeded, so the action resolves.
        let Some(resolved) = self.config().action(&request.resource, &request.action) else {
            return denied(DecisionReason::UnknownAction.denial());
        };
        let Ok(credential) = self.providers.get(resolved.secret_ref).await else {
            return failed(FailureReason::CredentialUnavailable);
        };
        match self
            .connector
            .execute(ConnectorCall {
                action: resolved,
                params: &normalized,
                credential,
            })
            .await
        {
            Ok(output) => {
                let mut result = json!({ "status": output.status, "body": output.body });
                if !output.headers.is_empty() {
                    result["headers"] = Value::Object(output.headers);
                }
                ActionResponse::Completed {
                    request_id,
                    result,
                    operation: None,
                }
            }
            Err(error) => failed(failure_reason(&error)),
        }
    }
}

fn failure_reason(error: &ConnectorError) -> FailureReason {
    match error {
        ConnectorError::BindingMismatch
        | ConnectorError::UnsupportedStrategy
        | ConnectorError::InvalidCredential => FailureReason::CredentialUnusable,
        ConnectorError::InvalidRequest(_) | ConnectorError::RequestTooLarge => {
            FailureReason::RequestInvalid
        }
        ConnectorError::DestinationForbidden(_) | ConnectorError::PlaintextForbidden => {
            FailureReason::DestinationRefused
        }
        ConnectorError::Timeout => FailureReason::DownstreamTimeout,
        ConnectorError::Transport => FailureReason::DownstreamUnavailable,
        ConnectorError::RedirectNotFollowed
        | ConnectorError::ResponseTooLarge
        | ConnectorError::ResponseNotJson => FailureReason::DownstreamResponseInvalid,
        ConnectorError::CredentialReflected => FailureReason::CredentialReflected,
    }
}
