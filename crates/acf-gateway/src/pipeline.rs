//! The request lifecycle.
//!
//! ```text
//! identity → pre-authorize (identity, task) → validate + normalize params
//!          → authorize (all layers) → approval gate → audit decision
//!          → retrieve secret → connector → audit outcome → filtered result
//! ```
//!
//! Authorization always completes before the secret provider is called, and
//! the provider is called only after an allow. When audit is required, the
//! allow decision must be recorded before the secret is retrieved; if it
//! cannot be, the request fails without touching the credential. No step
//! spawns a background task, so a cancelled request drops every in-flight
//! future, including the downstream call and the credential.
//!
//! Milestone 0 limits:
//! - Tasks are [`TaskAuthorization::DevelopmentUnscoped`]; the capability
//!   transport arrives with WP-09.
//! - Requests that need approval are denied; the approval flow arrives with
//!   WP-13 and WP-14.
//! - Replay, freshness, quotas, and rate limits arrive with WP-10.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use acf_audit::{
    AuditEvent, AuditHasher, AuditParam, AuditSink, Downstream, EventKind, GatewayInfo, PolicyRef,
    Verdict,
};
use acf_config::{AuditClass, ResolvedAction, ValidatedConfig, validate_params};
use acf_connectors::{ActionConnector, ConnectorCall, ConnectorError, normalize_params};
use acf_identity::{ConnectionInfo, IdentityContext, IdentityContextProvider};
use acf_policy::{AuthorizationRequest, Authorizer, DecisionReason, Permit, TaskAuthorization};
use acf_protocol::{ActionRequest, ActionResponse, DenialReason, FailureReason};
use acf_secrets::{ResolvedSecret, SecretError, SecretProvider, SecretRef};
use serde_json::{Map, Value, json};
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

/// Audit wiring.
pub struct AuditSettings {
    /// Where events go.
    pub sink: Arc<dyn AuditSink>,
    /// Keyed hasher for `hash`-classified parameters.
    pub hasher: AuditHasher,
    /// If true, an allowed request fails unless its decision event is
    /// recorded first.
    pub required: bool,
    /// Identifies this gateway in events.
    pub gateway: GatewayInfo,
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
    audit: AuditSettings,
}

/// Per-request audit context.
struct Trail<'a> {
    gateway: &'a Gateway,
    request: &'a ActionRequest,
    identity: Option<&'a IdentityContext>,
}

impl Trail<'_> {
    fn event(&self, kind: EventKind, verdict: Verdict) -> AuditEvent {
        let mut event = AuditEvent::new(
            kind,
            self.gateway.audit.gateway.clone(),
            self.request.request_id.clone(),
            self.request.task_id.clone(),
            self.request.action.clone(),
            self.request.resource.clone(),
            verdict,
        );
        if let Some(identity) = self.identity {
            event.principal = Some(identity.principal.clone());
            event.device.clone_from(&identity.device);
        }
        event
    }

    /// Records a denial. Denials are returned whether or not the sink works.
    async fn denied(&self, reason: String) {
        let mut event = self.event(EventKind::Decision, Verdict::Denied);
        event.reason = Some(reason);
        let _ = self.gateway.audit.sink.emit(&event).await;
    }

    /// Adds the action context: connector, logical secret, classified params.
    fn describe(
        &self,
        event: &mut AuditEvent,
        resolved: &ResolvedAction<'_>,
        params: &Map<String, Value>,
    ) {
        event.connector = Some(resolved.profile.connector.to_string());
        event.secret_ref = Some(resolved.secret_ref.to_string());
        for name in resolved.action.params.keys() {
            let Some(value) = params.get(name.as_str()) else {
                continue;
            };
            let audited = match resolved.action.audit.classify(name) {
                AuditClass::Record => AuditParam::Value(value.clone()),
                AuditClass::Hash => {
                    AuditParam::Hmac(self.gateway.audit.hasher.hash(name.as_str(), value))
                }
                AuditClass::Omit => continue,
            };
            event.params.insert(name.to_string(), audited);
        }
    }
    /// The allow decision, recorded before the credential is retrieved.
    fn allowed(
        &self,
        resolved: &ResolvedAction<'_>,
        params: &Map<String, Value>,
        permit: &Permit,
    ) -> AuditEvent {
        let mut event = self.event(EventKind::Decision, Verdict::Allowed);
        self.describe(&mut event, resolved, params);
        event.approval_required = Some(permit.approval_required);
        event.policy = Some(PolicyRef {
            version: permit.policy_version.to_string(),
            rules: permit
                .policy_rules
                .iter()
                .map(ToString::to_string)
                .collect(),
        });
        event
    }
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
        audit: AuditSettings,
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
            audit,
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

        let Ok(identity) = self.identity.resolve(connection).await else {
            Trail {
                gateway: self,
                request: &request,
                identity: None,
            }
            .denied("unauthenticated".to_owned())
            .await;
            return denied(DenialReason::Unauthenticated);
        };
        let trail = Trail {
            gateway: self,
            request: &request,
            identity: Some(&identity),
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
            trail.denied(reason.code()).await;
            return denied(reason.denial());
        }

        // Constraints must see normalized values. Unknown actions skip
        // normalization; `authorize` denies them below.
        let normalized = match self.config().action(&request.resource, &request.action) {
            Some(resolved) => {
                let normalized = validate_params(&resolved.action.params, &request.parameters)
                    .ok()
                    .and_then(|()| {
                        normalize_params(&resolved.action.params, &request.parameters).ok()
                    });
                let Some(normalized) = normalized else {
                    trail.denied("invalid_parameters".to_owned()).await;
                    return denied(DenialReason::InvalidParameters);
                };
                normalized
            }
            None => request.parameters.clone(),
        };
        authorization.params = &normalized;
        let permit = match self.authorizer.authorize(&authorization) {
            Ok(permit) => permit,
            Err(reason) => {
                trail.denied(reason.code()).await;
                return denied(reason.denial());
            }
        };
        // `authorize` succeeded, so the action resolves.
        let Some(resolved) = self.config().action(&request.resource, &request.action) else {
            return denied(DecisionReason::UnknownAction.denial());
        };
        if permit.approval_required {
            trail.denied("approval_unavailable".to_owned()).await;
            return denied(DenialReason::ApprovalInvalid);
        }

        self.run_allowed(&trail, resolved, &normalized, &permit)
            .await
    }

    /// Records the allow, retrieves the credential, runs the connector, and
    /// records the outcome.
    async fn run_allowed(
        &self,
        trail: &Trail<'_>,
        resolved: ResolvedAction<'_>,
        normalized: &Map<String, Value>,
        permit: &Permit,
    ) -> ActionResponse {
        let request_id = trail.request.request_id.clone();
        // Record the allow before the credential is touched.
        let decision = trail.allowed(&resolved, normalized, permit);
        if self.audit.sink.emit(&decision).await.is_err() && self.audit.required {
            return ActionResponse::Failed {
                request_id,
                reason: FailureReason::AuditUnavailable,
            };
        }

        let started = Instant::now();
        let result = match self.providers.get(resolved.secret_ref).await {
            Err(_) => Err(FailureReason::CredentialUnavailable),
            Ok(credential) => self
                .connector
                .execute(ConnectorCall {
                    action: resolved,
                    params: normalized,
                    credential,
                })
                .await
                .map_err(|e| failure_reason(&e)),
        };
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        let verdict = if result.is_ok() {
            Verdict::Completed
        } else {
            Verdict::Failed
        };
        let mut outcome = trail.event(EventKind::Outcome, verdict);
        trail.describe(&mut outcome, &resolved, normalized);
        outcome.downstream = Some(Downstream {
            status: result.as_ref().ok().map(|output| output.status),
            latency_ms,
        });
        if let Err(reason) = &result {
            outcome.reason = Some(failure_code(*reason));
        }
        // The action has already run; an outcome-event failure cannot undo
        // it, so the result is returned either way.
        let _ = self.audit.sink.emit(&outcome).await;

        match result {
            Ok(output) => {
                let mut body = json!({ "status": output.status, "body": output.body });
                if !output.headers.is_empty() {
                    body["headers"] = Value::Object(output.headers);
                }
                ActionResponse::Completed {
                    request_id,
                    result: body,
                    operation: None,
                }
            }
            Err(reason) => ActionResponse::Failed { request_id, reason },
        }
    }
}

fn failure_code(reason: FailureReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "failed".to_owned())
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
