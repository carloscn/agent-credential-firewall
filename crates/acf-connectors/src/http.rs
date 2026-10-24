//! Restricted HTTP connector for declarative profiles.
//!
//! The method, origin, path template, credential placement, and response
//! allowlist all come from the reviewed profile. The agent contributes only
//! validated, normalized parameter values. The client never uses a proxy,
//! never follows redirects, never retries, and connects only to addresses the
//! [`NetworkPolicy`] accepts.
//!
//! Plaintext boundary: the credential is copied into one sensitive HTTP
//! header value, which the HTTP stack holds until the request is written. The
//! temporary buffer used to build it is zeroized.

use std::error::Error as _;
use std::sync::Arc;
use std::time::Duration;

use acf_config::{Authentication, HttpMethod, ParamLocation, ResolvedAction};
use acf_secrets::{ResolvedSecret, SecretUseBinding};
use async_trait::async_trait;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, Url, redirect, retry};
use serde_json::{Map, Value};
use url::Host;
use zeroize::Zeroize;

use crate::network::{ForbiddenAddress, HostResolver, NetworkPolicy, ValidatingResolver};
use crate::projection::project;

/// Size and time limits for one downstream call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpLimits {
    /// TCP and TLS connect timeout.
    pub connect_timeout: Duration,
    /// Whole-request timeout, including reading the response.
    pub total_timeout: Duration,
    /// Largest request body sent.
    pub max_request_bytes: usize,
    /// Largest response body read.
    pub max_response_bytes: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            max_request_bytes: 64 * 1024,
            max_response_bytes: 1024 * 1024,
        }
    }
}

/// One authorized call to execute.
pub struct ConnectorCall<'a> {
    /// The resolved action, profile, resource, and secret registration.
    pub action: ResolvedAction<'a>,
    /// Validated and normalized parameters.
    pub params: &'a Map<String, Value>,
    /// The credential for the action's slot, retrieved after authorization.
    pub credential: ResolvedSecret,
}

/// What the agent may see of the downstream response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorOutput {
    /// Downstream HTTP status.
    pub status: u16,
    /// Allowlisted body fields.
    pub body: Value,
    /// Allowlisted response headers, lowercase names.
    pub headers: Map<String, Value>,
}

/// Connector failures. Never contain credential material.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorError {
    /// The secret's use binding does not permit this connector, origin, or
    /// slot, or the provider's attested binding is broader than the registry's.
    #[error("credential use binding does not permit this destination")]
    BindingMismatch,
    /// The profile's authentication strategy is not implemented yet.
    #[error("authentication strategy is not supported")]
    UnsupportedStrategy,
    /// The credential cannot be placed in a header (for example, it
    /// contains control characters).
    #[error("credential cannot be encoded as a header value")]
    InvalidCredential,
    /// The request could not be built from the template and parameters.
    #[error("request could not be built: {0}")]
    InvalidRequest(String),
    /// The destination is not allowed by the network policy.
    #[error("destination refused: {0}")]
    DestinationForbidden(ForbiddenAddress),
    /// Plaintext HTTP is not allowed by the network policy.
    #[error("plaintext http destinations are not allowed")]
    PlaintextForbidden,
    /// The request body exceeds the limit.
    #[error("request body exceeds the limit")]
    RequestTooLarge,
    /// The downstream service answered with a redirect, which is never followed.
    #[error("downstream redirect was not followed")]
    RedirectNotFollowed,
    /// The downstream call timed out. For a mutation the outcome is unknown.
    #[error("downstream call timed out")]
    Timeout,
    /// A transport failure other than a timeout.
    #[error("downstream transport failure")]
    Transport,
    /// The response body exceeds the limit.
    #[error("response body exceeds the limit")]
    ResponseTooLarge,
    /// The response body is not JSON.
    #[error("response body is not JSON")]
    ResponseNotJson,
    /// The allowlisted response contained the credential; it was discarded.
    #[error("response contained the credential and was discarded")]
    CredentialReflected,
}

/// Executes one authorized action.
#[async_trait]
pub trait ActionConnector: Send + Sync {
    /// Executes `call`.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError`]; no partial output is returned.
    async fn execute(&self, call: ConnectorCall<'_>) -> Result<ConnectorOutput, ConnectorError>;
}

/// The restricted HTTP runtime shared by all declarative profiles.
pub struct HttpConnector {
    client: Client,
    policy: NetworkPolicy,
    limits: HttpLimits,
}

impl HttpConnector {
    /// Builds the connector.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Transport`] if the HTTP client cannot be
    /// initialized (for example, no TLS roots).
    pub fn new(
        policy: NetworkPolicy,
        resolver: Arc<dyn HostResolver>,
        limits: HttpLimits,
    ) -> Result<Self, ConnectorError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .retry(retry::never())
            .referer(false)
            .https_only(!policy.allow_plaintext_http)
            .connect_timeout(limits.connect_timeout)
            .timeout(limits.total_timeout)
            .user_agent(concat!("acf-gateway/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(ValidatingResolver {
                inner: resolver,
                policy,
            })
            .build()
            .map_err(|_| ConnectorError::Transport)?;
        Ok(Self {
            client,
            policy,
            limits,
        })
    }

    fn build_url(&self, call: &ConnectorCall<'_>) -> Result<Url, ConnectorError> {
        let profile = call.action.profile;
        let path = call
            .action
            .action
            .path
            .render(
                &profile.base_url,
                &call.action.resource.bindings,
                call.params,
            )
            .map_err(|e| ConnectorError::InvalidRequest(e.to_string()))?;
        let origin = profile.base_url.origin().as_str();
        let mut url = Url::parse(&format!("{origin}{path}"))
            .map_err(|_| ConnectorError::InvalidRequest("invalid url".to_owned()))?;

        let mut query: Vec<(&str, String)> = Vec::new();
        for (name, spec) in &call.action.action.params {
            if spec.location != ParamLocation::Query {
                continue;
            }
            if let Some(value) = call.params.get(name.as_str()) {
                query.push((name.as_str(), scalar_to_string(value)?));
            }
        }
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }

        // The rendered URL must still be on the profile's origin.
        if url.origin().ascii_serialization() != origin {
            return Err(ConnectorError::InvalidRequest(
                "url left the profile origin".to_owned(),
            ));
        }
        if url.scheme() == "http" && !self.policy.allow_plaintext_http {
            return Err(ConnectorError::PlaintextForbidden);
        }
        // IP-literal hosts bypass the resolver; check them here.
        match url.host() {
            Some(Host::Ipv4(ip)) => self.policy.check_ip(ip.into()),
            Some(Host::Ipv6(ip)) => self.policy.check_ip(ip.into()),
            Some(Host::Domain(_)) => Ok(()),
            None => Err(ForbiddenAddress::Unresolved),
        }
        .map_err(ConnectorError::DestinationForbidden)?;
        Ok(url)
    }

    fn build_body(&self, call: &ConnectorCall<'_>) -> Result<Option<Vec<u8>>, ConnectorError> {
        let mut body = Map::new();
        for (name, spec) in &call.action.action.params {
            if spec.location == ParamLocation::Body
                && let Some(value) = call.params.get(name.as_str())
            {
                body.insert(name.to_string(), value.clone());
            }
        }
        let has_body_params = call
            .action
            .action
            .params
            .values()
            .any(|spec| spec.location == ParamLocation::Body);
        if !has_body_params {
            return Ok(None);
        }
        let bytes = serde_json::to_vec(&Value::Object(body))
            .map_err(|_| ConnectorError::InvalidRequest("body".to_owned()))?;
        if bytes.len() > self.limits.max_request_bytes {
            return Err(ConnectorError::RequestTooLarge);
        }
        Ok(Some(bytes))
    }
}

fn scalar_to_string(value: &Value) -> Result<String, ConnectorError> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err(ConnectorError::InvalidRequest(
            "query parameters must be scalars".to_owned(),
        )),
    }
}

fn method(method: HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Delete => Method::DELETE,
    }
}

/// Re-checks the use binding immediately before injection.
fn check_binding(call: &ConnectorCall<'_>) -> Result<(), ConnectorError> {
    let profile = call.action.profile;
    let registry: &SecretUseBinding = &call.action.secret.use_binding;
    let origin = profile.base_url.origin();
    let slot = &call.action.action.credential_slot;
    if !registry.permits(&profile.connector, origin, slot) {
        return Err(ConnectorError::BindingMismatch);
    }
    if let Some(attested) = &call.credential.attested_binding
        && (!attested.is_within(registry) || !attested.permits(&profile.connector, origin, slot))
    {
        return Err(ConnectorError::BindingMismatch);
    }
    Ok(())
}

/// Builds the credential header. The temporary buffer is zeroized.
fn credential_header(
    authentication: &Authentication,
    credential: &ResolvedSecret,
) -> Result<(HeaderName, HeaderValue), ConnectorError> {
    let secret = credential.material.expose_secret();
    if secret.is_empty() {
        return Err(ConnectorError::InvalidCredential);
    }
    let (name, mut raw) = match authentication {
        Authentication::Bearer => {
            let mut raw = Vec::with_capacity(7 + secret.len());
            raw.extend_from_slice(b"Bearer ");
            raw.extend_from_slice(secret);
            (AUTHORIZATION, raw)
        }
        Authentication::HeaderApiKey { header } => (
            HeaderName::from_bytes(header.as_str().as_bytes())
                .map_err(|_| ConnectorError::InvalidCredential)?,
            secret.to_vec(),
        ),
        Authentication::Basic => return Err(ConnectorError::UnsupportedStrategy),
    };
    let value = HeaderValue::from_bytes(&raw);
    raw.zeroize();
    let mut value = value.map_err(|_| ConnectorError::InvalidCredential)?;
    if value.as_bytes().iter().any(|b| *b < 0x20 || *b == 0x7f) {
        // Tabs and other controls are legal in header values but never in a
        // credential; refuse rather than forward them.
        return Err(ConnectorError::InvalidCredential);
    }
    value.set_sensitive(true);
    Ok((name, value))
}

fn classify_send_error(error: &reqwest::Error) -> ConnectorError {
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(forbidden) = cause.downcast_ref::<ForbiddenAddress>() {
            return ConnectorError::DestinationForbidden(*forbidden);
        }
        source = cause.source();
    }
    if error.is_timeout() {
        ConnectorError::Timeout
    } else {
        ConnectorError::Transport
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[async_trait]
impl ActionConnector for HttpConnector {
    async fn execute(&self, call: ConnectorCall<'_>) -> Result<ConnectorOutput, ConnectorError> {
        check_binding(&call)?;
        let url = self.build_url(&call)?;
        let body = self.build_body(&call)?;
        let spec = call.action.action;
        let (auth_name, auth_value) =
            credential_header(&call.action.profile.authentication, &call.credential)?;

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(auth_name, auth_value);
        let mut request = self
            .client
            .request(method(spec.method), url)
            .headers(headers);
        if let Some(body) = body {
            request = request
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(body);
        }

        let mut response = request.send().await.map_err(|e| classify_send_error(&e))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(ConnectorError::RedirectNotFollowed);
        }

        let mut allowed_headers = Map::new();
        for name in &spec.response.headers {
            if let Some(value) = response
                .headers()
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
            {
                allowed_headers.insert(name.as_str().to_owned(), Value::String(value.to_owned()));
            }
        }

        let mut raw = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| classify_send_error(&e))?
        {
            if raw.len() + chunk.len() > self.limits.max_response_bytes {
                return Err(ConnectorError::ResponseTooLarge);
            }
            raw.extend_from_slice(&chunk);
        }
        let parsed = if raw.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&raw).map_err(|_| ConnectorError::ResponseNotJson)?
        };
        let body = project(&parsed, &spec.response.fields);

        // Defense in depth: an upstream that echoes the credential into an
        // allowlisted field must not deliver it to the agent.
        let visible = serde_json::to_vec(&(&body, &allowed_headers))
            .map_err(|_| ConnectorError::ResponseNotJson)?;
        if contains(&visible, call.credential.material.expose_secret()) {
            return Err(ConnectorError::CredentialReflected);
        }

        Ok(ConnectorOutput {
            status: status.as_u16(),
            body,
            headers: allowed_headers,
        })
    }
}
