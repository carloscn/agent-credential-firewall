//! Gateway end-to-end tests: HTTP in, recording upstream out.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acf_audit::{AuditError, AuditEvent, AuditHasher, AuditSink, GatewayInfo, MemorySink, Verdict};
use acf_config::load_yaml;
use acf_connectors::{
    ActionConnector, ConnectorCall, ConnectorError, ConnectorOutput, HttpConnector, HttpLimits,
    NetworkPolicy, SystemResolver,
};
use acf_gateway::{AuditSettings, Gateway, GatewayError, ProviderRegistry, ServerLimits, router};
use acf_identity::{ConnectionInfo, DevelopmentIdentityProvider};
use acf_policy::{Authorizer, AuthorizerSettings};
use acf_protocol::{
    ActionRequest, ActionResponse, AudienceId, DenialReason, FailureReason, PrincipalId,
};
use acf_secrets::{
    InMemoryProvider, Namespace, ResolvedSecret, SecretAdmin, SecretError, SecretMaterial,
    SecretProvider, SecretRef,
};
use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CANARY: &str = "ACF-CANARY-gateway-5e1f";

// ---------------------------------------------------------------------------
// Recording upstream that also notices when the caller hangs up early.
// ---------------------------------------------------------------------------

/// Method, target, and `Authorization` header of one upstream request.
type SeenRequest = (String, String, Option<String>);

#[derive(Clone, Default)]
struct UpstreamLog {
    requests: Arc<Mutex<Vec<SeenRequest>>>,
    closed_early: Arc<AtomicBool>,
}

async fn start_upstream(delay: Duration) -> (u16, UpstreamLog) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = UpstreamLog::default();
    let shared = log.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let log = shared.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buffer).to_string();
                let mut lines = head.split("\r\n");
                let mut first = lines.next().unwrap_or_default().split(' ');
                let method = first.next().unwrap_or_default().to_owned();
                let target = first.next().unwrap_or_default().to_owned();
                let authorization = lines
                    .filter_map(|l| l.split_once(": "))
                    .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
                    .map(|(_, v)| v.to_owned());
                log.requests
                    .lock()
                    .unwrap()
                    .push((method, target, authorization));

                // Wait out the delay, unless the caller hangs up first.
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    read = stream.read(&mut chunk) => {
                        if matches!(read, Ok(0)) {
                            log.closed_early.store(true, Ordering::SeqCst);
                        }
                        return;
                    }
                }
                let body = json!({ "user": "demo", "authenticated": true, "internal": "dropped" })
                    .to_string();
                let mut reply = String::new();
                let _ = write!(
                    reply,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    (port, log)
}

// ---------------------------------------------------------------------------
// Instrumented provider and connector: record the order of side effects.
// ---------------------------------------------------------------------------

type Events = Arc<Mutex<Vec<&'static str>>>;

struct RecordingProvider {
    inner: Arc<InMemoryProvider>,
    events: Events,
}

#[async_trait]
impl SecretProvider for RecordingProvider {
    async fn get(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretError> {
        self.events.lock().unwrap().push("retrieve");
        self.inner.get(reference).await
    }
}

struct RecordingConnector {
    inner: HttpConnector,
    events: Events,
}

#[async_trait]
impl ActionConnector for RecordingConnector {
    async fn execute(&self, call: ConnectorCall<'_>) -> Result<ConnectorOutput, ConnectorError> {
        self.events.lock().unwrap().push("execute");
        self.inner.execute(call).await
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BUNDLE: &str = r#"
schema: acf.config/v1
deployment: { profile: development, environment: development }
secret_providers:
  development: { type: in-memory }
profiles:
  - schema: acf.profile/v1
    connector: example-api
    revision: 1
    base_url: {ORIGIN}
    authentication: { strategy: bearer }
    actions:
      example.profile.get:
        method: GET
        path: /profile
        credential_slot: read
        classification: read
        params:
          view: { location: query, type: string, enum: [summary, full] }
          note: { location: query, type: string }
          token: { location: query, type: string }
        response: { fields: [user, authenticated] }
        audit: { record: [view], hash: [note] }
      example.records.create:
        method: POST
        path: /records
        credential_slot: write
        classification: mutate
        params:
          name: { location: body, type: string, required: true }
        response: { fields: [id] }
resources:
  "example-api:development":
    connector: example-api
    environment: development
    credentials:
      read: secret://development/example-api/read
      write: secret://development/example-api/write
secrets:
  "secret://development/example-api/read":
    use_binding: { connectors: [example-api], origins: ["{ORIGIN}"], auth_slot: read, environment: development }
  "secret://development/example-api/write":
    use_binding: { connectors: [example-api], origins: ["{ORIGIN}"], auth_slot: write, environment: development }
"#;

const POLICY: &str = r"
schema: acf.policy/v1
version: dev.1
rules:
  - id: dev-agent
    effect: allow
    principals: [dev-agent]
    actions: [example.profile.get, example.records.create]
    resources: ['example-api:development']
";

struct Harness {
    gateway: Arc<Gateway>,
    events: Events,
    upstream: UpstreamLog,
    audit: Arc<MemorySink>,
}

fn audit_settings(sink: Arc<dyn AuditSink>) -> AuditSettings {
    AuditSettings {
        sink,
        hasher: AuditHasher::random().unwrap(),
        required: true,
        gateway: GatewayInfo {
            id: "gw-test".to_owned(),
            build: "development".to_owned(),
            deployment_profile: "development".to_owned(),
        },
    }
}

async fn harness(principal: &str, delay: Duration, seed: bool) -> Harness {
    harness_with(principal, delay, seed, None).await
}

async fn harness_with(
    principal: &str,
    delay: Duration,
    seed: bool,
    sink: Option<Arc<dyn AuditSink>>,
) -> Harness {
    let (port, upstream) = start_upstream(delay).await;
    let origin = format!("http://127.0.0.1:{port}");
    let config = load_yaml(&BUNDLE.replace("{ORIGIN}", &origin)).unwrap();

    let store = Arc::new(InMemoryProvider::new([
        Namespace::new("development").unwrap()
    ]));
    if seed {
        let reference = SecretRef::parse("secret://development/example-api/read").unwrap();
        let binding = config.secret(&reference).unwrap().use_binding.clone();
        store
            .put(
                &reference,
                SecretMaterial::from_string(CANARY.to_owned()),
                binding,
            )
            .await
            .unwrap();
    }
    let events: Events = Arc::default();
    let provider = Arc::new(RecordingProvider {
        inner: store,
        events: Arc::clone(&events),
    });
    let connector = Arc::new(RecordingConnector {
        inner: HttpConnector::new(
            NetworkPolicy::development_loopback(),
            Arc::new(SystemResolver),
            HttpLimits::default(),
        )
        .unwrap(),
        events: Arc::clone(&events),
    });
    let settings = AuthorizerSettings {
        audience: AudienceId::new("acf-gateway-dev").unwrap(),
        clock_skew_secs: 30,
    };
    let authorizer = Authorizer::new(config, POLICY, settings).unwrap();
    let identity = Arc::new(DevelopmentIdentityProvider::new(
        PrincipalId::new(principal).unwrap(),
        None,
        BTreeSet::new(),
        None,
    ));
    let registry = ProviderRegistry::default().with("development", provider);
    let audit = Arc::new(MemorySink::default());
    let sink = sink.unwrap_or_else(|| audit.clone());
    let gateway = Gateway::new(
        authorizer,
        identity,
        registry,
        connector,
        audit_settings(sink),
    )
    .unwrap();
    Harness {
        gateway: Arc::new(gateway),
        events,
        upstream,
        audit,
    }
}

async fn serve(gateway: Arc<Gateway>, limits: ServerLimits) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(gateway, limits))
            .await
            .unwrap();
    });
    format!("http://{address}")
}

fn request(action: &str, resource: &str, params: &Value) -> ActionRequest {
    serde_json::from_value(json!({
        "requestId": "req-1",
        "timestamp": "2026-10-24T18:00:00Z",
        "taskId": "dev-task",
        "action": action,
        "resource": resource,
        "parameters": params,
    }))
    .unwrap()
}

fn profile_get() -> ActionRequest {
    request(
        "example.profile.get",
        "example-api:development",
        &json!({ "view": "summary" }),
    )
}

async fn post(base: &str, body: Vec<u8>) -> (u16, String) {
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/actions/execute"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.text().await.unwrap())
}

// ---------------------------------------------------------------------------
// Milestone 0 demo and ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m0_demo_returns_allowlisted_data_and_never_the_credential() {
    let h = harness("dev-agent", Duration::ZERO, true).await;
    let base = serve(Arc::clone(&h.gateway), ServerLimits::default()).await;

    let (status, text) = post(&base, serde_json::to_vec(&profile_get()).unwrap()).await;
    assert_eq!(status, 200, "{text}");
    assert!(
        !text.contains(CANARY),
        "credential leaked to the agent: {text}"
    );
    let response: ActionResponse = serde_json::from_str(&text).unwrap();
    let ActionResponse::Completed { result, .. } = response else {
        panic!("{text}")
    };
    assert_eq!(
        result,
        json!({ "status": 200, "body": { "user": "demo", "authenticated": true } })
    );

    // Authorization happened first; then retrieval; then the connector.
    assert_eq!(*h.events.lock().unwrap(), ["retrieve", "execute"]);
    let requests = h.upstream.requests.lock().unwrap().clone();
    assert_eq!(
        requests,
        [(
            "GET".to_owned(),
            "/profile?view=summary".to_owned(),
            Some(format!("Bearer {CANARY}"))
        )]
    );
}

#[tokio::test]
async fn denied_requests_never_reach_the_provider_or_upstream() {
    let cases = [
        ("someone-else", profile_get(), DenialReason::PolicyDenied),
        (
            "dev-agent",
            request(
                "example.profile.delete",
                "example-api:development",
                &json!({}),
            ),
            DenialReason::UnknownAction,
        ),
        (
            "dev-agent",
            request("example.profile.get", "example-api:production", &json!({})),
            DenialReason::UnknownResource,
        ),
        (
            "dev-agent",
            request(
                "example.profile.get",
                "example-api:development",
                &json!({ "url": "http://evil" }),
            ),
            DenialReason::InvalidParameters,
        ),
        (
            "dev-agent",
            request(
                "example.profile.get",
                "example-api:development",
                &json!({ "view": "everything" }),
            ),
            DenialReason::InvalidParameters,
        ),
        (
            "dev-agent",
            request(
                "example.records.create",
                "example-api:development",
                &json!({ "name": "n" }),
            ),
            DenialReason::ApprovalInvalid,
        ),
    ];
    for (principal, request, expected) in cases {
        let h = harness(principal, Duration::ZERO, true).await;
        let response = h
            .gateway
            .execute(&ConnectionInfo::default(), request.clone())
            .await;
        match response {
            ActionResponse::Denied { reason, .. } => assert_eq!(reason, expected, "{request:?}"),
            other => panic!("expected denial for {request:?}, got {other:?}"),
        }
        assert!(
            h.events.lock().unwrap().is_empty(),
            "provider or connector ran for {request:?}"
        );
        assert!(h.upstream.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn missing_credentials_fail_before_the_connector() {
    let h = harness("dev-agent", Duration::ZERO, false).await;
    let response = h
        .gateway
        .execute(&ConnectionInfo::default(), profile_get())
        .await;
    assert!(
        matches!(
            response,
            ActionResponse::Failed {
                reason: FailureReason::CredentialUnavailable,
                ..
            }
        ),
        "{response:?}"
    );
    assert_eq!(*h.events.lock().unwrap(), ["retrieve"]);
    assert!(h.upstream.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unreachable_upstream_is_a_failure_not_a_denial() {
    let h = harness("dev-agent", Duration::ZERO, true).await;
    // Point the same gateway at a port nobody listens on.
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config =
        load_yaml(&BUNDLE.replace("{ORIGIN}", &format!("http://127.0.0.1:{closed}"))).unwrap();
    let reference = SecretRef::parse("secret://development/example-api/read").unwrap();
    let store = Arc::new(InMemoryProvider::new([
        Namespace::new("development").unwrap()
    ]));
    store
        .put(
            &reference,
            SecretMaterial::from_string(CANARY.to_owned()),
            config.secret(&reference).unwrap().use_binding.clone(),
        )
        .await
        .unwrap();
    let gateway = Gateway::new(
        Authorizer::new(
            config,
            POLICY,
            AuthorizerSettings {
                audience: AudienceId::new("acf-gateway-dev").unwrap(),
                clock_skew_secs: 30,
            },
        )
        .unwrap(),
        Arc::new(DevelopmentIdentityProvider::new(
            PrincipalId::new("dev-agent").unwrap(),
            None,
            BTreeSet::new(),
            None,
        )),
        ProviderRegistry::default().with("development", store),
        Arc::new(
            HttpConnector::new(
                NetworkPolicy::development_loopback(),
                Arc::new(SystemResolver),
                HttpLimits::default(),
            )
            .unwrap(),
        ),
        audit_settings(Arc::new(MemorySink::default())),
    )
    .unwrap();
    let response = gateway
        .execute(&ConnectionInfo::default(), profile_get())
        .await;
    assert!(
        matches!(
            response,
            ActionResponse::Failed {
                reason: FailureReason::DownstreamUnavailable,
                ..
            }
        ),
        "{response:?}"
    );
    drop(h);
}

// ---------------------------------------------------------------------------
// Cancellation and time limits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancelling_a_request_drops_the_downstream_call() {
    let h = harness("dev-agent", Duration::from_secs(5), true).await;
    let connection = ConnectionInfo::default();
    let call = h.gateway.execute(&connection, profile_get());
    assert!(
        tokio::time::timeout(Duration::from_millis(300), call)
            .await
            .is_err(),
        "call should still be pending"
    );

    // Dropping the future closed the downstream connection: no background
    // task kept the credential-bearing request alive.
    for _ in 0..50 {
        if h.upstream.closed_early.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("upstream connection stayed open after cancellation");
}

#[tokio::test]
async fn the_server_time_limit_cancels_slow_requests() {
    let h = harness("dev-agent", Duration::from_secs(5), true).await;
    let limits = ServerLimits {
        request_timeout: Duration::from_millis(300),
        ..ServerLimits::default()
    };
    let base = serve(Arc::clone(&h.gateway), limits).await;
    let (status, text) = post(&base, serde_json::to_vec(&profile_get()).unwrap()).await;
    assert_eq!(status, 504);
    assert!(text.contains("gateway_timeout"), "{text}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(h.upstream.closed_early.load(Ordering::SeqCst));
}

// ---------------------------------------------------------------------------
// HTTP surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_and_malformed_requests() {
    let h = harness("dev-agent", Duration::ZERO, true).await;
    let base = serve(
        Arc::clone(&h.gateway),
        ServerLimits {
            max_body_bytes: 2048,
            ..ServerLimits::default()
        },
    )
    .await;

    let health = reqwest::get(format!("{base}/healthz")).await.unwrap();
    assert_eq!(health.status().as_u16(), 200);
    assert_eq!(
        serde_json::from_str::<Value>(&health.text().await.unwrap()).unwrap(),
        json!({ "status": "ok" })
    );

    // Unknown fields and malformed JSON get a fixed body that echoes nothing.
    for body in [
        json!({ "requestId": "ECHO-ME", "url": "http://evil", "action": "x.y" }).to_string(),
        "{not json ECHO-ME".to_owned(),
    ] {
        let (status, text) = post(&base, body.into_bytes()).await;
        assert_eq!(status, 400);
        assert_eq!(text, r#"{"error":"invalid_request"}"#);
    }

    let (status, _) = post(&base, vec![b' '; 4096]).await;
    assert_eq!(status, 413);
    assert!(h.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn startup_rejects_unsafe_wiring() {
    let config = load_yaml(&BUNDLE.replace("{ORIGIN}", "http://127.0.0.1:8080")).unwrap();
    let settings = AuthorizerSettings {
        audience: AudienceId::new("acf-gateway-dev").unwrap(),
        clock_skew_secs: 30,
    };
    let identity = Arc::new(DevelopmentIdentityProvider::new(
        PrincipalId::new("dev-agent").unwrap(),
        None,
        BTreeSet::new(),
        None,
    ));
    let connector = Arc::new(
        HttpConnector::new(
            NetworkPolicy::development_loopback(),
            Arc::new(SystemResolver),
            HttpLimits::default(),
        )
        .unwrap(),
    );

    // A configured namespace without a runtime provider.
    let result = Gateway::new(
        Authorizer::new(config, POLICY, settings.clone()).unwrap(),
        identity.clone(),
        ProviderRegistry::default(),
        connector.clone(),
        audit_settings(Arc::new(MemorySink::default())),
    );
    assert_eq!(
        result.err(),
        Some(GatewayError::MissingProvider("development".to_owned()))
    );

    // A development identity under the production profile.
    let production = include_str!("../../acf-config/tests/fixtures/cloudflare-production.yaml");
    let policy = "schema: acf.policy/v1\nversion: p.1\n";
    let result = Gateway::new(
        Authorizer::new(load_yaml(production).unwrap(), policy, settings).unwrap(),
        identity,
        ProviderRegistry::default(),
        connector,
        audit_settings(Arc::new(MemorySink::default())),
    );
    assert_eq!(result.err(), Some(GatewayError::IdentityProviderRejected));
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn allowed_requests_emit_attributable_decision_and_outcome_events() {
    let h = harness("dev-agent", Duration::ZERO, true).await;
    h.gateway
        .execute(&ConnectionInfo::default(), profile_get())
        .await;

    let events = h.audit.events();
    let [decision, outcome] = events.as_slice() else {
        panic!("{events:#?}")
    };
    for event in [decision, outcome] {
        assert_eq!(event.request_id.as_str(), "req-1");
        assert_eq!(event.task_id.as_str(), "dev-task");
        assert_eq!(
            event.principal.as_ref().map(PrincipalId::as_str),
            Some("dev-agent")
        );
        assert_eq!(event.gateway.id, "gw-test");
        assert_eq!(event.connector.as_deref(), Some("example-api"));
        assert_eq!(
            event.secret_ref.as_deref(),
            Some("secret://development/example-api/read")
        );
    }
    assert_eq!(decision.verdict, Verdict::Allowed);
    assert_eq!(decision.policy.as_ref().unwrap().version, "dev.1");
    assert_eq!(decision.policy.as_ref().unwrap().rules, ["dev-agent"]);
    assert_eq!(outcome.verdict, Verdict::Completed);
    assert_eq!(outcome.downstream.unwrap().status, Some(200));
}

#[tokio::test]
async fn denied_requests_emit_attributable_reason_codes() {
    for (principal, request, reason) in [
        ("someone-else", profile_get(), "policy_no_matching_rule"),
        (
            "dev-agent",
            request(
                "example.profile.delete",
                "example-api:development",
                &json!({}),
            ),
            "unknown_action",
        ),
        (
            "dev-agent",
            request(
                "example.profile.get",
                "example-api:development",
                &json!({ "url": "x" }),
            ),
            "invalid_parameters",
        ),
        (
            "dev-agent",
            request(
                "example.records.create",
                "example-api:development",
                &json!({ "name": "n" }),
            ),
            "approval_unavailable",
        ),
    ] {
        let h = harness(principal, Duration::ZERO, true).await;
        h.gateway.execute(&ConnectionInfo::default(), request).await;
        let events = h.audit.events();
        let [decision] = events.as_slice() else {
            panic!("{events:#?}")
        };
        assert_eq!(decision.verdict, Verdict::Denied);
        assert_eq!(decision.reason.as_deref(), Some(reason));
        assert_eq!(
            decision.principal.as_ref().map(PrincipalId::as_str),
            Some(principal)
        );
        assert!(decision.secret_ref.is_none() && decision.params.is_empty());
    }
}

#[tokio::test]
async fn parameters_appear_only_as_classified() {
    let h = harness("dev-agent", Duration::ZERO, true).await;
    let call = request(
        "example.profile.get",
        "example-api:development",
        &json!({ "view": "full", "note": "ticket-4711", "token": CANARY }),
    );
    h.gateway.execute(&ConnectionInfo::default(), call).await;

    for event in h.audit.events() {
        let text = serde_json::to_string(&event).unwrap();
        assert!(!text.contains(CANARY), "omitted parameter leaked: {text}");
        assert!(
            !text.contains("ticket-4711"),
            "hashed parameter leaked: {text}"
        );
        let params = serde_json::to_value(&event.params).unwrap();
        assert_eq!(params["view"], json!({ "value": "full" }));
        let hmac = params["note"]["hmac"].as_str().unwrap();
        assert_eq!(hmac.len(), 64);
        assert!(params.get("token").is_none());
    }
}

struct FailingSink;

#[async_trait]
impl AuditSink for FailingSink {
    async fn emit(&self, _: &AuditEvent) -> Result<(), AuditError> {
        Err(AuditError::Unavailable)
    }
}

#[tokio::test]
async fn required_audit_fails_closed_before_the_credential_is_touched() {
    let h = harness_with(
        "dev-agent",
        Duration::ZERO,
        true,
        Some(Arc::new(FailingSink)),
    )
    .await;
    let response = h
        .gateway
        .execute(&ConnectionInfo::default(), profile_get())
        .await;
    assert!(
        matches!(
            response,
            ActionResponse::Failed {
                reason: FailureReason::AuditUnavailable,
                ..
            }
        ),
        "{response:?}"
    );
    assert!(
        h.events.lock().unwrap().is_empty(),
        "provider or connector ran"
    );
    assert!(h.upstream.requests.lock().unwrap().is_empty());

    // Denials are still returned when the sink is down.
    let h = harness_with(
        "someone-else",
        Duration::ZERO,
        true,
        Some(Arc::new(FailingSink)),
    )
    .await;
    let response = h
        .gateway
        .execute(&ConnectionInfo::default(), profile_get())
        .await;
    assert!(
        matches!(response, ActionResponse::Denied { .. }),
        "{response:?}"
    );
}
