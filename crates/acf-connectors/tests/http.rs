//! The restricted HTTP connector against a recording local upstream.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acf_config::{ConfigError, ValidatedConfig, load_yaml};
use acf_connectors::{
    ActionConnector, ConnectorCall, ConnectorError, ConnectorOutput, ForbiddenAddress,
    HostResolver, HttpConnector, HttpLimits, NetworkPolicy,
};
use acf_protocol::{ActionName, ResourceId};
use acf_secrets::{
    AuthSlot, ConnectorName, Environment, Origin, ResolvedSecret, SecretMaterial, SecretUseBinding,
    SecretVersion,
};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CANARY: &str = "ACF-CANARY-c0ffee";

// ---------------------------------------------------------------------------
// Recording upstream
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    delay: Duration,
}

impl Reply {
    fn json(value: &Value) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: serde_json::to_vec(value).unwrap(),
            delay: Duration::ZERO,
        }
    }
}

type Handler = Arc<dyn Fn(&Recorded) -> Reply + Send + Sync>;

struct Upstream {
    port: u16,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl Upstream {
    async fn start(handler: impl Fn(&Recorded) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler: Handler = Arc::new(handler);
        let recorded = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let handler = Arc::clone(&handler);
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    recorded.lock().unwrap().push(request.clone());
                    let reply = handler(&request);
                    tokio::time::sleep(reply.delay).await;
                    let mut head = format!(
                        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    for (name, value) in &reply.headers {
                        let _ = write!(head, "{name}: {value}\r\n");
                    }
                    head.push_str("\r\n");
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&reply.body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { port, requests }
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Recorded> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(i) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
    };
    let head = String::from_utf8(buffer[..head_end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(n, v)| (n.to_ascii_lowercase(), v.to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Recorded {
        method,
        target,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// Configuration and connector fixtures
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
          view: { location: query, type: string }
          ip: { location: query, type: ipv4 }
        response:
          fields: [user, authenticated]
          headers: [x-request-id]
      example.records.get:
        method: GET
        path: /records/{params.id}
        credential_slot: read
        classification: read
        params:
          id: { location: path, type: string, required: true }
        response: { fields: [id] }
      example.records.create:
        method: POST
        path: /records
        credential_slot: write
        classification: mutate
        params:
          name: { location: body, type: string, required: true }
          count: { location: body, type: integer }
        response: { fields: [id] }
  - schema: acf.profile/v1
    connector: keyed-api
    revision: 1
    base_url: {ORIGIN}/v2
    authentication: { strategy: header_api_key, header: X-Api-Key }
    actions:
      keyed.status.get:
        method: GET
        path: /status
        credential_slot: read
        classification: read
        response: { fields: [ok] }
resources:
  "example-api:development":
    connector: example-api
    environment: development
    credentials:
      read: secret://development/example-api/read
      write: secret://development/example-api/write
  "keyed-api:development":
    connector: keyed-api
    environment: development
    credentials:
      read: secret://development/keyed-api/read
secrets:
  "secret://development/example-api/read":
    use_binding: { connectors: [example-api], origins: ["{ORIGIN}"], auth_slot: read, environment: development }
  "secret://development/example-api/write":
    use_binding: { connectors: [example-api], origins: ["{ORIGIN}"], auth_slot: write, environment: development }
  "secret://development/keyed-api/read":
    use_binding: { connectors: [keyed-api], origins: ["{ORIGIN}"], auth_slot: read, environment: development }
"#;

fn config(origin: &str) -> ValidatedConfig {
    load_yaml(&BUNDLE.replace("{ORIGIN}", origin)).unwrap()
}

/// Resolves fixed names; anything else fails.
struct MapResolver(HashMap<&'static str, Vec<IpAddr>>);

#[async_trait]
impl HostResolver for MapResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        self.0
            .get(host)
            .cloned()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such host"))
    }
}

fn resolver(entries: &[(&'static str, &[&str])]) -> Arc<MapResolver> {
    Arc::new(MapResolver(
        entries
            .iter()
            .map(|(host, ips)| (*host, ips.iter().map(|ip| ip.parse().unwrap()).collect()))
            .collect(),
    ))
}

fn connector(policy: NetworkPolicy, limits: HttpLimits) -> HttpConnector {
    HttpConnector::new(
        policy,
        resolver(&[("upstream.test", &["127.0.0.1"])]),
        limits,
    )
    .unwrap()
}

fn dev_connector() -> HttpConnector {
    connector(NetworkPolicy::development_loopback(), HttpLimits::default())
}

fn params(value: &Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn binding(connector: &str, origin: &str, slot: &str) -> SecretUseBinding {
    SecretUseBinding::new(
        [ConnectorName::new(connector).unwrap()].into(),
        [Origin::parse(origin).unwrap()].into(),
        AuthSlot::new(slot).unwrap(),
        Environment::new("development").unwrap(),
    )
    .unwrap()
}

async fn call_with(
    connector: &HttpConnector,
    config: &ValidatedConfig,
    resource: &str,
    action: &str,
    args: &Value,
    secret: &str,
    attested: Option<SecretUseBinding>,
) -> Result<ConnectorOutput, ConnectorError> {
    let resolved = config
        .action(
            &ResourceId::new(resource).unwrap(),
            &ActionName::new(action).unwrap(),
        )
        .unwrap();
    let args = params(args);
    connector
        .execute(ConnectorCall {
            action: resolved,
            params: &args,
            credential: ResolvedSecret {
                material: SecretMaterial::from_string(secret.to_owned()),
                version: SecretVersion::FIRST,
                attested_binding: attested,
            },
        })
        .await
}

async fn call(
    connector: &HttpConnector,
    config: &ValidatedConfig,
    action: &str,
    args: &Value,
) -> Result<ConnectorOutput, ConnectorError> {
    call_with(
        connector,
        config,
        "example-api:development",
        action,
        args,
        CANARY,
        None,
    )
    .await
}

fn assert_no_canary(text: &str) {
    assert!(!text.contains(CANARY), "canary leaked: {text}");
}

fn profile_reply() -> Reply {
    Reply::json(&json!({ "user": "demo", "authenticated": true, "internal": "dropped" }))
}

// ---------------------------------------------------------------------------
// Acceptance: injected canary, filtered response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn injects_the_credential_and_returns_only_allowlisted_data() {
    let upstream = Upstream::start(|_| {
        let mut reply = profile_reply();
        reply.headers.push(("X-Request-Id", "req-42".to_owned()));
        reply.headers.push(("Set-Cookie", "session=abc".to_owned()));
        reply
    })
    .await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let output = call(
        &dev_connector(),
        &config(&origin),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap();

    assert_eq!(output.status, 200);
    assert_eq!(
        output.body,
        json!({ "user": "demo", "authenticated": true })
    );
    assert_eq!(output.headers, params(&json!({ "x-request-id": "req-42" })));
    assert_no_canary(&format!("{output:?}"));

    let [request] = upstream.requests().try_into().unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(request.target, "/profile");
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {CANARY}").as_str())
    );
    let names: Vec<&str> = request.headers.iter().map(|(n, _)| n.as_str()).collect();
    for forbidden in [
        "cookie",
        "referer",
        "proxy-authorization",
        "x-forwarded-for",
    ] {
        assert!(!names.contains(&forbidden), "unexpected header {forbidden}");
    }
}

#[tokio::test]
async fn api_key_strategy_uses_only_the_configured_header() {
    let upstream = Upstream::start(|_| Reply::json(&json!({ "ok": true }))).await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let output = call_with(
        &dev_connector(),
        &config(&origin),
        "keyed-api:development",
        "keyed.status.get",
        &json!({}),
        CANARY,
        None,
    )
    .await
    .unwrap();
    assert_eq!(output.body, json!({ "ok": true }));
    let [request] = upstream.requests().try_into().unwrap();
    assert_eq!(request.target, "/v2/status");
    assert_eq!(request.header("x-api-key"), Some(CANARY));
    assert_eq!(request.header("authorization"), None);
}

#[tokio::test]
async fn parameters_land_only_in_their_declared_locations() {
    let upstream = Upstream::start(|_| Reply::json(&json!({ "id": "r1" }))).await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let config = config(&origin);
    let connector = dev_connector();

    // Query values are encoded; they cannot add parameters or change the path.
    call(
        &connector,
        &config,
        "example.profile.get",
        &json!({ "view": "a&b=c#x/../y", "ip": "203.0.113.7" }),
    )
    .await
    .unwrap();
    // Body parameters are sent as JSON.
    call(
        &connector,
        &config,
        "example.records.create",
        &json!({ "name": "n1", "count": 2 }),
    )
    .await
    .unwrap();

    let requests = upstream.requests();
    assert_eq!(
        requests[0].target,
        "/profile?ip=203.0.113.7&view=a%26b%3Dc%23x%2F..%2Fy"
    );
    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[1].header("content-type"), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[1].body).unwrap(),
        json!({ "name": "n1", "count": 2 })
    );
}

// ---------------------------------------------------------------------------
// Negative tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn path_parameters_cannot_traverse_or_inject() {
    let upstream = Upstream::start(|_| Reply::json(&json!({ "id": "x" }))).await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let config = config(&origin);
    let connector = dev_connector();
    for bad in [
        "../admin",
        "a/b",
        "..",
        "%2e%2e",
        "a%2Fb",
        "x?y=1",
        "x#y",
        "evil.com@x",
    ] {
        let error = call(
            &connector,
            &config,
            "example.records.get",
            &json!({ "id": bad }),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, ConnectorError::InvalidRequest(_)),
            "{bad}: {error:?}"
        );
    }
    assert!(upstream.requests().is_empty(), "no request may be sent");
    call(
        &connector,
        &config,
        "example.records.get",
        &json!({ "id": "rec-1" }),
    )
    .await
    .unwrap();
    assert_eq!(upstream.requests()[0].target, "/records/rec-1");
}

#[tokio::test]
async fn credentials_with_control_characters_are_refused() {
    let upstream = Upstream::start(|_| profile_reply()).await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let config = config(&origin);
    for secret in [
        format!("{CANARY}\r\nX-Evil: 1"),
        format!("{CANARY}\ttab"),
        format!("{CANARY}\0"),
        String::new(),
    ] {
        let error = call_with(
            &dev_connector(),
            &config,
            "example-api:development",
            "example.profile.get",
            &json!({}),
            &secret,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error, ConnectorError::InvalidCredential);
        assert_no_canary(&format!("{error} {error:?}"));
    }
    assert!(upstream.requests().is_empty());
}

#[tokio::test]
async fn redirects_are_never_followed() {
    let upstream = Upstream::start(|_| Reply {
        status: 302,
        headers: vec![("Location", "http://evil.example/steal".to_owned())],
        body: Vec::new(),
        delay: Duration::ZERO,
    })
    .await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let error = call(
        &dev_connector(),
        &config(&origin),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ConnectorError::RedirectNotFollowed);
    assert_eq!(upstream.requests().len(), 1);
}

#[tokio::test]
async fn reflected_credentials_are_discarded() {
    // The upstream echoes the authorization header into an allowlisted field.
    let upstream = Upstream::start(|r| {
        Reply::json(&json!({ "user": r.header("authorization").unwrap_or_default(), "authenticated": true }))
    })
    .await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let error = call(
        &dev_connector(),
        &config(&origin),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ConnectorError::CredentialReflected);

    // Echoed into a field that is not allowlisted, it never leaves the gateway.
    let upstream = Upstream::start(|r| {
        Reply::json(
            &json!({ "user": "demo", "authenticated": true, "debug": r.header("authorization") }),
        )
    })
    .await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let output = call(
        &dev_connector(),
        &config(&origin),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap();
    assert_no_canary(&format!("{output:?}"));
}

#[tokio::test]
async fn response_size_and_format_are_bounded() {
    let upstream = Upstream::start(|_| {
        Reply::json(&json!({ "user": "x".repeat(4096), "authenticated": true }))
    })
    .await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let small = HttpLimits {
        max_response_bytes: 1024,
        ..HttpLimits::default()
    };
    let error = call(
        &connector(NetworkPolicy::development_loopback(), small),
        &config(&origin),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ConnectorError::ResponseTooLarge);

    let upstream = Upstream::start(|_| Reply {
        status: 200,
        headers: Vec::new(),
        body: b"<html>not json</html>".to_vec(),
        delay: Duration::ZERO,
    })
    .await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let error = call(
        &dev_connector(),
        &config(&origin),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ConnectorError::ResponseNotJson);
}

#[tokio::test]
async fn slow_upstreams_time_out() {
    let upstream = Upstream::start(|_| Reply {
        delay: Duration::from_secs(5),
        ..profile_reply()
    })
    .await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let quick = HttpLimits {
        total_timeout: Duration::from_millis(300),
        ..HttpLimits::default()
    };
    let error = call(
        &connector(NetworkPolicy::development_loopback(), quick),
        &config(&origin),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ConnectorError::Timeout);
}

#[tokio::test]
async fn destinations_are_filtered_by_address_policy() {
    let upstream = Upstream::start(|_| profile_reply()).await;
    let port = upstream.port;

    // A name that resolves to loopback is refused outside development
    // (DNS rebinding to a local service).
    let plaintext_only = NetworkPolicy {
        allow_plaintext_http: true,
        ..NetworkPolicy::production()
    };
    let by_name = format!("http://upstream.test:{port}");
    let error = call(
        &connector(plaintext_only, HttpLimits::default()),
        &config(&by_name),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error,
        ConnectorError::DestinationForbidden(ForbiddenAddress::Loopback)
    );

    // An IP-literal host bypasses DNS but is still checked.
    let by_ip = format!("http://127.0.0.1:{port}");
    let error = call(
        &connector(plaintext_only, HttpLimits::default()),
        &config(&by_ip),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error,
        ConnectorError::DestinationForbidden(ForbiddenAddress::Loopback)
    );

    // Plaintext http is refused by the production policy.
    let error = call(
        &connector(NetworkPolicy::production(), HttpLimits::default()),
        &config(&by_ip),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ConnectorError::PlaintextForbidden);

    // A rebinding answer mixing a public and a metadata address is refused,
    // even under the development policy.
    let rebinding = resolver(&[("upstream.test", &["203.0.113.10", "169.254.169.254"])]);
    let dev = HttpConnector::new(
        NetworkPolicy::development_loopback(),
        rebinding,
        HttpLimits::default(),
    )
    .unwrap();
    let error = call(&dev, &config(&by_name), "example.profile.get", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        ConnectorError::DestinationForbidden(ForbiddenAddress::Reserved)
    );

    // Development reaches the loopback upstream by name.
    call(
        &dev_connector(),
        &config(&by_name),
        "example.profile.get",
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        upstream.requests().len(),
        1,
        "only the allowed call reached the upstream"
    );
}

#[tokio::test]
async fn use_binding_is_rechecked_before_injection() {
    let upstream = Upstream::start(|_| profile_reply()).await;
    let origin = format!("http://127.0.0.1:{}", upstream.port);
    let config = config(&origin);

    let other_origin = binding("example-api", "https://evil.example", "read");
    let broader = SecretUseBinding::new(
        ["example-api", "keyed-api"]
            .iter()
            .map(|c| ConnectorName::new(*c).unwrap())
            .collect(),
        [Origin::parse(&origin).unwrap()].into(),
        AuthSlot::new("read").unwrap(),
        Environment::new("development").unwrap(),
    )
    .unwrap();
    for attested in [
        other_origin,
        broader,
        binding("example-api", &origin, "write"),
    ] {
        let error = call_with(
            &dev_connector(),
            &config,
            "example-api:development",
            "example.profile.get",
            &json!({}),
            CANARY,
            Some(attested),
        )
        .await
        .unwrap_err();
        assert_eq!(error, ConnectorError::BindingMismatch);
    }
    assert!(upstream.requests().is_empty());

    let exact = binding("example-api", &origin, "read");
    call_with(
        &dev_connector(),
        &config,
        "example-api:development",
        "example.profile.get",
        &json!({}),
        CANARY,
        Some(exact),
    )
    .await
    .unwrap();
}

#[test]
fn profiles_cannot_configure_redirects_proxies_or_extra_headers() {
    for (from, to) in [
        (
            "        classification: read\n        params:\n          view",
            "        classification: read\n        follow_redirects: true\n        params:\n          view",
        ),
        (
            "    authentication: { strategy: bearer }",
            "    authentication: { strategy: bearer }\n    proxy: http://proxy.example:3128",
        ),
        (
            "        classification: read\n        params:\n          view",
            "        classification: read\n        request_headers: { X-Forwarded-For: 1.2.3.4 }\n        params:\n          view",
        ),
    ] {
        assert!(BUNDLE.contains(from));
        let source = BUNDLE
            .replacen(from, to, 1)
            .replace("{ORIGIN}", "http://127.0.0.1:8080");
        match load_yaml(&source) {
            Err(ConfigError::Parse(message)) => {
                assert!(message.contains("unknown field"), "{message}");
            }
            other => panic!("expected an unknown-field error, got {other:?}"),
        }
    }
}

#[test]
fn errors_never_contain_the_credential() {
    let all = [
        ConnectorError::BindingMismatch,
        ConnectorError::UnsupportedStrategy,
        ConnectorError::InvalidCredential,
        ConnectorError::InvalidRequest("path".to_owned()),
        ConnectorError::DestinationForbidden(ForbiddenAddress::Reserved),
        ConnectorError::PlaintextForbidden,
        ConnectorError::RequestTooLarge,
        ConnectorError::RedirectNotFollowed,
        ConnectorError::Timeout,
        ConnectorError::Transport,
        ConnectorError::ResponseTooLarge,
        ConnectorError::ResponseNotJson,
        ConnectorError::CredentialReflected,
    ];
    for error in all {
        assert_no_canary(&format!("{error} {error:?}"));
    }
}
