//! TLS 1.3 + mTLS listener and certificate identity (WP-08, ADR 0002).

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/pki.rs"]
mod pki;

use std::fmt::Write as _;
use std::sync::Arc;

use acf_audit::{AuditHasher, GatewayInfo, MemorySink};
use acf_config::{load_yaml, parse_yaml};
use acf_connectors::{HttpConnector, HttpLimits, NetworkPolicy, SystemResolver};
use acf_gateway::{
    AuditSettings, Gateway, ProviderRegistry, ServerLimits, StateSettings, router, serve_tls,
    server_config,
};
use acf_identity::{DeviceRegistry, MtlsIdentityProvider, thumbprint};
use acf_policy::{Authorizer, AuthorizerSettings};
use acf_protocol::{AudienceId, IssuerId};
use acf_secrets::{InMemoryProvider, Namespace, SecretAdmin, SecretMaterial, SecretRef};
use acf_state::MemoryStateStore;
use pki::{Issued, Pki};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
        response: { fields: [user, authenticated] }
resources:
  "example-api:development":
    connector: example-api
    environment: development
    credentials:
      read: secret://development/example-api/read
secrets:
  "secret://development/example-api/read":
    use_binding: { connectors: [example-api], origins: ["{ORIGIN}"], auth_slot: read, environment: development }
"#;

const POLICY: &str = r"
schema: acf.policy/v1
version: tls.1
rules:
  - id: vps-17
    effect: allow
    principals: ['workload:vps-17']
    actions: [example.profile.get]
    resources: ['example-api:development']
";

async fn upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let body = r#"{"user":"demo","authenticated":true}"#;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    port
}

fn registry(entries: &[(&str, &[&Issued])]) -> DeviceRegistry {
    let mut yaml = String::from("schema: acf.devices/v1\ndevices:\n");
    for (device, certificates) in entries {
        let _ = write!(
            yaml,
            "  - device: {device}\n    principal: 'workload:{device}'\n    certificates:\n"
        );
        for certificate in *certificates {
            let _ = writeln!(yaml, "      - {}", thumbprint(&certificate.der));
        }
    }
    parse_yaml(&yaml).unwrap()
}

struct Server {
    base: String,
    ca: Pki,
    identity: Arc<MtlsIdentityProvider>,
    audit: Arc<MemorySink>,
}

/// Starts the gateway on mTLS with `enrolled` registered as device `vps-17`.
async fn start(ca: Pki, enrolled: &Issued) -> Server {
    let origin = format!("http://127.0.0.1:{}", upstream().await);
    let config = load_yaml(&BUNDLE.replace("{ORIGIN}", &origin)).unwrap();
    let secrets = Arc::new(InMemoryProvider::new([
        Namespace::new("development").unwrap()
    ]));
    let reference = SecretRef::parse("secret://development/example-api/read").unwrap();
    secrets
        .put(
            &reference,
            SecretMaterial::from_string("token".to_owned()),
            config.secret(&reference).unwrap().use_binding.clone(),
        )
        .await
        .unwrap();
    let identity = Arc::new(
        MtlsIdentityProvider::new(
            IssuerId::new("gw-mtls").unwrap(),
            registry(&[("vps-17", &[enrolled])]),
        )
        .unwrap(),
    );
    let audit = Arc::new(MemorySink::default());
    let gateway = Gateway::new(
        Authorizer::new(
            config,
            POLICY,
            AuthorizerSettings {
                audience: AudienceId::new("gw").unwrap(),
                clock_skew_secs: 30,
            },
        )
        .unwrap(),
        identity.clone(),
        ProviderRegistry::default().with("development", secrets),
        Arc::new(
            HttpConnector::new(
                NetworkPolicy::development_loopback(),
                Arc::new(SystemResolver),
                HttpLimits::default(),
            )
            .unwrap(),
        ),
        AuditSettings {
            sink: audit.clone(),
            hasher: AuditHasher::random().unwrap(),
            required: true,
            gateway: GatewayInfo {
                id: "gw".to_owned(),
                build: "development".to_owned(),
                deployment_profile: "development".to_owned(),
                config_digest: None,
            },
        },
        StateSettings::new(
            Arc::new(MemoryStateStore::new()),
            OffsetDateTime::now_utc().unix_timestamp() - 3600,
        ),
    )
    .unwrap();

    let server = ca.server(&["localhost"]);
    let tls = server_config(
        server.certificate_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca.ca_pem().as_bytes(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_tls(
        listener,
        tls,
        router(Arc::new(gateway), ServerLimits::default()),
    ));
    Server {
        base: format!("https://localhost:{port}"),
        ca,
        identity,
        audit,
    }
}

fn client(
    server_ca: &str,
    identity: Option<&Issued>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> reqwest::Client {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(server_ca.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_root_certificates(roots);
    let mut config = match identity {
        Some(issued) => builder
            .with_client_auth_cert(
                CertificateDer::pem_slice_iter(issued.certificate_pem.as_bytes())
                    .map(Result::unwrap)
                    .collect(),
                PrivateKeyDer::from_pem_slice(issued.key_pem.as_bytes()).unwrap(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .resolve("localhost", "127.0.0.1:0".parse().unwrap())
        .no_proxy()
        .build()
        .unwrap()
}

fn request_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "requestId": format!("req-{}", OffsetDateTime::now_utc().unix_timestamp_nanos()),
        "timestamp": OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
        "taskId": "tls-task",
        "action": "example.profile.get",
        "resource": "example-api:development",
        "parameters": {},
    }))
    .unwrap()
}

async fn post(
    client: &reqwest::Client,
    base: &str,
    headers: &[(&str, &str)],
) -> Result<(u16, Value), reqwest::Error> {
    let mut request = client
        .post(format!("{base}/v1/actions/execute"))
        .header("content-type", "application/json")
        .body(request_body());
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await?;
    let status = response.status().as_u16();
    Ok((status, response.json_or_null().await))
}

trait JsonOrNull {
    async fn json_or_null(self) -> Value;
}

impl JsonOrNull for reqwest::Response {
    async fn json_or_null(self) -> Value {
        serde_json::from_slice(&self.bytes().await.unwrap_or_default()).unwrap_or(Value::Null)
    }
}

#[tokio::test]
async fn an_enrolled_certificate_is_the_callers_identity() {
    let ca = Pki::new("acf-test-ca");
    let device = ca.client("vps-17");
    let server = start(ca, &device).await;
    let client = client(
        &server.ca.ca_pem(),
        Some(&device),
        &[&rustls::version::TLS13],
    );

    let (status, body) = post(&client, &server.base, &[]).await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["result"]["body"],
        json!({ "user": "demo", "authenticated": true })
    );
    let decision = &server.audit.events()[0];
    assert_eq!(
        decision.principal.as_ref().unwrap().as_str(),
        "workload:vps-17"
    );
    assert_eq!(decision.device.as_ref().unwrap().as_str(), "vps-17");
}

#[tokio::test]
async fn identity_headers_are_ignored() {
    let ca = Pki::new("acf-test-ca");
    let device = ca.client("vps-17");
    let server = start(ca, &device).await;
    let client = client(
        &server.ca.ca_pem(),
        Some(&device),
        &[&rustls::version::TLS13],
    );
    let spoofed = [
        ("x-forwarded-client-cert", "Hash=AAAA;Subject=\"CN=admin\""),
        ("x-client-cert", "-----BEGIN CERTIFICATE-----"),
        ("x-acf-principal", "workload:admin"),
        ("x-ssl-client-s-dn", "CN=admin"),
    ];
    let (status, _) = post(&client, &server.base, &spoofed).await.unwrap();
    assert_eq!(status, 200);
    for event in server.audit.events() {
        assert_eq!(
            event.principal.as_ref().unwrap().as_str(),
            "workload:vps-17"
        );
    }
}

#[tokio::test]
async fn untrusted_expired_wrong_purpose_and_missing_certificates_fail_the_handshake() {
    let ca = Pki::new("acf-test-ca");
    let device = ca.client("vps-17");
    let expired = ca.expired_client("vps-17-old");
    let wrong_purpose = ca.server_purpose_client("vps-17-server");
    let stranger_ca = Pki::new("someone-else");
    let foreign = stranger_ca.client("vps-17");
    let server = start(ca, &device).await;
    let server_ca = server.ca.ca_pem();

    for (name, identity) in [
        ("no certificate", None),
        ("expired", Some(&expired)),
        ("serverAuth only", Some(&wrong_purpose)),
        ("other CA", Some(&foreign)),
    ] {
        let client = client(&server_ca, identity, &[&rustls::version::TLS13]);
        assert!(
            post(&client, &server.base, &[]).await.is_err(),
            "{name} must fail the handshake"
        );
    }
    assert!(
        server.audit.events().is_empty(),
        "no request reached the pipeline"
    );
}

#[tokio::test]
async fn tls_12_is_refused() {
    let ca = Pki::new("acf-test-ca");
    let device = ca.client("vps-17");
    let server = start(ca, &device).await;
    let client = client(
        &server.ca.ca_pem(),
        Some(&device),
        &[&rustls::version::TLS12],
    );
    assert!(post(&client, &server.base, &[]).await.is_err());
}

#[tokio::test]
async fn trusted_but_unenrolled_certificates_are_unauthenticated() {
    let ca = Pki::new("acf-test-ca");
    let device = ca.client("vps-17");
    let unenrolled = ca.client("vps-99");
    let server = start(ca, &device).await;
    let client = client(
        &server.ca.ca_pem(),
        Some(&unenrolled),
        &[&rustls::version::TLS13],
    );
    let (status, body) = post(&client, &server.base, &[]).await.unwrap();
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], "unauthenticated");
}

#[tokio::test]
async fn rotation_swaps_certificates_without_a_restart() {
    let ca = Pki::new("acf-test-ca");
    let old = ca.client("vps-17");
    let new = ca.client("vps-17-next");
    let server = start(ca, &old).await;
    let server_ca = server.ca.ca_pem();

    // Overlap: both enrolled.
    server
        .identity
        .replace(registry(&[("vps-17", &[&old, &new])]))
        .unwrap();
    for issued in [&old, &new] {
        let (status, _) = post(
            &client(&server_ca, Some(issued), &[&rustls::version::TLS13]),
            &server.base,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(status, 200);
    }
    // Old removed.
    server
        .identity
        .replace(registry(&[("vps-17", &[&new])]))
        .unwrap();
    let (status, _) = post(
        &client(&server_ca, Some(&old), &[&rustls::version::TLS13]),
        &server.base,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(status, 401);
    let (status, _) = post(
        &client(&server_ca, Some(&new), &[&rustls::version::TLS13]),
        &server.base,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
}

#[test]
fn server_config_disables_early_data_and_tickets() {
    let ca = Pki::new("acf-test-ca");
    let server = ca.server(&["localhost"]);
    let config = server_config(
        server.certificate_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca.ca_pem().as_bytes(),
    )
    .unwrap();
    assert_eq!(config.max_early_data_size, 0, "no 0-RTT");
    assert_eq!(config.send_tls13_tickets, 0);
    assert_eq!(config.alpn_protocols, [b"http/1.1".to_vec()]);
    assert!(
        server_config(
            server.certificate_pem.as_bytes(),
            server.key_pem.as_bytes(),
            b""
        )
        .is_err(),
        "a client CA is mandatory"
    );
}

#[tokio::test]
async fn the_daemon_forwards_agent_requests_over_mtls() {
    use acf_agent::{build_local_request, daemon, gateway, local};

    let ca = Pki::new("acf-test-ca");
    let device = ca.client("vps-17");
    let server = start(ca, &device).await;
    let tls = gateway::client_config(
        device.certificate_pem.as_bytes(),
        device.key_pem.as_bytes(),
        server.ca.ca_pem().as_bytes(),
    )
    .unwrap();
    let client = gateway::GatewayClient::new(&server.base, tls).unwrap();

    let dir = std::env::temp_dir().join(format!("acf-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = daemon::bind(&dir.join("acf.sock"), daemon::DEFAULT_SOCKET_MODE).unwrap();
    let path = socket.path().to_owned();
    let allowed = std::collections::BTreeSet::from([socket.owner()]);
    tokio::spawn(daemon::serve(socket, allowed, daemon::router(client, None)));

    let task = local::create_task(&path, "daemon-task", None)
        .await
        .unwrap();
    let request = build_local_request(
        "example.profile.get",
        "example-api:development",
        task.task_handle.as_str(),
        &[],
    )
    .unwrap();
    let response = serde_json::to_value(local::execute(&path, &request).await.unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();

    assert_eq!(response["status"], "completed", "{response}");
    assert_eq!(
        response["result"]["body"],
        json!({ "user": "demo", "authenticated": true })
    );
    let decision = &server.audit.events()[0];
    assert_eq!(
        decision.principal.as_ref().unwrap().as_str(),
        "workload:vps-17"
    );
    assert_eq!(decision.task_id.as_str(), "daemon-task");
    assert!(
        decision.request_id.as_str().starts_with("req-"),
        "the daemon chose the request id"
    );
}
