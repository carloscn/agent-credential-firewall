//! WP-09 end to end: daemon → Capability Authority → daemon → gateway, all
//! over mTLS, with capabilities signed by the real authority (ADR 0003).

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../acf-gateway/tests/support/pki.rs"]
mod pki;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use acf_agent::gateway::{AuthorityClient, GatewayClient, client_config};
use acf_agent::{AgentError, build_local_request, daemon, local};
use acf_audit::{AuditEvent, AuditHasher, EventKind, GatewayInfo, MemorySink, Verdict};
use acf_config::{ValidatedConfig, load_yaml, parse_yaml};
use acf_connectors::{HttpConnector, HttpLimits, NetworkPolicy, SystemResolver};
use acf_control_plane::{
    Authority, AuthorityConfig, AuthorityPolicy, CapabilitySigner, JobFile, generate_pem,
    parse_key_pair, public_key, sign_detached,
};
use acf_gateway::{
    AuditSettings, Gateway, ProviderRegistry, ServerLimits, StateSettings, serve_tls, server_config,
};
use acf_identity::{
    AUTHORITY_KEYS_SCHEMA, AuthorityKey, AuthorityKeys, CapabilityVerifier, DeviceRegistry,
    MtlsIdentityProvider, thumbprint,
};
use acf_policy::{Authorizer, AuthorizerSettings};
use acf_protocol::{
    AudienceId, BasisRequest, CAPABILITY_HEADER, CapabilityId, CreateTaskRequest, IssuerId, JobId,
    KeyId, LocalErrorCode, TaskId, TaskIssued,
};
use acf_secrets::{InMemoryProvider, Namespace, SecretAdmin, SecretMaterial, SecretRef};
use acf_state::{MemoryStateStore, Revocation, RevocationTarget, StateStore};
use pki::{Issued, Pki};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PROFILE: &str = "example.profile.get";
const CREATE: &str = "example.records.create";
const DELETE: &str = "example.records.delete";
const RESOURCE: &str = "example-api:development";

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
      example.records.create:
        method: POST
        path: /records
        credential_slot: read
        classification: read
        params:
          name: { location: body, type: string, required: true }
        response: { fields: [user] }
      example.records.delete:
        method: DELETE
        path: /records
        credential_slot: read
        classification: mutate
        response: { fields: [user] }
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

/// Gateway policy allows both devices everything; the capability is what
/// narrows them.
const POLICY: &str = r"
schema: acf.policy/v1
version: e2e.1
rules:
  - id: devices
    effect: allow
    principals: ['workload:vps-17', 'workload:vps-18']
    actions: [example.profile.get, example.records.create, example.records.delete]
    resources: ['example-api:development']
";

const JOB: &str = r#"schema: acf.job/v1
id: profile-check
principals: ["workload:vps-17", "workload:vps-18"]
ttl_secs: 600
limits: { maxRequests: 3 }
grants:
  - { action: example.profile.get, resource: "example-api:development" }
  - { action: example.records.create, resource: "example-api:development" }
  - { action: example.records.delete, resource: "example-api:development" }
"#;

fn authority_config(admin: &str) -> AuthorityConfig {
    parse_yaml(&format!(
        r#"
schema: acf.authority/v1
issuer: acf-authority-e2e
audience: acf-gateway-e2e
default_ttl_secs: 300
max_ttl_secs: 900
entitlements:
  - principal: "workload:vps-17"
    grants: [{{ action: {PROFILE}, resource: "{RESOURCE}" }}]
  - principal: "workload:vps-18"
    grants:
      - {{ action: {PROFILE}, resource: "{RESOURCE}" }}
      - {{ action: {DELETE}, resource: "{RESOURCE}" }}
job_signers:
  - {{ kid: admin-1, public_key: {admin} }}
"#
    ))
    .unwrap()
}

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

fn registry(devices: &[(&str, &Issued)]) -> DeviceRegistry {
    let mut yaml = String::from("schema: acf.devices/v1\ndevices:\n");
    for (device, issued) in devices {
        let _ = writeln!(
            yaml,
            "  - device: {device}\n    principal: 'workload:{device}'\n    certificates: [{}]",
            thumbprint(&issued.der)
        );
    }
    parse_yaml(&yaml).unwrap()
}

struct World {
    ca: Pki,
    vps17: Issued,
    vps18: Issued,
    gateway: String,
    authority: String,
    signer_pem: String,
    audit: Arc<MemorySink>,
    store: Arc<MemoryStateStore>,
}

async fn listen(router: axum::Router, ca: &Pki, server: &Issued) -> String {
    let tls = server_config(
        server.certificate_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca.ca_pem().as_bytes(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_tls(listener, tls, router));
    format!("https://localhost:{port}")
}

/// A gateway that requires capabilities signed by `trust`.
async fn gateway(
    config: ValidatedConfig,
    devices: DeviceRegistry,
    trust: AuthorityKey,
    audit: Arc<MemorySink>,
    store: Arc<MemoryStateStore>,
) -> Gateway {
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
    Gateway::new(
        Authorizer::new(
            config,
            POLICY,
            AuthorizerSettings {
                audience: AudienceId::new("acf-gateway-e2e").unwrap(),
                clock_skew_secs: 30,
            },
        )
        .unwrap(),
        Arc::new(MtlsIdentityProvider::new(IssuerId::new("gw-mtls").unwrap(), devices).unwrap()),
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
            sink: audit,
            hasher: AuditHasher::random().unwrap(),
            required: true,
            gateway: GatewayInfo {
                id: "gw".to_owned(),
                build: "development".to_owned(),
                deployment_profile: "development".to_owned(),
                config_digest: None,
            },
        },
        StateSettings::new(store, OffsetDateTime::now_utc().unix_timestamp() - 3600),
    )
    .unwrap()
    .require_capabilities(
        CapabilityVerifier::new(AuthorityKeys {
            schema: AUTHORITY_KEYS_SCHEMA.to_owned(),
            keys: vec![trust],
        })
        .unwrap(),
    )
}

impl World {
    async fn new() -> Self {
        let ca = Pki::new("acf-e2e-ca");
        let server = ca.server(&["localhost"]);
        let vps17 = ca.client("vps-17");
        let vps18 = ca.client("vps-18");
        let devices = registry(&[("vps-17", &vps17), ("vps-18", &vps18)]);

        // Authority.
        let admin = parse_key_pair(&generate_pem().unwrap()).unwrap();
        let signature = sign_detached(KeyId::new("admin-1").unwrap(), &admin, JOB.as_bytes());
        let job = JobFile {
            name: "profile-check.yaml".to_owned(),
            bytes: JOB.as_bytes().to_vec(),
            signature: serde_json::to_vec(&signature).unwrap(),
        };
        let origin = format!("http://127.0.0.1:{}", upstream().await);
        let config = load_yaml(&BUNDLE.replace("{ORIGIN}", &origin)).unwrap();
        let policy =
            AuthorityPolicy::new(authority_config(&public_key(&admin)), &config, &[job]).unwrap();
        let signer_pem = generate_pem().unwrap();
        let signer = signer(&signer_pem);
        let trust = signer.trust_entry();
        let authority = Authority::new(policy, config.clone(), signer).unwrap();
        let authority_identity = Arc::new(
            MtlsIdentityProvider::new(IssuerId::new("authority-mtls").unwrap(), devices.clone())
                .unwrap(),
        );
        let authority_url = listen(
            acf_control_plane::router(authority, authority_identity),
            &ca,
            &server,
        )
        .await;

        let audit = Arc::new(MemorySink::default());
        let store = Arc::new(MemoryStateStore::new());
        let gateway = gateway(config, devices, trust, audit.clone(), store.clone()).await;
        let gateway_url = listen(
            acf_gateway::router(Arc::new(gateway), ServerLimits::default()),
            &ca,
            &server,
        )
        .await;

        Self {
            ca,
            vps17,
            vps18,
            gateway: gateway_url,
            authority: authority_url,
            signer_pem,
            audit,
            store,
        }
    }

    fn tls(&self, device: &Issued) -> rustls::ClientConfig {
        client_config(
            device.certificate_pem.as_bytes(),
            device.key_pem.as_bytes(),
            self.ca.ca_pem().as_bytes(),
        )
        .unwrap()
    }

    /// Starts a daemon for `device`; with `authority`, tasks need capabilities.
    fn daemon(&self, device: &Issued, authority: bool) -> TempSocket {
        let socket = TempSocket::new();
        let bound = daemon::bind(&socket.path(), daemon::DEFAULT_SOCKET_MODE).unwrap();
        let allowed = BTreeSet::from([bound.owner()]);
        let gateway = GatewayClient::new(&self.gateway, self.tls(device)).unwrap();
        let authority =
            authority.then(|| AuthorityClient::new(&self.authority, self.tls(device)).unwrap());
        tokio::spawn(daemon::serve(
            bound,
            allowed,
            daemon::router(gateway, authority),
        ));
        socket
    }

    /// Asks the authority directly, as `device`'s daemon would.
    async fn issue(&self, device: &Issued, grants: Value) -> TaskIssued {
        let client = mtls(self.tls(device));
        let response = client
            .post(format!("{}/v1/tasks", self.authority))
            .header("content-type", "application/json")
            .body(
                json!({
                    "taskId": "direct-task",
                    "basis": { "type": "job", "job": "profile-check" },
                    "grants": grants,
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 201);
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
    }

    /// Calls the gateway directly over `device`'s mTLS with `capabilities`
    /// in the header.
    async fn execute(
        &self,
        device: &Issued,
        task: &str,
        action: &str,
        capabilities: &[&str],
    ) -> (u16, Value) {
        let mut request = mtls(self.tls(device))
            .post(format!("{}/v1/actions/execute", self.gateway))
            .header("content-type", "application/json")
            .body(
                json!({
                    "requestId": format!("req-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
                    "timestamp": OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
                    "taskId": task,
                    "action": action,
                    "resource": RESOURCE,
                    "parameters": if action == CREATE { json!({ "name": "n" }) } else { json!({}) },
                })
                .to_string(),
            );
        for capability in capabilities {
            request = request.header(CAPABILITY_HEADER, *capability);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let body = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap_or(Value::Null);
        (status, body)
    }

    fn decisions(&self) -> Vec<AuditEvent> {
        self.audit
            .events()
            .into_iter()
            .filter(|e| e.kind == EventKind::Decision)
            .collect()
    }

    fn last_denial(&self) -> String {
        self.decisions()
            .into_iter()
            .rev()
            .find(|e| e.verdict == Verdict::Denied)
            .and_then(|e| e.reason)
            .unwrap()
    }
}

fn signer(pem: &str) -> CapabilitySigner {
    CapabilitySigner::new(
        IssuerId::new("acf-authority-e2e").unwrap(),
        KeyId::new("authority-1").unwrap(),
        parse_key_pair(pem).unwrap(),
    )
}

fn mtls(tls: rustls::ClientConfig) -> reqwest::Client {
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .no_proxy()
        .build()
        .unwrap()
}

static NEXT: AtomicU32 = AtomicU32::new(0);

struct TempSocket(PathBuf);

impl TempSocket {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "acf-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> PathBuf {
        self.0.join("acf.sock")
    }
}

impl Drop for TempSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn job_task(task: &str, grants: Value) -> CreateTaskRequest {
    CreateTaskRequest {
        task_id: TaskId::new(task).unwrap(),
        pid: None,
        basis: Some(BasisRequest::Job {
            job: JobId::new("profile-check").unwrap(),
        }),
        grants: serde_json::from_value(grants).unwrap(),
        ttl_secs: None,
    }
}

#[tokio::test]
async fn a_daemon_task_runs_on_a_reusable_authority_capability() {
    let world = World::new().await;
    let socket = world.daemon(&world.vps17, true);
    let task = local::propose_task(&socket.path(), &job_task("e2e-task", json!([])))
        .await
        .unwrap();
    // The job also allows create; vps-17 is entitled only to the profile read.
    assert_eq!(task.grants.len(), 1);
    assert_eq!(task.grants[0].action.as_str(), PROFILE);
    assert_eq!(task.limits.unwrap().max_requests, Some(3));
    let status_json = serde_json::to_string(&task).unwrap();
    assert!(
        !status_json.contains("eyJ"),
        "the agent never sees the capability"
    );

    let request = build_local_request(PROFILE, RESOURCE, task.task_handle.as_str(), &[]).unwrap();
    for _ in 0..2 {
        let response =
            serde_json::to_value(local::execute(&socket.path(), &request).await.unwrap()).unwrap();
        assert_eq!(response["status"], "completed", "{response}");
    }
    let decisions = world.decisions();
    assert_eq!(decisions.len(), 2);
    assert_eq!(
        decisions[0].capability, decisions[1].capability,
        "one capability, two requests"
    );
    assert!(decisions[0].capability.is_some());
    assert_eq!(
        decisions[0].principal.as_ref().unwrap().as_str(),
        "workload:vps-17"
    );
}

#[tokio::test]
async fn agent_scope_is_only_a_proposal() {
    let world = World::new().await;
    let socket = world.daemon(&world.vps17, true);
    // Proposing only what is not entitled leaves nothing: refused.
    let denied = local::propose_task(
        &socket.path(),
        &job_task(
            "greedy",
            json!([{ "action": CREATE, "resource": RESOURCE }]),
        ),
    )
    .await;
    assert!(matches!(
        denied,
        Err(AgentError::Daemon(LocalErrorCode::TaskDenied))
    ));

    // Proposing both yields only the entitled read; create is then denied by
    // the gateway even though its policy allows it.
    let task = local::propose_task(
        &socket.path(),
        &job_task(
            "mixed",
            json!([
                { "action": PROFILE, "resource": RESOURCE },
                { "action": CREATE, "resource": RESOURCE },
            ]),
        ),
    )
    .await
    .unwrap();
    assert_eq!(task.grants.len(), 1);
    let create = build_local_request(
        CREATE,
        RESOURCE,
        task.task_handle.as_str(),
        &["name=n".to_owned()],
    )
    .unwrap();
    let response =
        serde_json::to_value(local::execute(&socket.path(), &create).await.unwrap()).unwrap();
    assert_eq!(response["status"], "denied");
    assert_eq!(world.last_denial(), "capability_not_granted");
}

#[tokio::test]
async fn a_capability_presented_over_another_certificate_is_denied() {
    let world = World::new().await;
    let issued = world.issue(&world.vps17, json!([])).await;
    let (status, _) = world
        .execute(&world.vps17, "direct-task", PROFILE, &[&issued.capability])
        .await;
    assert_eq!(status, 200);
    // vps-18 is enrolled and its policy allows the action, but the
    // capability is bound to vps-17's certificate.
    let (status, body) = world
        .execute(&world.vps18, "direct-task", PROFILE, &[&issued.capability])
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "certificate_mismatch");
}

#[tokio::test]
async fn missing_forged_and_malformed_capabilities_are_refused() {
    let world = World::new().await;
    let issued = world.issue(&world.vps17, json!([])).await;

    let (status, body) = world
        .execute(&world.vps17, "direct-task", PROFILE, &[])
        .await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (403, Some("capability_invalid"))
    );
    assert_eq!(world.last_denial(), "capability_missing");

    // Same kid and claims, signed by a key the gateway does not trust.
    let claims = acf_identity::CapabilityVerifier::new(AuthorityKeys {
        schema: AUTHORITY_KEYS_SCHEMA.to_owned(),
        keys: vec![signer(&world.signer_pem).trust_entry()],
    })
    .unwrap()
    .verify(&issued.capability)
    .unwrap();
    let forged = signer(&generate_pem().unwrap()).sign(&claims).unwrap();
    let (status, _) = world
        .execute(&world.vps17, "direct-task", PROFILE, &[&forged])
        .await;
    assert_eq!(status, 403);
    assert_eq!(world.last_denial(), "capability_bad_signature");

    let (status, _) = world
        .execute(&world.vps17, "direct-task", PROFILE, &["not.a.token"])
        .await;
    assert_eq!(status, 403);
    assert_eq!(world.last_denial(), "capability_malformed");

    let (status, _) = world
        .execute(
            &world.vps17,
            "direct-task",
            PROFILE,
            &[&issued.capability, &issued.capability],
        )
        .await;
    assert_eq!(status, 400, "two capability headers");
}

#[tokio::test]
async fn revocation_and_limits_apply_to_the_capability() {
    let world = World::new().await;
    // maxRequests: 3 from the job definition.
    let limited = world.issue(&world.vps17, json!([])).await;
    for _ in 0..3 {
        let (status, _) = world
            .execute(&world.vps17, "direct-task", PROFILE, &[&limited.capability])
            .await;
        assert_eq!(status, 200);
    }
    let (status, body) = world
        .execute(&world.vps17, "direct-task", PROFILE, &[&limited.capability])
        .await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (403, Some("quota_exceeded"))
    );

    let revoked = world.issue(&world.vps18, json!([])).await;
    let (status, _) = world
        .execute(&world.vps18, "direct-task", PROFILE, &[&revoked.capability])
        .await;
    assert_eq!(status, 200);
    let jti = world
        .decisions()
        .last()
        .unwrap()
        .capability
        .clone()
        .unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    world
        .store
        .revoke(Revocation {
            target: RevocationTarget::Capability(CapabilityId::new(jti.as_str()).unwrap()),
            revoked_at: now,
            expires_at: None,
        })
        .await
        .unwrap();
    let (status, body) = world
        .execute(&world.vps18, "direct-task", PROFILE, &[&revoked.capability])
        .await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (403, Some("capability_revoked"))
    );
}

#[tokio::test]
async fn unscoped_daemons_and_unenrolled_callers_get_nothing() {
    let world = World::new().await;
    // A daemon without an authority can open only unscoped tasks, which a
    // capability-requiring gateway refuses.
    let socket = world.daemon(&world.vps17, false);
    let task = local::create_task(&socket.path(), "unscoped", None)
        .await
        .unwrap();
    let request = build_local_request(PROFILE, RESOURCE, task.task_handle.as_str(), &[]).unwrap();
    let response =
        serde_json::to_value(local::execute(&socket.path(), &request).await.unwrap()).unwrap();
    assert_eq!(response["reason"], "capability_invalid");
    // It also refuses to pretend it can scope a task.
    assert!(matches!(
        local::propose_task(&socket.path(), &job_task("scoped", json!([]))).await,
        Err(AgentError::Daemon(LocalErrorCode::InvalidRequest))
    ));

    // The authority issues nothing to a certificate that is not enrolled.
    let stranger = world.ca.client("vps-99");
    let response = mtls(world.tls(&stranger))
        .post(format!("{}/v1/tasks", world.authority))
        .header("content-type", "application/json")
        .body(
            json!({ "taskId": "t", "basis": { "type": "job", "job": "profile-check" } })
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

/// Sends `messages` to the MCP adapter over the daemon at `socket` and
/// returns the response to each request.
async fn mcp(socket: &Path, messages: &[Value]) -> Vec<Value> {
    let mut input = Vec::new();
    for message in messages {
        input.extend_from_slice(message.to_string().as_bytes());
        input.push(b'\n');
    }
    let mut output = Vec::new();
    acf_agent::mcp::serve(socket.to_owned(), &input[..], &mut output)
        .await
        .unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn tool_call(id: u32, tool: &str, arguments: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": tool, "arguments": arguments } })
}

#[tokio::test]
async fn mcp_tools_read_through_the_gateway_and_relay_mutation_refusals() {
    let world = World::new().await;
    let socket = world.daemon(&world.vps18, true);
    let task = &mcp(
        &socket.path(),
        &[tool_call(
            1,
            "acf_request_task",
            &json!({ "taskId": "mcp-task", "job": "profile-check" }),
        )],
    )
    .await[0]["result"];
    assert_eq!(task["isError"], false, "{task}");
    let granted: Vec<&str> = task["structuredContent"]["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["action"].as_str().unwrap())
        .collect();
    assert_eq!(granted, [PROFILE, DELETE]);
    let handle = task["structuredContent"]["taskHandle"].as_str().unwrap();

    let responses = mcp(
        &socket.path(),
        &[
            tool_call(
                2,
                "acf_execute_action",
                &json!({ "taskHandle": handle, "action": PROFILE, "resource": RESOURCE }),
            ),
            tool_call(
                3,
                "acf_execute_action",
                &json!({ "taskHandle": handle, "action": DELETE, "resource": RESOURCE }),
            ),
            tool_call(4, "acf_get_task_status", &json!({ "taskHandle": handle })),
        ],
    )
    .await;
    let read = &responses[0]["result"];
    assert_eq!(read["isError"], false, "{read}");
    assert_eq!(
        read["structuredContent"]["result"]["body"],
        json!({ "user": "demo", "authenticated": true })
    );
    // Granted by the capability, but v1.0 is read-only: the gateway's
    // refusal comes back unchanged.
    let mutation = &responses[1]["result"];
    assert_eq!(mutation["isError"], true);
    assert_eq!(mutation["structuredContent"]["status"], "denied");
    assert_eq!(mutation["structuredContent"]["reason"], "approval_invalid");
    assert_eq!(world.last_denial(), "approval_unavailable");

    // Nothing the tools returned carries a capability or the credential.
    let everything = format!("{task}{responses:?}");
    assert!(!everything.contains("eyJ"), "no capability token");
    assert!(!everything.contains("token"), "no credential");
    assert!(!everything.contains("secret://"), "no secret reference");
}
