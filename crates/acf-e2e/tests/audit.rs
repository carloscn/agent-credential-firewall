//! WP-12 end to end: a gateway hash-chains its audit log and publishes
//! signed checkpoints over mTLS to the control plane's collector; the log is
//! then verified against what the collector holds (ADR 0005).

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../acf-gateway/tests/support/pki.rs"]
mod pki;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use acf_audit::{
    AUDIT_KEYS_SCHEMA, AnchorState, AuditHasher, AuditKeyEntry, AuditKeys, AuditKeysDocument,
    ChainHead, ChainedJsonSink, CheckpointFinding, CheckpointPublisher, CheckpointSigner,
    GatewayInfo, PublishError, check_checkpoints, genesis, line_hash, run_checkpoints, verify_log,
};
use acf_config::{load_yaml, parse_yaml};
use acf_connectors::{HttpConnector, HttpLimits, NetworkPolicy, SystemResolver};
use acf_control_plane::{CheckpointStore, checkpoint_router, read_stored};
use acf_gateway::{
    AuditSettings, Gateway, HttpCheckpointPublisher, ProviderRegistry, ServerLimits, StateSettings,
    serve_tls, server_config,
};
use acf_identity::{
    DeviceRegistry, MtlsIdentityProvider, client_config, generate_pem, parse_key_pair, public_key,
    thumbprint,
};
use acf_policy::{Authorizer, AuthorizerSettings};
use acf_protocol::{AudienceId, IssuerId, KeyId, PrincipalId};
use acf_secrets::{InMemoryProvider, Namespace, SecretAdmin, SecretMaterial, SecretRef};
use acf_state::MemoryStateStore;
use pki::{Issued, Pki};
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

const POLICY: &str = r"
schema: acf.policy/v1
version: audit.1
rules:
  - id: vps-17
    effect: allow
    principals: ['workload:vps-17']
    actions: [example.profile.get]
    resources: ['example-api:development']
";

static NEXT: AtomicU32 = AtomicU32::new(0);

async fn upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let body = r#"{"user":"demo"}"#;
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

fn registry(entries: &[(&str, &str, &Issued)]) -> DeviceRegistry {
    let mut yaml = String::from("schema: acf.devices/v1\ndevices:\n");
    for (device, principal, issued) in entries {
        let _ = writeln!(
            yaml,
            "  - device: {device}\n    principal: '{principal}'\n    certificates: [{}]",
            thumbprint(&issued.der)
        );
    }
    parse_yaml(&yaml).unwrap()
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

/// A development-profile gateway with mTLS identity and `sink` as its audit.
async fn gateway(devices: DeviceRegistry, sink: Arc<ChainedJsonSink>) -> Gateway {
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
    Gateway::new(
        Authorizer::new(
            config,
            POLICY,
            AuthorizerSettings {
                audience: AudienceId::new("gw").unwrap(),
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
            sink,
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
    .unwrap()
}

struct World {
    dir: PathBuf,
    ca: Pki,
    vps17: Issued,
    gw1: Issued,
    gateway: String,
    collector: String,
    audit_pem: String,
    keys: AuditKeys,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl World {
    /// A collector, and a gateway that checkpoints to `collector_url` (the
    /// real collector unless overridden) every 50 ms.
    async fn new(collector_override: Option<&str>, max_lag: Duration) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "acf-audit-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = Pki::new("acf-audit-ca");
        let server = ca.server(&["localhost"]);
        let vps17 = ca.client("vps-17");
        let gw1 = ca.client("gw-1");
        let devices = registry(&[
            ("vps-17", "workload:vps-17", &vps17),
            ("gw-1", "gateway:gw-1", &gw1),
        ]);

        // Collector.
        let audit_pem = generate_pem().unwrap();
        let keys = AuditKeys::new(AuditKeysDocument {
            schema: AUDIT_KEYS_SCHEMA.to_owned(),
            keys: vec![AuditKeyEntry {
                kid: KeyId::new("gw-audit").unwrap(),
                gateway: "gw".to_owned(),
                principal: PrincipalId::new("gateway:gw-1").unwrap(),
                public_key: public_key(&parse_key_pair(&audit_pem).unwrap()),
            }],
        })
        .unwrap();
        let store =
            Arc::new(CheckpointStore::open(&dir.join("checkpoints"), keys.clone()).unwrap());
        let collector_identity = Arc::new(
            MtlsIdentityProvider::new(IssuerId::new("cp-mtls").unwrap(), devices.clone()).unwrap(),
        );
        let collector = listen(checkpoint_router(store, collector_identity), &ca, &server).await;

        // Gateway with a chained, anchored audit log.
        let anchor = Arc::new(AnchorState::new(max_lag));
        let sink = Arc::new(
            ChainedJsonSink::open(&dir.join("audit.jsonl"))
                .unwrap()
                .with_anchor(anchor.clone()),
        );
        let url = format!(
            "{}/v1/audit/checkpoints",
            collector_override.unwrap_or(&collector)
        );
        let publisher = Arc::new(
            HttpCheckpointPublisher::new(
                &url,
                client_config(
                    gw1.certificate_pem.as_bytes(),
                    gw1.key_pem.as_bytes(),
                    ca.ca_pem().as_bytes(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let signer = CheckpointSigner::new(
            KeyId::new("gw-audit").unwrap(),
            "gw".to_owned(),
            parse_key_pair(&audit_pem).unwrap(),
        );
        tokio::spawn(run_checkpoints(
            sink.clone(),
            signer,
            publisher,
            anchor,
            Duration::from_millis(50),
            |_| {},
        ));

        let gateway = gateway(devices, sink).await;
        let gateway = listen(
            acf_gateway::router(Arc::new(gateway), ServerLimits::default()),
            &ca,
            &server,
        )
        .await;
        Self {
            dir,
            ca,
            vps17,
            gw1,
            gateway,
            collector,
            audit_pem,
            keys,
        }
    }

    fn client(&self, device: &Issued) -> reqwest::Client {
        reqwest::Client::builder()
            .use_preconfigured_tls(
                client_config(
                    device.certificate_pem.as_bytes(),
                    device.key_pem.as_bytes(),
                    self.ca.ca_pem().as_bytes(),
                )
                .unwrap(),
            )
            .no_proxy()
            .build()
            .unwrap()
    }

    async fn execute(&self, action: &str) -> (u16, Value) {
        let body = json!({
            "requestId": format!("req-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
            "timestamp": OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            "taskId": "audit-task",
            "action": action,
            "resource": "example-api:development",
            "parameters": {},
        });
        let response = self
            .client(&self.vps17)
            .post(format!("{}/v1/actions/execute", self.gateway))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (
            status,
            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap_or(Value::Null),
        )
    }

    fn log_bytes(&self) -> Vec<u8> {
        std::fs::read(self.dir.join("audit.jsonl")).unwrap()
    }

    fn checkpoints(&self, log: &str) -> Vec<acf_audit::CheckpointStatement> {
        read_stored(&self.dir.join("checkpoints"), log)
            .unwrap()
            .iter()
            .map(|envelope| self.keys.verify(envelope).unwrap().0)
            .collect()
    }

    /// Waits until a checkpoint covers the log's current head.
    async fn anchored(&self) -> u64 {
        for _ in 0..100 {
            let log = verify_log(&self.log_bytes()).unwrap();
            let head = log.head().seq;
            if self.checkpoints(&log.log).iter().any(|c| c.seq == head) {
                return head;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no checkpoint covered the head");
    }
}

fn lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Rewrites a log from `events` with a freshly computed, internally valid
/// chain: what an attacker with host control can always do.
fn forge(events: &[Value]) -> Vec<u8> {
    let log = events[0]["chain"]["log"].as_str().unwrap().to_owned();
    let mut prev = genesis(&log);
    let mut out = Vec::new();
    for (seq, event) in events.iter().enumerate() {
        let mut event = event.clone();
        event["chain"] = json!({ "log": log, "seq": seq, "prev": prev });
        let line = serde_json::to_vec(&event).unwrap();
        prev = line_hash(&line);
        out.extend_from_slice(&line);
        out.push(b'\n');
    }
    out
}

#[tokio::test]
async fn checkpoints_expose_truncation_and_rewritten_history() {
    let world = World::new(None, Duration::from_secs(60)).await;
    for _ in 0..3 {
        assert_eq!(world.execute("example.profile.get").await.0, 200);
    }
    let head = world.anchored().await;
    assert_eq!(head, 5, "a decision and an outcome per request");

    let original = world.log_bytes();
    let log = verify_log(&original).unwrap();
    let checkpoints = world.checkpoints(&log.log);
    assert!(check_checkpoints(&log, &checkpoints).is_empty());

    // Dropping the newest two events leaves a valid chain; only the
    // checkpoint shows the cut.
    let all = lines(&original);
    let cut = format!("{}\n", all[..4].join("\n"));
    let cut_log = verify_log(cut.as_bytes()).unwrap();
    assert_eq!(
        check_checkpoints(&cut_log, &checkpoints),
        [CheckpointFinding::Truncated { seq: 5, events: 4 }]
    );

    // Turning an allow into a deny and recomputing every link also leaves a
    // valid chain; only the checkpoint shows the replacement.
    let mut events: Vec<Value> = all
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    events[0]["verdict"] = json!("denied");
    let forged = forge(&events);
    let forged_log = verify_log(&forged).unwrap();
    assert!(
        check_checkpoints(&forged_log, &checkpoints)
            .iter()
            .any(|f| matches!(f, CheckpointFinding::Replaced { .. }))
    );
}

#[tokio::test]
async fn the_collector_refuses_rewritten_history_and_other_callers() {
    let world = World::new(None, Duration::from_secs(60)).await;
    world.execute("example.profile.get").await;
    let head = world.anchored().await;
    let log = verify_log(&world.log_bytes()).unwrap();

    let signer = CheckpointSigner::new(
        KeyId::new("gw-audit").unwrap(),
        "gw".to_owned(),
        parse_key_pair(&world.audit_pem).unwrap(),
    );
    let rewritten = signer.sign(
        &ChainHead {
            log: log.log.clone(),
            seq: head,
            hash: format!("sha256:{}", "0".repeat(64)),
        },
        OffsetDateTime::now_utc(),
    );
    let publisher = |device: &Issued| {
        HttpCheckpointPublisher::new(
            &format!("{}/v1/audit/checkpoints", world.collector),
            client_config(
                device.certificate_pem.as_bytes(),
                device.key_pem.as_bytes(),
                world.ca.ca_pem().as_bytes(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    // Even with the gateway's own key and certificate, a different head for
    // an already anchored position is refused.
    assert_eq!(
        publisher(&world.gw1).publish(&rewritten).await,
        Err(PublishError::Conflict)
    );
    // vps-17 is enrolled but is not the key's principal.
    assert_eq!(
        publisher(&world.vps17).publish(&rewritten).await,
        Err(PublishError::Unavailable("HTTP 403".to_owned()))
    );
    // An unenrolled certificate is not authenticated at all.
    assert_eq!(
        publisher(&world.ca.client("gw-9"))
            .publish(&rewritten)
            .await,
        Err(PublishError::Unavailable("HTTP 401".to_owned()))
    );
    // Only the genuine checkpoint is stored.
    assert!(
        world
            .checkpoints(&log.log)
            .iter()
            .all(|c| log.hash_at(c.seq) == Some(c.head.as_str()))
    );
}

#[tokio::test]
async fn a_stale_anchor_fails_allowed_requests_closed() {
    // Nothing listens on port 9: no checkpoint is ever accepted.
    let world = World::new(Some("https://localhost:9"), Duration::from_millis(300)).await;
    assert_eq!(world.execute("example.profile.get").await.0, 200);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (status, body) = world.execute("example.profile.get").await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["reason"], "audit_unavailable");
    // Denials are still answered, even though their events cannot be written.
    let (status, body) = world.execute("example.profile.delete").await;
    assert_eq!((status, body["status"].as_str()), (403, Some("denied")));
}
