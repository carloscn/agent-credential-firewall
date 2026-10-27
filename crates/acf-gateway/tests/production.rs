//! Production startup validation and configuration admission (WP-11,
//! ADR 0004), run against the real binary in whichever flavor it was built.
//!
//! `cargo test --all-features` builds the development flavor, which must
//! refuse `production`. `cargo test -p acf-gateway --test production` builds
//! the release flavor, which must start a production gateway: admitted
//! configuration, an encrypted local store created with `acf-store`, mTLS,
//! capabilities, and anchored audit.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/pki.rs"]
mod pki;

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use acf_config::{ConfigRole, ConfigSignature, sha256, signing_message};
use acf_protocol::{KeyId, base64url_encode};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};

const BUNDLE: &str = r#"schema: acf.config/v1
deployment: { profile: production, environment: production }
secret_providers:
  production:
    type: encrypted-local
    path: {STORE}
    key_source: mounted-file
    key_location: {KEY}
    rollback_resistance: none
resources:
  "example-api:production":
    connector: example-api
    environment: production
    credentials:
      read: secret://production/example-api/read
secrets:
  "secret://production/example-api/read":
    use_binding: { connectors: [example-api], origins: ["https://api.example-corp.net"], auth_slot: read, environment: production }
"#;

const PROFILE: &str = r"schema: acf.profile/v1
connector: example-api
revision: 1
base_url: https://api.example-corp.net
authentication: { strategy: bearer }
actions:
  example.profile.get:
    method: GET
    path: /profile
    credential_slot: read
    classification: read
    response: { fields: [user] }
";

const POLICY: &str = r"schema: acf.policy/v1
version: prod.1
rules:
  - id: vps-17
    effect: allow
    principals: ['workload:vps-17']
    actions: [example.profile.get]
    resources: ['example-api:production']
";

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Admin {
    profiles: Ed25519KeyPair,
    secrets: Ed25519KeyPair,
}

impl Admin {
    fn new() -> Self {
        let pair = || {
            let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
        };
        Self {
            profiles: pair(),
            secrets: pair(),
        }
    }

    fn key(&self, role: ConfigRole) -> (&str, &Ed25519KeyPair) {
        match role {
            ConfigRole::ProfileAuthor => ("profiles-1", &self.profiles),
            ConfigRole::SecretAdmin | ConfigRole::PolicyAdmin => ("secrets-1", &self.secrets),
        }
    }

    fn trust(&self, pins: &str) -> String {
        format!(
            "schema: acf.config-trust/v1\nsigners:\n  - {{ kid: profiles-1, public_key: {}, roles: [profile-author] }}\n  - {{ kid: secrets-1, public_key: {}, roles: [secret-admin, policy-admin] }}\npins: [{pins}]\n",
            base64url_encode(self.profiles.public_key().as_ref()),
            base64url_encode(self.secrets.public_key().as_ref()),
        )
    }
}

/// A configuration directory with signed documents and a trust anchor.
struct Setup {
    dir: PathBuf,
    admin: Admin,
}

impl Setup {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "acf-production-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("profiles")).unwrap();
        let setup = Self {
            dir,
            admin: Admin::new(),
        };
        setup.write_material();
        setup.write(
            "bundle.yaml",
            &setup.bundle(),
            Some(ConfigRole::SecretAdmin),
        );
        setup.write(
            "profiles/example-api.yaml",
            PROFILE,
            Some(ConfigRole::ProfileAuthor),
        );
        setup.write("policy.yaml", POLICY, Some(ConfigRole::PolicyAdmin));
        setup.write_trust("", 0o644);
        setup
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The production bundle, pointing at this setup's store and key.
    fn bundle(&self) -> String {
        BUNDLE
            .replace("{STORE}", self.path("store").to_str().unwrap())
            .replace("{KEY}", self.path("store.key").to_str().unwrap())
    }

    fn write_private(&self, name: &str, bytes: &[u8], mode: u32) {
        let path = self.path(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// TLS material, enrolled devices, authority keys, the audit key, and
    /// the store's root key: everything a production gateway reads.
    fn write_material(&self) {
        let ca = pki::Pki::new("acf-production-test-ca");
        let server = ca.server(&["localhost"]);
        let device = ca.client("vps-17");
        let gateway_client = ca.client("gw-1");
        std::fs::write(self.path("ca.pem"), ca.ca_pem()).unwrap();
        std::fs::write(self.path("gateway.pem"), &server.certificate_pem).unwrap();
        self.write_private("gateway.key", server.key_pem.as_bytes(), 0o600);
        std::fs::write(self.path("client.pem"), &gateway_client.certificate_pem).unwrap();
        self.write_private("client.key", gateway_client.key_pem.as_bytes(), 0o600);
        std::fs::write(
            self.path("devices.yaml"),
            format!(
                "schema: acf.devices/v1\ndevices:\n  - {{ device: vps-17, principal: 'workload:vps-17', certificates: [{}] }}\n",
                acf_identity::thumbprint(&device.der)
            ),
        )
        .unwrap();
        std::fs::write(
            self.path("authority-keys.yaml"),
            format!(
                "schema: acf.authority-keys/v1\nkeys:\n  - {{ kid: authority-1, issuer: acf-authority, alg: EdDSA, public_key: {} }}\n",
                base64url_encode(self.admin.secrets.public_key().as_ref())
            ),
        )
        .unwrap();
        self.write_private(
            "audit.key",
            acf_identity::generate_pem().unwrap().as_bytes(),
            0o600,
        );
        let mut root_key = [0u8; 32];
        SystemRandom::new().fill(&mut root_key).unwrap();
        self.write_private("store.key", &root_key, 0o400);
    }

    /// Creates the store with `acf-store` and loads the read credential.
    fn create_store(&self) {
        let path = |name: &str| self.path(name).to_str().unwrap().to_owned();
        let store = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_acf-store"))
                .args([
                    "--config",
                    &path("bundle.yaml"),
                    "--profiles",
                    &path("profiles"),
                ])
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        let init = store(&["init", "--namespace", "production"])
            .wait_with_output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let mut put = store(&["put", "secret://production/example-api/read"]);
        put.stdin
            .take()
            .unwrap()
            .write_all(b"production-token\n")
            .unwrap();
        let put = put.wait_with_output().unwrap();
        assert!(
            put.status.success(),
            "{}",
            String::from_utf8_lossy(&put.stderr)
        );
    }

    /// Writes `name`, signed for `role` with that role's key if given.
    fn write(&self, name: &str, contents: &str, role: Option<ConfigRole>) {
        std::fs::write(self.path(name), contents).unwrap();
        let signature = self.path(&format!("{name}.sig"));
        let _ = std::fs::remove_file(&signature);
        if let Some(role) = role {
            self.sign(name, contents, role, role);
        }
    }

    /// Signs `contents` as `signed_as` with the key that `key_of` uses.
    fn sign(&self, name: &str, contents: &str, signed_as: ConfigRole, key_of: ConfigRole) {
        let (kid, pair) = self.admin.key(key_of);
        let signature = ConfigSignature {
            kid: KeyId::new(kid).unwrap(),
            signature: base64url_encode(
                pair.sign(&signing_message(signed_as, contents.as_bytes()))
                    .as_ref(),
            ),
        };
        std::fs::write(
            self.path(&format!("{name}.sig")),
            serde_json::to_vec(&signature).unwrap(),
        )
        .unwrap();
    }

    fn write_trust(&self, pins: &str, mode: u32) {
        let path = self.path("trust.yaml");
        std::fs::write(&path, self.admin.trust(pins)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Runs the gateway with every production flag; `drop` removes flags.
    /// Returns whether it started listening (it is then stopped) and its
    /// standard error.
    fn run(&self, drop: &[&str]) -> (bool, String) {
        let dir = |name: &str| self.path(name).to_str().unwrap().to_owned();
        let flags: Vec<(&str, String)> = vec![
            ("--config", dir("bundle.yaml")),
            ("--profiles", dir("profiles")),
            ("--policy", dir("policy.yaml")),
            ("--config-trust", dir("trust.yaml")),
            ("--listen", "127.0.0.1:0".to_owned()),
            ("--tls-cert", dir("gateway.pem")),
            ("--tls-key", dir("gateway.key")),
            ("--client-ca", dir("ca.pem")),
            ("--devices", dir("devices.yaml")),
            ("--authority-keys", dir("authority-keys.yaml")),
            ("--audit-log", dir("audit.jsonl")),
            ("--audit-key", dir("audit.key")),
            ("--audit-kid", "gw-audit-1".to_owned()),
            (
                "--checkpoint-url",
                "https://localhost:9/v1/audit/checkpoints".to_owned(),
            ),
            ("--checkpoint-client-cert", dir("client.pem")),
            ("--checkpoint-client-key", dir("client.key")),
            ("--checkpoint-ca", dir("ca.pem")),
            ("--state-db", dir("state.sqlite")),
        ];
        let mut command = Command::new(env!("CARGO_BIN_EXE_acf-gateway"));
        for (flag, value) in flags {
            if !drop.contains(&flag) {
                command.args([flag, &value]);
            }
        }
        let mut child = command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (lines, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if lines.send(line).is_err() {
                    break;
                }
            }
        });
        let mut text = String::new();
        let mut started = false;
        while let Ok(line) = received.recv_timeout(Duration::from_secs(20)) {
            text.push_str(&line);
            text.push('\n');
            if line.contains("listening on") {
                started = true;
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        while let Ok(line) = received.try_recv() {
            text.push_str(&line);
            text.push('\n');
        }
        (started, text)
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn refusals(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .collect()
}

#[test]
fn an_admitted_production_configuration_starts() {
    let setup = Setup::new();
    setup.create_store();
    let (started, stderr) = setup.run(&[]);
    if cfg!(feature = "development") {
        assert!(!started);
        assert!(
            stderr.contains("refusing to start under the production profile"),
            "{stderr}"
        );
        assert_eq!(
            refusals(&stderr),
            ["this binary was built with the `development` feature"],
            "{stderr}"
        );
    } else {
        assert!(started, "{stderr}");
        assert!(
            stderr.contains("release build, production profile, config sha256:"),
            "{stderr}"
        );
        assert!(
            stderr.contains("encrypted-local at")
                && stderr.contains("integrity only, no rollback resistance"),
            "{stderr}"
        );
        assert!(!stderr.contains("production-token"), "{stderr}");
    }
}

#[test]
fn unimplemented_store_guarantees_are_refused_not_ignored() {
    // A configured rollback anchor would claim a protection the store does
    // not provide.
    let setup = Setup::new();
    setup.create_store();
    let anchored = setup
        .bundle()
        .replace("rollback_resistance: none", "rollback_anchor: tpm-nv");
    setup.write("bundle.yaml", &anchored, Some(ConfigRole::SecretAdmin));
    let (started, stderr) = setup.run(&[]);
    assert!(!started);
    if cfg!(not(feature = "development")) {
        assert!(
            stderr.contains("rollback anchors are not implemented"),
            "{stderr}"
        );
    }

    // A readable root key fails the mounted-file check.
    let setup = Setup::new();
    setup.create_store();
    std::fs::set_permissions(
        setup.path("store.key"),
        std::fs::Permissions::from_mode(0o440),
    )
    .unwrap();
    let (started, stderr) = setup.run(&[]);
    assert!(!started);
    if cfg!(not(feature = "development")) {
        assert!(
            stderr.contains("must not be accessible by group or others"),
            "{stderr}"
        );
    }

    // No store yet: the gateway does not create one.
    let setup = Setup::new();
    let (started, stderr) = setup.run(&[]);
    assert!(!started);
    if cfg!(not(feature = "development")) {
        assert!(
            stderr.contains("create it with `acf-store init`"),
            "{stderr}"
        );
    }
}

#[test]
fn production_refuses_every_missing_control_at_once() {
    let setup = Setup::new();
    let (ok, stderr) = setup.run(&[
        "--config-trust",
        "--tls-cert",
        "--tls-key",
        "--client-ca",
        "--devices",
        "--authority-keys",
        "--audit-log",
        "--audit-key",
        "--audit-kid",
        "--checkpoint-url",
        "--checkpoint-client-cert",
        "--checkpoint-client-key",
        "--checkpoint-ca",
    ]);
    assert!(!ok);
    let found = refusals(&stderr);
    for needle in [
        "configuration must be admitted",
        "plaintext listener",
        "--authority-keys",
        "--audit-log",
        "anchored externally",
    ] {
        assert!(
            found.iter().any(|r| r.contains(needle)),
            "{needle}: {stderr}"
        );
    }
}

#[test]
fn production_refuses_development_components_in_the_configuration() {
    let setup = Setup::new();
    let encrypted = setup
        .bundle()
        .lines()
        .skip_while(|line| !line.contains("type: encrypted-local"))
        .take(5)
        .fold(String::new(), |mut block, line| {
            block.push_str(line);
            block.push('\n');
            block
        });
    let bundle = setup
        .bundle()
        .replace(&encrypted, "    type: in-memory\n")
        .replace("https://api.example-corp.net", "http://127.0.0.1:8080");
    let profile = PROFILE.replace("https://api.example-corp.net", "http://127.0.0.1:8080");
    setup.write("bundle.yaml", &bundle, Some(ConfigRole::SecretAdmin));
    setup.write(
        "profiles/example-api.yaml",
        &profile,
        Some(ConfigRole::ProfileAuthor),
    );
    let (ok, stderr) = setup.run(&[]);
    assert!(!ok);
    let found = refusals(&stderr);
    for needle in ["in-memory provider", "base_url", "use_binding.origins"] {
        assert!(
            found.iter().any(|r| r.contains(needle)),
            "{needle}: {stderr}"
        );
    }

    // Inline profiles bypass profile-author admission.
    let setup = Setup::new();
    let inline = format!(
        "{}profiles:\n  - {}",
        setup.bundle(),
        PROFILE.trim_end().replace('\n', "\n    ")
    );
    setup.write("bundle.yaml", &inline, Some(ConfigRole::SecretAdmin));
    std::fs::remove_file(setup.path("profiles/example-api.yaml")).unwrap();
    std::fs::remove_file(setup.path("profiles/example-api.yaml.sig")).unwrap();
    let (_, stderr) = setup.run(&[]);
    assert!(
        refusals(&stderr).iter().any(|r| r.contains("not inline")),
        "{stderr}"
    );
}

#[test]
fn documents_must_be_admitted_for_their_own_role() {
    // An unsigned draft in the profiles directory.
    let setup = Setup::new();
    setup.write(
        "profiles/draft.yaml",
        &PROFILE.replace("example-api", "draft-api"),
        None,
    );
    let (ok, stderr) = setup.run(&[]);
    assert!(!ok);
    assert!(
        stderr.contains("draft.yaml is neither signed nor pinned for profile-author"),
        "{stderr}"
    );

    // A profile edited after signing.
    let setup = Setup::new();
    let signed = setup.path("profiles/example-api.yaml.sig");
    let signature = std::fs::read(&signed).unwrap();
    setup.write(
        "profiles/example-api.yaml",
        &PROFILE.replace("path: /profile", "path: /admin"),
        None,
    );
    std::fs::write(&signed, signature).unwrap();
    let (_, stderr) = setup.run(&[]);
    assert!(
        stderr.contains("invalid signature for profile-author"),
        "{stderr}"
    );

    // The profile author signs the bundle: the key lacks secret-admin.
    let setup = Setup::new();
    setup.sign(
        "bundle.yaml",
        &setup.bundle(),
        ConfigRole::SecretAdmin,
        ConfigRole::ProfileAuthor,
    );
    let (_, stderr) = setup.run(&[]);
    assert!(stderr.contains("not trusted for secret-admin"), "{stderr}");

    // A policy signature replayed as the bundle's.
    let setup = Setup::new();
    setup.sign(
        "bundle.yaml",
        &setup.bundle(),
        ConfigRole::PolicyAdmin,
        ConfigRole::SecretAdmin,
    );
    let (_, stderr) = setup.run(&[]);
    assert!(
        stderr.contains("invalid signature for secret-admin"),
        "{stderr}"
    );
}

#[test]
fn pins_admit_and_writable_trust_anchors_are_refused() {
    let setup = Setup::new();
    std::fs::remove_file(setup.path("policy.yaml.sig")).unwrap();
    let pin = format!(
        "{{ role: policy-admin, sha256: \"{}\" }}",
        sha256(POLICY.as_bytes()).as_str()
    );
    setup.write_trust(&pin, 0o644);
    let (_, stderr) = setup.run(&[]);
    assert!(!stderr.contains("not admitted"), "{stderr}");

    setup.write_trust(&pin, 0o666);
    let (_, stderr) = setup.run(&[]);
    assert!(stderr.contains("writable by group or others"), "{stderr}");
}

/// The audit trail names the admitted configuration (development build:
/// plaintext listener with the development identity).
#[cfg(feature = "development")]
#[test]
fn audit_events_record_the_config_digest() {
    use acf_config::config_digest;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    let setup = Setup::new();
    let dev_bundle = r#"schema: acf.config/v1
deployment: { profile: development, environment: development }
secret_providers:
  development: { type: in-memory }
resources:
  "example-api:development":
    connector: example-api
    environment: development
    credentials:
      read: secret://development/example-api/read
secrets:
  "secret://development/example-api/read":
    use_binding: { connectors: [example-api], origins: ["http://127.0.0.1:9"], auth_slot: read, environment: development }
"#;
    let dev_profile = PROFILE.replace("https://api.example-corp.net", "http://127.0.0.1:9");
    let dev_policy = POLICY.replace("example-api:production", "example-api:development");
    setup.write("bundle.yaml", dev_bundle, Some(ConfigRole::SecretAdmin));
    setup.write(
        "profiles/example-api.yaml",
        &dev_profile,
        Some(ConfigRole::ProfileAuthor),
    );
    setup.write("policy.yaml", &dev_policy, Some(ConfigRole::PolicyAdmin));
    let expected = config_digest(&[
        (ConfigRole::SecretAdmin, sha256(dev_bundle.as_bytes())),
        (ConfigRole::ProfileAuthor, sha256(dev_profile.as_bytes())),
        (ConfigRole::PolicyAdmin, sha256(dev_policy.as_bytes())),
    ]);

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = |name: &str| setup.path(name).to_str().unwrap().to_owned();
    let mut gateway = Command::new(env!("CARGO_BIN_EXE_acf-gateway"))
        .args(["--config", &path("bundle.yaml")])
        .args(["--profiles", &path("profiles")])
        .args(["--policy", &path("policy.yaml")])
        .args(["--config-trust", &path("trust.yaml")])
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .args(["--audit-log", &path("audit.jsonl")])
        .args(["--state-db", &path("state.sqlite")])
        .spawn()
        .unwrap();
    let mut stream = None;
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut stream = stream.expect("gateway did not start");
    let body = format!(
        r#"{{"requestId":"req-1","timestamp":"{}","taskId":"t","action":"example.unknown","resource":"example-api:development","parameters":{{}}}}"#,
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    );
    write!(
        stream,
        "POST /v1/actions/execute HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let _ = gateway.kill();
    let _ = gateway.wait();

    let audit = std::fs::read_to_string(setup.path("audit.jsonl")).unwrap();
    let event: serde_json::Value = serde_json::from_str(audit.lines().next().unwrap()).unwrap();
    assert_eq!(
        event["gateway"]["config_digest"],
        expected.as_str(),
        "{audit}"
    );
    assert_eq!(event["gateway"]["build"], "development");
    assert_eq!(event["gateway"]["deployment_profile"], "development");
}
