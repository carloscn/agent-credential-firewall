//! The gateway binary serving requests from an encrypted local store that
//! `acf-store` created (WP-07 wiring). Development flavor: plaintext
//! loopback with the development identity.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TOKEN: &str = "ACF-STORE-CANARY-6e1f";

/// Answers `/profile` and records each request's `Authorization` header.
fn upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 8192];
            let read = stream.read(&mut request).unwrap_or(0);
            let text = String::from_utf8_lossy(&request[..read]).into_owned();
            if let Some(line) = text
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
            {
                record.lock().unwrap().push(line.to_owned());
            }
            let body = r#"{"user":"demo"}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (port, seen)
}

struct Setup {
    dir: PathBuf,
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Setup {
    fn new(upstream: u16) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "acf-encrypted-store-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let setup = Self { dir };
        let origin = format!("http://127.0.0.1:{upstream}");
        std::fs::write(
            setup.path("config.yaml"),
            format!(
                r#"schema: acf.config/v1
deployment: {{ profile: development, environment: development }}
secret_providers:
  development:
    type: encrypted-local
    path: {store}
    key_source: mounted-file
    key_location: {key}
    rollback_resistance: none
profiles:
  - schema: acf.profile/v1
    connector: example-api
    revision: 1
    base_url: {origin}
    authentication: {{ strategy: bearer }}
    actions:
      example.profile.get:
        method: GET
        path: /profile
        credential_slot: read
        classification: read
        response: {{ fields: [user] }}
resources:
  "example-api:development":
    connector: example-api
    environment: development
    credentials:
      read: secret://development/example-api/read
secrets:
  "secret://development/example-api/read":
    use_binding: {{ connectors: [example-api], origins: ["{origin}"], auth_slot: read, environment: development }}
"#,
                store = setup.path("store").display(),
                key = setup.path("store.key").display(),
            ),
        )
        .unwrap();
        std::fs::write(
            setup.path("policy.yaml"),
            "schema: acf.policy/v1\nversion: store.1\nrules:\n  - { id: dev, effect: allow, principals: [dev-agent], actions: [example.profile.get], resources: ['example-api:development'] }\n",
        )
        .unwrap();
        let mut key = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(setup.path("store.key"))
            .unwrap();
        key.write_all(&[42u8; 32]).unwrap();
        std::fs::set_permissions(
            setup.path("store.key"),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        setup
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Runs `acf-store` with `stdin`; returns success, stdout, and stderr.
    fn store(&self, args: &[&str], stdin: &[u8]) -> (bool, String, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_acf-store"))
            .args(["--config", self.path("config.yaml").to_str().unwrap()])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// Starts the gateway and waits until it listens; `None` if it exits.
    fn gateway(&self, port: u16) -> (Option<Child>, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_acf-gateway"))
            .args(["--config", self.path("config.yaml").to_str().unwrap()])
            .args(["--policy", self.path("policy.yaml").to_str().unwrap()])
            .args(["--listen", &format!("127.0.0.1:{port}")])
            .args(["--audit-log", self.path("audit.jsonl").to_str().unwrap()])
            .args(["--state-db", self.path("state.sqlite").to_str().unwrap()])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let mut text = String::new();
        while let Some(Ok(line)) = lines.next() {
            text.push_str(&line);
            text.push('\n');
            if line.contains("listening on") {
                std::thread::spawn(move || for _ in lines {});
                return (Some(child), text);
            }
        }
        let _ = child.wait();
        (None, text)
    }
}

fn execute(port: u16) -> (u16, String) {
    let body = format!(
        r#"{{"requestId":"req-{}","timestamp":"{}","taskId":"t","action":"example.profile.get","resource":"example-api:development","parameters":{{}}}}"#,
        time::OffsetDateTime::now_utc().unix_timestamp_nanos(),
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "POST /v1/actions/execute HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, response)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn requests_use_the_credential_from_the_encrypted_store() {
    let (upstream_port, seen) = upstream();
    let setup = Setup::new(upstream_port);

    let (ok, stdout, stderr) = setup.store(&["init", "--namespace", "development"], b"");
    assert!(ok, "{stderr}");
    assert!(stdout.contains("integrity only, no rollback resistance"));
    let (ok, _, stderr) = setup.store(&["put", "secret://development/example-api/read"], b"");
    assert!(
        !ok && stderr.contains("standard input is empty"),
        "{stderr}"
    );
    let (ok, stdout, stderr) = setup.store(
        &["put", "secret://development/example-api/read"],
        format!("{TOKEN}\n").as_bytes(),
    );
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("read v1") && !stdout.contains(TOKEN),
        "{stdout}"
    );
    let (ok, stdout, _) = setup.store(&["list", "--namespace", "development"], b"");
    assert!(ok && stdout.contains("secret://development/example-api/read v1"));
    assert!(!stdout.contains(TOKEN));

    // Nothing in the store directory holds the plaintext.
    for entry in std::fs::read_dir(setup.path("store")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    }

    let port = free_port();
    let (gateway, log) = setup.gateway(port);
    let mut gateway = gateway.unwrap_or_else(|| panic!("gateway did not start:\n{log}"));
    assert!(log.contains("encrypted-local at"), "{log}");

    let (status, response) = execute(port);
    assert_eq!(status, 200, "{response}");
    assert!(!response.contains(TOKEN));
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [format!("authorization: Bearer {TOKEN}")]
    );

    // Tamper with the stored record: the next request fails closed.
    for entry in std::fs::read_dir(setup.path("store")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "acf-record") {
            let mut bytes = std::fs::read(&path).unwrap();
            let middle = bytes.len() / 2;
            bytes[middle] ^= 1;
            std::fs::write(&path, bytes).unwrap();
        }
    }
    let (status, response) = execute(port);
    assert_eq!(status, 502, "{response}");
    assert!(response.contains("credential_unavailable"), "{response}");
    assert_eq!(seen.lock().unwrap().len(), 1, "no second upstream call");

    let _ = gateway.kill();
    let _ = gateway.wait();
    let audit = std::fs::read_to_string(setup.path("audit.jsonl")).unwrap();
    assert!(!audit.contains(TOKEN));
}
