//! `acf-setup` (WP-17): a generated deployment must be complete, keep
//! offline keys off the servers, and start under `production` from exactly
//! the generated unit commands.
//!
//! The release flavor (`cargo test -p acf-gateway --test setup`, after a
//! workspace build so `acf-control-plane` and `acf-agent` exist next to the
//! gateway binary) starts all three services. The development flavor checks
//! that the gateway refuses only because of its build.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Root {
    dir: PathBuf,
    run: PathBuf,
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_dir_all(&self.run);
    }
}

impl Root {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("acf-setup-{}-{n}", std::process::id()));
        // Unix socket paths are short; keep the run directory near the root.
        let run = PathBuf::from(format!("/tmp/acf-s{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, run }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.join(relative)
    }

    fn bin_dir() -> PathBuf {
        Path::new(env!("CARGO_BIN_EXE_acf-gateway"))
            .parent()
            .unwrap()
            .to_owned()
    }

    fn setup(args: &[&str]) -> (bool, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_acf-setup"))
            .args(args)
            .output()
            .unwrap();
        (
            output.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    }

    fn init(&self) {
        let p = |r: &str| self.path(r).to_str().unwrap().to_owned();
        let bin = Self::bin_dir();
        let (ok, output) = Self::setup(&[
            "init",
            "--out",
            &p("out"),
            "--device",
            "laptop-1",
            "--etc",
            &p("etc"),
            "--state",
            &p("state"),
            "--run",
            self.run.to_str().unwrap(),
            "--bin",
            bin.to_str().unwrap(),
            "--gateway-listen",
            "127.0.0.1:0",
            "--control-plane-listen",
            &format!("127.0.0.1:{}", free_port()),
        ]);
        assert!(ok, "{output}");
    }

    /// Copies each role directory to its install location and creates the
    /// state directories and the secret store, as DEPLOY.md describes.
    fn install(&self) {
        for (from, to) in [
            ("out/gateway", "etc/gateway"),
            ("out/control-plane", "etc/control-plane"),
            ("out/agent-laptop-1", "etc/agent"),
        ] {
            copy_dir(&self.path(from), &self.path(to));
        }
        for dir in ["state/gateway", "state/control-plane"] {
            std::fs::create_dir_all(self.path(dir)).unwrap();
        }
        std::fs::create_dir_all(&self.run).unwrap();
        std::fs::set_permissions(&self.run, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_acf-store"))
            .args([
                "--config",
                self.path("etc/gateway/config/bundle.yaml")
                    .to_str()
                    .unwrap(),
            ])
            .args([
                "--profiles",
                self.path("etc/gateway/config/profiles").to_str().unwrap(),
            ])
            .args(["init", "--namespace", "production"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Starts a service from its unit's `ExecStart` and waits until it
    /// listens. Returns the process, or its output if it exited.
    fn start(&self, unit: &str) -> Result<Child, String> {
        let text = std::fs::read_to_string(self.path(unit)).unwrap();
        let line = text
            .lines()
            .find_map(|l| l.strip_prefix("ExecStart="))
            .unwrap();
        let mut words = line.split_whitespace();
        let program = words.next().unwrap();
        assert!(
            Path::new(program).exists(),
            "{program} is missing: build the workspace first (cargo test --workspace)"
        );
        let mut child = Command::new(program)
            .args(words)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let mut output = String::new();
        while let Some(Ok(line)) = lines.next() {
            output.push_str(&line);
            output.push('\n');
            if line.contains("listening on") {
                std::thread::spawn(move || for _ in lines {});
                return Ok(child);
            }
        }
        let _ = child.wait();
        Err(output)
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            all.extend(files(&path));
        } else {
            all.push(path);
        }
    }
    all
}

struct Running(Vec<Child>);

impl Drop for Running {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn offline_keys_stay_off_the_servers_and_private_keys_are_private() {
    let root = Root::new();
    root.init();
    let offline: Vec<Vec<u8>> = files(&root.path("out/offline"))
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "key"))
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    assert_eq!(offline.len(), 5, "the CA key and four administrator keys");
    for role in ["gateway", "control-plane", "agent-laptop-1"] {
        for file in files(&root.path(&format!("out/{role}"))) {
            let bytes = std::fs::read(&file).unwrap();
            assert!(
                !offline.contains(&bytes),
                "{} holds offline key material",
                file.display()
            );
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            if file.extension().is_some_and(|e| e == "key") {
                assert_eq!(mode & 0o077, 0, "{} is mode {mode:o}", file.display());
            }
        }
    }
    let (ok, output) = Root::setup(&["init", "--out", root.path("out").to_str().unwrap()]);
    assert!(!ok && output.contains("already exists"), "{output}");
}

#[test]
fn admit_refuses_production_violations_and_signs_valid_edits() {
    let root = Root::new();
    root.init();
    let out = root.path("out");
    let profile = "schema: acf.profile/v1\nconnector: example-api\nrevision: 1\nbase_url: https://api.example-corp.net\nauthentication: { strategy: bearer }\nactions:\n  example.profile.get:\n    method: GET\n    path: /profile\n    credential_slot: read\n    classification: read\n    response: { fields: [user] }\n";
    std::fs::write(
        out.join("gateway/config/profiles/example-api.yaml"),
        profile,
    )
    .unwrap();
    let bundle_path = out.join("gateway/config/bundle.yaml");
    let bundle = std::fs::read_to_string(&bundle_path).unwrap().replace(
        "resources: {}\nsecrets: {}\n",
        "resources:\n  \"example-api:production\":\n    connector: example-api\n    environment: production\n    credentials: { read: secret://production/example-api/read }\nsecrets:\n  \"secret://production/example-api/read\":\n    use_binding: { connectors: [example-api], origins: [\"https://api.example-corp.net\"], auth_slot: read, environment: production }\n",
    );
    // A loopback destination breaks the production rules.
    std::fs::write(
        &bundle_path,
        bundle.replace("https://api.example-corp.net", "http://127.0.0.1:8080"),
    )
    .unwrap();
    std::fs::write(
        out.join("gateway/config/profiles/example-api.yaml"),
        profile.replace("https://api.example-corp.net", "http://127.0.0.1:8080"),
    )
    .unwrap();
    let (ok, output) = Root::setup(&["admit", "--out", out.to_str().unwrap()]);
    assert!(
        !ok && output.contains("breaks production rules"),
        "{output}"
    );

    std::fs::write(&bundle_path, &bundle).unwrap();
    std::fs::write(
        out.join("gateway/config/profiles/example-api.yaml"),
        profile,
    )
    .unwrap();
    let mut job =
        std::fs::File::create(out.join("control-plane/config/jobs/profile.yaml")).unwrap();
    job.write_all(b"schema: acf.job/v1\nid: profile\nprincipals: ['workload:laptop-1']\ngrants: [{ action: example.profile.get, resource: 'example-api:production' }]\n").unwrap();
    let (ok, output) = Root::setup(&["admit", "--out", out.to_str().unwrap()]);
    assert!(ok, "{output}");
    assert!(output.contains("admitted 1 profiles"), "{output}");
    for signed in [
        "gateway/config/profiles/example-api.yaml.sig",
        "control-plane/config/jobs/profile.yaml.sig",
        "control-plane/config/gateway/profiles/example-api.yaml",
    ] {
        assert!(out.join(signed).exists(), "{signed}");
    }
}

#[test]
fn a_generated_deployment_starts_from_its_units() {
    let root = Root::new();
    root.init();
    root.install();

    let gateway = root.start("etc/gateway/acf-gateway.service");
    if cfg!(feature = "development") {
        let output = gateway.expect_err("a development build refuses production");
        assert!(
            output.contains("built with the `development` feature")
                && !output.contains("configuration must be admitted"),
            "{output}"
        );
        return;
    }
    // Release flavor: all three services, in the documented order.
    let mut running = Running(Vec::new());
    drop(gateway.map(|child| running.0.push(child)));
    let control_plane = root
        .start("etc/control-plane/acf-control-plane.service")
        .unwrap_or_else(|output| panic!("control plane did not start:\n{output}"));
    running.0.push(control_plane);
    let daemon = root
        .start("etc/agent/acf-agent.service")
        .unwrap_or_else(|output| panic!("daemon did not start:\n{output}"));
    running.0.push(daemon);
    assert!(running.0.len() == 3, "the gateway started");

    // The daemon reaches the authority over mTLS with generated certificates;
    // with no job yet, the authority refuses the basis.
    let task = Command::new(Root::bin_dir().join("acf-agent"))
        .args(["task", "create", "--socket"])
        .arg(root.run.join("acf.sock"))
        .args(["--task", "t1", "--job", "none"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&task.stderr);
    assert!(stderr.contains("task_denied"), "{stderr}");
    std::thread::sleep(Duration::from_millis(100));
}
