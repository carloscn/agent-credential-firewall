//! `acf-setup`: generates a complete production deployment (WP-17).
//!
//! - `init` writes one directory per role: `gateway/`, `control-plane/`,
//!   `agent-<device>/`, and `offline/`. Each server directory is copied to
//!   `<etc>/<role>` on its host; paths inside the generated files already
//!   point there. `offline/` holds the CA key and the administrator signing
//!   keys and never belongs on a server.
//! - `admit` validates the edited gateway configuration against the
//!   production rules, re-signs every document with its role key, signs job
//!   definitions, and refreshes the control plane's copy.
//!
//! Nothing here is an agent action, and no secret value passes through it:
//! secrets are loaded later with `acf-store`.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use acf_config::{ConfigRole, ConfigSignature, production_issues, signing_message};
use acf_gateway::{load_config, profile_sources, read, read_bytes, source, text};
use acf_identity::{generate_pem, parse_key_pair, public_key, thumbprint};
use acf_protocol::{KeyId, base64url_encode};
use clap::{Args, Parser, Subcommand};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use ring::rand::{SecureRandom, SystemRandom};
use time::{Duration, OffsetDateTime};

const PROFILES_KID: &str = "profiles-1";
const SECRETS_KID: &str = "secrets-1";
const POLICY_KID: &str = "policy-1";
const JOBS_KID: &str = "jobs-1";
const AUTHORITY_KID: &str = "authority-1";
const ISSUER: &str = "acf-authority";

/// Generate and maintain an ACF production deployment.
#[derive(Parser)]
#[command(name = "acf-setup", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new deployment directory.
    Init(Box<InitArgs>),
    /// Validate and re-sign the gateway configuration and job definitions
    /// after editing them.
    Admit {
        /// The directory `init` wrote.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args)]
struct InitArgs {
    /// Output directory; must not exist.
    #[arg(long)]
    out: PathBuf,
    /// Name or IP address agents use to reach the gateway.
    #[arg(long, default_value = "localhost")]
    gateway_host: String,
    /// Name or IP address of the control plane. Default: the gateway host.
    #[arg(long)]
    control_plane_host: Option<String>,
    /// Agent host to enroll; repeatable.
    #[arg(long = "device", value_name = "NAME", default_values_t = vec!["agent-1".to_owned()])]
    devices: Vec<String>,
    /// UID of an agent account allowed to use the daemon socket; repeatable.
    #[arg(long = "agent-uid", value_name = "UID")]
    agent_uids: Vec<u32>,
    /// Gateway identifier, also the capability audience.
    #[arg(long, default_value = "gw-1")]
    gateway_id: String,
    /// Environment and secret namespace.
    #[arg(long, default_value = "production")]
    environment: String,
    /// Where configuration is installed on each host.
    #[arg(long, default_value = "/etc/acf")]
    etc: PathBuf,
    /// Where state lives on each host.
    #[arg(long, default_value = "/var/lib/acf")]
    state: PathBuf,
    /// Directory of the daemon socket.
    #[arg(long, default_value = "/run/acf-agent")]
    run: PathBuf,
    /// Directory of the installed binaries.
    #[arg(long, default_value = "/usr/local/bin")]
    bin: PathBuf,
    /// Gateway listen address.
    #[arg(long, default_value = "0.0.0.0:8443")]
    gateway_listen: String,
    /// Control-plane listen address.
    #[arg(long, default_value = "0.0.0.0:8444")]
    control_plane_listen: String,
    /// Validity of server and client certificates, in days.
    #[arg(long, default_value_t = 90)]
    cert_days: i64,
}

impl InitArgs {
    fn control_plane_host(&self) -> &str {
        self.control_plane_host
            .as_deref()
            .unwrap_or(&self.gateway_host)
    }

    fn port(listen: &str) -> &str {
        listen.rsplit_once(':').map_or(listen, |(_, port)| port)
    }

    /// The installed path of `relative` under `<etc>/<role>`.
    fn etc(&self, role: &str, relative: &str) -> String {
        self.etc.join(role).join(relative).display().to_string()
    }

    fn state(&self, role: &str, relative: &str) -> String {
        self.state.join(role).join(relative).display().to_string()
    }
}

/// Writes generated files, refusing to overwrite anything.
struct Out {
    root: PathBuf,
}

impl Out {
    fn dir(&self, relative: &str, mode: u32) -> Result<(), String> {
        let path = self.root.join(relative);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(&path)
            .map_err(|e| format!("cannot create {}: {e}", path.display()))
    }

    fn write(&self, relative: &str, contents: &[u8], mode: u32) -> Result<(), String> {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        file.write_all(contents)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    fn public(&self, relative: &str, contents: &str) -> Result<(), String> {
        self.write(relative, contents.as_bytes(), 0o644)
    }

    fn private(&self, relative: &str, contents: &[u8]) -> Result<(), String> {
        self.write(relative, contents, 0o600)
    }
}

/// A certificate and its key in PEM.
struct Issued {
    certificate: String,
    key: String,
    der: Vec<u8>,
}

struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    days: i64,
}

impl Ca {
    fn new(days: i64) -> Result<Self, String> {
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "ACF deployment CA");
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(3650);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        Ok(Self {
            issuer: CertifiedIssuer::self_signed(params, key).map_err(|e| e.to_string())?,
            days,
        })
    }

    fn issue(
        &self,
        names: &[&str],
        common_name: &str,
        usage: ExtendedKeyUsagePurpose,
    ) -> Result<Issued, String> {
        let mut params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .map_err(|e| e.to_string())?;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.extended_key_usages = vec![usage];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(self.days);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| e.to_string())?;
        Ok(Issued {
            certificate: certificate.pem(),
            key: key.serialize_pem(),
            der: certificate.der().to_vec(),
        })
    }
}

fn registry(entries: &[(&str, String, &Issued)]) -> String {
    let mut yaml = String::from("schema: acf.devices/v1\ndevices:\n");
    for (device, principal, issued) in entries {
        let _ = writeln!(
            yaml,
            "  - device: {device}\n    principal: '{principal}'\n    certificates:\n      - {}",
            thumbprint(&issued.der)
        );
    }
    yaml
}

fn sign_config(
    key_pem: &str,
    kid: &str,
    role: ConfigRole,
    bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let pair = parse_key_pair(key_pem).ok_or("administrator key is not an Ed25519 PEM key")?;
    let signature = ConfigSignature {
        kid: KeyId::new(kid).map_err(|e| e.to_string())?,
        signature: base64url_encode(pair.sign(&signing_message(role, bytes)).as_ref()),
    };
    serde_json::to_vec(&signature).map_err(|e| e.to_string())
}

/// A job-definition signature: Ed25519 over the exact bytes (ADR 0003).
fn sign_job(key_pem: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let pair = parse_key_pair(key_pem).ok_or("job signing key is not an Ed25519 PEM key")?;
    let signature = serde_json::json!({
        "kid": JOBS_KID,
        "signature": base64url_encode(pair.sign(bytes).as_ref()),
    });
    Ok(format!("{signature}\n").into_bytes())
}

struct Keys {
    authority: String,
    audit: String,
    profiles: String,
    secrets: String,
    policy: String,
    jobs: String,
}

fn public_of(pem: &str) -> Result<String, String> {
    parse_key_pair(pem)
        .map(|pair| public_key(&pair))
        .ok_or_else(|| "generated key does not parse".to_owned())
}

fn bundle(args: &InitArgs) -> String {
    let env = &args.environment;
    format!(
        r"# Gateway configuration (acf.config/v1), role secret-admin.
# Add resources and secrets here and connector profiles under profiles/,
# then run `acf-setup admit` and copy the result to the hosts.
schema: acf.config/v1
deployment: {{ profile: production, environment: {env} }}
secret_providers:
  {env}:
    type: encrypted-local
    path: {store}
    key_source: mounted-file
    key_location: {key}
    # No rollback anchor is implemented: the store provides integrity only.
    rollback_resistance: none
resources: {{}}
secrets: {{}}
",
        store = args.state("gateway", "store"),
        key = args.etc("gateway", "keys/store.key"),
    )
}

fn authority_config(args: &InitArgs, jobs_public: &str) -> String {
    format!(
        r"# Capability Authority configuration (acf.authority/v1).
# Entitlements say what each device may ever be granted; signed job
# definitions in jobs/ authorize concrete tasks.
schema: acf.authority/v1
issuer: {ISSUER}
audience: {gateway_id}
default_ttl_secs: 900
max_ttl_secs: 3600
entitlements: []
schedulers: []
job_signers:
  - {{ kid: {JOBS_KID}, public_key: {jobs_public} }}
",
        gateway_id = args.gateway_id,
    )
}

const HARDENING: &str = "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestrictNamespaces=yes\nLockPersonality=yes\nCapabilityBoundingSet=\nUMask=0077\n";

fn gateway_unit(args: &InitArgs) -> String {
    let e = |p: &str| args.etc("gateway", p);
    let s = |p: &str| args.state("gateway", p);
    let gw = &args.gateway_id;
    format!(
        "[Unit]\nDescription=ACF Credential Gateway\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nUser=acf-gateway\nGroup=acf-gateway\n\
ExecStart={bin}/acf-gateway --config {config} --profiles {profiles} --policy {policy} --config-trust {trust} \
--listen {listen} --tls-cert {cert} --tls-key {key} --client-ca {ca} --devices {devices} \
--authority-keys {authority_keys} --audience {gw} --gateway-id {gw} \
--audit-log {audit} --audit-key {audit_key} --audit-kid {gw}-audit \
--checkpoint-url https://{cp}:{cp_port}/v1/audit/checkpoints --checkpoint-client-cert {client_cert} \
--checkpoint-client-key {client_key} --checkpoint-ca {ca} --state-db {state_db}\n\
ReadWritePaths={state_dir}\nRestart=on-failure\n{HARDENING}\n[Install]\nWantedBy=multi-user.target\n",
        bin = args.bin.display(),
        config = e("config/bundle.yaml"),
        profiles = e("config/profiles"),
        policy = e("config/policy.yaml"),
        trust = e("config/trust.yaml"),
        listen = args.gateway_listen,
        cert = e("tls/server.pem"),
        key = e("tls/server.key"),
        ca = e("tls/ca.pem"),
        devices = e("config/devices.yaml"),
        authority_keys = e("config/authority-keys.yaml"),
        audit = s("audit.jsonl"),
        audit_key = e("keys/audit.key"),
        cp = args.control_plane_host(),
        cp_port = InitArgs::port(&args.control_plane_listen),
        client_cert = e("tls/checkpoint-client.pem"),
        client_key = e("tls/checkpoint-client.key"),
        state_db = s("state.sqlite"),
        state_dir = args.state.join("gateway").display(),
    )
}

fn control_plane_unit(args: &InitArgs) -> String {
    let e = |p: &str| args.etc("control-plane", p);
    format!(
        "[Unit]\nDescription=ACF Capability Authority and checkpoint collector\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nUser=acf-control-plane\nGroup=acf-control-plane\n\
ExecStart={bin}/acf-control-plane serve --authority-config {authority} --bundle {bundle} --profiles {profiles} \
--jobs {jobs} --signing-key {signing_key} --kid {AUTHORITY_KID} --listen {listen} --tls-cert {cert} \
--tls-key {key} --client-ca {ca} --devices {devices} --audit-keys {audit_keys} --checkpoint-store {store}\n\
ReadWritePaths={state_dir}\nRestart=on-failure\n{HARDENING}\n[Install]\nWantedBy=multi-user.target\n",
        bin = args.bin.display(),
        authority = e("config/authority.yaml"),
        bundle = e("config/gateway/bundle.yaml"),
        profiles = e("config/gateway/profiles"),
        jobs = e("config/jobs"),
        signing_key = e("keys/authority.key"),
        listen = args.control_plane_listen,
        cert = e("tls/server.pem"),
        key = e("tls/server.key"),
        ca = e("tls/ca.pem"),
        devices = e("config/devices.yaml"),
        audit_keys = e("config/audit-keys.yaml"),
        store = args.state("control-plane", "checkpoints"),
        state_dir = args.state.join("control-plane").display(),
    )
}

fn agent_unit(args: &InitArgs) -> String {
    let e = |p: &str| args.etc("agent", p);
    let mut allowed = String::new();
    for uid in &args.agent_uids {
        let _ = write!(allowed, " --allowed-uid {uid}");
    }
    format!(
        "[Unit]\nDescription=ACF agent daemon\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nUser=acf-daemon\nGroup=acf-agents\nRuntimeDirectory={runtime}\nRuntimeDirectoryMode=0750\n\
ExecStart={bin}/acf-agent daemon --socket {socket} --gateway https://{gw}:{gw_port} \
--authority https://{cp}:{cp_port} --client-cert {cert} --client-key {key} --gateway-ca {ca}{allowed}\n\
Restart=on-failure\n{HARDENING}\n[Install]\nWantedBy=multi-user.target\n",
        runtime = args
            .run
            .file_name()
            .map_or_else(|| "acf-agent".into(), |n| n.to_string_lossy()),
        bin = args.bin.display(),
        socket = args.run.join("acf.sock").display(),
        gw = args.gateway_host,
        gw_port = InitArgs::port(&args.gateway_listen),
        cp = args.control_plane_host(),
        cp_port = InitArgs::port(&args.control_plane_listen),
        cert = e("tls/client.pem"),
        key = e("tls/client.key"),
        ca = e("tls/ca.pem"),
    )
}

fn deploy_guide(args: &InitArgs) -> String {
    format!(
        include_str!("acf-setup-deploy.md"),
        etc = args.etc.display(),
        state = args.state.display(),
        env = args.environment,
        gateway_host = args.gateway_host,
        control_plane_host = args.control_plane_host(),
        devices = args.devices.join(", "),
    )
}

/// Writes a deployment into `args.out`, removing the partial output if any
/// step fails: it contains private keys.
fn init(args: &InitArgs) -> Result<(), String> {
    if args.out.exists() {
        return Err(format!(
            "{} already exists; choose a new directory",
            args.out.display()
        ));
    }
    let result = generate(args);
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&args.out);
    }
    result
}

fn generate(args: &InitArgs) -> Result<(), String> {
    if args.out.exists() {
        return Err(format!(
            "{} already exists; choose a new directory",
            args.out.display()
        ));
    }
    let out = Out {
        root: args.out.clone(),
    };
    out.dir("", 0o755)?;
    out.dir("offline", 0o700)?;

    let ca = Ca::new(args.cert_days)?;
    let gateway_server = ca.issue(
        &[&args.gateway_host],
        "acf-gateway",
        ExtendedKeyUsagePurpose::ServerAuth,
    )?;
    let cp_server = ca.issue(
        &[args.control_plane_host()],
        "acf-control-plane",
        ExtendedKeyUsagePurpose::ServerAuth,
    )?;
    let checkpoint_client = ca.issue(
        &[],
        &format!("gateway-{}", args.gateway_id),
        ExtendedKeyUsagePurpose::ClientAuth,
    )?;
    let devices = args
        .devices
        .iter()
        .map(|d| {
            ca.issue(&[], d, ExtendedKeyUsagePurpose::ClientAuth)
                .map(|c| (d.as_str(), c))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let keys = Keys {
        authority: generate_pem().map_err(|e| e.to_string())?,
        audit: generate_pem().map_err(|e| e.to_string())?,
        profiles: generate_pem().map_err(|e| e.to_string())?,
        secrets: generate_pem().map_err(|e| e.to_string())?,
        policy: generate_pem().map_err(|e| e.to_string())?,
        jobs: generate_pem().map_err(|e| e.to_string())?,
    };
    let mut store_key = [0u8; 32];
    SystemRandom::new()
        .fill(&mut store_key)
        .map_err(|_| "no secure random source")?;
    let ca_pem = ca.issuer.pem();

    // Offline: never copied to a server.
    out.public("offline/ca.pem", &ca_pem)?;
    out.private("offline/ca.key", ca.issuer.key().serialize_pem().as_bytes())?;
    out.private("offline/keys/profiles.key", keys.profiles.as_bytes())?;
    out.private("offline/keys/secrets.key", keys.secrets.as_bytes())?;
    out.private("offline/keys/policy.key", keys.policy.as_bytes())?;
    out.private("offline/keys/jobs.key", keys.jobs.as_bytes())?;

    write_gateway(
        args,
        &out,
        &ca_pem,
        &gateway_server,
        &checkpoint_client,
        &devices,
        &keys,
        &store_key,
    )?;
    write_control_plane(
        args,
        &out,
        &ca_pem,
        &cp_server,
        &checkpoint_client,
        &devices,
        &keys,
    )?;
    for (device, issued) in &devices {
        let dir = format!("agent-{device}");
        out.public(&format!("{dir}/tls/ca.pem"), &ca_pem)?;
        out.public(&format!("{dir}/tls/client.pem"), &issued.certificate)?;
        out.private(&format!("{dir}/tls/client.key"), issued.key.as_bytes())?;
        out.public(&format!("{dir}/acf-agent.service"), &agent_unit(args))?;
    }
    out.public("DEPLOY.md", &deploy_guide(args))?;
    admit(&args.out)
}

#[expect(
    clippy::too_many_arguments,
    reason = "every generated input of the gateway"
)]
fn write_gateway(
    args: &InitArgs,
    out: &Out,
    ca_pem: &str,
    server: &Issued,
    checkpoint_client: &Issued,
    devices: &[(&str, Issued)],
    keys: &Keys,
    store_key: &[u8],
) -> Result<(), String> {
    out.public("gateway/tls/ca.pem", ca_pem)?;
    out.public("gateway/tls/server.pem", &server.certificate)?;
    out.private("gateway/tls/server.key", server.key.as_bytes())?;
    out.public(
        "gateway/tls/checkpoint-client.pem",
        &checkpoint_client.certificate,
    )?;
    out.private(
        "gateway/tls/checkpoint-client.key",
        checkpoint_client.key.as_bytes(),
    )?;
    out.private("gateway/keys/audit.key", keys.audit.as_bytes())?;
    out.write("gateway/keys/store.key", store_key, 0o400)?;
    out.dir("gateway/config/profiles", 0o755)?;
    out.public("gateway/config/bundle.yaml", &bundle(args))?;
    out.public(
        "gateway/config/policy.yaml",
        "# Gateway policy (acf.policy/v1), role policy-admin.\nschema: acf.policy/v1\nversion: initial\nrules: []\n",
    )?;
    out.public(
        "gateway/config/trust.yaml",
        &format!(
            r"# Configuration trust anchor (acf.config-trust/v1). Keep it root-owned.
schema: acf.config-trust/v1
signers:
  - {{ kid: {PROFILES_KID}, public_key: {}, roles: [profile-author] }}
  - {{ kid: {SECRETS_KID}, public_key: {}, roles: [secret-admin] }}
  - {{ kid: {POLICY_KID}, public_key: {}, roles: [policy-admin] }}
",
            public_of(&keys.profiles)?,
            public_of(&keys.secrets)?,
            public_of(&keys.policy)?,
        ),
    )?;
    let agents: Vec<(&str, String, &Issued)> = devices
        .iter()
        .map(|(d, c)| (*d, format!("workload:{d}"), c))
        .collect();
    out.public("gateway/config/devices.yaml", &registry(&agents))?;
    out.public(
        "gateway/config/authority-keys.yaml",
        &format!(
            "schema: acf.authority-keys/v1\nkeys:\n  - {{ kid: {AUTHORITY_KID}, issuer: {ISSUER}, alg: EdDSA, public_key: {} }}\n",
            public_of(&keys.authority)?
        ),
    )?;
    out.public("gateway/acf-gateway.service", &gateway_unit(args))
}

fn write_control_plane(
    args: &InitArgs,
    out: &Out,
    ca_pem: &str,
    server: &Issued,
    checkpoint_client: &Issued,
    devices: &[(&str, Issued)],
    keys: &Keys,
) -> Result<(), String> {
    out.public("control-plane/tls/ca.pem", ca_pem)?;
    out.public("control-plane/tls/server.pem", &server.certificate)?;
    out.private("control-plane/tls/server.key", server.key.as_bytes())?;
    out.private(
        "control-plane/keys/authority.key",
        keys.authority.as_bytes(),
    )?;
    out.dir("control-plane/config/jobs", 0o755)?;
    out.public(
        "control-plane/config/authority.yaml",
        &authority_config(args, &public_of(&keys.jobs)?),
    )?;
    let gateway_principal = format!("gateway:{}", args.gateway_id);
    let mut entries: Vec<(&str, String, &Issued)> = devices
        .iter()
        .map(|(d, c)| (*d, format!("workload:{d}"), c))
        .collect();
    let gateway_device = format!("gateway-{}", args.gateway_id);
    entries.push((
        &gateway_device,
        gateway_principal.clone(),
        checkpoint_client,
    ));
    out.public("control-plane/config/devices.yaml", &registry(&entries))?;
    out.public(
        "control-plane/config/audit-keys.yaml",
        &format!(
            "schema: acf.audit-keys/v1\nkeys:\n  - {{ kid: {gw}-audit, gateway: {gw}, principal: '{gateway_principal}', public_key: {} }}\n",
            public_of(&keys.audit)?,
            gw = args.gateway_id,
        ),
    )?;
    out.public(
        "control-plane/acf-control-plane.service",
        &control_plane_unit(args),
    )
}

/// Re-signs `path` for `role` with `key_pem`, replacing any old signature.
fn resign(path: &Path, role: ConfigRole, key_pem: &str, kid: &str) -> Result<(), String> {
    let bytes = read_bytes(path)?;
    let mut signature = path.as_os_str().to_owned();
    signature.push(".sig");
    std::fs::write(
        PathBuf::from(signature),
        sign_config(key_pem, kid, role, &bytes)?,
    )
    .map_err(|e| format!("cannot sign {}: {e}", path.display()))
}

fn yaml_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    paths.sort();
    Ok(paths)
}

#[expect(clippy::print_stdout, reason = "command output")]
fn admit(out: &Path) -> Result<(), String> {
    let config = out.join("gateway/config");
    let offline = out.join("offline/keys");
    let key = |name: &str| read(&offline.join(name));

    // Validate first: the bundle with its profiles, the production rules,
    // and the policy against the bundle.
    let profiles = profile_sources(&config.join("profiles"))?;
    let validated = load_config(&source(&config.join("bundle.yaml"))?, &profiles)?;
    let issues = production_issues(&validated);
    if !issues.is_empty() {
        let lines: Vec<String> = issues.iter().map(ToString::to_string).collect();
        return Err(format!(
            "the configuration breaks production rules:\n  - {}",
            lines.join("\n  - ")
        ));
    }
    acf_policy::load_policy_yaml(&read(&config.join("policy.yaml"))?, &validated)
        .map_err(|e| format!("policy.yaml: {e}"))?;

    resign(
        &config.join("bundle.yaml"),
        ConfigRole::SecretAdmin,
        &key("secrets.key")?,
        SECRETS_KID,
    )?;
    resign(
        &config.join("policy.yaml"),
        ConfigRole::PolicyAdmin,
        &key("policy.key")?,
        POLICY_KID,
    )?;
    for profile in yaml_files(&config.join("profiles"))? {
        resign(
            &profile,
            ConfigRole::ProfileAuthor,
            &key("profiles.key")?,
            PROFILES_KID,
        )?;
    }
    let jobs = out.join("control-plane/config/jobs");
    for job in yaml_files(&jobs)? {
        let mut signature = job.as_os_str().to_owned();
        signature.push(".sig");
        std::fs::write(
            PathBuf::from(signature),
            sign_job(&key("jobs.key")?, &read_bytes(&job)?)?,
        )
        .map_err(|e| format!("cannot sign {}: {e}", job.display()))?;
    }

    // The control plane validates grants against the same configuration.
    let copy = out.join("control-plane/config/gateway");
    let _ = std::fs::remove_dir_all(&copy);
    std::fs::create_dir_all(copy.join("profiles"))
        .map_err(|e| format!("cannot create {}: {e}", copy.display()))?;
    std::fs::copy(config.join("bundle.yaml"), copy.join("bundle.yaml"))
        .map_err(|e| e.to_string())?;
    for file in &profiles {
        let name = Path::new(&file.name)
            .file_name()
            .ok_or("profile without a file name")?;
        std::fs::write(copy.join("profiles").join(name), text(file)?.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    println!(
        "admitted {} profiles, the bundle, the policy, and {} jobs in {}",
        profiles.len(),
        yaml_files(&jobs)?.len(),
        out.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Init(args) => init(&args),
        Command::Admit { out } => admit(&out),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[expect(clippy::print_stderr, reason = "operator error")]
            {
                eprintln!("acf-setup: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
