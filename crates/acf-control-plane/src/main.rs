//! `acf-control-plane` binary entry point. Behavior belongs in the library crate.
//!
//! - `serve`: the Capability Authority over mTLS (ADR 0002, ADR 0003).
//! - `keygen`: a new Ed25519 PKCS#8 key, written with mode 0600.
//! - `trust-entry`: the `acf.authority-keys/v1` document gateways need.
//! - `sign-job`: a detached signature for a job definition.
//! - `admit`: checks a configuration document for its role and signs it
//!   (ADR 0004). Drafts, including agent-authored profiles, do nothing until
//!   admitted.
//!
//! Private keys are read from files, never from the command line.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use acf_config::{
    ConfigRole, ConfigSignature, check_document, load_yaml, parse_yaml, sha256, signing_message,
};
use acf_control_plane::{
    Authority, AuthorityConfig, AuthorityPolicy, CapabilitySigner, generate_pem, public_key,
    read_jobs, read_key_pair, router, sign_detached,
};
use acf_identity::{
    AUTHORITY_KEYS_SCHEMA, DeviceRegistry, MtlsIdentityProvider, serve_tls, server_config,
    watch_registry,
};
use acf_protocol::base64url_encode;
use acf_protocol::{IssuerId, KeyId};
use clap::{Parser, Subcommand};

/// ACF control plane: the Capability Authority.
#[derive(Parser)]
#[command(name = "acf-control-plane", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the Capability Authority over mTLS.
    Serve(Box<ServeArgs>),
    /// Generate an Ed25519 private key (PKCS#8 PEM, mode 0600) and print its
    /// public key.
    Keygen {
        /// Output file; must not exist.
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the `acf.authority-keys/v1` document for gateways.
    TrustEntry {
        /// Authority signing key.
        #[arg(long)]
        signing_key: PathBuf,
        /// Key identifier.
        #[arg(long)]
        kid: String,
        /// Issuer the key signs for.
        #[arg(long)]
        issuer: String,
    },
    /// Admit a configuration document: check it for its role, print its
    /// digest, and write `<file>.sig`.
    Admit {
        /// `profile-author`, `secret-admin`, or `policy-admin`.
        #[arg(long, value_parser = parse_role)]
        role: ConfigRole,
        /// Administrator signing key for that role.
        #[arg(long)]
        key: PathBuf,
        /// Administrator key identifier, as listed in the trust anchor.
        #[arg(long)]
        kid: String,
        /// The document.
        file: PathBuf,
    },
    /// Write `<job>.sig`, a detached signature over the job definition file.
    SignJob {
        /// Administrator signing key.
        #[arg(long)]
        key: PathBuf,
        /// Administrator key identifier.
        #[arg(long)]
        kid: String,
        /// Job definition (acf.job/v1).
        job: PathBuf,
    },
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Authority configuration (acf.authority/v1).
    #[arg(long)]
    authority_config: PathBuf,
    /// Configuration bundle (acf.config/v1); grants must name its actions.
    #[arg(long)]
    bundle: PathBuf,
    /// Directory of signed job definitions (`*.yaml` with `*.yaml.sig`).
    #[arg(long)]
    jobs: Option<PathBuf>,
    /// Capability signing key (Ed25519 PKCS#8 PEM, mode 0600).
    #[arg(long)]
    signing_key: PathBuf,
    /// Signing key identifier (JWS `kid`).
    #[arg(long)]
    kid: String,
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8444")]
    listen: SocketAddr,
    /// Server certificate chain (PEM, leaf first).
    #[arg(long)]
    tls_cert: PathBuf,
    /// Server private key (PKCS#8 PEM).
    #[arg(long)]
    tls_key: PathBuf,
    /// CA bundle that issues daemon client certificates (PEM).
    #[arg(long)]
    client_ca: PathBuf,
    /// Device registry (acf.devices/v1), re-read when it changes.
    #[arg(long)]
    devices: PathBuf,
}

fn parse_role(text: &str) -> Result<ConfigRole, String> {
    [
        ConfigRole::ProfileAuthor,
        ConfigRole::SecretAdmin,
        ConfigRole::PolicyAdmin,
    ]
    .into_iter()
    .find(|role| role.as_str() == text)
    .ok_or_else(|| "expected profile-author, secret-admin, or policy-admin".to_owned())
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

#[expect(clippy::print_stderr, reason = "operator messages")]
fn report(message: &str) {
    eprintln!("acf-control-plane: {message}");
}

#[expect(clippy::print_stdout, reason = "command output")]
fn print(text: &str) {
    print!("{text}");
}

fn new_id<T>(
    make: impl Fn(String) -> Result<T, acf_protocol::IdError>,
    text: &str,
) -> Result<T, String> {
    make(text.to_owned()).map_err(|e| e.to_string())
}

async fn serve(args: ServeArgs) -> Result<(), String> {
    let bundle = load_yaml(&read(&args.bundle)?).map_err(|e| e.to_string())?;
    let config: AuthorityConfig =
        parse_yaml(&read(&args.authority_config)?).map_err(|e| e.to_string())?;
    let jobs = match &args.jobs {
        Some(dir) => read_jobs(dir)?,
        None => Vec::new(),
    };
    let policy = AuthorityPolicy::new(config, &bundle, &jobs).map_err(|e| e.to_string())?;
    let issuer = policy.config.issuer.clone();
    let pair = read_key_pair(&args.signing_key).map_err(|e| e.to_string())?;
    let signer = CapabilitySigner::new(issuer.clone(), new_id(KeyId::new, &args.kid)?, pair);
    let job_count = policy.jobs.len();
    let authority = Authority::new(policy, bundle, signer)?;

    let registry: DeviceRegistry = parse_yaml(&read(&args.devices)?).map_err(|e| e.to_string())?;
    let identity = Arc::new(
        MtlsIdentityProvider::new(new_id(IssuerId::new, &format!("{issuer}-mtls"))?, registry)
            .map_err(|e| e.to_string())?,
    );
    let tls = server_config(
        &read_bytes(&args.tls_cert)?,
        &read_bytes(&args.tls_key)?,
        &read_bytes(&args.client_ca)?,
    )
    .map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
    tokio::spawn(watch_registry(
        identity.clone(),
        args.devices.clone(),
        |text| parse_yaml::<DeviceRegistry>(text).map_err(|e| e.to_string()),
        report,
    ));
    report(&format!(
        "Capability Authority `{issuer}` listening on https://{} ({job_count} signed jobs)",
        args.listen
    ));
    serve_tls(listener, tls, router(authority, identity))
        .await
        .map_err(|e| e.to_string())
}

fn write_new(path: &Path, contents: &str, mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| {
            format!(
                "cannot create {} (refusing to overwrite): {e}",
                path.display()
            )
        })?;
    file.write_all(contents.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn run_offline(command: Command) -> Result<(), String> {
    match command {
        Command::Serve(_) => Err("serve runs asynchronously".to_owned()),
        Command::Keygen { out } => {
            let pem = generate_pem().map_err(|e| e.to_string())?;
            write_new(&out, &pem, 0o600)?;
            let pair = read_key_pair(&out).map_err(|e| e.to_string())?;
            print(&format!("{}\n", public_key(&pair)));
            Ok(())
        }
        Command::TrustEntry {
            signing_key,
            kid,
            issuer,
        } => {
            let pair = read_key_pair(&signing_key).map_err(|e| e.to_string())?;
            let kid = new_id(KeyId::new, &kid)?;
            let issuer = new_id(IssuerId::new, &issuer)?;
            print(&format!(
                "schema: {AUTHORITY_KEYS_SCHEMA}\nkeys:\n  - kid: {kid}\n    issuer: {issuer}\n    alg: EdDSA\n    public_key: {}\n",
                public_key(&pair)
            ));
            Ok(())
        }
        Command::Admit {
            role,
            key,
            kid,
            file,
        } => {
            let bytes = read_bytes(&file)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| format!("{} is not UTF-8", file.display()))?;
            check_document(role, text).map_err(|e| format!("{}: {e}", file.display()))?;
            let pair = read_key_pair(&key).map_err(|e| e.to_string())?;
            let signature = ConfigSignature {
                kid: new_id(KeyId::new, &kid)?,
                signature: base64url_encode(pair.sign(&signing_message(role, &bytes)).as_ref()),
            };
            let mut target = file.clone().into_os_string();
            target.push(".sig");
            let text = serde_json::to_string(&signature).map_err(|e| e.to_string())?;
            std::fs::write(PathBuf::from(&target), format!("{text}\n"))
                .map_err(|e| format!("cannot write {}: {e}", PathBuf::from(&target).display()))?;
            print(&format!(
                "{role} {} {}\n",
                sha256(&bytes).as_str(),
                file.display()
            ));
            Ok(())
        }
        Command::SignJob { key, kid, job } => {
            let pair = read_key_pair(&key).map_err(|e| e.to_string())?;
            let bytes = read_bytes(&job)?;
            let signature = sign_detached(new_id(KeyId::new, &kid)?, &pair, &bytes);
            let text = serde_json::to_string(&signature).map_err(|e| e.to_string())?;
            let target = job.with_extension("yaml.sig");
            std::fs::write(&target, format!("{text}\n"))
                .map_err(|e| format!("cannot write {}: {e}", target.display()))
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Serve(args) => serve(*args).await,
        other => run_offline(other),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}
