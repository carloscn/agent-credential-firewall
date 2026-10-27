//! `acf-gateway` binary entry point. Behavior belongs in the library crate.
//!
//! Runs in both build flavors (ADR 0004):
//!
//! - **release** (no `development` feature): mTLS only (`--tls-cert`,
//!   `--tls-key`, `--client-ca`, `--devices`; ADR 0002), no in-memory
//!   provider, no development identity. Runs either deployment profile.
//! - **development**: adds the in-memory provider seeded from environment
//!   variables, and a plaintext loopback listener with a fixed development
//!   identity. Refuses the `production` profile.
//!
//! Configuration is a bundle (`--config`), connector profiles (`--profiles`
//! directory or inline), and a policy (`--policy`). With `--config-trust`,
//! each is admitted by a role-bound signature (`<file>.sig`) or a pinned
//! digest; `production` requires it and checks everything in design §13.4.
//!
//! With `--authority-keys`, every request must carry a task capability signed
//! by one of those keys (ADR 0003). Secret values are never accepted as
//! arguments.
//!
//! Audit events are hash-chained (ADR 0005). With `--checkpoint-url`, the
//! chain head is signed with `--audit-key` and published to an external
//! collector; if none is accepted for `--checkpoint-max-lag-secs`, the audit
//! sink refuses new events and allowed requests fail closed.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use acf_audit::{
    AnchorState, AuditHasher, ChainedJsonSink, CheckpointSigner, GatewayInfo, run_checkpoints,
};
use acf_config::{
    ConfigRole, ConfigTrust, DeploymentProfile, SecretProviderConfig, ValidatedConfig, parse_yaml,
};
use acf_connectors::{HttpConnector, HttpLimits, NetworkPolicy, SystemResolver};
use acf_gateway::{
    AuditSettings, BUILD_FLAVOR, EncryptedStore, Gateway, HttpCheckpointPublisher,
    ProviderRegistry, RateLimits, ServerLimits, StartupFacts, StateSettings, load_config,
    production_refusals, profile_sources, read, read_bytes, router, serve_tls, server_config,
    source, text,
};
use acf_identity::{
    AuthorityKeys, CapabilityVerifier, DeviceRegistry, IdentityContextProvider,
    MtlsIdentityProvider, client_config, read_key_pair, watch_registry,
};
use acf_policy::{Authorizer, AuthorizerSettings};
use acf_protocol::{AudienceId, IssuerId, KeyId, Sha256Digest};
use acf_state::SqliteStateStore;
use clap::Parser;

/// ACF Credential Gateway.
#[derive(Parser)]
#[command(name = "acf-gateway", version)]
struct Args {
    /// Configuration bundle (acf.config/v1); role `secret-admin`.
    #[arg(long)]
    config: PathBuf,
    /// Directory of connector profiles (`*.yaml`, acf.profile/v1); role
    /// `profile-author`. Required under `production`.
    #[arg(long)]
    profiles: Option<PathBuf>,
    /// Policy document (acf.policy/v1); role `policy-admin`.
    #[arg(long)]
    policy: PathBuf,
    /// Configuration trust anchor (acf.config-trust/v1). Required under
    /// `production`.
    #[arg(long)]
    config_trust: Option<PathBuf>,
    /// Listen address. Plaintext mode requires loopback.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// Server certificate chain (PEM, leaf first). Enables mTLS.
    #[arg(long, requires_all = ["tls_key", "client_ca", "devices"])]
    tls_cert: Option<PathBuf>,
    /// Server private key (PKCS#8 PEM).
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// CA bundle that issues daemon client certificates (PEM).
    #[arg(long, requires = "tls_cert")]
    client_ca: Option<PathBuf>,
    /// Device registry (acf.devices/v1), re-read when it changes.
    #[arg(long, requires = "tls_cert")]
    devices: Option<PathBuf>,
    /// Principal of the fixed development identity (plaintext mode).
    #[cfg(feature = "development")]
    #[arg(long, default_value = "dev-agent", conflicts_with = "tls_cert")]
    principal: String,
    /// Authority public keys (acf.authority-keys/v1). Requires a capability
    /// on every request.
    #[arg(long)]
    authority_keys: Option<PathBuf>,
    /// This gateway's capability audience.
    #[arg(long, default_value = "acf-gateway-dev")]
    audience: String,
    /// Seed a development secret: `secret://...=ENV_VAR`. The value is read
    /// from the environment variable, never from the command line.
    #[cfg(feature = "development")]
    #[arg(long = "secret-env", value_name = "REF=ENV_VAR")]
    secret_env: Vec<String>,
    /// Append audit events as JSON lines to this file. Default: stderr
    /// (refused under `production`).
    #[arg(long)]
    audit_log: Option<PathBuf>,
    /// Ed25519 key (PKCS#8 PEM, mode 0600) that signs audit checkpoints.
    #[arg(long, requires = "audit_kid")]
    audit_key: Option<PathBuf>,
    /// Identifier of the audit key, as the collector knows it.
    #[arg(long, requires = "audit_key")]
    audit_kid: Option<String>,
    /// Checkpoint collector URL, for example
    /// `https://control-plane:8444/v1/audit/checkpoints`. Required under
    /// `production`.
    #[arg(long, requires_all = ["audit_key", "checkpoint_client_cert", "checkpoint_client_key", "checkpoint_ca"])]
    checkpoint_url: Option<String>,
    /// Client certificate chain this gateway presents to the collector (PEM).
    #[arg(long, requires = "checkpoint_url")]
    checkpoint_client_cert: Option<PathBuf>,
    /// Private key for that certificate (PKCS#8 PEM).
    #[arg(long, requires = "checkpoint_url")]
    checkpoint_client_key: Option<PathBuf>,
    /// CA that issued the collector's certificate (PEM).
    #[arg(long, requires = "checkpoint_url")]
    checkpoint_ca: Option<PathBuf>,
    /// Seconds between checkpoints while the log grows.
    #[arg(long, default_value_t = 30)]
    checkpoint_interval_secs: u64,
    /// Seconds the log may run ahead of its newest accepted checkpoint
    /// before allowed requests fail closed.
    #[arg(long, default_value_t = 300)]
    checkpoint_max_lag_secs: u64,
    /// Gateway identifier recorded in audit events.
    #[arg(long, default_value = "acf-gateway-dev")]
    gateway_id: String,
    /// Durable state database (replay cache, revocations, counters).
    #[arg(long)]
    state_db: PathBuf,
    /// Requests per principal per minute.
    #[arg(long)]
    rate_limit_principal: Option<u32>,
    /// Requests per resource per minute.
    #[arg(long)]
    rate_limit_resource: Option<u32>,
    /// Requests per action per minute.
    #[arg(long)]
    rate_limit_action: Option<u32>,
}

/// The configuration, admitted if a trust anchor was given.
struct Loaded {
    config: ValidatedConfig,
    policy: String,
    digest: Option<Sha256Digest>,
    trust_anchor_writable: bool,
}

fn load(args: &Args) -> Result<Loaded, String> {
    let bundle = source(&args.config)?;
    let policy = source(&args.policy)?;
    let profiles = match &args.profiles {
        Some(dir) => profile_sources(dir)?,
        None => Vec::new(),
    };
    let config = load_config(&bundle, &profiles)?;

    let (digest, trust_anchor_writable) = match &args.config_trust {
        Some(path) => {
            let mode = std::fs::metadata(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?
                .permissions()
                .mode();
            let trust = ConfigTrust::parse(&read(path)?).map_err(|e| e.to_string())?;
            let mut documents = vec![
                (ConfigRole::SecretAdmin, &bundle),
                (ConfigRole::PolicyAdmin, &policy),
            ];
            documents.extend(profiles.iter().map(|p| (ConfigRole::ProfileAuthor, p)));
            let digest = trust.admit_all(&documents).map_err(|errors| {
                let lines: Vec<String> = errors.iter().map(ToString::to_string).collect();
                format!("configuration not admitted:\n  - {}", lines.join("\n  - "))
            })?;
            (Some(digest), mode & 0o022 != 0)
        }
        None => (None, false),
    };
    Ok(Loaded {
        config,
        policy: text(&policy)?.to_owned(),
        digest,
        trust_anchor_writable,
    })
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    let loaded = load(&args)?;
    let profile = loaded.config.deployment().profile;
    if profile == DeploymentProfile::Production {
        let facts = StartupFacts {
            development_build: cfg!(feature = "development"),
            config_admitted: loaded.digest.is_some(),
            trust_anchor_writable: loaded.trust_anchor_writable,
            mtls: args.tls_cert.is_some(),
            capabilities_required: args.authority_keys.is_some(),
            audit_sink: args.audit_log.is_some(),
            audit_anchored: args.checkpoint_url.is_some(),
        };
        let refusals = production_refusals(&facts, &loaded.config);
        if !refusals.is_empty() {
            return Err(format!(
                "refusing to start under the production profile:\n  - {}",
                refusals.join("\n  - ")
            ));
        }
    }
    let profile_name = match profile {
        DeploymentProfile::Development => "development",
        DeploymentProfile::Production => "production",
    };
    let network = match profile {
        DeploymentProfile::Development => NetworkPolicy::development_loopback(),
        DeploymentProfile::Production => NetworkPolicy::production(),
    };

    let registry = providers(&args, &loaded.config).await?;
    let authorizer = Authorizer::new(
        loaded.config,
        &loaded.policy,
        AuthorizerSettings {
            audience: AudienceId::new(args.audience.clone()).map_err(|e| e.to_string())?,
            clock_skew_secs: 30,
        },
    )
    .map_err(|e| e.to_string())?;
    let identity = identity(&args)?;
    let connector = Arc::new(
        HttpConnector::new(network, Arc::new(SystemResolver), HttpLimits::default())
            .map_err(|e| e.to_string())?,
    );
    let gateway_info = GatewayInfo {
        id: args.gateway_id.clone(),
        build: BUILD_FLAVOR.to_owned(),
        deployment_profile: profile_name.to_owned(),
        config_digest: loaded.digest.as_ref().map(|d| d.as_str().to_owned()),
    };
    let (audit, audit_summary) = audit_settings(&args, gateway_info)?;
    let store = SqliteStateStore::open(&args.state_db)
        .map_err(|_| format!("cannot open state database {}", args.state_db.display()))?;
    let mut state = StateSettings::new(
        Arc::new(store),
        time::OffsetDateTime::now_utc().unix_timestamp(),
    );
    state.rate_limits = RateLimits {
        per_principal_per_minute: args.rate_limit_principal,
        per_resource_per_minute: args.rate_limit_resource,
        per_action_per_minute: args.rate_limit_action,
    };
    let mut gateway = Gateway::new(
        authorizer,
        identity.provider(),
        registry,
        connector,
        audit,
        state,
    )
    .map_err(|e| e.to_string())?;
    if let Some(path) = &args.authority_keys {
        let keys: AuthorityKeys = parse_yaml(&read(path)?).map_err(|e| e.to_string())?;
        gateway =
            gateway.require_capabilities(CapabilityVerifier::new(keys).map_err(|e| e.to_string())?);
    }
    let summary = format!(
        "{BUILD_FLAVOR} build, {profile_name} profile, config {}, {audit_summary}",
        loaded
            .digest
            .as_ref()
            .map_or("not admitted", Sha256Digest::as_str)
    );
    serve(
        &args,
        identity,
        router(Arc::new(gateway), ServerLimits::default()),
        &summary,
    )
    .await
}

async fn serve(
    args: &Args,
    identity: Identity,
    app: axum::Router,
    summary: &str,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
    let address = listener.local_addr().unwrap_or(args.listen);
    match identity {
        #[cfg(feature = "development")]
        Identity::Development(_) => {
            report(&format!(
                "acf-gateway ({summary}, plaintext) listening on http://{address}"
            ));
            axum::serve(listener, app).await.map_err(|e| e.to_string())
        }
        Identity::Mtls(provider, devices) => {
            let tls = server_config(
                &read_bytes(args.tls_cert.as_deref().unwrap_or(Path::new("")))?,
                &read_bytes(args.tls_key.as_deref().unwrap_or(Path::new("")))?,
                &read_bytes(args.client_ca.as_deref().unwrap_or(Path::new("")))?,
            )
            .map_err(|e| e.to_string())?;
            tokio::spawn(watch_registry(
                provider,
                devices,
                |text| parse_yaml::<DeviceRegistry>(text).map_err(|e| e.to_string()),
                report,
            ));
            report(&format!(
                "acf-gateway ({summary}, mTLS) listening on https://{address}"
            ));
            serve_tls(listener, tls, app)
                .await
                .map_err(|e| e.to_string())
        }
    }
}

enum Identity {
    #[cfg(feature = "development")]
    Development(Arc<acf_identity::DevelopmentIdentityProvider>),
    Mtls(Arc<MtlsIdentityProvider>, PathBuf),
}

impl Identity {
    fn provider(&self) -> Arc<dyn IdentityContextProvider> {
        match self {
            #[cfg(feature = "development")]
            Self::Development(provider) => provider.clone(),
            Self::Mtls(provider, _) => provider.clone(),
        }
    }
}

fn identity(args: &Args) -> Result<Identity, String> {
    let Some(devices) = &args.devices else {
        return development::identity(args);
    };
    let registry: DeviceRegistry = parse_yaml(&read(devices)?).map_err(|e| e.to_string())?;
    let issuer = IssuerId::new(format!("{}-mtls", args.gateway_id)).map_err(|e| e.to_string())?;
    let provider = MtlsIdentityProvider::new(issuer, registry).map_err(|e| e.to_string())?;
    Ok(Identity::Mtls(Arc::new(provider), devices.clone()))
}

async fn providers(args: &Args, config: &ValidatedConfig) -> Result<ProviderRegistry, String> {
    let mut registry = ProviderRegistry::default();
    for (namespace, provider) in config.providers() {
        registry = match provider {
            SecretProviderConfig::InMemory => {
                development::in_memory(registry, args, config, namespace).await?
            }
            SecretProviderConfig::EncryptedLocal { .. } => {
                let store = EncryptedStore::from_config(namespace, provider)?;
                let opened = store.open()?;
                report(&store.describe());
                registry.with(namespace.as_str(), Arc::new(opened))
            }
            SecretProviderConfig::External { adapter, .. } => {
                return Err(format!(
                    "secret_providers.{namespace}: no `{adapter}` adapter in this build"
                ));
            }
        };
    }
    Ok(registry)
}

/// Development-build pieces: the in-memory provider and the development
/// identity. Release builds get stubs that refuse.
#[cfg(feature = "development")]
mod development {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use acf_config::ValidatedConfig;
    use acf_gateway::ProviderRegistry;
    use acf_identity::DevelopmentIdentityProvider;
    use acf_protocol::PrincipalId;
    use acf_secrets::{InMemoryProvider, Namespace, SecretAdmin, SecretMaterial, SecretRef};

    use super::{Args, Identity};

    pub(super) fn identity(args: &Args) -> Result<Identity, String> {
        if !args.listen.ip().is_loopback() {
            return Err(
                "plaintext mode listens on loopback only; use --tls-cert for other addresses"
                    .to_owned(),
            );
        }
        Ok(Identity::Development(Arc::new(
            DevelopmentIdentityProvider::new(
                PrincipalId::new(args.principal.clone()).map_err(|e| e.to_string())?,
                None,
                BTreeSet::new(),
                None,
            ),
        )))
    }

    /// Registers an in-memory provider for `namespace`, seeded from the
    /// `--secret-env` entries in that namespace.
    pub(super) async fn in_memory(
        registry: ProviderRegistry,
        args: &Args,
        config: &ValidatedConfig,
        namespace: &Namespace,
    ) -> Result<ProviderRegistry, String> {
        let store = Arc::new(InMemoryProvider::new([namespace.clone()]));
        for entry in &args.secret_env {
            let (reference, variable) = entry
                .split_once('=')
                .ok_or_else(|| format!("--secret-env expects REF=ENV_VAR, got `{entry}`"))?;
            let reference = SecretRef::parse(reference).map_err(|e| e.to_string())?;
            if reference.namespace() != namespace.as_str() {
                continue;
            }
            let registration = config
                .secret(&reference)
                .ok_or_else(|| format!("`{reference}` has no secret registration"))?;
            let value = std::env::var(variable)
                .map_err(|_| format!("environment variable `{variable}` is not set"))?;
            store
                .put(
                    &reference,
                    SecretMaterial::from_string(value),
                    registration.use_binding.clone(),
                )
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(registry.with(namespace.as_str(), store))
    }
}

#[cfg(not(feature = "development"))]
mod development {
    use acf_config::ValidatedConfig;
    use acf_gateway::ProviderRegistry;
    use acf_secrets::Namespace;

    use super::{Args, Identity};

    pub(super) fn identity(_: &Args) -> Result<Identity, String> {
        Err(
            "release builds require mTLS: pass --tls-cert, --tls-key, --client-ca, and --devices"
                .to_owned(),
        )
    }

    #[expect(
        clippy::unused_async,
        reason = "same signature as the development build"
    )]
    pub(super) async fn in_memory(
        _: ProviderRegistry,
        _: &Args,
        _: &ValidatedConfig,
        namespace: &Namespace,
    ) -> Result<ProviderRegistry, String> {
        Err(format!(
            "secret_providers.{namespace}: the in-memory provider is not in release builds"
        ))
    }
}

/// Hash-chained, fail-closed JSON-lines audit to a file (continuing its
/// log) or to stderr, and, with `--checkpoint-url`, signed checkpoints to an
/// external collector. Returns the settings and a one-line description.
fn audit_settings(args: &Args, gateway: GatewayInfo) -> Result<(AuditSettings, String), String> {
    let sink = match &args.audit_log {
        Some(path) => ChainedJsonSink::open(path).map_err(|e| e.to_string())?,
        None => ChainedJsonSink::new(Box::new(std::io::stderr())).map_err(|e| e.to_string())?,
    };
    let mut summary = format!("audit {}", sink.log());
    let sink = if let Some(url) = &args.checkpoint_url {
        summary.push_str(" anchored by checkpoints");
        anchored(args, sink, url, &gateway.id)?
    } else {
        summary.push_str(" with local hash chain only");
        Arc::new(sink)
    };
    Ok((
        AuditSettings {
            sink,
            hasher: AuditHasher::random().map_err(|e| e.to_string())?,
            // An allowed request runs only after its decision is recorded.
            required: true,
            gateway,
        },
        summary,
    ))
}

/// Gates `sink` on checkpoint freshness and starts publishing checkpoints
/// of its head to `url`.
fn anchored(
    args: &Args,
    sink: ChainedJsonSink,
    url: &str,
    gateway_id: &str,
) -> Result<Arc<ChainedJsonSink>, String> {
    let anchor = Arc::new(AnchorState::new(Duration::from_secs(
        args.checkpoint_max_lag_secs,
    )));
    let sink = Arc::new(sink.with_anchor(anchor.clone()));
    let path = |p: &Option<PathBuf>| p.as_deref().unwrap_or(Path::new("")).to_owned();
    let tls = client_config(
        &read_bytes(&path(&args.checkpoint_client_cert))?,
        &read_bytes(&path(&args.checkpoint_client_key))?,
        &read_bytes(&path(&args.checkpoint_ca))?,
    )
    .map_err(|e| format!("checkpoint client: {e}"))?;
    let publisher = Arc::new(HttpCheckpointPublisher::new(url, tls)?);
    let key = read_key_pair(&path(&args.audit_key)).map_err(|e| e.to_string())?;
    let kid = KeyId::new(args.audit_kid.clone().unwrap_or_default())
        .map_err(|e| format!("--audit-kid: {e}"))?;
    let signer = CheckpointSigner::new(kid, gateway_id.to_owned(), key);
    tokio::spawn(run_checkpoints(
        sink.clone(),
        signer,
        publisher,
        anchor,
        Duration::from_secs(args.checkpoint_interval_secs.max(1)),
        report,
    ));
    Ok(sink)
}

#[expect(
    clippy::print_stderr,
    reason = "operator messages; telemetry arrives later"
)]
fn report(message: &str) {
    eprintln!("{message}");
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            report(&format!("acf-gateway: {message}"));
            ExitCode::FAILURE
        }
    }
}
