//! `acf-gateway` binary entry point. Behavior belongs in the library crate.
//!
//! Runs only with the `development` feature and a `development` deployment
//! profile until production startup validation lands (WP-11). Two transports:
//!
//! - **mTLS** (`--tls-cert`, `--tls-key`, `--client-ca`, `--devices`): TLS 1.3
//!   with mandatory client certificates; identity comes from the device
//!   registry (ADR 0002).
//! - **Plaintext loopback** (no TLS flags): a fixed development identity.
//!
//! With `--authority-keys`, every request must carry a task capability
//! signed by one of those keys (ADR 0003).
//!
//! Development secrets are read from environment variables named on the
//! command line; secret values are never accepted as arguments.

use std::process::ExitCode;

#[cfg(feature = "development")]
mod development {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use acf_audit::{AuditHasher, GatewayInfo, JsonLinesSink};
    use acf_config::{
        DeploymentProfile, SecretProviderConfig, ValidatedConfig, load_yaml, parse_yaml,
    };
    use acf_connectors::{HttpConnector, HttpLimits, NetworkPolicy, SystemResolver};
    use acf_gateway::{
        AuditSettings, Gateway, ProviderRegistry, RateLimits, ServerLimits, StateSettings, router,
        serve_tls, server_config,
    };
    use acf_identity::{
        AuthorityKeys, CapabilityVerifier, DevelopmentIdentityProvider, DeviceRegistry,
        IdentityContextProvider, MtlsIdentityProvider, watch_registry,
    };
    use acf_policy::{Authorizer, AuthorizerSettings};
    use acf_protocol::{AudienceId, IssuerId, PrincipalId};
    use acf_secrets::{InMemoryProvider, SecretAdmin, SecretMaterial, SecretRef};
    use acf_state::SqliteStateStore;
    use clap::Parser;

    /// Development gateway.
    #[derive(Parser)]
    #[command(name = "acf-gateway", version)]
    struct Args {
        /// Configuration bundle (acf.config/v1).
        #[arg(long)]
        config: PathBuf,
        /// Policy document (acf.policy/v1).
        #[arg(long)]
        policy: PathBuf,
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
        #[arg(long, default_value = "dev-agent", conflicts_with = "tls_cert")]
        principal: String,
        /// Authority public keys (acf.authority-keys/v1). Requires a
        /// capability on every request.
        #[arg(long)]
        authority_keys: Option<PathBuf>,
        /// This gateway's capability audience.
        #[arg(long, default_value = "acf-gateway-dev")]
        audience: String,
        /// Seed a development secret: `secret://...=ENV_VAR`. The value is read
        /// from the environment variable, never from the command line.
        #[arg(long = "secret-env", value_name = "REF=ENV_VAR")]
        secret_env: Vec<String>,
        /// Append audit events as JSON lines to this file. Default: stderr.
        #[arg(long)]
        audit_log: Option<PathBuf>,
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

    fn read(path: &Path) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    }

    fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
        std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    }

    pub(crate) async fn run() -> Result<(), String> {
        let args = Args::parse();
        let config = load_yaml(&read(&args.config)?).map_err(|e| e.to_string())?;
        if config.deployment().profile != DeploymentProfile::Development {
            return Err(
                "production startup validation arrives with WP-11; refusing to start".to_owned(),
            );
        }
        let registry = providers(&config, &args.secret_env).await?;
        let settings = AuthorizerSettings {
            audience: AudienceId::new(args.audience.clone()).map_err(|e| e.to_string())?,
            clock_skew_secs: 30,
        };
        let authorizer =
            Authorizer::new(config, &read(&args.policy)?, settings).map_err(|e| e.to_string())?;
        let identity = identity(&args)?;
        let connector = Arc::new(
            HttpConnector::new(
                NetworkPolicy::development_loopback(),
                Arc::new(SystemResolver),
                HttpLimits::default(),
            )
            .map_err(|e| e.to_string())?,
        );
        let audit = audit_settings(args.audit_log.as_ref(), args.gateway_id.clone())?;
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
        let identity_provider: Arc<dyn IdentityContextProvider> = match &identity {
            Identity::Development(provider) => provider.clone(),
            Identity::Mtls(provider, _) => provider.clone(),
        };
        let mut gateway = Gateway::new(
            authorizer,
            identity_provider,
            registry,
            connector,
            audit,
            state,
        )
        .map_err(|e| e.to_string())?;
        if let Some(path) = &args.authority_keys {
            let keys: AuthorityKeys = parse_yaml(&read(path)?).map_err(|e| e.to_string())?;
            gateway = gateway
                .require_capabilities(CapabilityVerifier::new(keys).map_err(|e| e.to_string())?);
        }
        let app = router(Arc::new(gateway), ServerLimits::default());

        let listener = tokio::net::TcpListener::bind(args.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
        match identity {
            Identity::Development(_) => {
                report(&format!(
                    "acf-gateway (development, plaintext) listening on http://{}",
                    args.listen
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
                    "acf-gateway (development, mTLS) listening on https://{}",
                    args.listen
                ));
                serve_tls(listener, tls, app)
                    .await
                    .map_err(|e| e.to_string())
            }
        }
    }

    enum Identity {
        Development(Arc<DevelopmentIdentityProvider>),
        Mtls(Arc<MtlsIdentityProvider>, PathBuf),
    }

    fn identity(args: &Args) -> Result<Identity, String> {
        let Some(devices) = &args.devices else {
            if !args.listen.ip().is_loopback() {
                return Err(
                    "plaintext mode listens on loopback only; use --tls-cert for other addresses"
                        .to_owned(),
                );
            }
            return Ok(Identity::Development(Arc::new(
                DevelopmentIdentityProvider::new(
                    PrincipalId::new(args.principal.clone()).map_err(|e| e.to_string())?,
                    None,
                    BTreeSet::new(),
                    None,
                ),
            )));
        };
        let registry: DeviceRegistry = parse_yaml(&read(devices)?).map_err(|e| e.to_string())?;
        let issuer =
            IssuerId::new(format!("{}-mtls", args.gateway_id)).map_err(|e| e.to_string())?;
        let provider = MtlsIdentityProvider::new(issuer, registry).map_err(|e| e.to_string())?;
        Ok(Identity::Mtls(Arc::new(provider), devices.clone()))
    }

    async fn providers(
        config: &ValidatedConfig,
        secret_env: &[String],
    ) -> Result<ProviderRegistry, String> {
        let mut registry = ProviderRegistry::default();
        let mut memory = BTreeMap::new();
        for (namespace, provider) in config.providers() {
            match provider {
                SecretProviderConfig::InMemory => {
                    let store = Arc::new(InMemoryProvider::new([namespace.clone()]));
                    registry = registry.with(namespace.as_str(), store.clone());
                    memory.insert(namespace.to_string(), store);
                }
                _ => return Err(format!("provider for `{namespace}` is not available yet")),
            }
        }
        for entry in secret_env {
            let (reference, variable) = entry
                .split_once('=')
                .ok_or_else(|| format!("--secret-env expects REF=ENV_VAR, got `{entry}`"))?;
            let reference = SecretRef::parse(reference).map_err(|e| e.to_string())?;
            let registration = config
                .secret(&reference)
                .ok_or_else(|| format!("`{reference}` has no secret registration"))?;
            let value = std::env::var(variable)
                .map_err(|_| format!("environment variable `{variable}` is not set"))?;
            let store = memory
                .get(reference.namespace())
                .ok_or_else(|| format!("no in-memory provider for `{reference}`"))?;
            store
                .put(
                    &reference,
                    SecretMaterial::from_string(value),
                    registration.use_binding.clone(),
                )
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(registry)
    }

    /// Fail-closed JSON-lines audit to a file, or to stderr.
    fn audit_settings(path: Option<&PathBuf>, gateway_id: String) -> Result<AuditSettings, String> {
        let writer: Box<dyn std::io::Write + Send> = match path {
            Some(path) => Box::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| format!("cannot open audit log {}: {e}", path.display()))?,
            ),
            None => Box::new(std::io::stderr()),
        };
        Ok(AuditSettings {
            sink: Arc::new(JsonLinesSink::new(writer)),
            hasher: AuditHasher::random().map_err(|e| e.to_string())?,
            // An allowed request runs only after its decision is recorded.
            required: true,
            gateway: GatewayInfo {
                id: gateway_id,
                build: "development".to_owned(),
                deployment_profile: "development".to_owned(),
            },
        })
    }

    #[expect(
        clippy::print_stderr,
        reason = "operator messages; telemetry arrives later"
    )]
    fn report(message: &str) {
        eprintln!("{message}");
    }
}

#[cfg(feature = "development")]
#[tokio::main]
async fn main() -> ExitCode {
    match development::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => fail(&message),
    }
}

#[cfg(not(feature = "development"))]
fn main() -> ExitCode {
    fail(
        "built without the `development` feature; production startup validation arrives with WP-11",
    )
}

#[expect(
    clippy::print_stderr,
    reason = "fatal startup error; telemetry arrives later"
)]
fn fail(message: &str) -> ExitCode {
    eprintln!("acf-gateway: {message}");
    ExitCode::FAILURE
}
