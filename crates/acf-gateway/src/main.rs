//! `acf-gateway` binary entry point. Behavior belongs in the library crate.
//!
//! Milestone 0 runs only with the `development` feature and a `development`
//! deployment profile: plaintext loopback, a fixed development identity, and
//! the in-memory provider. Development secrets are read from environment
//! variables named on the command line; secret values are never accepted as
//! arguments.

use std::process::ExitCode;

#[cfg(feature = "development")]
mod development {
    use std::collections::BTreeSet;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use acf_config::{DeploymentProfile, SecretProviderConfig, load_yaml};
    use acf_connectors::{HttpConnector, HttpLimits, NetworkPolicy, SystemResolver};
    use acf_gateway::{Gateway, ProviderRegistry, ServerLimits, router};
    use acf_identity::DevelopmentIdentityProvider;
    use acf_policy::{Authorizer, AuthorizerSettings};
    use acf_protocol::{AudienceId, PrincipalId};
    use acf_secrets::{InMemoryProvider, SecretAdmin, SecretMaterial, SecretRef};
    use clap::Parser;

    /// Development gateway (Milestone 0).
    #[derive(Parser)]
    #[command(name = "acf-gateway", version)]
    struct Args {
        /// Configuration bundle (acf.config/v1).
        #[arg(long)]
        config: PathBuf,
        /// Policy document (acf.policy/v1).
        #[arg(long)]
        policy: PathBuf,
        /// Listen address. Must be loopback.
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: SocketAddr,
        /// Principal of the fixed development identity.
        #[arg(long, default_value = "dev-agent")]
        principal: String,
        /// This gateway's capability audience.
        #[arg(long, default_value = "acf-gateway-dev")]
        audience: String,
        /// Seed a development secret: `secret://...=ENV_VAR`. The value is read
        /// from the environment variable, never from the command line.
        #[arg(long = "secret-env", value_name = "REF=ENV_VAR")]
        secret_env: Vec<String>,
    }

    pub(crate) async fn run() -> Result<(), String> {
        let args = Args::parse();
        if !args.listen.ip().is_loopback() {
            return Err("the development gateway listens on loopback only".to_owned());
        }
        let read = |path: &PathBuf| {
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))
        };
        let config = load_yaml(&read(&args.config)?).map_err(|e| e.to_string())?;
        if config.deployment().profile != DeploymentProfile::Development {
            return Err(
                "production serving requires TLS client identity (WP-08); refusing to start"
                    .to_owned(),
            );
        }

        let mut registry = ProviderRegistry::default();
        let mut memory = std::collections::BTreeMap::new();
        for (namespace, provider) in config.providers() {
            match provider {
                SecretProviderConfig::InMemory => {
                    let store = Arc::new(InMemoryProvider::new([namespace.clone()]));
                    registry = registry.with(namespace.as_str(), store.clone());
                    memory.insert(namespace.to_string(), store);
                }
                _ => {
                    return Err(format!(
                        "provider for `{namespace}` is not available in Milestone 0"
                    ));
                }
            }
        }
        for entry in &args.secret_env {
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

        let settings = AuthorizerSettings {
            audience: AudienceId::new(args.audience).map_err(|e| e.to_string())?,
            clock_skew_secs: 30,
        };
        let authorizer =
            Authorizer::new(config, &read(&args.policy)?, settings).map_err(|e| e.to_string())?;
        let identity = Arc::new(DevelopmentIdentityProvider::new(
            PrincipalId::new(args.principal).map_err(|e| e.to_string())?,
            None,
            BTreeSet::new(),
            None,
        ));
        let connector = Arc::new(
            HttpConnector::new(
                NetworkPolicy::development_loopback(),
                Arc::new(SystemResolver),
                HttpLimits::default(),
            )
            .map_err(|e| e.to_string())?,
        );
        let gateway =
            Gateway::new(authorizer, identity, registry, connector).map_err(|e| e.to_string())?;

        let listener = tokio::net::TcpListener::bind(args.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
        report(&format!(
            "acf-gateway (development) listening on http://{}",
            args.listen
        ));
        axum::serve(listener, router(Arc::new(gateway), ServerLimits::default()))
            .await
            .map_err(|e| e.to_string())
    }

    #[expect(
        clippy::print_stderr,
        reason = "startup message; telemetry arrives later"
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
    fail("built without the `development` feature; production wiring arrives with WP-08 and WP-11")
}

#[expect(
    clippy::print_stderr,
    reason = "fatal startup error; telemetry arrives later"
)]
fn fail(message: &str) -> ExitCode {
    eprintln!("acf-gateway: {message}");
    ExitCode::FAILURE
}
