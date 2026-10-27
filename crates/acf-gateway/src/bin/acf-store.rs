//! `acf-store`: administers encrypted local secret stores (encrypted-local.md
//! §7). An operator tool, never an agent action.
//!
//! - `init --namespace NS`: create the store configured for `NS`.
//! - `put SECRET_REF`: store a value read from standard input, with the use
//!   binding the configuration registers for that reference. One trailing
//!   newline is removed. Values are never accepted as arguments or printed.
//! - `delete SECRET_REF`: leave a tombstone, so the version cannot be reused.
//! - `list --namespace NS`: references, versions, and bindings; no values.
//!
//! The store location and key source come from the same configuration the
//! gateway loads (`--config`, `--profiles`).

use std::io::Read as _;
use std::path::PathBuf;
use std::process::ExitCode;

use acf_config::ValidatedConfig;
use acf_gateway::{EncryptedStore, load_config, profile_sources, source};
use acf_secrets::{Namespace, SecretAdmin, SecretMaterial, SecretRef, SecretScope};
use clap::{Parser, Subcommand};

/// Administer encrypted local secret stores.
#[derive(Parser)]
#[command(name = "acf-store", version)]
struct Cli {
    /// Configuration bundle (acf.config/v1).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Directory of connector profiles, when they are not inline.
    #[arg(long, global = true)]
    profiles: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the store for a namespace.
    Init {
        /// Namespace whose provider is `encrypted-local`.
        #[arg(long)]
        namespace: String,
    },
    /// Store the value on standard input under a registered reference.
    Put {
        /// `secret://...`
        reference: String,
    },
    /// Delete a reference, leaving a tombstone.
    Delete {
        /// `secret://...`
        reference: String,
    },
    /// List references and versions in a namespace; never values.
    List {
        /// Namespace.
        #[arg(long)]
        namespace: String,
    },
}

#[expect(clippy::print_stdout, reason = "command output")]
fn print(text: &str) {
    println!("{text}");
}

fn store(config: &ValidatedConfig, namespace: &Namespace) -> Result<EncryptedStore, String> {
    let provider = config
        .provider(namespace)
        .ok_or_else(|| format!("no secret provider for namespace `{namespace}`"))?;
    EncryptedStore::from_config(namespace, provider)
}

fn stdin_value() -> Result<SecretMaterial, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read standard input: {e}"))?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        return Err("standard input is empty".to_owned());
    }
    Ok(SecretMaterial::from_bytes(bytes))
}

async fn run(cli: Cli) -> Result<(), String> {
    let config_path = cli.config.ok_or("--config is required")?;
    let profiles = match &cli.profiles {
        Some(dir) => profile_sources(dir)?,
        None => Vec::new(),
    };
    let config = load_config(&source(&config_path)?, &profiles)?;
    match cli.command {
        Command::Init { namespace } => {
            let namespace = Namespace::new(namespace).map_err(|e| e.to_string())?;
            let store = store(&config, &namespace)?;
            store.initialize()?;
            print(&format!("created {}", store.describe()));
        }
        Command::Put { reference } => {
            let reference = SecretRef::parse(reference).map_err(|e| e.to_string())?;
            let registration = config
                .secret(&reference)
                .ok_or_else(|| format!("`{reference}` has no secret registration"))?;
            let namespace = Namespace::new(reference.namespace()).map_err(|e| e.to_string())?;
            let provider = store(&config, &namespace)?.open()?;
            let version = provider
                .put(&reference, stdin_value()?, registration.use_binding.clone())
                .await
                .map_err(|e| e.to_string())?;
            print(&format!("stored {reference} {version}"));
        }
        Command::Delete { reference } => {
            let reference = SecretRef::parse(reference).map_err(|e| e.to_string())?;
            let namespace = Namespace::new(reference.namespace()).map_err(|e| e.to_string())?;
            let provider = store(&config, &namespace)?.open()?;
            provider
                .delete(&reference)
                .await
                .map_err(|e| e.to_string())?;
            print(&format!("deleted {reference}"));
        }
        Command::List { namespace } => {
            let namespace = Namespace::new(namespace).map_err(|e| e.to_string())?;
            let provider = store(&config, &namespace)?.open()?;
            let scope = SecretScope::namespace(namespace);
            for entry in provider
                .list_metadata(&scope)
                .await
                .map_err(|e| e.to_string())?
            {
                print(&format!("{} {}", entry.reference, entry.version));
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[expect(clippy::print_stderr, reason = "operator error")]
            {
                eprintln!("acf-store: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
