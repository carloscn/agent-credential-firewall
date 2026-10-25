//! `acf-agent` binary entry point. Behavior belongs in the library crate.
//!
//! Exit codes: 0 completed, 2 denied or failed, 1 usage or transport error.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use acf_agent::daemon;
use acf_agent::gateway::{self, AuthorityClient, GatewayClient};
use acf_agent::{AgentError, local};
use acf_protocol::{ActionResponse, BasisRequest, CreateTaskRequest, JobId, TaskHandle, TaskId};
use clap::{Args, Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};

/// ACF agent: local daemon and CLI.
#[derive(Parser)]
#[command(name = "acf-agent", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the local daemon: a Unix socket for agents, mTLS to the gateway.
    Daemon(DaemonArgs),
    /// Tasks on the local daemon.
    Task {
        #[command(subcommand)]
        command: TaskCommand,
    },
    /// Semantic actions.
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },
}

#[derive(Args)]
struct DaemonArgs {
    /// Socket path. Put it in a directory only the daemon can write to.
    #[arg(long)]
    socket: PathBuf,
    /// Socket mode in octal. Must not grant access to others.
    #[arg(long, default_value = "660", value_parser = parse_mode)]
    socket_mode: u32,
    /// UID allowed to connect; repeatable. Default: the daemon's own UID.
    #[arg(long = "allowed-uid", value_name = "UID")]
    allowed_uids: Vec<u32>,
    /// Gateway base URL (https).
    #[arg(long)]
    gateway: String,
    /// Client certificate chain (PEM, leaf first).
    #[arg(long)]
    client_cert: PathBuf,
    /// Client private key (PKCS#8 PEM, mode 0600).
    #[arg(long)]
    client_key: PathBuf,
    /// CA that issued the gateway's certificate (PEM). System roots are not used.
    #[arg(long)]
    gateway_ca: PathBuf,
    /// Capability Authority base URL (https). Every task then needs a
    /// capability from it.
    #[arg(long)]
    authority: Option<String>,
    /// CA that issued the authority's certificate (PEM). Default: `--gateway-ca`.
    #[arg(long, requires = "authority")]
    authority_ca: Option<PathBuf>,
}

#[derive(Subcommand)]
enum TaskCommand {
    /// Open a task and print its handle.
    Create {
        /// Daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Task identifier.
        #[arg(long)]
        task: String,
        /// Restrict the handle to this PID (for launchers).
        #[arg(long)]
        pid: Option<u32>,
        /// Ask the authority to authorize under this signed job definition.
        #[arg(long, conflicts_with = "scheduler")]
        job: Option<String>,
        /// Ask the authority to authorize as a configured scheduler.
        #[arg(long)]
        scheduler: bool,
        /// Proposed grant as ACTION@RESOURCE; repeatable. Default: the
        /// whole scope of the basis.
        #[arg(long = "grant", value_name = "ACTION@RESOURCE")]
        grants: Vec<String>,
        /// Proposed lifetime in seconds.
        #[arg(long)]
        ttl: Option<u32>,
    },
    /// Show a task.
    Status {
        /// Daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Task handle.
        #[arg(long)]
        handle: String,
    },
}

#[derive(Subcommand)]
enum ActionCommand {
    /// Execute one semantic action through the daemon (`--socket`) or a
    /// development gateway (`--gateway`).
    Execute {
        /// Daemon socket.
        #[arg(long, conflicts_with_all = ["gateway", "task"], requires = "task_handle")]
        socket: Option<PathBuf>,
        /// Task handle from `task create`.
        #[arg(long, requires = "socket")]
        task_handle: Option<String>,
        /// Development gateway base URL (plaintext loopback).
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        gateway: String,
        /// Task identifier, for the development gateway.
        #[arg(long, default_value = "dev-task")]
        task: String,
        /// Semantic action, for example `example.profile.get`.
        #[arg(long)]
        action: String,
        /// Registered resource, for example `example-api:development`.
        #[arg(long)]
        resource: String,
        /// Parameter as KEY=VALUE; VALUE is JSON if it parses, else a string.
        #[arg(long = "param", value_name = "KEY=VALUE")]
        params: Vec<String>,
    },
}

fn parse_mode(text: &str) -> Result<u32, String> {
    u32::from_str_radix(text, 8).map_err(|_| format!("`{text}` is not an octal mode"))
}

#[expect(clippy::print_stderr, reason = "daemon startup messages")]
async fn run_daemon(args: DaemonArgs) -> ExitCode {
    let clients = (|| {
        let key = gateway::read_private_key(&args.client_key)?;
        let certificate = gateway::read_public(&args.client_cert)?;
        let tls =
            gateway::client_config(&certificate, &key, &gateway::read_public(&args.gateway_ca)?)?;
        let authority = match &args.authority {
            Some(url) => {
                let ca =
                    gateway::read_public(args.authority_ca.as_ref().unwrap_or(&args.gateway_ca))?;
                Some(AuthorityClient::new(
                    url,
                    gateway::client_config(&certificate, &key, &ca)?,
                )?)
            }
            None => None,
        };
        Ok::<_, gateway::GatewayError>((GatewayClient::new(&args.gateway, tls)?, authority))
    })();
    let (client, authority) = match clients {
        Ok(clients) => clients,
        Err(error) => {
            eprintln!("acf-agent: {error}");
            return ExitCode::FAILURE;
        }
    };
    let socket = match daemon::bind(&args.socket, args.socket_mode) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("acf-agent: {error}");
            return ExitCode::FAILURE;
        }
    };
    let allowed: BTreeSet<u32> = if args.allowed_uids.is_empty() {
        BTreeSet::from([socket.owner()])
    } else {
        args.allowed_uids.into_iter().collect()
    };
    let path = socket.path().to_owned();
    eprintln!(
        "acf-agent daemon: listening on {} (mode {:o}, uids {allowed:?})",
        path.display(),
        args.socket_mode
    );
    let (Ok(mut terminate), Ok(mut interrupt)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return ExitCode::FAILURE;
    };
    tokio::select! {
        () = daemon::serve(socket, allowed, daemon::router(client, authority)) => {}
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    let _ = std::fs::remove_file(&path);
    ExitCode::SUCCESS
}

#[expect(clippy::print_stdout, reason = "CLI output")]
fn print(value: &impl serde::Serialize) -> bool {
    match serde_json::to_string_pretty(value) {
        Ok(text) => {
            println!("{text}");
            true
        }
        Err(_) => false,
    }
}

async fn task(command: TaskCommand) -> Result<ExitCode, AgentError> {
    let status = match command {
        TaskCommand::Create {
            socket,
            task,
            pid,
            job,
            scheduler,
            grants,
            ttl,
        } => {
            let basis = match (job, scheduler) {
                (Some(job), _) => Some(BasisRequest::Job {
                    job: JobId::new(job)?,
                }),
                (None, true) => Some(BasisRequest::Scheduler),
                (None, false) => None,
            };
            let request = CreateTaskRequest {
                task_id: TaskId::new(task)?,
                pid,
                basis,
                grants: grants
                    .iter()
                    .map(|g| acf_agent::parse_grant(g))
                    .collect::<Result<_, _>>()?,
                ttl_secs: ttl,
            };
            local::propose_task(&socket, &request).await?
        }
        TaskCommand::Status { socket, handle } => {
            local::task_status(&socket, &TaskHandle::new(handle)?).await?
        }
    };
    Ok(if print(&status) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

async fn execute(
    socket: Option<&Path>,
    task_handle: Option<&str>,
    gateway: &str,
    task: &str,
    action: &str,
    resource: &str,
    params: &[String],
) -> Result<ActionResponse, AgentError> {
    if let (Some(socket), Some(handle)) = (socket, task_handle) {
        let request = acf_agent::build_local_request(action, resource, handle, params)?;
        local::execute(socket, &request).await
    } else {
        let request = acf_agent::build_request(action, resource, task, params)?;
        acf_agent::send(gateway, &request).await
    }
}

#[expect(clippy::print_stderr, reason = "CLI output")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Daemon(args) => return run_daemon(args).await,
        Command::Task { command } => task(command).await,
        Command::Action {
            command:
                ActionCommand::Execute {
                    socket,
                    task_handle,
                    gateway,
                    task,
                    action,
                    resource,
                    params,
                },
        } => execute(
            socket.as_deref(),
            task_handle.as_deref(),
            &gateway,
            &task,
            &action,
            &resource,
            &params,
        )
        .await
        .map(|response| {
            if !print(&response) {
                ExitCode::FAILURE
            } else if matches!(response, ActionResponse::Completed { .. }) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }),
    };
    result.unwrap_or_else(|error| {
        eprintln!("acf-agent: {error}");
        ExitCode::FAILURE
    })
}
