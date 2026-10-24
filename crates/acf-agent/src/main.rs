//! `acf-agent` binary entry point. Behavior belongs in the library crate.
//!
//! Exit codes: 0 completed, 2 denied or failed, 1 usage or transport error.

use std::process::ExitCode;

use acf_protocol::ActionResponse;
use clap::{Parser, Subcommand};

/// ACF agent (development CLI, Milestone 0).
#[derive(Parser)]
#[command(name = "acf-agent", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Semantic actions.
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },
}

#[derive(Subcommand)]
enum ActionCommand {
    /// Execute one semantic action through the gateway.
    Execute {
        /// Gateway base URL.
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        gateway: String,
        /// Semantic action, for example `example.profile.get`.
        #[arg(long)]
        action: String,
        /// Registered resource, for example `example-api:development`.
        #[arg(long)]
        resource: String,
        /// Task identifier.
        #[arg(long, default_value = "dev-task")]
        task: String,
        /// Parameter as KEY=VALUE; VALUE is JSON if it parses, else a string.
        #[arg(long = "param", value_name = "KEY=VALUE")]
        params: Vec<String>,
    },
}

#[expect(clippy::print_stdout, clippy::print_stderr, reason = "CLI output")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Command::Action {
        command:
            ActionCommand::Execute {
                gateway,
                action,
                resource,
                task,
                params,
            },
    } = Cli::parse().command;

    let result = async {
        let request = acf_agent::build_request(&action, &resource, &task, &params)?;
        acf_agent::send(&gateway, &request).await
    }
    .await;
    match result {
        Ok(response) => {
            match serde_json::to_string_pretty(&response) {
                Ok(text) => println!("{text}"),
                Err(_) => return ExitCode::FAILURE,
            }
            if matches!(response, ActionResponse::Completed { .. }) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(error) => {
            eprintln!("acf-agent: {error}");
            ExitCode::FAILURE
        }
    }
}
