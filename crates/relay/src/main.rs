//! The `snailfish-relay` command.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use snailfish_relay::core::{Config, OpenError, Relay};
use snailfish_relay::http::router;

#[derive(Parser)]
#[command(name = "snailfish-relay", version)]
struct Cli {
    /// The data directory.
    #[arg(long, global = true, env = "SNAILFISH_DATA")]
    data: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the relay.
    Serve {
        /// The address to listen on.
        #[arg(long, env = "SNAILFISH_LISTEN", default_value = "127.0.0.1:8080")]
        listen: String,
        /// The authority that request signatures cover, for example
        /// `sync.example.net` or `relay.example.ts.net:8443`.
        #[arg(long, env = "SNAILFISH_AUTHORITY")]
        authority: Option<String>,
    },
    /// Manage users.
    User {
        #[command(subcommand)]
        action: UserAction,
    },
}

#[derive(Subcommand)]
enum UserAction {
    /// Create a user and its tenant, and print the tenant handle.
    Add {
        /// The user name.
        name: String,
    },
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("snailfish-relay: {msg}");
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(data) = cli.data else {
        return fail("set --data or SNAILFISH_DATA");
    };
    match cli.command {
        Command::User {
            action: UserAction::Add { name },
        } => {
            // The user command needs no authority.
            match Relay::open(Config::new(data, "unused.invalid")).and_then(|r| r.add_user(&name)) {
                Ok(handle) => {
                    println!("{handle}");
                    ExitCode::SUCCESS
                }
                Err(OpenError::UserExists) => fail("a user with this name exists"),
                Err(e) => fail(&e.to_string()),
            }
        }
        Command::Serve { listen, authority } => {
            let Some(authority) = authority.filter(|a| !a.is_empty()) else {
                return fail(
                    "set --authority or SNAILFISH_AUTHORITY: the relay does not start without it",
                );
            };
            serve(data, &listen, authority).await
        }
    }
}

async fn serve(data: PathBuf, listen: &str, authority: String) -> ExitCode {
    #[cfg(feature = "webauthn")]
    if let Err(e) = snailfish_relay::passkey::check_builder(&authority) {
        return fail(&e);
    }
    let relay = match Relay::open(Config::new(data, authority)) {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string()),
    };
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => return fail(&format!("cannot listen: {e}")),
    };
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match axum::serve(listener, router(relay))
        .with_graceful_shutdown(shutdown)
        .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&format!("server error: {e}")),
    }
}
