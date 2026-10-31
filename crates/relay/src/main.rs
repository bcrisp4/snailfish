//! The `snailfish-relay` command.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use snailfish_relay::core::{Config, OpenError, Relay};
use snailfish_relay::http::router;
use snailfish_relay::ops;

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
    /// Check the health route of a running relay. Exit 0 if it answers
    /// 200. The container image has no curl, so its HEALTHCHECK uses this.
    Health {
        /// The health URL: `http://` with an IP address or host and a port.
        #[arg(long, default_value = "http://127.0.0.1:8080/v1/health")]
        url: String,
    },
    /// Manage users.
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Copy the data directory with the SQLite online backup API, while the
    /// relay runs. The relay refuses space creation until it ends.
    Backup {
        /// The backup directory. It must be empty or absent.
        dir: PathBuf,
    },
    /// Restore a backup into the data directory. Stop the relay first. Each
    /// restored space goes on restore hold.
    Restore {
        /// The backup directory.
        dir: PathBuf,
        /// Delete the relay data in the data directory first.
        #[arg(long)]
        replace: bool,
    },
    /// Print the restore hold of a space: the device reports and the repair
    /// sessions. Changes nothing.
    HoldStatus {
        /// The user name.
        user: String,
        /// The log ID text.
        log: String,
    },
    /// End the restore hold of a space.
    ReleaseHold {
        /// The user name.
        user: String,
        /// The log ID text.
        log: String,
        /// Release also while a device is "not repaired". The release can
        /// lose changes that only its app database holds.
        #[arg(long)]
        force: bool,
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
    if let Command::Health { url } = &cli.command {
        return match health(url) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e),
        };
    }
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
        Command::Health { .. } => ExitCode::SUCCESS,
        Command::Backup { dir } => match ops::backup(&data, &dir) {
            Ok(s) => {
                println!("backup: {} tenants, {} spaces", s.tenants, s.spaces);
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e.to_string()),
        },
        Command::Restore { dir, replace } => {
            match ops::restore(&data, &dir, replace, snailfish_relay::core::system_time()) {
                Ok(s) => {
                    println!("restore: {} tenants", s.tenants);
                    for log in &s.held {
                        println!("on hold: {log}");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e.to_string()),
            }
        }
        Command::HoldStatus { user, log } => match ops::hold_report(&data, &user, &log) {
            Ok(r) => {
                print!("{r}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e.to_string()),
        },
        Command::ReleaseHold { user, log, force } => {
            match ops::release_hold(&data, &user, &log, force) {
                Ok(r) => {
                    print!("{r}");
                    println!("released: {log}");
                    ExitCode::SUCCESS
                }
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
    // Held until the process ends, so `restore` cannot run beside it.
    let _lock = match ops::serve_lock(&data) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
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
    // A container stop sends SIGTERM, and a terminal sends SIGINT.
    let shutdown = async {
        let term = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut s) => {
                    s.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = term => {}
        }
    };
    match axum::serve(listener, router(relay))
        .with_graceful_shutdown(shutdown)
        .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&format!("server error: {e}")),
    }
}

/// One `GET` of a plain HTTP health URL, with a 5 second limit.
fn health(url: &str) -> Result<(), String> {
    use std::io::{Read as _, Write as _};
    let rest = url
        .strip_prefix("http://")
        .ok_or("the health URL must start with http://")?;
    let (host, path) = rest
        .split_once('/')
        .map_or((rest, "/"), |(h, _)| (h, &rest[h.len()..]));
    let timeout = std::time::Duration::from_secs(5);
    let addr = std::net::ToSocketAddrs::to_socket_addrs(host)
        .map_err(|e| format!("health: {e}"))?
        .next()
        .ok_or("health: no address")?;
    let mut s =
        std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("health: {e}"))?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| format!("health: {e}"))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| format!("health: {e}"))?;
    let mut head = [0u8; 12];
    s.read_exact(&mut head)
        .map_err(|e| format!("health: {e}"))?;
    if head.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err(format!("health: {}", String::from_utf8_lossy(&head)))
    }
}
