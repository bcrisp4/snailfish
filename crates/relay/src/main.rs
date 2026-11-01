//! The `snailfish-relay` command.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use snailfish_relay::core::{Config, OpenError, Quotas, Relay};
use snailfish_relay::http::router;
use snailfish_relay::ops;

#[derive(Parser)]
#[command(name = "snailfish-relay", version)]
struct Cli {
    /// The data directory.
    #[arg(long, global = true, env = "SNAILFISH_DATA")]
    data: Option<PathBuf>,
    /// The authority that request signatures cover, for example
    /// `sync.example.net` or `relay.example.ts.net:8443`.
    #[arg(long, global = true, env = "SNAILFISH_AUTHORITY")]
    authority: Option<String>,
    /// The origin of the user page. The default is `https://` and the
    /// authority. Its host must be a domain name (`WebAuthn`).
    #[arg(long, global = true, env = "SNAILFISH_ORIGIN")]
    origin: Option<String>,
    /// The `secrets` directory with `session.key`. The default is the
    /// directory `secrets` beside the data directory. Backups do not copy it.
    #[arg(long, global = true, env = "SNAILFISH_SECRETS")]
    secrets: Option<PathBuf>,
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
        /// The most spaces of each tenant ([QTA-5]).
        #[arg(long, env = "SNAILFISH_MAX_SPACES", default_value_t = Quotas::default().max_spaces)]
        max_spaces: u64,
        /// The most stored change bytes of each space ([QTA-1]).
        #[arg(long, env = "SNAILFISH_SPACE_BYTES", default_value_t = Quotas::default().space_bytes)]
        space_bytes: u64,
        /// The hosts that a user webhook may name, separated by commas.
        /// Empty turns webhooks off ([USR-8]).
        #[arg(
            long,
            env = "SNAILFISH_WEBHOOK_HOSTS",
            value_delimiter = ',',
            default_value = ""
        )]
        webhook_hosts: Vec<String>,
    },
    /// Set the quotas of one user. A value that is not given goes back to
    /// the default of `serve`.
    Quota {
        /// The user name.
        user: String,
        /// The most spaces of the tenant.
        #[arg(long)]
        spaces: Option<u64>,
        /// The most stored change bytes of each space.
        #[arg(long)]
        space_bytes: Option<u64>,
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
    /// Create a user and its tenant, and print a one-time invite link.
    Add {
        /// The user name.
        name: String,
    },
    /// Print a new invite link for a user. It removes the passkeys and the
    /// browser sessions of the user, and an unused older link.
    Invite {
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
    let authority = cli.authority.filter(|a| !a.is_empty());
    let config = |authority: &str| {
        let mut c = Config::new(data.clone(), authority);
        if let Some(o) = &cli.origin {
            c.origin.clone_from(o);
        }
        if let Some(s) = &cli.secrets {
            c.secrets_dir.clone_from(s);
        }
        c
    };
    let need_authority =
        || fail("set --authority or SNAILFISH_AUTHORITY: the relay does not start without it");
    match cli.command {
        Command::User { action } => {
            // The invite link names the origin of the user page.
            let Some(a) = authority else {
                return need_authority();
            };
            user_command(config(&a), action)
        }
        Command::Quota {
            user,
            spaces,
            space_bytes,
        } => {
            // The quota command needs no authority.
            match Relay::open(config("unused.invalid"))
                .and_then(|r| r.set_quotas(&user, spaces, space_bytes))
            {
                Ok(()) => ExitCode::SUCCESS,
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
        Command::Serve {
            listen,
            max_spaces,
            space_bytes,
            webhook_hosts,
        } => {
            let Some(a) = authority else {
                return need_authority();
            };
            let mut c = config(&a);
            c.quotas = Quotas {
                max_spaces,
                space_bytes,
            };
            c.webhook_hosts = webhook_hosts
                .into_iter()
                .filter(|h| !h.is_empty())
                .collect();
            serve(c, &listen).await
        }
    }
}

/// `user add` and `user invite`: print the invite link.
fn user_command(config: Config, action: UserAction) -> ExitCode {
    let made = Relay::open(config).and_then(|r| match action {
        UserAction::Add { name } => r.add_user(&name).and_then(|_| r.invite(&name)),
        UserAction::Invite { name } => r.invite(&name),
    });
    match made {
        Ok(link) => {
            println!("{link}");
            ExitCode::SUCCESS
        }
        Err(OpenError::UserExists) => fail("a user with this name exists"),
        Err(e) => fail(&e.to_string()),
    }
}

async fn serve(config: Config, listen: &str) -> ExitCode {
    // Held until the process ends, so `restore` cannot run beside it.
    let _lock = match ops::serve_lock(&config.data_dir) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
    let relay = match Relay::open(config) {
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
    tokio::spawn(snailfish_relay::webhook::run(relay.clone()));
    let app = router(relay).into_make_service_with_connect_info::<std::net::SocketAddr>();
    match axum::serve(listener, app)
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
