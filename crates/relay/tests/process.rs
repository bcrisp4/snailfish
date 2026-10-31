//! The `snailfish-relay` binary: `serve` and `health` as a user runs them.

#![cfg(test)]

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_snailfish-relay");

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn health(url: &str) -> bool {
    Command::new(BIN)
        .args(["health", "--url", url])
        .output()
        .unwrap()
        .status
        .success()
}

/// Without this, a relay that exits at once, or a health check that always
/// passes, would show a container as healthy while it serves nothing.
#[test]
fn serve_answers_health_and_the_health_command_reports_failure() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/v1/health");
    assert!(!health(&url), "nothing listens yet");
    let mut server = Server(
        Command::new(BIN)
            .args(["serve", "--data"])
            .arg(dir.path())
            .args(["--listen", &format!("127.0.0.1:{port}")])
            .args(["--authority", "relay.test"])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    while !health(&url) {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "the relay exited early"
        );
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "no health answer"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        server.0.try_wait().unwrap().is_none(),
        "serve keeps running"
    );
    // A 404 is not a healthy answer.
    assert!(!health(&format!("http://127.0.0.1:{port}/v1/nothing")));
    assert!(!health("https://127.0.0.1/v1/health"));
}

/// Without this, an empty `SNAILFISH_AUTHORITY` would start a relay whose
/// signatures no client can match.
#[test]
fn serve_refuses_an_empty_authority() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(BIN)
        .args(["serve", "--data"])
        .arg(dir.path())
        .args(["--listen", &format!("127.0.0.1:{}", free_port())])
        .env("SNAILFISH_AUTHORITY", "")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--authority"));
}
