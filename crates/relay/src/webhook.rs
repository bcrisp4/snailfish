//! User webhooks (`PROTOCOL.md` 12.5, [USR-8]).
//!
//! The relay resolves the host each time, refuses a restricted address
//! unless the operator allowlist names that address, and connects to the
//! address that it checked. The HTTP client does not resolve the name again,
//! so a DNS answer that changes between the check and the connection cannot
//! move the request to another address. It follows no redirect, waits at
//! most 10 seconds and reads at most 4 KiB of the response.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use snailfish_protocol::setup::{WebhookUrl, parse_webhook_url, webhook_body};
use tokio::net::TcpStream;

use crate::core::Relay;

/// The time limit of one send.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// The most response bytes that the relay reads.
pub const MAX_RESPONSE: usize = 4096;

/// True for an address that a webhook must not reach unless the allowlist
/// names it: the restricted ranges of 12.5. 100.64.0.0/10 is restricted
/// because a relay on a Tailscale network reaches its peers there.
#[must_use]
pub fn restricted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            a == 0
                || a == 10
                || (a == 100 && (b & 0xc0) == 64)
                || a == 127
                || (a == 169 && b == 254)
                || (a == 172 && (b & 0xf0) == 16)
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 168)
                || (a == 198 && (b & 0xfe) == 18)
                || a >= 224
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return restricted(IpAddr::V4(v4));
            }
            let s = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (s & 0xfe00) == 0xfc00
                || (s & 0xffc0) == 0xfe80
                || (s & 0xff00) == 0xff00
        }
    }
}

/// The IPv4 address inside an IPv6 address of 12.5: mapped (`::ffff:0:0/96`),
/// compatible (`::/96`), NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`). The
/// gateway of each form forwards to that IPv4 address, so it must pass the
/// IPv4 rule. `::` and `::1` are not compatible addresses.
fn embedded_v4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let o = v6.octets();
    let low = std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    match v6.segments() {
        [0, 0, 0, 0, 0, 0xffff, _, _] | [0x64, 0xff9b, 0, 0, 0, 0, _, _] => Some(low),
        [0, 0, 0, 0, 0, 0, _, _] if !v6.is_loopback() && !v6.is_unspecified() => Some(low),
        [0x2002, ..] => Some(std::net::Ipv4Addr::new(o[2], o[3], o[4], o[5])),
        _ => None,
    }
}

/// The addresses of `addrs` that a webhook may reach under `allowlist`.
#[must_use]
pub fn allowed(addrs: &[SocketAddr], allowlist: &[String]) -> Vec<SocketAddr> {
    addrs
        .iter()
        .copied()
        .filter(|a| {
            !restricted(a.ip())
                || allowlist
                    .iter()
                    .any(|h| h.parse::<IpAddr>().ok() == Some(a.ip()))
        })
        .collect()
}

/// Check a webhook URL against the allowlist and the address rule, with a
/// blocking DNS lookup. Returns the parsed URL and the checked addresses.
///
/// # Errors
///
/// A text for the user page.
pub fn check_url(url: &str, allowlist: &[String]) -> Result<(WebhookUrl, Vec<SocketAddr>), String> {
    let u = parse_webhook_url(url).map_err(|e| e.0)?;
    if allowlist.is_empty() {
        return Err("the relay operator turned webhooks off".into());
    }
    if !allowlist.iter().any(|h| h == &u.host) {
        return Err(format!(
            "the host {} is not in the allowlist of the relay operator",
            u.host
        ));
    }
    let addrs: Vec<SocketAddr> = (u.host.as_str(), u.port)
        .to_socket_addrs()
        .map_err(|_| format!("the host {} does not resolve", u.host))?
        .collect();
    let ok = allowed(&addrs, allowlist);
    if ok.is_empty() {
        return Err(format!(
            "the host {} resolves only to a loopback, link-local or private address",
            u.host
        ));
    }
    Ok((u, ok))
}

/// Send one message. Returns the HTTP status.
///
/// # Errors
///
/// A text for the user page.
pub async fn send(url: &str, text: &str, allowlist: Vec<String>) -> Result<u16, String> {
    let url_owned = url.to_owned();
    // The limit covers the DNS lookup too (12.5): a slow resolver must not
    // hold the loop, which sends for each tenant in turn. A lookup that
    // outlives the limit ends on its own blocking thread.
    let body = webhook_body(text);
    tokio::time::timeout(TIMEOUT, async move {
        let (u, addrs) = tokio::task::spawn_blocking(move || check_url(&url_owned, &allowlist))
            .await
            .map_err(|_| "the check failed".to_owned())??;
        post(&u, &addrs, body).await
    })
    .await
    .map_err(|_| "no answer within 10 seconds".to_owned())?
}

async fn post(u: &WebhookUrl, addrs: &[SocketAddr], body: Vec<u8>) -> Result<u16, String> {
    let mut last = String::from("no address");
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(tcp) => return exchange(u, tcp, body).await,
            Err(e) => last = format!("connect: {e}"),
        }
    }
    Err(last)
}

/// The TLS client configuration, built once: the root store copy and the
/// provider setup are the same for each send.
fn tls_config() -> Result<Arc<tokio_rustls::rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<tokio_rustls::rustls::ClientConfig>, String>> =
        OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("tls: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            Ok(Arc::new(config))
        })
        .clone()
}

async fn exchange(u: &WebhookUrl, tcp: TcpStream, body: Vec<u8>) -> Result<u16, String> {
    if u.https {
        let config = tls_config()?;
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(u.host.clone())
            .map_err(|_| "tls: the host is not a valid server name".to_owned())?;
        let tls = tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(|e| format!("tls: {e}"))?;
        request(u, TokioIo::new(tls), body).await
    } else {
        request(u, TokioIo::new(tcp), body).await
    }
}

async fn request<T>(u: &WebhookUrl, io: TokioIo<T>, body: Vec<u8>) -> Result<u16, String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut tx, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
        .await
        .map_err(|e| format!("http: {e}"))?;
    tokio::spawn(conn);
    let default = if u.https { 443 } else { 80 };
    let host = match (u.host.contains(':'), u.port == default) {
        (true, true) => format!("[{}]", u.host),
        (true, false) => format!("[{}]:{}", u.host, u.port),
        (false, true) => u.host.clone(),
        (false, false) => format!("{}:{}", u.host, u.port),
    };
    let req = http::Request::post(u.target.as_str())
        .header("host", host)
        .header("content-type", "application/json")
        .header("user-agent", "snailfish-relay")
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("http: {e}"))?;
    let resp = tx
        .send_request(req)
        .await
        .map_err(|e| format!("http: {e}"))?;
    let status = resp.status().as_u16();
    // Read at most 4 KiB, then drop the connection. A longer body is not an
    // error: the status is the answer.
    let _ = Limited::new(resp.into_body(), MAX_RESPONSE).collect().await;
    Ok(status)
}

/// How often the loop sends queued messages.
pub const SEND_EVERY: Duration = Duration::from_secs(2);
/// How often the loop checks the alert cases.
pub const ALERTS_EVERY: Duration = Duration::from_secs(60);

/// Send the queued messages of each tenant, and queue new alerts, until the
/// process ends.
pub async fn run(relay: Relay) {
    if relay.config().webhook_hosts.is_empty() {
        return;
    }
    // The first pass checks the alert cases, so a restart does not delay
    // them by one interval.
    let start = tokio::time::Instant::now();
    let mut alerts = start.checked_sub(ALERTS_EVERY).unwrap_or(start);
    loop {
        let r = relay.clone();
        let check = alerts.elapsed() >= ALERTS_EVERY;
        if check {
            alerts = tokio::time::Instant::now();
        }
        let work = tokio::task::spawn_blocking(move || {
            let now = (r.config().clock)();
            let mut out = Vec::new();
            for t in r.tenant_ids().unwrap_or_default() {
                if check {
                    let _ = r.queue_alerts(&t, now);
                }
                if let Ok(Some(q)) = r.next_webhook(&t) {
                    out.push((t, q));
                }
            }
            out
        })
        .await
        .unwrap_or_default();
        for (tenant, q) in work {
            let result = match send(&q.url, &q.text, relay.config().webhook_hosts.clone()).await {
                Ok(code) => format!("HTTP {code}"),
                Err(e) => format!("failed: {e}"),
            };
            let r = relay.clone();
            let _ =
                tokio::task::spawn_blocking(move || r.webhook_sent(&tenant, q.seq, &result)).await;
        }
        tokio::time::sleep(SEND_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_addresses() {
        // [USR-8] Each class of 12.5, and public addresses next to them.
        for no in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            // 12.5: shared address space (Tailscale), this network,
            // benchmark, IETF protocol and reserved.
            "100.64.0.1",
            "100.127.255.254",
            "0.1.2.3",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.0.8",
            "240.0.0.1",
            // IPv4 inside IPv6: compatible, NAT64 and 6to4.
            "::127.0.0.1",
            "::a00:1",
            "64:ff9b::a00:1",
            "64:ff9b::6440:1",
            "2002:a00:1::1",
            "2002:7f00:1::",
        ] {
            assert!(restricted(no.parse().unwrap()), "{no}");
        }
        for ok in [
            "8.8.8.8",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "198.20.0.1",
            "192.0.2.1",
            "223.255.255.255",
            "2001:4860::8888",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "fec0::1",
        ] {
            assert!(!restricted(ok.parse().unwrap()), "{ok}");
        }
    }

    #[test]
    fn allowlist_names_a_restricted_address() {
        let a: Vec<SocketAddr> = vec![
            "127.0.0.1:80".parse().unwrap(),
            "8.8.8.8:80".parse().unwrap(),
        ];
        assert_eq!(allowed(&a, &[]), vec![a[1]]);
        assert_eq!(allowed(&a, &["127.0.0.1".into()]), a);
        assert_eq!(
            allowed(&a[..1], &["localhost".into()]),
            Vec::<SocketAddr>::new()
        );
    }

    #[test]
    fn check_url_refuses_hosts_and_private_addresses() {
        assert!(
            check_url("http://127.0.0.1:9/h", &[])
                .unwrap_err()
                .contains("off")
        );
        assert!(
            check_url("http://127.0.0.1:9/h", &["example.com".into()])
                .unwrap_err()
                .contains("allowlist")
        );
        assert!(
            check_url("http://localhost:9/h", &["localhost".into()])
                .unwrap_err()
                .contains("private")
        );
        let (u, addrs) = check_url("http://127.0.0.1:9/h", &["127.0.0.1".into()]).unwrap();
        assert_eq!((u.port, addrs.len()), (9, 1));
    }

    #[tokio::test]
    async fn send_posts_the_message_and_reads_the_status() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut got = Vec::new();
            while !got.windows(4).any(|w| w == b"\r\n\r\n") || !got.ends_with(b"}") {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            // A redirect answer is a result, not a hop.
            s.write_all(
                b"HTTP/1.1 302 Found\r\nlocation: http://8.8.8.8/\r\ncontent-length: 0\r\n\r\n",
            )
            .await
            .unwrap();
            String::from_utf8(got).unwrap()
        });
        let status = send(
            &format!("http://127.0.0.1:{port}/hook"),
            "hi",
            vec!["127.0.0.1".into()],
        )
        .await;
        assert_eq!(status, Ok(302));
        let req = server.await.unwrap();
        assert!(req.starts_with("POST /hook HTTP/1.1\r\n"), "{req}");
        assert!(req.contains(&format!("host: 127.0.0.1:{port}")));
        assert!(req.ends_with(r#"{"text":"hi"}"#));
    }
}
