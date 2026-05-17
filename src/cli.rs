use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub sni: String,
    pub insecure: bool,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}

impl Config {
    /// Build config from SIP003 environment variables and `SS_PLUGIN_OPTIONS`.
    ///
    /// SIP003 vars:
    ///   SS_REMOTE_HOST, SS_REMOTE_PORT, SS_LOCAL_HOST, SS_LOCAL_PORT, SS_PLUGIN_OPTIONS
    ///
    /// Plugin options (semicolon separated `k=v`):
    ///   mode=client|server   (default: client)
    ///   sni=<hostname>       (default: SS_REMOTE_HOST)
    ///   insecure             (skip TLS verification, client only)
    ///   cert=<pem>           (server only)
    ///   key=<pem>            (server only)
    pub fn from_env_and_args() -> Result<Self> {
        let remote_host = env_required("SS_REMOTE_HOST")?;
        let remote_port: u16 = env_required("SS_REMOTE_PORT")?
            .parse()
            .context("SS_REMOTE_PORT")?;
        let local_host = env_required("SS_LOCAL_HOST")?;
        let local_port: u16 = env_required("SS_LOCAL_PORT")?
            .parse()
            .context("SS_LOCAL_PORT")?;
        let opts_raw = std::env::var("SS_PLUGIN_OPTIONS").unwrap_or_default();
        let opts = parse_options(&opts_raw)?;

        let mode = match opts.get("mode").map(String::as_str).unwrap_or("client") {
            "client" => Mode::Client,
            "server" => Mode::Server,
            other => bail!("invalid mode={other}, expected client or server"),
        };

        let remote = resolve(&remote_host, remote_port)?;
        let local = resolve(&local_host, local_port)?;
        let sni = opts.get("sni").cloned().unwrap_or(remote_host);
        let insecure = opts.contains_key("insecure");
        let cert = opts.get("cert").map(PathBuf::from);
        let key = opts.get("key").map(PathBuf::from);

        if mode == Mode::Server && (cert.is_none() || key.is_none()) {
            tracing::warn!(
                "server mode without cert=/key=; generating ephemeral self-signed cert for sni={sni}"
            );
        }

        Ok(Self {
            mode,
            local,
            remote,
            sni,
            insecure,
            cert,
            key,
        })
    }
}

fn env_required(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| anyhow!("required env var {name} not set"))
}

fn parse_options(s: &str) -> Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    if s.is_empty() {
        return Ok(out);
    }
    // SIP003 escapes ';' and '=' with backslash. Tolerate simple parsing.
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    let mut pieces = Vec::new();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            ';' => {
                pieces.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        pieces.push(cur);
    }
    for piece in pieces {
        if let Some((k, v)) = piece.split_once('=') {
            out.insert(k.to_string(), v.to_string());
        } else {
            out.insert(piece, String::new());
        }
    }
    Ok(out)
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let mut iter = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}:{port}"))?;
    iter.next()
        .ok_or_else(|| anyhow!("no addresses for {host}:{port}"))
}
