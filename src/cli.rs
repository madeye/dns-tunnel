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
    pub path: String,
    pub insecure: bool,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub acme: Option<AcmeConfig>,
}

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// Contact email(s), comma-separated.
    pub contact: String,
    /// Domain(s) to request, comma-separated.
    pub domains: Vec<String>,
    /// Cert + account cache directory.
    pub cache_dir: PathBuf,
    /// Use Let's Encrypt staging instead of production.
    pub staging: bool,
    /// TCP port to bind for TLS-ALPN-01 challenges (default 443).
    pub tls_port: u16,
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
    ///   path=<path>          (default: /dns-query)
    ///   insecure             (skip TLS verification, client only)
    ///   cert=<pem>           (server only)
    ///   key=<pem>            (server only)
    ///   acme=<email>         (server only; enables Let's Encrypt auto-cert via TLS-ALPN-01)
    ///   acme-domain=<host>   (server only; default: sni; comma-separated for SAN)
    ///   acme-dir=<path>      (server only; cache dir; default: ./acme-cache)
    ///   acme-staging         (server only; use LE staging directory)
    ///   acme-tls-port=<n>    (server only; TCP port for TLS-ALPN-01; default 443)
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
        let path = opts
            .get("path")
            .cloned()
            .unwrap_or_else(|| "/dns-query".into());
        let insecure = opts.contains_key("insecure");
        let cert = opts.get("cert").map(PathBuf::from);
        let key = opts.get("key").map(PathBuf::from);

        let acme = if let Some(email) = opts.get("acme") {
            let domains = opts
                .get("acme-domain")
                .cloned()
                .unwrap_or_else(|| sni.clone())
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect::<Vec<_>>();
            if domains.is_empty() {
                bail!("acme= requires a non-empty domain (acme-domain= or sni=)");
            }
            let cache_dir = opts
                .get("acme-dir")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("acme-cache"));
            let staging = opts.contains_key("acme-staging");
            let tls_port = opts
                .get("acme-tls-port")
                .map(|s| s.parse::<u16>())
                .transpose()
                .context("acme-tls-port")?
                .unwrap_or(443);
            Some(AcmeConfig {
                contact: email.clone(),
                domains,
                cache_dir,
                staging,
                tls_port,
            })
        } else {
            None
        };

        if mode == Mode::Server && cert.is_none() && key.is_none() && acme.is_none() {
            tracing::warn!(
                "server mode without cert=/key= or acme=; generating ephemeral self-signed cert for sni={sni}"
            );
        }

        Ok(Self {
            mode,
            local,
            remote,
            sni,
            path,
            insecure,
            cert,
            key,
            acme,
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
