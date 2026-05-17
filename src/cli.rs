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
    pub acme: Option<AcmeConfig>,
    pub decoy: Option<DecoyConfig>,
}

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// Contact email used in the ACME account.
    pub contact: String,
    /// Domains requested on the certificate (SAN list).
    pub domains: Vec<String>,
    /// Persistent account+cert cache directory.
    pub cache_dir: PathBuf,
    /// Use Let's Encrypt staging directory instead of production.
    pub staging: bool,
    /// TCP port to bind for TLS-ALPN-01 challenges. Real traffic still flows
    /// over UDP/QUIC on `SS_REMOTE_PORT`; this is purely for the challenge.
    pub tls_port: u16,
}

#[derive(Debug, Clone)]
pub struct DecoyConfig {
    /// `(sni, port)` pairs. The SNI doubles as the DNS name used for address
    /// resolution, so use hostnames here (not IP literals).
    pub resolvers: Vec<(String, u16)>,
    /// Average sleep between queries per resolver task; actual sleep is
    /// uniformly jittered in `[0.5x, 1.5x]`.
    pub interval_ms: u64,
    /// Pool of domains to issue real A queries for.
    pub domains: Vec<String>,
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
    ///   acme=<email>         (server only; enables Let's Encrypt via TLS-ALPN-01)
    ///   acme-domain=<host>   (server only; comma-separated SAN list; default: sni)
    ///   acme-dir=<path>      (server only; account+cert cache; default: acme-cache)
    ///   acme-staging         (server only; use LE staging directory)
    ///   acme-tls-port=<n>    (server only; TCP port for the challenge; default 443)
    ///   decoy                (client only; enable decoy DoQ traffic to public resolvers)
    ///   decoy-resolvers=     (client only; `host:port,host:port,...`; default AdGuard+Quad9)
    ///   decoy-interval-ms=   (client only; mean interval per resolver; default 5000)
    ///   decoy-domains=       (client only; comma-separated A-record query targets)
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

        let acme = if mode == Mode::Server {
            if let Some(email) = opts.get("acme") {
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
            }
        } else {
            None
        };

        if mode == Mode::Server && cert.is_none() && key.is_none() && acme.is_none() {
            tracing::warn!(
                "server mode without cert=/key= or acme=; generating ephemeral self-signed cert for sni={sni}"
            );
        }

        let decoy = if mode == Mode::Client && opts.contains_key("decoy") {
            let resolvers = opts
                .get("decoy-resolvers")
                .cloned()
                .unwrap_or_else(|| "dns.adguard-dns.com:853,dns.quad9.net:853".into());
            let resolvers = resolvers
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(parse_host_port)
                .collect::<Result<Vec<_>>>()?;
            if resolvers.is_empty() {
                bail!("decoy-resolvers= must contain at least one host:port");
            }
            let interval_ms = opts
                .get("decoy-interval-ms")
                .map(|s| s.parse::<u64>())
                .transpose()
                .context("decoy-interval-ms")?
                .unwrap_or(5000);
            let domains = opts
                .get("decoy-domains")
                .cloned()
                .unwrap_or_else(|| {
                    "example.com,wikipedia.org,github.com,cloudflare.com,apple.com".into()
                })
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect::<Vec<_>>();
            if domains.is_empty() {
                bail!("decoy-domains= must contain at least one domain");
            }
            Some(DecoyConfig {
                resolvers,
                interval_ms,
                domains,
            })
        } else {
            None
        };

        Ok(Self {
            mode,
            local,
            remote,
            sni,
            insecure,
            cert,
            key,
            acme,
            decoy,
        })
    }
}

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("expected host:port, got {s}"))?;
    let port: u16 = port.parse().with_context(|| format!("port in {s}"))?;
    Ok((host.to_string(), port))
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
