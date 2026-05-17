use crate::cli::Config;
use crate::dns::{self, MsgKind};
use crate::tls;
use anyhow::{anyhow, bail, Context, Result};
use quinn::{ClientConfig, Connection, Endpoint};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub async fn run(cfg: Config) -> Result<()> {
    let listener = TcpListener::bind(cfg.local)
        .await
        .with_context(|| format!("binding TCP listener on {}", cfg.local))?;
    tracing::info!("client listening on {}", cfg.local);

    let endpoint = build_endpoint(cfg.remote, &cfg)?;
    let pool = Arc::new(QuicConn::new(endpoint, cfg.clone()));

    if let Some(decoy_cfg) = cfg.decoy.clone() {
        tracing::info!(
            resolvers = ?decoy_cfg.resolvers,
            interval_ms = decoy_cfg.interval_ms,
            "decoy traffic enabled"
        );
        if let Err(e) = crate::decoy::spawn(decoy_cfg) {
            tracing::warn!(error=%e, "failed to start decoy traffic");
        }
    }

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error=%e, "accept failed");
                continue;
            }
        };
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, peer, pool).await {
                tracing::debug!(error=%e, %peer, "connection ended with error");
            }
        });
    }
}

fn build_endpoint(remote: SocketAddr, cfg: &Config) -> Result<Endpoint> {
    let bind: SocketAddr = if remote.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = Endpoint::client(bind).context("creating QUIC endpoint")?;
    let crypto = tls::client_config(cfg.insecure)?;
    let qcfg: quinn::crypto::rustls::QuicClientConfig = crypto
        .try_into()
        .map_err(|e| anyhow!("rustls→quic client config: {e}"))?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(qcfg)));
    Ok(endpoint)
}

/// Pooled QUIC connection that reconnects on demand.
struct QuicConn {
    endpoint: Endpoint,
    cfg: Config,
    inner: Mutex<Option<Connection>>,
}

impl QuicConn {
    fn new(endpoint: Endpoint, cfg: Config) -> Self {
        Self {
            endpoint,
            cfg,
            inner: Mutex::new(None),
        }
    }

    async fn get(&self) -> Result<Connection> {
        let mut guard = self.inner.lock().await;
        if let Some(c) = guard.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let conn = self.dial().await?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn dial(&self) -> Result<Connection> {
        tracing::info!(remote=%self.cfg.remote, sni=%self.cfg.sni, "dialing QUIC");
        let connecting = self
            .endpoint
            .connect(self.cfg.remote, &self.cfg.sni)
            .context("QUIC connect()")?;
        let conn = connecting.await.context("QUIC handshake")?;
        Ok(conn)
    }
}

async fn handle_conn(mut tcp: TcpStream, peer: SocketAddr, pool: Arc<QuicConn>) -> Result<()> {
    tcp.set_nodelay(true).ok();

    // Open a fresh bidi stream on the pooled QUIC connection. If open_bi fails
    // (connection dead), invalidate and retry once.
    let (mut send, mut recv) = match pool.get().await?.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error=%e, "open_bi failed, redialing");
            *pool.inner.lock().await = None;
            pool.get().await?.open_bi().await.context("open_bi retry")?
        }
    };

    tracing::debug!(%peer, "tunnel open");
    let (mut tcp_r, mut tcp_w) = tcp.split();

    // TCP -> QUIC: encode payload chunks as DNS queries with [u16 len] frame.
    let up = async {
        let mut buf = vec![0u8; dns::MAX_PAYLOAD];
        loop {
            let n = tcp_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let dns_msg = dns::encode(MsgKind::Query, &buf[..n])?;
            send.write_u16(dns_msg.len() as u16).await?;
            send.write_all(&dns_msg).await?;
        }
        send.finish().ok();
        Ok::<_, anyhow::Error>(())
    };

    // QUIC -> TCP: read framed DNS responses, decode, write payload to TCP.
    let down = async {
        loop {
            let len = match recv.read_u16().await {
                Ok(n) => n as usize,
                Err(e) if is_eof(&e) => {
                    let _ = tcp_w.shutdown().await;
                    return Ok::<_, anyhow::Error>(());
                }
                Err(e) => return Err(e.into()),
            };
            let mut msg = vec![0u8; len];
            recv.read_exact(&mut msg).await?;
            let (kind, payload) = dns::decode(msg.into())?;
            if kind != MsgKind::Response {
                bail!("expected DNS response from server, got {:?}", kind);
            }
            if !payload.is_empty() {
                tcp_w.write_all(&payload).await?;
            }
        }
    };

    let _ = tokio::try_join!(up, down);
    Ok(())
}

fn is_eof(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::UnexpectedEof
}
