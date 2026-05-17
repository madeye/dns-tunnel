use crate::cli::Config;
use crate::dns;
use crate::protocol::{Frame, FLAG_CLOSE, FLAG_OPEN, HEADER_LEN};
use crate::tls;
use anyhow::{anyhow, bail, Context, Result};
use quinn::{ClientConfig, Connection, Endpoint};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Cadence at which the client polls (sends an empty query) when it has no
/// upstream data and is waiting for downstream bytes from the server.
const POLL_INTERVAL_MS: u64 = 80;

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
        connecting.await.context("QUIC handshake")
    }
}

async fn handle_conn(mut tcp: TcpStream, peer: SocketAddr, pool: Arc<QuicConn>) -> Result<()> {
    tcp.set_nodelay(true).ok();
    let session: u64 = rand::random();
    tracing::debug!(%peer, session, "tunnel open");

    let (mut tcp_r, mut tcp_w) = tcp.split();
    let mut seq: u16 = 0;
    let mut open_sent = false;
    let mut upstream_eof = false;
    let mut downstream_closed = false;
    let max_body = dns::MAX_QUERY_PAYLOAD - HEADER_LEN;
    let mut tcp_buf = vec![0u8; max_body];

    while !downstream_closed {
        // Gather upstream chunk. Fast path: try_read for data already buffered
        // (so a sustained upload isn't paced by the poll-fallback timer). Slow
        // path: select on a fresh read or a poll deadline.
        let body = if upstream_eof {
            Vec::new()
        } else {
            match tcp_r.try_read(&mut tcp_buf) {
                Ok(0) => {
                    upstream_eof = true;
                    Vec::new()
                }
                Ok(n) => tcp_buf[..n].to_vec(),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::select! {
                        r = tcp_r.read(&mut tcp_buf) => {
                            match r {
                                Ok(0) => { upstream_eof = true; Vec::new() }
                                Ok(n) => tcp_buf[..n].to_vec(),
                                Err(e) => return Err(e.into()),
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)) => Vec::new(),
                    }
                }
                Err(e) => return Err(e.into()),
            }
        };

        let mut flags = 0u8;
        if !open_sent {
            flags |= FLAG_OPEN;
            open_sent = true;
        }
        if upstream_eof {
            flags |= FLAG_CLOSE;
        }
        let frame = Frame {
            session,
            flags,
            seq,
            body,
        };
        seq = seq.wrapping_add(1);

        let resp_frame = match round_trip(&pool, &frame).await {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!(error=%e, %peer, session, "round-trip failed; tearing down");
                break;
            }
        };

        if !resp_frame.body.is_empty() {
            tcp_w.write_all(&resp_frame.body).await?;
        }
        if resp_frame.is_close() {
            downstream_closed = true;
        }
        if upstream_eof && downstream_closed {
            break;
        }
    }

    let _ = tcp_w.shutdown().await;
    Ok(())
}

async fn round_trip(pool: &Arc<QuicConn>, frame: &Frame) -> Result<Frame> {
    let frame_bytes = frame.encode_vec();
    let query = dns::encode_query(&frame_bytes)?;

    // Try once on the cached connection; on any QUIC-level error, redial.
    let resp = match send_recv(pool.get().await?, &query).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error=%e, "quic stream failed; redialing");
            *pool.inner.lock().await = None;
            send_recv(pool.get().await?, &query).await?
        }
    };
    let resp_payload = dns::decode_response(resp.into())?;
    let resp_frame = Frame::decode(&resp_payload)?;
    if resp_frame.session != frame.session {
        bail!(
            "session mismatch: sent {:x} got {:x}",
            frame.session,
            resp_frame.session
        );
    }
    Ok(resp_frame)
}

async fn send_recv(conn: Connection, query: &[u8]) -> Result<Vec<u8>> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow!("open_bi: {e}"))?;
    send.write_u16(query.len() as u16).await?;
    send.write_all(query).await?;
    send.finish().ok();
    let len = recv.read_u16().await? as usize;
    if len > 64 * 1024 {
        bail!("absurd response length {len}");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}
