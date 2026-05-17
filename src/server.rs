use crate::cli::Config;
use crate::dns::{self, MsgKind};
use crate::tls;
use anyhow::{anyhow, bail, Context, Result};
use quinn::{Endpoint, ServerConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn run(cfg: Config) -> Result<()> {
    let crypto = tls::server_config(cfg.cert.as_deref(), cfg.key.as_deref(), &cfg.sni)?;
    let qcfg: quinn::crypto::rustls::QuicServerConfig = crypto
        .try_into()
        .map_err(|e| anyhow!("rustls→quic server config: {e}"))?;
    let server_cfg = ServerConfig::with_crypto(Arc::new(qcfg));
    let endpoint = Endpoint::server(server_cfg, cfg.remote).context("binding QUIC endpoint")?;
    tracing::info!(remote=%cfg.remote, "server listening for QUIC (DoQ)");

    let cfg = Arc::new(cfg);
    while let Some(incoming) = endpoint.accept().await {
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_quic(incoming, cfg).await {
                tracing::debug!(error=%e, "quic conn error");
            }
        });
    }
    Ok(())
}

async fn handle_quic(incoming: quinn::Incoming, cfg: Arc<Config>) -> Result<()> {
    let conn = incoming.await.context("QUIC handshake")?;
    let peer = conn.remote_address();
    tracing::debug!(%peer, "quic conn accepted");

    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::TimedOut) => break,
            Err(e) => {
                tracing::debug!(error=%e, %peer, "accept_bi failed");
                break;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, cfg).await {
                tracing::debug!(error=%e, "stream error");
            }
        });
    }
    Ok(())
}

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    cfg: Arc<Config>,
) -> Result<()> {
    let tcp = TcpStream::connect(cfg.local)
        .await
        .with_context(|| format!("connecting upstream {}", cfg.local))?;
    tcp.set_nodelay(true).ok();
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    // QUIC -> TCP: read framed DNS queries from client, decode, forward payload.
    let up = async {
        loop {
            let len = match recv.read_u16().await {
                Ok(n) => n as usize,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    let _ = tcp_w.shutdown().await;
                    return Ok::<_, anyhow::Error>(());
                }
                Err(e) => return Err(e.into()),
            };
            let mut msg = vec![0u8; len];
            recv.read_exact(&mut msg).await?;
            let (kind, payload) = dns::decode(msg.into())?;
            if kind != MsgKind::Query {
                bail!("expected DNS query from client, got {:?}", kind);
            }
            if !payload.is_empty() {
                tcp_w.write_all(&payload).await?;
            }
        }
    };

    // TCP -> QUIC: read TCP bytes, encode as DNS responses, frame with [u16 len].
    let down = async {
        let mut buf = vec![0u8; dns::MAX_PAYLOAD];
        loop {
            let n = tcp_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let dns_msg = dns::encode(MsgKind::Response, &buf[..n])?;
            send.write_u16(dns_msg.len() as u16).await?;
            send.write_all(&dns_msg).await?;
        }
        send.finish().ok();
        Ok::<_, anyhow::Error>(())
    };

    let _ = tokio::try_join!(up, down);
    Ok(())
}
