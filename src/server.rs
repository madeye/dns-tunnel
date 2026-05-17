use crate::cli::Config;
use crate::dns::{self, MsgKind};
use crate::tls;
use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::Response;
use quinn::{Endpoint, ServerConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn run(cfg: Config) -> Result<()> {
    let crypto = match &cfg.acme {
        Some(acme) => {
            tracing::info!(
                domains = ?acme.domains,
                staging = acme.staging,
                cache = %acme.cache_dir.display(),
                tls_port = acme.tls_port,
                "ACME enabled (Let's Encrypt, TLS-ALPN-01)"
            );
            tls::acme_server_config(acme)?
        }
        None => tls::server_config(cfg.cert.as_deref(), cfg.key.as_deref(), &cfg.sni)?,
    };
    let qcfg: quinn::crypto::rustls::QuicServerConfig = crypto
        .try_into()
        .map_err(|e| anyhow!("rustls→quic server config: {e}"))?;
    let server_cfg = ServerConfig::with_crypto(Arc::new(qcfg));
    let endpoint = Endpoint::server(server_cfg, cfg.remote).context("binding QUIC endpoint")?;
    tracing::info!(remote=%cfg.remote, "server listening for QUIC");

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
    let quinn_conn = h3_quinn::Connection::new(conn);
    let mut h3_conn = h3::server::Connection::new(quinn_conn)
        .await
        .context("h3 server conn")?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    let (req, stream) = match resolver.resolve_request().await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(error=%e, "request resolve failed");
                            return;
                        }
                    };
                    if let Err(e) = handle_request(req, stream, cfg).await {
                        tracing::debug!(error=%e, "request handler error");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!(error=%e, "h3 accept failed");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_request<S>(
    req: http::Request<()>,
    stream: h3::server::RequestStream<S, Bytes>,
    cfg: Arc<Config>,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
    <S as h3::quic::BidiStream<Bytes>>::SendStream: Send,
    <S as h3::quic::BidiStream<Bytes>>::RecvStream: Send,
{
    if req.uri().path() != cfg.path {
        let resp = Response::builder().status(404).body(()).unwrap();
        let (mut send, _recv) = stream.split();
        let _ = send.send_response(resp).await;
        let _ = send.finish().await;
        return Ok(());
    }

    let resp = Response::builder()
        .status(200)
        .header("content-type", "application/dns-message")
        .body(())
        .unwrap();

    let (mut send_body, mut recv_body) = stream.split();
    send_body
        .send_response(resp)
        .await
        .map_err(|e| anyhow!("send_response: {e}"))?;

    // Open upstream TCP to ss-server
    let tcp = TcpStream::connect(cfg.local)
        .await
        .with_context(|| format!("connecting upstream {}", cfg.local))?;
    tcp.set_nodelay(true).ok();
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    // Downstream H3 -> TCP (DNS queries from client)
    let up = async {
        let mut acc = BytesMut::new();
        loop {
            while !has_full_frame(&acc) {
                match recv_body
                    .recv_data()
                    .await
                    .map_err(|e| anyhow!("h3 recv_data: {e}"))?
                {
                    Some(mut chunk) => {
                        while chunk.has_remaining() {
                            let s = chunk.chunk();
                            acc.extend_from_slice(s);
                            let n = s.len();
                            chunk.advance(n);
                        }
                    }
                    None => {
                        if !acc.is_empty() {
                            bail!("trailing {} bytes without full frame", acc.len());
                        }
                        let _ = tcp_w.shutdown().await;
                        return Ok::<_, anyhow::Error>(());
                    }
                }
            }
            let msg = take_frame(&mut acc)?;
            let (kind, payload) = dns::decode(msg)?;
            if kind != MsgKind::Query {
                bail!("expected DNS query from client, got {:?}", kind);
            }
            if !payload.is_empty() {
                tcp_w.write_all(&payload).await?;
            }
        }
    };

    // TCP -> H3 (DNS responses to client)
    let down = async {
        let mut buf = vec![0u8; dns::MAX_PAYLOAD];
        loop {
            let n = tcp_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let dns_msg = dns::encode(MsgKind::Response, &buf[..n])?;
            let framed = frame(&dns_msg);
            send_body
                .send_data(framed)
                .await
                .map_err(|e| anyhow!("h3 send_data: {e}"))?;
        }
        send_body
            .finish()
            .await
            .map_err(|e| anyhow!("h3 finish: {e}"))?;
        Ok::<_, anyhow::Error>(())
    };

    let _ = tokio::try_join!(up, down);
    Ok(())
}

fn frame(msg: &Bytes) -> Bytes {
    let mut out = BytesMut::with_capacity(2 + msg.len());
    out.put_u16(msg.len() as u16);
    out.extend_from_slice(msg);
    out.freeze()
}

fn has_full_frame(acc: &BytesMut) -> bool {
    if acc.len() < 2 {
        return false;
    }
    let n = u16::from_be_bytes([acc[0], acc[1]]) as usize;
    acc.len() >= 2 + n
}

fn take_frame(acc: &mut BytesMut) -> Result<Bytes> {
    let n = u16::from_be_bytes([acc[0], acc[1]]) as usize;
    acc.advance(2);
    Ok(acc.split_to(n).freeze())
}
