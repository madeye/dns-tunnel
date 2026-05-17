use crate::cli::Config;
use crate::dns::{self, MsgKind};
use crate::tls;
use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use http::Request;
use quinn::{ClientConfig, Endpoint};
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
    let h3 = Arc::new(H3Conn::new(endpoint, cfg.clone()));

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error=%e, "accept failed");
                continue;
            }
        };
        let h3 = h3.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, peer, h3, cfg).await {
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

/// Pooled h3 client connection that reconnects on demand.
struct H3Conn {
    endpoint: Endpoint,
    cfg: Config,
    inner: Mutex<Option<SendRequest<OpenStreams, Bytes>>>,
}

impl H3Conn {
    fn new(endpoint: Endpoint, cfg: Config) -> Self {
        Self {
            endpoint,
            cfg,
            inner: Mutex::new(None),
        }
    }

    async fn get(&self) -> Result<SendRequest<OpenStreams, Bytes>> {
        let mut guard = self.inner.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }
        let send = self.dial().await?;
        *guard = Some(send.clone());
        Ok(send)
    }

    async fn invalidate(&self) {
        let mut guard = self.inner.lock().await;
        *guard = None;
    }

    async fn dial(&self) -> Result<SendRequest<OpenStreams, Bytes>> {
        tracing::info!(remote=%self.cfg.remote, sni=%self.cfg.sni, "dialing QUIC");
        let connecting = self
            .endpoint
            .connect(self.cfg.remote, &self.cfg.sni)
            .context("QUIC connect()")?;
        let conn = connecting.await.context("QUIC handshake")?;
        let quinn_conn = h3_quinn::Connection::new(conn);
        let (mut driver, send_request) = h3::client::new(quinn_conn)
            .await
            .context("h3::client::new")?;
        tokio::spawn(async move {
            // Drive the connection until it closes.
            let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
            tracing::debug!("h3 connection driver finished");
        });
        Ok(send_request)
    }
}

async fn handle_conn(
    mut tcp: TcpStream,
    peer: SocketAddr,
    pool: Arc<H3Conn>,
    cfg: Config,
) -> Result<()> {
    tcp.set_nodelay(true).ok();
    let url = format!("https://{}{}", cfg.sni, cfg.path);
    tracing::debug!(%peer, %url, "new tunnel");

    // Try once, reconnect on failure
    let mut send_request = pool.get().await?;
    let req = Request::post(&url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(())
        .context("building request")?;
    let stream = match send_request.send_request(req).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error=%e, "send_request failed, invalidating pool");
            pool.invalidate().await;
            send_request = pool.get().await?;
            let req = Request::post(&url)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(())
                .unwrap();
            send_request
                .send_request(req)
                .await
                .context("send_request retry")?
        }
    };

    let (mut send_body, mut recv_body) = stream.split();
    let (mut tcp_r, mut tcp_w) = tcp.split();

    // TCP -> H3 (DNS queries)
    let up = async {
        let mut buf = vec![0u8; dns::MAX_PAYLOAD];
        loop {
            let n = tcp_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let dns_msg = dns::encode(MsgKind::Query, &buf[..n])?;
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

    // H3 -> TCP (DNS responses)
    let down = async {
        let mut acc = BytesMut::new();
        loop {
            // Pull more bytes if we don't yet have a full frame
            while !has_full_frame(&acc) {
                match recv_body
                    .recv_data()
                    .await
                    .map_err(|e| anyhow!("h3 recv_data: {e}"))?
                {
                    Some(chunk) => {
                        // h3 0.0.8 returns Buf chunks; copy into accumulator
                        let mut chunk = chunk;
                        while chunk.has_remaining() {
                            let s = chunk.chunk();
                            acc.extend_from_slice(s);
                            let n = s.len();
                            chunk.advance(n);
                        }
                    }
                    None => {
                        if !acc.is_empty() {
                            bail!("trailing {} bytes without full DNS frame", acc.len());
                        }
                        let _ = tcp_w.shutdown().await;
                        return Ok::<_, anyhow::Error>(());
                    }
                }
            }
            let msg = take_frame(&mut acc)?;
            let (kind, payload) = dns::decode(msg)?;
            if kind != MsgKind::Response {
                bail!("expected DNS response from server, got {:?}", kind);
            }
            if !payload.is_empty() {
                tcp_w.write_all(&payload).await?;
            }
        }
    };

    let result = tokio::try_join!(up, down);
    if let Err(e) = &result {
        tracing::debug!(error=%e, %peer, "tunnel error");
    }
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
