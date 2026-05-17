use crate::cli::Config;
use crate::dns;
use crate::protocol::{Frame, FLAG_CLOSE, HEADER_LEN};
use crate::tls;
use anyhow::{anyhow, bail, Context, Result};
use quinn::{Endpoint, ServerConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

type Sessions = Arc<Mutex<HashMap<u64, Arc<Session>>>>;

enum UpstreamMsg {
    Data(Vec<u8>),
    Close,
}

struct Session {
    upstream: mpsc::Sender<UpstreamMsg>,
    /// Held across queries; query handlers take this lock and read with a
    /// short timeout to gather whatever downstream bytes have accumulated.
    downstream: Mutex<OwnedReadHalf>,
}

pub async fn run(cfg: Config) -> Result<()> {
    let crypto = tls::server_config(cfg.cert.as_deref(), cfg.key.as_deref(), &cfg.sni)?;
    let qcfg: quinn::crypto::rustls::QuicServerConfig = crypto
        .try_into()
        .map_err(|e| anyhow!("rustls→quic server config: {e}"))?;
    let server_cfg = ServerConfig::with_crypto(Arc::new(qcfg));
    let endpoint = Endpoint::server(server_cfg, cfg.remote).context("binding QUIC endpoint")?;
    tracing::info!(remote=%cfg.remote, "server listening for QUIC (strict DoQ)");

    let cfg = Arc::new(cfg);
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    while let Some(incoming) = endpoint.accept().await {
        let cfg = cfg.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_quic(incoming, cfg, sessions).await {
                tracing::debug!(error=%e, "quic conn error");
            }
        });
    }
    Ok(())
}

async fn handle_quic(
    incoming: quinn::Incoming,
    cfg: Arc<Config>,
    sessions: Sessions,
) -> Result<()> {
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
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, cfg, sessions).await {
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
    sessions: Sessions,
) -> Result<()> {
    // Parse one length-prefixed DNS query from the stream
    let len = recv.read_u16().await.context("read query length")? as usize;
    if len > 64 * 1024 {
        bail!("absurd query length {len}");
    }
    let mut msg = vec![0u8; len];
    recv.read_exact(&mut msg).await.context("read query")?;
    let parsed = dns::decode_query(msg.into())?;
    let frame = Frame::decode(&parsed.payload)?;
    let frame_session = frame.session;
    let frame_seq = frame.seq;
    let frame_close = frame.is_close();
    let frame_open = frame.is_open();
    let frame_body = frame.body;

    let session = ensure_session(&sessions, &cfg, frame_session, frame_open).await?;

    if !frame_body.is_empty() {
        let _ = session.upstream.send(UpstreamMsg::Data(frame_body)).await;
    }
    if frame_close {
        let _ = session.upstream.send(UpstreamMsg::Close).await;
    }

    // Gather downstream bytes. Fast path: if data is already buffered, return
    // it immediately so an upstream burst isn't paced by the poll-hold. Slow
    // path (no data ready): hold up to ~poll_hold_ms so empty polls don't
    // hot-loop.
    let mut down_buf = vec![0u8; dns::MAX_RESPONSE_PAYLOAD - HEADER_LEN];
    let (down_body, downstream_eof) = {
        let mut reader = session.downstream.lock().await;
        match reader.try_read(&mut down_buf) {
            Ok(0) => (Vec::new(), true),
            Ok(n) => (down_buf[..n].to_vec(), false),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let hold = Duration::from_millis(dns::poll_hold_ms());
                match tokio::time::timeout(hold, reader.read(&mut down_buf)).await {
                    Ok(Ok(0)) => (Vec::new(), true),
                    Ok(Ok(n)) => (down_buf[..n].to_vec(), false),
                    Ok(Err(_)) => (Vec::new(), true),
                    Err(_) => (Vec::new(), false),
                }
            }
            Err(_) => (Vec::new(), true),
        }
    };

    let mut resp_flags = 0u8;
    if downstream_eof {
        resp_flags |= FLAG_CLOSE;
        sessions.lock().await.remove(&frame_session);
    }
    let resp_frame = Frame {
        session: frame_session,
        flags: resp_flags,
        seq: frame_seq,
        body: down_body,
    };

    let resp_msg = dns::encode_response(&parsed.qname_raw, parsed.qtype, &resp_frame.encode_vec())?;
    send.write_u16(resp_msg.len() as u16).await?;
    send.write_all(&resp_msg).await?;
    send.finish().ok();
    Ok(())
}

async fn ensure_session(
    sessions: &Sessions,
    cfg: &Config,
    session_id: u64,
    is_open: bool,
) -> Result<Arc<Session>> {
    if let Some(s) = sessions.lock().await.get(&session_id) {
        return Ok(s.clone());
    }
    if !is_open {
        bail!("unknown session {session_id:x} (no OPEN flag)");
    }
    let tcp = TcpStream::connect(cfg.local)
        .await
        .with_context(|| format!("connecting upstream {}", cfg.local))?;
    tcp.set_nodelay(true).ok();
    let (read_half, write_half) = tcp.into_split();
    let (tx, rx) = mpsc::channel::<UpstreamMsg>(32);
    let session = Arc::new(Session {
        upstream: tx,
        downstream: Mutex::new(read_half),
    });
    sessions.lock().await.insert(session_id, session.clone());
    tokio::spawn(upstream_writer(write_half, rx));
    Ok(session)
}

async fn upstream_writer(mut w: OwnedWriteHalf, mut rx: mpsc::Receiver<UpstreamMsg>) {
    while let Some(msg) = rx.recv().await {
        match msg {
            UpstreamMsg::Data(b) => {
                if w.write_all(&b).await.is_err() {
                    break;
                }
            }
            UpstreamMsg::Close => {
                let _ = w.shutdown().await;
                break;
            }
        }
    }
}
