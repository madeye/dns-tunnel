//! NS-tunnel transport: client → public recursive resolver → our authoritative
//! NS → client. Standard DNS messages. The recursive resolver is the visible
//! peer on both ends — no direct flow between client and server exists at the
//! network layer.
//!
//! Client-side multi-path: each query advances through the resolver pool, so
//! long byte streams are chunk-striped across resolvers instead of relying on
//! per-query randomness. The cache-buster nonce embedded in
//! `nstun_codec::encode_query` ensures resolvers always re-fetch from us.
//!
//! Server-side: one UDP listener, per-query session lookup. Sessions are
//! keyed by the 64-bit Frame.session ID just like the DoQ path. Upstream
//! TCP fan-out and downstream poll-hold mirror `server::handle_stream`.

use crate::cli::{Config, NsResolverTransport};
use crate::nstun_codec::{self, query_capacity, MAX_RESPONSE_PAYLOAD};
use crate::protocol::{Frame, FLAG_CLOSE, FLAG_OPEN, HEADER_LEN};
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use quinn::{ClientConfig, Endpoint};
use rand::Rng;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};

const CLIENT_POLL_INTERVAL_MS: u64 = 80;
const CLIENT_QUERY_TIMEOUT_MS: u64 = 1500;
const CLIENT_MAX_ATTEMPTS: u32 = 3;

// ============================================================================
// Server
// ============================================================================

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

pub async fn run_server(cfg: Config) -> Result<()> {
    let zone = cfg
        .ns_zone
        .clone()
        .ok_or_else(|| anyhow!("ns-zone= required for transport=ns server"))?;
    let bind = cfg.ns_bind.unwrap_or(cfg.remote);
    let sock = Arc::new(
        UdpSocket::bind(bind)
            .await
            .context("binding NS UDP socket")?,
    );
    tracing::info!(%bind, %zone, "ns-tunnel authoritative server listening");

    let cfg = Arc::new(cfg);
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let zone = Arc::new(zone);
    loop {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = sock.recv_from(&mut buf).await.context("recv_from")?;
        buf.truncate(n);
        let sock = sock.clone();
        let sessions = sessions.clone();
        let cfg = cfg.clone();
        let zone = zone.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_packet(sock, peer, Bytes::from(buf), zone.as_str(), cfg, sessions).await
            {
                tracing::debug!(error=%e, %peer, "ns server: packet error");
            }
        });
    }
}

async fn handle_packet(
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    pkt: Bytes,
    zone: &str,
    cfg: Arc<Config>,
    sessions: Sessions,
) -> Result<()> {
    let parsed = match nstun_codec::decode_packet(pkt, zone)? {
        nstun_codec::ParsedPacket::Tunnel(q) => q,
        nstun_codec::ParsedPacket::Question(q) => {
            if !nstun_codec::question_under_zone(&q, zone) {
                bail!("question outside zone");
            }
            let msg = if q.qtype == nstun_codec::QTYPE_NS
                && nstun_codec::question_is_zone_apex(&q, zone)
            {
                nstun_codec::encode_ns_response(q.txid, &q.qname_raw, zone)?
            } else {
                nstun_codec::encode_empty_noerror(q.txid, &q.qname_raw, q.qtype)?
            };
            sock.send_to(&msg, peer)
                .await
                .context("send_to probe response")?;
            return Ok(());
        }
    };
    let frame = Frame::decode(&parsed.payload)?;
    let session_id = frame.session;
    let seq = frame.seq;
    let is_open = frame.is_open();
    let is_close = frame.is_close();
    let body = frame.body;

    let session = ensure_session(&sessions, &cfg, session_id, is_open).await?;
    if !body.is_empty() {
        let _ = session.upstream.send(UpstreamMsg::Data(body)).await;
    }
    if is_close {
        let _ = session.upstream.send(UpstreamMsg::Close).await;
    }

    let mut down_buf = vec![0u8; MAX_RESPONSE_PAYLOAD - HEADER_LEN];
    let (down_body, downstream_eof) = {
        let mut reader = session.downstream.lock().await;
        match reader.try_read(&mut down_buf) {
            Ok(0) => (Vec::new(), true),
            Ok(n) => (down_buf[..n].to_vec(), false),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let hold = Duration::from_millis(crate::dns::poll_hold_ms());
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
        sessions.lock().await.remove(&session_id);
    }
    let resp_frame = Frame {
        session: session_id,
        flags: resp_flags,
        seq,
        body: down_body,
    };
    let resp_bytes = resp_frame.encode_vec();
    let msg =
        nstun_codec::encode_response(parsed.txid, &parsed.qname_raw, parsed.qtype, &resp_bytes)?;
    sock.send_to(&msg, peer).await.context("send_to")?;
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

// ============================================================================
// Client
// ============================================================================

pub async fn run_client(cfg: Config) -> Result<()> {
    let zone = cfg
        .ns_zone
        .clone()
        .ok_or_else(|| anyhow!("ns-zone= required for transport=ns client"))?;
    let resolvers = cfg.ns_resolvers.clone().unwrap_or_default();
    if resolvers.is_empty() {
        bail!("ns-resolvers= must contain at least one host:port");
    }
    let resolved = resolve_all(&resolvers).await?;
    if resolved.is_empty() {
        bail!("ns-resolvers= resolved to zero addresses");
    }
    tracing::info!(
        ?resolved,
        cap = query_capacity(&zone),
        "ns-tunnel client: resolver pool"
    );

    let listener = TcpListener::bind(cfg.local)
        .await
        .with_context(|| format!("binding TCP listener on {}", cfg.local))?;
    tracing::info!("ns-tunnel client listening on {}", cfg.local);

    let zone = Arc::new(zone);
    let resolved = Arc::new(ResolverPool::new(resolved));
    let resolver_transport = cfg.ns_resolver_transport;
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error=%e, "accept failed");
                continue;
            }
        };
        let zone = zone.clone();
        let resolved = resolved.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client_conn(tcp, peer, zone, resolved, resolver_transport).await
            {
                tracing::debug!(error=%e, %peer, "ns-tunnel: connection ended");
            }
        });
    }
}

#[derive(Debug, Clone)]
struct ResolvedResolver {
    sni: String,
    addr: SocketAddr,
}

async fn resolve_all(specs: &[(String, u16)]) -> Result<Vec<ResolvedResolver>> {
    let mut out = Vec::new();
    for (host, port) in specs {
        use std::net::ToSocketAddrs;
        let addrs = (host.as_str(), *port)
            .to_socket_addrs()
            .with_context(|| format!("resolving {host}:{port}"))?;
        for a in addrs {
            out.push(ResolvedResolver {
                sni: host.clone(),
                addr: a,
            });
        }
    }
    Ok(out)
}

async fn handle_client_conn(
    mut tcp: TcpStream,
    peer: SocketAddr,
    zone: Arc<String>,
    resolvers: Arc<ResolverPool>,
    resolver_transport: NsResolverTransport,
) -> Result<()> {
    tcp.set_nodelay(true).ok();
    let session: u64 = rand::random();
    tracing::debug!(%peer, session, "ns-tunnel: session open");

    let (mut tcp_r, mut tcp_w) = tcp.split();
    let mut seq: u16 = 0;
    let mut open_sent = false;
    let mut upstream_eof = false;
    let mut downstream_closed = false;
    let cap = query_capacity(&zone);
    let max_body = cap.saturating_sub(HEADER_LEN);
    if max_body == 0 {
        bail!("zone {} leaves no room for payload", zone);
    }
    let mut tcp_buf = vec![0u8; max_body];

    while !downstream_closed {
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
                        _ = tokio::time::sleep(Duration::from_millis(CLIENT_POLL_INTERVAL_MS)) => Vec::new(),
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

        let resp_frame = match round_trip(&zone, &resolvers, resolver_transport, &frame).await {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!(error=%e, %peer, session, "round-trip failed; tearing down");
                break;
            }
        };
        if resp_frame.session != frame.session {
            tracing::debug!(
                sent = format!("{:x}", frame.session),
                got = format!("{:x}", resp_frame.session),
                "session mismatch; tearing down"
            );
            break;
        }

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

struct ResolverPool {
    addrs: Vec<ResolvedResolver>,
    next: AtomicUsize,
}

impl ResolverPool {
    fn new(addrs: Vec<ResolvedResolver>) -> Self {
        Self {
            addrs,
            next: AtomicUsize::new(0),
        }
    }

    fn next(&self) -> ResolvedResolver {
        let idx = self.next.fetch_add(1, Ordering::Relaxed);
        self.addrs[idx % self.addrs.len()].clone()
    }
}

async fn round_trip(
    zone: &str,
    resolvers: &ResolverPool,
    resolver_transport: NsResolverTransport,
    frame: &Frame,
) -> Result<Frame> {
    let frame_bytes = frame.encode_vec();
    let mut last_err: Option<anyhow::Error> = None;
    for _ in 0..CLIENT_MAX_ATTEMPTS {
        let resolver = resolvers.next();
        let txid: u16 = match resolver_transport {
            NsResolverTransport::Udp => rand::thread_rng().gen(),
            NsResolverTransport::Doq => 0,
        };
        let query = nstun_codec::encode_query(txid, zone, &frame_bytes)?;
        if resolver_transport == NsResolverTransport::Doq {
            match send_doq(&resolver, &query).await {
                Ok(pkt) => match nstun_codec::decode_response(pkt) {
                    Ok((got_txid, body)) if got_txid == txid => {
                        let resp = Frame::decode(&body)?;
                        return Ok(resp);
                    }
                    Ok((got_txid, _)) => {
                        last_err = Some(anyhow!("txid mismatch want={txid} got={got_txid}"));
                    }
                    Err(e) => last_err = Some(e),
                },
                Err(e) => last_err = Some(e),
            }
            continue;
        }
        let resolver_addr = resolver.addr;
        let bind: SocketAddr = if resolver_addr.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let sock = match UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e.into());
                continue;
            }
        };
        if let Err(e) = sock.connect(resolver_addr).await {
            last_err = Some(e.into());
            continue;
        }
        if let Err(e) = sock.send(&query).await {
            last_err = Some(e.into());
            continue;
        }
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(
            Duration::from_millis(CLIENT_QUERY_TIMEOUT_MS),
            sock.recv(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) => {
                let pkt = Bytes::copy_from_slice(&buf[..n]);
                match nstun_codec::decode_response(pkt) {
                    Ok((got_txid, body)) if got_txid == txid => {
                        let resp = Frame::decode(&body)?;
                        return Ok(resp);
                    }
                    Ok((got_txid, _)) => {
                        last_err = Some(anyhow!("txid mismatch want={txid} got={got_txid}"));
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            Ok(Err(e)) => last_err = Some(e.into()),
            Err(_) => {
                last_err = Some(anyhow!("query timeout to {resolver_addr}"));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("ns round-trip exhausted attempts")))
}

async fn send_doq(resolver: &ResolvedResolver, query: &[u8]) -> Result<Bytes> {
    let bind: SocketAddr = if resolver.addr.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = Endpoint::client(bind).context("creating DoQ endpoint")?;
    let crypto = crate::tls::client_config(false)?;
    let qcfg: quinn::crypto::rustls::QuicClientConfig = crypto
        .try_into()
        .map_err(|e| anyhow!("rustls→quic client config: {e}"))?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(qcfg)));
    let conn = endpoint
        .connect(resolver.addr, &resolver.sni)
        .with_context(|| format!("DoQ connect setup to {}", resolver.addr))?
        .await
        .with_context(|| format!("DoQ handshake with {}", resolver.sni))?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow!("open_bi: {e}"))?;
    send.write_u16(query.len() as u16).await?;
    send.write_all(query).await?;
    send.finish().ok();
    let len = recv.read_u16().await? as usize;
    if len > 64 * 1024 {
        bail!("absurd DoQ response length {len}");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    conn.close(0u32.into(), b"done");
    Ok(Bytes::from(buf))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Mode, NsResolverTransport, Transport};

    fn cfg_template() -> Config {
        Config {
            mode: Mode::Server,
            transport: Transport::Ns,
            local: "127.0.0.1:0".parse().unwrap(),
            remote: "127.0.0.1:0".parse().unwrap(),
            sni: String::new(),
            insecure: false,
            cert: None,
            key: None,
            acme: None,
            decoy: None,
            ns_zone: Some("t.example.com".into()),
            ns_resolvers: None,
            ns_resolver_transport: NsResolverTransport::Udp,
            ns_bind: None,
        }
    }

    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    async fn pick_free_udp() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.local_addr().unwrap()
    }

    async fn pick_free_tcp() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    }

    #[tokio::test]
    async fn loopback_echo_round_trip() {
        let echo_addr = spawn_echo().await;

        // Server: bind UDP at fixed port, ferry to echo TCP.
        let ns_bind = pick_free_udp().await;
        let mut server_cfg = cfg_template();
        server_cfg.mode = Mode::Server;
        server_cfg.local = echo_addr;
        server_cfg.remote = ns_bind;
        server_cfg.ns_bind = Some(ns_bind);
        tokio::spawn(async move {
            run_server(server_cfg).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Client: TCP listener, "resolver pool" = server's UDP addr directly.
        let client_listen = pick_free_tcp().await;
        let mut client_cfg = cfg_template();
        client_cfg.mode = Mode::Client;
        client_cfg.local = client_listen;
        client_cfg.remote = ns_bind;
        client_cfg.ns_resolvers = Some(vec![(ns_bind.ip().to_string(), ns_bind.port())]);
        tokio::spawn(async move {
            run_client(client_cfg).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Talk TCP to the client; bytes should bounce off the echo server.
        let mut conn = TcpStream::connect(client_listen).await.unwrap();
        let payload = b"hello-ns-tunnel-from-test";
        conn.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut got))
            .await
            .expect("read timeout")
            .expect("read failed");
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn loopback_large_payload() {
        let echo_addr = spawn_echo().await;
        let ns_bind = pick_free_udp().await;
        let mut server_cfg = cfg_template();
        server_cfg.mode = Mode::Server;
        server_cfg.local = echo_addr;
        server_cfg.remote = ns_bind;
        server_cfg.ns_bind = Some(ns_bind);
        tokio::spawn(async move {
            run_server(server_cfg).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client_listen = pick_free_tcp().await;
        let mut client_cfg = cfg_template();
        client_cfg.mode = Mode::Client;
        client_cfg.local = client_listen;
        client_cfg.remote = ns_bind;
        client_cfg.ns_resolvers = Some(vec![(ns_bind.ip().to_string(), ns_bind.port())]);
        tokio::spawn(async move {
            run_client(client_cfg).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut conn = TcpStream::connect(client_listen).await.unwrap();
        // Push ~8 KB through to exercise multiple queries.
        let payload: Vec<u8> = (0..8192u32).map(|i| (i & 0xff) as u8).collect();
        conn.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut got))
            .await
            .expect("read timeout")
            .expect("read failed");
        assert_eq!(got, payload);
    }
}
