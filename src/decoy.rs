//! Cover traffic generator: maintains DoQ sessions to a list of public
//! recursive resolvers and issues real DNS A queries on a jittered timer.
//!
//! The goal is mimicry only — responses are discarded. From a passive
//! observer's view, the host is one of many DoQ clients talking to public
//! resolvers; the real tunnel (also DoQ) blends into that crowd.

use anyhow::{anyhow, bail, Context, Result};
use bytes::{BufMut, BytesMut};
use quinn::{ClientConfig, Endpoint};
use rand::seq::SliceRandom;
use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::lookup_host;

use crate::cli::DecoyConfig;
use crate::tls;

pub fn spawn(cfg: DecoyConfig) -> Result<()> {
    let crypto = tls::client_config(false)?;
    let qcfg: quinn::crypto::rustls::QuicClientConfig = crypto
        .try_into()
        .map_err(|e| anyhow!("rustls→quic config: {e}"))?;
    let client_cfg = ClientConfig::new(Arc::new(qcfg));

    // One v4 and one v6 endpoint so we can dial either family.
    let mut ep_v4 =
        Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into()).context("v4 decoy endpoint")?;
    ep_v4.set_default_client_config(client_cfg.clone());
    let mut ep_v6 = Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into()).ok();
    if let Some(ep) = ep_v6.as_mut() {
        ep.set_default_client_config(client_cfg);
    }

    let domains = Arc::new(cfg.domains);
    for (sni, port) in cfg.resolvers {
        let ep_v4 = ep_v4.clone();
        let ep_v6 = ep_v6.clone();
        let domains = domains.clone();
        let interval = cfg.interval_ms;
        tokio::spawn(async move {
            run_resolver(ep_v4, ep_v6, sni, port, domains, interval).await;
        });
    }
    Ok(())
}

async fn run_resolver(
    ep_v4: Endpoint,
    ep_v6: Option<Endpoint>,
    sni: String,
    port: u16,
    domains: Arc<Vec<String>>,
    interval_ms: u64,
) {
    loop {
        let target = match resolve_first(&sni, port).await {
            Some(t) => t,
            None => {
                tracing::debug!(%sni, "decoy resolver: failed DNS lookup; sleeping");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        let ep = match (target.is_ipv6(), ep_v6.as_ref()) {
            (true, Some(ep)) => ep.clone(),
            (true, None) => {
                tracing::debug!(%sni, "decoy: v6 endpoint unavailable, skipping");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
            (false, _) => ep_v4.clone(),
        };

        let conn = match ep.connect(target, &sni) {
            Ok(c) => match c.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(%sni, error=%e, "decoy: QUIC handshake failed; backoff");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            },
            Err(e) => {
                tracing::debug!(%sni, error=%e, "decoy: QUIC connect setup failed; backoff");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        tracing::info!(%sni, peer=%target, "decoy: connected to public DoQ resolver");

        loop {
            if let Err(e) = issue_one(&conn, pick_domain(&domains)).await {
                tracing::debug!(%sni, error=%e, "decoy: query failed; reconnecting");
                conn.close(0u32.into(), b"decoy-end");
                break;
            }
            tokio::time::sleep(jittered(interval_ms)).await;
        }
    }
}

async fn resolve_first(host: &str, port: u16) -> Option<SocketAddr> {
    lookup_host((host, port))
        .await
        .ok()
        .and_then(|mut it| it.next())
}

fn pick_domain(domains: &[String]) -> &str {
    domains
        .choose(&mut rand::thread_rng())
        .map(String::as_str)
        .unwrap_or("example.com")
}

fn jittered(mean_ms: u64) -> Duration {
    if mean_ms == 0 {
        return Duration::from_millis(1);
    }
    let lo = mean_ms / 2;
    let hi = mean_ms + mean_ms / 2;
    Duration::from_millis(rand::thread_rng().gen_range(lo..=hi))
}

/// Open a bidi stream, send one length-prefixed A-record query, read the
/// length-prefixed response, drop it.
async fn issue_one(conn: &quinn::Connection, domain: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow!("open_bi: {e}"))?;

    let query = build_a_query(domain)?;
    send.write_u16(query.len() as u16).await?;
    send.write_all(&query).await?;
    send.finish().ok();

    let len = recv.read_u16().await? as usize;
    if len > 64 * 1024 {
        bail!("absurd response length {len}");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    // discard
    Ok(())
}

/// Build a minimal valid DNS query: header + question(QTYPE=A, QCLASS=IN).
fn build_a_query(domain: &str) -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(64);
    // DoQ requires message ID = 0 (RFC 9250 §4.2.1).
    buf.put_u16(0);
    buf.put_u16(0x0100); // RD=1
    buf.put_u16(1); // QDCOUNT
    buf.put_u16(0); // ANCOUNT
    buf.put_u16(0); // NSCOUNT
    buf.put_u16(0); // ARCOUNT
    write_qname(&mut buf, domain)?;
    buf.put_u16(1); // QTYPE A
    buf.put_u16(1); // QCLASS IN
    Ok(buf.to_vec())
}

fn write_qname(buf: &mut BytesMut, domain: &str) -> Result<()> {
    for label in domain.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() {
            bail!("empty label in {domain}");
        }
        if bytes.len() > 63 {
            bail!("label too long in {domain}");
        }
        buf.put_u8(bytes.len() as u8);
        buf.put_slice(bytes);
    }
    buf.put_u8(0);
    Ok(())
}
