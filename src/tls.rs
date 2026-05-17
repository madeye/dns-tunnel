use crate::cli::AcmeConfig;
use anyhow::{Context, Result};
use futures::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;

/// ALPN for DNS-over-QUIC (RFC 9250 §4.1.1).
pub const ALPN_DOQ: &[u8] = b"doq";

pub fn client_config(insecure: bool) -> Result<rustls::ClientConfig> {
    let mut cfg = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    cfg.alpn_protocols = vec![ALPN_DOQ.to_vec()];
    cfg.enable_early_data = false;
    Ok(cfg)
}

pub fn server_config(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    sni: &str,
) -> Result<rustls::ServerConfig> {
    let (certs, key) = match (cert_path, key_path) {
        (Some(c), Some(k)) => load_pem(c, k)?,
        _ => generate_self_signed(sni)?,
    };
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("rustls server config")?;
    cfg.alpn_protocols = vec![ALPN_DOQ.to_vec()];
    cfg.max_early_data_size = 0;
    Ok(cfg)
}

/// Build a `rustls::ServerConfig` whose certificate is provisioned and
/// renewed via ACME (Let's Encrypt) using the TLS-ALPN-01 challenge type.
///
/// Spawns two background tasks:
///   * the ACME state machine (polls the CA, renews ~30d before expiry);
///   * a TCP listener on `acme.tls_port` that handles `acme-tls/1` ALPN
///     challenge connections. Real Shadowsocks traffic flows over UDP/QUIC
///     on `SS_REMOTE_PORT`; this TCP socket exists solely to satisfy the
///     challenge.
pub fn acme_server_config(acme: &AcmeConfig) -> Result<rustls::ServerConfig> {
    std::fs::create_dir_all(&acme.cache_dir)
        .with_context(|| format!("creating acme cache dir {}", acme.cache_dir.display()))?;

    let mut state = rustls_acme::AcmeConfig::new(acme.domains.clone())
        .contact_push(format!("mailto:{}", acme.contact))
        .cache(rustls_acme::caches::DirCache::new(acme.cache_dir.clone()))
        .directory_lets_encrypt(!acme.staging)
        .state();
    let resolver: Arc<dyn ResolvesServerCert> = state.resolver();
    #[allow(deprecated)]
    let acceptor = state.acceptor();

    tokio::spawn(async move {
        while let Some(event) = state.next().await {
            match event {
                Ok(ok) => tracing::info!(?ok, "acme event"),
                Err(err) => tracing::warn!(%err, "acme error"),
            }
        }
    });

    let bind: SocketAddr = (Ipv4Addr::UNSPECIFIED, acme.tls_port).into();
    let domains_dbg = acme.domains.join(",");
    tokio::spawn(async move {
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error=%e, addr=%bind, "failed to bind ACME challenge listener");
                return;
            }
        };
        tracing::info!(addr=%bind, domains=%domains_dbg, "ACME TLS-ALPN-01 challenge listener up");
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error=%e, "acme listener accept");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                use tokio_util::compat::TokioAsyncReadCompatExt;
                match acceptor.accept(stream.compat()).await {
                    Ok(None) => tracing::debug!(%peer, "served TLS-ALPN-01 challenge"),
                    Ok(Some(_)) => tracing::debug!(%peer, "dropping non-ACME TCP TLS connection"),
                    Err(e) => tracing::debug!(error=%e, %peer, "acme accept failed"),
                }
            });
        }
    });

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![ALPN_DOQ.to_vec()];
    cfg.max_early_data_size = 0;
    Ok(cfg)
}

fn load_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_bytes = std::fs::read(cert_path)
        .with_context(|| format!("reading cert {}", cert_path.display()))?;
    let key_bytes =
        std::fs::read(key_path).with_context(|| format!("reading key {}", key_path.display()))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<Result<_, _>>()
        .context("parsing cert PEM")?;
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .context("parsing key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", key_path.display()))?;
    Ok((certs, key))
}

fn generate_self_signed(
    sni: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec![sni.to_string()])
        .context("generating self-signed cert")?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("serializing self-signed key: {e}"))?;
    Ok((vec![cert_der], key_der))
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme as S;
        vec![
            S::RSA_PKCS1_SHA256,
            S::RSA_PKCS1_SHA384,
            S::RSA_PKCS1_SHA512,
            S::ECDSA_NISTP256_SHA256,
            S::ECDSA_NISTP384_SHA384,
            S::ED25519,
            S::RSA_PSS_SHA256,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA512,
        ]
    }
}
