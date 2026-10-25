//! TLS 1.3 listener with mandatory client certificates (ADR 0002), shared by
//! the gateway and the Capability Authority.
//!
//! The service terminates TLS itself. The verified leaf certificate's
//! thumbprint is attached to every request on the connection as
//! [`ConnectionInfo`]; nothing a client sends in HTTP can change it.

use std::sync::Arc;
use std::time::Duration;

use crate::{ConnectionInfo, thumbprint};
use axum::{Extension, Router};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Time allowed for a client to complete the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a TLS configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The server certificate chain is missing or malformed.
    #[error("server certificate chain is missing or not valid PEM")]
    Certificate,
    /// The private key is missing or malformed.
    #[error("server private key is missing or not valid PKCS#8 PEM")]
    PrivateKey,
    /// The client CA bundle is missing or malformed.
    #[error("client CA bundle is missing or not valid PEM")]
    ClientCa,
    /// rustls rejected the configuration.
    #[error("TLS configuration rejected: {0}")]
    Config(String),
}

/// Builds the server configuration: TLS 1.3 only, client certificates
/// required and verified against `client_ca_pem`, no 0-RTT, no session
/// tickets (every connection presents its certificate), ALPN `http/1.1`.
///
/// # Errors
///
/// Returns [`TlsError`] if any input is malformed or rustls rejects it.
pub fn server_config(
    certificate_chain_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<ServerConfig>, TlsError> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(certificate_chain_pem)
        .collect::<Result<_, _>>()
        .map_err(|_| TlsError::Certificate)?;
    if chain.is_empty() {
        return Err(TlsError::Certificate);
    }
    let key = PrivateKeyDer::from_pem_slice(private_key_pem).map_err(|_| TlsError::PrivateKey)?;

    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(client_ca_pem) {
        roots
            .add(certificate.map_err(|_| TlsError::ClientCa)?)
            .map_err(|_| TlsError::ClientCa)?;
    }
    if roots.is_empty() {
        return Err(TlsError::ClientCa);
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .map_err(|e| TlsError::Config(e.to_string()))?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// Accepts TLS connections and serves `router` on each.
///
/// Connections that fail the handshake (no, untrusted, expired, or
/// wrong-purpose client certificate; TLS below 1.3) are dropped before any
/// HTTP is read.
///
/// # Errors
///
/// Never returns under normal operation; the listener runs until the task
/// is cancelled.
pub async fn serve_tls(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    router: Router,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            // Transient accept errors (for example, file-descriptor
            // exhaustion) must not stop the listener.
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let Ok(Ok(stream)) =
                tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
            else {
                return;
            };
            let connection = ConnectionInfo {
                verified_client_certificate: stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .map(|leaf| thumbprint(leaf.as_ref())),
            };
            let service = TowerToHyperService::new(router.layer(Extension(connection)));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
