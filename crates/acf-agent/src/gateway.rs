//! The daemon's mTLS connection to the gateway (ADR 0002).

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use acf_protocol::{ActionRequest, ActionResponse};
use reqwest::Url;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

/// Largest gateway response the daemon reads.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Why the gateway client could not be built or used.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The gateway URL is not an `https` URL.
    #[error("gateway URL must be an https URL")]
    Url,
    /// A credential file could not be read.
    #[error("cannot read {0}")]
    Read(String),
    /// The client key is readable by group or others.
    #[error("{0} must not be accessible by group or others (chmod 600)")]
    KeyPermissions(String),
    /// A PEM file is malformed.
    #[error("{0} is not valid PEM")]
    Pem(&'static str),
    /// rustls or reqwest rejected the configuration.
    #[error("TLS configuration rejected: {0}")]
    Config(String),
    /// The gateway could not be reached.
    #[error("gateway unreachable")]
    Transport,
    /// The gateway answered with something other than an action response.
    #[error("gateway returned an unexpected response (HTTP {0})")]
    UnexpectedResponse(u16),
}

/// Reads the client private key, refusing a file that group or others can
/// access. The mode is checked on the open handle, not the path.
///
/// # Errors
///
/// Returns [`GatewayError`] if the file is unreadable or too permissive.
pub fn read_private_key(path: &Path) -> Result<Vec<u8>, GatewayError> {
    let name = path.display().to_string();
    let mut file = File::open(path).map_err(|_| GatewayError::Read(name.clone()))?;
    let metadata = file
        .metadata()
        .map_err(|_| GatewayError::Read(name.clone()))?;
    if !metadata.is_file() {
        return Err(GatewayError::Read(name));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(GatewayError::KeyPermissions(name));
    }
    let mut key = Vec::new();
    file.read_to_end(&mut key)
        .map_err(|_| GatewayError::Read(name))?;
    Ok(key)
}

/// Reads a public file such as a certificate.
///
/// # Errors
///
/// Returns [`GatewayError::Read`] if the file cannot be read.
pub fn read_public(path: &Path) -> Result<Vec<u8>, GatewayError> {
    std::fs::read(path).map_err(|_| GatewayError::Read(path.display().to_string()))
}

/// Builds the client TLS configuration: TLS 1.3 only, trusting only
/// `gateway_ca_pem`, presenting `certificate_chain_pem` with `key_pem`.
///
/// # Errors
///
/// Returns [`GatewayError`] if any input is malformed.
pub fn client_config(
    certificate_chain_pem: &[u8],
    key_pem: &[u8],
    gateway_ca_pem: &[u8],
) -> Result<ClientConfig, GatewayError> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(certificate_chain_pem)
        .collect::<Result<_, _>>()
        .map_err(|_| GatewayError::Pem("client certificate"))?;
    if chain.is_empty() {
        return Err(GatewayError::Pem("client certificate"));
    }
    let key =
        PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| GatewayError::Pem("client key"))?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(gateway_ca_pem) {
        roots
            .add(certificate.map_err(|_| GatewayError::Pem("gateway CA"))?)
            .map_err(|_| GatewayError::Pem("gateway CA"))?;
    }
    if roots.is_empty() {
        return Err(GatewayError::Pem("gateway CA"));
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| GatewayError::Config(e.to_string()))?
    .with_root_certificates(roots)
    .with_client_auth_cert(chain, key)
    .map_err(|e| GatewayError::Config(e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    Ok(config)
}

/// Sends semantic requests to the gateway over mTLS.
#[derive(Clone, Debug)]
pub struct GatewayClient {
    execute: Url,
    http: reqwest::Client,
}

impl GatewayClient {
    /// A client for the gateway at `base` (an `https` URL).
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError`] if the URL is not `https` or the client
    /// cannot be built.
    pub fn new(base: &str, tls: ClientConfig) -> Result<Self, GatewayError> {
        let base = Url::parse(base).map_err(|_| GatewayError::Url)?;
        if base.scheme() != "https" {
            return Err(GatewayError::Url);
        }
        let execute = base
            .join("/v1/actions/execute")
            .map_err(|_| GatewayError::Url)?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| GatewayError::Config(e.to_string()))?;
        Ok(Self { execute, http })
    }

    /// Sends one request; returns the HTTP status and the parsed response.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError`] if the gateway is unreachable, the response
    /// is too large, or it is not an action response.
    pub async fn execute(
        &self,
        request: &ActionRequest,
    ) -> Result<(u16, ActionResponse), GatewayError> {
        let body = serde_json::to_vec(request).map_err(|_| GatewayError::Transport)?;
        let mut response = self
            .http
            .post(self.execute.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| GatewayError::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| GatewayError::Transport)?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(GatewayError::UnexpectedResponse(status));
            }
            bytes.extend_from_slice(&chunk);
        }
        let parsed =
            serde_json::from_slice(&bytes).map_err(|_| GatewayError::UnexpectedResponse(status))?;
        Ok((status, parsed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn permissive_keys_are_refused() {
        let dir = std::env::temp_dir().join(format!("acf-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, mode, ok) in [
            ("private", 0o600, true),
            ("group", 0o640, false),
            ("world", 0o604, false),
        ] {
            let path = dir.join(name);
            let _ = std::fs::remove_file(&path);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&path)
                .unwrap();
            // The umask may have cleared bits; set the mode exactly.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(read_private_key(&path).is_ok(), ok, "{name}");
        }
        assert!(read_private_key(&dir).is_err(), "directories are refused");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_https_gateways_are_accepted() {
        let tls = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
        assert!(matches!(
            GatewayClient::new("http://127.0.0.1:8443", tls),
            Err(GatewayError::Url)
        ));
    }
}
