//! Publishes audit checkpoints to an external collector over mTLS
//! (ADR 0005).

use std::time::Duration;

use acf_audit::{CheckpointEnvelope, CheckpointPublisher, PublishError};
use async_trait::async_trait;
use rustls::ClientConfig;

const TIMEOUT: Duration = Duration::from_secs(10);

/// POSTs checkpoints to a collector such as the control plane's
/// `/v1/audit/checkpoints`.
#[derive(Clone, Debug)]
pub struct HttpCheckpointPublisher {
    url: reqwest::Url,
    http: reqwest::Client,
}

impl HttpCheckpointPublisher {
    /// A publisher for `url` (`https` only), authenticating with `tls`.
    ///
    /// # Errors
    ///
    /// Returns a message if the URL is not `https` or the client cannot be
    /// built.
    pub fn new(url: &str, tls: ClientConfig) -> Result<Self, String> {
        let url = reqwest::Url::parse(url).map_err(|e| format!("checkpoint URL: {e}"))?;
        if url.scheme() != "https" {
            return Err("checkpoint URL must be https".to_owned());
        }
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { url, http })
    }
}

#[async_trait]
impl CheckpointPublisher for HttpCheckpointPublisher {
    async fn publish(&self, envelope: &CheckpointEnvelope) -> Result<(), PublishError> {
        let body = serde_json::to_vec(envelope)
            .map_err(|_| PublishError::Unavailable("encoding".to_owned()))?;
        let response = self
            .http
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| PublishError::Unavailable("unreachable".to_owned()))?;
        match response.status().as_u16() {
            200 | 201 => Ok(()),
            409 => Err(PublishError::Conflict),
            status => Err(PublishError::Unavailable(format!("HTTP {status}"))),
        }
    }
}
