//! Official Bitwarden Rust SDK implementation of the backend boundary.

use acf_secrets::{SecretMaterial, SecretVersion};
use async_trait::async_trait;
use bitwarden_sm::{
    AccessTokenLoginRequest, ClientSettings, DeviceType, SecretsManagerClient,
    secrets::{SecretGetRequest, SecretResponse},
};
use zeroize::Zeroize;

use crate::{
    BitwardenBackend, BitwardenBackendError, BitwardenLocator, BitwardenRecord, BitwardenSettings,
};

/// SDK initialization errors with no embedded credential or vendor response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BitwardenConnectError {
    /// A tracing filter would expose the machine-account client secret.
    #[error("Bitwarden SDK sensitive logging is enabled")]
    UnsafeLoggingConfiguration,
    /// The machine-account token was not valid UTF-8.
    #[error("Bitwarden access token has invalid encoding")]
    InvalidAccessTokenEncoding,
    /// Authentication failed or returned an unauthenticated session.
    #[error("Bitwarden authentication failed")]
    AuthenticationFailed,
}

/// Authenticated implementation backed by Bitwarden's official Rust SDK.
pub struct SdkBitwardenBackend {
    client: SecretsManagerClient,
    organization_id: uuid::Uuid,
}

impl SdkBitwardenBackend {
    /// Authenticates an in-memory SDK client with a machine-account token.
    ///
    /// The token is accepted as [`SecretMaterial`], copied once into the SDK's
    /// required `String` request, and explicitly zeroized after the login
    /// future completes. No SDK state file is used.
    ///
    /// # Errors
    ///
    /// Returns a sanitized [`BitwardenConnectError`] and never an SDK error
    /// string or response body.
    pub async fn connect(
        settings: &BitwardenSettings,
        access_token: SecretMaterial,
    ) -> Result<Self, BitwardenConnectError> {
        if sdk_sensitive_logging_enabled() {
            return Err(BitwardenConnectError::UnsafeLoggingConfiguration);
        }

        let token = std::str::from_utf8(access_token.expose_secret())
            .map_err(|_| BitwardenConnectError::InvalidAccessTokenEncoding)?
            .to_owned();

        let client = SecretsManagerClient::new(Some(ClientSettings {
            identity_url: settings.identity_url().to_owned(),
            api_url: settings.api_url().to_owned(),
            user_agent: format!("agent-credential-firewall/{}", env!("CARGO_PKG_VERSION")),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            bitwarden_package_type: None,
        }));

        let mut login = AccessTokenLoginRequest {
            access_token: token,
            // Persisting SDK authentication state would create another
            // bootstrap-secret lifecycle; ACF keeps the session in memory.
            state_file: None,
        };
        let result = client.auth().login_access_token(&login).await;
        login.access_token.zeroize();
        let response = result.map_err(|_| BitwardenConnectError::AuthenticationFailed)?;
        if !response.authenticated {
            return Err(BitwardenConnectError::AuthenticationFailed);
        }

        Ok(Self {
            client,
            organization_id: settings.organization_id(),
        })
    }
}

#[async_trait]
impl BitwardenBackend for SdkBitwardenBackend {
    async fn fetch(
        &self,
        locator: BitwardenLocator,
    ) -> Result<BitwardenRecord, BitwardenBackendError> {
        // The SDK can refresh its machine-account session during a request.
        // Recheck so a dynamically reloaded tracing filter fails closed.
        if sdk_sensitive_logging_enabled() {
            return Err(BitwardenBackendError::UnsafeLoggingConfiguration);
        }

        // SDK errors can contain remote response bodies. They are intentionally
        // collapsed here rather than crossing into ACF errors or logs.
        let response = self
            .client
            .secrets()
            .get(&SecretGetRequest {
                id: locator.secret_id.into_uuid(),
            })
            .await
            .map_err(|_| BitwardenBackendError::Unavailable)?;

        convert_response(response, self.organization_id, locator.expected_project_id)
    }
}

fn sdk_sensitive_logging_enabled() -> bool {
    // In bitwarden-core 4.0.0 AccessTokenRequest derives Debug and logs its
    // client_secret at DEBUG. Its HTTP middleware also logs request bodies at
    // TRACE. Check the exact callsite targets without formatting any secret.
    tracing::enabled!(
        target: "bitwarden_core::auth::api::request::access_token_request",
        tracing::Level::DEBUG
    ) || tracing::enabled!(
        target: "bitwarden_core::client::tracing_middleware",
        tracing::Level::TRACE
    )
}

fn convert_response(
    response: SecretResponse,
    expected_organization: uuid::Uuid,
    expected_project: Option<uuid::Uuid>,
) -> Result<BitwardenRecord, BitwardenBackendError> {
    if response.organization_id != expected_organization
        || expected_project.is_some_and(|project| response.project_id != Some(project))
    {
        return Err(BitwardenBackendError::Corrupted);
    }

    let revision = u64::try_from(response.revision_date.timestamp_millis())
        .ok()
        .and_then(SecretVersion::new)
        .unwrap_or(SecretVersion::FIRST);

    // `SecretResponse` uses ordinary Strings and derives Debug. Never format
    // it. Clear unused decrypted metadata and move the value directly into
    // ACF's zeroizing secret type.
    let mut key = response.key;
    let mut note = response.note;
    key.zeroize();
    note.zeroize();

    Ok(BitwardenRecord {
        material: SecretMaterial::from_string(response.value),
        version: revision,
    })
}
