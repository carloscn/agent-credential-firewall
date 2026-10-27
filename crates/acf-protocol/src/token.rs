//! Capability wire encoding: JWS compact serialization (ADR 0003).
//!
//! This module only encodes and parses. Signing lives in the Capability
//! Authority and verification in `acf-identity`; neither is reachable from
//! here.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::capability::TaskCapabilityClaims;
use crate::ids::KeyId;

/// Value of the JWS `typ` header for capabilities.
pub const CAPABILITY_TYPE: &str = "acf-cap+jwt";

/// HTTP request header that carries a capability from daemon to gateway.
pub const CAPABILITY_HEADER: &str = "acf-capability";

/// Largest accepted capability token, in bytes.
pub const MAX_CAPABILITY_BYTES: usize = 8 * 1024;

/// Signature algorithms. The algorithm is a property of the trusted key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8037).
    #[serde(rename = "EdDSA")]
    EdDsa,
}

/// The JWS protected header. Exactly these members; anything else, such as
/// `crit`, `jku`, `jwk`, or `x5u`, is rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityHeader {
    /// Signature algorithm.
    pub alg: SignatureAlgorithm,
    /// Must be [`CAPABILITY_TYPE`].
    pub typ: String,
    /// Signing key.
    pub kid: KeyId,
}

/// Why a token could not be parsed or encoded. Never echoes the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// Larger than [`MAX_CAPABILITY_BYTES`].
    #[error("capability token is too large")]
    TooLarge,
    /// Not three base64url segments.
    #[error("capability token is malformed")]
    Malformed,
    /// The header is not an ACF capability header.
    #[error("capability header is not accepted")]
    Header,
    /// The claims do not parse.
    #[error("capability claims are malformed")]
    Claims,
}

/// Unpadded base64url, rejecting non-canonical input.
///
/// # Errors
///
/// Returns [`TokenError::Malformed`] for anything but canonical unpadded
/// base64url.
pub fn base64url_decode(text: &str) -> Result<Vec<u8>, TokenError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| TokenError::Malformed)
}

/// Unpadded base64url.
#[must_use]
pub fn base64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A token split into its parts. The signature has not been checked.
pub struct UnverifiedCapability<'a> {
    /// Parsed protected header.
    pub header: CapabilityHeader,
    /// `header "." payload`, the bytes the signature covers.
    pub signing_input: &'a [u8],
    /// Decoded payload. Parse it only after the signature verifies.
    pub payload: Vec<u8>,
    /// Decoded signature.
    pub signature: Vec<u8>,
}

impl fmt::Debug for UnverifiedCapability<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnverifiedCapability")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

/// Splits a compact token and checks its header.
///
/// # Errors
///
/// Returns [`TokenError`] if the token is oversized, malformed, or its header
/// is not exactly an ACF capability header.
pub fn split_capability(token: &str) -> Result<UnverifiedCapability<'_>, TokenError> {
    if token.len() > MAX_CAPABILITY_BYTES {
        return Err(TokenError::TooLarge);
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TokenError::Malformed);
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(TokenError::Malformed);
    }
    let header: CapabilityHeader =
        serde_json::from_slice(&base64url_decode(header)?).map_err(|_| TokenError::Header)?;
    if header.typ != CAPABILITY_TYPE {
        return Err(TokenError::Header);
    }
    let signing_input_len = token.len() - signature.len() - 1;
    Ok(UnverifiedCapability {
        header,
        signing_input: &token.as_bytes()[..signing_input_len],
        payload: base64url_decode(payload)?,
        signature: base64url_decode(signature)?,
    })
}

/// Parses verified payload bytes into claims.
///
/// # Errors
///
/// Returns [`TokenError::Claims`] if the payload is not exactly the claims
/// model.
pub fn parse_claims(payload: &[u8]) -> Result<TaskCapabilityClaims, TokenError> {
    serde_json::from_slice(payload).map_err(|_| TokenError::Claims)
}

/// Encodes and signs a capability. `sign` receives the signing input and
/// returns the raw signature.
///
/// # Errors
///
/// Returns [`TokenError`] if serialization fails or the result is too large.
pub fn encode_capability(
    header: &CapabilityHeader,
    claims: &TaskCapabilityClaims,
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<String, TokenError> {
    let header = serde_json::to_vec(header).map_err(|_| TokenError::Header)?;
    let claims = serde_json::to_vec(claims).map_err(|_| TokenError::Claims)?;
    let mut token = base64url_encode(&header);
    token.push('.');
    token.push_str(&base64url_encode(&claims));
    let signature = sign(token.as_bytes());
    token.push('.');
    token.push_str(&base64url_encode(&signature));
    if token.len() > MAX_CAPABILITY_BYTES {
        return Err(TokenError::TooLarge);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn header(extra: Option<(&str, &str)>) -> String {
        let mut value = json!({ "alg": "EdDSA", "typ": CAPABILITY_TYPE, "kid": "k1" });
        if let Some((key, val)) = extra {
            value[key] = json!(val);
        }
        base64url_encode(value.to_string().as_bytes())
    }

    #[test]
    fn splits_a_well_formed_token() {
        let token = format!(
            "{}.{}.{}",
            header(None),
            base64url_encode(b"{}"),
            base64url_encode(b"sig")
        );
        let parts = split_capability(&token).unwrap();
        assert_eq!(parts.header.kid.as_str(), "k1");
        assert_eq!(parts.payload, b"{}");
        assert_eq!(parts.signature, b"sig");
        assert_eq!(
            parts.signing_input,
            token.rsplit_once('.').unwrap().0.as_bytes()
        );
    }

    #[test]
    fn rejects_other_headers_and_shapes() {
        let body = base64url_encode(b"{}");
        let sig = base64url_encode(b"sig");
        for (name, extra) in [
            ("crit", "x"),
            ("jku", "https://evil"),
            ("jwk", "{}"),
            ("x5u", "https://evil"),
        ] {
            let token = format!("{}.{body}.{sig}", header(Some((name, extra))));
            assert_eq!(
                split_capability(&token).unwrap_err(),
                TokenError::Header,
                "{name}"
            );
        }
        for alg in ["none", "HS256", "ES256", "RS256"] {
            let bad = base64url_encode(
                json!({ "alg": alg, "typ": CAPABILITY_TYPE, "kid": "k1" })
                    .to_string()
                    .as_bytes(),
            );
            assert_eq!(
                split_capability(&format!("{bad}.{body}.{sig}")).unwrap_err(),
                TokenError::Header,
                "{alg}"
            );
        }
        let jwt = base64url_encode(
            json!({ "alg": "EdDSA", "typ": "JWT", "kid": "k1" })
                .to_string()
                .as_bytes(),
        );
        assert_eq!(
            split_capability(&format!("{jwt}.{body}.{sig}")).unwrap_err(),
            TokenError::Header
        );
        let h = header(None);
        for token in [
            format!("{h}.{body}"),
            format!("{h}.{body}.{sig}.x"),
            format!("{h}.{body}.{sig}="),
            format!("{h}.{body}.{sig}+"),
            format!("{h}.{body}."),
        ] {
            assert!(split_capability(&token).is_err(), "{token}");
        }
        assert_eq!(
            split_capability(&"a".repeat(MAX_CAPABILITY_BYTES + 1)).unwrap_err(),
            TokenError::TooLarge
        );
    }

    #[test]
    fn base64url_rejects_non_canonical_encodings() {
        assert_eq!(base64url_decode("AQ").unwrap(), [1]);
        assert!(base64url_decode("AR").is_err(), "trailing bits set");
        assert!(base64url_decode("AQ==").is_err(), "padding");
        assert!(base64url_decode("A/8").is_err(), "standard alphabet");
    }
}
