//! Ed25519 keys: the authority's capability signer and job-definition
//! signatures (ADR 0003). Key files are read with `acf_identity`'s helpers.

use acf_identity::{AuthorityKey, public_key};
use acf_protocol::{
    CAPABILITY_TYPE, CapabilityHeader, IssuerId, KeyId, SignatureAlgorithm, TaskCapabilityClaims,
    TokenError, base64url_decode, base64url_encode, encode_capability,
};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

/// Signs capabilities for one issuer with one key.
pub struct CapabilitySigner {
    issuer: IssuerId,
    kid: KeyId,
    pair: Ed25519KeyPair,
}

impl std::fmt::Debug for CapabilitySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilitySigner")
            .field("issuer", &self.issuer)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl CapabilitySigner {
    /// A signer for `issuer` using `pair` under `kid`.
    #[must_use]
    pub fn new(issuer: IssuerId, kid: KeyId, pair: Ed25519KeyPair) -> Self {
        Self { issuer, kid, pair }
    }

    /// The issuer this signer signs for.
    #[must_use]
    pub fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// The trust-store entry gateways need to verify this signer.
    #[must_use]
    pub fn trust_entry(&self) -> AuthorityKey {
        AuthorityKey {
            kid: self.kid.clone(),
            issuer: self.issuer.clone(),
            alg: SignatureAlgorithm::EdDsa,
            public_key: public_key(&self.pair),
        }
    }

    /// Signs `claims`.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if the claims cannot be encoded.
    pub fn sign(&self, claims: &TaskCapabilityClaims) -> Result<String, TokenError> {
        let header = CapabilityHeader {
            alg: SignatureAlgorithm::EdDsa,
            typ: CAPABILITY_TYPE.to_owned(),
            kid: self.kid.clone(),
        };
        encode_capability(&header, claims, |input| {
            self.pair.sign(input).as_ref().to_vec()
        })
    }
}

/// A detached job-definition signature (`<file>.sig`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    /// Signing key.
    pub kid: KeyId,
    /// Unpadded base64url Ed25519 signature over the exact file bytes.
    pub signature: String,
}

/// Signs `bytes` with `pair` under `kid`.
#[must_use]
pub fn sign_detached(kid: KeyId, pair: &Ed25519KeyPair, bytes: &[u8]) -> DetachedSignature {
    DetachedSignature {
        kid,
        signature: base64url_encode(pair.sign(bytes).as_ref()),
    }
}

/// Whether `signature` is a valid signature of `bytes` by `public_key`
/// (unpadded base64url, 32 bytes).
#[must_use]
pub fn verify_detached(public_key: &str, bytes: &[u8], signature: &DetachedSignature) -> bool {
    let (Ok(key), Ok(signature)) = (
        base64url_decode(public_key),
        base64url_decode(&signature.signature),
    ) else {
        return false;
    };
    key.len() == 32
        && UnparsedPublicKey::new(&ED25519, key)
            .verify(bytes, &signature)
            .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use acf_identity::{generate_pem, parse_key_pair};

    #[test]
    fn generated_keys_round_trip_through_pem() {
        let pem = generate_pem().unwrap();
        let pair = parse_key_pair(&pem).unwrap();
        assert_eq!(public_key(&pair).len(), 43);
        assert!(parse_key_pair(&pem.replace("PRIVATE KEY", "PUBLIC KEY")).is_none());
        assert!(parse_key_pair("garbage").is_none());
    }

    #[test]
    fn detached_signatures_cover_the_exact_bytes() {
        let pair = parse_key_pair(&generate_pem().unwrap()).unwrap();
        let kid = KeyId::new("admin").unwrap();
        let signature = sign_detached(kid, &pair, b"job: a\n");
        assert!(verify_detached(&public_key(&pair), b"job: a\n", &signature));
        assert!(!verify_detached(
            &public_key(&pair),
            b"job: b\n",
            &signature
        ));
        let other = parse_key_pair(&generate_pem().unwrap()).unwrap();
        assert!(!verify_detached(
            &public_key(&other),
            b"job: a\n",
            &signature
        ));
    }
}
