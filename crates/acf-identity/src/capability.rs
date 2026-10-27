//! Capability signature verification (ADR 0003).
//!
//! The trust store holds only public keys. Nothing in this crate can sign a
//! capability; signing lives in `acf-control-plane`.

use std::collections::BTreeMap;

use acf_protocol::{
    IssuerId, KeyId, SignatureAlgorithm, TaskCapabilityClaims, TokenError, base64url_decode,
    parse_claims, split_capability,
};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;

/// Schema identifier for authority key sets.
pub const AUTHORITY_KEYS_SCHEMA: &str = "acf.authority-keys/v1";

/// Longest accepted capability lifetime (`exp − nbf`), in seconds.
pub const MAX_CAPABILITY_LIFETIME_SECS: i64 = 24 * 60 * 60;

/// One trusted authority public key.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityKey {
    /// Key identifier, matched against the token's `kid`.
    pub kid: KeyId,
    /// The only issuer this key may sign for.
    pub issuer: IssuerId,
    /// The only algorithm this key is used with.
    pub alg: SignatureAlgorithm,
    /// Raw public key, unpadded base64url.
    pub public_key: String,
}

/// The `acf.authority-keys/v1` document.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityKeys {
    /// Must be [`AUTHORITY_KEYS_SCHEMA`].
    pub schema: String,
    /// Trusted keys.
    pub keys: Vec<AuthorityKey>,
}

/// Why a key set was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityKeysError {
    /// Wrong schema identifier.
    #[error("authority key set schema must be `{AUTHORITY_KEYS_SCHEMA}`")]
    Schema,
    /// No keys.
    #[error("authority key set is empty")]
    Empty,
    /// A `kid` appears twice.
    #[error("key `{0}` appears twice")]
    DuplicateKey(String),
    /// A public key is not 32 bytes of base64url.
    #[error("key `{0}` is not a 32-byte base64url Ed25519 public key")]
    InvalidKey(String),
}

/// Why a capability was rejected. Never echoes the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    /// Malformed token, header, or claims.
    #[error("capability is malformed: {0}")]
    Token(TokenError),
    /// The `kid` is not trusted.
    #[error("capability key is not trusted")]
    UnknownKey,
    /// The header algorithm is not the key's algorithm.
    #[error("capability algorithm does not match its key")]
    Algorithm,
    /// The signature does not verify.
    #[error("capability signature is invalid")]
    Signature,
    /// `iss` is not the key's issuer.
    #[error("capability issuer does not match its key")]
    Issuer,
    /// `iat`, `nbf`, and `exp` are inconsistent or the lifetime is too long.
    #[error("capability lifetime is invalid")]
    Lifetime,
}

impl CapabilityError {
    /// A stable code for audit events.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Token(_) => "capability_malformed",
            Self::UnknownKey => "capability_unknown_key",
            Self::Algorithm => "capability_algorithm_mismatch",
            Self::Signature => "capability_bad_signature",
            Self::Issuer => "capability_issuer_mismatch",
            Self::Lifetime => "capability_lifetime_invalid",
        }
    }
}

#[derive(Clone, Debug)]
struct TrustedKey {
    issuer: IssuerId,
    alg: SignatureAlgorithm,
    public_key: [u8; 32],
}

/// Verifies capability signatures against a fixed set of authority keys.
#[derive(Clone, Debug)]
pub struct CapabilityVerifier {
    keys: BTreeMap<KeyId, TrustedKey>,
}

impl CapabilityVerifier {
    /// Builds a verifier from a validated key set.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityKeysError`] if the key set is malformed.
    pub fn new(document: AuthorityKeys) -> Result<Self, AuthorityKeysError> {
        if document.schema != AUTHORITY_KEYS_SCHEMA {
            return Err(AuthorityKeysError::Schema);
        }
        if document.keys.is_empty() {
            return Err(AuthorityKeysError::Empty);
        }
        let mut keys = BTreeMap::new();
        for key in document.keys {
            let public_key: [u8; 32] = base64url_decode(&key.public_key)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| AuthorityKeysError::InvalidKey(key.kid.to_string()))?;
            let trusted = TrustedKey {
                issuer: key.issuer,
                alg: key.alg,
                public_key,
            };
            if keys.insert(key.kid.clone(), trusted).is_some() {
                return Err(AuthorityKeysError::DuplicateKey(key.kid.to_string()));
            }
        }
        Ok(Self { keys })
    }

    /// Verifies `token` and returns its claims. Time, audience, certificate,
    /// and grant checks are the authorizer's job.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError`] as described in ADR 0003.
    pub fn verify(&self, token: &str) -> Result<TaskCapabilityClaims, CapabilityError> {
        let parts = split_capability(token).map_err(CapabilityError::Token)?;
        let key = self
            .keys
            .get(&parts.header.kid)
            .ok_or(CapabilityError::UnknownKey)?;
        if parts.header.alg != key.alg {
            return Err(CapabilityError::Algorithm);
        }
        match key.alg {
            SignatureAlgorithm::EdDsa => UnparsedPublicKey::new(&ED25519, &key.public_key)
                .verify(parts.signing_input, &parts.signature)
                .map_err(|_| CapabilityError::Signature)?,
        }
        let claims = parse_claims(&parts.payload).map_err(CapabilityError::Token)?;
        if claims.iss != key.issuer {
            return Err(CapabilityError::Issuer);
        }
        if !(claims.iat <= claims.nbf
            && claims.nbf < claims.exp
            && claims.exp - claims.nbf <= MAX_CAPABILITY_LIFETIME_SECS)
        {
            return Err(CapabilityError::Lifetime);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acf_protocol::{ActionName, Sha256Digest};
    use acf_protocol::{
        AudienceId, AuthorizationBasis, CAPABILITY_TYPE, CapabilityHeader, CapabilityId,
        CertificateThumbprint, Confirmation, Grant, Limits, PrincipalId, ResourceId, TaskId,
        TaskInfo, base64url_encode, encode_capability,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key_pair() -> Ed25519KeyPair {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
    }

    fn verifier(pairs: &[(&str, &str, &Ed25519KeyPair)]) -> CapabilityVerifier {
        CapabilityVerifier::new(AuthorityKeys {
            schema: AUTHORITY_KEYS_SCHEMA.to_owned(),
            keys: pairs
                .iter()
                .map(|(kid, issuer, pair)| AuthorityKey {
                    kid: KeyId::new(*kid).unwrap(),
                    issuer: IssuerId::new(*issuer).unwrap(),
                    alg: SignatureAlgorithm::EdDsa,
                    public_key: base64url_encode(pair.public_key().as_ref()),
                })
                .collect(),
        })
        .unwrap()
    }

    fn claims() -> TaskCapabilityClaims {
        TaskCapabilityClaims {
            iss: IssuerId::new("authority").unwrap(),
            aud: AudienceId::new("gw").unwrap(),
            sub: PrincipalId::new("workload:vps-17").unwrap(),
            jti: CapabilityId::new("cap-1").unwrap(),
            iat: 1_000,
            nbf: 1_000,
            exp: 1_900,
            cnf: Confirmation {
                x5t_s256: CertificateThumbprint::parse(
                    "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
                )
                .unwrap(),
            },
            task: TaskInfo {
                id: TaskId::new("t-1").unwrap(),
                basis: AuthorizationBasis::JobDefinition {
                    definition_digest: Sha256Digest::parse(format!("sha256:{}", "0".repeat(64)))
                        .unwrap(),
                },
            },
            grants: vec![Grant {
                action: ActionName::new("example.profile.get").unwrap(),
                resource: ResourceId::new("example-api:development").unwrap(),
                constraints: acf_protocol::ConstraintSet::default(),
            }],
            limits: Limits::default(),
        }
    }

    fn sign(kid: &str, claims: &TaskCapabilityClaims, pair: &Ed25519KeyPair) -> String {
        let header = CapabilityHeader {
            alg: SignatureAlgorithm::EdDsa,
            typ: CAPABILITY_TYPE.to_owned(),
            kid: KeyId::new(kid).unwrap(),
        };
        encode_capability(&header, claims, |input| pair.sign(input).as_ref().to_vec()).unwrap()
    }

    #[test]
    fn verifies_a_signed_capability() {
        let pair = key_pair();
        let verifier = verifier(&[("k1", "authority", &pair)]);
        assert_eq!(verifier.verify(&sign("k1", &claims(), &pair)), Ok(claims()));
    }

    #[test]
    fn rejects_untrusted_keys_forged_signatures_and_tampering() {
        let pair = key_pair();
        let attacker = key_pair();
        let verifier = verifier(&[("k1", "authority", &pair)]);
        assert_eq!(
            verifier.verify(&sign("k2", &claims(), &pair)),
            Err(CapabilityError::UnknownKey)
        );
        assert_eq!(
            verifier.verify(&sign("k1", &claims(), &attacker)),
            Err(CapabilityError::Signature)
        );

        // Swap in a payload with an extra grant, keeping the old signature.
        let token = sign("k1", &claims(), &pair);
        let mut widened = claims();
        widened.grants.push(widened.grants[0].clone());
        widened.grants[1].resource = ResourceId::new("prod-api:production").unwrap();
        let forged = sign("k1", &widened, &attacker);
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = forged.split('.').nth(1).unwrap();
        assert_eq!(
            verifier.verify(&parts.join(".")),
            Err(CapabilityError::Signature)
        );
    }

    #[test]
    fn keys_sign_only_for_their_issuer() {
        let pair = key_pair();
        let verifier = verifier(&[("k1", "other-authority", &pair)]);
        assert_eq!(
            verifier.verify(&sign("k1", &claims(), &pair)),
            Err(CapabilityError::Issuer)
        );
    }

    #[test]
    fn lifetimes_must_be_ordered_and_bounded() {
        let pair = key_pair();
        let verifier = verifier(&[("k1", "authority", &pair)]);
        for (iat, nbf, exp) in [
            (1_000, 1_000, 1_000),
            (2_000, 1_000, 3_000),
            (1_000, 1_000, 1_000 + MAX_CAPABILITY_LIFETIME_SECS + 1),
        ] {
            let mut c = claims();
            (c.iat, c.nbf, c.exp) = (iat, nbf, exp);
            assert_eq!(
                verifier.verify(&sign("k1", &c, &pair)),
                Err(CapabilityError::Lifetime),
                "{iat} {nbf} {exp}"
            );
        }
    }

    #[test]
    fn key_sets_are_validated() {
        let pair = key_pair();
        let entry = |kid: &str, public_key: String| AuthorityKey {
            kid: KeyId::new(kid).unwrap(),
            issuer: IssuerId::new("authority").unwrap(),
            alg: SignatureAlgorithm::EdDsa,
            public_key,
        };
        let good = base64url_encode(pair.public_key().as_ref());
        let set = |keys| AuthorityKeys {
            schema: AUTHORITY_KEYS_SCHEMA.to_owned(),
            keys,
        };
        assert_eq!(
            CapabilityVerifier::new(set(vec![])).unwrap_err(),
            AuthorityKeysError::Empty
        );
        assert_eq!(
            CapabilityVerifier::new(set(vec![entry("k", good.clone()), entry("k", good)]))
                .unwrap_err(),
            AuthorityKeysError::DuplicateKey("k".to_owned())
        );
        assert_eq!(
            CapabilityVerifier::new(set(vec![entry("k", base64url_encode(&[0; 31]))])).unwrap_err(),
            AuthorityKeysError::InvalidKey("k".to_owned())
        );
    }
}
