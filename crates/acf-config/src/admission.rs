//! Configuration admission: role-bound signatures and pinned digests
//! (design §7.2.3, ADR 0004).
//!
//! This module only verifies. Signing happens with administrators' keys,
//! outside the gateway.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use acf_protocol::{KeyId, Sha256Digest, base64url_decode};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::bundle::{ConfigError, parse_yaml};

/// Schema identifier for configuration trust anchors.
pub const CONFIG_TRUST_SCHEMA: &str = "acf.config-trust/v1";

const SIGNATURE_DOMAIN: &[u8] = b"acf.config-signature/v1";
const DIGEST_DOMAIN: &str = "acf.config-digest/v1\n";

/// Who may admit a kind of configuration document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigRole {
    /// Connector profiles (`acf.profile/v1`).
    ProfileAuthor,
    /// The bundle: providers, resources, secrets and use bindings
    /// (`acf.config/v1`).
    SecretAdmin,
    /// Gateway policy (`acf.policy/v1`).
    PolicyAdmin,
}

impl ConfigRole {
    /// The role's name as written in trust anchors and signatures.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProfileAuthor => "profile-author",
            Self::SecretAdmin => "secret-admin",
            Self::PolicyAdmin => "policy-admin",
        }
    }
}

impl fmt::Display for ConfigRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A detached signature file (`<file>.sig`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSignature {
    /// Signing key.
    pub kid: KeyId,
    /// Unpadded base64url Ed25519 signature over [`signing_message`].
    pub signature: String,
}

/// The bytes a configuration signature covers: a domain tag, the role, and
/// the exact file bytes.
#[must_use]
pub fn signing_message(role: ConfigRole, bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + bytes.len() + 32);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.push(0);
    message.extend_from_slice(role.as_str().as_bytes());
    message.push(0);
    message.extend_from_slice(bytes);
    message
}

/// The `sha256:<hex>` digest of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Sha256Digest {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut text = String::from("sha256:");
    for byte in digest.as_ref() {
        let _ = write!(text, "{byte:02x}");
    }
    // 32 bytes always format as a well-formed digest.
    Sha256Digest::parse(text).unwrap_or_else(|_| unreachable!())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSigner {
    kid: KeyId,
    public_key: String,
    roles: BTreeSet<ConfigRole>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPin {
    role: ConfigRole,
    sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrust {
    schema: String,
    #[serde(default)]
    signers: Vec<RawSigner>,
    #[serde(default)]
    pins: Vec<RawPin>,
}

struct Signer {
    public_key: [u8; 32],
    roles: BTreeSet<ConfigRole>,
}

/// A parsed `acf.config-trust/v1` anchor.
pub struct ConfigTrust {
    signers: BTreeMap<KeyId, Signer>,
    pins: BTreeSet<(ConfigRole, Sha256Digest)>,
}

impl fmt::Debug for ConfigTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigTrust")
            .field("signers", &self.signers.keys().collect::<Vec<_>>())
            .field("pins", &self.pins.len())
            .finish()
    }
}

/// One configuration document as read from disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFile {
    /// Name for messages, usually the path.
    pub name: String,
    /// Exact file bytes.
    pub bytes: Vec<u8>,
    /// Contents of `<file>.sig`, if present.
    pub signature: Option<Vec<u8>>,
}

/// Why a document was not admitted. Names the file, never its content.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// Neither a signature nor a pin.
    #[error("{0} is neither signed nor pinned for {1}")]
    Unadmitted(String, ConfigRole),
    /// The signature file is malformed.
    #[error("{0}.sig is malformed")]
    MalformedSignature(String),
    /// The signing key is unknown or lacks the role.
    #[error("{0} is signed by key `{1}`, which is not trusted for {2}")]
    UntrustedKey(String, String, ConfigRole),
    /// The signature does not verify.
    #[error("{0} has an invalid signature for {1}")]
    BadSignature(String, ConfigRole),
}

impl ConfigTrust {
    /// Parses and validates a trust anchor.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the document is malformed, a key is not a
    /// 32-byte base64url Ed25519 public key, a `kid` repeats, or a signer
    /// has no role.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawTrust = parse_yaml(text)?;
        let invalid = |problem: String| {
            ConfigError::Invalid(vec![crate::ConfigIssue {
                location: "config-trust".to_owned(),
                problem,
            }])
        };
        if raw.schema != CONFIG_TRUST_SCHEMA {
            return Err(invalid(format!("schema must be `{CONFIG_TRUST_SCHEMA}`")));
        }
        let mut signers = BTreeMap::new();
        for signer in raw.signers {
            let public_key: [u8; 32] = base64url_decode(&signer.public_key)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    invalid(format!(
                        "key `{}` is not a 32-byte base64url Ed25519 public key",
                        signer.kid
                    ))
                })?;
            if signer.roles.is_empty() {
                return Err(invalid(format!("key `{}` has no role", signer.kid)));
            }
            let kid = signer.kid.clone();
            if signers
                .insert(
                    signer.kid,
                    Signer {
                        public_key,
                        roles: signer.roles,
                    },
                )
                .is_some()
            {
                return Err(invalid(format!("key `{kid}` appears twice")));
            }
        }
        let pins = raw.pins.into_iter().map(|p| (p.role, p.sha256)).collect();
        Ok(Self { signers, pins })
    }

    /// Admits `file` for `role` and returns its digest.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the file is neither validly signed by a
    /// key holding `role` nor pinned for `role`.
    pub fn admit(
        &self,
        role: ConfigRole,
        file: &SourceFile,
    ) -> Result<Sha256Digest, AdmissionError> {
        let digest = sha256(&file.bytes);
        if let Some(signature) = &file.signature {
            let parsed: ConfigSignature = serde_json::from_slice(signature)
                .map_err(|_| AdmissionError::MalformedSignature(file.name.clone()))?;
            let signer = self
                .signers
                .get(&parsed.kid)
                .filter(|signer| signer.roles.contains(&role))
                .ok_or_else(|| {
                    AdmissionError::UntrustedKey(file.name.clone(), parsed.kid.to_string(), role)
                })?;
            let raw = base64url_decode(&parsed.signature)
                .map_err(|_| AdmissionError::MalformedSignature(file.name.clone()))?;
            return UnparsedPublicKey::new(&ED25519, &signer.public_key)
                .verify(&signing_message(role, &file.bytes), &raw)
                .map(|()| digest)
                .map_err(|_| AdmissionError::BadSignature(file.name.clone(), role));
        }
        if self.pins.contains(&(role, digest.clone())) {
            Ok(digest)
        } else {
            Err(AdmissionError::Unadmitted(file.name.clone(), role))
        }
    }
}

impl ConfigTrust {
    /// Admits every document and returns the configuration digest.
    ///
    /// # Errors
    ///
    /// Returns every [`AdmissionError`], not just the first.
    pub fn admit_all(
        &self,
        documents: &[(ConfigRole, &SourceFile)],
    ) -> Result<Sha256Digest, Vec<AdmissionError>> {
        let mut admitted = Vec::new();
        let mut errors = Vec::new();
        for (role, file) in documents {
            match self.admit(*role, file) {
                Ok(digest) => admitted.push((*role, digest)),
                Err(error) => errors.push(error),
            }
        }
        if errors.is_empty() {
            Ok(config_digest(&admitted))
        } else {
            Err(errors)
        }
    }
}

/// The digest of a whole admitted configuration: independent of file names
/// and order (ADR 0004).
#[must_use]
pub fn config_digest(documents: &[(ConfigRole, Sha256Digest)]) -> Sha256Digest {
    let mut lines: Vec<String> = documents
        .iter()
        .map(|(role, digest)| format!("{role} {}\n", digest.as_str()))
        .collect();
    lines.sort();
    sha256(format!("{DIGEST_DOMAIN}{}", lines.concat()).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acf_protocol::base64url_encode;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn pair() -> Ed25519KeyPair {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
    }

    fn trust(pair: &Ed25519KeyPair, roles: &str, pins: &str) -> ConfigTrust {
        ConfigTrust::parse(&format!(
            "schema: acf.config-trust/v1\nsigners:\n  - kid: k1\n    public_key: {}\n    roles: [{roles}]\npins: [{pins}]\n",
            base64url_encode(pair.public_key().as_ref())
        ))
        .unwrap()
    }

    fn signed(pair: &Ed25519KeyPair, role: ConfigRole, bytes: &[u8]) -> SourceFile {
        let signature = ConfigSignature {
            kid: KeyId::new("k1").unwrap(),
            signature: base64url_encode(pair.sign(&signing_message(role, bytes)).as_ref()),
        };
        SourceFile {
            name: "file.yaml".to_owned(),
            bytes: bytes.to_vec(),
            signature: Some(serde_json::to_vec(&signature).unwrap()),
        }
    }

    #[test]
    fn signatures_admit_only_for_the_signers_roles() {
        let key = pair();
        let trust = trust(&key, "profile-author", "");
        let file = signed(&key, ConfigRole::ProfileAuthor, b"profile");
        assert_eq!(
            trust.admit(ConfigRole::ProfileAuthor, &file),
            Ok(sha256(b"profile"))
        );
        // Same key, a role it does not hold.
        let bundle = signed(&key, ConfigRole::SecretAdmin, b"bundle");
        assert!(matches!(
            trust.admit(ConfigRole::SecretAdmin, &bundle),
            Err(AdmissionError::UntrustedKey(..))
        ));
    }

    #[test]
    fn a_signature_is_bound_to_its_role_and_bytes() {
        let key = pair();
        let trust = trust(&key, "profile-author, secret-admin", "");
        // Signed as a profile, presented as the bundle.
        let file = signed(&key, ConfigRole::ProfileAuthor, b"doc");
        assert!(matches!(
            trust.admit(ConfigRole::SecretAdmin, &file),
            Err(AdmissionError::BadSignature(..))
        ));
        let mut tampered = signed(&key, ConfigRole::SecretAdmin, b"doc");
        tampered.bytes = b"doc2".to_vec();
        assert!(matches!(
            trust.admit(ConfigRole::SecretAdmin, &tampered),
            Err(AdmissionError::BadSignature(..))
        ));
        let foreign = signed(&pair(), ConfigRole::SecretAdmin, b"doc");
        assert!(matches!(
            trust.admit(ConfigRole::SecretAdmin, &foreign),
            Err(AdmissionError::BadSignature(..))
        ));
    }

    #[test]
    fn pins_admit_exact_bytes_for_one_role() {
        let key = pair();
        let digest = sha256(b"policy");
        let trust = trust(
            &key,
            "profile-author",
            &format!("{{ role: policy-admin, sha256: \"{}\" }}", digest.as_str()),
        );
        let file = |bytes: &[u8]| SourceFile {
            name: "policy.yaml".to_owned(),
            bytes: bytes.to_vec(),
            signature: None,
        };
        assert_eq!(
            trust.admit(ConfigRole::PolicyAdmin, &file(b"policy")),
            Ok(digest)
        );
        assert!(
            trust
                .admit(ConfigRole::PolicyAdmin, &file(b"policy2"))
                .is_err()
        );
        assert!(
            trust
                .admit(ConfigRole::SecretAdmin, &file(b"policy"))
                .is_err()
        );
    }

    #[test]
    fn the_config_digest_ignores_order() {
        let a = (ConfigRole::ProfileAuthor, sha256(b"a"));
        let b = (ConfigRole::SecretAdmin, sha256(b"b"));
        assert_eq!(
            config_digest(&[a.clone(), b.clone()]),
            config_digest(&[b.clone(), a.clone()])
        );
        assert_ne!(
            config_digest(std::slice::from_ref(&a)),
            config_digest(&[a, b])
        );
    }

    #[test]
    fn trust_anchors_are_validated() {
        for text in [
            "schema: acf.config-trust/v2\n",
            "schema: acf.config-trust/v1\nsigners:\n  - { kid: k, public_key: AAAA, roles: [policy-admin] }\n",
            "schema: acf.config-trust/v1\nsigners:\n  - { kid: k, public_key: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo, roles: [] }\n",
            "schema: acf.config-trust/v1\nsigners:\n  - { kid: k, public_key: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo, roles: [root] }\n",
        ] {
            assert!(ConfigTrust::parse(text).is_err(), "{text}");
        }
    }
}
