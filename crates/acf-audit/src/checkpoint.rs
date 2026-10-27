//! Signed checkpoints of the audit chain head (ADR 0005).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use acf_protocol::{KeyId, PrincipalId, base64url_decode, base64url_encode};
use async_trait::async_trait;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::chain::{AnchorState, ChainHead, ChainedJsonSink, VerifiedLog};

/// Schema identifier for checkpoint statements.
pub const CHECKPOINT_SCHEMA: &str = "acf.audit-checkpoint/v1";
/// Schema identifier for audit key sets.
pub const AUDIT_KEYS_SCHEMA: &str = "acf.audit-keys/v1";

const SIGNATURE_DOMAIN: &[u8] = b"acf.audit-checkpoint/v1";

/// What a checkpoint asserts: the head of one log at one moment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointStatement {
    /// Must be [`CHECKPOINT_SCHEMA`].
    pub schema: String,
    /// Log identifier.
    pub log: String,
    /// Sequence number of the head.
    pub seq: u64,
    /// Hash of the head event.
    pub head: String,
    /// Gateway identifier.
    pub gateway: String,
    /// When the checkpoint was signed.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
}

/// A signed checkpoint as published and stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointEnvelope {
    /// Signing key.
    pub kid: KeyId,
    /// Unpadded base64url of the statement's JSON.
    pub payload: String,
    /// Unpadded base64url Ed25519 signature over the domain tag and payload bytes.
    pub signature: String,
}

fn signing_message(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 1 + payload.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.push(0);
    message.extend_from_slice(payload);
    message
}

/// Signs checkpoints with the gateway's audit key.
pub struct CheckpointSigner {
    kid: KeyId,
    gateway: String,
    pair: Ed25519KeyPair,
}

impl std::fmt::Debug for CheckpointSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointSigner")
            .field("kid", &self.kid)
            .field("gateway", &self.gateway)
            .finish_non_exhaustive()
    }
}

impl CheckpointSigner {
    /// A signer for `gateway` using `pair` under `kid`.
    #[must_use]
    pub fn new(kid: KeyId, gateway: String, pair: Ed25519KeyPair) -> Self {
        Self { kid, gateway, pair }
    }

    /// Signs a checkpoint of `head`.
    #[must_use]
    pub fn sign(&self, head: &ChainHead, now: OffsetDateTime) -> CheckpointEnvelope {
        let statement = CheckpointStatement {
            schema: CHECKPOINT_SCHEMA.to_owned(),
            log: head.log.clone(),
            seq: head.seq,
            head: head.hash.clone(),
            gateway: self.gateway.clone(),
            issued_at: now,
        };
        // Serializing this struct cannot fail.
        let payload = serde_json::to_vec(&statement).unwrap_or_default();
        CheckpointEnvelope {
            kid: self.kid.clone(),
            payload: base64url_encode(&payload),
            signature: base64url_encode(self.pair.sign(&signing_message(&payload)).as_ref()),
        }
    }
}

/// One trusted gateway audit key.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditKeyEntry {
    /// Key identifier.
    pub kid: KeyId,
    /// Gateway identifier the key signs for.
    pub gateway: String,
    /// mTLS principal that may submit this gateway's checkpoints.
    pub principal: PrincipalId,
    /// Raw Ed25519 public key, unpadded base64url.
    pub public_key: String,
}

/// The `acf.audit-keys/v1` document.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditKeysDocument {
    /// Must be [`AUDIT_KEYS_SCHEMA`].
    pub schema: String,
    /// Trusted keys.
    pub keys: Vec<AuditKeyEntry>,
}

/// Why a checkpoint or key set was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    /// Malformed key set.
    #[error("audit key set is invalid: {0}")]
    Keys(String),
    /// Malformed envelope or statement.
    #[error("checkpoint is malformed")]
    Malformed,
    /// The key is not trusted.
    #[error("checkpoint key `{0}` is not trusted")]
    UnknownKey(String),
    /// The signature does not verify.
    #[error("checkpoint signature is invalid")]
    BadSignature,
    /// The statement names a different gateway than the key.
    #[error("checkpoint gateway does not match its key")]
    GatewayMismatch,
}

/// Verifies checkpoints against trusted gateway audit keys.
#[derive(Clone, Debug)]
pub struct AuditKeys {
    keys: BTreeMap<KeyId, (AuditKeyEntry, [u8; 32])>,
}

impl AuditKeys {
    /// Validates a key set.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointError::Keys`] for a wrong schema, a repeated
    /// `kid`, or a malformed public key.
    pub fn new(document: AuditKeysDocument) -> Result<Self, CheckpointError> {
        if document.schema != AUDIT_KEYS_SCHEMA {
            return Err(CheckpointError::Keys(format!(
                "schema must be `{AUDIT_KEYS_SCHEMA}`"
            )));
        }
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            let raw: [u8; 32] = base64url_decode(&entry.public_key)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    CheckpointError::Keys(format!("key `{}` is not a 32-byte key", entry.kid))
                })?;
            let kid = entry.kid.clone();
            if keys.insert(kid.clone(), (entry, raw)).is_some() {
                return Err(CheckpointError::Keys(format!("key `{kid}` appears twice")));
            }
        }
        Ok(Self { keys })
    }

    /// Verifies an envelope and returns its statement and key.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointError`] if the envelope is malformed, its key is
    /// unknown, its signature fails, or its gateway differs from the key's.
    pub fn verify(
        &self,
        envelope: &CheckpointEnvelope,
    ) -> Result<(CheckpointStatement, &AuditKeyEntry), CheckpointError> {
        let (entry, public_key) = self
            .keys
            .get(&envelope.kid)
            .ok_or_else(|| CheckpointError::UnknownKey(envelope.kid.to_string()))?;
        let payload =
            base64url_decode(&envelope.payload).map_err(|_| CheckpointError::Malformed)?;
        let signature =
            base64url_decode(&envelope.signature).map_err(|_| CheckpointError::Malformed)?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&signing_message(&payload), &signature)
            .map_err(|_| CheckpointError::BadSignature)?;
        let statement: CheckpointStatement =
            serde_json::from_slice(&payload).map_err(|_| CheckpointError::Malformed)?;
        if statement.schema != CHECKPOINT_SCHEMA {
            return Err(CheckpointError::Malformed);
        }
        if statement.gateway != entry.gateway {
            return Err(CheckpointError::GatewayMismatch);
        }
        Ok((statement, entry))
    }
}

/// A checkpoint the log contradicts.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointFinding {
    /// The log ends before a checkpointed event: it was truncated.
    #[error("checkpoint at seq {seq} but the log has only {events} events: truncated")]
    Truncated {
        /// Checkpointed sequence number.
        seq: u64,
        /// Events in the log.
        events: u64,
    },
    /// The log has a different event at a checkpointed position: replaced.
    #[error("checkpoint at seq {seq} does not match the log: replaced")]
    Replaced {
        /// Checkpointed sequence number.
        seq: u64,
    },
}

/// Compares a verified log with checkpoints of the same log; checkpoints of
/// other logs are ignored.
#[must_use]
pub fn check_checkpoints(
    log: &VerifiedLog,
    checkpoints: &[CheckpointStatement],
) -> Vec<CheckpointFinding> {
    checkpoints
        .iter()
        .filter(|c| c.log == log.log)
        .filter_map(|c| match log.hash_at(c.seq) {
            None => Some(CheckpointFinding::Truncated {
                seq: c.seq,
                events: log.len(),
            }),
            Some(hash) if hash != c.head => Some(CheckpointFinding::Replaced { seq: c.seq }),
            Some(_) => None,
        })
        .collect()
}

/// Why a checkpoint was not accepted by the collector.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    /// The collector could not be reached or answered unexpectedly.
    #[error("checkpoint collector unavailable: {0}")]
    Unavailable(String),
    /// The collector holds a different history for this log.
    #[error("checkpoint conflicts with the collector's record: possible log rollback")]
    Conflict,
}

/// Sends checkpoints to an external append-only collector.
#[async_trait]
pub trait CheckpointPublisher: Send + Sync {
    /// Publishes one checkpoint; `Ok` means the collector accepted it.
    ///
    /// # Errors
    ///
    /// Returns [`PublishError`] if it was not accepted.
    async fn publish(&self, envelope: &CheckpointEnvelope) -> Result<(), PublishError>;
}

/// Signs and publishes the head now and then every `interval` when it has
/// moved, recording accepted checkpoints in `anchor`. Runs until cancelled.
pub async fn run_checkpoints(
    sink: Arc<ChainedJsonSink>,
    signer: CheckpointSigner,
    publisher: Arc<dyn CheckpointPublisher>,
    anchor: Arc<AnchorState>,
    interval: Duration,
    report: impl Fn(&str),
) {
    loop {
        if let Some(head) = sink.head()
            && anchor.anchored_seq() != Some(head.seq)
        {
            let envelope = signer.sign(&head, OffsetDateTime::now_utc());
            match publisher.publish(&envelope).await {
                Ok(()) => anchor.anchored(head.seq),
                Err(error) => report(&format!(
                    "audit checkpoint for {} seq {} not accepted: {error}",
                    head.log, head.seq
                )),
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::verify_log;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;

    fn pair() -> Ed25519KeyPair {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
    }

    fn keys(pair: &Ed25519KeyPair, gateway: &str) -> AuditKeys {
        AuditKeys::new(AuditKeysDocument {
            schema: AUDIT_KEYS_SCHEMA.to_owned(),
            keys: vec![AuditKeyEntry {
                kid: KeyId::new("gw-audit").unwrap(),
                gateway: gateway.to_owned(),
                principal: PrincipalId::new("gateway:gw-1").unwrap(),
                public_key: base64url_encode(pair.public_key().as_ref()),
            }],
        })
        .unwrap()
    }

    fn head(seq: u64, hash: &str) -> ChainHead {
        ChainHead {
            log: "log-1".to_owned(),
            seq,
            hash: hash.to_owned(),
        }
    }

    #[test]
    fn signed_checkpoints_verify_only_with_the_gateways_key() {
        let key = pair();
        let signer = CheckpointSigner::new(KeyId::new("gw-audit").unwrap(), "gw-1".to_owned(), key);
        let envelope = signer.sign(&head(4, "sha256:aa"), OffsetDateTime::UNIX_EPOCH);
        let other = pair();
        let trusted = keys(&signer.pair, "gw-1");
        let (statement, entry) = trusted.verify(&envelope).unwrap();
        assert_eq!((statement.seq, statement.head.as_str()), (4, "sha256:aa"));
        assert_eq!(entry.principal.as_str(), "gateway:gw-1");
        assert_eq!(
            keys(&other, "gw-1").verify(&envelope),
            Err(CheckpointError::BadSignature)
        );
        assert_eq!(
            keys(&signer.pair, "gw-2").verify(&envelope),
            Err(CheckpointError::GatewayMismatch)
        );
        // A statement swapped under an existing signature.
        let forged =
            CheckpointSigner::new(KeyId::new("gw-audit").unwrap(), "gw-1".to_owned(), other)
                .sign(&head(9, "sha256:bb"), OffsetDateTime::UNIX_EPOCH);
        let swapped = CheckpointEnvelope {
            payload: forged.payload,
            ..envelope
        };
        assert_eq!(
            keys(&signer.pair, "gw-1").verify(&swapped),
            Err(CheckpointError::BadSignature)
        );
    }

    #[test]
    fn checkpoints_expose_truncation_and_replacement() {
        let line = |seq: u64, prev: &str| {
            format!(r#"{{"n":{seq},"chain":{{"log":"log-1","seq":{seq},"prev":"{prev}"}}}}"#)
        };
        let mut text = String::new();
        let mut prev = crate::chain::genesis("log-1");
        for seq in 0..3 {
            let l = line(seq, &prev);
            prev = crate::chain::line_hash(l.as_bytes());
            text.push_str(&l);
            text.push('\n');
        }
        let log = verify_log(text.as_bytes()).unwrap();
        let statement = |seq: u64, head: &str| CheckpointStatement {
            schema: CHECKPOINT_SCHEMA.to_owned(),
            log: "log-1".to_owned(),
            seq,
            head: head.to_owned(),
            gateway: "gw-1".to_owned(),
            issued_at: OffsetDateTime::UNIX_EPOCH,
        };
        let good = statement(1, log.hash_at(1).unwrap());
        assert!(check_checkpoints(&log, std::slice::from_ref(&good)).is_empty());
        assert_eq!(
            check_checkpoints(&log, &[statement(5, "sha256:x")]),
            [CheckpointFinding::Truncated { seq: 5, events: 3 }]
        );
        assert_eq!(
            check_checkpoints(&log, &[statement(2, "sha256:x")]),
            [CheckpointFinding::Replaced { seq: 2 }]
        );
        let mut other_log = good;
        other_log.log = "log-2".to_owned();
        other_log.seq = 99;
        assert!(check_checkpoints(&log, &[other_log]).is_empty());
    }
}
