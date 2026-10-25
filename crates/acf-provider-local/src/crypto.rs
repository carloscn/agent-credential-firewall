//! Cryptographic record format for the local provider demo.

use acf_secrets::{SecretRef, SecretUseBinding, SecretVersion};
use ring::{aead, hmac};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::provider::LocalStoreKey;

pub(crate) const FORMAT_VERSION: u8 = 1;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordMetadata {
    pub(crate) format_version: u8,
    pub(crate) reference: SecretRef,
    pub(crate) version: SecretVersion,
    pub(crate) binding: SecretUseBinding,
    pub(crate) deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordEnvelope {
    pub(crate) metadata: RecordMetadata,
    pub(crate) nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) integrity: Vec<u8>,
}

pub(crate) struct DerivedKeys {
    encryption: Zeroizing<[u8; 32]>,
    integrity: Zeroizing<[u8; 32]>,
    index: Zeroizing<[u8; 32]>,
}

impl DerivedKeys {
    #[allow(clippy::needless_pass_by_value)] // consume and promptly drop the root key
    pub(crate) fn new(root: LocalStoreKey, namespace: &str) -> Self {
        Self {
            encryption: derive(root.as_bytes(), b"encryption", namespace),
            integrity: derive(root.as_bytes(), b"integrity", namespace),
            index: derive(root.as_bytes(), b"index", namespace),
        }
    }

    pub(crate) fn record_name(&self, reference: &SecretRef) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.index.as_ref());
        let tag = hmac::sign(&key, reference.as_str().as_bytes());
        let mut name = hex(tag.as_ref());
        name.push_str(".acf-record");
        name
    }

    pub(crate) fn seal(
        &self,
        metadata: RecordMetadata,
        plaintext: &[u8],
        nonce: [u8; NONCE_LEN],
    ) -> Result<RecordEnvelope, CryptoError> {
        let aad = metadata_bytes(&metadata)?;
        let mut ciphertext = plaintext.to_vec();
        let key = encryption_key(&self.encryption)?;
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad.as_slice()),
            &mut ciphertext,
        )
        .map_err(|_| CryptoError::Failed)?;

        let mut envelope = RecordEnvelope {
            metadata,
            nonce: nonce.to_vec(),
            ciphertext,
            integrity: Vec::new(),
        };
        envelope.integrity = self.integrity_tag(&envelope)?;
        Ok(envelope)
    }

    pub(crate) fn tombstone(
        &self,
        mut metadata: RecordMetadata,
    ) -> Result<RecordEnvelope, CryptoError> {
        metadata.deleted = true;
        let mut envelope = RecordEnvelope {
            metadata,
            nonce: Vec::new(),
            ciphertext: Vec::new(),
            integrity: Vec::new(),
        };
        envelope.integrity = self.integrity_tag(&envelope)?;
        Ok(envelope)
    }

    pub(crate) fn verify(&self, envelope: &RecordEnvelope) -> Result<(), CryptoError> {
        validate_shape(envelope)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.integrity.as_ref());
        hmac::verify(&key, &integrity_input(envelope)?, &envelope.integrity)
            .map_err(|_| CryptoError::Failed)
    }

    pub(crate) fn open(&self, mut envelope: RecordEnvelope) -> Result<Vec<u8>, CryptoError> {
        self.verify(&envelope)?;
        if envelope.metadata.deleted {
            return Err(CryptoError::Deleted);
        }
        let aad = metadata_bytes(&envelope.metadata)?;
        let nonce: [u8; NONCE_LEN] = envelope
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Failed)?;
        let key = encryption_key(&self.encryption)?;
        let plaintext = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.as_slice()),
                &mut envelope.ciphertext,
            )
            .map_err(|_| CryptoError::Failed)?;
        let plaintext_len = plaintext.len();
        envelope.ciphertext.truncate(plaintext_len);
        Ok(envelope.ciphertext)
    }

    pub(crate) fn key_check(&self, namespace: &str) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.integrity.as_ref());
        let mut context = hmac::Context::with_key(&key);
        context.update(b"acf-local-demo-key-check-v1");
        context.update(namespace.as_bytes());
        context.sign().as_ref().to_vec()
    }

    pub(crate) fn verify_key_check(
        &self,
        namespace: &str,
        candidate: &[u8],
    ) -> Result<(), CryptoError> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.integrity.as_ref());
        let mut input = Vec::from(b"acf-local-demo-key-check-v1".as_slice());
        input.extend_from_slice(namespace.as_bytes());
        hmac::verify(&key, &input, candidate).map_err(|_| CryptoError::Failed)
    }

    fn integrity_tag(&self, envelope: &RecordEnvelope) -> Result<Vec<u8>, CryptoError> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.integrity.as_ref());
        Ok(hmac::sign(&key, &integrity_input(envelope)?)
            .as_ref()
            .to_vec())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CryptoError {
    Failed,
    Deleted,
}

fn derive(root: &[u8; 32], label: &[u8], namespace: &str) -> Zeroizing<[u8; 32]> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, root);
    let mut context = hmac::Context::with_key(&key);
    context.update(b"acf-local-demo-kdf-v1");
    context.update(label);
    context.update(namespace.as_bytes());
    let mut derived = Zeroizing::new([0_u8; 32]);
    derived.copy_from_slice(context.sign().as_ref());
    derived
}

fn encryption_key(bytes: &[u8; 32]) -> Result<aead::LessSafeKey, CryptoError> {
    aead::UnboundKey::new(&aead::AES_256_GCM, bytes)
        .map(aead::LessSafeKey::new)
        .map_err(|_| CryptoError::Failed)
}

fn metadata_bytes(metadata: &RecordMetadata) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    serde_json::to_vec(metadata)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Failed)
}

fn integrity_input(envelope: &RecordEnvelope) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let metadata = metadata_bytes(&envelope.metadata)?;
    let mut input = Zeroizing::new(Vec::with_capacity(
        48 + metadata.len() + envelope.nonce.len() + envelope.ciphertext.len(),
    ));
    input.extend_from_slice(b"acf-local-demo-envelope-v1");
    input.extend_from_slice(
        &u64::try_from(metadata.len())
            .map_err(|_| CryptoError::Failed)?
            .to_be_bytes(),
    );
    input.extend_from_slice(&metadata);
    input.extend_from_slice(&envelope.nonce);
    input.extend_from_slice(&envelope.ciphertext);
    Ok(input)
}

fn validate_shape(envelope: &RecordEnvelope) -> Result<(), CryptoError> {
    if envelope.metadata.format_version != FORMAT_VERSION || envelope.integrity.len() != 32 {
        return Err(CryptoError::Failed);
    }
    if envelope.metadata.deleted {
        if !envelope.nonce.is_empty() || !envelope.ciphertext.is_empty() {
            return Err(CryptoError::Failed);
        }
    } else if envelope.nonce.len() != NONCE_LEN || envelope.ciphertext.len() < TAG_LEN {
        return Err(CryptoError::Failed);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
