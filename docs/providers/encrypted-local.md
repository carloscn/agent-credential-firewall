# Encrypted Local Secret Provider

Status: Draft

Last updated: 2026-10-24

## 1. Purpose

The encrypted local provider allows an ACF Gateway to store secrets on gateway-controlled VPS or on-premises storage without requiring a third-party secret-management service.

It is a built-in provider behind the same `SecretProvider` interface used by external adapters. Agents, connector profiles, and policies cannot tell whether a secret is local or remote.

## 2. Security properties

The provider should protect against:

- Plaintext exposure in filesystem snapshots and backups.
- Loss or theft of an encrypted data volume without the key source.
- Offline modification or corruption of stored ciphertext.
- Partial files caused by crashes or interrupted writes.
- Accidental secret disclosure through metadata, logs, or errors.

It does not protect against a fully compromised gateway host while the provider is unlocked. A root-level attacker may read gateway process memory, invoke the unlocked provider, or alter the gateway binary. Hardware-backed keys and process isolation reduce some risks but do not eliminate this boundary.

## 3. Storage layout

A typical installation uses:

```text
/var/lib/acf/
├── provider.toml       # Non-secret provider metadata
├── secrets.acf         # Authenticated encrypted store
├── secrets.acf.lock    # Process/file lock
└── backup/             # Optional encrypted snapshots
```

Recommended filesystem controls:

- Dedicated `acf` service user.
- Directory mode `0700` or stricter equivalent.
- Files owned by the gateway service identity.
- Encrypted volume where available.
- Backups readable only by the backup principal.
- No secret data under world-readable temporary or log directories.

Disk encryption is defense in depth. It does not replace application-layer encryption because mounted volumes are readable after host compromise.

## 4. Envelope encryption

The provider should use envelope encryption:

```text
Key source
    ↓ supplies or unwraps KEK
Key-encryption key (KEK)
    ↓ unwraps
Random data-encryption key (DEK)
    ↓ authenticated encryption
Secret records
```

Requirements:

- Use authenticated encryption through a reviewed cryptographic library.
- Generate random keys and nonces with an operating-system CSPRNG.
- Bind provider ID, namespace, secret path, record version, and format version as authenticated associated data.
- Use a unique nonce according to the selected algorithm's requirements.
- Store only a wrapped DEK alongside ciphertext.
- Include an explicit format version and key identifier.
- Reject unknown algorithms, versions, and malformed metadata.
- Do not implement a custom cryptographic primitive.

The exact algorithm and crate should be recorded in a security ADR after review. AES-256-GCM and XChaCha20-Poly1305 are candidates only when used through maintained, audited implementations and with correct nonce management.

## 5. Key sources

The provider uses a `KeySource` abstraction:

```rust
#[async_trait]
pub trait KeySource: Send + Sync {
    async fn unwrap_dek(&self, wrapped: &WrappedKey)
        -> Result<SecretKeyMaterial, KeySourceError>;

    async fn wrap_dek(&self, dek: &SecretKeyMaterial)
        -> Result<WrappedKey, KeySourceError>;
}
```

Potential implementations:

- TPM- or hardware-backed sealing.
- Cloud KMS or HSM wrapping.
- Operating-system credential facility.
- Root-only file mounted from a separately protected volume.
- Interactive operator unlock for offline or small installations.

Storing the effective key next to `secrets.acf` under the same user and volume protects mainly against accidental disclosure and some backup scenarios. It does not create a meaningful boundary against host compromise.

Development-only key sources must be explicitly marked insecure and rejected when production mode is enabled.

## 6. File format and updates

The MVP should favor a simple versioned encrypted snapshot over a complex encrypted database.

Conceptual envelope:

```text
Header
├── magic
├── format_version
├── provider_id
├── generation
├── key_id
└── wrapped_dek

Encrypted payload
├── namespaces
├── secret records
├── secret versions
└── metadata

Authentication tag
```

Mutation flow:

1. Acquire an exclusive lock.
2. Read and authenticate the current snapshot.
3. Apply the administrative mutation in memory.
4. Increment the generation number.
5. Encrypt a complete new snapshot with a fresh nonce.
6. Write to a new file in the same filesystem.
7. Flush file data and required directory metadata.
8. Atomically rename the new file over the old file.
9. Release the lock.

After a crash, the provider must expose either the previous valid snapshot or the new valid snapshot, never a partially written plaintext or partially trusted state.

## 7. Runtime and administrative separation

The gateway runtime needs retrieval only:

```text
get(secret_ref)
list_metadata(scope)
```

Administrative operations use a separate local command or root-controlled Unix socket:

```text
acf secrets init
acf secrets put
acf secrets rotate
acf secrets delete
acf secrets backup
acf secrets restore
```

Administrative commands must not accept secret values or raw keys as command-line arguments. They should use protected stdin, a restricted file descriptor, or an interactive no-echo prompt. Shell history and process arguments must never contain secrets.

The agent-facing API and MCP tools must not expose these generic administrative operations.

## 8. Rotation

Two rotations are distinct:

- **Secret rotation** replaces a downstream credential while preserving its logical reference.
- **Storage-key rotation** creates a new DEK or KEK and re-encrypts or re-wraps the store.

Rotation should preserve a monotonic generation number and produce an auditable administrative event without recording old or new plaintext values.

Rollback to an older encrypted snapshot must be an explicit restore operation. Silent rollback can reactivate revoked downstream credentials.

## 9. Backup and recovery

Backups contain only authenticated ciphertext and non-secret format metadata. Key material or recovery credentials must be backed up through a separate security domain.

A recovery test must prove that operators can:

1. Restore an encrypted snapshot.
2. Obtain the correct key through the configured key source.
3. Validate the snapshot generation and integrity.
4. Start the gateway without exporting all plaintext secrets.

Backup documentation must state that losing the only key source makes the encrypted store unrecoverable.

## 10. Failure behavior

The provider fails closed when:

- The key source is unavailable.
- The wrapped DEK cannot be authenticated or unwrapped.
- The ciphertext or associated data is modified.
- The format version is unsupported.
- A requested namespace or reference is not assigned to the gateway.
- The file is truncated or only a temporary update file exists.

Errors distinguish operational categories for recovery while never including plaintext, raw keys, ciphertext fragments, or sensitive paths beyond the logical reference permitted for audit.

## 11. Required tests

- Round-trip retrieval after process restart.
- Wrong-key rejection.
- Modified-ciphertext rejection.
- Modified-header/AAD rejection.
- Truncated-file recovery.
- Interrupted-write recovery.
- Concurrent-reader and exclusive-writer behavior.
- Storage-key rotation.
- Backup and restore.
- Canary-secret absence from files, logs, errors, metrics, and audit events.
- Production-mode rejection of development key sources.
