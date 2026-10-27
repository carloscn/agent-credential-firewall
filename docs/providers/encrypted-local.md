# Encrypted Local Secret Provider

Status: Integrity-only store implemented and wired into the gateway; KEK/DEK, rollback anchor, and rotation pending

Last updated: 2026-10-27

## 1. Purpose

The encrypted local provider allows an ACF Gateway to store secrets on gateway-controlled VPS or on-premises storage without requiring a third-party secret-management service.

It is a built-in provider behind the same runtime `SecretProvider` interface used by external adapters. Agents, connector profiles, and policies cannot tell whether a secret is local or remote.

### 1.1 Implemented demo

`acf-provider-local::DemoLocalProvider` supplies a small, executable implementation for development and architecture validation:

- implements both `SecretProvider` and the separately scoped `SecretAdmin` contract;
- encrypts each secret in its own record with AES-256-GCM and a fresh random 96-bit nonce;
- derives separate encryption, record-index, and integrity keys from a 256-bit root key;
- converts logical references into HMAC-derived opaque filenames;
- authenticates the reference, monotonic version, use binding, deletion state, nonce, and ciphertext;
- uses a mode-`0700` directory, mode-`0600` files, temporary-file flush, atomic rename, and directory flush on Unix;
- keeps deletion tombstones so deleting and recreating a logical reference cannot reuse an old version;
- decrypts only the selected record during `get()`; metadata listing verifies HMACs without decrypting secret values;
- returns the stored authenticated use binding in `ResolvedSecret::attested_binding`;
- serializes writers across processes with an exclusive OS lock on `.writer.lock`.

### 1.2 Gateway wiring and key sources

The gateway opens one store per `encrypted-local` namespace at startup. It never creates a store, so a missing store stops startup.

```yaml
secret_providers:
  production:
    type: encrypted-local
    path: /var/lib/acf/store
    key_source: systemd-credential   # or mounted-file
    key_location: acf-store-production   # credential name, or the key file's absolute path
    rollback_resistance: none        # required: no anchor is implemented
```

The root key is exactly 32 bytes, read from a regular file (never through a symlink) that group and others cannot access:

| `key_source` | Where the key is read from | Profiles |
| --- | --- | --- |
| `systemd-credential` | `$CREDENTIALS_DIRECTORY/<key_location>` (default name `acf-store-<namespace>`), as set up by systemd `LoadCredential=` or `LoadCredentialEncrypted=` | Both |
| `mounted-file` | The absolute path in `key_location`, on a separately protected volume | Both |
| `insecure-development` | The path in `key_location`, without the permission check | Development only |
| `tpm`, `kms`, `interactive` | Not implemented: the gateway refuses to start | — |

**No anchor is implemented, so a configured `rollback_anchor` is refused rather than ignored.** A store must therefore acknowledge `rollback_resistance: none`. Every gateway startup states "integrity only, no rollback resistance" for each store.

Under `production` the store is accepted only on those terms: an implemented, non-development key source and the explicit acknowledgement. An older copy of a record, or of the whole directory, can therefore reactivate an older credential; restore and rotation procedures must account for that.

Stores are administered with `acf-store`, using the same configuration as the gateway. It is an operator tool, never an agent action:

```text
acf-store --config bundle.yaml [--profiles DIR] init --namespace production
acf-store --config bundle.yaml [--profiles DIR] put secret://production/…   < value
acf-store --config bundle.yaml [--profiles DIR] delete secret://production/…
acf-store --config bundle.yaml [--profiles DIR] list --namespace production
```

- `put` reads the value from standard input, never from an argument, and stores it with the use binding the configuration registers for that reference.
- Output names references and versions only.

Minimal construction:

```rust
let key = LocalStoreKey::from_material(root_key_material)?;
let provider = DemoLocalProvider::initialize(
    "/var/lib/acf-demo",
    Namespace::new("development")?,
    key,
)?;

provider.put(&reference, secret_material, binding).await?;
let resolved = provider.get(&reference).await?;
```

The root key must come from a protected operator or service bootstrap path. It must never be placed in repository configuration, command-line arguments, logs, or an agent-visible environment variable.

### 1.3 Limitations

The implementation does **not** provide every property this document specifies. In particular, it currently has:

- one process-held root key instead of a KEK and independently wrapped per-record DEKs;
- authenticated but plaintext logical-reference and binding metadata inside each opaque-named record;
- no external rollback anchor, so an older valid directory snapshot can reactivate an older credential;
- no TPM, KMS, or interactive key source, and no storage-key rotation, backup/restore ceremony, manifest reload protocol, or crash-recovery journal;
- ordinary blocking filesystem calls inside the async trait implementation;
- no protection against a privileged process reading the unlocked gateway memory;
- no guarantee that overwritten ciphertext blocks are physically erased by the filesystem or storage device.

Production deployments that use it accept these limitations explicitly through `rollback_resistance: none`. Deployments that need rollback resistance or hardware-backed keys must wait for those sections, or use an external provider.

## 2. Security properties

The provider should protect against:

- Plaintext exposure in filesystem snapshots and backups.
- Loss or theft of an encrypted data volume without the key source.
- Offline modification or corruption of stored ciphertext and authenticated metadata.
- Partial files caused by crashes or interrupted writes.
- Accidental secret disclosure through metadata, logs, or errors.
- Loading unrelated write-capable credentials while serving a read-only request.

It does not protect against a fully compromised gateway host while the provider is unlocked. A root-level attacker may read gateway process memory, invoke the unlocked provider, or alter the gateway binary. Hardware-backed keys and process isolation reduce some risks but do not eliminate this boundary.

Rollback resistance is a separate property from ciphertext integrity. Restoring an old, valid ciphertext record cannot be detected using an authentication tag stored in that same record. A deployment may claim rollback resistance only when it uses a trusted generation anchor outside the encrypted store.

## 3. Storage layout

The MVP uses an authenticated manifest plus independently encrypted records:

```text
/var/lib/acf/
├── provider.toml              # Non-secret provider and deployment metadata
├── manifest.acf               # Authenticated index and current generation
├── records/
│   ├── 01JB....record         # One encrypted secret version
│   └── 01JC....record
├── provider.lock              # Administrative writer lock
└── backup/                    # Optional encrypted snapshots
```

The manifest maps an opaque record identifier to the current encrypted record, version, binding metadata, and content digest. Logical secret paths should be encrypted or replaced with keyed identifiers when metadata confidentiality is required.

Recommended filesystem controls:

- Dedicated `acf` service user.
- Directory mode `0700` or stricter equivalent.
- Files owned by the gateway service identity.
- Encrypted volume where available.
- Backups readable only by the backup principal.
- No secret data under world-readable temporary or log directories.

Disk encryption is defense in depth. It does not replace application-layer encryption because mounted volumes are readable after host compromise.

## 4. Per-record envelope encryption

The provider uses per-record envelope encryption:

```text
Key source
    ↓ supplies or unwraps KEK
Key-encryption key (KEK)
    ↓ unwraps only the selected record key
Random record DEK
    ↓ authenticated encryption
One secret record
```

Requirements:

- Use authenticated encryption through a reviewed cryptographic library.
- Generate random keys and nonces with an operating-system CSPRNG.
- Give every record version its own nonce and preferably its own DEK.
- Bind provider ID, namespace, opaque record ID, secret version, connector/origin binding, and format version as authenticated associated data.
- Store only a wrapped record DEK alongside each ciphertext.
- Include explicit format, algorithm, and key identifiers.
- Reject unknown algorithms, versions, malformed metadata, and binding mismatches.
- Do not implement a custom cryptographic primitive.
- `get(secret_ref)` authenticates the manifest and decrypts only the selected record.
- The gateway must not deserialize an entire vault into plaintext memory.

The exact algorithm and crate should be recorded in a security ADR after review. AES-256-GCM and XChaCha20-Poly1305 are candidates only when used through maintained, audited implementations and with correct nonce management.

Separating read and write Cloudflare tokens now has a concrete memory property: a read action does not decrypt or load the write token. It does not protect against a gateway process that is itself compromised and authorized to request both records.

## 5. Key sources and deployment profiles

The provider uses a `KeySource` abstraction:

```rust
#[async_trait]
pub trait KeySource: Send + Sync {
    /// Unwraps the store's KEK at unlock time.
    async fn unwrap_kek(&self, wrapped: &WrappedKey)
        -> Result<SecretKeyMaterial, KeySourceError>;

    /// Wraps a new KEK during initialization or storage-key rotation.
    async fn wrap_kek(&self, kek: &SecretKeyMaterial)
        -> Result<WrappedKey, KeySourceError>;
}
```

The key source is involved only in unlock and storage-key rotation. While the provider is unlocked, it holds the unwrapped KEK in protected memory. It uses the KEK to unwrap a record DEK only for the record being read, and drops that DEK after use. A KMS or HSM key source is therefore not called on every request.

Holding the KEK means an unlocked provider can decrypt any record. Per-record encryption limits how much plaintext is in memory at any moment, and with it what a crash dump or buffer leak can expose. It does not protect against an attacker with control of the gateway process. Stronger read/write separation requires separate stores with separate key sources in separate gateway security domains.

Potential implementations:

- TPM- or hardware-backed sealing.
- Cloud KMS or HSM wrapping.
- Operating-system credential facility.
- Root-only file mounted from a separately protected volume.
- Interactive operator unlock for offline or small installations.

Storing the effective key next to the encrypted records under the same user and volume protects mainly against accidental disclosure and some backup scenarios. It does not create a meaningful boundary against host compromise.

ACF has explicit `development` and `production` runtime deployment profiles. Production startup validation rejects development key sources, insecure permissions, and unknown algorithms. It also rejects a store configured with neither a `rollback_anchor` nor an explicit `rollback_resistance: none` acknowledgement. Test-only key-source implementations should also be omitted from release artifacts where practical, but compile-time exclusion is defense in depth rather than the sole security boundary.

## 6. Manifest, record updates, and reload

The authenticated manifest contains no plaintext secret value:

```text
Manifest
├── magic and format_version
├── provider_id
├── generation
├── key_id
├── wrapped_kek
└── records
    └── opaque_record_id
        ├── current_version
        ├── record_file
        ├── ciphertext_digest
        └── authenticated use-binding metadata

Record envelope
├── format_version and algorithm
├── provider_id and opaque_record_id
├── secret_version
├── wrapped_record_dek
├── nonce
├── ciphertext
└── authentication_tag
```

Administrative mutation flow:

1. Acquire the exclusive writer lock.
2. Read and authenticate the current manifest.
3. Compare its generation with the external rollback anchor when configured.
4. Encrypt the changed record into a new file with a fresh nonce and record DEK.
5. Flush the record file.
6. Write and authenticate a new manifest with an incremented generation.
7. Flush the manifest and required directory metadata.
8. Atomically publish the new manifest with a rename.
9. Advance the external generation anchor to the new generation.
10. Notify running gateway instances to reload the manifest and invalidate the affected record cache.
11. Release the lock and garbage-collect unreachable record versions after the retention window.

The manifest is published before the anchor advances. Writing in the other order would let a crash between the two steps leave the anchor ahead of every valid manifest, which is a self-inflicted denial of service.

On load, let `A` be the anchor value and `G` the authenticated manifest generation:

| Condition | Action |
| --- | --- |
| `G == A` | Accept. |
| `G == A + 1` | Accept. A crash happened after publication but before the anchor advanced. Advance the anchor to `G` before serving requests. |
| `G < A` | Fail closed. The manifest has been rolled back. |
| `G > A + 1` | Fail closed. The anchor and store are inconsistent and require an audited recovery ceremony. |

Accepting `A + 1` does not reopen rollback. The only manifest that can carry generation `A + 1` is the most recently published one, so accepting it cannot reintroduce an older state.

After recovery, the provider exposes a previous or new valid generation, never a partially trusted state.

Runtime instances watch a generation notification or poll the authenticated manifest. They atomically swap validated indexes and invalidate affected cached material. Milestone 1 should keep no long-lived plaintext secret cache; a request retrieves, uses, and drops one record.

## 7. Runtime and administrative separation

The gateway runtime has exact-reference retrieval only:

```rust
#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn get(&self, reference: &SecretRef)
        -> Result<ResolvedSecret, SecretError>;
}
```

For this provider, `ResolvedSecret::attested_binding` is always present. It is read from the record's authenticated metadata.

Enumeration and mutation go through the separate `SecretAdmin` trait and a root-controlled local socket or command:

```text
acf secrets init
acf secrets put
acf secrets list-metadata
acf secrets rotate
acf secrets delete
acf secrets backup
acf secrets restore
```

Administrative commands must not accept secret values or raw keys as command-line arguments. They should use protected stdin, a restricted file descriptor, or an interactive no-echo prompt. Shell history and process arguments must never contain secrets.

The agent-facing API, MCP tools, gateway runtime identity, and connector interfaces must not expose the administrative trait or generic enumeration operations.

## 8. Use-binding metadata

Each secret version contains authenticated metadata that restricts where it may be used:

```yaml
allowed_connectors: [cloudflare]
allowed_origins: ["https://api.cloudflare.com"]
auth_slot: read
environment: production
```

The authoritative binding is the secret registration in the signed Config Registry. The gateway checks that registration before calling `get()`.

This provider stores its own copy of the binding in authenticated metadata and returns it as `attested_binding`. The gateway requires the attested binding to equal the registry binding or be narrower. On a mismatch, it fails closed.

The connector verifies the resolved origin and credential slot again before injection.

The stored copy is defense in depth. If an attacker can change the signed registry binding, the gateway still refuses a secret whose authenticated metadata does not allow the new use.

Provider administration may narrow these bindings but must not silently broaden them without an attributable administrative event and configuration review.

## 9. Rotation

Two rotations are distinct:

- **Secret rotation** replaces a downstream credential while preserving its logical reference.
- **Storage-key rotation** creates new record DEKs, changes the KEK, or re-wraps stored record keys.

Rotation produces a new record version and a monotonic manifest generation. It emits an auditable administrative event without recording old or new plaintext values.

Rollback to an older encrypted snapshot is an explicit restore operation. Restore always moves forward. It re-publishes the restored records under a new generation `A + 1`, advances the anchor, and emits an attributable administrative event. Restoring an old backup therefore never requires the anchor to move backward.

Resetting the anchor itself is reserved for the case where the anchor is lost or corrupted. It requires an audited recovery ceremony.

Without an anchor, documentation and provider status must state that an old valid snapshot can silently reactivate revoked credentials.

## 10. Rollback anchor, backup, and recovery

Supported rollback anchors may include:

- A TPM NV monotonic counter or sealed state.
- KMS-held generation state.
- A separately protected local state file when it genuinely has a stronger protection boundary.
- A remotely stored signed manifest checkpoint.

The encrypted record directory and its generation field are not an anchor for themselves.

Backups contain only authenticated ciphertext and non-secret format metadata. Key material, recovery credentials, and rollback-anchor recovery procedures must be stored in a separate security domain.

A recovery test must prove that operators can:

1. Restore encrypted records and a manifest.
2. Obtain the correct key through the configured key source.
3. Validate the manifest against the rollback anchor or perform an audited recovery ceremony.
4. Start the gateway without exporting all plaintext secrets.

Backup documentation must state that losing the only key source makes the encrypted store unrecoverable.

Detailed host-to-host, re-key, snapshot, and cross-provider migration behavior is specified in [Local Provider Data Migration](local-migration.md).

## 11. Failure behavior

The provider fails closed when:

- The key source is unavailable.
- A wrapped record DEK cannot be authenticated or unwrapped.
- The manifest, ciphertext, use-binding metadata, or associated data is modified.
- The format version or algorithm is unsupported.
- A requested namespace or exact reference is not assigned to the gateway.
- The manifest references a missing, truncated, or digest-mismatched record.
- The generation is older than the trusted rollback anchor.
- Production validation detects an insecure key source, permissions, or required anchor configuration.

Errors distinguish operational categories for recovery while never including plaintext, raw keys, ciphertext fragments, or sensitive paths beyond the logical reference permitted for audit.

## 12. Required tests

- Round-trip retrieval after process restart.
- Verification that `get()` decrypts only the selected record.
- Verification that a read request never loads the paired write credential.
- Wrong-key and wrong-record-key rejection.
- Modified-record, manifest, header, AAD, and use-binding rejection.
- Truncated-record and missing-record recovery behavior.
- Interrupted record write, manifest publication, and anchor update recovery.
- Concurrent-reader and exclusive-writer behavior.
- Manifest reload and cache invalidation after administrative mutation.
- Secret and storage-key rotation.
- Backup and forward-moving restore (restored content receives generation `A + 1`).
- Anchor reconciliation for `G == A`, `G == A + 1`, `G < A`, and `G > A + 1`.
- Old-generation rejection when an external anchor is configured.
- Attested-binding mismatch against the registry binding fails closed.
- Explicit documentation/test of absent rollback guarantees when no anchor is configured.
- Canary-secret absence from files, logs, errors, metrics, and audit events.
- Production-profile rejection of development key sources and insecure permissions.
