# Local Provider Data Migration

Status: Design draft; demo implementation supports offline same-key copies only

Last updated: 2026-10-25

## 1. Goals and boundaries

This document defines how encrypted local-provider data moves between hosts, keys, and provider implementations without exposing reusable credentials to an agent.

Migration is an administrative control-plane operation. It is never an agent action, connector action, Skill, MCP tool, or generic secret-export endpoint. Only a separately authorized administrative identity may start it.

The design covers:

1. Moving an encrypted local store to another host while retaining its key and namespace.
2. Moving a local store while changing its root key or key source.
3. Migrating logical secrets between different `SecretProvider` implementations, such as Bitwarden and the encrypted local provider.

Migration does not weaken the core rule: agents request semantic actions and never receive reusable credentials.

## 2. Required invariants

Every migration must preserve or explicitly transform:

- the exact logical `SecretRef`;
- the authenticated `SecretUseBinding`;
- deletion tombstones or equivalent version history;
- secret freshness and version semantics;
- namespace ownership;
- an attributable administrative audit trail;
- confidentiality of root keys, KEKs, DEKs, and secret plaintext;
- a deterministic cutover point between source and destination.

A migration must fail closed when records are missing, duplicated, malformed, unauthenticated, outside the requested scope, or bound more broadly at the destination.

The source remains authoritative until destination verification and an explicit cutover succeed.

## 3. Current demo portability

The current `DemoLocalProvider` directory contains:

```text
store.acf                       # format, namespace, HMAC key check
<opaque HMAC>.acf-record        # authenticated metadata and ciphertext
```

The directory is path-independent and JSON-based, so an offline copy can be opened on another compatible host when all of these remain identical:

- root key;
- namespace;
- record format version;
- complete set of live records and deletion tombstones.

The root key is not stored in the directory. It must be transferred through a separate protected channel and supplied again when the destination opens the store.

The demo does not have a global manifest or cross-process writer lock. Copying it while administrative writes continue can produce a mixed snapshot. Therefore the only supported demo migration procedure is:

1. Stop or quiesce all administrative writes.
2. Flush and close the source provider.
3. Take an atomic filesystem or volume snapshot of the whole directory.
4. Transfer the encrypted snapshot.
5. Transfer the root key through a different protected channel.
6. Restore directory mode `0700` and file mode `0600` on Unix.
7. Open the destination with the same namespace and root key.
8. Verify every record and tombstone before enabling reads.
9. Cut over gateway configuration.
10. Retain the source in a sealed, read-disabled state for the recovery window, then destroy it according to policy.

Because the demo has no external rollback anchor, an older valid snapshot is indistinguishable from the newest state. Offline copy support must not be described as rollback resistance.

## 4. Portable encrypted snapshot

The production provider should export an encrypted snapshot package containing no root key or plaintext secret:

```text
acf-local-snapshot/
├── snapshot.json
├── manifest.acf
└── records/
    └── <opaque-record-id>.record
```

`snapshot.json` contains non-secret transfer metadata:

```yaml
format_version: 1
provider_format: acf-local-v1
provider_id: gateway-production
namespace: production
generation: 184
record_count: 27
created_at: 2026-10-25T09:00:00Z
manifest_digest: sha256:...
rollback_anchor_requirement: external
```

The authenticated manifest remains the authority for record IDs, versions, bindings, tombstones, ciphertext digests, and generation. The package must be deterministic enough to verify counts and digests, but it must not expose secret values or unencrypted key material.

The snapshot operation must hold the administrative writer lock or use an equivalent storage snapshot transaction. Copying individual files without a stable manifest generation is unsupported.

## 5. Key handling during migration

Encrypted data and the key capable of decrypting it must use different transfer channels and access principals.

Acceptable key movement includes:

- re-sealing a key to the destination TPM;
- re-wrapping a KEK through the destination KMS or HSM;
- delivering a systemd credential through the deployment control plane;
- an operator-mediated, authenticated recovery ceremony.

The root key must not be placed in:

- the snapshot archive;
- command-line arguments;
- repository or deployment YAML;
- logs, audit bodies, or support bundles;
- agent-visible environment variables;
- an unprotected file beside the encrypted records.

The destination authenticates the key against the store header before reading any record. Failure returns a sanitized key-rejected error and never reports key bytes, key length, ciphertext, or filesystem paths.

## 6. Migration while changing keys

The demo uses one derived encryption hierarchy for all records. Changing its root key therefore requires decrypting and re-encrypting every live secret in a trusted migration process.

The production design should instead use envelope encryption:

```text
secret plaintext
    ↓ encrypted by
record DEK
    ↓ wrapped by
store KEK
    ↓ obtained or unwrapped through
KeySource
```

With envelope encryption, changing a KMS, HSM, TPM, or KEK normally requires re-wrapping each record DEK rather than decrypting every secret value. A migration still authenticates the complete record metadata and advances the manifest generation.

Required re-key flow:

1. Lock administrative writes.
2. Authenticate the source manifest against its rollback anchor.
3. Obtain the old KEK through the old `KeySource`.
4. Obtain or create the new KEK through the destination `KeySource`.
5. Re-wrap each DEK and write a new record envelope or manifest entry.
6. Publish a new manifest generation atomically.
7. Advance the external rollback anchor.
8. Re-open and verify a sample plus complete digest/count reconciliation.
9. Revoke the old key source only after cutover succeeds.

The implementation must never overwrite the only recoverable copy of wrapped key material before the new generation is durable and verified.

## 7. Provider-to-provider migration

Migration between providers uses the provider-neutral interfaces inside a trusted administrative process:

```text
Source SecretProvider
        │ get(reference)
        ▼
trusted migration process memory
        │ put(reference, material, binding)
        ▼
Destination SecretAdmin
```

The migration process handles one record at a time:

1. Resolve an explicit authorized reference set from the signed Config Registry and migration plan. Do not add enumeration to the runtime provider interface; an optional administrative catalog may only confirm the planned set.
2. Read one exact logical reference from the source runtime interface.
3. Verify that the source attested binding is equal to or narrower than the signed Config Registry binding.
4. Compute an ephemeral comparison tag with a random migration-session key held only in process memory.
5. Write the value and binding to the destination administrative interface, consuming and dropping the source plaintext material.
6. Read the destination record back, verify version and binding, compute its ephemeral comparison tag, compare the tags in constant time, and drop the destination plaintext and per-record tags.
7. Record a receipt containing logical reference, source/destination provider IDs, non-secret versions, and status—never plaintext or a reusable digest of low-entropy secret material. Destroy the migration-session key when the migration process ends.
8. Continue with the next record.

There is no generic plaintext export file. The migration API must not return secret values to an agent, browser, terminal output, Skill, or MCP caller.

## 8. Version semantics

Provider-native version numbers are not guaranteed to have the same meaning. A Bitwarden revision timestamp, local monotonic counter, and cloud-vault version ID cannot be copied into one universal numeric field safely.

Migration therefore tracks two concepts:

- `provider_version`: the source or destination provider's native version;
- `migration_epoch`: an ACF-controlled identifier for one migration/cutover operation.

For the current interfaces, destination `put()` creates or increments the destination-native `SecretVersion`. Migration receipts record both source and destination versions. The destination must never lower an existing destination version or overwrite a newer destination record without an explicit conflict decision.

Deletion history is security-relevant. Local-provider tombstones must be included in same-provider snapshots. Cross-provider migration must either reproduce a destination tombstone or record the deletion in an authoritative migration journal so an older credential cannot silently reappear.

## 9. Conflict policy

Each destination reference is classified before writing:

| Destination state | Default action |
| --- | --- |
| Missing | Create. |
| Same verified value and binding | Mark already converged. |
| Existing older migration receipt | Replace only with explicit migration policy. |
| Existing different value or binding | Stop with conflict. |
| Existing broader binding | Stop and require configuration review. |
| Existing newer destination version | Stop; never downgrade automatically. |
| Tombstoned | Stop unless the migration explicitly authorizes resurrection. |

There is no unconditional `--force` mode. Conflict overrides must identify the exact reference, expected source/destination state, operator, and approval.

## 10. Cutover protocol

Migration and cutover are separate phases:

```text
Prepare destination
        ↓
Copy and verify records
        ↓
Freeze source mutations
        ↓
Final delta and reconciliation
        ↓
Sign new Config Registry generation
        ↓
Atomically activate destination mapping
        ↓
Observe and then revoke source access
```

The signed Config Registry is the switch. Agents continue using the same logical references and semantic actions; only the administrator-controlled namespace-to-provider mapping changes.

Before activation, reconciliation must verify:

- expected live-record and tombstone counts;
- every requested reference has one destination result;
- every destination binding is equal to or narrower than the registry binding;
- no out-of-scope destination record was created;
- destination read-back succeeds through the same runtime interface the gateway will use;
- the destination key source and storage permissions pass production validation.

After activation, the source becomes read-disabled for ordinary gateway traffic. Its credentials and machine-account access are revoked only after the defined rollback observation window.

## 11. Rollback and recovery

Rollback means switching provider mappings back to a still-valid source generation. It does not mean moving a monotonic rollback anchor backward.

If writes occurred after cutover, automatic rollback is unsafe because the providers have diverged. The operation becomes a new forward migration with explicit conflict resolution.

For local snapshots with an external anchor:

- a restored manifest with generation below the anchor fails closed;
- restore republishes selected old content as a new generation above the anchor;
- resetting or lowering the anchor requires a separately audited recovery ceremony.

The current demo lacks this protection and must state that restoring an old directory can reactivate revoked data.

## 12. Proposed administrative commands

```text
acf secrets snapshot \
  --provider local-production \
  --output-fd <protected-fd>

acf secrets restore \
  --provider local-recovery \
  --input-fd <protected-fd>

acf secrets migrate plan \
  --from bitwarden-production \
  --to local-production \
  --scope secret://production/cloudflare

acf secrets migrate execute \
  --plan <signed-plan-id>

acf secrets migrate verify \
  --migration <migration-epoch>

acf secrets migrate cutover \
  --migration <migration-epoch> \
  --approval <approval-id>
```

Commands accept protected file descriptors, authenticated service APIs, or no-echo operator input for sensitive material. Secret values and raw keys are never accepted as ordinary command-line arguments.

## 13. Audit events

Required non-secret events include:

- migration planned, approved, started, paused, resumed, failed, and completed;
- source/destination provider IDs and logical scope;
- per-reference result and non-secret version mapping;
- conflict decision and approving identity;
- snapshot generation and manifest digest;
- Config Registry generation activated at cutover;
- source access revoked;
- rollback or forward-recovery action.

Audit data must not contain plaintext, raw keys, wrapped key bytes, ciphertext fragments, or stable unkeyed hashes of secret values.

## 14. Required tests

- Offline same-key copy opens on a second path and returns the same logical records.
- Missing records or tombstones fail reconciliation.
- Copying while a write generation changes is rejected.
- Wrong key, namespace, provider ID, format, or manifest digest fails closed.
- Root-key migration decrypts/re-encrypts one record at a time and leaves no plaintext artifact.
- Envelope-key migration re-wraps DEKs without exposing secret plaintext.
- Cross-provider migration preserves or narrows every use binding.
- Conflicting and newer destination records are never overwritten automatically.
- Deleted credentials cannot be resurrected without an explicit approved decision.
- Cutover changes only the signed provider mapping; agent actions remain unchanged.
- Failure before cutover leaves the source authoritative.
- Failure after cutover produces a resumable, idempotent recovery state.
- Old snapshots fail against an external rollback anchor.
- Canary values never appear in plans, receipts, logs, errors, metrics, audit events, or snapshot metadata.
