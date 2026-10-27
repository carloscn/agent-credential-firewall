# ADR 0005: Audit hash chain and external checkpoints

Status: Accepted

Date: 2026-10-27

Work package: WP-12

## Context

Design §15 requires tamper evidence with an external anchor. Either a local hash chain is signed into periodic checkpoints published to an external append-only sink, or events go directly to a remote append-only sink. A local chain alone is never sufficient: an attacker who controls the gateway host can truncate the log or rewrite it, chain included.

WP-12 asks for three things:

- hash-linked events,
- signed checkpoints to an external append-only sink,
- an explicit policy for audit-sink failure.

The gateway already writes one JSON object per line and refuses an allowed request whose decision event cannot be written (WP-06).

## Decision

We use the first option: a local hash chain plus signed checkpoints. The Capability Authority's host (the control plane) is the external sink.

### Hash chain

Every event carries a `chain` member:

```json
"chain": { "log": "log-5f0c…", "seq": 41, "prev": "sha256:…" }
```

- **`log`** identifies one chain: `log-` plus 128 random bits in hex, chosen when the gateway starts a new audit file.
- **`seq`** starts at 0 and increases by one per event, with no gaps.
- **`prev`** is the hash of the previous event. For `seq` 0 it is a genesis value derived from the log identifier, `SHA-256("acf.audit-chain/v1" 0x00 <log>)`, so a chain cannot be spliced onto another log's start.
- **Event hash:** the SHA-256 of the event's exact line bytes, without the trailing newline. The gateway hashes what it writes, so no canonicalization step can disagree with the file. Changing any byte of any event, including its `chain`, breaks every later link.
- **Restart:** the gateway reads the last line of an existing audit file and continues that log (`seq + 1`, `prev` = its hash). It refuses to start if the file ends in a partial line or its last line is not a chained event; the operator then verifies and rotates the file. A new or empty file starts a new log. Full-file verification is the verification tool's job, not startup's.

### Checkpoints

A checkpoint is a statement about the head of one log:

```json
{ "schema": "acf.audit-checkpoint/v1", "log": "log-5f0c…", "seq": 41,
  "head": "sha256:…", "gateway": "gw-1", "issuedAt": "2026-10-27T14:00:00Z" }
```

It travels as an envelope:

```json
{ "kid": "gw-1-audit-2026", "payload": "<base64url statement>", "signature": "<base64url>" }
```

- The signature is Ed25519 over `"acf.audit-checkpoint/v1" 0x00 <payload bytes>`. Signing the encoded payload means the verifier checks exactly the bytes that were signed, and the domain tag keeps checkpoint signatures distinct from configuration (ADR 0004) and capability (ADR 0003) signatures.
- **Signing key:** the gateway's own audit key (`--audit-key`, Ed25519 PKCS#8, mode 0600, `--audit-kid`). It is separate from the TLS key and from every authority key.
- **Cadence:** the gateway signs and publishes one checkpoint at startup and then every `--checkpoint-interval` (default 30 s) whenever the head has moved.
- **Transport:** HTTPS `POST` over mTLS to `--checkpoint-url`. The gateway presents its own enrolled client certificate.

### The collector

The control plane serves `POST /v1/audit/checkpoints` on its mTLS listener when started with `--audit-keys` (an `acf.audit-keys/v1` set of `{kid, gateway, principal, public_key}`) and `--checkpoint-store DIR`. It accepts a checkpoint only if all of the following hold:

1. The signature verifies with the key named by `kid`.
2. The statement's `gateway` matches that key's gateway.
3. The mTLS caller is that key's principal.

If so, it appends the envelope to `DIR/<log>.jsonl`. It never rewrites a file.

| Incoming `seq` versus the last stored checkpoint for that log | Result |
| --- | --- |
| Greater | Appended (`201`) |
| Equal, same head | Idempotent (`200`) |
| Equal with a different head, or lower | Refused (`409 checkpoint_conflict`) and logged |

A conflict means the gateway is presenting a different history than it already committed to: a rewrite, or two gateways sharing a log.

The store belongs on storage that the gateway's host cannot reach, ideally replicated or write-once. The collector's guarantee is only as strong as that separation.

### Verification

`acf-control-plane verify-audit --log FILE --checkpoints DIR --audit-keys KEYS` checks:

- every link (`log`, `seq`, `prev`) from the first line to the last,
- every stored checkpoint's signature,
- for each checkpoint, that the log contains that `seq` with exactly that hash.

It reports:

- the head,
- the newest checkpoint,
- how many events follow it and are therefore protected only by the local chain.

It exits non-zero on a broken link, truncation (the log ends before a checkpointed `seq`), replacement (a different hash at a checkpointed `seq`), or a bad signature.

**What is protected:** truncation or replacement of any event at or before the newest accepted checkpoint is detectable from the log and the collector's store alone. Events after it are protected only by the local chain, which a host attacker can rewrite. The checkpoint interval and the maximum lag (below) bound that window. A stolen audit key lets an attacker sign checkpoints for a future history, but not replace history the collector has already accepted.

### Failure policy

| Failure | Behavior |
| --- | --- |
| The local audit file cannot be written | The request fails before the secret is retrieved (`audit_unavailable`); a denial is still returned. Unchanged from WP-06. |
| A checkpoint cannot be published | The gateway logs the failure and retries at the next interval. |
| No checkpoint accepted for `--checkpoint-max-lag` (default 300 s) while events keep arriving | The sink refuses new events. Allowed requests fail with `audit_unavailable` until a checkpoint is accepted. The unanchored window is therefore bounded, at the cost of availability. |
| The collector answers `409 checkpoint_conflict` | Treated as a failed publication and logged as a possible rollback |

- Under `production`, checkpointing is mandatory. The gateway refuses to start without `--audit-key`, `--audit-kid`, `--checkpoint-url`, and a checkpoint client certificate.
- Under `development`, the chain is always written and checkpointing is optional.

## Non-goals

- **Direct writes to a remote append-only sink** such as a SIEM or WORM bucket. The checkpoint envelope can be forwarded to such a sink later.
- **Rotation and archival of audit files.** Rotation is a new file and therefore a new log; the old log stays verifiable against its checkpoints.
- **Hardware-backed audit keys.**

## Consequences

- Each event line grows by about 130 bytes.
- The gateway needs its own client certificate, enrolled with the control plane, and an Ed25519 audit key. `dev-pki` issues the certificate.
- `base64` and `ring`, both already dependencies, cover the encoding and cryptography. `reqwest` becomes a direct dependency of the gateway for publishing.
