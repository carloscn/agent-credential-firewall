# ADR 0003: Capability wire encoding and Authority keys

Status: Accepted

Date: 2026-10-25

Work package: WP-09

## Context

The Capability Authority issues certificate-bound task capabilities (design §7.2.1, §8.2). The gateway must verify them offline with the authority's public key, so the data plane can check a capability but never mint one. The claims model already exists (`acf_protocol::TaskCapabilityClaims`, WP-01). This ADR fixes:

- how claims are serialized and signed,
- how keys are identified, stored, and rotated,
- how a capability travels between the authority, the daemon, and the gateway,
- how job definitions are signed for the job-definition authorization basis.

## Decision

### Token format: JWS Compact Serialization, EdDSA (Ed25519)

A capability is a JWS (RFC 7515) in compact serialization:

```text
BASE64URL(header) "." BASE64URL(claims) "." BASE64URL(signature)
```

- **Algorithm:** `EdDSA` with Ed25519 (RFC 8037). Signatures are deterministic, so there is no per-signature nonce to get wrong. Verification is fast, and keys and signatures are small.
- **Header:** exactly three members. Any other member is rejected, including `crit`, `jku`, `jwk`, `x5u`, `x5c`, and `b64`, so a token cannot point the verifier at a key or change how the payload is processed.

  ```json
  { "alg": "EdDSA", "typ": "acf-cap+jwt", "kid": "authority-2026-10" }
  ```

- **Explicit type:** `typ` must be `acf-cap+jwt` (RFC 8725 §3.11), so no other JWT a key might sign is accepted as a capability.
- **Payload:** the JSON of `TaskCapabilityClaims` (design §7.9.4). Unknown members are rejected. The signature covers the exact transmitted bytes; claims are not canonicalized.
- **Base64url:** unpadded, and non-canonical encodings are rejected. A token is at most 8 KiB.
- **Algorithm pinning:** the algorithm belongs to the trusted key, not to the token. Each trust entry records its `alg`. A token whose header `alg` differs from its key's `alg` is rejected, so `none`, HMAC, and other algorithm-confusion attacks cannot apply. A later ADR may add `ES256` keys for HSMs that lack Ed25519; that adds a key type, not a verifier mode.

Rejected alternatives:

- **PASETO v4.public** has no standard confirmation claim or explicit typing, and adds a less common format to audit.
- **CWT/COSE** is a binary encoding with less tooling, and nothing in ACF needs its compactness.
- **Biscuit** offers attenuation that ACF does not use, because delegation goes through the authority.
- **Opaque reference plus server-side session:** the design keeps this as an alternative for deployments that never verify offline. It is not the default because every gateway request would then depend on the authority being reachable.

### Verification rules

The gateway, in order:

1. Splits the token, decodes and parses the header, and applies the header rules above.
2. Looks up `kid` in its trust store. An unknown key is rejected.
3. Verifies the signature over `header "." payload` with that key.
4. Parses the claims. `iss` must equal the issuer recorded for the key, so a key trusted for one issuer cannot sign for another.
5. Checks `iat ≤ nbf < exp` and `exp − nbf ≤ 24 h` (the gateway's maximum capability lifetime).

The authorizer (WP-03) then checks:

- `aud` against the gateway audience,
- `nbf`/`exp` against the clock, with the configured skew,
- `cnf.x5t#S256` against the certificate on the current TLS connection,
- `sub` against the principal enrolled for that certificate,
- the task id, the matching grant, and the grant's constraints.

The state layer (WP-10) checks revocation by `jti`, task, principal, and device, and charges `limits` against the `jti`.

A capability may authorize many requests within its lifetime. It is never consumed; the per-request `requestId` is the replay unit.

### Keys

| Key | Format | Held by |
| --- | --- | --- |
| Authority signing key | Ed25519 PKCS#8 PEM (v1 or v2), mode 0600 | The authority only |
| Authority public keys | `acf.authority-keys/v1` YAML (below) | Gateways |
| Job-definition signing key | Ed25519 PKCS#8 PEM | Administrators, offline |
| Job-definition public keys | In the authority configuration | The authority |

The gateway trust store holds only raw 32-byte public keys:

```yaml
schema: acf.authority-keys/v1
keys:
  - kid: authority-2026-10
    issuer: acf-authority-prod
    alg: EdDSA
    public_key: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo   # base64url, 32 bytes
```

- The format has no field for private key material.
- The gateway has no signing code path. Only `acf-control-plane` signs, and `deny.toml` keeps the gateway from linking it. So the gateway can verify capabilities but cannot mint them.
- **Rotation:** gateways read their trust store at startup.
  1. Add the new public key to every gateway's trust store, and restart them.
  2. Switch the authority to the new `kid`.
  3. Once the longest capability issued under the old key has expired, remove the old key.
- **Key ID:** `kid` is an administrator-chosen opaque identifier. A date-based name such as `authority-2026-10` is recommended.
- **Hardware keys:** non-exportable authority keys (KMS or HSM) are later work behind the same signer interface.

### Transport

- **Daemon → authority:** `POST /v1/tasks` over mTLS. The authority returns the token in the JSON response body. The device identity comes from the TLS layer (ADR 0002).
- **Daemon → gateway:** each `POST /v1/actions/execute` carries the token in the `ACF-Capability` request header. It is not part of the `ActionRequest` body model, so the body stays the semantic request.
- **Daemon → agent:** never. The daemon keeps the token in memory, keyed by the opaque task handle. The agent can see the effective grants, limits, and expiry, but not the token.

When a gateway is configured with authority keys, every request must carry a valid capability. Without authority keys, only the development profile accepts requests without one (unscoped development tasks, WP-03). A capability presented to a gateway that has no trust store is rejected rather than ignored.

### Signed job definitions

A job definition (`acf.job/v1` YAML) is an administrator-approved scope for an unattended workload. It is signed with a detached Ed25519 signature over the exact file bytes, stored next to it as `<file>.sig`:

```json
{ "kid": "admin-2026", "signature": "<base64url Ed25519 signature>" }
```

- The authority loads job definitions at startup and refuses any definition that is unsigned, signed by an unknown key, or has a bad signature.
- The capability's authorization basis records `definitionDigest`, the SHA-256 of the signed bytes, so an audit can tie every capability to the exact definition that authorized it.

## Consequences

- One new direct dependency: `base64`, which is already compiled in through `hyper-util`. Ed25519 comes from `ring`, which is already a dependency.
- Capabilities are readable with standard JWT tooling for debugging, but ACF accepts only the narrow profile above.
- Human confirmation (WebAuthn) is not an authorization basis in WP-09. It arrives with the Approval Service.
