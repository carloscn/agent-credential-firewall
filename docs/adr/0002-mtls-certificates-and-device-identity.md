# ADR 0002: mTLS certificates, keys, and device identity

Status: Accepted

Date: 2026-10-25

Work package: WP-08

## Context

WP-08 puts mutual TLS between each agent host's daemon and the gateway, and derives the caller's identity from the verified client certificate (design §7.3, §7.5). The capability `cnf.x5t#S256` claim from WP-01 must later match that same certificate. Several format choices follow.

## Decision

### Keys

**ECDSA P-256** for every certificate: the gateway's server certificate, daemon client certificates, and the issuing CA.

- TPM 2.0, Apple Secure Enclave, Windows CNG, and PKCS#11 tokens all support P-256. The design's non-exportable device keys will need one of those, and the Secure Enclave supports P-256 only, which rules out Ed25519.
- rustls and aws-lc-rs support it, and it is FIPS-approved.

### Files

- Certificates are X.509 v3 in PEM. A chain file holds the leaf first.
- Private keys are PKCS#8 PEM.
- The daemon refuses to start if its private key file is readable by group or others (`mode & 0o077 != 0`). In the documented production topology, the key file belongs to the daemon's service account, so the agent's account cannot read it. Hardware-backed non-exportable keys (TPM, Keychain, PKCS#11) are later work behind the same file-free interface.

### Certificate profile

| Certificate | Extended key usage | Names | Suggested lifetime |
| --- | --- | --- | --- |
| Gateway server | `serverAuth` | DNS or IP SAN of the gateway | ≤ 90 days |
| Daemon client | `clientAuth` | Not used for identity | ≤ 30 days |

Name constraints and policy OIDs are not required. Identity does not come from certificate names (next section).

### Identity mapping: CA validation plus an enrollment registry

A client certificate authenticates only if both hold:

1. It chains to a configured client CA, is within its validity period, and carries `clientAuth` (rustls `WebPkiClientVerifier`).
2. Its SHA-256 thumbprint (`x5t#S256`, unpadded base64url of the DER) is enrolled in the device registry.

```yaml
schema: acf.devices/v1
devices:
  - device: laptop-0142
    principal: user:alice@example.com
    labels: [laptop, developer]
    certificates:
      - 47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU
```

- The registry maps a thumbprint to a principal, device, and labels. Nothing in a certificate's subject or SANs grants identity, so a CA misissuance alone cannot impersonate an enrolled device.
- The thumbprint is the value a capability's `cnf.x5t#S256` will carry (WP-09), so certificate binding needs no second format.
- **Rotation:** enroll the new thumbprint next to the old one, roll the daemon to the new certificate, then remove the old thumbprint. The gateway re-reads the registry when its file changes; a removal takes effect within the documented poll interval (5 seconds).
- Rejected alternative: deriving identity from a SAN URI such as `urn:acf:principal:…`. It would let any certificate the CA issues assert any identity, and it needs an X.509 parser in the gateway.

### TLS

- TLS 1.3 only, on both the gateway and the daemon.
- Client authentication is mandatory; anonymous clients fail the handshake.
- 0-RTT is disabled (`max_early_data_size = 0`), and session tickets are not issued, so every connection performs a full handshake that presents the client certificate.
- ALPN offers `http/1.1` only.
- The crypto provider is aws-lc-rs, the one the rest of the TLS stack already uses.
- The daemon trusts only the configured gateway CA, not the system roots, and never uses a proxy.

### TLS termination

The gateway terminates TLS itself. It does not accept identity from forwarded headers such as `X-Forwarded-Client-Cert`. A deployment that must terminate TLS in front of the gateway needs an authenticated proxy hop that preserves the verified certificate. That is not supported in M1, and the gateway has no code path that reads such a header.

### Server certificate rotation

In M1 the gateway's server certificate, key, and client CA bundle are read at startup; rotating them requires a restart. Client certificate rotation needs no restart (registry reload).

## Daemon local API

- The daemon listens on a Unix socket created with mode `0660` (configurable). It reads each caller's UID, GID, and PID from the kernel (`SO_PEERCRED`).
- Agents create a task with `POST /v1/tasks` and receive an opaque, random task handle. The handle is bound to the caller's UID and, when a launcher registers one, to a PID. Every other daemon call must present a handle owned by the calling UID and PID. Unknown and foreign handles look identical (`404`).
- The daemon fills in the request identifier and timestamp itself and forwards the semantic request to the gateway over mTLS. Agents never see the client key or, once WP-09 lands, the capability.
- Peer credentials prove operating-system provenance, not intent: any process running as the permitted UID can use that UID's handles. Task scope, policy, constraints, and approvals limit what such a process can do.

## Consequences

- Enrolling a device is an explicit administrative step (add its thumbprint to the registry).
- No X.509 parsing beyond what rustls and webpki already do.
- Dev certificates come from an `rcgen`-based example (`cargo run -p acf-gateway --example dev-pki`). It is not part of any release binary.
