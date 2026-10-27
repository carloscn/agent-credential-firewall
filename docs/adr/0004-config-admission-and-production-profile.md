# ADR 0004: Configuration admission and the production profile

Status: Accepted

Date: 2026-10-27

Work package: WP-11

## Context

Design §7.2.3 says the gateway loads only signed or pinned configuration. Profile authoring and secret-binding administration are separate permissions, and agent-drafted profiles stay inert until an administrator admits them. Design §13.4 lists what `production` startup must refuse. Until now the gateway has loaded one unsigned YAML bundle and run only in development builds. This ADR fixes:

- how configuration is split by permission,
- how it is admitted (signature or pin),
- what production startup checks,
- how the build flavor, profile, and configuration digest are reported.

## Decision

### Three documents, three roles

| Role | Document | Contains |
| --- | --- | --- |
| `profile-author` | Each `acf.profile/v1` file in `--profiles DIR` | One connector profile: base URL, actions, response fields |
| `secret-admin` | The `acf.config/v1` bundle (`--config`) | Deployment, secret providers, resources (which secret serves which slot), secret registrations with use bindings |
| `policy-admin` | The `acf.policy/v1` document (`--policy`) | Gateway policy |

- A profile author can change what a connector does but not where a secret may be used. Use bindings pin each secret to connectors, origins, and a credential slot, and they live in the secret administrator's document. If a profile's base URL moves to another origin, the bundle no longer validates.
- Under `production`, the bundle may not contain inline `profiles`; every profile comes from its own admitted file. Under `development`, inline profiles still work, so the M0 examples keep running.
- One key may hold several roles. The roles keep the permissions distinct; whether one person holds both is an organizational choice.

### Admission: signature or pin

A document is admitted for a role if either of these holds:

1. **Signed.** `<file>.sig` holds `{"kid": "...", "signature": "<base64url>"}`, an Ed25519 signature over:

   ```text
   "acf.config-signature/v1" 0x00 <role> 0x00 <exact file bytes>
   ```

   The key must be listed in the trust anchor with that role. Because the role is in the signed message, a signature made for one role cannot be replayed for another, and a job-definition signature (ADR 0003) cannot be passed off as a configuration signature.
2. **Pinned.** The SHA-256 of the file bytes is listed in the trust anchor for that role.

The trust anchor is a separate `acf.config-trust/v1` file passed with `--config-trust`:

```yaml
schema: acf.config-trust/v1
signers:
  - kid: profiles-2026
    public_key: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo   # base64url, 32 bytes
    roles: [profile-author]
  - kid: secrets-2026
    public_key: ...
    roles: [secret-admin, policy-admin]
pins:
  - role: policy-admin
    sha256: "sha256:..."
```

- The trust anchor is the root of configuration trust. Under `production` the gateway refuses to start if it is missing, if it is writable by group or others, or if any document fails admission.
- An unsigned file in the profiles directory stops production startup; it is not skipped. Drafts therefore live elsewhere, for example `drafts/`, and do nothing until a profile author admits them.
- Admission tooling: `acf-control-plane admit --role R --key K --kid ID FILE` checks that `FILE` is a well-formed document for `R`, prints its digest, and writes `FILE.sig`. Signing keys stay with administrators, never on the gateway.
- Under `development`, signatures are checked when a trust anchor is given and otherwise not required.

### Configuration digest

The gateway computes one digest for the configuration it runs:

```text
sha256( "acf.config-digest/v1\n" + for each admitted document, sorted: "<role> <sha256:file digest>\n" )
```

File names and order on disk do not affect it. Every audit event records it (`gateway.config_digest`), as does the startup line, so an audit trail ties each decision to the exact admitted configuration.

### Production startup validation

Under `production` the gateway refuses to start, listing every problem at once, if any of these holds:

| Check | Rule |
| --- | --- |
| Build flavor | The binary was built with the `development` feature |
| Configuration | No trust anchor; trust anchor writable by group or others; any document not admitted; inline profiles in the bundle |
| Identity | No mTLS (`--tls-cert`, `--client-ca`, `--devices`); development identity is unavailable outside development builds anyway |
| Listener | Plaintext. TLS 1.3 with client certificates is the only production listener. |
| Capabilities | No `--authority-keys`; every request must carry a certificate-bound capability (ADR 0003) |
| Audit | No explicit `--audit-log` sink; standard error does not count. Audit is always required: a decision that cannot be recorded fails the request. |
| Secret providers | `in-memory`; `encrypted-local` with `key_source: insecure-development`; `encrypted-local` with neither `rollback_anchor` nor `rollback_resistance: none` |
| Destinations | A profile base URL or use-binding origin that is `http://`, `localhost`, `*.localhost`, a loopback, private, link-local, or unspecified IP literal, or under a reserved test name (`.test`, `.example`, `.invalid`, `.local`, `example.com`, `example.net`, `example.org`) |

The outbound network policy under `production` is `NetworkPolicy::production()`: public destinations over HTTPS only, with every resolved address checked.

### Build flavor reporting

- `development` builds include the in-memory provider, the fixed development identity, and the plaintext loopback listener. They refuse `production`.
- `release` builds (no `development` feature) contain none of those. They run either profile, with mTLS only.
- The flavor and profile appear in the startup line and in every audit event (`gateway.build`, `gateway.deployment_profile`).

## Non-goals

- **Signing the remaining files.** The Capability Authority's configuration, the device registry, and the authority key set are protected by file ownership and permissions only. Signing them belongs with the Config Registry service.
- **Configuration database or registry service.** In Milestone 1 the registry is signed files on disk.
- **The encrypted local provider runtime.** That is WP-07, in PR #12. Until it merges, a production gateway passes validation and then stops when it builds its secret providers, with an explicit message.
- **Profiles for the authority and the daemon.** Here the profile governs the gateway only.

## Consequences

- Production deployments need three keys or pins and a root-owned trust file. Development is unchanged.
- `ring` becomes a direct dependency of `acf-config`, for Ed25519 verification and SHA-256. It is already in the dependency tree.
