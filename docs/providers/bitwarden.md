# Bitwarden Secret Provider

Status: Implemented optional provider; license approval required before merge/distribution

Last updated: 2026-10-25

## 1. Role and isolation boundary

Bitwarden Secrets Manager is an optional external `SecretProvider`. Its implementation lives in the leaf crate `acf-provider-bitwarden`; it is not a dependency of `acf-secrets`, protocol, policy, connectors, state, audit, the agent daemon, or the control plane.

```text
Gateway composition root
        │ dyn SecretProvider
        ▼
acf-secrets                       stable, vendor-neutral contract
        ▲
        │ implements
acf-provider-bitwarden            vendor adapter
        │ narrow BitwardenBackend boundary
        ▼
official bitwarden Rust crate     vendor SDK
```

The stable runtime contract remains:

```rust
#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn get(&self, reference: &SecretRef)
        -> Result<ResolvedSecret, SecretError>;
}
```

Replacing Bitwarden with the encrypted local provider or another external vault does not change agent actions, task capabilities, policy, connectors, approval, or audit schemas.

Inside the adapter, `BitwardenBackend` is a narrower anti-corruption boundary around the SDK. It accepts only an administrator-selected UUID locator and returns protected `BitwardenRecord` material or a sanitized error. SDK request/response/error types never cross into ACF core crates.

## 2. Logical mapping

ACF uses provider-neutral logical references:

```text
secret://enterprise/cloudflare/example.com/dns-read
```

The adapter requires an explicit, exact mapping to a Bitwarden secret UUID:

```yaml
secret_providers:
  enterprise:
    type: bitwarden
    settings:
      api_url: https://api.bitwarden.com
      identity_url: https://identity.bitwarden.com
      organization_id: 00000000-0000-0000-0000-000000000001
      credential_source: systemd-credential

    mappings:
      cloudflare/example.com/dns-read:
        secret_id: 00000000-0000-0000-0000-000000000101
        expected_project_id: 00000000-0000-0000-0000-000000000201
      cloudflare/example.com/dns-write:
        secret_id: 00000000-0000-0000-0000-000000000102
        expected_project_id: 00000000-0000-0000-0000-000000000201
```

Runtime lookup never lists secrets and never resolves by Bitwarden key name. Names may be duplicated and listing would broaden the provider API. The adapter checks the ACF namespace before lookup, resolves one exact UUID, and optionally verifies the returned project ID.

Agents and connector profiles never receive the Bitwarden UUID, organization ID, project ID, or machine-account access token.

## 3. SDK session construction

The adapter uses `bitwarden-sm`, Bitwarden's Secrets Manager Rust component. Version 4.0.0 package metadata points to Bitwarden's current `sdk-internal` repository; the older public `sdk-sm` repository remains the design/API starting point named by this project. The component is pinned independently so ACF does not need the top-level SDK's unrelated generator surface. The supported construction path is:

```rust
let settings = BitwardenSettings::new(api_url, identity_url, organization_id)?;
let backend = SdkBitwardenBackend::connect(&settings, machine_account_token).await?;
let provider = BitwardenProvider::new(namespace, mappings, backend)?;
```

Security behavior:

- API and identity endpoints must use HTTPS and cannot contain user info, query strings, or fragments.
- Self-hosted endpoint paths such as `/api` and `/identity` are allowed.
- The machine-account token enters through `SecretMaterial`, not ordinary configuration.
- The temporary SDK login request is explicitly zeroized after authentication.
- No SDK state file is created; the authenticated session remains in memory.
- SDK error strings and response bodies are collapsed into sanitized provider errors.
- The organization ID and optional project ID are checked on every fetched response.
- Login and retrieval fail closed if the SDK's credential-bearing `DEBUG` or request-body `TRACE` callsites are enabled.

`bitwarden-core 4.0.0` logs the machine-account `client_secret` while constructing its access-token request at `DEBUG`, and its HTTP middleware can log request bodies at `TRACE`. ACF checks the exact tracing callsite targets before login and before every retrieval. Production composition must also keep the `bitwarden_core` target below `DEBUG` and must not reload a broader filter while a request is executing. An SDK upgrade must re-audit these callsites; deleting this guard merely because upstream code moved is not acceptable.

The SDK necessarily holds authenticated session state in gateway memory. Root compromise of the gateway remains outside the provider's protection boundary.

## 4. Runtime retrieval

For `get(secret_ref)`:

1. Reject a namespace not assigned to this provider as `NotAssigned`.
2. Require an exact configured logical-reference mapping; do not call Bitwarden for an unmapped reference.
3. Call `SecretsClient::get` with the configured secret UUID.
4. Verify the response organization and optional project.
5. Derive ACF's `SecretVersion` from the Bitwarden revision timestamp.
6. Clear unused decrypted key/note strings.
7. Move the decrypted value immediately into zeroizing `SecretMaterial`.
8. Return `ResolvedSecret { attested_binding: None, ... }`.

The official SDK currently represents the decrypted `SecretResponse::value`, key, and note as ordinary `String` values and derives `Debug` for the response. Adapter code must never log or format that response. ACF moves the value into its protected type as soon as possible and zeroizes the unused key and note, but copies inside the SDK and HTTP stack remain unavoidable plaintext boundaries.

## 5. Use-binding enforcement

Bitwarden does not store or authenticate ACF's connector/origin use binding. Therefore this provider always returns:

```rust
attested_binding: None
```

The signed Config Registry is authoritative for:

- allowed connector;
- destination origin;
- authentication slot;
- environment.

The gateway validates the registry binding before retrieval, and the connector validates the final origin and slot before injection. Migrating a logical reference between Bitwarden and another provider does not change those rules.

## 6. Error and timeout behavior

The vendor boundary exposes only these sanitized categories:

- `NotFound`;
- `AuthenticationFailed`;
- `Unavailable`;
- `UnsafeLoggingConfiguration`, mapped to provider unavailable so requests fail closed;
- `Timeout`;
- `Corrupted`, including tenant/project mismatch.

Current SDK fetch failures are conservatively mapped to `Unavailable` because the public SDK error type can contain provider response bodies and is not allowed to cross or be formatted. Missing ACF mappings are still precise `NotFound` results. The gateway's outer provider deadline supplies deterministic timeout enforcement.

## 7. Administration and rotation

The Bitwarden adapter intentionally does not implement ACF `SecretAdmin`.

Secret creation, updates, deletion, project assignment, machine-account management, and access-token issuance use Bitwarden's administrative tooling or UI. They are not reachable from the agent action API or MCP tools.

Downstream credential rotation should:

1. Create or obtain the replacement downstream credential.
2. Update the mapped Bitwarden secret through an authorized administrative path.
3. Validate ACF retrieval and downstream use.
4. Revoke the old downstream credential.

Machine-account access-token rotation is a separate gateway bootstrap procedure. Tokens must not be passed through command-line arguments, repository configuration, logs, or agent-visible environment variables.

## 8. Testing

The crate's default tests use a fake `BitwardenBackend`, never live credentials. They cover:

- the shared runtime-provider conformance suite;
- exact mapping and namespace isolation;
- `attested_binding: None`;
- duplicate and cross-namespace mapping rejection;
- safe endpoint validation;
- absence of backend calls for unmapped references.

Live integration tests, when added, must be opt-in and use a dedicated non-production organization, machine account, project, and canary secrets.

## 9. SDK lifecycle and license

The adapter pins `bitwarden-sm = 4.0.0` rather than accepting floating SDK releases. The top-level `bitwarden 2.1.0` release still pulls a `bitwarden-state 3.x` SQLite dependency that cannot coexist with ACF's current security-state store, while the current `bitwarden-sm 4.0.0` component uses the compatible SDK generation. Upgrades require API review, dependency review, conformance tests, and a check that decrypted response handling has not changed.

The `bitwarden-sm 4.0.0` package is source-available under the Bitwarden SDK License Agreement rather than a standard permissive open-source license. Its published metadata names `LICENSE_SDK.txt`, while transitive Bitwarden crates declare `GPL-3.0-only OR LicenseRef-Bitwarden-SDK`. Anyone distributing or offering an ACF build containing this adapter must review and accept the applicable terms. ACF's current `cargo-deny` allowlist is permissive-only, so this dependency must not be allowlisted or merged merely to make CI green: the maintainer must first choose an approved distribution model or obtain suitable terms. Keeping the code in an isolated leaf crate prevents the vendor dependency and its licensing constraints from becoming part of ACF's provider-neutral interfaces.

## 10. References

- [Bitwarden Secrets Manager SDK repository](https://github.com/bitwarden/sdk-sm)
- [Current Bitwarden Rust SDK source repository](https://github.com/bitwarden/sdk-internal)
- [Bitwarden Secrets Manager Rust component](https://docs.rs/bitwarden-sm/4.0.0/bitwarden_sm/)
- [Bitwarden Machine Accounts](https://bitwarden.com/help/machine-accounts/)
- [Bitwarden Access Tokens](https://bitwarden.com/help/access-tokens/)
