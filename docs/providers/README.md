# Secret Providers

Secret providers are replaceable implementations behind ACF's vendor-neutral `SecretProvider` contract.

The gateway and connectors use logical references:

```text
secret://production/cloudflare/example.com/dns-read
```

They do not depend on a vendor-specific identifier or SDK. A provider registry maps the first path component, `production` in this example, to a configured provider implementation.

## Provider categories

| Provider | Purpose | Core dependency |
| --- | --- | --- |
| In-memory | Tests and deterministic local development | Built in |
| Encrypted local | Self-hosted storage on gateway-controlled infrastructure | Built in |
| Bitwarden | Existing Bitwarden Secrets Manager deployments | Optional adapter |
| Other external vaults | Existing enterprise or cloud secret stores | Optional adapters |

Provider selection does not change agent actions, task capabilities, policies, connector profiles, or audit schemas.

## Required contract

Every provider must implement retrieval and metadata operations through protected types:

```rust
#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn get(&self, reference: &SecretRef)
        -> Result<SecretMaterial, SecretError>;

    async fn list_metadata(&self, scope: &SecretScope)
        -> Result<Vec<SecretMetadata>, SecretError>;
}
```

Administrative mutation is intentionally separate from the runtime retrieval contract. Agents and connectors must not receive generic secret create, update, export, or decrypt capabilities.

## Conformance requirements

Every provider adapter must pass a shared suite covering:

- Namespace isolation.
- Exact-reference resolution.
- Protected return types.
- Error and log redaction.
- Cancellation and timeout handling.
- Missing, unavailable, locked, and corrupted states.
- Metadata that never contains plaintext secret values.
- No secret material in protocol responses or audit events.
- Predictable behavior during provider rotation and shutdown.

Provider-specific authentication credentials and storage keys are bootstrap secrets. They must remain outside agent hosts and outside provider configuration files wherever possible.

## Implementations

- [Encrypted local provider](encrypted-local.md)
- [Bitwarden provider](bitwarden.md)
