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

Every runtime provider implements exact-reference retrieval through protected types:

```rust
#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn get(&self, reference: &SecretRef)
        -> Result<ResolvedSecret, SecretError>;
}

pub struct ResolvedSecret {
    pub material: SecretMaterial,
    pub version: SecretVersion,
    /// Present only when the provider stores authenticated use-binding metadata.
    pub attested_binding: Option<SecretUseBinding>,
}
```

Metadata enumeration and administrative mutation are intentionally separate from the runtime retrieval contract. They use the distinct `SecretAdmin` trait and a root-controlled administrative API. Agents and connectors must not receive generic secret list, create, update, export, or decrypt capabilities.

Every secret has a use binding. The binding constrains the connector, destination origin, authentication slot, and environment allowed to receive the value. Enforcement works as follows:

- **Source of truth.** The secret registration in the signed Config Registry is authoritative. The gateway checks it before calling `get()`.
- **Attestation.** A provider that can store authenticated metadata, such as the encrypted local provider, returns an `attested_binding`. That binding must equal the registry binding or be narrower.
- **No attestation.** A provider that cannot attest returns `None` and relies on the registry binding alone.
- **Injection.** The connector checks the final origin and credential slot again before injection.

## Conformance requirements

Every provider adapter must pass a shared suite covering:

- Namespace isolation.
- Exact-reference resolution.
- Protected return types.
- Error and log redaction.
- Cancellation and timeout handling.
- Missing, unavailable, locked, and corrupted states.
- Exact-reference lookup without runtime namespace enumeration.
- Correct `attested_binding` behavior: authenticated when present, `None` when the provider cannot attest.
- No secret material in protocol responses or audit events.
- Predictable behavior during provider rotation and shutdown.

`SecretAdmin` implementations have a separate administrative conformance suite.

Provider-specific authentication credentials and storage keys are bootstrap secrets. They must remain outside agent hosts and outside provider configuration files wherever possible.

## Implementations

- [Encrypted local provider](encrypted-local.md)
- [Local provider data migration](local-migration.md)
- [Bitwarden provider](bitwarden.md)
