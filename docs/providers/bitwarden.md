# Bitwarden Secret Provider

Status: Optional provider design

Last updated: 2026-10-24

## 1. Role

Bitwarden Secrets Manager is an optional external `SecretProvider` implementation. It is not a core ACF dependency and does not change agent, policy, connector, approval, or audit contracts.

Use this adapter when an organization already operates Bitwarden Secrets Manager or prefers a managed/self-hosted vault over the built-in encrypted local provider.

## 2. Mapping

ACF continues to use logical references:

```text
secret://enterprise/cloudflare/example.com/dns-read
```

Provider configuration maps these references to Bitwarden secret identifiers:

```yaml
secret_providers:
  enterprise:
    type: external
    adapter: bitwarden
    config:
      api_server: https://api.bitwarden.com
      identity_server: https://identity.bitwarden.com
      organization_id: organization-id
      credential_source: systemd-credential

    mappings:
      cloudflare/example.com/dns-read: secret-id-read
      cloudflare/example.com/dns-write: secret-id-write
```

Agents and connector profiles never receive the Bitwarden secret ID or machine-account access token unless a non-sensitive identifier is explicitly required for administration.

## 3. Runtime flow

1. The gateway resolves the logical provider namespace.
2. The adapter maps the logical path to a configured Bitwarden secret ID.
3. The adapter authenticates with a narrowly scoped machine account.
4. The Bitwarden SDK retrieves and decrypts the secret locally.
5. The adapter converts it immediately into a `ResolvedSecret` with `attested_binding: None`.
6. The gateway enforces the use binding from the signed Config Registry, and the connector uses the material without exposing it to the agent.
7. ACF records only the logical reference and provider outcome.

The core adapter should use the native Rust SDK when its supported API is compatible with the required retrieval operations. SDK-specific values and errors must remain inside the adapter boundary.

Bitwarden does not store ACF use bindings as authenticated metadata. This adapter therefore never attests a binding, and the registry binding is the only binding check before injection. The runtime adapter implements only `SecretProvider::get()`. Enumeration and mutation happen through Bitwarden's own administrative tooling, not through ACF's `SecretAdmin` trait.

This adapter is planned for M3.

## 4. Security boundaries

- Use separate machine accounts or access tokens for development and production.
- Scope machine accounts to the minimum projects and secrets.
- Keep the access token outside agent hosts.
- Do not commit access tokens to source control or container images.
- Do not pass access tokens in command-line arguments.
- Treat the gateway's authenticated Bitwarden session as an additional revocation boundary.
- Redact SDK errors and tracing fields before they cross the adapter boundary.

Bitwarden documents that revoking an access token prevents new authentication, but an already authenticated machine may continue retrieving and decrypting secrets until its session expires, for up to approximately one hour. Gateway shutdown, ACF session revocation, and network isolation therefore remain separate incident-response controls. See [Bitwarden Access Tokens](https://bitwarden.com/help/access-tokens/).

## 5. Provider conformance

The adapter must pass the same provider conformance suite as the encrypted local provider:

- Exact logical-reference mapping.
- Namespace isolation.
- Protected `ResolvedSecret` return type with `attested_binding: None`.
- Cancellation and timeout handling.
- Redacted authentication and retrieval errors.
- Missing, revoked, expired, and unavailable states.
- No plaintext in logs, audit events, or protocol responses.

Provider-specific integration tests are opt-in and use a dedicated non-production organization/project and canary secrets.

## 6. Administration and rotation

Secret creation, project assignment, machine-account management, and access-token issuance are administrative workflows outside the agent action API.

Downstream credential rotation should:

1. Create or obtain the new downstream credential.
2. Update the mapped Bitwarden secret through an authorized administrative path.
3. Validate ACF retrieval and downstream use.
4. Revoke the old downstream credential.

Machine-account token rotation follows a separate bootstrap-credential procedure and must not require exposing the token to an agent.

## 7. References

- [Bitwarden Secrets Manager SDK](https://bitwarden.com/help/secrets-manager-sdk/)
- [Bitwarden Machine Accounts](https://bitwarden.com/help/machine-accounts/)
- [Bitwarden Access Tokens](https://bitwarden.com/help/access-tokens/)
