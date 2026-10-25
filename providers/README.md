# External Secret Provider Adapters

This directory is reserved for optional external `SecretProvider` implementations.

Core gateway, policy, connector, protocol, and agent crates must not depend on a concrete provider in this directory. Each adapter depends on the provider-neutral interfaces in `acf-secrets` and must pass the shared provider conformance suite.

Provider design documents live under [`docs/providers`](../docs/providers/README.md).

Implemented external adapters live in dedicated workspace crates so vendor SDKs do not enter core dependency graphs:

- [`acf-provider-bitwarden`](../crates/acf-provider-bitwarden) — Bitwarden Secrets Manager through the official Rust SDK.
