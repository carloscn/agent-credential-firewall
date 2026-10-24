# agent-credential-firewall

Identity-aware, task-scoped credential gateway for AI agents.

## Documentation

- [System design](docs/design.md)
- [Implementation plan](docs/implementation-plan.md)
- [Secret provider model](docs/providers/README.md)
- [Encrypted local provider](docs/providers/encrypted-local.md)
- [Bitwarden provider](docs/providers/bitwarden.md)
- [Tailscale deployment use case](docs/use-cases/tailscale.md)

## Status

Implementation has started with WP-00 (workspace and CI). Every crate is a skeleton with no behavior yet. The binaries exit with a failure status.

## Development

The toolchain is pinned in `rust-toolchain.toml`. `rustup` installs it on first use.

These are the commands CI runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
cargo audit
```

`cargo deny` and `cargo audit` come from separate tools. Install them with:

```bash
cargo install --locked cargo-deny cargo-audit
```

## Crates and ownership

Every crate in this workspace handles secrets, identity, authorization, or audit integrity, so every crate is security-sensitive. Changes need a reviewer other than the author. The PR description must also list the security invariants the change affects (see the [PR contract](docs/implementation-plan.md#9-pull-request-contract)).

| Crate | Responsibility | Work packages |
| --- | --- | --- |
| `acf-protocol` | API, task, approval, and operation models | WP-01 |
| `acf-secrets` | Provider traits, protected secret types, in-memory provider | WP-01 |
| `acf-config` | Schemas, validation, pinning | WP-02, WP-11 |
| `acf-identity` | Connection and peer identity | WP-03, WP-08 |
| `acf-policy` | Authorization and constraint composition | WP-03 |
| `acf-connectors` | Semantic connectors and domain types | WP-04, WP-15 |
| `acf-gateway` | Data-plane request lifecycle | WP-05 |
| `acf-audit` | Redacted, tamper-evident audit events | WP-06, WP-12 |
| `acf-provider-local` | Encrypted local provider | WP-07 |
| `acf-agent` | Endpoint/VPS daemon and CLI | WP-05, WP-08 |
| `acf-control-plane` | Capability Authority and Approval Service | WP-09, WP-13 |
| `acf-state` | Replay, revocation, quotas, receipts, journal | WP-10, WP-14 |

`deny.toml` enforces part of the dependency direction. Only `acf-gateway` may depend on `acf-provider-local`, and OpenSSL-based TLS crates are banned.
