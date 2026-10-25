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

Milestone 0 (WP-00 through WP-06) is implemented. The development demo, where an agent reads a profile through the gateway without receiving the token, is in [`examples/m0`](examples/m0/README.md). Every request produces audit events, and a canary leak harness runs the real gateway binary and scans its responses, stdout, stderr, and audit log.

Milestone 1 is in progress:

- WP-10 (done): replay protection, revocation, quotas, and rate limits, backed by SQLite.
- WP-08 (done): the local daemon on a peer-credential Unix socket, plus TLS 1.3 mutual authentication with identity taken from an enrolled client certificate ([ADR 0002](docs/adr/0002-mtls-certificates-and-device-identity.md)). The demo is in [`examples/m1`](examples/m1/README.md).

- WP-09 (done): the Capability Authority in `acf-control-plane`. It narrows a daemon's task proposal to the intersection of the caller's entitlements, a signed job definition or scheduler policy, and the registered actions. It then signs a certificate-bound capability (JWS, Ed25519; [ADR 0003](docs/adr/0003-capability-wire-encoding.md)). The gateway verifies it with public keys only, and the agent only ever holds a task handle.

The gateway still runs only with the `development` feature and deployment profile until production validation (WP-11) lands.

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
| `acf-e2e` | Test-only: daemon, authority, and gateway end to end | WP-09 |

`deny.toml` enforces part of the dependency direction. Only `acf-gateway` may depend on `acf-provider-local`, and OpenSSL-based TLS crates are banned.
