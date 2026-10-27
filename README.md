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

- WP-11 (done): configuration admission and the `production` profile ([ADR 0004](docs/adr/0004-config-admission-and-production-profile.md)). The bundle, each connector profile, and the policy are admitted separately, by a role-bound signature or a pinned digest, so a profile author cannot redirect where a secret is used. Every audit event records the admitted configuration's digest. Under `production`, the gateway refuses development builds, unadmitted configuration, plaintext listeners, missing capabilities or audit sink, the in-memory provider, and test or internal destinations, listing every problem at once.

- WP-12 (done): audit integrity ([ADR 0005](docs/adr/0005-audit-hash-chain-and-checkpoints.md)). Every audit event is hash-chained to the previous one. The gateway signs the chain head and publishes it over mTLS to the control plane's append-only checkpoint collector. `acf-control-plane verify-audit` detects broken links, and truncation or replacement of anything a checkpoint covers. If no checkpoint is accepted within the maximum lag, allowed requests fail closed. Production requires checkpointing. A local hash chain alone is never treated as sufficient.

- WP-07 (done, integrity only): the per-record encrypted local provider ([encrypted-local.md](docs/providers/encrypted-local.md)), administered with `acf-store`. Keys come from systemd credentials or a protected mounted file. No rollback anchor is implemented, so production requires the explicit `rollback_resistance: none` acknowledgement and refuses a configured anchor.

**Deploying:** `acf-setup init` generates a complete production deployment in one command; see [docs/deployment.md](docs/deployment.md).

**Next: v1.0, a read-only release.** It makes the M1 core installable with one command and usable by agents through MCP, after a bounded security review. Mutations stay refused until M2. See [the plan](docs/implementation-plan.md#23-v10--read-only-release).

Release builds (no `development` feature) run with mTLS only, and a release build starts under `production` with an admitted configuration and an encrypted local store.

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
| `acf-provider-local` | Encrypted local provider (integrity only) | WP-07 |
| `acf-agent` | Endpoint/VPS daemon and CLI | WP-05, WP-08 |
| `acf-control-plane` | Capability Authority and Approval Service | WP-09, WP-13 |
| `acf-state` | Replay, revocation, quotas, receipts, journal | WP-10, WP-14 |
| `acf-e2e` | Test-only: daemon, authority, and gateway end to end | WP-09 |

`deny.toml` enforces part of the dependency direction. Only `acf-gateway` may depend on `acf-provider-local`, and OpenSSL-based TLS crates are banned.
