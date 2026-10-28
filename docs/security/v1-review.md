# ACF v1.0 security review

Work package: WP-19

Date: 2026-10-28

Scope: master at `7af4c6a` (M1, WP-07, WP-17, WP-18), plus the fixes in this review.

Result: **no high-severity findings.**
- Two medium findings and one low finding are fixed.
- One medium finding is mitigated, with a follow-up.
- The remaining findings are accepted and documented.

This is an internal design and code review by the implementing team. It is not an independent assessment. An external review or penetration test is still recommended before ACF guards production credentials of real consequence.

## 1. Method and assumptions

Each v1.0 trust boundary was reviewed against the code and against the tests that exercise it. For each boundary the review asked:

- Who can send input across it?
- How is that input authenticated and validated?
- What fails closed?
- What could an attacker on the less-trusted side achieve?

The review also covered:
- **Remote-reachable panics:** clippy denies `unwrap`, `expect`, and `panic` outside tests. Indexing in the parsers was checked by hand.
- **Resource limits** on every listener.
- **Behavior on malformed or tampered state:** configuration, store records, audit files, and checkpoint stores.

Threat model, consistent with the design:

- **In scope.** A compromised or manipulated agent, including arbitrary code running as the agent's account. Other local accounts. Network attackers on any path. A stolen agent-host disk. An enrolled device acting outside its task. A misconfiguration that an administrator then admits.
- **Out of scope for v1.0.** Root or service-account compromise of the gateway or control-plane host: an attacker there can use credentials while they are in use. Compromise of the offline administrator keys. Malicious downstream APIs, beyond response filtering.

## 2. Boundaries

### 2.1 Agent ↔ daemon (Unix socket)

| Control | Evidence |
| --- | --- |
| The socket mode is 0660 at most; modes that grant access to others are refused. A stale socket is replaced; a live socket or a non-socket file is refused. | `acf-agent` `tests/daemon.rs` |
| The kernel reports each caller (`SO_PEERCRED`). UIDs outside the allow-list are disconnected before any HTTP is read. | `connections_from_other_uids_are_closed` |
| Task handles are 256-bit random values bound to the caller's UID and, optionally, a PID. Unknown and foreign handles look the same, and each UID holds at most 256 handles. | `tasks.rs` unit tests, `pid_bound_handles_are_unknown_to_other_processes` |
| The agent cannot set `requestId`, `timestamp`, `taskId`, or a capability: `deny_unknown_fields` on the local API, and the same rule in the MCP tool schemas. | `malformed_and_daemon_owned_fields_are_rejected`, the `acf-agent` `tests/mcp.rs` |
| The capability never crosses this boundary; its `Debug` output is redacted. | `capabilities_stay_inside_the_registry`, the MCP end-to-end scan |

Peer credentials prove operating-system provenance, not intent. Any process running as an allowed UID can use that UID's handles, within the task's grants. PID binding is hygiene, because PIDs are reused. Both points are documented (ADR 0002, `docs/mcp.md`).

### 2.2 Daemon ↔ authority and daemon ↔ gateway (mTLS)

| Control | Evidence |
| --- | --- |
| TLS 1.3 only, a mandatory client certificate, and no 0-RTT or session tickets. The daemon trusts only the deployment CA and never uses a proxy or follows a redirect. | `acf-gateway` `tests/tls.rs` |
| Identity comes from CA validation plus enrollment by `x5t#S256`. Certificate names, and headers such as `X-Forwarded-Client-Cert`, are never used. | `identity_headers_are_ignored`, `trusted_but_unenrolled_certificates_are_unauthenticated` |
| Capabilities are EdDSA JWS with a strict header profile, pinned to a key and its issuer, valid for 24 h at most. At request time the gateway checks `aud`, time, `cnf.x5t#S256`, `sub`, the task, the grant, and the grant's constraints. | `acf-identity` capability tests, `acf-e2e` `capabilities.rs` |
| Agent scope is a proposal: the grant is proposal ∩ entitlement ∩ basis ∩ registered actions. | `a_proposal_can_only_narrow`, `agent_scope_is_only_a_proposal` |
| Replay protection per principal and `requestId`, a freshness window, and revocation by capability, task, principal, or device. | `acf-gateway` `tests/gateway.rs`, `revocation_and_limits_apply_to_the_capability` |
| v1.0 is read-only: every `mutate` action is refused even when a capability grants it. | `mcp_tools_read_through_the_gateway_and_relay_mutation_refusals` |

### 2.3 Administrator ↔ configuration

| Control | Evidence |
| --- | --- |
| The bundle, each profile, and the policy are admitted separately, by role-bound signatures or pins. Signatures cannot cross roles. A profile author cannot redirect where a secret is used. | `acf-config` admission tests, `acf-gateway` `tests/production.rs` |
| `production` refuses development builds and components, plaintext, missing capabilities or audit anchoring, and test or internal destinations, listing every problem. | `tests/production.rs` (both flavors) |
| `acf-setup` keeps the CA key and administrator keys in `offline/`, writes private keys as 0600 or stricter, and `admit` re-checks the production rules before signing. | `acf-gateway` `tests/setup.rs` |

### 2.4 Gateway ↔ secret store

| Control | Evidence |
| --- | --- |
| Per-record AES-256-GCM with the metadata authenticated. Opaque file names. Tombstones. Mode and symlink checks. Reads fail closed. | `acf-provider-local` `tests/provider.rs` |
| The root key is read from a private regular file or a systemd credential, never from an argument or configuration value. | `key_source.rs` tests |
| The binding stored with a record must equal the configured use binding, or the connector refuses the credential. | `acf-connectors` binding tests |
| A tampered record makes the request fail without calling the downstream API. | `acf-gateway` `tests/encrypted_store.rs` |
| Unimplemented guarantees (rollback anchors, TPM, KMS) are refused, never silently ignored. | `unimplemented_store_guarantees_are_refused_not_ignored` |

### 2.5 Gateway ↔ checkpoint collector

| Control | Evidence |
| --- | --- |
| Hash-chained events; a partial record or an unchained file stops startup. | `acf-audit` chain tests |
| Checkpoints are domain-separated Ed25519 statements. The collector checks the signature and the key's principal, and only moves a log's history forward. | collector tests, `acf-e2e` `audit.rs` |
| Truncation, or replacement with a recomputed chain, is detected only through checkpoints. | `checkpoints_expose_truncation_and_rewritten_history` |
| Allowed requests fail closed once the newest checkpoint is older than the maximum lag. | `a_stale_anchor_fails_allowed_requests_closed` |

## 3. Findings

| ID | Severity | Boundary | Finding | Resolution |
| --- | --- | --- | --- | --- |
| V1-01 | Medium | All listeners | The gateway, authority, and daemon had no header-read timeout (hyper arms none without a timer) and no connection cap. An enrolled device, or any allowed local user, could hold unlimited idle connections and exhaust file descriptors and tasks. | **Fixed.** A shared `http1()` builder arms a 10-second header-read timeout. `serve_tls` holds at most 1024 connections and the daemon at most 256, taking a slot before `accept`. Test: `a_client_that_never_sends_headers_is_disconnected`. |
| V1-02 | Medium | Collector | The collector bound a checkpoint to its key's principal, but not the log to a gateway. A second enrolled gateway could submit a far-ahead checkpoint for another gateway's log. That would block the victim's checkpoints (it then fails closed after the lag) and raise false truncation findings. | **Fixed.** Each log belongs to the gateway that signed its first checkpoint, including after a collector restart. Test: `a_log_belongs_to_the_gateway_that_first_checkpointed_it`. |
| V1-03 | Medium | Daemon ↔ authority | Capability `limits` and task quotas are counted per capability and per task ID. The authority issues capabilities without a budget, so an agent can reset its limits by requesting fresh capabilities and task IDs. Only the optional per-principal rate limit bounds the total. | **Mitigated.** `acf-setup` now writes `--rate-limit-principal 600` into the gateway unit. **Follow-up:** an issuance budget per principal and job at the authority. |
| V1-04 | Medium | Administrator ↔ configuration | `authority.yaml` (entitlements and schedulers), the device registries, the authority key set, and the audit key set are protected by file ownership only (ADR 0004 non-goal). Whoever can write `authority.yaml` can define a scheduler and grant without any signed job. Whoever can write `authority-keys.yaml` can trust a key of their own. | **Accepted for v1.0.** The files are root-owned and the services run with `ProtectSystem=strict`. Writing them requires root on a server, which is out of scope. **Follow-up:** admit these files through the trust anchor with their own roles. |
| V1-05 | Low | Collector | `verify-audit` checked only the log it was given. A deleted log file left only its checkpoints behind, and nothing pointed to them. | **Fixed.** `verify-audit` lists the gateway's other checkpointed logs and asks for each to be verified. |
| V1-06 | Low | All listeners | Request bodies have no read deadline after the headers arrive. | **Accepted.** The body is capped at 64 KiB and the connection caps from V1-01 apply. |
| V1-07 | Low | Device registry | A registry reload that fails validation keeps the previous registry. A device removal written with a syntax error therefore does not take effect; the failure is only logged. | **Accepted, fail-safe for availability.** Operators must check the reload message. **Follow-up:** expose reload status in health output. |
| V1-08 | Low | Single-host installs | When the gateway and the control plane share a host name, the control plane's certificate is also valid for the gateway's name, so it could impersonate the gateway to daemons. | **Accepted.** Both services are on the same host. Split installs use distinct names. |
| V1-09 | Info | Store | The store provides integrity, not rollback resistance. | **Accepted and explicit:** configuration must acknowledge it, and startup states it. |

## 4. Residual risks for v1.0 operators

- **Gateway host compromise.** Root on the gateway host can decrypt the store and use credentials. Run the gateway on a dedicated host and keep the offline keys off it.
- **Misuse inside a granted scope.** An agent influenced by hostile input can still use every action its task grants, within its constraints and rate limits. Keep job scopes narrow and short-lived.
- **Expiring certificates.** Certificates expire after 90 days by default, and v1.0 has no renewal command. Monitor expiry.
- **No independent assessment yet.** See the note at the top.

## 5. Follow-ups

| Item | From |
| --- | --- |
| Authority issuance budget per principal and job | V1-03 |
| Admit the authority configuration, registries, and key sets through the trust anchor | V1-04 |
| Registry reload status in health output | V1-07 |
| `acf-setup renew` for certificate renewal | WP-17 |
| Independent security assessment | This review |
