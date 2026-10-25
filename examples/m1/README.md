# WP-08 demo: daemon and mTLS

The same `example.profile.get` read as the [Milestone 0 demo](../m0/README.md), with three changes:

- The agent talks only to a local daemon, over a Unix socket. It holds an opaque task handle and nothing else.
- The daemon reaches the gateway over TLS 1.3 with a client certificate.
- The gateway takes the caller's identity from that certificate, looked up in a device registry. It ignores any identity a request claims.

Development only: a throwaway CA, the in-memory provider, and every process under one account. The production topology (below) separates the accounts.

```bash
cargo build -p acf-gateway --features development --bins --examples -p acf-agent
PKI=$(mktemp -d)/pki
RUN=$(mktemp -d) && chmod 700 "$RUN"   # only the daemon's account may create the socket here

# CA, gateway certificate for localhost, client certificate for device vps-17,
# and devices.yaml enrolling it as workload:vps-17. Keys are written 0600.
target/debug/examples/dev-pki "$PKI" vps-17

export DEMO_TOKEN="demo-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
python3 examples/m0/upstream.py 8080 &

target/debug/acf-gateway \
  --config examples/m0/config.yaml \
  --policy examples/m1/policy.yaml \
  --tls-cert "$PKI/gateway.pem" --tls-key "$PKI/gateway.key" \
  --client-ca "$PKI/ca.pem" --devices "$PKI/devices.yaml" \
  --secret-env secret://development/example-api/read=DEMO_TOKEN \
  --audit-log /tmp/acf-m1-audit.jsonl \
  --state-db /tmp/acf-m1-state.sqlite &

target/debug/acf-agent daemon \
  --socket "$RUN/acf.sock" \
  --gateway https://localhost:8443 \
  --client-cert "$PKI/vps-17.pem" --client-key "$PKI/vps-17.key" \
  --gateway-ca "$PKI/ca.pem" &

# The agent side: open a task, then act through the handle.
HANDLE=$(target/debug/acf-agent task create --socket "$RUN/acf.sock" --task demo-task \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["taskHandle"])')
target/debug/acf-agent action execute --socket "$RUN/acf.sock" --task-handle "$HANDLE" \
  --action example.profile.get --resource example-api:development
```

The result is the same as in M0. The audit log's decision event now records `"principal": "workload:vps-17"` and `"device": "vps-17"`. The daemon chose the `requestId` and timestamp. The agent could not supply them: the daemon rejects a local request that names them, or the `taskId`.

## What to try

- `curl http://127.0.0.1:8443/healthz` fails: the listener speaks TLS only.
- `curl --cacert "$PKI/ca.pem" https://localhost:8443/healthz` fails the handshake: a client certificate is mandatory.
- Replace the thumbprint in `devices.yaml` and wait 5 seconds. The next action is denied with `unauthenticated`, because the certificate still chains to the CA but is no longer enrolled. Put the thumbprint back to restore access. Rotation works the same way: list both thumbprints, switch the daemon to the new certificate, then remove the old one.
- `chmod 640 "$PKI/vps-17.key"` and restart the daemon. It refuses to start.
- Run `acf-agent task create --pid 1 …` and use the handle from your shell. The daemon answers `unknown_task`: the handle is bound to PID 1.

## Production topology

| Account | Can read | Can connect to |
| --- | --- | --- |
| `acf-daemon` (service) | Client key (0600), client certificate, gateway CA | Gateway (mTLS) |
| `agent` | Nothing of the above | The daemon socket (mode 0660, group `acf-agents`), and only if its UID is passed with `--allowed-uid` |

- The daemon checks each caller's UID, GID, and PID from the kernel (`SO_PEERCRED`). Connections from UIDs that are not allowed are closed before any HTTP is read.
- Task handles are random 256-bit values bound to the creating UID and, if a launcher registers one, a PID. Unknown and foreign handles get the same `404`.
- **Peer credentials prove operating-system provenance, not intent.** Any process running as an allowed UID can use that UID's handles, including commands a compromised agent runs. What such a process can do is bounded by task scope, policy, resource constraints, quotas, and approvals, not by the socket check. PID binding is hygiene, not process authentication: PIDs are reused.
- Hardware-backed, non-exportable device keys (TPM, Keychain, PKCS#11) are later work behind the same interface. Until then, the key file's 0600 mode under the service account is what keeps the agent from reading it.
