# Deploying ACF v1.0

ACF v1.0 is read-only: agents can run semantic read actions, and every mutation is refused. See the [v1.0 plan](implementation-plan.md#23-v10--read-only-release) for scope and limitations.

## One command

```bash
acf-setup init --out acf-deploy \
  --gateway-host gateway.internal --control-plane-host control.internal \
  --device build-runner-1 --device laptop-7 --agent-uid 1001
```

The command writes one directory per role. Paths inside each directory already point at its install location (`--etc`, default `/etc/acf`):

| Directory | Install on | Contents |
| --- | --- | --- |
| `gateway/` | The gateway host, as `/etc/acf/gateway` | Server and checkpoint-client certificates, audit and store keys, admitted configuration, trust anchor, device registry, authority keys, systemd unit |
| `control-plane/` | The control-plane host, as `/etc/acf/control-plane` | Server certificate, authority signing key, authority configuration, job directory, device registry, audit keys, systemd unit |
| `agent-<device>/` | That agent host, as `/etc/acf/agent` | Client certificate, gateway CA, systemd unit for the daemon |
| `offline/` | **No server** | CA key and the administrator keys that admit configuration and sign jobs |

The generated `DEPLOY.md` lists the exact commands: accounts, ownership, creating the secret store, and starting the services. It also covers adding a connector, defining a job, loading a secret, and checking the audit trail.

## Agents

Agents reach ACF through the daemon on their host. The read-only MCP adapter, `acf-agent mcp`, gives MCP clients such as Claude Code three tools; see [mcp.md](mcp.md).

## Single host

Install all three role directories on one machine. The defaults (`--gateway-host localhost`, listeners on ports 8443 and 8444) cover this case. Only one agent device can be installed per host.

## Changing configuration

Edit the files under the output directory, then run:

```bash
acf-setup admit --out acf-deploy
```

`admit` checks the bundle, profiles, and policy against the production rules. It then re-signs every document with its role key from `offline/`, signs job definitions, and refreshes the control plane's copy of the gateway configuration. Copy the changed `config` directories to the hosts and restart the services.

## Certificates

Leaf certificates expire after `--cert-days` (default 90). v1.0 has no renewal command yet. Issue new certificates from `offline/ca.key` before expiry, and update the device registries (`devices.yaml`) with the new thumbprints. A registry can list the old and new thumbprints together while devices switch over (ADR 0002).
