# ACF deployment runbook (for a DevOps agent)

Target: **ACF v1.0.0-rc.1** on a single Linux host, using the Cloudflare DNS read-only connector. This is the WP-20 staging run. When every check in §7 passes, the project tags v1.0.0.

Follow the steps in order. Every step lists what must be true before moving on. If a check fails, **stop and report**; do not work around it.

## 0. Inputs (from the human operator)

| Input | Example | Notes |
| --- | --- | --- |
| Target host with sudo | `acf-staging-1` | Linux x86-64, systemd, glibc ≥ 2.35 (Ubuntu 22.04+, Debian 12+) |
| Gateway host name | `localhost` for single host | Name the agent host uses to reach the gateway and control plane |
| Agent account | `claude` | The account the AI agent runs as |
| Cloudflare zone name and zone ID | `example.org`, `023e105f…` | From the Cloudflare dashboard → Overview |
| Cloudflare API token | — | Scope **only** *Zone → DNS → Read* on that zone. Delivered through a secure channel, never in chat, tickets, or files you commit |
| Offline storage for `offline/` | Encrypted volume or password manager | It holds the CA key and the administrator signing keys |

Steps 1–4 run on an **admin workstation**. Steps 5–7 run on the **target host**. For a single-host staging run they may be the same machine, but `offline/` must still never stay on the host when you finish.

## Guardrails (always)

- **Never put the Cloudflare token** in a command-line argument, environment variable, file in the repository, log, or report. Load it only through `acf-store put` on standard input (§6), and remove any temporary copy with `shred -u`.
- **Never copy `offline/`** (`ca.key`, `keys/*.key`) to the target host, and never commit it. Move it to offline storage at the end of §4.
- **Do not weaken the systemd hardening** in the generated units, chmod keys to be more permissive, or disable a production check to make something start. Report the failure instead (§8).
- **ACF v1.0 is read-only.** Do not try to make a mutation succeed.

## 1. Preflight (target host)

```bash
uname -m                      # x86_64
ldd --version | head -1       # glibc 2.35 or newer
systemctl --version | head -1
timedatectl show -p NTPSynchronized --value   # yes: capabilities and checkpoints are time-bound
ss -ltn '( sport = :8443 or sport = :8444 )'  # nothing listening
id <agent-account>
```

**Pass:** x86_64, glibc ≥ 2.35, systemd present, clock synchronized, ports 8443 and 8444 free, agent account exists. Record the agent account's UID; you need it in §3.

## 2. Download and verify the release (admin workstation and target host)

```bash
base=https://github.com/carloscn/agent-credential-firewall/releases/download/v1.0.0-rc.1
curl -fLO "$base/acf-1.0.0-rc.1-x86_64-unknown-linux-gnu.tar.gz"
curl -fLO "$base/acf-1.0.0-rc.1-x86_64-unknown-linux-gnu.tar.gz.sha256"
sha256sum -c acf-1.0.0-rc.1-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf acf-1.0.0-rc.1-x86_64-unknown-linux-gnu.tar.gz
cd acf-1.0.0-rc.1-x86_64-unknown-linux-gnu
sudo install -m 0755 bin/* /usr/local/bin/      # on the target host
for b in acf-gateway acf-control-plane acf-agent acf-setup acf-store; do $b --version; done
```

**Pass:** the checksum line ends in `OK`, and all five tools print `1.0.0-rc.1`.

The archive contains `docs/deployment.md`, `docs/staging.md`, `docs/mcp.md`, `docs/security-review.md`, `RELEASE-NOTES.md`, and `examples/cloudflare-readonly/`. This runbook follows `docs/staging.md`; read it once.

## 3. Generate the deployment (admin workstation)

```bash
acf-setup init --out acf-staging \
  --gateway-host <gateway-host> \
  --device agent-1 \
  --agent-uid <agent-account-uid>
```

**Pass:** exit code 0. `acf-staging/` contains `gateway/`, `control-plane/`, `agent-agent-1/`, `offline/`, and `DEPLOY.md`.

## 4. Add the Cloudflare connector and admit (admin workstation)

Apply `examples/cloudflare-readonly/` exactly as `docs/staging.md` §2 describes. In every snippet, replace `example.com` with the zone name and the `zone_id` value with the zone ID.

| Generated file | Change |
| --- | --- |
| `acf-staging/gateway/config/bundle.yaml` | Replace `resources: {}` and `secrets: {}` with `bundle-resources.yaml` |
| `acf-staging/gateway/config/policy.yaml` | Replace `rules: []` with `policy-rules.yaml` |
| `acf-staging/control-plane/config/authority.yaml` | Replace `entitlements: []` with `entitlements.yaml` |
| `acf-staging/gateway/config/profiles/` | Copy in `profiles/cloudflare.yaml` |
| `acf-staging/control-plane/config/jobs/` | Copy in `jobs/dns-read.yaml` |

Then admit the configuration:

```bash
acf-setup admit --out acf-staging
```

**Pass:** the output says `admitted 1 profiles, the bundle, the policy, and 1 jobs`.

Copy `gateway/`, `control-plane/`, `agent-agent-1/`, and `DEPLOY.md` to the target host. Then **move `offline/` to offline storage** and delete it from the workstation's working copy.

## 5. Install and start (target host, as root)

Run `acf-staging/DEPLOY.md` sections 1–3 with these substitutions:

- `{etc}` = `/etc/acf`.
- `{state}` = `/var/lib/acf`.
- `{env}` = `production`.
- `agent-<device>` = `agent-agent-1`.
- `<agent-user>` = the agent account.

In order:

1. Accounts and directories (all three roles on this host), then `usermod -aG acf-agents <agent-account>`.
2. `acf-store … init --namespace production`, run as `acf-gateway`.
3. Install the three units, `systemctl daemon-reload`, then start `acf-control-plane`, then `acf-gateway`, then `acf-agent`.

```bash
systemctl --no-pager status acf-control-plane acf-gateway acf-agent
journalctl -u acf-gateway -n 20 --no-pager
```

**Pass:** all three units are `active (running)`. The gateway journal shows:
- `release build, production profile, config sha256:…`;
- `anchored by checkpoints, mTLS) listening on https://0.0.0.0:8443`;
- the store line `integrity only, no rollback resistance`.

## 6. Load the Cloudflare token (target host)

Have the operator paste the token into a hidden prompt. The token never touches the command line:

```bash
read -rs CF_TOKEN && printf '%s' "$CF_TOKEN" | sudo -u acf-gateway acf-store \
  --config /etc/acf/gateway/config/bundle.yaml --profiles /etc/acf/gateway/config/profiles \
  put secret://production/cloudflare/<zone-name>/dns-read; unset CF_TOKEN
```

**Pass:** the output is `stored secret://production/cloudflare/<zone-name>/dns-read v1`. The token is not printed.

## 7. Acceptance checks (target host)

Run as the agent account unless noted. All of these must pass.

1. **A task is granted.**

   ```bash
   acf-agent task create --socket /run/acf-agent/acf.sock --task staging --job dns-read
   ```

   The output includes `cloudflare.dns.records.list` and `"maxRequests": 50`. Keep the `taskHandle` for the next step.

2. **The read works.**

   ```bash
   acf-agent action execute --socket /run/acf-agent/acf.sock --task-handle <handle> \
     --action cloudflare.dns.records.list --resource cloudflare-zone:<zone-name> --param type=A
   ```

   The result is `"status": "completed"` with the zone's A records, showing only allowlisted fields.

3. **The token never leaks** (as root):

   ```bash
   sudo grep -rF "<first 8 characters of the token>" /etc/acf /var/lib/acf /run/acf-agent; echo $?
   ```

   Prints `1` (no match).

4. **A mutation is refused.** Run step 2 with `--action cloudflare.dns.records.create`. The result is `"status": "denied"` with `"reason": "policy_denied"`.

5. **The audit log verifies.** Wait at least 30 seconds after step 2, then run as root:

   ```bash
   acf-control-plane verify-audit --log /var/lib/acf/gateway/audit.jsonl \
     --checkpoints /var/lib/acf/control-plane/checkpoints \
     --audit-keys /etc/acf/control-plane/config/audit-keys.yaml; echo $?
   ```

   Exit code `0` and at least `1 checkpoints`.

6. **Revocation works.** Run as root.
   1. Save the registry and replace it with a valid empty one:

      ```bash
      cp /etc/acf/gateway/config/devices.yaml /root/devices.yaml.bak
      printf 'schema: acf.devices/v1\ndevices: []\n' > /etc/acf/gateway/config/devices.yaml
      ```

      The file must stay valid YAML. An invalid registry is ignored and the old one stays in force (review finding V1-07), so the check would fail for the wrong reason.
   2. Wait 6 seconds, then repeat step 2 as the agent account. The result is `"reason": "unauthenticated"`.
   3. Restore the registry: `cp /root/devices.yaml.bak /etc/acf/gateway/config/devices.yaml`.
   4. Wait 6 seconds, then repeat step 2. It completes again.

7. **MCP works (optional).** As the agent account:

   ```bash
   claude mcp add acf -- /usr/local/bin/acf-agent mcp --socket /run/acf-agent/acf.sock
   ```

   Ask the agent to list the zone's A records with ACF. It must use `acf_request_task` with job `dns-read`, then `acf_execute_action`.

## 8. Report

Post a comment on the roadmap issue, [#23](https://github.com/carloscn/agent-credential-firewall/issues/23), or the issue the operator names, using this template. **Never include the token or any key.**

```markdown
## ACF v1.0.0-rc.1 staging run
- Host / OS / glibc:
- Preflight (§1): pass/fail
- Release checksum (§2): pass/fail
- init + admit (§3–4): pass/fail
- Services (§5): pass/fail — gateway start line:
- Token load (§6): pass/fail
- Checks (§7): 1 task / 2 read / 3 no leak / 4 mutation refused / 5 verify-audit / 6 revocation / 7 MCP
- Failures: step, exact command, full output, `journalctl -u <unit> -n 50`
- Deviations from this runbook:
```

## Rollback

On the target host, as root:

```bash
systemctl disable --now acf-agent acf-gateway acf-control-plane
rm /etc/systemd/system/acf-{agent,gateway,control-plane}.service && systemctl daemon-reload
```

Keep `/var/lib/acf` (store, state, audit log, checkpoints) for the report unless the operator asks for removal. Then revoke the Cloudflare token in the Cloudflare dashboard.
