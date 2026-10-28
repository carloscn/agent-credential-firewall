# Staging run: Cloudflare DNS, read-only

This is the WP-20 staging check: a deployment from `acf-setup` serves one real read-only API end to end, and the audit log verifies against its checkpoints. It uses the files in `examples/cloudflare-readonly/`.

You need:

- **A Linux x86-64 host**, or a VM with systemd.
- **A Cloudflare zone.**
- **A Cloudflare API token** with only *Zone → DNS → Read* on that zone.

The token is the credential ACF protects. It goes into the encrypted store once and never appears in configuration, arguments, logs, or agent output.

## 1. Generate the deployment (on your workstation)

```bash
acf-setup init --out acf-staging --gateway-host localhost --agent-uid "$(id -u <agent-user>)"
```

## 2. Add the Cloudflare connector

Apply `examples/cloudflare-readonly/` to the generated files. In each snippet, replace `example.com` and the `zone_id` value with your zone's name and ID.

| Generated file | Change |
| --- | --- |
| `acf-staging/gateway/config/bundle.yaml` | Replace `resources: {}` and `secrets: {}` with `bundle-resources.yaml` |
| `acf-staging/gateway/config/policy.yaml` | Replace `rules: []` with `policy-rules.yaml` |
| `acf-staging/control-plane/config/authority.yaml` | Replace `entitlements: []` with `entitlements.yaml` |
| `acf-staging/gateway/config/profiles/` | Copy in `profiles/cloudflare.yaml` |
| `acf-staging/control-plane/config/jobs/` | Copy in `jobs/dns-read.yaml` |

Then admit the edited configuration. It must report 1 profile and 1 job:

```bash
acf-setup admit --out acf-staging
```

## 3. Install and start

Follow `acf-staging/DEPLOY.md`, sections 1 to 3, on the host:
1. Create the accounts and directories.
2. Copy each role directory into place.
3. Run `acf-store init`.
4. Start `acf-control-plane`, then `acf-gateway`, then `acf-agent`.

Load the token. It is read from standard input only:

```bash
sudo -u acf-gateway acf-store --config /etc/acf/gateway/config/bundle.yaml \
  --profiles /etc/acf/gateway/config/profiles \
  put secret://production/cloudflare/example.com/dns-read < cloudflare-token.txt
shred -u cloudflare-token.txt
```

## 4. Run the read as the agent user

Use either the CLI or MCP.

With the CLI:

```bash
acf-agent task create --socket /run/acf-agent/acf.sock --task staging --job dns-read
acf-agent action execute --socket /run/acf-agent/acf.sock --task-handle <handle> \
  --action cloudflare.dns.records.list --resource cloudflare-zone:example.com --param type=A
```

With MCP (Claude Code): `claude mcp add acf -- acf-agent mcp --socket /run/acf-agent/acf.sock`. Then ask the agent to list the zone's A records through `acf_request_task` (job `dns-read`) and `acf_execute_action`.

**Expected:** `status: completed` and only the allowlisted fields (`result.id`, `result.name`, `result.content`, and so on). No token appears anywhere.

## 5. Check

Each check, with its expected result:

1. **The token never leaks.** `sudo grep -r "<first 8 characters of the token>" /var/lib/acf /etc/acf /run/acf-agent` finds nothing: the store holds only ciphertext.
2. **A mutation is refused.** Ask the agent for `cloudflare.dns.records.create`: it is denied with `policy_denied`, and the audit log records `capability_not_granted`.
3. **The audit log verifies.** Wait at least 30 seconds for a checkpoint, then run on the control-plane host (with a copy of the gateway's log if they are separate):

   ```bash
   acf-control-plane verify-audit --log /var/lib/acf/gateway/audit.jsonl \
     --checkpoints /var/lib/acf/control-plane/checkpoints \
     --audit-keys /etc/acf/control-plane/config/audit-keys.yaml
   ```

   It exits 0 and reports at least one checkpoint.
4. **Revocation works.** Remove `agent-1`'s entry from `/etc/acf/gateway/config/devices.yaml`. Within 5 seconds the next request is denied `unauthenticated`. Restore the entry afterwards.

Record each step's output, without the token. Failures go to the issue tracker with the `staging` label.
