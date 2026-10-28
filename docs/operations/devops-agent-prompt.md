# Prompt for the DevOps agent

Copy everything below the line into the DevOps agent's session. Replace the `<…>` values first. The Cloudflare token is **not** part of the prompt: the operator types it into the hidden prompt in runbook §6.

---

You are deploying **ACF (Agent Credential Firewall) v1.0.0-rc.2** for its staging run.

Repository: https://github.com/carloscn/agent-credential-firewall

Follow this runbook exactly, step by step: `docs/operations/devops-runbook.md`. Supporting documents, also in the release archive:

- `docs/staging.md`: the staging procedure the runbook implements.
- `docs/deployment.md`: what `acf-setup` generates and how to change configuration.
- The `DEPLOY.md` that `acf-setup init` generates.

Inputs:

- **Target host:** `<host>`, which you can reach with sudo.
- **Gateway host name, used by the agent:** `<gateway-host>`. Use `localhost` for a single host.
- **Agent account on the host:** `<agent-account>`.
- **Cloudflare zone:** `<zone-name>`, zone ID `<zone-id>`.
- **Offline storage** for the generated `offline/` directory: `<where>`.

Rules:

1. Complete each step's **Pass** condition before moving on. If one fails, stop, collect the exact command, its full output, and `journalctl -u <unit> -n 50`, and report. Do not work around failures.
2. Never place the Cloudflare token in a command argument, an environment variable that outlives one command, a file, a log, or your report. Load it only with the `read -rs` command in runbook §6, which the operator completes.
3. Never copy `offline/` to the target host or commit it. Move it to the offline storage above when runbook §4 says so.
4. Do not edit the generated systemd units' hardening, loosen file permissions, or disable production checks. ACF v1.0 is read-only; do not try to make a mutation succeed.
5. Finish by posting the report from runbook §8 on GitHub issue #23 (https://github.com/carloscn/agent-credential-firewall/issues/23). Leave the services running unless told otherwise.
