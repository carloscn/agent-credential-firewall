# Using ACF from an agent (MCP)

`acf-agent mcp` is a read-only [Model Context Protocol](https://modelcontextprotocol.io) server over stdio. It runs under the agent's own account, talks to the local ACF daemon through its Unix socket, and holds no key, capability, or credential. It is a convenience layer, not a security boundary: everything it can do, the agent could also do through `acf-agent` on the command line, and the daemon and gateway enforce the same checks either way.

## Claude Code

```bash
claude mcp add acf -- /usr/local/bin/acf-agent mcp --socket /run/acf-agent/acf.sock
```

Or check it into a project as `.mcp.json`:

```json
{
  "mcpServers": {
    "acf": {
      "command": "/usr/local/bin/acf-agent",
      "args": ["mcp", "--socket", "/run/acf-agent/acf.sock"]
    }
  }
}
```

The agent's account needs two things: membership in the `acf-agents` group, and its UID allowed by the daemon (`acf-setup init --agent-uid`, or `--allowed-uid` in the daemon unit).

## Tools (version `v1`)

| Tool | Arguments | Returns |
| --- | --- | --- |
| `acf_request_task` | `taskId`; `job` *or* `scheduler: true`; optional `grants` (`[{action, resource}]`) and `ttlSecs` | An opaque `taskHandle` with the grants, limits, and expiry the Capability Authority actually allowed |
| `acf_get_task_status` | `taskHandle` | The same task status |
| `acf_execute_action` | `taskHandle`, `action`, `resource`, optional `parameters` object | The gateway's response: allowlisted result fields, or a denial or failure with a reason code |

- A proposal is only a proposal. The authority intersects it with the device's entitlements and the job's scope, so the returned grants may be narrower.
- Tasks opened through the adapter are bound to the adapter's process; other local processes cannot use their handles.
- Denials and failures, including the refusal of every mutation in v1.0, come back unchanged with `isError: true`, so the agent sees why.
- Tool arguments outside the schemas, such as a capability or a URL, are rejected. No tool returns a capability, a credential, or a secret reference.
- Every tool definition carries `_meta["acf/toolsVersion"] = "v1"`, which follows the daemon local API. Changes are backward compatible within `v1`.

Discovery tools (`acf_list_resources`, `acf_describe_action`) need a describe endpoint on the daemon and arrive after v1.0. Until then, tell the agent which jobs, actions, and resources it may use, for example in the project's `CLAUDE.md`.

## Example session

```text
agent → acf_request_task { "taskId": "dns-audit", "job": "dns-read" }
     ← { "taskHandle": "th-…", "grants": [{ "action": "cloudflare.dns.records.list", … }], "limits": { "maxRequests": 50 }, "expiresAt": "…" }
agent → acf_execute_action { "taskHandle": "th-…", "action": "cloudflare.dns.records.list",
                             "resource": "cloudflare-zone:example.com", "parameters": { "name": "api.example.com" } }
     ← { "status": "completed", "result": { "status": 200, "body": { "result": [ … ] } } }
```
