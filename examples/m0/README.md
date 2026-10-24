# Milestone 0 demo

An agent performs `example.profile.get` against a local upstream without
ever receiving the bearer token. Development only: plaintext loopback, a fixed
development identity, and the in-memory provider.

```bash
cargo build -p acf-gateway --features development -p acf-agent
export DEMO_TOKEN="demo-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"

python3 examples/m0/upstream.py 8080 &
target/debug/acf-gateway \
  --config examples/m0/config.yaml \
  --policy examples/m0/policy.yaml \
  --secret-env secret://development/example-api/read=DEMO_TOKEN &

target/debug/acf-agent action execute \
  --action example.profile.get \
  --resource example-api:development
```

Expected output:

```json
{
  "status": "completed",
  "requestId": "req-…",
  "result": {
    "status": 200,
    "body": { "user": "demo", "authenticated": true }
  }
}
```

The upstream also echoes the `Authorization` header in
`debug_authorization_echo`; that field is not in the profile's response
allowlist, so the gateway drops it. The token is passed to the gateway through
an environment variable and never appears on a command line or in the agent's
output.
