# Tailscale Deployment Use Case

Status: Draft

Last updated: 2026-10-24

## Overview

This document describes one recommended way to deploy Agent Credential Firewall (ACF) using Tailscale. Tailscale is an optional integration and is not a core dependency of ACF.

In this use case, Tailscale provides:

- Authenticated, encrypted connectivity between agents and gateways.
- User, device, and workload network identity.
- Private reachability without exposing the gateway to the public Internet.
- Network access policy through grants.
- Optional application capabilities and device-posture context.
- Device quarantine and removal controls during incident response.

ACF remains responsible for task authorization, secret retrieval, connector enforcement, response filtering, and credential-use auditing.

## Recommended topology

```text
Tailnet
├── gateway-dev-01        tag:credential-gateway-dev
├── gateway-prod-eu-01    tag:credential-gateway-prod-eu
├── gateway-prod-eu-02    tag:credential-gateway-prod-eu
├── laptop-agents         user identities / tag:agent-dev
├── vps-agent-dev         tag:agent-dev
└── vps-agent-prod        tag:agent-prod
```

The gateway should listen only on its Tailscale interface or use an embedded tailnet endpoint. It should not expose its Agent API through a public network interface.

Development and production should use separate gateway identities, access rules, and secret-provider namespaces or access identities.

## Network grants

Network policy should deny access by default and permit only the required source-to-gateway connections.

Conceptual example:

```json
{
  "grants": [
    {
      "src": ["tag:agent-dev"],
      "dst": ["tag:credential-gateway-dev"],
      "ip": ["tcp:8443"]
    },
    {
      "src": ["tag:agent-prod"],
      "dst": ["tag:credential-gateway-prod-eu"],
      "ip": ["tcp:8443"]
    }
  ]
}
```

Agents should not receive broad lateral connectivity to other agent devices. Developer endpoints should not receive production gateway access by default.

## Application capabilities

An installation may use Tailscale application capabilities to carry broad authorization context to ACF.

Conceptual example:

```json
{
  "src": ["tag:agent-prod"],
  "dst": ["tag:credential-gateway-prod-eu"],
  "app": {
    "agentcredentialfirewall.dev/cap/actions": [
      {
        "actions": ["github.create_pull_request"],
        "resources": ["repo:example/backend"]
      }
    ]
  }
}
```

ACF can resolve the caller and its capabilities using LocalAPI or an embedded tailnet integration. The gateway must validate the actual connection identity; it must not trust identity headers supplied directly by an agent.

Application capabilities are only one authorization layer. ACF must still validate the signed task capability, evaluate gateway policy, and enforce the exact downstream request in its connector.

## Device classes

### Developer endpoints

- Combine user and device identity.
- Require posture checks for sensitive environments where available.
- Require approval for high-impact production actions.
- Default to development gateways and resources.

### Unattended VPS agents

- Use tag-owned workload identities instead of personal identities.
- Assign each VPS or workload a unique ACF agent identity.
- Restrict each tag to the minimum gateway and port.
- Avoid storing remote secret-provider bootstrap credentials on the VPS.

### Remote or unmanaged terminals

- Do not return raw production secrets.
- Permit only proxy actions or remote execution on trusted infrastructure.
- Use short task capabilities and approval for sensitive operations.

## Tailnet Lock

Tailnet Lock can add an approval boundary for new nodes joining the tailnet. It reduces the risk of an unauthorized node being introduced through the coordination plane.

It does not make a compromised, already authorized endpoint trustworthy. ACF should continue to apply task-scoped authorization, operation-level policy, rate limits, and anomaly detection.

## Failure and incident response

If a device is suspected of compromise:

1. Quarantine or remove the device from the tailnet.
2. Revoke active ACF sessions and task capabilities.
3. Revoke or rotate the affected gateway's provider credential or storage key if the gateway may be compromised.
4. Rotate downstream credentials used during the exposure window.
5. Correlate ACF, secret-provider, Tailscale, and downstream audit events.

Identity resolution failures must fail closed. Cached identity or capability data should have a short, bounded lifetime, and production secret use should not silently fall back to unauthenticated connectivity.

## Security boundary

Tailscale can establish who or which tagged node initiated a connection. It cannot establish that the node is free from malware or that an agent request is aligned with the user's intent.

The security boundary therefore remains layered:

```text
Tailscale connectivity and identity
        ↓
ACF task capability
        ↓
ACF contextual policy
        ↓
Connector request enforcement
        ↓
Downstream service authorization
```
