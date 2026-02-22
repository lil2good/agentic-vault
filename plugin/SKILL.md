---
name: vault
description: Manage per-agent scoped API credentials with JIT tokens, proxy enforcement, revocation, and full audit logging. Use when agents need to call external APIs (GitHub, Stripe, OpenAI, etc.) without exposing master secrets.
---

# Agentic Credential Vault

## Overview

The vault replaces raw API keys with scoped, short-lived tokens. Master secrets stay server-side — agents never see them.

## Agent Tools

### `vault_issue_token` — Get a scoped token
```
vault_issue_token({
  service: "github",
  scope: ["github:repos:read"],
  ttl: 60,
  agentId: "tony",
  sessionId: "current-session",
  taskId: "current-task",
  skillId: "github-read"
})
```
Returns: `{ token, tokenId, expiresInSec }`

### `vault_call` — Proxy an API call
```
vault_call({
  token: "<from issue_token>",
  service: "github",
  action: "repos.get",
  params: {},
  agentId: "tony",
  sessionId: "current-session",
  taskId: "current-task",
  skillId: "github-read"
})
```
Returns: upstream API response (vault attaches master secret server-side)

### `vault_revoke` — Kill switch
```
vault_revoke({ sessionId: "compromised-session" })
vault_revoke({ agentId: "rogue-agent" })
vault_revoke({ tokenId: "specific-token-id" })
```

### `vault_admin` — Configure services (main agent only)
```
// List available templates
vault_admin({ action: "listTemplates" })

// Load a template (user provides the API key)
vault_admin({
  action: "loadTemplate",
  template: "github",
  masterSecret: "<user's PAT>",
  allowedAgents: ["tony", "steve"]
})

// Add a custom service
vault_admin({
  action: "addService",
  service: "my-api",
  baseUrl: "https://api.example.com",
  allowedAgents: ["tony"],
  allowedActions: ["issue", "data.get"],
  allowedScopes: ["myapi:data:read"],
  endpoints: {
    "data.get": { "method": "GET", "path": "/data", "requiredScope": ["myapi:data:read"] }
  },
  secretRef: "myapi_key",
  masterSecret: "<the key>"
})

// List configured services (secrets redacted)
vault_admin({ action: "listServices" })
```

## Setup

The vault plugin auto-starts with the OpenClaw gateway. On first run it generates:
- Signing key (`~/.openclaw/vault-data/.vault-signing-key`)
- Admin token (`~/.openclaw/vault-data/.vault-admin-token`)
- Encrypted secret store (`~/.openclaw/vault-data/secrets.enc`)

No manual configuration needed. Just tell your agent: "Add my GitHub token to the vault."

## Security Model

- **Deny by default** — only explicitly allowlisted services/actions/agents work
- **Context-bound tokens** — agent ID, session, task, and skill must match
- **Short TTL** — tokens expire in minutes (max 15m)
- **Encrypted at rest** — master secrets stored with AES-256-GCM
- **Full audit trail** — every issuance, call, denial, and revocation logged
- **Instant revocation** — kill by token, session, task, or agent
