---
name: agentic-credential-vault
description: Per-agent scoped API credentials with JIT tokens, proxy enforcement, revocation, and audit logging. Use when the user wants to secure API keys, add a service to the vault, manage agent credentials, or when any agent needs to call external APIs without exposing master secrets.
metadata:
  {
    "openclaw":
      {
        "requires": { "bins": ["node", "npm"] },
      },
  }
---

# Agentic Credential Vault

Replaces raw API keys with scoped, short-lived tokens. Master secrets stay server-side — agents never see them.

## First-Time Setup

If the vault is not yet installed, run these steps:

```bash
# 1. Clone the repo
git clone https://github.com/lil2good/agentic-credential-vault ~/projects/agentic-credential-vault
cd ~/projects/agentic-credential-vault

# 2. Install dependencies
npm install

# 3. Auto-generate secure .env (signing key + admin token)
SIGNING_KEY=$(openssl rand -hex 32)
ADMIN_TOKEN=$(openssl rand -hex 24)
cat > .env <<EOF
PORT=8787
VAULT_SIGNING_KEY=$SIGNING_KEY
VAULT_ADMIN_TOKEN=$ADMIN_TOKEN
VAULT_AUDIENCE=agentic-credential-vault-proxy
VAULT_POLICY_PATH=./config/policy.json
VAULT_DATA_DIR=./data
EOF
echo "Vault .env created with secure random keys."

# 4. Start the vault (use pm2 for persistence, or run directly)
# With pm2 (recommended — survives reboots):
pm2 start src/vault.js --name vault --env-file .env
pm2 save

# Without pm2 (manual):
# node --env-file=.env src/vault.js &
```

Verify it's running:
```bash
curl -s http://localhost:8787/health
# Expected: {"ok":true}
```

## Check If Vault Is Running

Before any vault operation, always check:
```bash
curl -s http://localhost:8787/health 2>/dev/null || echo "VAULT_DOWN"
```

If `VAULT_DOWN`:
```bash
cd ~/projects/agentic-credential-vault
pm2 start src/vault.js --name vault --env-file .env 2>/dev/null || node --env-file=.env src/vault.js &
sleep 1
curl -s http://localhost:8787/health
```

## Read Admin Token

All admin operations need the admin token from `.env`:
```bash
ADMIN_TOKEN=$(grep VAULT_ADMIN_TOKEN ~/projects/agentic-credential-vault/.env | cut -d= -f2)
```

## Adding a Service (User Says "Add My X Key")

### Option A: Use a built-in template (recommended)

Available templates: `github`, `stripe`, `shopify`, `openai`, `anthropic`

```bash
# List templates
curl -s http://localhost:8787/vault.admin.listTemplates \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{}'

# Load a template with the user's API key
curl -s http://localhost:8787/vault.admin.loadTemplate \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "template": "github",
    "masterSecret": "<USER_API_KEY>",
    "allowedAgents": ["tony", "steve", "jarvis"]
  }'
```

**Important:** Ask the user for their API key. Never generate or guess API keys. Store them ONLY via the vault API — never write them to files, logs, or chat.

### Option B: Add a custom service

```bash
curl -s http://localhost:8787/vault.admin.addService \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "service": "my-api",
    "baseUrl": "https://api.example.com",
    "allowedAgents": ["tony"],
    "allowedActions": ["issue", "data.get"],
    "allowedScopes": ["myapi:data:read"],
    "endpoints": {
      "data.get": {
        "method": "GET",
        "path": "/data",
        "requiredScope": ["myapi:data:read"]
      }
    },
    "secretRef": "myapi_key",
    "masterSecret": "<USER_API_KEY>"
  }'
```

## List Configured Services

```bash
curl -s http://localhost:8787/vault.admin.listServices \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{}'
```

Returns service names, allowed agents, scopes — secrets are NEVER returned.

## Using the Vault (Agent Makes an API Call)

### Step 1: Issue a scoped token

```bash
curl -s http://localhost:8787/vault.issueToken \
  -H 'content-type: application/json' \
  -d '{
    "service": "github",
    "scope": ["github:repos:read"],
    "ttl": 60,
    "agentId": "tony",
    "sessionId": "sess-123",
    "taskId": "task-456",
    "skillId": "github-read",
    "tool": "vault.issueToken"
  }'
```

Returns: `{ tokenId, token, expiresInSec }`

### Step 2: Proxy the API call

```bash
curl -s http://localhost:8787/vault.call \
  -H 'content-type: application/json' \
  -d '{
    "token": "<TOKEN_FROM_STEP_1>",
    "service": "github",
    "action": "repos.get",
    "params": {},
    "context": {
      "agentId": "tony",
      "sessionId": "sess-123",
      "taskId": "task-456",
      "skillId": "github-read",
      "tool": "vault.call"
    }
  }'
```

The vault attaches the master secret server-side and forwards the request. The agent never sees the real API key.

## Revocation (Kill Switch)

Revoke by token, session, task, or agent:

```bash
# Revoke a specific session
curl -s http://localhost:8787/vault.revoke \
  -H 'content-type: application/json' \
  -d '{"sessionId": "sess-123", "reason": "task complete"}'

# Revoke an entire agent
curl -s http://localhost:8787/vault.revoke \
  -H 'content-type: application/json' \
  -d '{"agentId": "tony", "reason": "security incident"}'
```

## Audit Log

Query the append-only audit trail:

```bash
curl -s http://localhost:8787/vault.audit.query \
  -H 'content-type: application/json' \
  -d '{"filters": {"event": "proxy.call"}, "limit": 20}'
```

## Update / Remove a Service

```bash
# Update (merge — only changes specified fields)
curl -s http://localhost:8787/vault.admin.updateService \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"service": "github", "allowedAgents": ["tony", "steve", "jarvis", "bruce"]}'

# Remove entirely
curl -s http://localhost:8787/vault.admin.removeService \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"service": "github"}'
```

## Security Rules

- **NEVER** log, print, or return master secrets — they stay in the vault
- **NEVER** write API keys to files outside the vault's encrypted store
- **NEVER** pass API keys in chat messages — use the vault API only
- Short TTL tokens (60s–600s) — don't request more than you need
- Revoke sessions/tokens when tasks are done
- All operations are audit-logged automatically
