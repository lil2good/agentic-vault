# Agentic Credential Vault

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen)](#)

# Agentic Credential Vault

Per-agent scoped API credentials with JIT tokens, proxy enforcement, and audit logging for AI agents.

Agents never see your API keys. They get short-lived, scoped tokens. The vault proxies the actual API call with the real secret server-side.

```
Agent → vault.issueToken (scoped token) → vault.call (vault adds secret) → GitHub/Shopify/etc
```

## Install

```bash
# As an OpenClaw skill (recommended)
git clone https://github.com/lil2good/agentic-credential-vault ~/.openclaw/skills/agentic-credential-vault
cd ~/.openclaw/skills/agentic-credential-vault
npm install
```

Then tell your agent: **"Set up the credential vault"** — it reads `SKILL.md` and handles the rest.

### Manual setup

```bash
# Generate secure keys
cat > .env <<EOF
PORT=8787
VAULT_SIGNING_KEY=$(openssl rand -hex 32)
VAULT_ADMIN_TOKEN=$(openssl rand -hex 24)
VAULT_AUDIENCE=agentic-credential-vault-proxy
VAULT_DATA_DIR=./data
EOF

# Start
pm2 start "node --env-file=.env src/vault.js" --name vault --cwd "$(pwd)"
# or: node --env-file=.env src/vault.js

# Verify
curl -s http://localhost:8787/health   # → {"ok":true}
```

## CLI: agentvault

A portable bash + curl + jq helper. No node dependency.

```bash
# Install (symlink to PATH)
ln -sf ~/.openclaw/skills/agentic-credential-vault/agentvault ~/bin/agentvault

# Use it
agentvault health
agentvault services
agentvault token github github:repos:read
agentvault call github repo.get --token "$TOKEN" --json '{"owner":"lil2good","repo":"my-repo"}'
agentvault revoke --agent tony --reason "done"
agentvault audit --limit 10
```

Or source in scripts:

```bash
source ~/.openclaw/skills/agentic-credential-vault/agentvault.sh
TOKEN=$(agentvault_token github github:repos:read)
agentvault_call "$TOKEN" github repo.get '{"owner":"lil2good","repo":"my-repo"}'
```

## Service Management

Each service is a JSON file in `config/services/`:

```
config/services/
├── github.json
├── shopify.json
└── my-custom-api.json
```

### Add from a built-in template

Templates: `github`, `stripe`, `shopify`, `openai`, `anthropic`

```bash
curl -s http://localhost:8787/vault.admin.loadTemplate \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"template":"github","masterSecret":"ghp_xxx","allowedAgents":["main","tony"]}'
```

### Add a custom service

```bash
curl -s http://localhost:8787/vault.admin.addService \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
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
        "path": "/data/{id}",
        "requiredScope": ["myapi:data:read"]
      }
    },
    "secretRef": "myapi_key",
    "masterSecret": "sk-xxx"
  }'
```

Path params like `{id}` are interpolated from the `params` object. Remaining params become query string (GET) or JSON body (POST).

## API Reference

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | — | Health check |
| `POST /vault.issueToken` | — | Issue a scoped, short-lived token |
| `POST /vault.call` | token | Proxy an API call (vault adds the real secret) |
| `POST /vault.revoke` | — | Revoke by token/session/task/agent |
| `POST /vault.audit.query` | — | Query the audit log |
| `POST /vault.admin.listTemplates` | admin | List available service templates |
| `POST /vault.admin.loadTemplate` | admin | Load a template + store secret |
| `POST /vault.admin.addService` | admin | Add a custom service |
| `POST /vault.admin.updateService` | admin | Update service config (merge) |
| `POST /vault.admin.removeService` | admin | Remove a service + its secret |
| `POST /vault.admin.listServices` | admin | List all configured services |
| `POST /vault.admin.addSecret` | admin | Store an encrypted secret |
| `POST /vault.admin.removeSecret` | admin | Remove a secret |

## How It Works

1. **Admin configures a service** — API key goes into encrypted storage, endpoints/scopes defined in `config/services/<name>.json`
2. **Agent requests a token** — `vault.issueToken` with service + scopes + agentId. Token is JWT, short-lived (max 15min), audience-bound
3. **Agent makes a call** — `vault.call` with the token. Vault verifies the token, checks scopes, interpolates path params, attaches the real secret, proxies to upstream
4. **Everything is logged** — append-only audit trail in `data/audit.log.jsonl`
5. **Kill switch** — revoke by token, session, task, or agent at any time

## Security

- **Deny-by-default** — only allowlisted actions + scopes + agents can issue tokens
- **Master secrets never leave the vault** — encrypted at rest, injected server-side on proxy
- **Short-lived tokens** — 60s–600s, max 900s
- **Context-bound** — tokens are tied to agentId, sessionId, taskId
- **Audit everything** — every token issue, proxy call, and revocation is logged
- **Atomic writes** — config and revocation files use write-tmp-then-rename

## Requirements

- Node.js 20+ (for `--env-file` support)
- npm
- jq (for the CLI helper only)

## License

Private — not yet published.