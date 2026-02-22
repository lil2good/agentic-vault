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

The skill directory IS the vault server. No separate clone needed.

```bash
# Find this skill's directory (where this SKILL.md lives)
VAULT_DIR="$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")"
# Fallback: search common locations
for d in ~/.openclaw/skills/agentic-credential-vault ~/openclaw/skills/agentic-credential-vault; do
  [ -f "$d/src/vault.js" ] && VAULT_DIR="$d" && break
done
cd "$VAULT_DIR"

# 1. Install dependencies (one time)
npm install

# 2. Auto-generate secure .env if it doesn't exist
if [ ! -f .env ]; then
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
fi

# 3. Start the vault with pm2 (recommended — survives reboots)
# pm2 doesn't support --env-file, so use an ecosystem config:
cat > ecosystem.config.cjs <<ECOEOF
module.exports = {
  apps: [{
    name: 'vault',
    script: 'src/vault.js',
    cwd: '$(pwd)',
    env: $(node -e "const fs=require('fs'); const lines=fs.readFileSync('.env','utf8').split('\n').filter(l=>l&&!l.startsWith('#')); const o={}; lines.forEach(l=>{const [k,...v]=l.split('=');o[k]=v.join('=')}); console.log(JSON.stringify(o,null,6))")
  }]
};
ECOEOF
pm2 start ecosystem.config.cjs
pm2 save
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

If `VAULT_DOWN`, find the skill directory and start it:
```bash
for d in ~/.openclaw/skills/agentic-credential-vault ~/openclaw/skills/agentic-credential-vault; do
  [ -f "$d/src/vault.js" ] && cd "$d" && break
done
pm2 start src/vault.js --name vault --env-file .env 2>/dev/null || node --env-file=.env src/vault.js &
sleep 1
curl -s http://localhost:8787/health
```

## Read Admin Token

All admin operations need the admin token from `.env`:
```bash
for d in ~/.openclaw/skills/agentic-credential-vault ~/openclaw/skills/agentic-credential-vault; do
  [ -f "$d/.env" ] && ADMIN_TOKEN=$(grep VAULT_ADMIN_TOKEN "$d/.env" | cut -d= -f2) && break
done
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

Minimal (single-agent setup — agentId defaults to "main"):
```bash
curl -s http://localhost:8787/vault.issueToken \
  -H 'content-type: application/json' \
  -d '{"service": "github", "scope": ["github:repos:read"]}'
```

Multi-agent (specify which agent):
```bash
curl -s http://localhost:8787/vault.issueToken \
  -H 'content-type: application/json' \
  -d '{
    "service": "github",
    "scope": ["github:repos:read"],
    "ttl": 60,
    "agentId": "coder"
  }'
```

Optional fields: `sessionId`, `taskId`, `skillId`, `tool` — auto-generated if omitted. Pass them for stricter audit/binding in multi-agent setups.

Returns: `{ tokenId, token, expiresInSec }`

### Step 2: Proxy the API call

```bash
curl -s http://localhost:8787/vault.call \
  -H 'content-type: application/json' \
  -d '{
    "token": "<TOKEN_FROM_STEP_1>",
    "service": "github",
    "action": "repos.get",
    "params": {}
  }'
```

Context fields (`agentId`, `sessionId`, etc.) are optional on `vault.call` too — they default to match the token if omitted.

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

## Shell Helper (agentvault)

Instead of raw curl commands, use the `agentvault` CLI or source the helper in scripts.

### Installation

```bash
# Symlink to somewhere on your PATH (requires jq)
mkdir -p ~/bin
ln -sf ~/.openclaw/skills/agentic-credential-vault/agentvault ~/bin/agentvault

# Add ~/bin to PATH if not already there
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Install jq if needed (no sudo required)
curl -sL https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64 -o ~/bin/jq
chmod +x ~/bin/jq
```

### Terminal Usage

```bash
# Check vault status
agentvault health

# Issue a scoped token
agentvault token github github:repos:read

# Proxy an API call (pass token explicitly)
TOKEN=$(agentvault token github github:repos:read)
agentvault call github repos.get --token "$TOKEN"

# Or pipe the token
agentvault token github github:repos:read | agentvault call github repos.get

# List configured services
agentvault services

# Revoke tokens for an agent
agentvault revoke --agent tony --reason "task complete"

# Query audit log
agentvault audit --limit 10 --event proxy.call
```

### Script Usage

```bash
source ~/.openclaw/skills/agentic-credential-vault/agentvault.sh

# Issue a token (returns just the token string)
TOKEN="$(agentvault_token github github:repos:read)"

# Make a proxied API call
agentvault_call "$TOKEN" github repos.get

# With a JSON payload
agentvault_call "$TOKEN" github repo.get '{"owner":"lil2good","repo":"my-repo"}'

# Check vault health
agentvault_health

# List services (requires admin token)
agentvault_services
```

### Available GitHub Actions

| Action | Method | Scopes | Path Params |
|--------|--------|--------|-------------|
| `repos.list` | GET | `github:repos:read` | — |
| `repo.get` | GET | `github:repos:read` | owner, repo |
| `contents.get` | GET | `github:repos:read` | owner, repo, path |
| `contents.create_or_update` | PUT | `github:repos:write` | owner, repo, path |
| `branches.list` | GET | `github:repos:read` | owner, repo |
| `branches.get` | GET | `github:repos:read` | owner, repo, branch |
| `refs.get` | GET | `github:git:read` | owner, repo, branch |
| `refs.create` | POST | `github:git:write` | owner, repo |
| `refs.update` | PATCH | `github:git:write` | owner, repo, branch |
| `commits.list` | GET | `github:git:read` | owner, repo |
| `commits.get` | GET | `github:git:read` | owner, repo, sha |
| `blobs.create` | POST | `github:git:write` | owner, repo |
| `trees.create` | POST | `github:git:write` | owner, repo |
| `git_commits.create` | POST | `github:git:write` | owner, repo |
| `issues.list` | GET | `github:issues:read` | owner, repo |
| `issues.get` | GET | `github:issues:read` | owner, repo, issue_number |
| `issues.create` | POST | `github:issues:write` | owner, repo |
| `pulls.list` | GET | `github:prs:read` | owner, repo |
| `pulls.get` | GET | `github:prs:read` | owner, repo, pull_number |
| `pulls.create` | POST | `github:prs:write` | owner, repo |
| `pulls.merge` | PUT | `github:prs:write` | owner, repo, pull_number |
| `pulls.files` | GET | `github:prs:read` | owner, repo, pull_number |

### Common Workflow: Push Files

```bash
source ~/.openclaw/skills/agentic-credential-vault/agentvault.sh
TOKEN=$(agentvault_token github github:git:read github:git:write)

# 1. Get branch SHA
REF=$(agentvault_call "$TOKEN" github refs.get '{"owner":"O","repo":"R","branch":"main"}')
SHA=$(echo "$REF" | jq -r '.object.sha')

# 2. Get base tree
COMMIT=$(agentvault_call "$TOKEN" github commits.get "{\"owner\":\"O\",\"repo\":\"R\",\"sha\":\"$SHA\"}")
TREE=$(echo "$COMMIT" | jq -r '.tree.sha')

# 3. Create blob → tree → commit → update ref
BLOB=$(agentvault_call "$TOKEN" github blobs.create '{"owner":"O","repo":"R","content":"hello","encoding":"utf-8"}')
# ... (see ~/.openclaw/skills/github/SKILL.md for full workflow)
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_URL` | `http://127.0.0.1:8787` | Vault server URL |
| `VAULT_ADMIN_TOKEN` | (auto-read from .env) | Admin token for service management |
| `AGENTVAULT_AGENT_ID` | `main` | Agent identity for token requests |
| `AGENTVAULT_TTL` | `300` | Token TTL in seconds |
| `AGENTVAULT_DIR` | (auto-detected) | Skill directory override |
