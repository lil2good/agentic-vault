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

## Architecture

```
┌─────────────┐     issueToken     ┌───────────────┐     proxy call     ┌──────────────┐
│   Agent     │ ──────────────────▶ │    Vault      │ ──────────────────▶│  GitHub /    │
│ (tony/steve)│ ◀────── token ──── │ localhost:8787 │ ◀── response ──── │  Shopify /   │
│             │ ── vault.call ───▶ │               │    (adds secret)   │  OpenAI etc  │
└─────────────┘                    └───────────────┘                    └──────────────┘
                                         │
                                   config/services/
                                   ├── github.json    ← one file per service
                                   ├── shopify.json
                                   └── openai.json
```

Each service lives in its own JSON file under `config/services/`. Add a service = drop a file. Remove = delete it.

---

## First-Time Setup

```bash
cd ~/.openclaw/skills/agentic-credential-vault

# 1. Install dependencies
npm install

# 2. Generate secure .env
if [ ! -f .env ]; then
  cat > .env <<EOF
PORT=8787
VAULT_SIGNING_KEY=$(openssl rand -hex 32)
VAULT_ADMIN_TOKEN=$(openssl rand -hex 24)
VAULT_AUDIENCE=agentic-credential-vault-proxy
VAULT_DATA_DIR=./data
EOF
fi

# 3. Start with pm2
pm2 start "node --env-file=.env src/vault.js" --name vault --cwd "$(pwd)"
pm2 save

# 4. Verify
curl -s http://localhost:8787/health   # → {"ok":true}
```

### Install the CLI

```bash
mkdir -p ~/bin
ln -sf ~/.openclaw/skills/agentic-credential-vault/agentvault ~/bin/agentvault
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc

# jq is required (install without sudo if needed)
command -v jq || { curl -sL https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64 -o ~/bin/jq && chmod +x ~/bin/jq; }
```

---

## Service Management

### How services are stored

Each service is a JSON file in `config/services/`:

```
config/services/
├── github.json       ← endpoints, scopes, allowedAgents
├── shopify.json
└── my-custom-api.json
```

A service file looks like this:

```json
{
  "baseUrl": "https://api.github.com",
  "secretRef": "github_pat",
  "allowedAgents": ["main", "tony", "steve"],
  "allowedActions": ["issue", "repo.get", "pulls.list"],
  "allowedScopes": ["github:repos:read", "github:repos:write", "github:prs:read", "github:prs:write"],
  "agentScopes": {
    "steve": ["github:repos:read", "github:prs:read"]
  },
  "endpoints": {
    "repo.get": {
      "method": "GET",
      "path": "/repos/{owner}/{repo}",
      "requiredScope": ["github:repos:read"]
    }
  }
}
```

Path params like `{owner}` and `{repo}` are interpolated from the `params` object at call time. Remaining params become query string (GET) or JSON body (POST/PUT/PATCH).

### Per-Agent Scope Restrictions (`agentScopes`)

Optional. Narrows `allowedScopes` for specific agents. Agents **not** listed in `agentScopes` get access to the full `allowedScopes` set (backward compatible).

```json
{
  "allowedAgents": ["main", "tony", "steve"],
  "allowedScopes": ["github:repos:read", "github:repos:write", "github:prs:read", "github:prs:write"],
  "agentScopes": {
    "steve": ["github:repos:read", "github:prs:read"]
  }
}
```

In the example above:
- **main** and **tony** can request any of the four scopes
- **steve** can only request `github:repos:read` and `github:prs:read` — requesting `github:repos:write` returns `INSUFFICIENT_SCOPE`

Set via `vault.admin.addService`, `vault.admin.updateService`, or directly in the service JSON file.

### Add a service from a template

Built-in templates: `github`, `stripe`, `shopify`, `openai`, `anthropic`

```bash
agentvault services   # see what's already configured

# Load a template (creates config/services/<name>.json + stores the secret)
ADMIN_TOKEN=$(grep VAULT_ADMIN_TOKEN .env | cut -d= -f2)
curl -s http://localhost:8787/vault.admin.loadTemplate \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "template": "github",
    "masterSecret": "<USER_API_KEY>",
    "allowedAgents": ["main", "tony", "steve", "bruce"]
  }'
```

### Add a custom service

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
        "path": "/data/{id}",
        "requiredScope": ["myapi:data:read"]
      }
    },
    "secretRef": "myapi_key",
    "masterSecret": "<API_KEY>"
  }'
```

This creates `config/services/my-api.json` and encrypts the secret.

### Update / Remove

```bash
# Update (merges — only changes specified fields)
curl -s http://localhost:8787/vault.admin.updateService \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"service": "github", "allowedAgents": ["main", "tony", "steve", "bruce", "jarvis"]}'

# Remove entirely (deletes the service file + secret)
curl -s http://localhost:8787/vault.admin.removeService \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"service": "my-api"}'
```

**Important:** Ask the user for API keys. Never generate or guess them. Store them ONLY via the vault API.

---

## Using the Vault (agentvault CLI)

### Quick reference

```bash
agentvault health                          # check vault status
agentvault services                        # list configured services
agentvault token <svc> <scope...>          # issue a scoped token
agentvault call <svc> <action> [options]   # proxy an API call
agentvault revoke [--agent|--session <id>] # revoke tokens
agentvault audit [--limit N]              # query audit log
```

### Issue a token + make a call

```bash
# Get a read-only GitHub token
TOKEN=$(agentvault token github github:repos:read)

# Use it
agentvault call github repo.get --token "$TOKEN" --json '{"owner":"OWNER","repo":"REPO"}'

# Or pipe
agentvault token github github:repos:read | agentvault call github repo.get --json '{"owner":"OWNER","repo":"REPO"}'
```

### From scripts (source the helper)

```bash
source ~/.openclaw/skills/agentic-credential-vault/agentvault.sh

TOKEN=$(agentvault_token github github:repos:read github:prs:read)
agentvault_call "$TOKEN" github repo.get '{"owner":"OWNER","repo":"REPO"}'
agentvault_call "$TOKEN" github pulls.list '{"owner":"OWNER","repo":"REPO"}'
```

---

## GitHub Actions Reference

The built-in GitHub template provides 22 endpoints:

| Action | Method | Scopes | Path Params |
|--------|--------|--------|-------------|
| `repos.list` | GET | `repos:read` | — |
| `repo.get` | GET | `repos:read` | owner, repo |
| `contents.get` | GET | `repos:read` | owner, repo, path |
| `contents.create_or_update` | PUT | `repos:write` | owner, repo, path |
| `branches.list` | GET | `repos:read` | owner, repo |
| `branches.get` | GET | `repos:read` | owner, repo, branch |
| `refs.get` | GET | `git:read` | owner, repo, branch |
| `refs.create` | POST | `git:write` | owner, repo |
| `refs.update` | PATCH | `git:write` | owner, repo, branch |
| `commits.list` | GET | `git:read` | owner, repo |
| `commits.get` | GET | `git:read` | owner, repo, sha |
| `blobs.create` | POST | `git:write` | owner, repo |
| `trees.create` | POST | `git:write` | owner, repo |
| `git_commits.create` | POST | `git:write` | owner, repo |
| `issues.list` | GET | `issues:read` | owner, repo |
| `issues.get` | GET | `issues:read` | owner, repo, issue_number |
| `issues.create` | POST | `issues:write` | owner, repo |
| `pulls.list` | GET | `prs:read` | owner, repo |
| `pulls.get` | GET | `prs:read` | owner, repo, pull_number |
| `pulls.create` | POST | `prs:write` | owner, repo |
| `pulls.merge` | PUT | `prs:write` | owner, repo, pull_number |
| `pulls.files` | GET | `prs:read` | owner, repo, pull_number |

All scopes are prefixed `github:` (e.g. `github:repos:read`).

### Push files workflow

```bash
source ~/.openclaw/skills/agentic-credential-vault/agentvault.sh
TOKEN=$(agentvault_token github github:git:read github:git:write)

O="OWNER"; R="REPO"; B="feature/my-branch"

# 1. Get branch SHA
SHA=$(agentvault_call "$TOKEN" github refs.get "{\"owner\":\"$O\",\"repo\":\"$R\",\"branch\":\"$B\"}" | jq -r '.object.sha')

# 2. Get base tree
TREE=$(agentvault_call "$TOKEN" github commits.get "{\"owner\":\"$O\",\"repo\":\"$R\",\"sha\":\"$SHA\"}" | jq -r '.tree.sha')

# 3. Create blob
BLOB=$(agentvault_call "$TOKEN" github blobs.create "{\"owner\":\"$O\",\"repo\":\"$R\",\"content\":\"hello world\",\"encoding\":\"utf-8\"}" | jq -r '.sha')

# 4. Create tree
NEW_TREE=$(agentvault_call "$TOKEN" github trees.create "{\"owner\":\"$O\",\"repo\":\"$R\",\"base_tree\":\"$TREE\",\"tree\":[{\"path\":\"file.txt\",\"mode\":\"100644\",\"type\":\"blob\",\"sha\":\"$BLOB\"}]}" | jq -r '.sha')

# 5. Create commit
COMMIT=$(agentvault_call "$TOKEN" github git_commits.create "{\"owner\":\"$O\",\"repo\":\"$R\",\"message\":\"add file.txt\",\"tree\":\"$NEW_TREE\",\"parents\":[\"$SHA\"]}" | jq -r '.sha')

# 6. Update ref
agentvault_call "$TOKEN" github refs.update "{\"owner\":\"$O\",\"repo\":\"$R\",\"branch\":\"$B\",\"sha\":\"$COMMIT\"}"
```

---

## Revocation

```bash
# Revoke all tokens for an agent
agentvault revoke --agent tony --reason "security incident"

# Revoke a session
agentvault revoke --session sess-123 --reason "task complete"

# Revoke a specific token
agentvault revoke --token <tokenId> --reason "expired early"
```

## Audit Log

```bash
# Recent proxy calls
agentvault audit --limit 10 --event proxy.call

# All activity for an agent
agentvault audit --agent tony --limit 50
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_URL` | `http://127.0.0.1:8787` | Vault server URL |
| `VAULT_ADMIN_TOKEN` | (auto-read from .env) | Admin token for service management |
| `AGENTVAULT_AGENT_ID` | `main` | Agent identity for token requests |
| `AGENTVAULT_TTL` | `300` | Token TTL in seconds |
| `AGENTVAULT_DIR` | (auto-detected) | Skill directory override |

## AGENTS.md Integration

Add the following to your `AGENTS.md` (or equivalent agent rules file) to enforce Vault-first credential handling:

```markdown
## Credential Vault — Hard Rules
- **Vault-first for any skill or integration touching an external API. No exceptions.**
- When creating/updating a skill that needs API keys: register credentials in the Vault, issue scoped agent tokens. Never hardcode keys in scripts or references.
- When setting up a new integration: check if the Vault already has a service entry. If not, create one before writing any code.
- Skill creation checklist addition: "Does this skill need external API access? → Register in Vault, declare in SKILL.md."
- Subagents inherit this rule — use Vault-scoped tokens, not raw keys.
```

This ensures every session loads the rule and agents default to the Vault without manual reminders.

---

## Security Rules

- **NEVER** log, print, or return master secrets
- **NEVER** write API keys to files outside the vault's encrypted store
- **NEVER** pass API keys in chat messages — use the vault API only
- Short TTL tokens (60s–600s) — don't request more than you need
- Revoke sessions/tokens when tasks are done
- All operations are audit-logged automatically

