# Agentic Credential Vault

Per-agent scoped secrets with least-privilege identity for AI agents.

## What this MVP ships

- Stable principal context: `{agentId, sessionId, taskId, skillId, tool}`
- JIT token issuance: `POST /vault.issueToken`
- Proxy call mode: `POST /vault.call` (master secret never exposed to the agent)
- Revocation kill switches: token/session/task/agent
- Append-only audit log (`data/audit.log.jsonl`)

## Quick start

```bash
cp .env.example .env
npm install
node --env-file=.env src/vault.js
```

## API

### issue token
```bash
curl -s http://localhost:8787/vault.issueToken -H 'content-type: application/json' -d '{
  "service":"github",
  "scope":["repos:read"],
  "ttl":600,
  "agentId":"tony",
  "sessionId":"sess-123",
  "taskId":"task-abc",
  "skillId":"github-read",
  "tool":"vault.issueToken"
}'
```

### proxy call
```bash
curl -s http://localhost:8787/vault.call -H 'content-type: application/json' -d '{
  "token":"<issued-token>",
  "service":"github",
  "action":"repos.get",
  "params":{},
  "context":{
    "agentId":"tony",
    "sessionId":"sess-123",
    "taskId":"task-abc",
    "skillId":"github-read",
    "tool":"vault.call"
  }
}'
```

### revoke
```bash
curl -s http://localhost:8787/vault.revoke -H 'content-type: application/json' -d '{"sessionId":"sess-123"}'
```

### audit query
```bash
curl -s http://localhost:8787/vault.audit.query -H 'content-type: application/json' -d '{"filters":{"event":"proxy.call"},"limit":20}'
```

## Admin API (conversational configuration)

All admin endpoints require:

```bash
-H "Authorization: Bearer $VAULT_ADMIN_TOKEN"
```

### 1) List available templates
```bash
curl -s http://localhost:8787/vault.admin.listTemplates \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{}'
```

### 2) Load a template and set its master secret
```bash
curl -s http://localhost:8787/vault.admin.loadTemplate \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "template":"github",
    "masterSecret":"ghp_xxx",
    "allowedAgents":["tony","steve"]
  }'
```

### 3) Add a custom service
```bash
curl -s http://localhost:8787/vault.admin.addService \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "service":"custom-api",
    "baseUrl":"https://api.example.com",
    "allowedAgents":["tony"],
    "allowedActions":["issue","data.get"],
    "allowedScopes":["custom:data:read"],
    "endpoints":{
      "data.get":{
        "method":"GET",
        "path":"/data",
        "requiredScope":["custom:data:read"]
      }
    }
  }'
```

### 4) List configured services
```bash
curl -s http://localhost:8787/vault.admin.listServices \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{}'
```

## Security notes

- Tokens are audience-bound (`aud`) and context-bound.
- Policy is deny-by-default; only allowlisted actions are executable.
- Master secrets stay server-side in encrypted storage (`data/secrets.enc` via `VAULT_ENCRYPTION_KEY`).
- Use short TTL (5–15m). For risky actions, add single-use (`jti` spend-check) in next iteration.


## MVP runtime constraints

- `revocations.json` is designed for **single-process MVP** operation.
- Writes are atomic (`write tmp + rename`) but there is no cross-process lock.
- For multi-instance deployment, move revocation storage to SQLite/Postgres/Redis with transactional updates.
- Server fails fast at startup if `VAULT_SIGNING_KEY` is missing or `MASTER_SECRETS_JSON` is invalid JSON.
- Scope is mandatory on token issuance and enforced per endpoint via `requiredScope`.
