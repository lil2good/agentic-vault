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
node --env-file=.env src/server.js
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

## Security notes

- Tokens are audience-bound (`aud`) and context-bound.
- Policy is deny-by-default; only allowlisted actions are executable.
- Master secrets stay server-side (`MASTER_SECRETS_JSON` / backend secret manager adapter).
- Use short TTL (5–15m). For risky actions, add single-use (`jti` spend-check) in next iteration.
