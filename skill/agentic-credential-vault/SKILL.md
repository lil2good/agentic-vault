---
name: agentic-credential-vault
description: Issue and enforce short-lived, scoped credentials for AI agents with per-agent/session/task identity binding, proxy-mode secret isolation, revocation, and audit trails. Use when replacing shared API keys with least-privilege secret access in OpenClaw skills.
---

# Agentic Credential Vault Skill

Use this skill to replace raw `API_KEY` usage with scoped capability calls.

## Setup

1. Run the vault service.
2. Configure `config/policy.json` with service/action allowlists.
3. Store master secrets in backend env/secret manager (not in prompts).

## Tool contracts

### `vault.issueToken({service, scope, ttl, sessionId, taskId, skillId, agentId, tool})`

- Return short-lived token scoped to `service+scope`.
- Enforce max TTL (default 10m, max 15m).

### `vault.call({token, service, action, params, context})`

- Validate token + context binding (`agentId/sessionId/taskId/skillId`).
- Enforce deny-by-default action policy.
- Attach upstream master secret server-side.
- Write audit event with full attribution tuple.

### `vault.revoke({tokenId|sessionId|taskId|agentId})`

- Revoke instantly via denylist/kill switch.

### `vault.audit.query({filters, limit})`

- Query append-only log for incident response and compliance.

## Recommended policy defaults

- Deny by default
- Explicit service/action allowlist
- Per-agent service access
- Per-action rate limits (add in next iteration)

## Migration pattern for existing skills

- Before: `callThirdParty({ apiKey: process.env.X_API_KEY })`
- After: `vault.call({ service: 'x', action: 'allowedAction', params, context })`

Never expose master API keys to LLM context.
