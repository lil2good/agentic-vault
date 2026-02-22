# @openclaw/vault

Per-agent scoped secrets for OpenClaw. Agents get short-lived, context-bound tokens — master API keys never leave the server.

## Install

```bash
openclaw plugins install @openclaw/vault
```

## Quick Start

1. **Enable the plugin** (auto-starts with the gateway):
   ```bash
   openclaw plugins enable vault
   ```

2. **Tell your agent to add a service:**
   > "Add my GitHub PAT to the vault. Only let Tony and Steve use it for reading repos."

3. **Agents use vault tools instead of raw API keys:**
   - `vault_issue_token` → get a scoped token
   - `vault_call` → proxy API call (master secret attached server-side)
   - `vault_revoke` → kill tokens instantly

## Configuration (optional)

In `~/.openclaw/openclaw.json` under `plugins.entries.vault.config`:

```json
{
  "port": 8787,
  "autoStart": true,
  "dataDir": "~/.openclaw/vault-data"
}
```

All settings are optional. Defaults work out of the box.

## How It Works

```
Agent                    Vault Server              Upstream API
  │                          │                          │
  │─── vault_issue_token ───>│                          │
  │<── short-lived JWT ──────│                          │
  │                          │                          │
  │─── vault_call ──────────>│                          │
  │                          │── attaches master key ──>│
  │                          │<── response ─────────────│
  │<── proxied response ─────│                          │
```

The agent never sees the master secret. The token is scoped, context-bound, and expires in minutes.

## Service Templates

Built-in templates for common services:
- **GitHub** — repos, issues, PRs
- **Stripe** — charges, customers
- **Shopify** — orders, products
- **OpenAI** — completions, embeddings
- **Anthropic** — messages

Load via: `vault_admin({ action: "loadTemplate", template: "github", masterSecret: "ghp_..." })`

## License

MIT
