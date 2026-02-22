/**
 * Vault Agent Tools
 *
 * Registers tools that agents can use to interact with the vault:
 * - vault_issue_token: request a scoped, short-lived token
 * - vault_call: proxy an API call through the vault
 * - vault_revoke: revoke a token/session/task
 * - vault_admin: admin operations (add service, load template, etc.) — main agent only
 */

interface VaultToolOpts {
  port: number;
  logger: { info: Function; error: Function };
}

async function vaultFetch(port: number, endpoint: string, body: any, adminToken?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (adminToken) headers["Authorization"] = `Bearer ${adminToken}`;

  const res = await fetch(`http://127.0.0.1:${port}${endpoint}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await res.text();
  try {
    return { status: res.status, data: JSON.parse(text) };
  } catch {
    return { status: res.status, data: text };
  }
}

export function createVaultTools(opts: VaultToolOpts) {
  const { port, logger } = opts;

  const issueTokenTool = (_ctx: any) => ({
    name: "vault_issue_token",
    description:
      "Request a short-lived, scoped API token from the credential vault. " +
      "The token is bound to your agent ID, session, task, and skill. " +
      "Use this instead of raw API keys.",
    parameters: {
      type: "object" as const,
      properties: {
        service: { type: "string", description: "Service name (e.g. 'github', 'stripe', 'openai')" },
        scope: { type: "array", items: { type: "string" }, description: "Requested scopes (e.g. ['github:repos:read'])" },
        ttl: { type: "number", description: "Token TTL in seconds (max 900, default 600)" },
        agentId: { type: "string", description: "Your agent ID" },
        sessionId: { type: "string", description: "Current session ID" },
        taskId: { type: "string", description: "Current task ID" },
        skillId: { type: "string", description: "Current skill ID" },
      },
      required: ["service", "scope", "agentId", "sessionId", "taskId", "skillId"],
    },
    execute: async (params: any) => {
      const result = await vaultFetch(port, "/vault.issueToken", {
        ...params,
        tool: "vault_issue_token",
      });
      if (result.status !== 200) {
        return { error: result.data?.error || "Token issuance failed" };
      }
      return {
        tokenId: result.data.tokenId,
        token: result.data.token,
        expiresInSec: result.data.expiresInSec,
        note: "Use this token with vault_call. It expires in " + result.data.expiresInSec + "s.",
      };
    },
  });

  const callTool = (_ctx: any) => ({
    name: "vault_call",
    description:
      "Proxy an API call through the credential vault. The vault attaches the master secret " +
      "server-side — you never see it. Requires a token from vault_issue_token.",
    parameters: {
      type: "object" as const,
      properties: {
        token: { type: "string", description: "Token from vault_issue_token" },
        service: { type: "string", description: "Service name" },
        action: { type: "string", description: "Action to perform (e.g. 'repos.get')" },
        params: { type: "object", description: "Parameters for the upstream API call" },
        agentId: { type: "string" },
        sessionId: { type: "string" },
        taskId: { type: "string" },
        skillId: { type: "string" },
      },
      required: ["token", "service", "action", "agentId", "sessionId", "taskId", "skillId"],
    },
    execute: async (params: any) => {
      const { token, service, action, params: callParams, ...ctx } = params;
      const result = await vaultFetch(port, "/vault.call", {
        token,
        service,
        action,
        params: callParams || {},
        context: { ...ctx, tool: "vault_call" },
      });
      return result.data;
    },
  });

  const revokeTool = (_ctx: any) => ({
    name: "vault_revoke",
    description:
      "Revoke vault tokens by token ID, session, task, or agent. " +
      "Use for security incidents or when a session/task is complete.",
    parameters: {
      type: "object" as const,
      properties: {
        tokenId: { type: "string", description: "Specific token ID to revoke" },
        sessionId: { type: "string", description: "Revoke all tokens for this session" },
        taskId: { type: "string", description: "Revoke all tokens for this task" },
        agentId: { type: "string", description: "Revoke all tokens for this agent" },
        reason: { type: "string", description: "Reason for revocation" },
      },
    },
    execute: async (params: any) => {
      const result = await vaultFetch(port, "/vault.revoke", params);
      return result.data;
    },
  });

  const adminTool = (_ctx: any) => ({
    name: "vault_admin",
    description:
      "Admin operations for the credential vault. Only the main agent should use this. " +
      "Actions: listTemplates, loadTemplate, addService, updateService, removeService, " +
      "listServices, addSecret, removeSecret.",
    parameters: {
      type: "object" as const,
      properties: {
        action: {
          type: "string",
          enum: [
            "listTemplates", "loadTemplate", "addService", "updateService",
            "removeService", "listServices", "addSecret", "removeSecret",
          ],
          description: "Admin action to perform",
        },
        template: { type: "string", description: "Template name (e.g. 'github', 'stripe')" },
        masterSecret: { type: "string", description: "Master API key/secret for the service" },
        allowedAgents: { type: "array", items: { type: "string" }, description: "Agents allowed to use this service" },
        service: { type: "string", description: "Service name" },
        baseUrl: { type: "string", description: "Base URL for the service API" },
        allowedActions: { type: "array", items: { type: "string" } },
        allowedScopes: { type: "array", items: { type: "string" } },
        endpoints: { type: "object", description: "Endpoint definitions" },
        secretRef: { type: "string", description: "Secret reference name" },
        secret: { type: "string", description: "Secret value" },
      },
      required: ["action"],
    },
    execute: async (params: any) => {
      const { action, ...args } = params;

      // Read admin token from the vault data dir
      const fs = await import("node:fs");
      const path = await import("node:path");
      const dataDir = process.env.VAULT_DATA_DIR ||
        path.resolve(process.env.HOME || "~", ".openclaw", "vault-data");
      const tokenFile = path.join(dataDir, ".vault-admin-token");

      let adminToken = "";
      try {
        adminToken = fs.readFileSync(tokenFile, "utf8").trim();
      } catch {
        return { error: "Admin token not found. Is the vault server running?" };
      }

      const endpointMap: Record<string, string> = {
        listTemplates: "/vault.admin.listTemplates",
        loadTemplate: "/vault.admin.loadTemplate",
        addService: "/vault.admin.addService",
        updateService: "/vault.admin.updateService",
        removeService: "/vault.admin.removeService",
        listServices: "/vault.admin.listServices",
        addSecret: "/vault.admin.addSecret",
        removeSecret: "/vault.admin.removeSecret",
      };

      const endpoint = endpointMap[action];
      if (!endpoint) return { error: `Unknown action: ${action}` };

      const result = await vaultFetch(port, endpoint, args, adminToken);
      return result.data;
    },
  });

  return [issueTokenTool, callTool, revokeTool, adminTool];
}
