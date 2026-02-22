import type {
  AnyAgentTool,
  OpenClawPluginApi,
  OpenClawPluginToolFactory,
} from "openclaw/plugin-sdk";
import { createVaultTools } from "./src/vault-tools.js";
import { startVaultServer, stopVaultServer, getVaultStatus } from "./src/vault-server.js";

interface VaultConfig {
  port?: number;
  autoStart?: boolean;
  dataDir?: string;
}

export default function register(api: OpenClawPluginApi) {
  const logger = api.logger;
  const cfg = api.config.plugins?.entries?.["vault"]?.config as VaultConfig | undefined;
  const port = cfg?.port || 8787;
  const autoStart = cfg?.autoStart !== false; // default true
  const dataDir = cfg?.dataDir || undefined;

  logger.info(`[vault] Registering credential vault plugin (port: ${port}, autoStart: ${autoStart})`);

  // Register agent tools: vault_issue_token, vault_call, vault_revoke, vault_admin
  const tools = createVaultTools({ port, logger });
  for (const toolFactory of tools) {
    api.registerTool(
      ((ctx) => {
        if (ctx.sandboxed) return null; // vault tools need network access
        return toolFactory(ctx) as AnyAgentTool;
      }) as OpenClawPluginToolFactory,
      { optional: true },
    );
  }

  // Auto-start vault server with the gateway
  if (autoStart) {
    logger.info("[vault] Auto-starting vault server...");
    startVaultServer({ port, dataDir, logger }).catch((err) => {
      logger.error(`[vault] Failed to start vault server: ${err.message}`);
    });

    // Graceful shutdown
    const cleanup = () => {
      stopVaultServer(logger);
    };
    process.on("SIGINT", cleanup);
    process.on("SIGTERM", cleanup);
  }
}
