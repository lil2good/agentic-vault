/**
 * Vault Server Manager
 *
 * Spawns and manages the vault Express server as a child process.
 * The actual server code lives in the parent agentic-credential-vault package.
 */
import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";

let serverProcess: ChildProcess | null = null;

function findVaultEntrypoint(): string {
  // The vault server lives in the parent directory (../src/vault.js)
  const candidates = [
    // Installed as part of this repo
    path.resolve(import.meta.dirname, "..", "..", "src", "vault.js"),
    // Installed as a dependency
    path.resolve(import.meta.dirname, "..", "node_modules", "agentic-credential-vault", "src", "vault.js"),
    // Common dev locations
    path.resolve(process.env.HOME || "~", "projects", "agentic-credential-vault", "src", "vault.js"),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }

  throw new Error(
    `Cannot find vault server entrypoint. Searched:\n${candidates.join("\n")}\n` +
    `Clone the repo or install agentic-credential-vault.`
  );
}

function resolveDataDir(dataDir?: string): string {
  const dir = dataDir || path.resolve(process.env.HOME || "~", ".openclaw", "vault-data");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function ensureKey(dataDir: string, filename: string): string {
  const keyFile = path.join(dataDir, filename);
  if (fs.existsSync(keyFile)) {
    return fs.readFileSync(keyFile, "utf8").trim();
  }
  const key = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(keyFile, key, { mode: 0o600 });
  return key;
}

export async function startVaultServer(opts: {
  port: number;
  dataDir?: string;
  logger: { info: Function; error: Function; warn: Function };
}): Promise<void> {
  const { port, logger } = opts;

  if (serverProcess && !serverProcess.killed) {
    logger.info("[vault] Server already running");
    return;
  }

  const entrypoint = findVaultEntrypoint();
  const dataDir = resolveDataDir(opts.dataDir);
  const signingKey = ensureKey(dataDir, ".vault-signing-key");
  const adminToken = ensureKey(dataDir, ".vault-admin-token");
  const policyPath = path.resolve(path.dirname(entrypoint), "..", "config", "policy.json");

  logger.info(`[vault] Starting server: ${entrypoint} on port ${port}`);
  logger.info(`[vault] Data dir: ${dataDir}`);
  logger.info(`[vault] Admin token: ${path.join(dataDir, ".vault-admin-token")}`);

  const env: Record<string, string> = {
    ...process.env as Record<string, string>,
    PORT: String(port),
    VAULT_SIGNING_KEY: signingKey,
    VAULT_ADMIN_TOKEN: adminToken,
    VAULT_DATA_DIR: dataDir,
    VAULT_POLICY_PATH: policyPath,
    VAULT_AUDIENCE: "agentic-credential-vault-proxy",
  };

  serverProcess = spawn("node", [entrypoint], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
    detached: false,
  });

  serverProcess.stdout?.on("data", (chunk: Buffer) => {
    logger.info(`[vault] ${chunk.toString().trim()}`);
  });

  serverProcess.stderr?.on("data", (chunk: Buffer) => {
    logger.error(`[vault] ${chunk.toString().trim()}`);
  });

  serverProcess.on("exit", (code) => {
    logger.warn(`[vault] Server exited with code ${code}`);
    serverProcess = null;
  });

  // Wait for health check
  const maxWait = 5000;
  const start = Date.now();
  while (Date.now() - start < maxWait) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) {
        logger.info(`[vault] Server healthy on port ${port}`);
        return;
      }
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  logger.warn("[vault] Server started but health check timed out — may still be booting");
}

export function stopVaultServer(logger: { info: Function }) {
  if (serverProcess && !serverProcess.killed) {
    logger.info("[vault] Stopping vault server");
    serverProcess.kill("SIGTERM");
    serverProcess = null;
  }
}

export function getVaultStatus(): { running: boolean; pid?: number } {
  if (serverProcess && !serverProcess.killed) {
    return { running: true, pid: serverProcess.pid };
  }
  return { running: false };
}
