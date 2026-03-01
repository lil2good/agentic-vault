import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import {
  initSecrets,
  getSecret,
  setSecret,
  removeSecret,
  listSecretRefs,
} from './secrets.js';

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 8787;
const AUDIENCE = process.env.VAULT_AUDIENCE || 'agentic-credential-vault-proxy';
const DATA_DIR = process.env.VAULT_DATA_DIR || path.resolve('data');
const AUDIT_PATH = path.join(DATA_DIR, 'audit.log.jsonl');
const REVOCATIONS_PATH = path.join(DATA_DIR, 'revocations.json');
const SERVICES_DIR = process.env.VAULT_SERVICES_DIR || path.resolve('config/services');
const TEMPLATE_DIR = path.resolve('config/templates');
const ADMIN_TOKEN = process.env.VAULT_ADMIN_TOKEN || '';

if (!process.env.VAULT_SIGNING_KEY) {
  console.error('FATAL: VAULT_SIGNING_KEY is required. Refusing to start with unsafe default key.');
  process.exit(1);
}
const SIGNING_KEY = process.env.VAULT_SIGNING_KEY;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(SERVICES_DIR, { recursive: true });

if (!fs.existsSync(REVOCATIONS_PATH)) {
  fs.writeFileSync(
    REVOCATIONS_PATH,
    JSON.stringify({ jti: [], sessions: [], tasks: [], agents: [] }, null, 2)
  );
}

const readRevocations = () => JSON.parse(fs.readFileSync(REVOCATIONS_PATH, 'utf8'));
const writeAtomicJson = (targetPath, next) => {
  const tmp = `${targetPath}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(next, null, 2)}\n`);
  fs.renameSync(tmp, targetPath);
};
const writeRevocations = (next) => writeAtomicJson(REVOCATIONS_PATH, next);

// ---------------------------------------------------------------------------
// Service file management — one JSON file per service in config/services/
// ---------------------------------------------------------------------------

function readService(name) {
  const filePath = path.join(SERVICES_DIR, `${name}.json`);
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeService(name, config) {
  writeAtomicJson(path.join(SERVICES_DIR, `${name}.json`), config);
}

function deleteService(name) {
  const filePath = path.join(SERVICES_DIR, `${name}.json`);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
}

function listServices() {
  if (!fs.existsSync(SERVICES_DIR)) return {};
  const services = {};
  for (const file of fs.readdirSync(SERVICES_DIR)) {
    if (!file.endsWith('.json')) continue;
    const name = file.replace(/\.json$/, '');
    try {
      services[name] = JSON.parse(fs.readFileSync(path.join(SERVICES_DIR, file), 'utf8'));
    } catch { /* skip malformed */ }
  }
  return services;
}

// ---------------------------------------------------------------------------
// Legacy migration — move policy.json services into config/services/
// ---------------------------------------------------------------------------

function migrateLegacyPolicy() {
  const legacyPath = process.env.VAULT_POLICY_PATH || path.resolve('config/policy.json');
  if (!fs.existsSync(legacyPath)) return;

  let policy;
  try {
    policy = JSON.parse(fs.readFileSync(legacyPath, 'utf8'));
  } catch { return; }

  const services = policy.services || {};
  let migrated = 0;
  for (const [name, config] of Object.entries(services)) {
    const targetPath = path.join(SERVICES_DIR, `${name}.json`);
    if (!fs.existsSync(targetPath)) {
      writeAtomicJson(targetPath, config);
      migrated++;
    }
  }

  if (migrated > 0) {
    const backupPath = legacyPath.replace('.json', '.migrated.json');
    fs.renameSync(legacyPath, backupPath);
    console.log(`Migrated ${migrated} service(s) from policy.json → config/services/. Backup: ${backupPath}`);
  } else {
    // All services already exist as files — safe to remove legacy
    const backupPath = legacyPath.replace('.json', '.migrated.json');
    fs.renameSync(legacyPath, backupPath);
    console.log(`Legacy policy.json backed up to ${backupPath} (all services already in config/services/)`);
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function redactSensitive(value) {
  const SENSITIVE_KEYS = new Set([
    'token',
    'authorization',
    'auth',
    'apiKey',
    'apikey',
    'accessToken',
    'refreshToken',
    'master_secrets_json',
    'masterSecrets',
    'masterSecret',
    'secret',
  ]);

  if (Array.isArray(value)) {
    return value.map((item) => redactSensitive(item));
  }

  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      const key = String(k);
      if (SENSITIVE_KEYS.has(key) || /token|secret|auth|api[-_]?key/i.test(key)) {
        out[key] = '[REDACTED]';
      } else {
        out[key] = redactSensitive(v);
      }
    }
    return out;
  }

  return value;
}

function appendAudit(event, context = {}) {
  const line = JSON.stringify({ ts: Date.now(), event, ...context });
  fs.appendFileSync(AUDIT_PATH, `${line}\n`);
}

initSecrets({ dataDir: DATA_DIR, appendAudit });

function migrateMasterSecretsFromEnv() {
  if (!process.env.MASTER_SECRETS_JSON) return;

  let parsed;
  try {
    parsed = JSON.parse(process.env.MASTER_SECRETS_JSON);
  } catch (error) {
    console.error('FATAL: MASTER_SECRETS_JSON is invalid JSON.');
    console.error(error.message);
    process.exit(1);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    console.error('FATAL: MASTER_SECRETS_JSON must be an object of { secretRef: secret }.');
    process.exit(1);
  }

  const refs = Object.keys(parsed);
  for (const [ref, secret] of Object.entries(parsed)) {
    if (typeof secret === 'string' && secret.trim()) {
      setSecret(ref, secret);
    }
  }
  appendAudit('secret.migrated.from_env', { refs });
  console.warn('WARNING: MASTER_SECRETS_JSON was migrated into encrypted storage. Remove MASTER_SECRETS_JSON from env.');
}

migrateMasterSecretsFromEnv();
migrateLegacyPolicy();

function requireContext(input = {}) {
  if (!input.agentId) input.agentId = 'main';
  if (!input.sessionId) input.sessionId = `auto-${crypto.randomUUID().slice(0, 8)}`;
  if (!input.taskId) input.taskId = `auto-${crypto.randomUUID().slice(0, 8)}`;
  if (!input.skillId) input.skillId = 'default';
  if (!input.tool) input.tool = 'vault';
  return input;
}

function isActionAllowed(serviceConfig, action, agentId) {
  if (!serviceConfig) return false;
  const allowedActions = serviceConfig.allowedActions || [];
  const allowedAgents = serviceConfig.allowedAgents || [];
  return (
    allowedActions.includes(action) &&
    (allowedAgents.includes('*') || allowedAgents.includes(agentId))
  );
}

function validateScope(serviceConfig, requestedScope = [], agentId = null) {
  const allowedScopes = serviceConfig.allowedScopes || [];
  const requested = Array.isArray(requestedScope) ? requestedScope : [];
  if (requested.length === 0) throw new Error('SCOPE_REQUIRED');
  if (allowedScopes.length === 0) throw new Error('SERVICE_ALLOWED_SCOPES_NOT_CONFIGURED');
  const invalid = requested.filter((s) => !allowedScopes.includes(s));
  if (invalid.length > 0) throw new Error(`INVALID_SCOPE:${invalid.join(',')}`);

  // Per-agent scope restrictions
  const agentScopes = serviceConfig.agentScopes;
  if (agentId && agentScopes && typeof agentScopes === 'object' && agentId in agentScopes) {
    const permitted = agentScopes[agentId] || [];
    const denied = requested.filter((s) => !permitted.includes(s));
    if (denied.length > 0) throw new Error(`INSUFFICIENT_SCOPE:${denied.join(',')}`);
  }

  return requested;
}

function ensureActionScope(decodedScope = [], required = []) {
  const requiredScope = Array.isArray(required) ? required : [];
  for (const need of requiredScope) {
    if (!decodedScope.includes(need)) {
      throw new Error(`INSUFFICIENT_SCOPE:${need}`);
    }
  }
}

function issueToken({ service, scope, ttl = 600, context }) {
  context = requireContext(context);
  const jti = crypto.randomUUID();
  const payload = {
    sub: context.agentId,
    aud: AUDIENCE,
    jti,
    service,
    scope,
    ctx: context,
  };
  const expiresInSec = Math.min(ttl, 900);
  const token = jwt.sign(payload, SIGNING_KEY, { expiresIn: expiresInSec });
  appendAudit('token.issued', { tokenId: jti, service, scope, ttl: expiresInSec, context });
  return { tokenId: jti, token, expiresInSec };
}

function verifyToken(token, expectedContext) {
  const decoded = jwt.verify(token, SIGNING_KEY, { audience: AUDIENCE });
  const rev = readRevocations();
  if (rev.jti.includes(decoded.jti)) throw new Error('TOKEN_REVOKED');
  if (rev.sessions.includes(decoded.ctx.sessionId)) throw new Error('SESSION_REVOKED');
  if (rev.tasks.includes(decoded.ctx.taskId)) throw new Error('TASK_REVOKED');
  if (rev.agents.includes(decoded.ctx.agentId)) throw new Error('AGENT_REVOKED');

  if (decoded.ctx.agentId !== expectedContext.agentId) {
    throw new Error('CONTEXT_MISMATCH:agentId');
  }
  for (const key of ['sessionId', 'taskId', 'skillId']) {
    const tokenVal = decoded.ctx[key];
    const expectedVal = expectedContext[key];
    if (tokenVal?.startsWith('auto-') || expectedVal?.startsWith('auto-')) continue;
    if (tokenVal !== expectedVal) {
      throw new Error(`CONTEXT_MISMATCH:${key}`);
    }
  }
  return decoded;
}

function requireAdmin(req) {
  if (!ADMIN_TOKEN) throw new Error('ADMIN_NOT_CONFIGURED');

  const raw = req.headers.authorization || '';
  const [scheme, token] = raw.split(' ');
  if (scheme !== 'Bearer' || !token || token !== ADMIN_TOKEN) {
    throw new Error('ADMIN_UNAUTHORIZED');
  }
}

function assertString(value, field) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${field.toUpperCase()}_REQUIRED`);
  }
}

function assertArrayStrings(value, field, { required = true } = {}) {
  if (value == null && !required) return;
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${field.toUpperCase()}_REQUIRED`);
  }
  for (const item of value) {
    if (typeof item !== 'string' || !item.trim()) {
      throw new Error(`${field.toUpperCase()}_INVALID`);
    }
  }
}

function validateEndpoints(endpoints) {
  if (!endpoints || typeof endpoints !== 'object' || Array.isArray(endpoints)) {
    throw new Error('ENDPOINTS_REQUIRED');
  }

  for (const [name, def] of Object.entries(endpoints)) {
    if (!name.trim()) throw new Error('ENDPOINT_NAME_INVALID');
    if (!def || typeof def !== 'object' || Array.isArray(def)) {
      throw new Error(`ENDPOINT_INVALID:${name}`);
    }
    assertString(def.method, `endpoint.${name}.method`);
    assertString(def.path, `endpoint.${name}.path`);
    if (def.requiredScope != null) {
      if (!Array.isArray(def.requiredScope)) throw new Error(`ENDPOINT_REQUIRED_SCOPE_INVALID:${name}`);
      for (const scope of def.requiredScope) {
        if (typeof scope !== 'string' || !scope.trim()) {
          throw new Error(`ENDPOINT_REQUIRED_SCOPE_INVALID:${name}`);
        }
      }
    }
  }
}

function mergeDeep(base, patch) {
  const out = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      base[key] &&
      typeof base[key] === 'object' &&
      !Array.isArray(base[key])
    ) {
      out[key] = mergeDeep(base[key], value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function listTemplates() {
  if (!fs.existsSync(TEMPLATE_DIR)) return [];
  return fs
    .readdirSync(TEMPLATE_DIR)
    .filter((name) => name.endsWith('.json'))
    .map((name) => name.replace(/\.json$/, ''));
}

function loadTemplateByName(templateName) {
  assertString(templateName, 'template');
  const normalized = templateName.trim().toLowerCase();
  const filePath = path.join(TEMPLATE_DIR, `${normalized}.json`);
  if (!fs.existsSync(filePath)) {
    throw new Error(`UNKNOWN_TEMPLATE:${normalized}`);
  }

  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  assertString(parsed.name, 'template.name');
  assertString(parsed.baseUrl, 'template.baseUrl');
  assertArrayStrings(parsed.allowedActions, 'template.allowedActions');
  assertArrayStrings(parsed.allowedScopes, 'template.allowedScopes');
  validateEndpoints(parsed.endpoints);

  return parsed;
}

function sanitizeServiceList() {
  const services = listServices();
  return Object.entries(services).map(([service, cfg]) => ({
    service,
    baseUrl: cfg.baseUrl,
    secretRef: cfg.secretRef || null,
    authHeader: cfg.authHeader || null,
    allowedAgents: cfg.allowedAgents || [],
    allowedActions: cfg.allowedActions || [],
    allowedScopes: cfg.allowedScopes || [],
    ...(cfg.agentScopes ? { agentScopes: cfg.agentScopes } : {}),
    endpointNames: Object.keys(cfg.endpoints || {}),
  }));
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/vault.issueToken', (req, res) => {
  try {
    const {
      service,
      scope,
      ttl,
      sessionId,
      taskId,
      skillId,
      agentId,
      tool = 'vault.issueToken',
    } = req.body;

    if (!service) throw new Error('SERVICE_REQUIRED');
    const serviceConfig = readService(service);
    if (!serviceConfig) throw new Error('UNKNOWN_SERVICE');

    const context = requireContext({ agentId, sessionId, taskId, skillId, tool });
    if (!isActionAllowed(serviceConfig, 'issue', context.agentId)) {
      throw new Error('POLICY_DENY');
    }

    const validScope = validateScope(serviceConfig, scope, context.agentId);
    const token = issueToken({ service, scope: validScope, ttl, context });
    res.json(token);
  } catch (error) {
    appendAudit('token.issue.denied', { error: error.message, body: redactSensitive(req.body) });
    res.status(403).json({ error: error.message });
  }
});

app.post('/vault.call', async (req, res) => {
  try {
    const { token, service, action, params = {}, context: rawContext } = req.body;
    const context = requireContext(rawContext || {});

    const serviceConfig = readService(service);
    if (!serviceConfig) throw new Error('UNKNOWN_SERVICE');
    if (!isActionAllowed(serviceConfig, action, context.agentId)) {
      throw new Error('POLICY_DENY');
    }

    const decoded = verifyToken(token, context);
    if (decoded.service !== service) throw new Error('SERVICE_MISMATCH');

    const endpoint = serviceConfig.endpoints?.[action];
    if (!endpoint) throw new Error('UNKNOWN_ACTION');

    ensureActionScope(decoded.scope || [], endpoint.requiredScope || []);

    // Interpolate path params
    const pathParamKeys = new Set();
    const interpolatedPath = endpoint.path.replace(/\{(\w+)\}/g, (_, key) => {
      if (params[key] == null) throw new Error(`MISSING_PATH_PARAM:${key}`);
      pathParamKeys.add(key);
      return encodeURIComponent(params[key]);
    });

    const remainingParams = Object.fromEntries(
      Object.entries(params).filter(([k]) => !pathParamKeys.has(k))
    );
    let upstream = `${serviceConfig.baseUrl}${interpolatedPath}`;
    if (endpoint.method === 'GET' && Object.keys(remainingParams).length > 0) {
      const qs = new URLSearchParams(remainingParams).toString();
      upstream += `?${qs}`;
    }

    const headers = { 'Content-Type': 'application/json', ...(endpoint.headers || {}) };
    const secretRef = serviceConfig.secretRef;
    if (secretRef) {
      const secret = getSecret(secretRef);
      if (!secret) throw new Error(`MISSING_MASTER_SECRET:${secretRef}`);
      const authHeader = serviceConfig.authHeader || 'Authorization';
      const authScheme = serviceConfig.authScheme;
      headers[authHeader] = authScheme
        ? `${authScheme} ${secret}`
        : authHeader === 'Authorization'
          ? `Bearer ${secret}`
          : secret;
    }

    const response = await fetch(upstream, {
      method: endpoint.method || 'POST',
      headers,
      body: endpoint.method === 'GET' ? undefined : JSON.stringify(
        Object.fromEntries(Object.entries(params).filter(([k]) => !endpoint.path.includes(`{${k}}`)))
      ),
    });
    const text = await response.text();

    appendAudit('proxy.call', {
      service,
      action,
      context,
      tokenId: decoded.jti,
      scope: decoded.scope,
      status: response.status,
      upstream,
    });

    res.status(response.status).send(text);
  } catch (error) {
    appendAudit('proxy.call.denied', { error: error.message, body: redactSensitive(req.body) });
    res.status(403).json({ error: error.message });
  }
});

app.post('/vault.revoke', (req, res) => {
  try {
    const { tokenId, sessionId, taskId, agentId, reason = 'manual' } = req.body;
    const rev = readRevocations();
    if (tokenId && !rev.jti.includes(tokenId)) rev.jti.push(tokenId);
    if (sessionId && !rev.sessions.includes(sessionId)) rev.sessions.push(sessionId);
    if (taskId && !rev.tasks.includes(taskId)) rev.tasks.push(taskId);
    if (agentId && !rev.agents.includes(agentId)) rev.agents.push(agentId);
    writeRevocations(rev);

    appendAudit('token.revoked', { tokenId, sessionId, taskId, agentId, reason });
    res.json({ ok: true, revoked: { tokenId, sessionId, taskId, agentId } });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/vault.audit.query', (req, res) => {
  try {
    const { filters = {}, limit = 100 } = req.body;
    if (!fs.existsSync(AUDIT_PATH)) return res.json([]);

    const text = fs.readFileSync(AUDIT_PATH, 'utf8').trim();
    if (!text) return res.json([]);

    const rows = text
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));

    const result = rows.filter((row) =>
      Object.entries(filters).every(
        ([k, v]) => row[k] === v || row.context?.[k] === v
      )
    );

    res.json(result.slice(-limit));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------

app.post('/vault.admin.listTemplates', (req, res) => {
  try {
    requireAdmin(req);
    const templates = listTemplates();
    appendAudit('admin.listTemplates', { count: templates.length });
    res.json({ templates });
  } catch (error) {
    appendAudit('admin.listTemplates.denied', { error: error.message });
    res.status(403).json({ error: error.message });
  }
});

app.post('/vault.admin.addService', (req, res) => {
  try {
    requireAdmin(req);

    const {
      service,
      baseUrl,
      allowedAgents,
      allowedActions,
      allowedScopes,
      agentScopes,
      endpoints,
      secretRef,
      authHeader,
      authScheme,
      masterSecret,
    } = req.body;

    assertString(service, 'service');
    assertString(baseUrl, 'baseUrl');
    assertArrayStrings(allowedAgents, 'allowedAgents');
    assertArrayStrings(allowedActions, 'allowedActions');
    assertArrayStrings(allowedScopes, 'allowedScopes');
    validateEndpoints(endpoints);

    if (readService(service)) throw new Error('SERVICE_ALREADY_EXISTS');

    const config = {
      baseUrl,
      allowedAgents,
      allowedActions,
      allowedScopes,
      endpoints,
      ...(secretRef ? { secretRef } : {}),
      ...(authHeader ? { authHeader } : {}),
      ...(authScheme ? { authScheme } : {}),
      ...(agentScopes ? { agentScopes } : {}),
    };

    if (masterSecret != null) {
      const targetRef = secretRef || `${service}_secret`;
      config.secretRef = targetRef;
      setSecret(targetRef, masterSecret);
    }

    writeService(service, config);

    appendAudit('admin.addService', {
      service,
      secretRef: config.secretRef || null,
      body: redactSensitive(req.body),
    });

    res.json({ ok: true, service });
  } catch (error) {
    appendAudit('admin.addService.denied', { error: error.message, body: redactSensitive(req.body) });
    res.status(400).json({ error: error.message });
  }
});

app.post('/vault.admin.updateService', (req, res) => {
  try {
    requireAdmin(req);
    const { service, ...updates } = req.body;
    assertString(service, 'service');

    const disallowed = ['masterSecret', 'secret'];
    for (const key of disallowed) {
      if (key in updates) throw new Error(`FIELD_NOT_ALLOWED:${key}`);
    }

    if (updates.allowedAgents != null) assertArrayStrings(updates.allowedAgents, 'allowedAgents');
    if (updates.allowedActions != null) assertArrayStrings(updates.allowedActions, 'allowedActions');
    if (updates.allowedScopes != null) assertArrayStrings(updates.allowedScopes, 'allowedScopes');
    if (updates.baseUrl != null) assertString(updates.baseUrl, 'baseUrl');
    if (updates.endpoints != null) validateEndpoints(updates.endpoints);

    const existing = readService(service);
    if (!existing) throw new Error('UNKNOWN_SERVICE');

    writeService(service, mergeDeep(existing, updates));

    appendAudit('admin.updateService', { service, body: redactSensitive(req.body) });
    res.json({ ok: true, service });
  } catch (error) {
    appendAudit('admin.updateService.denied', { error: error.message, body: redactSensitive(req.body) });
    res.status(400).json({ error: error.message });
  }
});

app.post('/vault.admin.removeService', (req, res) => {
  try {
    requireAdmin(req);
    const { service } = req.body;
    assertString(service, 'service');

    const existing = readService(service);
    if (!existing) throw new Error('UNKNOWN_SERVICE');

    const secretRef = existing.secretRef;
    deleteService(service);

    if (secretRef) {
      removeSecret(secretRef);
    }

    appendAudit('admin.removeService', { service, secretRef: secretRef || null });
    res.json({ ok: true, service });
  } catch (error) {
    appendAudit('admin.removeService.denied', { error: error.message, body: redactSensitive(req.body) });
    res.status(400).json({ error: error.message });
  }
});

app.post('/vault.admin.listServices', (req, res) => {
  try {
    requireAdmin(req);
    const services = sanitizeServiceList();

    appendAudit('admin.listServices', { count: services.length });
    res.json({ services });
  } catch (error) {
    appendAudit('admin.listServices.denied', { error: error.message });
    res.status(403).json({ error: error.message });
  }
});

app.post('/vault.admin.addSecret', (req, res) => {
  try {
    requireAdmin(req);
    const { secretRef, secret } = req.body;
    assertString(secretRef, 'secretRef');
    assertString(secret, 'secret');

    setSecret(secretRef, secret);
    appendAudit('admin.addSecret', { secretRef, redacted: true });
    res.json({ ok: true, secretRef });
  } catch (error) {
    appendAudit('admin.addSecret.denied', { error: error.message, body: redactSensitive(req.body) });
    res.status(400).json({ error: error.message });
  }
});

app.post('/vault.admin.removeSecret', (req, res) => {
  try {
    requireAdmin(req);
    const { secretRef } = req.body;
    assertString(secretRef, 'secretRef');

    removeSecret(secretRef);
    appendAudit('admin.removeSecret', { secretRef });
    res.json({ ok: true, secretRef });
  } catch (error) {
    appendAudit('admin.removeSecret.denied', { error: error.message, body: redactSensitive(req.body) });
    res.status(400).json({ error: error.message });
  }
});

app.post('/vault.admin.loadTemplate', (req, res) => {
  try {
    requireAdmin(req);
    const { template, masterSecret, allowedAgents } = req.body;
    const loaded = loadTemplateByName(template);

    const serviceName = loaded.name;
    const effectiveAllowedAgents = Array.isArray(allowedAgents) && allowedAgents.length > 0
      ? allowedAgents
      : loaded.defaultAllowedAgents || ['*'];

    assertArrayStrings(effectiveAllowedAgents, 'allowedAgents');

    const serviceConfig = {
      baseUrl: loaded.baseUrl,
      secretRef: loaded.secretRef,
      allowedAgents: effectiveAllowedAgents,
      allowedActions: loaded.allowedActions,
      allowedScopes: loaded.allowedScopes,
      endpoints: loaded.endpoints,
    };

    const existing = readService(serviceName);
    const merged = existing ? mergeDeep(existing, serviceConfig) : serviceConfig;
    writeService(serviceName, merged);

    if (masterSecret != null) {
      assertString(masterSecret, 'masterSecret');
      setSecret(loaded.secretRef, masterSecret);
    }

    appendAudit('admin.loadTemplate', {
      template: loaded.name,
      service: serviceName,
      body: redactSensitive(req.body),
    });

    res.json({
      ok: true,
      service: serviceName,
      template: loaded.name,
      secretConfigured: Boolean(masterSecret),
    });
  } catch (error) {
    appendAudit('admin.loadTemplate.denied', { error: error.message, body: redactSensitive(req.body) });
    res.status(400).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  const serviceCount = Object.keys(listServices()).length;
  const refs = listSecretRefs();
  console.log(`agentic-credential-vault listening on :${PORT}`);
  console.log(`${serviceCount} service(s) loaded from config/services/`);
  console.log(`encrypted secrets ready (${refs.length} refs)`);
});
