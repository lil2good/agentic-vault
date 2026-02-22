import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 8787;
const SIGNING_KEY = process.env.VAULT_SIGNING_KEY || 'dev-signing-key-change-me';
const AUDIENCE = process.env.VAULT_AUDIENCE || 'agentic-credential-vault-proxy';
const DATA_DIR = process.env.VAULT_DATA_DIR || path.resolve('data');
const AUDIT_PATH = path.join(DATA_DIR, 'audit.log.jsonl');
const REVOCATIONS_PATH = path.join(DATA_DIR, 'revocations.json');
const POLICY_PATH = process.env.VAULT_POLICY_PATH || path.resolve('config/policy.json');
const MASTER_SECRETS = process.env.MASTER_SECRETS_JSON ? JSON.parse(process.env.MASTER_SECRETS_JSON) : {};

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(REVOCATIONS_PATH)) fs.writeFileSync(REVOCATIONS_PATH, JSON.stringify({ jti: [], sessions: [], tasks: [], agents: [] }, null, 2));

const readRevocations = () => JSON.parse(fs.readFileSync(REVOCATIONS_PATH, 'utf8'));
const writeRevocations = (next) => fs.writeFileSync(REVOCATIONS_PATH, JSON.stringify(next, null, 2));

function readPolicy() {
  return JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8'));
}

function appendAudit(event, context = {}) {
  const line = JSON.stringify({ ts: Date.now(), event, ...context });
  fs.appendFileSync(AUDIT_PATH, `${line}\n`);
}

function requireContext(input = {}) {
  const required = ['agentId', 'sessionId', 'taskId', 'skillId', 'tool'];
  for (const key of required) {
    if (!input[key]) throw new Error(`Missing required context: ${key}`);
  }
}

function isActionAllowed(policy, service, action, agentId) {
  const servicePolicy = policy.services?.[service];
  if (!servicePolicy) return false;
  const allowedActions = servicePolicy.allowedActions || [];
  const allowedAgents = servicePolicy.allowedAgents || [];
  return allowedActions.includes(action) && (allowedAgents.includes('*') || allowedAgents.includes(agentId));
}

function issueToken({ service, scope = [], ttl = 600, context }) {
  requireContext(context);
  const jti = crypto.randomUUID();
  const payload = {
    sub: context.agentId,
    aud: AUDIENCE,
    jti,
    service,
    scope,
    ctx: context,
  };
  const token = jwt.sign(payload, SIGNING_KEY, { expiresIn: Math.min(ttl, 900) });
  appendAudit('token.issued', { tokenId: jti, service, scope, ttl, context });
  return { tokenId: jti, token, expiresInSec: Math.min(ttl, 900) };
}

function verifyToken(token, expectedContext) {
  const decoded = jwt.verify(token, SIGNING_KEY, { audience: AUDIENCE });
  const rev = readRevocations();
  if (rev.jti.includes(decoded.jti)) throw new Error('TOKEN_REVOKED');
  if (rev.sessions.includes(decoded.ctx.sessionId)) throw new Error('SESSION_REVOKED');
  if (rev.tasks.includes(decoded.ctx.taskId)) throw new Error('TASK_REVOKED');
  if (rev.agents.includes(decoded.ctx.agentId)) throw new Error('AGENT_REVOKED');

  for (const key of ['agentId', 'sessionId', 'taskId', 'skillId']) {
    if (decoded.ctx[key] !== expectedContext[key]) {
      throw new Error(`CONTEXT_MISMATCH:${key}`);
    }
  }
  return decoded;
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/vault.issueToken', (req, res) => {
  try {
    const { service, scope, ttl, sessionId, taskId, skillId, agentId, tool = 'vault.issueToken' } = req.body;
    const policy = readPolicy();
    const context = { agentId, sessionId, taskId, skillId, tool };
    if (!service) throw new Error('service is required');
    if (!isActionAllowed(policy, service, 'issue', agentId)) {
      throw new Error('POLICY_DENY');
    }
    const token = issueToken({ service, scope, ttl, context });
    res.json(token);
  } catch (error) {
    appendAudit('token.issue.denied', { error: error.message, body: req.body });
    res.status(403).json({ error: error.message });
  }
});

app.post('/vault.call', async (req, res) => {
  try {
    const { token, service, action, params = {}, context } = req.body;
    requireContext(context);
    const policy = readPolicy();
    if (!isActionAllowed(policy, service, action, context.agentId)) {
      throw new Error('POLICY_DENY');
    }

    const decoded = verifyToken(token, context);
    if (decoded.service !== service) throw new Error('SERVICE_MISMATCH');

    const servicePolicy = policy.services[service];
    const endpoint = servicePolicy.endpoints?.[action];
    if (!endpoint) throw new Error('UNKNOWN_ACTION');

    const upstream = `${servicePolicy.baseUrl}${endpoint.path}`;
    const headers = { 'Content-Type': 'application/json', ...(endpoint.headers || {}) };
    const secretRef = servicePolicy.secretRef;
    if (secretRef) {
      if (!MASTER_SECRETS[secretRef]) throw new Error(`MISSING_MASTER_SECRET:${secretRef}`);
      headers.Authorization = `Bearer ${MASTER_SECRETS[secretRef]}`;
    }

    const response = await fetch(upstream, {
      method: endpoint.method || 'POST',
      headers,
      body: endpoint.method === 'GET' ? undefined : JSON.stringify(params),
    });
    const text = await response.text();

    appendAudit('proxy.call', {
      service,
      action,
      context,
      tokenId: decoded.jti,
      status: response.status,
      upstream,
    });

    res.status(response.status).send(text);
  } catch (error) {
    appendAudit('proxy.call.denied', { error: error.message, body: req.body });
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
    const rows = fs.readFileSync(AUDIT_PATH, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
    const result = rows.filter((row) => Object.entries(filters).every(([k, v]) => row[k] === v || row.context?.[k] === v));
    res.json(result.slice(-limit));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`agentic-credential-vault listening on :${PORT}`);
});
