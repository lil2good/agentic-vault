import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const DEFAULT_SECRETS_FILENAME = 'secrets.enc';
const DEFAULT_KEY_FILENAME = '.vault-key';

let secretsPath;
let keyPath;
let auditAppender = () => {};

function atomicWrite(targetPath, content) {
  const tmp = `${targetPath}.tmp`;
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, targetPath);
}

function resolveEncryptionKey() {
  const fromEnv = process.env.VAULT_ENCRYPTION_KEY;

  if (fromEnv) {
    const hexCandidate = fromEnv.trim();
    if (/^[0-9a-fA-F]{64}$/.test(hexCandidate)) {
      return Buffer.from(hexCandidate, 'hex');
    }

    try {
      const b64 = Buffer.from(fromEnv, 'base64');
      if (b64.length === 32) return b64;
    } catch {
      // Fallback to hash below
    }

    return crypto.createHash('sha256').update(fromEnv).digest();
  }

  if (fs.existsSync(keyPath)) {
    const saved = fs.readFileSync(keyPath, 'utf8').trim();
    return Buffer.from(saved, 'hex');
  }

  const generated = crypto.randomBytes(32);
  atomicWrite(keyPath, `${generated.toString('hex')}\n`);
  try {
    fs.chmodSync(keyPath, 0o600);
  } catch {
    // best effort
  }
  return generated;
}

function readEncryptedFile(key) {
  if (!fs.existsSync(secretsPath)) return {};

  const raw = fs.readFileSync(secretsPath, 'utf8').trim();
  if (!raw) return {};

  const payload = JSON.parse(raw);
  const iv = Buffer.from(payload.iv, 'base64');
  const tag = Buffer.from(payload.tag, 'base64');
  const data = Buffer.from(payload.data, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  const parsed = JSON.parse(decrypted || '{}');

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('INVALID_SECRETS_STORE');
  }

  return parsed;
}

function writeEncryptedFile(obj, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const plaintext = Buffer.from(JSON.stringify(obj));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const payload = {
    v: 1,
    alg: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: encrypted.toString('base64'),
  };

  atomicWrite(secretsPath, `${JSON.stringify(payload, null, 2)}\n`);
}

function loadAll() {
  const key = resolveEncryptionKey();
  return readEncryptedFile(key);
}

function saveAll(next) {
  const key = resolveEncryptionKey();
  writeEncryptedFile(next, key);
}

export function initSecrets({ dataDir, appendAudit }) {
  fs.mkdirSync(dataDir, { recursive: true });
  secretsPath = path.join(dataDir, DEFAULT_SECRETS_FILENAME);
  keyPath = path.join(dataDir, DEFAULT_KEY_FILENAME);
  auditAppender = typeof appendAudit === 'function' ? appendAudit : () => {};
  loadAll();
}

export function loadSecrets() {
  const loaded = loadAll();
  auditAppender('secret.load', { refs: Object.keys(loaded) });
  return loaded;
}

export function getSecret(ref) {
  const value = loadAll()[ref];
  auditAppender('secret.get', { secretRef: ref, found: Boolean(value) });
  return value;
}

export function setSecret(ref, value) {
  if (!ref) throw new Error('SECRET_REF_REQUIRED');
  if (typeof value !== 'string' || !value.trim()) throw new Error('SECRET_VALUE_REQUIRED');

  const next = loadAll();
  next[ref] = value;
  saveAll(next);
  auditAppender('secret.set', { secretRef: ref, redacted: true });
}

export function removeSecret(ref) {
  if (!ref) throw new Error('SECRET_REF_REQUIRED');
  const next = loadAll();
  const existed = Object.prototype.hasOwnProperty.call(next, ref);
  delete next[ref];
  saveAll(next);
  auditAppender('secret.remove', { secretRef: ref, existed });
}

export function listSecretRefs() {
  const refs = Object.keys(loadAll());
  auditAppender('secret.listRefs', { refs });
  return refs;
}
