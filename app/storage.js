import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config, ensureDataDirs } from './config.js';

ensureDataDirs();

const dbPath = path.join(config.dataDir, 'serverops.sqlite');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

db.exec(`
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  path TEXT NOT NULL UNIQUE,
  mime TEXT,
  size INTEGER NOT NULL DEFAULT 0,
  sha256 TEXT,
  cache_key TEXT UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS grants (
  token_hash TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  asset_id TEXT,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);

CREATE TABLE IF NOT EXISTS pending_admin_approvals (
  approval_id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_at INTEGER,
  denied_at INTEGER,
  token_hash TEXT,
  token_ciphertext TEXT,
  token_iv TEXT,
  token_tag TEXT,
  used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_pending_admin_approvals_actor
  ON pending_admin_approvals(actor, expires_at);

CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  request_id TEXT,
  status TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  metadata_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scopes TEXT NOT NULL,
  resource TEXT NOT NULL,
  subject TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  resource TEXT NOT NULL,
  subject TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS network_artifacts (
  id TEXT PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  client_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_network_artifacts_expiry ON network_artifacts(expires_at);
CREATE INDEX IF NOT EXISTS idx_network_artifacts_owner ON network_artifacts(client_id,subject);

CREATE TABLE IF NOT EXISTS bootstrap_tokens (
  token_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  claimed_at INTEGER
);

CREATE TABLE IF NOT EXISTS system_credentials (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
`);

export function now() {
  return Math.floor(Date.now() / 1000);
}

export function hashToken(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256Buffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function sha256File(filePath) {
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  const buf = Buffer.allocUnsafe(1024 * 1024);
  try {
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      h.update(buf.subarray(0, n));
    }
  } finally {
    fs.closeSync(fd);
  }
  return h.digest('hex');
}

// Credentials & System State
export function getSystemCredential(key) {
  const row = db.prepare('SELECT value FROM system_credentials WHERE key=?').get(key);
  return row ? row.value : null;
}

export function setSystemCredential(key, value) {
  const t = now();
  db.prepare('INSERT OR REPLACE INTO system_credentials(key, value, updated_at) VALUES(?,?,?)')
    .run(key, value, t);
}

export function getOwnerPasswordHash() {
  if (config.ownerPasswordHash) {
    return config.ownerPasswordHash;
  }
  return getSystemCredential('owner_password_hash');
}

export function setOwnerPasswordHash(hash) {
  setSystemCredential('owner_password_hash', hash);
}

export function isServerClaimed() {
  return Boolean(getOwnerPasswordHash());
}

// Bootstrap Token Management
export function createBootstrapToken(ttlSeconds = config.bootstrapTokenTtlSeconds) {
  // 256-bit cryptographically secure random token (32 bytes)
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(token);
  const t = now();
  const expiresAt = t + ttlSeconds;

  // Invalidate any previously unclaimed bootstrap tokens to enforce single active window
  db.prepare('UPDATE bootstrap_tokens SET claimed_at=? WHERE claimed_at IS NULL').run(t);

  db.prepare('INSERT INTO bootstrap_tokens(token_hash, created_at, expires_at, claimed_at) VALUES(?,?,?,NULL)')
    .run(tokenHash, t, expiresAt);

  return { token, tokenHash, expiresAt };
}

export function verifyBootstrapToken(token) {
  if (!token || typeof token !== 'string') return null;
  const tokenHash = hashToken(token.trim());
  const row = db.prepare('SELECT * FROM bootstrap_tokens WHERE token_hash=?').get(tokenHash);
  if (!row) return null;
  if (row.claimed_at) return { valid: false, reason: 'token_already_claimed' };
  if (row.expires_at <= now()) return { valid: false, reason: 'token_expired' };
  return { valid: true, row };
}

export function claimBootstrapToken(token, passwordHash) {
  const verification = verifyBootstrapToken(token);
  if (!verification || !verification.valid) {
    throw new Error(verification?.reason || 'invalid_bootstrap_token');
  }
  const t = now();
  const updateResult = db.prepare('UPDATE bootstrap_tokens SET claimed_at=? WHERE token_hash=? AND claimed_at IS NULL AND expires_at>?')
    .run(t, verification.row.token_hash, t);

  if (updateResult.changes !== 1) {
    throw new Error('token_claim_conflict');
  }

  setOwnerPasswordHash(passwordHash);
  audit('bootstrap_claimed', null, 'ok', 'Owner password configured via activation token');
  return true;
}

// Grants & One-Time Tokens
export function createGrant(purpose, assetId = null, ttl = 900) {
  const token = randomToken();
  const expiresAt = now() + ttl;
  db.prepare('INSERT INTO grants(token_hash, purpose, asset_id, expires_at) VALUES(?,?,?,?)')
    .run(hashToken(token), purpose, assetId, expiresAt);
  return { token, expiresAt };
}

export function consumeGrant(token, purpose, consume = true, expectedAssetId = undefined) {
  const row = db.prepare('SELECT * FROM grants WHERE token_hash=?').get(hashToken(token));
  const current = now();
  if (!row || row.purpose !== purpose || row.expires_at <= current || (consume && row.used_at)) return null;
  if (expectedAssetId !== undefined && row.asset_id !== expectedAssetId) return null;
  if (consume) {
    const changed = db.prepare('UPDATE grants SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?')
      .run(current, row.token_hash, current);
    if (changed.changes !== 1) return null;
    db.prepare('UPDATE pending_admin_approvals SET used_at=? WHERE token_hash=? AND used_at IS NULL')
      .run(current, row.token_hash);
  }
  return row;
}

function decodePendingAdminApproval(row) {
  if (!row) return null;
  let payload = {};
  try { payload = JSON.parse(row.payload_json); } catch {}
  return {
    approval_id: row.approval_id,
    action: row.action,
    actor: row.actor,
    payload_hash: row.payload_hash,
    created_at: row.created_at,
    expires_at: row.expires_at,
    approved_at: row.approved_at,
    denied_at: row.denied_at,
    used_at: row.used_at,
    status: row.denied_at ? 'denied' : row.approved_at ? (row.used_at ? 'used' : 'approved') : row.expires_at <= now() ? 'expired' : 'pending',
    canonical_payload: payload.canonical_payload ?? payload,
    review: payload.review ?? payload.canonical_payload ?? payload
  };
}

export function createPendingAdminApproval({ action, payload, review = payload, payloadHash, actor = 'unknown', ttlSeconds = 600 }) {
  if (!/^[a-z][a-z0-9_]{2,63}$/.test(String(action || ''))) throw new Error('invalid_approval_action');
  if (!/^[a-f0-9]{64}$/i.test(String(payloadHash || ''))) throw new Error('invalid_approval_payload_hash');
  const approvalId = crypto.randomUUID();
  const createdAt = now();
  const expiresAt = createdAt + Math.max(60, Math.min(Number(ttlSeconds) || 600, 1800));
  const payloadJson = JSON.stringify({ canonical_payload: payload ?? {}, review: review ?? payload ?? {} });
  if (Buffer.byteLength(payloadJson) > 4 * 1024 * 1024) throw new Error('approval_review_too_large');
  db.prepare('INSERT INTO pending_admin_approvals (approval_id,action,payload_json,payload_hash,actor,created_at,expires_at) VALUES(?,?,?,?,?,?,?)')
    .run(approvalId, action, payloadJson, payloadHash, String(actor || 'unknown').slice(0, 200), createdAt, expiresAt);
  audit('admin_approval_requested', null, 'pending', approvalId + ':' + action + ':' + payloadHash);
  return { approvalId, action, payloadHash, createdAt, expiresAt };
}

export function getPendingAdminApproval(approvalId) {
  return decodePendingAdminApproval(
    db.prepare('SELECT * FROM pending_admin_approvals WHERE approval_id=?').get(String(approvalId || ''))
  );
}

export function listPendingAdminApprovals(limit = 100) {
  const bounded = Math.max(1, Math.min(Number(limit) || 100, 500));
  return db.prepare('SELECT * FROM pending_admin_approvals WHERE approved_at IS NULL AND denied_at IS NULL ORDER BY created_at ASC LIMIT ?')
    .all(bounded).map(decodePendingAdminApproval);
}

export function approvePendingAdminApproval(approvalId, grantTtlSeconds = 300) {
  const current = now();
  const token = randomToken();
  const tokenHash = hashToken(token);
  const expiresAt = current + Math.max(60, Math.min(Number(grantTtlSeconds) || 300, 600));
  const tx = db.transaction(() => {
    const row = db.prepare('SELECT * FROM pending_admin_approvals WHERE approval_id=?').get(String(approvalId || ''));
    if (!row) throw new Error('approval_not_found');
    if (row.approved_at || row.denied_at || row.used_at) throw new Error('approval_not_pending');
    if (row.expires_at <= current) throw new Error('approval_request_expired');
    db.prepare('INSERT INTO grants(token_hash,purpose,asset_id,expires_at) VALUES(?,?,?,?)')
      .run(tokenHash, 'admin:' + row.action, row.payload_hash, expiresAt);
    const changed = db.prepare('UPDATE pending_admin_approvals SET approved_at=?, token_hash=? WHERE approval_id=? AND approved_at IS NULL AND denied_at IS NULL AND used_at IS NULL AND expires_at>?')
      .run(current, tokenHash, row.approval_id, current);
    if (changed.changes !== 1) throw new Error('approval_state_conflict');
    audit('admin_approval_owner_approved', null, 'ok', row.approval_id + ':' + row.action + ':' + row.payload_hash);
    return { token, expiresAt, approvalId: row.approval_id, action: row.action, payloadHash: row.payload_hash };
  });
  return tx();
}

export function denyPendingAdminApproval(approvalId) {
  const current = now();
  const changed = db.prepare('UPDATE pending_admin_approvals SET denied_at=? WHERE approval_id=? AND approved_at IS NULL AND denied_at IS NULL AND used_at IS NULL')
    .run(current, String(approvalId || ''));
  if (changed.changes !== 1) throw new Error('approval_not_pending');
  audit('admin_approval_owner_denied', null, 'denied', String(approvalId));
  return { approvalId: String(approvalId), deniedAt: current };
}

export function consumePendingAdminApproval(approvalId, token, action, expectedPayloadHash) {
  const current = now();
  const tx = db.transaction(() => {
    const row = db.prepare('SELECT * FROM pending_admin_approvals WHERE approval_id=?').get(String(approvalId || ''));
    if (!row || row.action !== action || row.payload_hash !== expectedPayloadHash ||
        !row.approved_at || row.denied_at || row.used_at || row.expires_at <= current ||
        row.token_hash !== hashToken(token)) return false;
    const grant = db.prepare('SELECT * FROM grants WHERE token_hash=?').get(row.token_hash);
    if (!grant || grant.purpose !== 'admin:' + action || grant.asset_id !== expectedPayloadHash ||
        grant.expires_at <= current || grant.used_at) return false;
    const grantChanged = db.prepare('UPDATE grants SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?')
      .run(current, row.token_hash, current);
    if (grantChanged.changes !== 1) return false;
    const approvalChanged = db.prepare('UPDATE pending_admin_approvals SET used_at=? WHERE approval_id=? AND used_at IS NULL')
      .run(current, row.approval_id);
    if (approvalChanged.changes !== 1) throw new Error('approval_state_conflict');
    audit('admin_approval_consumed', null, 'ok', row.approval_id + ':' + action + ':' + expectedPayloadHash);
    return true;
  });
  return tx();
}

// Assets Storage
export function assetById(id) {
  return db.prepare('SELECT * FROM assets WHERE id=?').get(id);
}

export function addAsset({ id = crypto.randomUUID(), kind, filePath, mime, size, sha256, cacheKey = null, expiresAt = null }) {
  db.prepare('INSERT INTO assets(id,kind,path,mime,size,sha256,cache_key,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id, kind, filePath, mime, size, sha256, cacheKey, now(), expiresAt);
  return assetById(id);
}

export function registerNetworkArtifact({ id, filePath, sha256, size, clientId, subject, expiresAt }) {
  if (!/^[0-9a-f-]{36}$/i.test(String(id || '')) || !/^[a-f0-9]{64}$/.test(String(sha256 || '')) ||
      !Number.isSafeInteger(size) || size < 0 || !clientId || !subject || !Number.isSafeInteger(expiresAt)) {
    throw new Error('network_artifact_metadata_invalid');
  }
  db.prepare('INSERT INTO network_artifacts(id,path,sha256,size,client_id,subject,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(id, filePath, sha256, size, clientId, subject, now(), expiresAt);
  return networkArtifactById(id);
}

export function networkArtifactById(id) {
  return db.prepare('SELECT * FROM network_artifacts WHERE id=?').get(id) || null;
}

// Audit & Diagnostics
export function audit(action, requestId, status, detail = '') {
  const sanitized = String(detail || '')
    .replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [REDACTED]')
    .replace(/(password|passwd|token|secret)\s*[:=]\s*["']?[^"'&\s]+/gi, '$1=[REDACTED]')
    .slice(0, 1000);

  db.prepare('INSERT INTO audit(action,request_id,status,detail,created_at) VALUES(?,?,?,?,?)')
    .run(action, requestId || null, status, sanitized, now());
}

export function diagnosticSummary(limit = 10) {
  const boundedLimit = Math.max(1, Math.min(Number(limit) || 10, 50));
  const rejected = db.prepare("SELECT COUNT(*) AS count FROM audit WHERE action IN ('mcp_http_rejected','mcp_tool_rejected')").get().count;
  const categoryRows = db.prepare("SELECT detail,COUNT(*) AS count FROM audit WHERE action IN ('mcp_http_rejected','mcp_tool_rejected') GROUP BY detail").all();
  const categoryCounts = new Map();
  for (const row of categoryRows) {
    const match = /^(forbidden|approval_required|approval_invalid|queue_full|execution_timeout|validation_failed|tool_execution_failed)(:[a-z0-9_]{1,64})?$/.exec(String(row.detail || ''));
    const category = match ? match[0] : 'tool_execution_failed';
    categoryCounts.set(category, (categoryCounts.get(category) || 0) + row.count);
  }
  const categories = [...categoryCounts].map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
  const recentErrors = db.prepare("SELECT action,request_id,status,created_at,detail FROM audit WHERE status!='ok' ORDER BY id DESC LIMIT ?")
    .all(boundedLimit)
    .map(row => {
      const action = /^[a-z0-9_]{1,64}$/.test(String(row.action || '')) ? row.action : 'unknown';
      const requestId = typeof row.request_id === 'string' && /^[A-Za-z0-9._-]{8,100}$/.test(row.request_id) ? row.request_id : null;
      const match = /^(forbidden|approval_required|approval_invalid|queue_full|execution_timeout|validation_failed|tool_execution_failed)(:[a-z0-9_]{1,64})?$/.exec(String(row.detail || ''));
      return {
        action,
        request_id: requestId,
        status: row.status === 'error' ? 'error' : 'non_success',
        created_at: Number.isSafeInteger(row.created_at) ? row.created_at : null,
        category: action === 'mcp_tool_rejected'
          ? (match ? match[0] : 'tool_execution_failed')
          : 'operation_failed'
      };
    });
  return { rejected_request_count: rejected, error_categories: categories, last_relevant_errors: recentErrors };
}

export function cleanup() {
  const timestamp = now();
  const expired = db.prepare('SELECT * FROM assets WHERE expires_at IS NOT NULL AND expires_at<=?').all(timestamp);
  for (const row of expired) {
    try { fs.unlinkSync(row.path); } catch {}
  }
  db.prepare('DELETE FROM assets WHERE expires_at IS NOT NULL AND expires_at<=?').run(timestamp);

  const networkRoot = path.resolve(config.dataDir, 'network') + path.sep;
  const expiredNetwork = db.prepare('SELECT id,path FROM network_artifacts WHERE expires_at<=?').all(timestamp);
  for (const row of expiredNetwork) {
    const candidate = path.resolve(row.path);
    if (candidate.startsWith(networkRoot)) {
      try { fs.unlinkSync(candidate); } catch {}
    }
  }
  db.prepare('DELETE FROM network_artifacts WHERE expires_at<=?').run(timestamp);
  db.prepare('DELETE FROM grants WHERE expires_at<=?').run(timestamp);
  return expired.length;
}

export { db };
