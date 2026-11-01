import crypto from 'node:crypto';
import { db, audit, now } from './storage.js';
import { config } from './config.js';
import { requestContext } from './request-context.js';

db.exec(`CREATE TABLE IF NOT EXISTS full_admin_tokens (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
 subject TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER
);`);
db.exec(`CREATE TABLE IF NOT EXISTS full_admin_oauth_grants (
 client_id TEXT NOT NULL, subject TEXT NOT NULL, granted_at INTEGER NOT NULL,
 revoked_at INTEGER, PRIMARY KEY(client_id, subject)
);`);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
export function revokeAllFullAdmin() {
  const timestamp = now();
  return db.transaction(() => {
    const tokens = db.prepare('UPDATE full_admin_tokens SET revoked_at=? WHERE revoked_at IS NULL').run(timestamp).changes;
    const oauthGrants = db.prepare('UPDATE full_admin_oauth_grants SET revoked_at=? WHERE revoked_at IS NULL').run(timestamp).changes;
    return { tokens, oauthGrants };
  })();
}
export function hasOAuthFullAdmin(clientId, subject) {
  if (!clientId || subject !== config.ownerSubject) return false;
  return Boolean(db.prepare('SELECT 1 FROM full_admin_oauth_grants WHERE client_id=? AND subject=? AND revoked_at IS NULL').get(clientId, subject));
}
export function grantOAuthClient(clientId, subject = config.ownerSubject) {
  if (subject !== config.ownerSubject) throw new Error('owner_subject_required');
  const authenticated = db.prepare('SELECT scopes FROM oauth_refresh_tokens WHERE client_id=? AND subject=? AND revoked_at IS NULL AND expires_at>?').all(clientId, subject, now());
  if (!authenticated.some(row => row.scopes.split(/\s+/).includes('system:admin'))) throw new Error('authenticated_admin_client_required');
  db.prepare('INSERT INTO full_admin_oauth_grants VALUES (?,?,?,NULL) ON CONFLICT(client_id,subject) DO UPDATE SET granted_at=excluded.granted_at,revoked_at=NULL').run(clientId,subject,now());
  audit('full_admin_oauth_granted',null,'ok',JSON.stringify({client_id:clientId,subject,expires_at:null}));
  return {client_id:clientId,subject,expires_at:null,full_admin:true};
}
export function revokeOAuthClient(clientId, subject = config.ownerSubject) {
  const result = db.prepare('UPDATE full_admin_oauth_grants SET revoked_at=? WHERE client_id=? AND subject=? AND revoked_at IS NULL').run(now(),clientId,subject);
  audit('full_admin_oauth_revoked',null,'ok',JSON.stringify({client_id:clientId,subject,changes:result.changes}));
  return {client_id:clientId,revoked:result.changes};
}
export function listOAuthGrants() {
  return db.prepare('SELECT client_id,subject,granted_at,revoked_at FROM full_admin_oauth_grants').all();
}
export function createToken(label) {
  if (!String(label || '').trim() || String(label).length > 120) throw new Error('invalid_token_label');
  const id = crypto.randomUUID();
  const token = 'sops_admin_' + crypto.randomBytes(48).toString('base64url');
  db.prepare('INSERT INTO full_admin_tokens VALUES (?,?,?,?,?,NULL)').run(id, hash(token), label, config.ownerSubject, now());
  audit('full_admin_token_created', null, 'ok', JSON.stringify({ id, label, expires_at: null }));
  return { id, token, expires_at: null };
}
export function listTokens() {
  return db.prepare('SELECT id,label,subject,created_at,revoked_at FROM full_admin_tokens ORDER BY created_at DESC').all();
}
export function revokeToken(id) {
  const result = db.prepare('UPDATE full_admin_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL').run(now(), id);
  audit('full_admin_token_revoked', null, 'ok', JSON.stringify({ id, changes: result.changes }));
  return result.changes;
}
export function verifyToken(token, scopes) {
  if (!/^sops_admin_[A-Za-z0-9_-]{64}$/.test(token)) throw new Error('invalid_admin_token');
  const row = db.prepare('SELECT id,subject FROM full_admin_tokens WHERE token_hash=? AND revoked_at IS NULL').get(hash(token));
  if (!row || row.subject !== config.ownerSubject) throw new Error('revoked_or_invalid_admin_token');
  return { clientId: 'full-admin:' + row.id, subject: row.subject, scopes: [...scopes], role: 'administrator', fullAdminId: row.id };
}
export function hasFullAdmin(auth = requestContext()?.authInfo) {
  if (!auth || auth.subject !== config.ownerSubject || !auth.scopes?.includes('system:admin')) return false;
  if (auth.fullAdminId) return Boolean(db.prepare('SELECT id FROM full_admin_tokens WHERE id=? AND subject=? AND revoked_at IS NULL').get(auth.fullAdminId, auth.subject));
  return hasOAuthFullAdmin(auth.clientId,auth.subject);
}
export function authorizeFullAdmin(action, payload) {
  if (!hasFullAdmin()) return false;
  const ctx = requestContext();
  audit('full_admin_operation_authorized', ctx.requestId || null, 'ok', JSON.stringify({ client: ctx.authInfo.clientId, subject: ctx.authInfo.subject, action, payload_sha256: hash(JSON.stringify(payload)) }));
  return true;
}
