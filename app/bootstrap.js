import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';
import * as store from './storage.js';

export function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('Password must be at least 8 characters long');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPasswordHash(password, storedHash) {
  if (!password || !storedHash) return false;
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, expected] = parts;
  try {
    const actual = crypto.scryptSync(password, salt, 64).toString('hex');
    const a = Buffer.from(actual);
    const b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

export function getBootstrapTokenFile() {
  return path.join(config.dataDir, 'bootstrap.token');
}

export function initializeBootstrapToken(isInteractive = false) {
  if (store.isServerClaimed()) {
    return null;
  }

  // Check if an existing valid unclaimed token exists in DB
  const current = store.now();
  const existing = store.db.prepare(
    'SELECT * FROM bootstrap_tokens WHERE claimed_at IS NULL AND expires_at > ?'
  ).get(current);

  if (existing) {
    return {
      active: true,
      expiresAt: existing.expires_at,
      tokenFile: getBootstrapTokenFile()
    };
  }

  // Generate 256-bit cryptographic single-use token
  const { token, expiresAt } = store.createBootstrapToken(config.bootstrapTokenTtlSeconds);
  const tokenFile = getBootstrapTokenFile();

  try {
    fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o750 });
    fs.writeFileSync(tokenFile, `${token}\n`, { mode: 0o600 });
  } catch (err) {
    if (process.env.NODE_ENV !== 'test') {
      console.warn(`[Bootstrap] Warning: could not write bootstrap token file: ${err.message}`);
    }
  }

  return {
    token,
    expiresAt,
    tokenFile
  };
}

export function claimServer({ token, password }) {
  if (store.isServerClaimed()) {
    throw new Error('server_already_claimed');
  }
  if (!token || typeof token !== 'string') {
    throw new Error('token_required');
  }
  if (!password || typeof password !== 'string' || password.length < 8) {
    throw new Error('password_minimum_length_8');
  }

  const newHash = hashPassword(password);
  store.claimBootstrapToken(token.trim(), newHash);

  // Safely cleanup token file
  const tokenFile = getBootstrapTokenFile();
  try {
    if (fs.existsSync(tokenFile)) {
      fs.unlinkSync(tokenFile);
    }
  } catch {}

  return { ok: true, message: 'Server claimed successfully. Owner password configured.' };
}

export function resetPasswordLocally(newPassword) {
  if (config.ownerPasswordHash) {
    throw new Error('SERVEROPS_OWNER_PASSWORD_HASH is configured; update the protected environment file and restart the service instead.');
  }
  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
    throw new Error('password_minimum_length_8');
  }
  const newHash = hashPassword(newPassword);
  const timestamp = store.now();
  const tx = store.db.transaction(() => {
    store.setOwnerPasswordHash(newHash);
    const revoked = store.db.prepare('UPDATE oauth_refresh_tokens SET revoked_at=? WHERE revoked_at IS NULL').run(timestamp);
    const codes = store.db.prepare('DELETE FROM oauth_codes').run();
    const grants = store.db.prepare('DELETE FROM grants').run();
    const approvals = store.db.prepare('UPDATE pending_admin_approvals SET denied_at=? WHERE denied_at IS NULL AND used_at IS NULL').run(timestamp);
    return { refreshSessions: revoked.changes, authorizationCodes: codes.changes, grants: grants.changes, approvals: approvals.changes };
  });
  const invalidated = tx();
  store.audit('password_reset_local', null, 'ok',
    'Owner password reset; refresh sessions revoked=' + invalidated.refreshSessions +
    '; authorization codes removed=' + invalidated.authorizationCodes +
    '; pending grants invalidated=' + (invalidated.grants + invalidated.approvals));
  return {
    ok: true,
    message: 'Owner password reset successfully. Revoked ' + invalidated.refreshSessions +
      ' refresh sessions and invalidated pending grants.'
  };
}
