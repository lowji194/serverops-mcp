import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Configure test environment before loading modules
process.env.NODE_ENV = 'test';
process.env.SERVEROPS_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-test-bootstrap-'));
process.env.SERVEROPS_OAUTH_SIGNING_KEY = 'test-signing-key-for-bootstrap-tests-at-least-thirty-two-bytes';

const store = await import('../app/storage.js');
const bootstrap = await import('../app/bootstrap.js');

test('bootstrap: generates 256-bit cryptographic token and writes 0600 file', () => {
  const result = bootstrap.initializeBootstrapToken(true);
  assert.ok(result);
  assert.ok(result.token);
  // 32 bytes hex = 64 characters (256 bits)
  assert.equal(result.token.length, 64);
  assert.ok(result.expiresAt > store.now());

  // Token file written with 0600 mode
  assert.ok(fs.existsSync(result.tokenFile));
  const fileContent = fs.readFileSync(result.tokenFile, 'utf8').trim();
  assert.equal(fileContent, result.token);

  // DB contains only hash, not the raw token
  const hashed = store.hashToken(result.token);
  const row = store.db.prepare('SELECT * FROM bootstrap_tokens WHERE token_hash=?').get(hashed);
  assert.ok(row);
  assert.equal(row.claimed_at, null);
});

test('bootstrap: rejects invalid or weak passwords', () => {
  const token = fs.readFileSync(bootstrap.getBootstrapTokenFile(), 'utf8').trim();
  assert.throws(() => {
    bootstrap.claimServer({ token, password: 'short' });
  }, /password_minimum_length_8/);
});

test('bootstrap: successfully claims server, hashes password, and invalidates token', () => {
  const token = fs.readFileSync(bootstrap.getBootstrapTokenFile(), 'utf8').trim();
  const outcome = bootstrap.claimServer({ token, password: 'StrongPassword123!' });
  assert.equal(outcome.ok, true);

  // Server is now claimed
  assert.equal(store.isServerClaimed(), true);

  // Token file was cleaned up
  assert.equal(fs.existsSync(bootstrap.getBootstrapTokenFile()), false);

  // Token hash marked claimed in DB
  const hashed = store.hashToken(token);
  const row = store.db.prepare('SELECT * FROM bootstrap_tokens WHERE token_hash=?').get(hashed);
  assert.ok(row.claimed_at > 0);

  // Password verification works
  assert.equal(bootstrap.verifyPasswordHash('StrongPassword123!', store.getOwnerPasswordHash()), true);
  assert.equal(bootstrap.verifyPasswordHash('WrongPassword', store.getOwnerPasswordHash()), false);
});

test('bootstrap: replay attack on claimed token is rejected', () => {
  assert.throws(() => {
    bootstrap.claimServer({ token: '4f'.repeat(32), password: 'AnotherPassword123!' });
  }, /server_already_claimed/);
});

test('bootstrap: local password reset revokes sessions, codes, grants and pending approvals', async () => {
  const oauth = await import('../app/oauth.js');
  const config = (await import('../app/config.js')).config;
  const timestamp = store.now();
  const refreshToken = 'reset-test-refresh-token-0123456789abcdef';
  const tokenHash = store.hashToken(refreshToken);
  store.db.prepare('INSERT INTO oauth_refresh_tokens VALUES(?,?,?,?,?,?,NULL)')
    .run(tokenHash, 'reset-test-client', 'system:read', oauth.RESOURCE, 'serverops-owner', timestamp + 3600);
  const accessToken = oauth.jwt({
    iss: config.oauthIssuer,
    aud: oauth.RESOURCE,
    sub: 'serverops-owner',
    client_id: 'reset-test-client',
    scope: 'system:read',
    iat: timestamp,
    nbf: timestamp,
    exp: timestamp + 3600,
    jti: 'reset-test-access-token',
    sid: tokenHash
  });
  assert.equal(oauth.verifyAccessToken(accessToken).clientId, 'reset-test-client');

  store.db.prepare('INSERT INTO oauth_codes VALUES(?,?,?,?,?,?,?,?,NULL)')
    .run('c'.repeat(64), 'reset-test-client', 'https://chatgpt.com/callback', 'd'.repeat(43), 'system:read', oauth.RESOURCE, 'serverops-owner', timestamp + 300);
  store.db.prepare('INSERT INTO grants VALUES(?,?,?,?,NULL)')
    .run('g'.repeat(64), 'network_request', null, timestamp + 300);
  store.db.prepare('INSERT INTO pending_admin_approvals(approval_id,action,payload_json,payload_hash,actor,created_at,expires_at) VALUES(?,?,?,?,?,?,?)')
    .run('11111111-1111-4111-8111-111111111111', 'command_execute', '{}', 'e'.repeat(64), 'reset-test-client', timestamp, timestamp + 300);

  const outcome = bootstrap.resetPasswordLocally('NewOwnerPassword456!');
  assert.equal(outcome.ok, true);
  assert.match(outcome.message, /refresh sessions/);
  assert.equal(bootstrap.verifyPasswordHash('NewOwnerPassword456!', store.getOwnerPasswordHash()), true);
  assert.equal(bootstrap.verifyPasswordHash('StrongPassword123!', store.getOwnerPasswordHash()), false);
  assert.throws(() => oauth.verifyAccessToken(accessToken), /invalid_session/);
  assert.equal(store.db.prepare('SELECT COUNT(*) AS count FROM oauth_codes').get().count, 0);
  assert.equal(store.db.prepare('SELECT COUNT(*) AS count FROM grants').get().count, 0);
  const pending = store.db.prepare('SELECT denied_at FROM pending_admin_approvals WHERE approval_id=?').get('11111111-1111-4111-8111-111111111111');
  assert.ok(pending.denied_at);
});
