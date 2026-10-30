import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

process.env.NODE_ENV = 'test';
process.env.SERVEROPS_OAUTH_SIGNING_KEY = 'storage-test-signing-key-that-is-at-least-thirty-two-bytes';
process.env.SERVEROPS_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-storage-test-'));

const store = await import('../app/storage.js');

test('one-time grant is consumed only once', () => {
  const grant = store.createGrant('admin-action', 'asset-id', 60);
  assert.equal(store.consumeGrant(grant.token, 'admin-action').asset_id, 'asset-id');
  assert.equal(store.consumeGrant(grant.token, 'admin-action'), null);
});

test('download grant may be reusable before expiry', () => {
  const grant = store.createGrant('artifact-download', 'artifact-id', 60);
  assert.equal(store.consumeGrant(grant.token, 'artifact-download', false).asset_id, 'artifact-id');
  assert.equal(store.consumeGrant(grant.token, 'artifact-download', false).asset_id, 'artifact-id');
});

test('audit log automatically redacts Bearer tokens and passwords', () => {
  store.audit('test_audit', 'req-1', 'ok', 'Bearer secret-jwt-token-value-here password="SuperSecretPassword"');
  const row = store.db.prepare('SELECT * FROM audit WHERE action=?').get('test_audit');
  assert.ok(row);
  assert.ok(row.detail.includes('Bearer [REDACTED]'));
  assert.ok(row.detail.includes('password=[REDACTED]'));
  assert.equal(row.detail.includes('secret-jwt-token-value-here'), false);
  assert.equal(row.detail.includes('SuperSecretPassword'), false);
});
