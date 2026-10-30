import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-admin-test-'));
process.env.NODE_ENV = 'test';
process.env.SERVEROPS_DATA_DIR = path.join(testDir, 'data');
process.env.SERVEROPS_BACKUP_DIR = path.join(testDir, 'backups');
process.env.SERVEROPS_OAUTH_SIGNING_KEY = 'test-signing-key-for-admin-tests-at-least-thirty-two-bytes';

const admin = await import('../app/admin.js');
const store = await import('../app/storage.js');

test('admin: prepareApproval produces one-time token bound to payload hash', () => {
  const filePath = path.join(testDir, 'test-file.txt');
  const payload = { path: filePath, content: 'hello world', mode: '0640' };
  const prep = admin.prepareApproval('file_write', payload, 'test-client');

  assert.equal(prep.action, 'file_write');
  assert.ok(prep.approval_id);
  assert.ok(prep.payload_hash);
  assert.equal(prep.status, 'pending_owner_approval');
  assert.equal(prep.token_issued, false);
  assert.equal(prep.approval_token, undefined);

  assert.throws(() => {
    admin.write(filePath, 'hello world', '0640', 'unapproved-token-value-123456', 'ROOT_ACTION_APPROVED');
  }, /invalid_or_expired_approval/);

  const ownerGrant = store.approvePendingAdminApproval(prep.approval_id);
  assert.ok(ownerGrant.token);

  assert.throws(() => {
    admin.write(filePath, 'different content', '0640', ownerGrant.token, 'ROOT_ACTION_APPROVED');
  }, /invalid_or_expired_approval/);

  const writeRes = admin.write(filePath, 'hello world', '0640', ownerGrant.token, 'ROOT_ACTION_APPROVED');
  assert.equal(writeRes.ok, true);
  assert.equal(fs.readFileSync(filePath, 'utf8'), 'hello world');

  // Replay fails (token is single-use)
  assert.throws(() => {
    admin.write(filePath, 'hello world', '0640', prep.approval_token, 'ROOT_ACTION_APPROVED');
  }, /invalid_or_expired_approval/);
});

test('admin: pre-mutation backup created when overwriting file', () => {
  const filePath = path.join(testDir, 'test-file.txt');
  assert.ok(fs.existsSync(filePath));

  const prep = admin.prepareApproval('file_write', { path: filePath, content: 'second version', mode: '0640' }, 'test-client');
  const ownerGrant = store.approvePendingAdminApproval(prep.approval_id);
  const writeRes = admin.write(filePath, 'second version', '0640', ownerGrant.token, 'ROOT_ACTION_APPROVED');
  assert.equal(writeRes.ok, true);
  assert.ok(writeRes.backup);
  assert.ok(fs.existsSync(writeRes.backup));
  assert.equal(fs.readFileSync(writeRes.backup, 'utf8'), 'hello world');
  assert.equal(fs.readFileSync(filePath, 'utf8'), 'second version');
});

test('admin: file removal moves to recovery backup rather than direct deletion', () => {
  const filePath = path.join(testDir, 'to-delete.txt');
  fs.writeFileSync(filePath, 'content to be removed', 'utf8');

  const prep = admin.prepareApproval('file_delete', { path: filePath }, 'test-client');
  const ownerGrant = store.approvePendingAdminApproval(prep.approval_id);
  const delRes = admin.remove(filePath, ownerGrant.token, 'ROOT_ACTION_APPROVED');
  assert.equal(delRes.ok, true);
  assert.equal(fs.existsSync(filePath), false);
  assert.ok(delRes.recovery_path);
  assert.ok(fs.existsSync(delRes.recovery_path));
  assert.equal(fs.readFileSync(delRes.recovery_path, 'utf8'), 'content to be removed');
});

test('admin: execution, network, and job-cancel grants are one-time and payload-bound', () => {
  const executionPayload = {
    command: "process.stdout.write('ok')",
    execution_kind: 'script',
    arguments: [],
    shell: 'node',
    cwd: '/tmp',
    env_sha256: 'a'.repeat(64),
    stdin_sha256: 'b'.repeat(64),
    timeout_seconds: 30,
    execution_mode: 'sync',
    max_output_bytes: 2097152
  };
  const execution = admin.prepareApproval('system_execute', executionPayload, 'test-client');
  const executionGrant = store.approvePendingAdminApproval(execution.approval_id);
  admin.requireApproval('system_execute', executionPayload, executionGrant.token, 'ROOT_ACTION_APPROVED');
  assert.throws(() => admin.requireApproval('system_execute', executionPayload, executionGrant.token, 'ROOT_ACTION_APPROVED'), /invalid_or_expired_approval/);

  const networkPayload = { action: 'http_request', url: 'https://example.com/', method: 'POST', allow_private_network: false };
  const network = admin.prepareApproval('network_request', networkPayload, 'test-client');
  const networkGrant = store.approvePendingAdminApproval(network.approval_id);
  admin.requireApproval('network_request', networkPayload, networkGrant.token, 'ROOT_ACTION_APPROVED');
  assert.throws(() => admin.requireApproval('network_request', networkPayload, networkGrant.token, 'ROOT_ACTION_APPROVED'), /invalid_or_expired_approval/);

  const cancelPayload = { execution_id: '123e4567-e89b-12d3-a456-426614174000' };
  const cancel = admin.prepareApproval('job_cancel', cancelPayload, 'test-client');
  const cancelGrant = store.approvePendingAdminApproval(cancel.approval_id);
  admin.requireApproval('job_cancel', cancelPayload, cancelGrant.token, 'ROOT_ACTION_APPROVED');
  assert.throws(() => admin.requireApproval('job_cancel', cancelPayload, cancelGrant.token, 'ROOT_ACTION_APPROVED'), /invalid_or_expired_approval/);
});


test('admin: denied and expired owner approvals never issue grants', () => {
  const denied = store.createPendingAdminApproval({
    action: 'file_delete',
    payload: { path: '/tmp/denied' },
    review: { path: '/tmp/denied' },
    payloadHash: 'a'.repeat(64),
    actor: 'test-client'
  });
  store.denyPendingAdminApproval(denied.approvalId);
  assert.throws(() => store.approvePendingAdminApproval(denied.approvalId), /approval_not_pending/);

  const expired = store.createPendingAdminApproval({
    action: 'file_delete',
    payload: { path: '/tmp/expired' },
    review: { path: '/tmp/expired' },
    payloadHash: 'b'.repeat(64),
    actor: 'test-client',
    ttlSeconds: 60
  });
  store.db.prepare('UPDATE pending_admin_approvals SET expires_at=? WHERE approval_id=?')
    .run(store.now() - 1, expired.approvalId);
  assert.throws(() => store.approvePendingAdminApproval(expired.approvalId), /approval_request_expired/);
});

test.after(() => {
  fs.rmSync(testDir, { recursive: true, force: true });
});
