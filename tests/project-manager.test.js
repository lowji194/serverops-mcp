import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-project-test-'));
const sandbox = path.join(testRoot, 'sandbox');
process.env.NODE_ENV = 'test';
process.env.SERVEROPS_SANDBOX_DIR = sandbox;
process.env.SERVEROPS_DATA_DIR = path.join(testRoot, 'data');
process.env.SERVEROPS_BACKUP_DIR = path.join(testRoot, 'backups');
process.env.SERVEROPS_OAUTH_SIGNING_KEY = 'test-signing-key-for-project-tests-at-least-thirty-two-bytes';

fs.mkdirSync(path.join(sandbox, 'src'), { recursive: true });
fs.mkdirSync(path.join(sandbox, 'tests'), { recursive: true });
fs.mkdirSync(path.join(sandbox, 'fixtures-protected'), { recursive: true });
fs.writeFileSync(path.join(sandbox, 'package.json'), '{"type":"module"}\n');
fs.writeFileSync(path.join(sandbox, 'src', 'value.js'), 'export const value = 1;\n');
fs.writeFileSync(path.join(sandbox, 'src', 'patched.js'), 'export const patched = 1;\n');
fs.writeFileSync(path.join(sandbox, 'fixtures-protected', 'source.js'), 'export const protectedDependency = true;\n');
fs.writeFileSync(path.join(sandbox, 'fixtures-protected', 'secret.db'), 'must-not-enter-validation\n');
fs.writeFileSync(path.join(sandbox, 'tests', 'basic.test.js'), "import test from 'node:test'; import assert from 'node:assert/strict'; import { value } from '../src/value.js'; test('value',()=>assert.equal(value,2));\n");

const projects = await import('../app/project-manager.js');
const store = await import('../app/storage.js');

test('project tools enforce boundaries and complete stage, validate, preview, publish, rollback', () => {
  assert.equal(projects.listProjects().projects.some(item => item.id === 'sandbox'), true);
  const original = projects.fileRead('sandbox', 'src/value.js');
  assert.equal(original.ok, true);
  assert.equal(projects.fileRead('sandbox', '../etc/passwd').error.code, 'PROJECT_PATH_TRAVERSAL');
  assert.equal(projects.fileRead('sandbox', '.env').error.code, 'PROJECT_SENSITIVE_PATH');
  assert.equal(projects.fileRead('sandbox', 'fixtures-protected/source.js').error.code, 'PROJECT_SENSITIVE_PATH');
  assert.equal(projects.filePut('sandbox', 'src/value.js', 'export const value = 2;\n', '0'.repeat(64)).error.code, 'PROJECT_SHA_CONFLICT');

  const patchBase = projects.fileRead('sandbox', 'src/patched.js');
  const patchText = '--- a/src/patched.js\n+++ b/src/patched.js\n@@ -1,1 +1,1 @@\n-export const patched = 1;\n+export const patched = 2;\n';
  const patched = projects.filePatch('sandbox', 'src/patched.js', patchText, patchBase.sha256);
  assert.equal(patched.ok, true);

  const staged = projects.filePut('sandbox', 'src/value.js', 'export const value = 2;\n', original.sha256);
  assert.equal(staged.ok, true);

  const added = projects.filePut('sandbox', 'src/new-file.js', 'export const added = true;\n');
  assert.equal(added.ok, true);
  assert.equal(projects.fileRead('sandbox', 'src/new-file.js', 0, 1000, true).staged, true);

  const reviewed = projects.diff('sandbox');
  assert.equal(reviewed.files.length, 3);
  assert.match(reviewed.diff, /value = 2/);

  const validation = projects.validate('sandbox', true);
  assert.equal(validation.ok, true, JSON.stringify(validation.checks));

  const preview = projects.deployPreview('sandbox', validation.validation_id);
  assert.equal(preview.ok, true);

  const approval = projects.deployApprovalPrepare('sandbox', validation.validation_id, validation.change_set_id, 'test-client');
  assert.equal(approval.ok, true);
  assert.equal(approval.status, 'pending_owner_approval');
  assert.equal(approval.approval_token, undefined);
  const publishGrant = store.approvePendingAdminApproval(approval.approval_id);

  const published = projects.deployPublish('sandbox', validation.validation_id, validation.change_set_id, approval.approval_id, publishGrant.token, 'PUBLISH_PROJECT_APPROVED');
  assert.equal(published.ok, true);
  assert.equal(fs.readFileSync(path.join(sandbox, 'src', 'value.js'), 'utf8'), 'export const value = 2;\n');

  // Rollback
  const rollbackApproval = projects.rollbackApprovalPrepare('sandbox', published.deployment.id, 'test-client');
  assert.equal(rollbackApproval.ok, true);
  assert.equal(rollbackApproval.status, 'pending_owner_approval');
  const rollbackGrant = store.approvePendingAdminApproval(rollbackApproval.approval_id);

  const rolledBack = projects.rollback('sandbox', published.deployment.id, rollbackApproval.approval_id, rollbackGrant.token, 'ROLLBACK_PROJECT_APPROVED');
  assert.equal(rolledBack.ok, true);
  assert.equal(fs.readFileSync(path.join(sandbox, 'src', 'value.js'), 'utf8'), 'export const value = 1;\n');
  assert.equal(fs.existsSync(path.join(sandbox, 'src', 'new-file.js')), false);
});

test('symlink leaves project boundary denied', () => {
  const link = path.join(sandbox, 'src', 'outside.js');
  try { fs.unlinkSync(link); } catch {}
  fs.symlinkSync('/etc/passwd', link);
  assert.equal(projects.fileRead('sandbox', 'src/outside.js').error.code, 'PROJECT_SYMLINK_DENIED');
  try { fs.unlinkSync(link); } catch {}
});

test('hardlinked files are rejected by project source reads', () => {
  const outside = path.join(testRoot, 'outside-source.js');
  const linked = path.join(sandbox, 'src', 'hardlinked.js');
  fs.writeFileSync(outside, 'export const privateValue = true;\\n');
  try {
    fs.linkSync(outside, linked);
    assert.equal(projects.fileRead('sandbox', 'src/hardlinked.js').error.code, 'PROJECT_HARDLINK_DENIED');
  } finally {
    try { fs.unlinkSync(linked); } catch {}
    try { fs.unlinkSync(outside); } catch {}
  }
});

test.after(() => {
  fs.rmSync(testRoot, { recursive: true, force: true });
});
