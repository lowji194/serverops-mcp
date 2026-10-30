import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const salt = 'diagnostic-test-salt';
process.env.NODE_ENV = 'test';
process.env.SERVEROPS_OAUTH_SIGNING_KEY = 'diagnostic-signing-key-at-least-thirty-two-bytes';
process.env.SERVEROPS_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-diagnostics-test-'));

const store = await import('../app/storage.js');
const { classifyToolError, systemMetrics } = await import('../app/diagnostics.js');

test('diagnostics classify rejection categories consistently without secrets', () => {
  assert.equal(classifyToolError('Missing OAuth scope: system:admin'), 'forbidden');
  assert.equal(classifyToolError('explicit_confirmation_required'), 'approval_required');
  assert.equal(classifyToolError('invalid_or_expired_approval'), 'approval_invalid');
  assert.equal(classifyToolError('execution_queue_full'), 'queue_full');
  assert.equal(classifyToolError('execution timed_out'), 'execution_timeout');
  store.audit('mcp_tool_rejected', 'request-123', 'error', 'approval_invalid:system_execute');
  const summary = store.diagnosticSummary(5);
  assert.equal(summary.rejected_request_count, 1);
  assert.deepEqual(summary.error_categories, [{ category: 'approval_invalid:system_execute', count: 1 }]);
  assert.equal(summary.last_relevant_errors[0].request_id, 'request-123');
  assert.equal(summary.last_relevant_errors[0].category, 'approval_invalid:system_execute');
  assert.equal(Object.hasOwn(summary.last_relevant_errors[0], 'detail'), false);

  store.audit('admin_command_execute', 'sensitive-request', 'error', 'command_sha256=abc;stderr=DIAGNOSTIC_SECRET_MARKER;path=/tmp/private-owner-data');
  store.audit('mcp_tool_rejected', 'invalid request id', 'error', 'approval_invalid:system_execute;DIAGNOSTIC_SECRET_MARKER');
  const safeSummary = store.diagnosticSummary(5);
  const serialized = JSON.stringify(safeSummary);
  assert.equal(serialized.includes('DIAGNOSTIC_SECRET_MARKER'), false);
  assert.equal(serialized.includes('/tmp/private-owner-data'), false);
  assert.equal(Object.hasOwn(safeSummary.last_relevant_errors[0], 'detail'), false);
  assert.equal(safeSummary.last_relevant_errors[0].request_id, null);
  assert.equal(safeSummary.last_relevant_errors[0].category, 'tool_execution_failed');
});

test('diagnostics: systemMetrics returns valid OS metrics', () => {
  const metrics = systemMetrics();
  assert.ok(metrics.hostname);
  assert.ok(metrics.platform);
  assert.ok(metrics.cpu.cores > 0);
  assert.ok(metrics.memory.total_bytes > 0);
  assert.ok(metrics.memory.used_percentage >= 0 && metrics.memory.used_percentage <= 100);
});
