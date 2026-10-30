import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-execution-test-'));
const salt = 'execution-test-salt';
process.env.NODE_ENV = 'test';
process.env.SERVEROPS_OAUTH_SIGNING_KEY = 'execution-test-signing-key-that-is-at-least-thirty-two-bytes';
process.env.SERVEROPS_DATA_DIR = path.join(testRoot, 'data');
process.env.SERVEROPS_TEST_SECRET = 'must-not-reach-child';

const store = await import('../app/storage.js');
const { ExecutionEngine } = await import('../app/execution-engine.js');
const engine = new ExecutionEngine({
  db: store.db,
  dataDir: path.join(testRoot, 'executions'),
  concurrency: 1,
  queueLimit: 4,
  maxTimeoutSeconds: 30,
  maxOutputBytes: 4 * 1024 * 1024,
  audit: store.audit
});

async function waitFor(executionId, states, timeoutMs = 5000) {
  const wanted = new Set(states);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const status = engine.status(executionId);
    if (wanted.has(status.status)) return status;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error(`timed_out_waiting_for:${[...wanted].join(',')}`);
}

test('privileged engine supports runtimes, stdin, cwd and secret isolation', async () => {
  const bash = await engine.execute({
    command: "read value; printf '%s|%s|%s' \"$value\" \"$JOB_FLAG\" \"$PWD\"; test -z \"${SERVEROPS_TEST_SECRET:-}\"",
    shell: 'bash',
    cwd: testRoot,
    env: { JOB_FLAG: 'approved-value' },
    stdin: 'stdin-value\n',
    timeout_seconds: 5,
    max_output_bytes: 65536
  }, 'test-operator');
  assert.equal(bash.status, 'completed');
  assert.equal(bash.exit_code, 0);
  assert.equal(bash.stdout, `stdin-value|approved-value|${testRoot}`);

  const python = await engine.execute({ command: "print('python-ok')", shell: 'python3', cwd: testRoot, timeout_seconds: 5 }, 'test-operator');
  assert.equal(python.status, 'completed');
  assert.equal(python.stdout, 'python-ok\n');

  const node = await engine.execute({ command: "process.stdout.write('node-ok')", shell: 'node', cwd: testRoot, timeout_seconds: 5 }, 'test-operator');
  assert.equal(node.status, 'completed');
  assert.equal(node.stdout, 'node-ok');

  const executable = await engine.execute({ command: '/usr/bin/printf', execution_kind: 'executable', arguments: ['%s:%s', 'direct', 'argv'], cwd: testRoot, timeout_seconds: 5 }, 'test-operator');
  assert.equal(executable.status, 'completed');
  assert.equal(executable.stdout, 'direct:argv');
});

test('multiline Bash, pipelines, stderr and output truncation are recorded', async () => {
  const output = await engine.execute({
    command: "cat <<'EOF' | tr 'a-z' 'A-Z'\nhello serverops\nEOF\nprintf 'diagnostic' >&2\nhead -c 4096 /dev/zero | tr '\\0' x",
    shell: 'bash',
    cwd: testRoot,
    timeout_seconds: 5,
    max_output_bytes: 128
  }, 'test-operator');
  assert.equal(output.status, 'completed');
  assert.match(output.stdout, /HELLO SERVEROPS/);
  assert.equal(output.stdout_page.truncated, true);
  assert.equal(output.stdout_page.total_bytes > output.stdout_page.bytes, true);
  assert.equal(output.stderr_page.total_bytes, Buffer.byteLength('diagnostic'));
});

test('async jobs can be inspected and their process groups cancelled', async () => {
  const queued = await engine.execute({ command: "printf 'started'; sleep 20", shell: 'bash', cwd: testRoot, timeout_seconds: 30, execution_mode: 'async' }, 'test-operator');
  assert.match(queued.status, /queued|starting|running/);
  await waitFor(queued.execution_id, ['running']);
  engine.cancel(queued.execution_id, 'test-operator');
  const cancelled = await waitFor(queued.execution_id, ['cancelled']);
  assert.equal(cancelled.status, 'cancelled');
  assert.equal(cancelled.pid, null);
});

test('timeouts terminate the process group and audit records omit command text', async () => {
  const marker = 'sensitive-command-marker';
  const timedOut = await engine.execute({ command: `sleep 20 # ${marker}`, shell: 'bash', cwd: testRoot, timeout_seconds: 1 }, 'test-operator');
  assert.equal(timedOut.status, 'timed_out');
  const audit = store.db.prepare("SELECT detail FROM audit WHERE action LIKE 'system_execute_%'").all();
  assert.equal(audit.length > 0, true);
  assert.equal(audit.some(row => row.detail.includes(marker)), false);
});

test.after(async () => {
  await engine.shutdown();
  fs.rmSync(testRoot, { recursive: true, force: true });
});
