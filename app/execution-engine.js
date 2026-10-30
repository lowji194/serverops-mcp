import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { config } from './config.js';
import * as store from './storage.js';

const ACTIVE_STATES = new Set(['queued', 'starting', 'running', 'cancelling']);
const FINAL_STATES = new Set(['completed', 'failed', 'timed_out', 'cancelled', 'unknown']);
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

function sha256(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest('hex');
}

function asPositiveInteger(value, fallback, maximum) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) throw new Error('invalid_numeric_limit');
  return parsed;
}

function resolveRunner(shell, command, executionKind = 'script', args = []) {
  if (executionKind === 'executable') {
    if (!path.isAbsolute(command)) throw new Error('executable_path_must_be_absolute');
    if (!Array.isArray(args) || args.length > 1024 || args.some(value => typeof value !== 'string' || Buffer.byteLength(value) > 65536)) throw new Error('executable_arguments_invalid');
    return { executable: command, args };
  }
  const selected = String(shell || 'bash');
  if (selected === 'bash' || selected === '/bin/bash') return { executable: '/bin/bash', args: ['-lc', command] };
  if (selected === 'sh' || selected === '/bin/sh') return { executable: '/bin/sh', args: ['-lc', command] };
  if (selected === 'python' || selected === 'python3') return { executable: '/usr/bin/python3', args: ['-c', command] };
  if (selected === 'node') return { executable: process.execPath, args: ['-e', command] };
  if (!path.isAbsolute(selected)) throw new Error('shell_must_be_builtin_or_absolute');
  return { executable: selected, args: ['-c', command] };
}

function validatedEnvironment(extra = {}) {
  // Never leak the MCP/OAuth/upstream process environment into an executed
  // command.  Privileged jobs receive a predictable login-like baseline and
  // only the additional variables explicitly bound to their approval token.
  const result = {
    PATH: process.env.PATH || '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    HOME: '/root',
    USER: 'root',
    LOGNAME: 'root',
    SHELL: '/bin/bash',
    LANG: process.env.LANG || 'C.UTF-8'
  };
  for (const [name, raw] of Object.entries(extra || {})) {
    if (!ENV_NAME.test(name)) throw new Error(`invalid_environment_name:${name}`);
    if (raw === null) delete result[name];
    else if (['string', 'number', 'boolean'].includes(typeof raw)) result[name] = String(raw);
    else throw new Error(`invalid_environment_value:${name}`);
  }
  return result;
}

function safeWorkingDirectory(input) {
  const cwd = path.resolve(String(input || '/root'));
  const stat = fs.statSync(cwd);
  if (!stat.isDirectory()) throw new Error('working_directory_not_directory');
  return cwd;
}

function readChunk(filePath, offset, limit) {
  const safeOffset = Math.max(0, Number(offset) || 0);
  const safeLimit = Math.min(1048576, Math.max(1, Number(limit) || 262144));
  let size = 0;
  try { size = fs.statSync(filePath).size; } catch { return { offset: safeOffset, next_offset: safeOffset, bytes: 0, eof: true, content: '' }; }
  if (safeOffset >= size) return { offset: safeOffset, next_offset: safeOffset, bytes: 0, eof: true, content: '' };
  const length = Math.min(safeLimit, size - safeOffset);
  const buffer = Buffer.allocUnsafe(length);
  const fd = fs.openSync(filePath, 'r');
  try {
    const bytes = fs.readSync(fd, buffer, 0, length, safeOffset);
    return { offset: safeOffset, next_offset: safeOffset + bytes, bytes, eof: safeOffset + bytes >= size, content: buffer.subarray(0, bytes).toString('utf8') };
  } finally { fs.closeSync(fd); }
}

export function canonicalExecutionApproval(input) {
  const envEntries = Object.entries(input.env || {}).sort(([a], [b]) => a.localeCompare(b));
  return {
    command_sha256: sha256(input.command),
    execution_kind: String(input.execution_kind || 'script'),
    arguments_sha256: sha256(JSON.stringify(input.arguments || [])),
    shell: String(input.shell || 'bash'),
    cwd: path.resolve(String(input.cwd || '/root')),
    env_sha256: sha256(JSON.stringify(envEntries)),
    stdin_sha256: sha256(input.stdin || ''),
    timeout_seconds: Number(input.timeout_seconds ?? 30),
    execution_mode: String(input.execution_mode || 'sync'),
    max_output_bytes: Number(input.max_output_bytes ?? 2097152)
  };
}

export class ExecutionEngine {
  constructor(options = {}) {
    this.db = options.db || store.db;
    this.dataDir = options.dataDir || path.join(config.dataDir, 'executions');
    this.concurrency = asPositiveInteger(options.concurrency, config.executionConcurrency, 64);
    this.queueLimit = asPositiveInteger(options.queueLimit, config.executionQueueLimit, 10000);
    this.maxTimeoutSeconds = asPositiveInteger(options.maxTimeoutSeconds, config.executionMaxTimeoutSeconds, 2592000);
    this.maxOutputBytes = asPositiveInteger(options.maxOutputBytes, config.executionMaxOutputBytes, 1073741824);
    this.audit = options.audit || store.audit;
    this.logger = options.logger || (() => {});
    this.queue = [];
    this.running = new Map();
    this.accepting = true;
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    this.db.exec(`CREATE TABLE IF NOT EXISTS system_executions (
      execution_id TEXT PRIMARY KEY, status TEXT NOT NULL, shell TEXT NOT NULL, cwd TEXT NOT NULL,
      command_sha256 TEXT NOT NULL, actor TEXT NOT NULL, pid INTEGER, queued_at INTEGER NOT NULL,
      started_at INTEGER, finished_at INTEGER, exit_code INTEGER, signal TEXT, timeout_seconds INTEGER NOT NULL,
      max_output_bytes INTEGER NOT NULL, stdout_path TEXT NOT NULL, stderr_path TEXT NOT NULL,
      stdout_bytes INTEGER NOT NULL DEFAULT 0, stderr_bytes INTEGER NOT NULL DEFAULT 0,
      stdout_truncated INTEGER NOT NULL DEFAULT 0, stderr_truncated INTEGER NOT NULL DEFAULT 0,
      error TEXT NOT NULL DEFAULT '', request_id TEXT
    )`);
    const columns = new Set(this.db.prepare('PRAGMA table_info(system_executions)').all().map(column => column.name));
    if (!columns.has('request_id')) this.db.exec('ALTER TABLE system_executions ADD COLUMN request_id TEXT');
    const now = Date.now();
    this.db.prepare(`UPDATE system_executions SET status='unknown', finished_at=?, pid=NULL,
      error='server_restarted_result_unknown' WHERE status IN ('queued','starting','running','cancelling')`).run(now);
  }

  execute(input, actor = 'authorized-operator', requestId = crypto.randomUUID()) {
    if (!this.accepting) throw new Error('execution_engine_shutting_down');
    if (this.queue.length + this.running.size >= this.queueLimit + this.concurrency) throw new Error('execution_queue_full');
    const command = String(input.command || '');
    if (!command || Buffer.byteLength(command) > 1048576) throw new Error('command_size_invalid');
    const cwd = safeWorkingDirectory(input.cwd);
    const timeoutSeconds = asPositiveInteger(input.timeout_seconds, 30, this.maxTimeoutSeconds);
    const maxOutputBytes = asPositiveInteger(input.max_output_bytes, 2097152, this.maxOutputBytes);
    const executionKind = String(input.execution_kind || 'script');
    if (!['script', 'executable'].includes(executionKind)) throw new Error('execution_kind_invalid');
    const runner = resolveRunner(input.shell, command, executionKind, input.arguments || []);
    const environment = validatedEnvironment(input.env);
    const stdin = String(input.stdin || '');
    if (Buffer.byteLength(stdin) > 8388608) throw new Error('stdin_too_large');
    const executionId = crypto.randomUUID();
    const traceId = String(requestId || executionId);
    const stdoutPath = path.join(this.dataDir, `${executionId}.stdout`);
    const stderrPath = path.join(this.dataDir, `${executionId}.stderr`);
    fs.writeFileSync(stdoutPath, '', { mode: 0o600, flag: 'wx' });
    fs.writeFileSync(stderrPath, '', { mode: 0o600, flag: 'wx' });
    const queuedAt = Date.now();
    this.db.prepare(`INSERT INTO system_executions
      (execution_id,status,shell,cwd,command_sha256,actor,queued_at,timeout_seconds,max_output_bytes,stdout_path,stderr_path,request_id)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(executionId, 'queued', String(input.shell || 'bash'), cwd, sha256(command), String(actor), queuedAt, timeoutSeconds, maxOutputBytes, stdoutPath, stderrPath, traceId);
    let finish;
    const finished = new Promise(resolve => { finish = resolve; });
    const job = { executionId, requestId: traceId, command, cwd, timeoutSeconds, maxOutputBytes, runner, environment, stdin, stdoutPath, stderrPath, finish, finished, mode: input.execution_mode || 'sync' };
    this.queue.push(job);
    this.audit('system_execute_queued', executionId, 'ok', `request_id=${traceId};actor=${String(actor)};command_sha256=${sha256(command)};kind=${executionKind};shell=${String(input.shell || 'bash')}`);
    this.logger({ event: 'system_execution', phase: 'queued', request_id: traceId, execution_id: executionId, actor: String(actor), execution_kind: executionKind, shell: String(input.shell || 'bash') });
    this.#drain();
    if (job.mode === 'async') return Promise.resolve(this.status(executionId));
    return finished.then(() => this.status(executionId));
  }

  #drain() {
    while (this.accepting && this.running.size < this.concurrency && this.queue.length) this.#start(this.queue.shift());
  }

  #start(job) {
    const startedAt = Date.now();
    this.db.prepare("UPDATE system_executions SET status='starting',started_at=? WHERE execution_id=?").run(startedAt, job.executionId);
    const stdoutFd = fs.openSync(job.stdoutPath, 'a');
    const stderrFd = fs.openSync(job.stderrPath, 'a');
    const state = { ...job, child: null, stdoutFd, stderrFd, stdoutBytes: 0, stderrBytes: 0, storedBytes: 0, stdoutTruncated: false, stderrTruncated: false, timedOut: false, cancelled: false, settled: false, timeout: null, killTimer: null };
    this.running.set(job.executionId, state);
    let child;
    try {
      child = spawn(job.runner.executable, job.runner.args, { cwd: job.cwd, env: job.environment, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
      state.child = child;
      this.db.prepare("UPDATE system_executions SET status='running',pid=? WHERE execution_id=?").run(child.pid, job.executionId);
      this.logger({ event: 'system_execution', phase: 'running', request_id: state.requestId, execution_id: state.executionId, pid: child.pid });
    } catch (error) {
      this.#settle(state, { status: 'failed', error: error.message });
      return;
    }
    const capture = (kind, chunk) => {
      const key = `${kind}Bytes`;
      state[key] += chunk.length;
      const remaining = Math.max(0, state.maxOutputBytes - state.storedBytes);
      if (remaining) {
        const part = chunk.subarray(0, remaining);
        fs.writeSync(kind === 'stdout' ? state.stdoutFd : state.stderrFd, part);
        state.storedBytes += part.length;
      }
      if (chunk.length > remaining) state[`${kind}Truncated`] = true;
    };
    child.stdout.on('data', chunk => capture('stdout', chunk));
    child.stderr.on('data', chunk => capture('stderr', chunk));
    child.on('error', error => this.#settle(state, { status: 'failed', error: error.message }));
    child.on('close', (code, signal) => {
      const status = state.timedOut ? 'timed_out' : state.cancelled ? 'cancelled' : code === 0 ? 'completed' : 'failed';
      this.#settle(state, { status, exitCode: Number.isInteger(code) ? code : null, signal: signal || null });
    });
    state.timeout = setTimeout(() => {
      state.timedOut = true;
      this.#terminate(state);
    }, job.timeoutSeconds * 1000);
    state.timeout.unref?.();
    child.stdin.on('error', () => {});
    child.stdin.end(job.stdin);
  }

  #terminate(state) {
    if (!state.child?.pid || state.settled) return;
    try { process.kill(-state.child.pid, 'SIGTERM'); } catch {}
    state.killTimer = setTimeout(() => { try { process.kill(-state.child.pid, 'SIGKILL'); } catch {} }, 2000);
    state.killTimer.unref?.();
  }

  #settle(state, outcome) {
    if (state.settled) return;
    state.settled = true;
    clearTimeout(state.timeout);
    clearTimeout(state.killTimer);
    try { fs.closeSync(state.stdoutFd); } catch {}
    try { fs.closeSync(state.stderrFd); } catch {}
    const finishedAt = Date.now();
    this.db.prepare(`UPDATE system_executions SET status=?,finished_at=?,exit_code=?,signal=?,pid=NULL,
      stdout_bytes=?,stderr_bytes=?,stdout_truncated=?,stderr_truncated=?,error=? WHERE execution_id=?`).run(
      outcome.status, finishedAt, outcome.exitCode ?? null, outcome.signal ?? null,
      state.stdoutBytes, state.stderrBytes, state.stdoutTruncated ? 1 : 0, state.stderrTruncated ? 1 : 0,
      String(outcome.error || '').slice(0, 500), state.executionId);
    this.running.delete(state.executionId);
    this.audit('system_execute_finished', state.executionId, outcome.status === 'completed' ? 'ok' : 'error', `request_id=${state.requestId};status=${outcome.status};exit_code=${outcome.exitCode ?? ''}`);
    this.logger({ event: 'system_execution', phase: 'finished', request_id: state.requestId, execution_id: state.executionId, status: outcome.status, exit_code: outcome.exitCode ?? null, signal: outcome.signal ?? null });
    state.finish();
    this.#drain();
  }

  status(executionId, options = {}) {
    const row = this.db.prepare('SELECT * FROM system_executions WHERE execution_id=?').get(executionId);
    if (!row) throw new Error('execution_not_found');
    const stdout = readChunk(row.stdout_path, options.stdout_offset, options.max_bytes);
    const stderr = readChunk(row.stderr_path, options.stderr_offset, options.max_bytes);
    return {
      execution_id: row.execution_id,
      request_id: row.request_id,
      status: row.status,
      exit_code: row.exit_code,
      signal: row.signal,
      pid: row.pid,
      shell: row.shell,
      cwd: row.cwd,
      queued_at: row.queued_at,
      started_at: row.started_at,
      finished_at: row.finished_at,
      duration_ms: row.started_at ? (row.finished_at || Date.now()) - row.started_at : 0,
      stdout: stdout.content,
      stderr: stderr.content,
      stdout_page: { offset: stdout.offset, next_offset: stdout.next_offset, bytes: stdout.bytes, eof: stdout.eof, total_bytes: row.stdout_bytes, truncated: Boolean(row.stdout_truncated) },
      stderr_page: { offset: stderr.offset, next_offset: stderr.next_offset, bytes: stderr.bytes, eof: stderr.eof, total_bytes: row.stderr_bytes, truncated: Boolean(row.stderr_truncated) },
      output_artifact: { execution_id: row.execution_id, pageable: true },
      error: row.error || undefined
    };
  }

  cancel(executionId, actor = 'authorized-operator', requestId = crypto.randomUUID()) {
    const row = this.db.prepare('SELECT status FROM system_executions WHERE execution_id=?').get(executionId);
    if (!row) throw new Error('execution_not_found');
    if (FINAL_STATES.has(row.status)) return this.status(executionId);
    const queuedIndex = this.queue.findIndex(job => job.executionId === executionId);
    if (queuedIndex >= 0) {
      const [job] = this.queue.splice(queuedIndex, 1);
      this.db.prepare("UPDATE system_executions SET status='cancelled',finished_at=?,error='cancelled_before_start' WHERE execution_id=?").run(Date.now(), executionId);
      job.finish();
    } else {
      const state = this.running.get(executionId);
      if (!state) throw new Error('execution_state_unavailable');
      state.cancelled = true;
      this.db.prepare("UPDATE system_executions SET status='cancelling' WHERE execution_id=?").run(executionId);
      this.#terminate(state);
    }
    this.audit('system_job_cancel', executionId, 'ok', `request_id=${String(requestId)};actor=${String(actor)}`);
    this.logger({ event: 'system_execution', phase: 'cancel_requested', request_id: String(requestId), execution_id: executionId, actor: String(actor) });
    return this.status(executionId);
  }

  inspect() {
    const counts = Object.fromEntries(this.db.prepare('SELECT status,COUNT(*) AS count FROM system_executions GROUP BY status').all().map(row => [row.status, row.count]));
    return {
      uid: process.getuid?.() ?? null,
      gid: process.getgid?.() ?? null,
      is_root: process.getuid?.() === 0,
      concurrency_limit: this.concurrency,
      running: this.running.size,
      queued: this.queue.length,
      queue_limit: this.queueLimit,
      max_timeout_seconds: this.maxTimeoutSeconds,
      max_output_bytes: this.maxOutputBytes,
      accepting: this.accepting,
      persisted_jobs_by_status: counts
    };
  }

  async shutdown() {
    this.accepting = false;
    for (const job of [...this.queue]) this.cancel(job.executionId, 'server-shutdown');
    for (const state of this.running.values()) {
      state.cancelled = true;
      this.#terminate(state);
    }
    await Promise.race([
      Promise.all([...this.running.values()].map(state => state.finished)),
      new Promise(resolve => setTimeout(resolve, 5000))
    ]);
  }
}

export const executionEngine = new ExecutionEngine({
  logger: entry => console.log(JSON.stringify({ service: 'VpsServer', ...entry }))
});
