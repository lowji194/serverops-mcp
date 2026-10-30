import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { config } from './config.js';
import * as store from './storage.js';

const execFileAsync = promisify(execFile);
const backupRoot = path.join(config.backupDir, 'admin');

try {
  fs.mkdirSync(backupRoot, { recursive: true, mode: 0o700 });
} catch {}

function absolute(input) {
  const value = path.resolve('/', String(input || ''));
  if (!value.startsWith('/')) throw new Error('absolute_path_required');
  return value;
}

function payloadHash(action, payload) {
  return crypto.createHash('sha256').update(JSON.stringify({ action, payload })).digest('hex');
}

export function prepareApproval(action, payload, actor = 'unknown', reviewPayload = payload) {
  const supportedActions = new Set([
    'file_write', 'directory_create', 'file_move', 'file_delete', 'file_chmod',
    'file_chown', 'service_action', 'command_execute', 'system_execute',
    'process_signal', 'network_request', 'job_cancel'
  ]);
  if (!supportedActions.has(action)) throw new Error('unsupported_approval_action');

  let canonical = payload;
  if (action === 'file_write') {
    canonical = {
      path: absolute(payload.path),
      content_sha256: crypto.createHash('sha256').update(String(payload.content ?? '')).digest('hex'),
      mode: payload.mode || null
    };
  }
  if (action === 'directory_create') canonical = { path: absolute(payload.path), mode: payload.mode || '0750' };
  if (action === 'file_move') canonical = { source: absolute(payload.source), destination: absolute(payload.destination) };
  if (action === 'file_delete') canonical = { path: absolute(payload.path) };
  if (action === 'service_action') canonical = { service: String(payload.service), action: String(payload.action) };
  if (action === 'command_execute') canonical = { command: String(payload.command), timeout_seconds: Number(payload.timeout_seconds ?? 30) };
  if (action === 'system_execute') canonical = payload;
  if (action === 'file_chmod') canonical = { path: absolute(payload.path), mode: String(payload.mode) };
  if (action === 'file_chown') canonical = { path: absolute(payload.path), uid: Number(payload.uid), gid: Number(payload.gid) };
  if (action === 'process_signal') canonical = { pid: Number(payload.pid), signal: String(payload.signal || 'SIGTERM').toUpperCase() };
  if (action === 'job_cancel') canonical = { execution_id: String(payload.execution_id) };

  const hash = payloadHash(action, canonical);
  const pending = store.createPendingAdminApproval({
    action,
    payload: canonical,
    review: reviewPayload ?? canonical,
    payloadHash: hash,
    actor,
    ttlSeconds: 600
  });
  return {
    action,
    approval_id: pending.approvalId,
    payload_hash: hash,
    status: 'pending_owner_approval',
    expires_at: pending.expiresAt,
    one_time: true,
    token_issued: false,
    owner_command: 'sudo serverops approvals list'
  };
}

export function requireApproval(action, payload, token, confirmation) {
  if (confirmation !== 'ROOT_ACTION_APPROVED') throw new Error('explicit_confirmation_required');
  const row = store.consumeGrant(token, `admin:${action}`, true, payloadHash(action, payload));
  if (!row) throw new Error('invalid_or_expired_approval');
}

function backupName(target) {
  return path.join(backupRoot, `${Date.now()}-${crypto.randomUUID()}-${path.basename(target)}`);
}

function backupExisting(target) {
  if (!fs.existsSync(target)) return null;
  const backup = backupName(target);
  fs.copyFileSync(target, backup);
  return backup;
}

export function stat(target) {
  const resolved = absolute(target);
  const stats = fs.statSync(resolved);
  return {
    path: resolved,
    exists: true,
    type: stats.isDirectory() ? 'directory' : stats.isFile() ? 'file' : stats.isSymbolicLink() ? 'symlink' : 'other',
    size: stats.size,
    mode: '0' + (stats.mode & 0o777).toString(8),
    uid: stats.uid,
    gid: stats.gid,
    mtime: stats.mtime.toISOString(),
    ctime: stats.ctime.toISOString()
  };
}

export function list(target, limit = 100) {
  const resolved = absolute(target);
  const entries = fs.readdirSync(resolved, { withFileTypes: true }).slice(0, limit).map(entry => {
    try {
      return stat(path.join(resolved, entry.name));
    } catch {
      return { path: path.join(resolved, entry.name), type: entry.isDirectory() ? 'directory' : 'other' };
    }
  });
  return { path: resolved, entries, truncated: fs.readdirSync(resolved).length > limit };
}

export function read(target, offset = 0, maxBytes = 262144) {
  const resolved = absolute(target);
  const fd = fs.openSync(resolved, 'r');
  const buffer = Buffer.alloc(maxBytes);
  try {
    const bytes = fs.readSync(fd, buffer, 0, maxBytes, offset);
    return {
      path: resolved,
      offset,
      bytes,
      truncated: offset + bytes < fs.fstatSync(fd).size,
      content: buffer.subarray(0, bytes).toString('utf8')
    };
  } finally {
    fs.closeSync(fd);
  }
}

export function write(target, content, mode, approvalToken, confirmation) {
  const resolved = absolute(target);
  const payload = {
    path: resolved,
    content_sha256: crypto.createHash('sha256').update(content).digest('hex'),
    mode: mode || null
  };
  requireApproval('file_write', payload, approvalToken, confirmation);
  const backup = backupExisting(resolved);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  const temporary = `${resolved}.serverops-${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temporary, content, { mode: mode ? Number.parseInt(mode, 8) : 0o640 });
  fs.renameSync(temporary, resolved);
  if (mode) fs.chmodSync(resolved, Number.parseInt(mode, 8));
  store.audit('admin_file_write', null, 'ok', `${resolved};backup=${backup || ''}`);
  return { ok: true, path: resolved, backup, sha256: crypto.createHash('sha256').update(content).digest('hex') };
}

export function mkdir(target, mode, approvalToken, confirmation) {
  const resolved = absolute(target);
  const payload = { path: resolved, mode };
  requireApproval('directory_create', payload, approvalToken, confirmation);
  fs.mkdirSync(resolved, { recursive: true, mode: Number.parseInt(mode, 8) });
  store.audit('admin_directory_create', null, 'ok', resolved);
  return stat(resolved);
}

export function move(source, destination, approvalToken, confirmation) {
  const from = absolute(source);
  const to = absolute(destination);
  const payload = { source: from, destination: to };
  requireApproval('file_move', payload, approvalToken, confirmation);
  const backup = backupExisting(to);
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.renameSync(from, to);
  store.audit('admin_file_move', null, 'ok', `${from}->${to};backup=${backup || ''}`);
  return { ok: true, source: from, destination: to, replaced_backup: backup };
}

export function remove(target, approvalToken, confirmation) {
  const resolved = absolute(target);
  if (['/', '/proc', '/sys', '/dev', '/run', '/boot'].includes(resolved)) {
    throw new Error('protected_system_root');
  }
  const payload = { path: resolved };
  requireApproval('file_delete', payload, approvalToken, confirmation);
  if (!fs.existsSync(resolved)) throw new Error('path_not_found');
  const recoveryPath = backupName(resolved);
  fs.renameSync(resolved, recoveryPath);
  store.audit('admin_file_delete', null, 'ok', `${resolved}->${recoveryPath}`);
  return { ok: true, path: resolved, recovery_path: recoveryPath };
}

export function chmod(target, mode, approvalToken, confirmation) {
  const resolved = absolute(target);
  const payload = { path: resolved, mode: String(mode) };
  requireApproval('file_chmod', payload, approvalToken, confirmation);
  fs.chmodSync(resolved, Number.parseInt(mode, 8));
  store.audit('admin_file_chmod', null, 'ok', `${resolved};mode=${mode}`);
  return stat(resolved);
}

export function chown(target, uid, gid, approvalToken, confirmation) {
  const resolved = absolute(target);
  const payload = { path: resolved, uid: Number(uid), gid: Number(gid) };
  requireApproval('file_chown', payload, approvalToken, confirmation);
  fs.chownSync(resolved, payload.uid, payload.gid);
  store.audit('admin_file_chown', null, 'ok', `${resolved};uid=${payload.uid};gid=${payload.gid}`);
  return stat(resolved);
}

export async function command(commandText, timeoutSeconds = 30, approvalToken, confirmation) {
  const payload = { command: commandText, timeout_seconds: timeoutSeconds };
  requireApproval('command_execute', payload, approvalToken, confirmation);
  const commandHash = crypto.createHash('sha256').update(commandText).digest('hex');
  try {
    const output = await execFileAsync('/bin/bash', ['-lc', commandText], {
      timeout: timeoutSeconds * 1000,
      maxBuffer: 4 * 1024 * 1024,
      encoding: 'utf8'
    });
    store.audit('admin_command_execute', null, 'ok', `command_sha256=${commandHash}`);
    return { ok: true, exit_code: 0, stdout: output.stdout, stderr: output.stderr };
  } catch (error) {
    store.audit('admin_command_execute', null, 'error', `command_sha256=${commandHash};error_code=${String(error.code ?? 'COMMAND_FAILED').slice(0, 64)};signal=${String(error.signal || 'none').slice(0, 32)}`);
    return {
      ok: false,
      exit_code: error.code ?? null,
      signal: error.signal ?? null,
      stdout: error.stdout || '',
      stderr: error.stderr || error.message
    };
  }
}

export async function serviceAction(service, action, approvalToken, confirmation) {
  const safeService = String(service).trim();
  const safeAction = String(action).trim();
  if (!/^[a-zA-Z0-9_.@-]+$/.test(safeService)) throw new Error('invalid_service_name');
  if (!['start', 'stop', 'restart', 'reload', 'enable', 'disable'].includes(safeAction)) {
    throw new Error('invalid_service_action');
  }
  const payload = { service: safeService, action: safeAction };
  requireApproval('service_action', payload, approvalToken, confirmation);
  try {
    const res = await execFileAsync('systemctl', [safeAction, safeService], { timeout: 15000, encoding: 'utf8' });
    store.audit('admin_service_action', null, 'ok', `${safeAction}:${safeService}`);
    return { ok: true, service: safeService, action: safeAction, output: res.stdout };
  } catch (err) {
    store.audit('admin_service_action', null, 'error', `${safeAction}:${safeService}:${err.message}`);
    return { ok: false, service: safeService, action: safeAction, error: err.stderr || err.message };
  }
}

export async function serviceStatus(service) {
  const safeService = String(service).trim();
  if (!/^[a-zA-Z0-9_.@-]+$/.test(safeService)) throw new Error('invalid_service_name');
  try {
    const res = await execFileAsync('systemctl', [
      'show', safeService, '--no-pager',
      '--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,Description'
    ], { timeout: 8000, encoding: 'utf8' });
    return { ok: true, service: safeService, active: /^ActiveState=active$/m.test(res.stdout), output: res.stdout };
  } catch (err) {
    return { ok: false, service: safeService, active: false, output: err.stdout || err.stderr || err.message };
  }
}

export async function serviceLogs(service, lines = 50) {
  const safeService = String(service).trim();
  const safeLines = Math.min(Math.max(1, Number(lines) || 50), 1000);
  if (!/^[a-zA-Z0-9_.@-]+$/.test(safeService)) throw new Error('invalid_service_name');
  try {
    const res = await execFileAsync('journalctl', ['-u', safeService, '-n', String(safeLines), '--no-pager'], { timeout: 10000, encoding: 'utf8' });
    return { ok: true, service: safeService, lines: safeLines, logs: res.stdout };
  } catch (err) {
    return { ok: false, service: safeService, error: err.stderr || err.message };
  }
}

export async function listServices(filter = '') {
  try {
    const args = ['list-units', '--type=service', '--no-pager', '--no-legend'];
    if (filter) args.push(String(filter));
    const res = await execFileAsync('systemctl', args, { timeout: 8000, encoding: 'utf8' });
    const services = res.stdout.trim().split('\n').filter(Boolean).map(line => {
      const parts = line.trim().split(/\s+/);
      return {
        unit: parts[0],
        load: parts[1],
        active: parts[2],
        sub: parts[3],
        description: parts.slice(4).join(' ')
      };
    });
    return { ok: true, count: services.length, services };
  } catch (err) {
    return { ok: false, error: err.stderr || err.message };
  }
}

export const serviceList = listServices;

export function processSignal(pid, signal = 'SIGTERM', approvalToken, confirmation) {
  const numPid = Number(pid);
  const upperSignal = String(signal).toUpperCase();
  if (!Number.isInteger(numPid) || numPid <= 1) throw new Error('invalid_pid');
  const allowed = ['SIGTERM', 'SIGKILL', 'SIGHUP', 'SIGINT', 'SIGUSR1', 'SIGUSR2'];
  if (!allowed.includes(upperSignal)) throw new Error('unsupported_signal');

  const payload = { pid: numPid, signal: upperSignal };
  requireApproval('process_signal', payload, approvalToken, confirmation);

  try {
    process.kill(numPid, upperSignal);
    store.audit('admin_process_signal', null, 'ok', `pid=${numPid};sig=${upperSignal}`);
    return { ok: true, pid: numPid, signal: upperSignal };
  } catch (err) {
    store.audit('admin_process_signal', null, 'error', `pid=${numPid};sig=${upperSignal};${err.message}`);
    throw err;
  }
}
