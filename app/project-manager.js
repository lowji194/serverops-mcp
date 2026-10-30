import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { config } from './config.js';
import * as store from './storage.js';

const VERSION = '2.1.0';
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_BATCH_FILES = 30;
const MAX_BATCH_BYTES = 4 * 1024 * 1024;
const TEXT_EXTENSIONS = new Set([
  '.php', '.html', '.htm', '.css', '.scss', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.py', '.json', '.md', '.txt', '.xml', '.yml', '.yaml', '.toml', '.ini', '.conf', '.sh',
  '.sql', '.env.example', '.gitignore', '.htaccess'
]);
const SECRET_SEGMENTS = new Set([
  '.env', '.ssh', '.gnupg', 'secrets', 'secret', 'credentials', 'sessions', 'cookies',
  'oauth', 'tokens', 'private', 'private_keys', 'password_store'
]);
const SECRET_FILE_RE = /(^|[._-])(secret|token|password|passwd|credential|cookie|session|private[-_]?key)([._-]|$)/i;
const BINARY_EXT_RE = /\.(?:sqlite3?|db|pem|key|p12|pfx|crt|cer|der|mp3|mp4|mov|webm|avi|mkv|wav|flac|png|jpe?g|gif|webp|ico|woff2?|ttf|otf|zip|tar|gz|7z|rar|so|dll|exe|bin|pyc)$/i;

const DEFAULT_PROJECTS = {
  serverops: {
    id: "serverops",
    name: "ServerOps MCP Server",
    root: process.env.SERVEROPS_PROJECT_ROOT || process.cwd(),
    type: "node-express",
    permissions: ["read_only", "edit", "preview", "publish", "rollback"],
    deniedPrefixes: ["node_modules", ".git"],
    test: { command: process.execPath, args: ["--test", "tests/*.test.js"], glob: true }
  },
  sandbox: {
    id: "sandbox",
    name: "ServerOps Project Sandbox",
    root: process.env.SERVEROPS_SANDBOX_DIR || path.join(os.tmpdir(), "serverops-project-sandbox"),
    type: "node-test",
    permissions: ["read_only", "edit", "preview", "publish", "rollback"],
    deniedPrefixes: ["fixtures-protected"],
    validationIncludes: ["fixtures-protected/source.js"],
    test: { command: process.execPath, args: ["--test", "tests/*.test.js"], glob: true }
  }
};

const DYNAMIC_PROJECTS = new Map(Object.entries(DEFAULT_PROJECTS));

export function registerProject(projectDef) {
  if (!projectDef?.id || !projectDef.root) throw new Error("invalid_project_definition");
  DYNAMIC_PROJECTS.set(projectDef.id, projectDef);
}

export function unregisterProject(projectId) {
  DYNAMIC_PROJECTS.delete(projectId);
}

function getProjectRegistry() {
  return Object.fromEntries(DYNAMIC_PROJECTS.entries());
}

function now() { return Math.floor(Date.now() / 1000); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function error(code, message, hint = '') {
  const e = new Error(message); e.code = code; e.hint = hint; return e;
}
function publicError(e) {
  return { ok: false, error: { code: e?.code || 'PROJECT_INTERNAL_ERROR', message: e?.message || 'Project operation failed', hint: e?.hint || '' } };
}
function project(projectId, permission = 'read_only') {
  const p = getProjectRegistry()[projectId];
  if (!p) throw error('PROJECT_NOT_FOUND', 'Unknown project ID.', 'Call project_list to discover allowed projects.');
  if (!p.permissions.includes(permission)) throw error('PROJECT_PERMISSION_DENIED', `Project does not allow ${permission}.`);
  return p;
}
function stateRoot() {
  const root = path.join(config.dataDir, 'project-manager');
  fs.mkdirSync(root, { recursive: true, mode: 0o750 });
  return root;
}
function projectStateDir(p) {
  const dir = path.join(stateRoot(), p.id); fs.mkdirSync(dir, { recursive: true, mode: 0o750 }); return dir;
}
function statePath(p) { return path.join(projectStateDir(p), 'state.json'); }
function readState(p) {
  try { return JSON.parse(fs.readFileSync(statePath(p), 'utf8')); }
  catch { return { changes: {}, validation: null, approvals: {}, lastDeploy: null }; }
}
function writeJsonAtomic(file, value, mode = 0o640) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o750 });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode, flag: 'wx' });
  fs.renameSync(tmp, file);
}
function writeState(p, state) { writeJsonAtomic(statePath(p), state); }
function normalizeRelative(input) {
  if (typeof input !== 'string' || !input || input.length > 1024 || input.includes('\0')) throw error('PROJECT_PATH_INVALID', 'Invalid relative path.');
  const value = input.replaceAll('\\', '/');
  if (path.posix.isAbsolute(value) || value.startsWith('/') || value.split('/').some(s => s === '' || s === '.' || s === '..')) throw error('PROJECT_PATH_TRAVERSAL', 'Path must be normalized and relative to the selected project.');
  return value;
}
function globallyDenied(rel) {
  const lower = rel.toLowerCase(); const parts = lower.split('/'); const base = parts.at(-1);
  if (parts.some(part => SECRET_SEGMENTS.has(part)) || SECRET_FILE_RE.test(base) || BINARY_EXT_RE.test(base)) return true;
  return parts.some(part => part === '.git' || part === 'node_modules' || part === '__pycache__');
}
function denied(p, rel) {
  const lower = rel.toLowerCase();
  return globallyDenied(rel) || p.deniedPrefixes.some(prefix => lower === prefix.toLowerCase() || lower.startsWith(`${prefix.toLowerCase()}/`));
}
function textAllowed(rel) {
  const base = path.posix.basename(rel).toLowerCase();
  if (['dockerfile', 'makefile', 'procfile', '.gitignore', '.htaccess'].includes(base)) return true;
  if (base.endsWith('.env.example')) return true;
  return TEXT_EXTENSIONS.has(path.posix.extname(base));
}
function ensureNoSymlink(p, rel, allowMissingLeaf = false) {
  const rootReal = fs.realpathSync(p.root); let cursor = rootReal; const parts = rel.split('/');
  for (let i = 0; i < parts.length; i += 1) {
    cursor = path.join(cursor, parts[i]);
    if (!fs.existsSync(cursor)) {
      if (allowMissingLeaf && i === parts.length - 1) return cursor;
      if (allowMissingLeaf) continue;
      throw error('PROJECT_FILE_NOT_FOUND', 'File or directory does not exist.');
    }
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) throw error('PROJECT_SYMLINK_DENIED', 'Symlinks are not followed by project tools.');
    if (stat.nlink > 1 && stat.isFile()) throw error('PROJECT_HARDLINK_DENIED', 'Hardlinked files are not accepted by project tools.');
  }
  const resolvedParent = fs.realpathSync(fs.existsSync(cursor) ? cursor : path.dirname(cursor));
  if (resolvedParent !== rootReal && !resolvedParent.startsWith(`${rootReal}${path.sep}`)) throw error('PROJECT_PATH_ESCAPE', 'Resolved path escapes the project root.');
  return cursor;
}
function safePath(p, relativePath, { write = false, directory = false, allowDeniedPrefix = false } = {}) {
  const rel = normalizeRelative(relativePath);
  const lower = rel.toLowerCase();
  const deniedByProject = p.deniedPrefixes.some(prefix => lower === prefix.toLowerCase() || lower.startsWith(`${prefix.toLowerCase()}/`));
  if (globallyDenied(rel) || (deniedByProject && !allowDeniedPrefix)) throw error('PROJECT_SENSITIVE_PATH', 'This path is excluded by the project security policy.');
  if (!directory && !textAllowed(rel)) throw error('PROJECT_FILE_TYPE_DENIED', 'Only allowlisted source text files are supported.');
  return { rel, absolute: ensureNoSymlink(p, rel, write) };
}
function openSafeDirectory(p, relativePath = '') {
  const rootReal = fs.realpathSync(p.root);
  const rel = relativePath ? normalizeRelative(relativePath) : '';
  const absolute = rel ? ensureNoSymlink(p, rel) : rootReal;
  const flags = fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0);
  let fd;
  try {
    fd = fs.openSync(absolute, flags);
    const stat = fs.fstatSync(fd);
    const actual = fs.realpathSync(`/proc/self/fd/${fd}`);
    const expected = rel ? path.resolve(rootReal, rel) : rootReal;
    if (!stat.isDirectory() || actual !== expected) throw error('PROJECT_PATH_ESCAPE', 'Directory changed while it was being opened.');
    return { fd, path: `/proc/self/fd/${fd}` };
  } catch (cause) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    if (cause?.code === 'ELOOP' || cause?.code === 'ENOTDIR') throw error('PROJECT_SYMLINK_DENIED', 'Symlink or non-directory path rejected.');
    throw cause;
  }
}
function readTextFile(p, rel, { allowDeniedPrefix = false } = {}) {
  const { absolute } = safePath(p, rel, { allowDeniedPrefix });
  const rootReal = fs.realpathSync(p.root);
  const expected = path.resolve(rootReal, rel);
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let fd;
  try {
    fd = fs.openSync(absolute, flags);
    const rawStat = fs.fstatSync(fd, { bigint: true });
    if (!rawStat.isFile()) throw error('PROJECT_NOT_A_FILE', 'Requested path is not a regular file.');
    if (rawStat.nlink > 1n) throw error('PROJECT_HARDLINK_DENIED', 'Hardlinked files are not accepted by project tools.');
    const size = Number(rawStat.size);
    if (!Number.isSafeInteger(size) || size > MAX_FILE_BYTES) throw error('PROJECT_FILE_TOO_LARGE', 'File exceeds ' + MAX_FILE_BYTES + ' bytes.');
    const actual = fs.realpathSync('/proc/self/fd/' + fd);
    if (actual !== expected) throw error('PROJECT_PATH_ESCAPE', 'Opened file resolves outside its expected project path.');
    const buffer = Buffer.alloc(size);
    let offset = 0;
    while (offset < buffer.length) {
      const bytes = fs.readSync(fd, buffer, offset, buffer.length - offset, offset);
      if (bytes === 0) break;
      offset += bytes;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if (offset !== size || after.dev !== rawStat.dev || after.ino !== rawStat.ino ||
        after.size !== rawStat.size || after.mtimeNs !== rawStat.mtimeNs || after.ctimeNs !== rawStat.ctimeNs) {
      throw error('PROJECT_FILE_CHANGED_DURING_READ', 'File changed while it was being read; retry the operation.');
    }
    if (buffer.includes(0)) throw error('PROJECT_BINARY_DENIED', 'Binary files are not exposed by source tools.');
    const stat = {
      mode: Number(rawStat.mode),
      uid: Number(rawStat.uid),
      gid: Number(rawStat.gid),
      size,
      nlink: Number(rawStat.nlink)
    };
    return { content: buffer.toString('utf8'), stat, sha256: sha256(buffer) };
  } catch (cause) {
    if (cause?.code === 'ELOOP') throw error('PROJECT_SYMLINK_DENIED', 'Symlinks are not followed by project tools.');
    throw cause;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
  }
}
function stagedContent(p, rel, state = readState(p)) {
  if (state.changes[rel]) return state.changes[rel].content;
  return fs.existsSync(path.join(p.root, rel)) ? readTextFile(p, rel).content : '';
}
function baseInfo(p, rel) {
  const absolute = path.join(p.root, rel);
  if (!fs.existsSync(absolute)) return { exists: false, sha256: null, content: '' };
  const data = readTextFile(p, rel); return { exists: true, sha256: data.sha256, content: data.content };
}
function verifyExpected(base, expectedSha256) {
  if (base.exists && !expectedSha256) throw error('PROJECT_EXPECTED_SHA_REQUIRED', 'expected_sha256 is required when editing an existing file.');
  if (!base.exists && expectedSha256) throw error('PROJECT_FILE_NOT_FOUND', 'expected_sha256 was provided but the file does not exist.');
  if (base.exists && base.sha256 !== String(expectedSha256).toLowerCase()) throw error('PROJECT_SHA_CONFLICT', 'Source changed since it was read. Re-read the file and retry with the new SHA-256.');
}
function validateContent(content) {
  if (typeof content !== 'string') throw error('PROJECT_CONTENT_INVALID', 'Content must be UTF-8 text.');
  if (Buffer.byteLength(content) > MAX_FILE_BYTES) throw error('PROJECT_FILE_TOO_LARGE', `Content exceeds ${MAX_FILE_BYTES} bytes.`);
  if (content.includes('\0')) throw error('PROJECT_BINARY_DENIED', 'NUL bytes are not accepted.');
}
function applyUnifiedDiff(original, patchText, rel) {
  validateContent(patchText);
  const lines = patchText.replaceAll('\r\n', '\n').split('\n');
  const oldHeader = lines.findIndex(line => line.startsWith('--- '));
  const newHeader = lines.findIndex((line, index) => index > oldHeader && line.startsWith('+++ '));
  if (oldHeader < 0 || newHeader < 0) throw error('PROJECT_PATCH_INVALID', 'Unified diff must contain --- and +++ headers.');
  const cleanHeader = value => value.split('\t')[0].replace(/^[ab]\//, '');
  const oldName = cleanHeader(lines[oldHeader].slice(4)); const newName = cleanHeader(lines[newHeader].slice(4));
  if (![oldName, newName].some(name => name === rel || name === '/dev/null')) throw error('PROJECT_PATCH_PATH_MISMATCH', 'Patch headers do not match relative_path.');
  const source = original.replaceAll('\r\n', '\n').split('\n');
  if (source.at(-1) === '') source.pop();
  const output = []; let sourceIndex = 0; let i = newHeader + 1; let sawHunk = false;
  while (i < lines.length) {
    if (!lines[i].startsWith('@@ ')) { i += 1; continue; }
    const match = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(lines[i]);
    if (!match) throw error('PROJECT_PATCH_INVALID', 'Invalid unified diff hunk header.');
    sawHunk = true; const oldStart = Number(match[1]); const start = oldStart === 0 ? 0 : oldStart - 1;
    if (start < sourceIndex || start > source.length) throw error('PROJECT_PATCH_CONFLICT', 'Patch hunk offset is invalid for current content.');
    output.push(...source.slice(sourceIndex, start)); sourceIndex = start; i += 1;
    while (i < lines.length && !lines[i].startsWith('@@ ')) {
      const line = lines[i]; if (line.startsWith('\\ No newline')) { i += 1; continue; }
      const mark = line[0]; const value = line.slice(1);
      if (mark === ' ') { if (source[sourceIndex] !== value) throw error('PROJECT_PATCH_CONFLICT', 'Patch context does not match current content.'); output.push(value); sourceIndex += 1; }
      else if (mark === '-') { if (source[sourceIndex] !== value) throw error('PROJECT_PATCH_CONFLICT', 'Patch removal does not match current content.'); sourceIndex += 1; }
      else if (mark === '+') output.push(value);
      else if (line === '' && i === lines.length - 1) break;
      else throw error('PROJECT_PATCH_INVALID', 'Unexpected unified diff line.');
      i += 1;
    }
  }
  if (!sawHunk) throw error('PROJECT_PATCH_INVALID', 'Unified diff contains no hunks.');
  output.push(...source.slice(sourceIndex));
  return `${output.join('\n')}\n`;
}
function changeSet(p, state = readState(p)) {
  const files = Object.entries(state.changes).sort(([a], [b]) => a.localeCompare(b)).map(([relativePath, c]) => {
    const base = baseInfo(p, relativePath); return { relative_path: relativePath, operation: base.exists ? 'modify' : 'create', base_sha256: base.sha256, staged_sha256: sha256(c.content), bytes: Buffer.byteLength(c.content) };
  });
  return { files, change_set_id: sha256(JSON.stringify(files)) };
}
function stageChange(p, rel, content, expectedSha256, state) {
  safePath(p, rel, { write: true }); validateContent(content); const base = baseInfo(p, rel); verifyExpected(base, expectedSha256);
  state.changes[rel] = { content, base_sha256: base.sha256, staged_at: now() }; state.validation = null; state.approvals = {};
}
function audit(action, p, status, detail = '') { store.audit(action, p?.id || null, status, detail); }
function operationResult(fn) { try { return fn(); } catch (e) { return publicError(e); } }

export function listProjects() {
  return { ok: true, version: VERSION, projects: Object.values(getProjectRegistry()).map(p => ({ id: p.id, name: p.name, type: p.type, path: p.root, permissions: p.permissions, exists: fs.existsSync(p.root) && fs.statSync(p.root).isDirectory(), staged_changes: changeSet(p).files.length })) };
}
export function tree(projectId, relativePath = '', depth = 2, cursor = 0, limit = 200, filter = '') {
  return operationResult(() => {
    const p = project(projectId); const rel = relativePath ? normalizeRelative(relativePath) : '';
    if (rel && denied(p, rel)) throw error('PROJECT_SENSITIVE_PATH', 'This path is excluded by project policy.');
    const rootHandle = openSafeDirectory(p, rel); const entries = [];
    function walk(handle, currentRel, level) {
      if (level > depth || entries.length >= cursor + limit + 1) return;
      for (const item of fs.readdirSync(handle.path, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
        const childRel = currentRel ? `${currentRel}/${item.name}` : item.name;
        if (denied(p, childRel) || item.isSymbolicLink()) continue;
        if (!filter || childRel.toLowerCase().includes(filter.toLowerCase())) entries.push({ path: childRel, type: item.isDirectory() ? 'directory' : 'file' });
        if (item.isDirectory() && level < depth) {
          let child;
          try { child = openSafeDirectory(p, childRel); } catch { continue; }
          try { walk(child, childRel, level + 1); } finally { fs.closeSync(child.fd); }
        }
      }
    }
    try { walk(rootHandle, rel, 1); } finally { fs.closeSync(rootHandle.fd); }
    const page = entries.slice(cursor, cursor + limit);
    return { ok: true, project_id: p.id, entries: page, next_cursor: cursor + limit < entries.length ? cursor + limit : null };
  });
}
export function search(projectId, query, relativePath = '', cursor = 0, limit = 100) {
  return operationResult(() => {
    const p = project(projectId); const needle = String(query || '').trim();
    if (!needle || needle.length > 200) throw error('PROJECT_QUERY_INVALID', 'Search query must be 1-200 characters.');
    const rootHandle = openSafeDirectory(p, relativePath || ''); const found = [];
    function walk(handle, rel) {
      if (found.length >= cursor + limit + 1) return;
      for (const item of fs.readdirSync(handle.path, { withFileTypes: true })) {
        const childRel = rel ? `${rel}/${item.name}` : item.name;
        if (denied(p, childRel) || item.isSymbolicLink()) continue;
        if (item.isDirectory()) {
          let child;
          try { child = openSafeDirectory(p, childRel); } catch { continue; }
          try { walk(child, childRel); } finally { fs.closeSync(child.fd); }
          continue;
        }
        if (!item.isFile() || !textAllowed(childRel)) continue;
        let content;
        try { content = readTextFile(p, childRel).content; } catch { continue; }
        const nameMatch = childRel.toLowerCase().includes(needle.toLowerCase());
        if (nameMatch || content.toLowerCase().includes(needle.toLowerCase())) {
          const line = content.toLowerCase().indexOf(needle.toLowerCase());
          const before = line < 0 ? '' : content.slice(Math.max(0, line - 120), Math.min(content.length, line + needle.length + 120));
          found.push({ path: childRel, name_match: nameMatch, snippet: before.replace(/[\r\n]+/g, ' ').slice(0, 300) });
        }
      }
    }
    try { walk(rootHandle, relativePath || ''); } finally { fs.closeSync(rootHandle.fd); }
    return { ok: true, project_id: p.id, matches: found.slice(cursor, cursor + limit), next_cursor: cursor + limit < found.length ? cursor + limit : null };
  });
}
export function fileRead(projectId, relativePath, offset = 0, maxBytes = 262144, includeStaged = false) {
  return operationResult(() => {
    const p = project(projectId); const state = readState(p); const staged = Boolean(includeStaged && state.changes[normalizeRelative(relativePath)]); const { rel } = safePath(p, relativePath, { write: staged });
    const content = includeStaged && state.changes[rel] ? state.changes[rel].content : readTextFile(p, rel).content;
    const buffer = Buffer.from(content); const end = Math.min(buffer.length, offset + maxBytes);
    return { ok: true, project_id: p.id, relative_path: rel, content: buffer.subarray(offset, end).toString('utf8'), offset, next_offset: end < buffer.length ? end : null, bytes: buffer.length, sha256: sha256(buffer), staged: Boolean(includeStaged && state.changes[rel]) };
  });
}
export function filePut(projectId, relativePath, content, expectedSha256 = null, dryRun = false) {
  return operationResult(() => {
    const p = project(projectId, 'edit'); const rel = normalizeRelative(relativePath); const state = readState(p); stageChange(p, rel, content, expectedSha256, state); const set = changeSet(p, state);
    if (!dryRun) { writeState(p, state); audit('project_file_put', p, 'ok', `${rel}:${set.change_set_id}`); }
    return { ok: true, dry_run: dryRun, project_id: p.id, relative_path: rel, staged_sha256: sha256(content), change_set_id: set.change_set_id };
  });
}
export function filePatch(projectId, relativePath, unifiedDiff, expectedSha256 = null, dryRun = false) {
  return operationResult(() => {
    const p = project(projectId, 'edit'); const rel = normalizeRelative(relativePath); safePath(p, rel, { write: true }); const base = baseInfo(p, rel); verifyExpected(base, expectedSha256);
    const content = applyUnifiedDiff(base.content, unifiedDiff, rel); const state = readState(p); state.changes[rel] = { content, base_sha256: base.sha256, staged_at: now() }; state.validation = null; state.approvals = {};
    const set = changeSet(p, state); if (!dryRun) { writeState(p, state); audit('project_file_patch', p, 'ok', `${rel}:${set.change_set_id}`); }
    return { ok: true, dry_run: dryRun, project_id: p.id, relative_path: rel, staged_sha256: sha256(content), change_set_id: set.change_set_id };
  });
}
export function filesBatch(projectId, operations, dryRun = false) {
  return operationResult(() => {
    const p = project(projectId, 'edit'); if (!Array.isArray(operations) || !operations.length || operations.length > MAX_BATCH_FILES) throw error('PROJECT_BATCH_INVALID', `Batch must contain 1-${MAX_BATCH_FILES} operations.`);
    const state = structuredClone(readState(p)); let total = 0;
    for (const op of operations) {
      const rel = normalizeRelative(op.path); const base = baseInfo(p, rel); verifyExpected(base, op.expected_sha256 || null);
      let content;
      if (op.type === 'put') content = op.content;
      else if (op.type === 'patch') content = applyUnifiedDiff(base.content, op.unified_diff, rel);
      else throw error('PROJECT_BATCH_INVALID', 'Each operation type must be put or patch.');
      validateContent(content); total += Buffer.byteLength(content); if (total > MAX_BATCH_BYTES) throw error('PROJECT_BATCH_TOO_LARGE', `Batch exceeds ${MAX_BATCH_BYTES} bytes.`);
      safePath(p, rel, { write: true }); state.changes[rel] = { content, base_sha256: base.sha256, staged_at: now() };
    }
    state.validation = null; state.approvals = {}; const set = changeSet(p, state);
    if (!dryRun) { writeState(p, state); audit('project_files_batch', p, 'ok', `${operations.length}:${set.change_set_id}`); }
    return { ok: true, dry_run: dryRun, project_id: p.id, files: set.files, change_set_id: set.change_set_id };
  });
}
function simpleDiff(rel, before, after) {
  if (before === after) return '';
  const oldLines = before.replaceAll('\r\n', '\n').split('\n'); const newLines = after.replaceAll('\r\n', '\n').split('\n');
  return [`--- a/${rel}`, `+++ b/${rel}`, `@@ -1,${oldLines.length} +1,${newLines.length} @@`, ...oldLines.map(x => `-${x}`), ...newLines.map(x => `+${x}`)].join('\n');
}
export function diff(projectId) {
  return operationResult(() => {
    const p = project(projectId); const state = readState(p); const set = changeSet(p, state); const diffs = set.files.map(file => simpleDiff(file.relative_path, baseInfo(p, file.relative_path).content, state.changes[file.relative_path].content));
    const joined = diffs.join('\n'); return { ok: true, project_id: p.id, change_set_id: set.change_set_id, files: set.files, diff: joined.slice(0, 512 * 1024), diff_truncated: joined.length > 512 * 1024 };
  });
}
function materialize(p, state, label = 'validation') {
  const dir = path.join(projectStateDir(p), 'workspaces', `${label}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
  function copy(handle, rel = '') {
    for (const item of fs.readdirSync(handle.path, { withFileTypes: true })) {
      const childRel = rel ? `${rel}/${item.name}` : item.name;
      if (denied(p, childRel) || item.isSymbolicLink()) continue;
      const dst = path.join(dir, childRel);
      if (item.isDirectory()) {
        let child;
        try { child = openSafeDirectory(p, childRel); } catch { continue; }
        fs.mkdirSync(dst, { recursive: true, mode: 0o750 });
        try { copy(child, childRel); } finally { fs.closeSync(child.fd); }
      } else if (item.isFile() && textAllowed(childRel)) {
        const data = readTextFile(p, childRel);
        fs.mkdirSync(path.dirname(dst), { recursive: true, mode: 0o750 });
        fs.writeFileSync(dst, data.content, { mode: data.stat.mode & 0o777 });
      }
    }
  }
  const rootHandle = openSafeDirectory(p, '');
  try { copy(rootHandle); } finally { fs.closeSync(rootHandle.fd); }
  for (const rel of p.validationIncludes || []) {
    const normalized = normalizeRelative(rel);
    if (!textAllowed(normalized)) throw error('PROJECT_VALIDATION_INCLUDE_DENIED', `Validation dependency is not allowlisted text source: ${normalized}`);
    const data = readTextFile(p, normalized, { allowDeniedPrefix: true });
    const dst = path.join(dir, normalized);
    fs.mkdirSync(path.dirname(dst), { recursive: true, mode: 0o750 });
    fs.writeFileSync(dst, data.content, { mode: data.stat.mode & 0o777 });
  }
  const modulesPath = path.join(p.root, 'node_modules');
  try {
    const modulesStat = fs.lstatSync(modulesPath);
    if (modulesStat.isDirectory() && !modulesStat.isSymbolicLink()) {
      fs.symlinkSync(fs.realpathSync(modulesPath), path.join(dir, 'node_modules'), 'dir');
    }
  } catch {}
  for (const [rel, c] of Object.entries(state.changes)) {
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o750 });
    fs.writeFileSync(file, c.content, { mode: 0o640 });
  }
  return dir;
}
function run(command, args, cwd, timeout = 120000) {
  const result = spawnSync(command, args, { cwd, shell: false, encoding: 'utf8', timeout, maxBuffer: 2 * 1024 * 1024, env: { PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8', NODE_ENV: 'test', HOME: '/tmp' } });
  return { command: [command, ...args].join(' '), status: result.status, signal: result.signal, stdout: String(result.stdout || '').slice(-20000), stderr: String(result.stderr || '').slice(-20000), ok: result.status === 0 };
}
function syntaxChecks(p, workspace, files) {
  const results = [];
  for (const file of files) {
    const abs = path.join(workspace, file.relative_path); const ext = path.extname(file.relative_path).toLowerCase();
    if (ext === '.php') results.push(run('/usr/bin/php', ['-l', abs], workspace, 30000));
    else if (ext === '.py') results.push(run('/usr/bin/python3', ['-m', 'py_compile', abs], workspace, 30000));
    else if (['.js', '.mjs', '.cjs'].includes(ext)) results.push(run('/usr/local/bin/node', ['--check', abs], workspace, 30000));
    else if (ext === '.json') { try { JSON.parse(fs.readFileSync(abs, 'utf8')); results.push({ command: `JSON.parse ${file.relative_path}`, status: 0, stdout: '', stderr: '', ok: true }); } catch (e) { results.push({ command: `JSON.parse ${file.relative_path}`, status: 1, stdout: '', stderr: e.message, ok: false }); } }
  }
  return results;
}

export function validate(projectId, includeTests = false) {
  return operationResult(() => {
    const p = project(projectId, 'preview'); const state = readState(p); const set = changeSet(p, state); if (!set.files.length) throw error('PROJECT_NO_CHANGES', 'No staged changes to validate.');
    const workspace = materialize(p, state); const checks = syntaxChecks(p, workspace, set.files); if (includeTests) checks.push({ command: 'untrusted project tests', status: 0, stdout: '', stderr: 'Skipped: staged test scripts are not executed by the privileged MCP service. Run them with system_execute after local owner approval.', ok: true, skipped: true });
    const passed = checks.every(x => x.ok); const validationId = crypto.randomUUID(); state.validation = { id: validationId, change_set_id: set.change_set_id, passed, checks, validated_at: now() }; state.approvals = {}; writeState(p, state);
    audit('project_validate', p, passed ? 'ok' : 'error', `${validationId}:${set.change_set_id}`);
    return { ok: passed, project_id: p.id, validation_id: validationId, change_set_id: set.change_set_id, checks, workspace };
  });
}
export function deployPreview(projectId, validationId) {
  return operationResult(() => {
    const p = project(projectId, 'preview'); const state = readState(p); const set = changeSet(p, state);
    if (!state.validation?.passed || state.validation.id !== validationId || state.validation.change_set_id !== set.change_set_id) throw error('PROJECT_VALIDATION_REQUIRED', 'A matching successful validation is required.');
    const previewId = `${Date.now()}-${set.change_set_id.slice(0, 12)}`; const workspace = materialize(p, state, 'preview');
    const record = { id: previewId, project_id: p.id, change_set_id: set.change_set_id, path: workspace, url: null, created_at: now() };
    writeJsonAtomic(path.join(projectStateDir(p), 'previews', `${previewId}.json`), record); audit('project_deploy_preview', p, 'ok', `${previewId}:${set.change_set_id}`);
    return { ok: true, preview: record, note: 'Preview is isolated and not public. A URL is returned only when a project has an explicitly configured authenticated preview host.' };
  });
}
function prepareApproval(projectId, action, binding, review, actor = 'unknown') {
  return operationResult(() => {
    const permission = action === 'publish' ? 'publish' : 'rollback';
    const p = project(projectId, permission);
    const grantAction = 'project_' + action;
    const approvalPayload = { project_id: p.id, binding };
    const payloadHash = sha256(JSON.stringify({ action: grantAction, payload: approvalPayload }));
    const pending = store.createPendingAdminApproval({
      action: grantAction,
      payload: approvalPayload,
      review,
      payloadHash,
      actor,
      ttlSeconds: 600
    });
    audit('project_' + action + '_approval_prepare', p, 'pending', pending.approvalId + ':' + binding);
    return {
      ok: true,
      project_id: p.id,
      approval_id: pending.approvalId,
      action,
      binding,
      status: 'pending_owner_approval',
      token_issued: false,
      expires_at: pending.expiresAt,
      owner_command: 'sudo serverops approvals list'
    };
  });
}
export function deployApprovalPrepare(projectId, validationId, changeSetId, actor = 'unknown') {
  const p = project(projectId, 'publish');
  const state = readState(p);
  if (!state.validation?.passed || state.validation.id !== validationId || state.validation.change_set_id !== changeSetId) {
    return publicError(error('PROJECT_VALIDATION_REQUIRED', 'Approval must reference the current successful validation and change set.'));
  }
  const files = Object.entries(state.changes || {}).map(([relative_path, change]) => ({
    relative_path,
    base_sha256: change.base_sha256,
    staged_sha256: sha256(change.content),
    bytes: Buffer.byteLength(change.content),
    content_preview: String(change.content).slice(0, 2048),
    preview_truncated: String(change.content).length > 2048
  }));
  const review = {
    project_id: p.id,
    action: 'publish',
    validation_id: validationId,
    change_set_id: changeSetId,
    service: p.service || null,
    health_url: p.healthUrl || null,
    files
  };
  return prepareApproval(projectId, 'publish', validationId + ':' + changeSetId, review, actor);
}
function consumeApproval(projectId, approvalId, token, action, binding) {
  const grantAction = 'project_' + action;
  const approvalPayload = { project_id: projectId, binding };
  const expectedHash = sha256(JSON.stringify({ action: grantAction, payload: approvalPayload }));
  if (!store.consumePendingAdminApproval(approvalId, token, grantAction, expectedHash)) {
    throw error('PROJECT_APPROVAL_INVALID', 'Owner approval is missing, expired, denied, already used, or bound to another project version.');
  }
}
function atomicProductionWrite(p, rel, content) {
  const { absolute } = safePath(p, rel, { write: true });
  fs.mkdirSync(path.dirname(absolute), { recursive: true, mode: 0o750 });
  const parentRel = path.posix.dirname(rel) === '.' ? '' : path.posix.dirname(rel);
  const parent = openSafeDirectory(p, parentRel);
  const rootReal = fs.realpathSync(p.root);
  const targetName = path.posix.basename(rel);
  const targetPath = path.join(parent.path, targetName);
  let previous = null;
  let previousFd;
  let tempPath;
  let tempFd;
  try {
    try {
      previousFd = fs.openSync(targetPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      previous = fs.fstatSync(previousFd);
      const actual = fs.realpathSync(`/proc/self/fd/${previousFd}`);
      if (!previous.isFile() || previous.nlink > 1 || actual !== path.resolve(rootReal, rel)) {
        throw error('PROJECT_HARDLINK_DENIED', 'Existing target is not a safe regular project file.');
      }
    } catch (cause) {
      if (cause?.code !== 'ENOENT') throw cause;
    } finally {
      if (previousFd !== undefined) { try { fs.closeSync(previousFd); } catch {} previousFd = undefined; }
    }
    const tempName = `${targetName}.${process.pid}.${crypto.randomBytes(5).toString('hex')}.tmp`;
    tempPath = path.join(parent.path, tempName);
    const mode = previous?.mode ? previous.mode & 0o777 : 0o640;
    tempFd = fs.openSync(tempPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), mode);
    fs.writeFileSync(tempFd, content, 'utf8');
    if (previous) fs.fchownSync(tempFd, previous.uid, previous.gid);
    fs.fsyncSync(tempFd);
    fs.closeSync(tempFd); tempFd = undefined;
    const parentReal = fs.realpathSync(parent.path);
    const expectedParent = parentRel ? path.resolve(rootReal, parentRel) : rootReal;
    if (parentReal !== expectedParent) throw error('PROJECT_PATH_ESCAPE', 'Parent directory changed before atomic replacement.');
    fs.renameSync(tempPath, targetPath);
    fs.fsyncSync(parent.fd);
  } catch (cause) {
    if (tempFd !== undefined) try { fs.closeSync(tempFd); } catch {}
    if (tempPath) try { fs.unlinkSync(tempPath); } catch {}
    throw cause;
  } finally {
    fs.closeSync(parent.fd);
  }
}
function backupChanges(p, state, deploymentId) {
  const root = path.join(config.backupDir, 'deploy', p.id, deploymentId);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const manifest = [];
  for (const rel of Object.keys(state.changes)) {
    const base = baseInfo(p, rel);
    const destination = path.join(root, 'files', rel);
    if (base.exists) {
      fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
      fs.writeFileSync(destination, base.content, { mode: 0o600, flag: 'wx' });
    }
    manifest.push({ relative_path: rel, existed: base.exists, sha256: base.sha256 });
  }
  writeJsonAtomic(path.join(root, 'manifest.json'), { deployment_id: deploymentId, project_id: p.id, project_root: p.root, created_at: now(), files: manifest }, 0o600);
  return root;
}
function healthCheck(p) {
  if (!p.healthUrl) return { ok: true, skipped: true };
  const check = run('/usr/bin/curl', ['-fsS', '--max-time', '20', '-o', '/dev/null', '-w', '%{http_code}', p.healthUrl], p.root, 30000);
  return { ok: check.ok && /^2\d\d$/.test(check.stdout.trim()), url: p.healthUrl, status: check.stdout.trim(), stderr: check.stderr };
}
export function deployPublish(projectId, validationId, changeSetId, approvalId, approvalToken, confirmation) {
  return operationResult(() => {
    const p = project(projectId, 'publish'); if (confirmation !== 'PUBLISH_PROJECT_APPROVED') throw error('PROJECT_APPROVAL_CONFIRMATION_REQUIRED', 'Explicit publish confirmation is required.');
    const state = readState(p); const set = changeSet(p, state); const binding = `${validationId}:${changeSetId}`;
    if (!state.validation?.passed || state.validation.id !== validationId || set.change_set_id !== changeSetId || state.validation.change_set_id !== changeSetId) throw error('PROJECT_VERSION_CONFLICT', 'Validation or diff no longer matches staged changes.');
    consumeApproval(p.id, approvalId, approvalToken, 'publish', binding); const deploymentId = `${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)}-${changeSetId.slice(0, 12)}`; const backup = backupChanges(p, state, deploymentId); const written = [];
    try {
      for (const [rel, c] of Object.entries(state.changes)) { const current = baseInfo(p, rel); if (current.sha256 !== c.base_sha256) throw error('PROJECT_SHA_CONFLICT', `Production changed before publish: ${rel}`); atomicProductionWrite(p, rel, c.content); written.push(rel); }
      const checks = syntaxChecks(p, p.root, set.files); if (checks.some(x => !x.ok)) throw error('PROJECT_POST_DEPLOY_VALIDATION_FAILED', 'Syntax validation failed after publish.');
      if (p.service) { const restart = run('/usr/bin/systemctl', ['restart', p.service], p.root, 60000); if (!restart.ok) throw error('PROJECT_SERVICE_RESTART_FAILED', restart.stderr || 'Service restart failed.'); }
      const health = healthCheck(p); if (!health.ok) throw error('PROJECT_HEALTHCHECK_FAILED', `Health check failed: ${health.url}`);
      state.lastDeploy = { id: deploymentId, change_set_id: changeSetId, files: written, backup, checks, health, deployed_at: now() }; state.changes = {}; state.validation = null; writeState(p, state); audit('project_deploy_publish', p, 'ok', `${deploymentId}:${changeSetId}`);
      return { ok: true, project_id: p.id, deployment: state.lastDeploy };
    } catch (e) {
      const manifest = JSON.parse(fs.readFileSync(path.join(backup, 'manifest.json'), 'utf8'));
      for (const item of manifest.files) { const target = path.join(p.root, item.relative_path); const saved = path.join(backup, 'files', item.relative_path); if (item.existed) atomicProductionWrite(p, item.relative_path, fs.readFileSync(saved, 'utf8')); else if (fs.existsSync(target)) fs.renameSync(target, path.join(backup, `failed-new-${path.basename(target)}`)); }
      if (p.service) run('/usr/bin/systemctl', ['restart', p.service], p.root, 60000); writeState(p, state); audit('project_deploy_publish', p, 'error', `${deploymentId}:${e.message}`); throw e;
    }
  });
}
function backupList(p) {
  const root = `${path.join(config.backupDir, "deploy", p.id)}`; if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return [];
  return fs.readdirSync(root, { withFileTypes: true }).filter(x => x.isDirectory()).map(x => {
    try { const m = JSON.parse(fs.readFileSync(path.join(root, x.name, 'manifest.json'), 'utf8')); return { backup_id: x.name, created_at: m.created_at, files: m.files.map(f => f.relative_path) }; } catch { return null; }
  }).filter(Boolean).sort((a, b) => b.created_at - a.created_at);
}
export function rollbackList(projectId) { return operationResult(() => { const p = project(projectId, 'rollback'); return { ok: true, project_id: p.id, backups: backupList(p) }; }); }
export function rollbackApprovalPrepare(projectId, backupId, actor = 'unknown') {
  const p = project(projectId, 'rollback');
  const backup = backupList(p).find(item => item.backup_id === backupId);
  if (!backup) return publicError(error('PROJECT_BACKUP_NOT_FOUND', 'Backup ID does not exist for this project.'));
  const review = {
    project_id: p.id,
    action: 'rollback',
    backup_id: backupId,
    created_at: backup.created_at,
    files: backup.files
  };
  return prepareApproval(projectId, 'rollback', backupId, review, actor);
}
export function rollback(projectId, backupId, approvalId, approvalToken, confirmation) {
  return operationResult(() => {
    const p = project(projectId, 'rollback'); if (confirmation !== 'ROLLBACK_PROJECT_APPROVED') throw error('PROJECT_APPROVAL_CONFIRMATION_REQUIRED', 'Explicit rollback confirmation is required.');
    const state = readState(p); consumeApproval(p.id, approvalId, approvalToken, 'rollback', backupId);
    const backup = `${path.join(config.backupDir, "deploy", p.id, backupId)}`; const manifestFile = path.join(backup, 'manifest.json'); if (!fs.existsSync(manifestFile) || !fs.statSync(manifestFile).isFile()) throw error('PROJECT_BACKUP_NOT_FOUND', 'Backup manifest not found.');
    const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8')); const safetyId = `pre-rollback-${Date.now()}`; backupChanges(p, { changes: Object.fromEntries(manifest.files.map(f => [f.relative_path, {}])) }, safetyId);
    for (const item of manifest.files) { const target = path.join(p.root, item.relative_path); const saved = path.join(backup, 'files', item.relative_path); if (item.existed) atomicProductionWrite(p, item.relative_path, fs.readFileSync(saved, 'utf8')); else if (fs.existsSync(target)) fs.renameSync(target, path.join(backup, `rolled-back-new-${path.basename(target)}-${Date.now()}`)); }
    const files = manifest.files.filter(x => fs.existsSync(path.join(p.root, x.relative_path))).map(x => ({ relative_path: x.relative_path })); const checks = syntaxChecks(p, p.root, files); if (checks.some(x => !x.ok)) throw error('PROJECT_ROLLBACK_VALIDATION_FAILED', 'Rollback syntax validation failed.');
    if (p.service) { const restart = run('/usr/bin/systemctl', ['restart', p.service], p.root, 60000); if (!restart.ok) throw error('PROJECT_SERVICE_RESTART_FAILED', restart.stderr); }
    const health = healthCheck(p); state.lastDeploy = { id: `rollback-${backupId}`, rollback: true, backup_id: backupId, checks, health, deployed_at: now() }; state.changes = {}; state.validation = null; writeState(p, state); audit('project_rollback', p, 'ok', backupId);
    return { ok: true, project_id: p.id, rollback: state.lastDeploy };
  });
}
export function deployStatus(projectId) {
  return operationResult(() => { const p = project(projectId); const state = readState(p); const set = changeSet(p, state); return { ok: true, project: { id: p.id, name: p.name, type: p.type, path: p.root, permissions: p.permissions }, version: VERSION, staged: set, validation: state.validation, last_deploy: state.lastDeploy, backups: backupList(p).slice(0, 20), production: healthCheck(p) }; });
}

