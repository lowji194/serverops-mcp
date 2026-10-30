import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dgram from 'node:dgram';
import path from 'node:path';
import { Readable } from 'node:stream';
import { config } from './config.js';
import * as store from './storage.js';

const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD']);
const SECRET_NAME = /^[A-Za-z0-9._-]{1,128}$/;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/;

function hash(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function absolute(value) {
  const resolved = path.resolve(String(value || ''));
  if (!path.isAbsolute(String(value || ''))) throw new Error('absolute_path_required');
  return resolved;
}
function ipv4FromGroups(high, low) {
  return [
    (high >> 8) & 255,
    high & 255,
    (low >> 8) & 255,
    low & 255
  ].join('.');
}

function ipv6Groups(address) {
  let value = String(address || '').toLowerCase().split('%')[0];
  const embedded = value.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (embedded) {
    if (!net.isIPv4(embedded[1])) return null;
    const octets = embedded[1].split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    value = value.slice(0, -embedded[1].length) + high + ':' + low;
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const parts = halves.length === 1 ? left : [...left, ...Array(missing).fill('0'), ...right];
  const groups = parts.map(part => /^[0-9a-f]{1,4}$/.test(part) ? Number.parseInt(part, 16) : NaN);
  return groups.length === 8 && groups.every(Number.isInteger) ? groups : null;
}

export function addressIsPrivate(address) {
  const value = String(address || '').toLowerCase().split('%')[0];
  if (net.isIPv4(value)) {
    const [a, b, c] = value.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224;
  }
  if (!net.isIPv6(value)) return true;
  const groups = ipv6Groups(value);
  if (!groups) return true;
  if (groups[0] === 0 && groups.slice(1).every(part => part === 0)) return true;
  if (groups.slice(0, 7).every(part => part === 0) && groups[7] === 1) return true;
  if (groups.slice(0, 5).every(part => part === 0) && groups[5] === 0xffff) {
    return addressIsPrivate(ipv4FromGroups(groups[6], groups[7]));
  }
  if (groups.slice(0, 6).every(part => part === 0)) {
    const embeddedIpv4 = ipv4FromGroups(groups[6], groups[7]);
    return addressIsPrivate(embeddedIpv4);
  }
  if ((groups[0] & 0xfe00) === 0xfc00) return true;
  if ((groups[0] & 0xffc0) === 0xfe80 || (groups[0] & 0xffc0) === 0xfec0) return true;
  if ((groups[0] & 0xff00) === 0xff00) return true;
  if (groups[0] === 0x0064 && groups[1] === 0xff9b) return true;
  if (groups[0] === 0x2002) return true;
  if (groups[0] === 0x2001 && (groups[1] <= 0x01ff || [0x0002, 0x0010, 0x0020, 0x0db8].includes(groups[1]))) return true;
  if (groups[0] === 0x3fff && groups[1] < 0x1000) return true;
  return groups[0] < 0x2000 || groups[0] > 0x3fff;
}
async function destination(hostname, allowPrivate) {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length) throw new Error('network_dns_no_addresses');
  if (!allowPrivate && records.some(record => addressIsPrivate(record.address))) throw new Error('private_network_requires_admin_approval');
  return { records, selected: records[0], private: records.some(record => addressIsPrivate(record.address)) };
}
export function pinnedLookup(selected) {
  return (_hostname, options, callback) => {
    const done = typeof options === 'function' ? options : callback;
    const wantsAll = typeof options === 'object' && options?.all === true;
    if (wantsAll) return done(null, [{ address: selected.address, family: selected.family }]);
    return done(null, selected.address, selected.family);
  };
}
function loadSecret(reference) {
  if (!SECRET_NAME.test(String(reference || ''))) throw new Error('invalid_secret_reference');
  const file = path.join(config.networkSecretDir, reference);
  const realRoot = fs.realpathSync(config.networkSecretDir);
  const realFile = fs.realpathSync(file);
  if (path.dirname(realFile) !== realRoot) throw new Error('invalid_secret_reference');
  const stat = fs.statSync(realFile);
  if (!stat.isFile() || stat.size > 65536) throw new Error('invalid_secret_file');
  return fs.readFileSync(realFile, 'utf8').replace(/[\r\n]+$/, '');
}
function requestHeaders(input) {
  const headers = {};
  for (const [name, value] of Object.entries(input.headers || {})) {
    if (!HEADER_NAME.test(name) || /[\r\n]/.test(String(value))) throw new Error('invalid_http_header');
    headers[name] = String(value);
  }
  for (const [name, reference] of Object.entries(input.secret_headers || {})) {
    if (!HEADER_NAME.test(name)) throw new Error('invalid_http_header');
    const value = loadSecret(reference);
    if (/[\r\n]/.test(value)) throw new Error('invalid_secret_header');
    headers[name] = value;
  }
  return headers;
}
function decodeBase64(value) {
  const text = String(value || '');
  if (text && (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 === 1)) throw new Error('invalid_base64_payload');
  return Buffer.from(text, 'base64');
}
function bodySpec(input) {
  const selected = [input.body_text !== undefined, input.body_base64 !== undefined, Boolean(input.source_file), Boolean(input.multipart?.length)].filter(Boolean).length;
  if (selected > 1) throw new Error('multiple_request_bodies');
  if (input.multipart?.length) {
    const manifest = input.multipart.map(part => {
      if (/[\r\n]/.test(part.name) || /[\r\n]/.test(part.filename || '') || /[\r\n]/.test(part.content_type || '')) throw new Error('invalid_multipart_header');
      if ([part.text !== undefined, part.data_base64 !== undefined, Boolean(part.file)].filter(Boolean).length > 1) throw new Error('multiple_multipart_values');
      if (part.file) { const file = absolute(part.file); const stat = fs.statSync(file); if (!stat.isFile()) throw new Error('multipart_source_not_file'); return { name: part.name, filename: path.basename(part.filename || file), content_type: part.content_type || 'application/octet-stream', file, length: stat.size, sha256: store.sha256File(file) }; }
      const buffer = part.data_base64 !== undefined ? decodeBase64(part.data_base64) : Buffer.from(part.text || '');
      return { name: part.name, filename: part.filename ? path.basename(part.filename) : null, content_type: part.content_type || 'text/plain; charset=utf-8', buffer, length: buffer.length, sha256: hash(buffer) };
    });
    const semanticHash = hash(JSON.stringify(manifest.map(({ buffer, ...part }) => part)));
    const boundary = `vps-server-${semanticHash.slice(0, 32)}`; const segments = [];
    for (const part of manifest) {
      const disposition = `form-data; name="${part.name.replaceAll('"', '')}"${part.filename ? `; filename="${part.filename.replaceAll('"', '')}"` : ''}`;
      segments.push(Buffer.from(`--${boundary}\r\nContent-Disposition: ${disposition}\r\nContent-Type: ${part.content_type}\r\n\r\n`), part.file ? { file: part.file } : part.buffer, Buffer.from('\r\n'));
    }
    segments.push(Buffer.from(`--${boundary}--\r\n`));
    const length = segments.reduce((total, segment) => total + (Buffer.isBuffer(segment) ? segment.length : fs.statSync(segment.file).size), 0);
    return { segments, length, sha256: semanticHash, contentType: `multipart/form-data; boundary=${boundary}` };
  }
  if (input.source_file) {
    const file = absolute(input.source_file); const stat = fs.statSync(file);
    if (!stat.isFile()) throw new Error('source_not_file');
    return { file, length: stat.size, sha256: store.sha256File(file) };
  }
  const buffer = input.body_base64 !== undefined ? decodeBase64(input.body_base64) : Buffer.from(input.body_text || '');
  if (buffer.length > 8 * 1024 * 1024) throw new Error('inline_body_too_large');
  return { buffer, length: buffer.length, sha256: hash(buffer) };
}
export function networkNeedsApproval(input) {
  const action = String(input.action || '');
  if (['tcp_request', 'udp_request'].includes(action)) return true;
  if (action !== 'http_request') return false;
  return !SAFE_HTTP_METHODS.has(String(input.method || 'GET').toUpperCase()) || Boolean(input.allow_private_network || input.source_file || input.destination_file || input.body_text !== undefined || input.body_base64 !== undefined || input.multipart?.length || Object.keys(input.secret_headers || {}).length);
}
export function canonicalNetworkApproval(input) {
  const body = bodySpec(input);
  return {
    action: String(input.action),
    url: input.url ? new URL(input.url).toString() : null,
    host: input.host || null,
    port: input.port ?? null,
    method: String(input.method || 'GET').toUpperCase(),
    headers_sha256: hash(JSON.stringify(Object.entries(input.headers || {}).sort())),
    secret_references: Object.entries(input.secret_headers || {}).sort(),
    body_sha256: body.sha256,
    source_file: input.source_file ? absolute(input.source_file) : null,
    destination_file: input.destination_file ? absolute(input.destination_file) : null,
    allow_private_network: Boolean(input.allow_private_network),
    timeout_ms: Number(input.timeout_ms || 30000),
    max_response_bytes: Number(input.max_response_bytes || 1048576),
    retry_count: Number(input.retry_count || 0),
    payload_sha256: hash(input.payload_base64 ? decodeBase64(input.payload_base64) : Buffer.alloc(0)),
    half_close: input.half_close !== false,
    expect_response: input.expect_response !== false,
    response_encoding: input.response_encoding || 'text',
    offset: Number(input.offset || 0),
    max_bytes: Number(input.max_bytes || 262144)
  };
}

function readArtifact(file, offset = 0, maxBytes = 262144, encoding = 'text') {
  const stat = fs.statSync(file);
  if (!stat.isFile()) throw new Error('network_artifact_invalid');
  const start = Math.min(Number.isSafeInteger(offset) ? Math.max(0, offset) : 0, stat.size);
  const limit = Math.min(1048576, Math.max(1, Number.isSafeInteger(maxBytes) ? maxBytes : 262144));
  const length = Math.min(limit, stat.size - start);
  const buffer = Buffer.alloc(length); const fd = fs.openSync(file, 'r');
  try { fs.readSync(fd, buffer, 0, length, start); } finally { fs.closeSync(fd); }
  const safeEncoding = encoding === 'base64' ? 'base64' : 'text';
  return { offset: start, next_offset: start + length, bytes: length, total_bytes: stat.size, eof: start + length >= stat.size, encoding: safeEncoding, content: safeEncoding === 'base64' ? buffer.toString('base64') : buffer.toString('utf8') };
}
async function httpOnce(input, context) {
  if (!context?.clientId || !context?.subject) throw new Error('network_artifact_owner_required');
  const url = new URL(input.url);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('http_scheme_not_allowed');
  if (url.username || url.password) throw new Error('url_credentials_not_allowed');
  const target = await destination(url.hostname, input.allow_private_network);
  const method = String(input.method || 'GET').toUpperCase();
  const body = bodySpec(input); const headers = requestHeaders(input);
  if (body.contentType && headers['Content-Type'] === undefined && headers['content-type'] === undefined) headers['Content-Type'] = body.contentType;
  if (body.length && headers['Content-Length'] === undefined && headers['content-length'] === undefined) headers['Content-Length'] = String(body.length);
  const id = crypto.randomUUID();
  const networkDir = path.join(config.dataDir, 'network');
  fs.mkdirSync(networkDir, { recursive: true, mode: 0o750 });
  const artifact = path.join(networkDir, `${id}.body`);
  const temporary = `${artifact}.tmp`;
  const timeout = Number(input.timeout_ms || 30000);
  const maxResponseBytes = Math.min(Number(input.max_response_bytes || 1048576), config.networkMaxResponseBytes);
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1) throw new Error('invalid_max_response_bytes');
  return await new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request(url, { method, headers, timeout, lookup: pinnedLookup(target.selected), servername: url.hostname }, response => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) { response.resume(); reject(Object.assign(new Error('http_redirect_not_followed'), { location: new URL(response.headers.location, url).toString() })); return; }
      const fd = fs.openSync(temporary, 'wx', 0o600);
      let bytes = 0; let failed = false;
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxResponseBytes) {
          failed = true;
          response.destroy(new Error('network_response_too_large'));
          return;
        }
        fs.writeSync(fd, chunk);
      });
      response.on('error', error => {
        try { fs.closeSync(fd); } catch {}
        try { fs.unlinkSync(temporary); } catch {}
        reject(error);
      });
      response.on('end', () => {
        if (failed) return;
        try {
          fs.closeSync(fd);
          fs.renameSync(temporary, artifact);
          let destinationFile = null;
          if (input.destination_file) {
            destinationFile = absolute(input.destination_file);
            fs.mkdirSync(path.dirname(destinationFile), { recursive: true });
            const destinationTemp = `${destinationFile}.${id}.tmp`;
            fs.copyFileSync(artifact, destinationTemp, fs.constants.COPYFILE_EXCL);
            fs.renameSync(destinationTemp, destinationFile);
          }
          const stat = fs.statSync(artifact);
          const digest = store.sha256File(artifact);
          const expiresAt = store.now() + config.networkArtifactTtlSeconds;
          store.registerNetworkArtifact({
            id,
            filePath: artifact,
            sha256: digest,
            size: stat.size,
            clientId: context.clientId,
            subject: context.subject,
            expiresAt
          });
          const responseHeaders = Object.fromEntries(Object.entries(response.headers).map(([name, value]) => [name, name === 'set-cookie' ? '[REDACTED]' : value]));
          store.audit('system_network_http', id, 'ok', `${method};host=${url.hostname};status=${response.statusCode};bytes=${bytes}`);
          resolve({
            network_id: id,
            protocol: url.protocol.slice(0, -1),
            method,
            host: url.hostname,
            resolved_address: target.selected.address,
            private_destination: target.private,
            status_code: response.statusCode,
            headers: responseHeaders,
            ...(destinationFile ? { destination_file: destinationFile } : {}),
            bytes,
            sha256: digest,
            expires_at: expiresAt,
            body_page: readArtifact(artifact, 0, Math.min(262144, bytes), input.response_encoding || 'text')
          });
        } catch (error) {
          try { fs.unlinkSync(temporary); } catch {}
          try { fs.unlinkSync(artifact); } catch {}
          reject(error);
        }
      });
    });
    request.on('timeout', () => request.destroy(new Error('network_timeout')));
    request.on('error', error => { try { fs.unlinkSync(temporary); } catch {} reject(error); });
    if (body.file) fs.createReadStream(body.file).on('error', reject).pipe(request);
    else if (body.segments) Readable.from((async function* () { for (const segment of body.segments) { if (Buffer.isBuffer(segment)) yield segment; else yield* fs.createReadStream(segment.file); } })()).on('error', reject).pipe(request);
    else request.end(body.buffer);
  });
}
async function httpRequest(input, context) {
  const retries = Number(input.retry_count || 0); const method = String(input.method || 'GET').toUpperCase();
  if (!Number.isInteger(retries) || retries < 0 || retries > 3) throw new Error('invalid_retry_count');
  if (retries && !SAFE_HTTP_METHODS.has(method)) throw new Error('retry_not_allowed_for_non_idempotent_method');
  let last;
  for (let attempt = 0; attempt <= retries; attempt += 1) { try { return { ...(await httpOnce(input, context)), attempts: attempt + 1 }; } catch (error) { last = error; if (error.location || attempt === retries) throw error; } }
  throw last;
}
async function socketRequest(input, udp = false) {
  const target = await destination(input.host, input.allow_private_network); const timeout = Number(input.timeout_ms || 30000);
  const payload = decodeBase64(input.payload_base64 || ''); const maxBytes = Math.min(Number(input.max_response_bytes || 1048576), config.networkMaxResponseBytes);
  if (udp) return await new Promise((resolve, reject) => {
    const socket = dgram.createSocket(target.selected.family === 6 ? 'udp6' : 'udp4'); const timer = setTimeout(() => { socket.close(); reject(new Error('network_timeout')); }, timeout);
    socket.once('error', error => { clearTimeout(timer); socket.close(); reject(error); });
    socket.once('message', message => { clearTimeout(timer); socket.close(); const data = message.subarray(0, maxBytes); resolve({ protocol: 'udp', host: input.host, resolved_address: target.selected.address, port: input.port, bytes: data.length, truncated: message.length > data.length, data_base64: data.toString('base64') }); });
    socket.send(payload, Number(input.port), target.selected.address, error => { if (error) return; if (input.expect_response === false) { clearTimeout(timer); socket.close(); resolve({ protocol: 'udp', host: input.host, resolved_address: target.selected.address, port: input.port, bytes_sent: payload.length, response_expected: false }); } });
  });
  return await new Promise((resolve, reject) => {
    const chunks = []; let bytes = 0; const socket = net.createConnection({ host: target.selected.address, port: Number(input.port), family: target.selected.family });
    socket.setTimeout(timeout); socket.on('connect', () => { if (payload.length) socket.write(payload); if (input.half_close !== false) socket.end(); });
    socket.on('data', chunk => { if (bytes < maxBytes) chunks.push(chunk.subarray(0, maxBytes - bytes)); bytes += chunk.length; });
    socket.on('timeout', () => socket.destroy(new Error('network_timeout'))); socket.on('error', reject);
    socket.on('close', hadError => { if (!hadError) resolve({ protocol: 'tcp', host: input.host, resolved_address: target.selected.address, port: input.port, bytes, truncated: bytes > maxBytes, data_base64: Buffer.concat(chunks).toString('base64') }); });
  });
}
export async function runNetwork(input, context = {}) {
  if (input.action === 'dns_lookup') return { hostname: input.host, records: await dns.lookup(input.host, { all: true, verbatim: true }) };
  if (input.action === 'http_request') return httpRequest(input, context);
  if (input.action === 'tcp_request') return socketRequest(input, false);
  if (input.action === 'udp_request') return socketRequest(input, true);
  if (input.action === 'artifact_read') {
    const id = String(input.network_id || '');
    if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error('invalid_network_id');
    if (!context?.clientId || !context?.subject) throw new Error('network_artifact_owner_required');
    const row = store.networkArtifactById(id);
    if (!row || row.expires_at <= store.now() || row.client_id !== context.clientId || row.subject !== context.subject) {
      throw new Error('network_artifact_not_found');
    }
    const networkRoot = fs.realpathSync(path.join(config.dataDir, 'network'));
    const artifactPath = fs.realpathSync(row.path);
    if (path.dirname(artifactPath) !== networkRoot || path.basename(artifactPath) !== `${id}.body`) {
      throw new Error('network_artifact_invalid');
    }
    const stat = fs.statSync(artifactPath);
    if (!stat.isFile() || stat.size !== row.size) throw new Error('network_artifact_invalid');
    return { network_id: id, expires_at: row.expires_at, ...readArtifact(artifactPath, input.offset, input.max_bytes, input.response_encoding) };
  }
  throw new Error('unsupported_network_action');
}
