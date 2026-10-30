import express from 'express';
import helmet from 'helmet';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { config, ensureDataDirs } from './config.js';
import { requireMcpAuth } from './auth.js';
import * as store from './storage.js';
import * as oauth from './oauth.js';
import * as admin from './admin.js';
import * as projects from './project-manager.js';
import { executionEngine, canonicalExecutionApproval } from './execution-engine.js';
import { runNetwork, networkNeedsApproval, canonicalNetworkApproval } from './network-engine.js';
import { requestContext, runWithRequestContext } from './request-context.js';
import { classifyToolError, systemMetrics } from './diagnostics.js';
import { renderAuthorizePage, escapeHtml } from './ui/authorize-template.js';
import { claimServer, initializeBootstrapToken } from './bootstrap.js';

const APP_VERSION = '1.1.0';

ensureDataDirs();

// Initialize bootstrap token if server is unclaimed
const bootstrapInfo = initializeBootstrapToken(false);
if (bootstrapInfo?.token) {
  console.log(JSON.stringify({
    event: 'bootstrap_initialized',
    message: 'ServerOps first-run activation required. One-time token generated (TTL 15m).',
    token_file: bootstrapInfo.tokenFile,
    expires_at: bootstrapInfo.expiresAt
  }));
}

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '16mb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

app.use((req, res, next) => {
  if (req.path !== '/mcp') return next();
  const supplied = String(req.get('x-request-id') || '');
  req.requestId = /^[A-Za-z0-9._-]{8,100}$/.test(supplied) ? supplied : crypto.randomUUID();
  const started = Date.now();
  console.log(JSON.stringify({
    event: 'mcp_request_received',
    service: 'ServerOps MCP',
    request_id: req.requestId,
    http_method: req.method,
    rpc_method: req.body?.method || null,
    tool: req.body?.params?.name || null
  }));
  res.on('finish', () => {
    const elapsed = Date.now() - started;
    console.log(JSON.stringify({
      event: 'mcp_request_finished',
      service: 'ServerOps MCP',
      request_id: req.requestId,
      http_method: req.method,
      rpc_method: req.body?.method || null,
      tool: req.body?.params?.name || null,
      http_status: res.statusCode,
      duration_ms: elapsed,
      client_id: req.authInfo?.clientId || null,
      subject: req.authInfo?.subject || null
    }));
  });
  next();
});

const rateBuckets = new Map();
function rateLimit(limit, windowMs) {
  return (req, res, next) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    let bucket = rateBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      rateBuckets.set(key, bucket);
    }
    bucket.count += 1;
    if (bucket.count > limit) {
      return res.status(429).json({ error: 'rate_limited', retry_after_seconds: Math.ceil((bucket.resetAt - now) / 1000) });
    }
    next();
  };
}

function checkOrigin(req, res, next) {
  const origin = req.get('origin');
  if (!origin) return next();
  try {
    const url = new URL(origin);
    const host = url.hostname;
    const exactGoogleOrigins = new Set([
      'https://gemini.google.com',
      'https://aistudio.google.com'
    ]);
    const allowed =
      host === 'localhost' ||
      host === '127.0.0.1' ||
      url.origin === config.publicBaseUrl ||
      url.origin === config.oauthIssuer ||
      exactGoogleOrigins.has(url.origin) ||
      host === 'chatgpt.com' ||
      host.endsWith('.chatgpt.com') ||
      host === 'openai.com' ||
      host.endsWith('.openai.com') ||
      oauth.GOOGLE_REDIRECT_HOSTS.has(host);
    if (allowed) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
      res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID, x-request-id');
      res.set('Access-Control-Expose-Headers', 'Mcp-Session-Id, MCP-Protocol-Version, WWW-Authenticate');
      res.set('Access-Control-Allow-Credentials', 'true');
      if (req.method === 'OPTIONS') return res.status(204).end();
      return next();
    }
  } catch {}
  return res.status(403).json({ error: 'origin_not_allowed' });
}
function result(data) {
  return { content: [{ type: 'text', text: JSON.stringify(data) }], structuredContent: data };
}

function fail(error) {
  const message = error instanceof Error ? error.message : String(error);
  const context = requestContext();
  store.audit('mcp_tool_rejected', context?.requestId, 'error', `${classifyToolError(error)}${context?.tool ? `:${context.tool}` : ''}`);
  return {
    content: [{ type: 'text', text: message }],
    structuredContent: { ok: false, error: { category: classifyToolError(error), message }, request_id: context?.requestId || null },
    isError: true
  };
}

function activeAuth(fallback) {
  return requestContext()?.authInfo || fallback;
}

function requireToolScope(authInfo, scope, fn) {
  return async (...args) => activeAuth(authInfo).scopes.includes(scope) ? fn(...args) : fail(`Missing OAuth scope: ${scope}`);
}

const oauthScheme = scopes => [{ type: 'oauth2', scopes }];

const execRunInputSchema = {
  command: z.string().min(1).max(2097152),
  execution_kind: z.enum(['script', 'executable']).default('script'),
  shell: z.string().max(256).default('bash'),
  arguments: z.array(z.string().max(65536)).max(1024).default([]),
  cwd: z.string().max(4096).optional(),
  env: z.record(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/), z.string().max(32768)).optional(),
  stdin: z.string().max(8388608).optional(),
  timeout_seconds: z.number().int().min(1).max(config.executionMaxTimeoutSeconds).default(30),
  max_output_bytes: z.number().int().min(1024).max(config.executionMaxOutputBytes).default(config.executionMaxOutputBytes),
  execution_mode: z.enum(['sync', 'async']).default('sync'),
  approval_token: z.string().min(20),
  confirmation: z.literal('ROOT_ACTION_APPROVED')
};

const networkInputSchema = {
  action: z.enum(['dns_lookup', 'http_request', 'tcp_request', 'udp_request', 'artifact_read']),
  url: z.string().url().max(8192).optional(),
  host: z.string().min(1).max(253).optional(),
  port: z.number().int().min(1).max(65535).optional(),
  method: z.string().regex(/^[A-Za-z]{3,10}$/).default('GET'),
  headers: z.record(z.string(), z.string()).optional(),
  secret_headers: z.record(z.string(), z.string()).optional(),
  body_text: z.string().max(8388608).optional(),
  body_base64: z.string().max(12000000).optional(),
  source_file: z.string().max(4096).optional(),
  destination_file: z.string().max(4096).optional(),
  multipart: z.array(z.object({
    name: z.string().min(1).max(128),
    filename: z.string().max(255).optional(),
    content_type: z.string().max(128).optional(),
    text: z.string().max(8388608).optional(),
    data_base64: z.string().max(12000000).optional(),
    file: z.string().max(4096).optional()
  })).max(100).optional(),
  timeout_ms: z.number().int().min(100).max(300000).default(30000),
  max_response_bytes: z.number().int().min(1024).max(config.networkMaxResponseBytes).default(1048576),
  retry_count: z.number().int().min(0).max(3).default(0),
  payload_base64: z.string().max(12000000).optional(),
  allow_private_network: z.boolean().default(false),
  half_close: z.boolean().default(true),
  expect_response: z.boolean().default(true),
  response_encoding: z.enum(['text', 'base64']).default('text'),
  network_id: z.string().uuid().optional(),
  offset: z.number().int().min(0).default(0),
  max_bytes: z.number().int().min(1).max(1048576).default(262144),
  approval_token: z.string().min(20).optional(),
  confirmation: z.literal('ROOT_ACTION_APPROVED').optional()
};

function buildServer(authInfo) {
  const server = new McpServer({ name: 'ServerOps MCP', version: APP_VERSION });
  const toolPermissionMatrix = [];
  const nativeRegisterTool = server.registerTool.bind(server);

  server.registerTool = (name, definition, handler) => {
    toolPermissionMatrix.push({
      tool: name,
      required_oauth_scopes: definition?._meta?.securitySchemes?.flatMap(scheme => scheme.scopes || []) || [],
      read_only: Boolean(definition?.annotations?.readOnlyHint),
      destructive: Boolean(definition?.annotations?.destructiveHint),
      open_world: Boolean(definition?.annotations?.openWorldHint)
    });
    return nativeRegisterTool(name, definition, handler);
  };

  // Health & Metrics
  server.registerTool('health_check', {
    title: 'ServerOps MCP health check',
    description: 'Read-only system connectivity, diagnostics, and metrics check.',
    inputSchema: {},
    _meta: { securitySchemes: oauthScheme(['system:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:read', async () => result({
    ok: true,
    service: 'ServerOps MCP',
    server_id: 'serverops-mcp',
    version: APP_VERSION,
    execution: executionEngine.inspect(),
    metrics: systemMetrics()
  })));

  server.registerTool('system_diagnostics', {
    title: 'Inspect system diagnostics and audit',
    description: 'Returns rejected requests, error categories, and recent error audits without leaking secrets.',
    inputSchema: { limit: z.number().int().min(1).max(50).default(10) },
    _meta: { securitySchemes: oauthScheme(['system:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:read', async ({ limit }) => result(store.diagnosticSummary(limit))));

  server.registerTool('system_resource_inspect', {
    title: 'Inspect system resources',
    description: 'Returns CPU, memory, uptime, load averages, and root filesystem disk usage.',
    inputSchema: {},
    _meta: { securitySchemes: oauthScheme(['system:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:read', async () => result(systemMetrics())));

  server.registerTool('system_environment_inspect', {
    title: 'Inspect host environment safe keys',
    description: 'Inspects general environment baseline without leaking server secrets or tokens.',
    inputSchema: {},
    _meta: { securitySchemes: oauthScheme(['system:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:read', async () => {
    const safeEnv = {};
    const allowed = ['PATH', 'SHELL', 'LANG', 'LC_ALL', 'USER', 'HOME', 'NODE_VERSION', 'TERM'];
    for (const key of allowed) {
      if (process.env[key]) safeEnv[key] = process.env[key];
    }
    return result({ ok: true, environment: safeEnv, node_version: process.version, platform: process.platform, arch: process.arch });
  }));

  // Filesystem Tools
  server.registerTool('root_stat', {
    title: 'Inspect file or directory metadata',
    description: 'Reads metadata (type, permissions, size, timestamps) for an absolute path.',
    inputSchema: { path: z.string().min(1).max(4096) },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ path }) => {
    try { return result(admin.stat(path)); } catch (e) { return fail(e); }
  }));

  server.registerTool('root_list', {
    title: 'List directory entries',
    description: 'Lists entries in an absolute directory path.',
    inputSchema: { path: z.string().min(1).max(4096), limit: z.number().int().min(1).max(1000).default(200) },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ path, limit }) => {
    try { return result(admin.list(path, limit)); } catch (e) { return fail(e); }
  }));

  server.registerTool('root_read', {
    title: 'Read file contents',
    description: 'Reads a slice of an absolute file up to max_bytes.',
    inputSchema: { path: z.string().min(1).max(4096), offset: z.number().int().min(0).default(0), max_bytes: z.number().int().min(1).max(1048576).default(262144) },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ path, offset, max_bytes }) => {
    try { return result(admin.read(path, offset, max_bytes)); } catch (e) { return fail(e); }
  }));

  // Approval Preparation (Required for privileged root mutations)
  server.registerTool('admin_approval_prepare', {
    title: 'Request local owner approval',
    description: 'Queues an exact privileged operation for approval on the VPS. It never issues a grant to the MCP client. The owner must review and approve it locally with the serverops CLI.',
    inputSchema: {
      action: z.enum(['file_write','directory_create','file_move','file_delete','file_chmod','file_chown','service_action','command_execute','system_execute','process_signal','network_request','job_cancel']),
      payload: z.record(z.string(), z.unknown())
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ action, payload }) => {
    try {
      const auth = activeAuth(authInfo);
      const canonical = action === 'system_execute'
        ? canonicalExecutionApproval({ ...payload, max_output_bytes: payload.max_output_bytes ?? config.executionMaxOutputBytes })
        : action === 'network_request'
          ? canonicalNetworkApproval(payload)
          : payload;
      let review = canonical;
      if (action === 'system_execute') {
        review = {
          command: String(payload.command || ''),
          execution_kind: payload.execution_kind || 'script',
          arguments: payload.arguments || [],
          shell: payload.shell || 'bash',
          cwd: payload.cwd || '/root',
          environment_keys: Object.keys(payload.env || {}).sort(),
          environment_values_hidden: true,
          env_sha256: canonical.env_sha256,
          stdin_bytes: Buffer.byteLength(String(payload.stdin || '')),
          stdin_sha256: canonical.stdin_sha256,
          timeout_seconds: canonical.timeout_seconds,
          execution_mode: canonical.execution_mode,
          max_output_bytes: canonical.max_output_bytes
        };
      } else if (action === 'network_request') {
        review = {
          ...canonical,
          header_names: Object.keys(payload.headers || {}).sort(),
          secret_header_names: Object.keys(payload.secret_headers || {}).sort(),
          body_text_preview: String(payload.body_text || '').slice(0, 2048),
          body_text_preview_truncated: String(payload.body_text || '').length > 2048,
          body_base64_supplied: payload.body_base64 !== undefined,
          multipart_parts: (payload.multipart || []).map(part => ({
            name: part.name,
            filename: part.filename || null,
            content_type: part.content_type || null,
            file: part.file || null,
            text_bytes: part.text === undefined ? null : Buffer.byteLength(part.text),
            data_base64_supplied: part.data_base64 !== undefined
          }))
        };
      } else if (action === 'file_write') {
        const content = String(payload.content || '');
        review = {
          path: payload.path,
          mode: payload.mode || null,
          content_sha256: canonical.content_sha256,
          content_bytes: Buffer.byteLength(content),
          content_preview: content.slice(0, 4096),
          content_preview_truncated: content.length > 4096
        };
      }
      return result(admin.prepareApproval(action, canonical, auth.clientId || auth.subject, review));
    } catch (e) { return fail(e); }
  }));

  server.registerTool('root_write', {
    title: 'Atomic file write with backup',
    description: 'Privileged file write with automatic backup. Requires a one-time grant issued by the VPS owner through the local CLI.',
    inputSchema: {
      path: z.string().min(1).max(4096),
      content: z.string().max(8388608),
      mode: z.string().regex(/^[0-7]{3,4}$/).optional(),
      approval_token: z.string().min(20),
      confirmation: z.literal('ROOT_ACTION_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ path, content, mode, approval_token, confirmation }) => {
    try { return result(admin.write(path, content, mode, approval_token, confirmation)); } catch (e) { return fail(e); }
  }));

  server.registerTool('root_mkdir', {
    title: 'Create directory',
    description: 'Recursively creates an absolute directory. Requires a one-time grant issued by the VPS owner through the local CLI.',
    inputSchema: {
      path: z.string().min(1).max(4096),
      mode: z.string().regex(/^[0-7]{3,4}$/).default('0750'),
      approval_token: z.string().min(20),
      confirmation: z.literal('ROOT_ACTION_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ path, mode, approval_token, confirmation }) => {
    try { return result(admin.mkdir(path, mode, approval_token, confirmation)); } catch (e) { return fail(e); }
  }));

  server.registerTool('root_move', {
    title: 'Move or rename path',
    description: 'Moves source to destination with backup. Requires a one-time grant issued by the VPS owner through the local CLI.',
    inputSchema: {
      source: z.string().min(1).max(4096),
      destination: z.string().min(1).max(4096),
      approval_token: z.string().min(20),
      confirmation: z.literal('ROOT_ACTION_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ source, destination, approval_token, confirmation }) => {
    try { return result(admin.move(source, destination, approval_token, confirmation)); } catch (e) { return fail(e); }
  }));

  server.registerTool('root_delete', {
    title: 'Safely delete path to backup',
    description: 'Moves a path to the recoverable backup directory. Requires a one-time grant issued by the VPS owner through the local CLI.',
    inputSchema: {
      path: z.string().min(1).max(4096),
      approval_token: z.string().min(20),
      confirmation: z.literal('ROOT_ACTION_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ path, approval_token, confirmation }) => {
    try { return result(admin.remove(path, approval_token, confirmation)); } catch (e) { return fail(e); }
  }));

  // Unified File Tool
  server.registerTool('system_file_manage', {
    title: 'Unified Linux file management',
    description: 'Inspects or mutates arbitrary host filesystem paths. Requires system:admin; mutations additionally require a local owner-approved one-time grant.',
    inputSchema: {
      action: z.enum(['stat','list','read','write','mkdir','move','remove','chmod','chown']),
      path: z.string().max(4096).optional(),
      source: z.string().max(4096).optional(),
      destination: z.string().max(4096).optional(),
      content: z.string().max(8388608).optional(),
      mode: z.string().regex(/^[0-7]{3,4}$/).optional(),
      uid: z.number().int().min(0).optional(),
      gid: z.number().int().min(0).optional(),
      offset: z.number().int().min(0).default(0),
      max_bytes: z.number().int().min(1).max(1048576).default(262144),
      limit: z.number().int().min(1).max(1000).default(200),
      approval_token: z.string().min(20).optional(),
      confirmation: z.enum(['ROOT_ACTION_APPROVED']).optional()
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async (input) => {
    try {
      if (input.action === 'stat') return result(admin.stat(input.path));
      if (input.action === 'list') return result(admin.list(input.path, input.limit));
      if (input.action === 'read') return result(admin.read(input.path, input.offset, input.max_bytes));
      if (!activeAuth(authInfo).scopes.includes('system:admin')) return fail('Missing OAuth scope: system:admin');
      if (input.action === 'write') return result(admin.write(input.path, input.content ?? '', input.mode, input.approval_token, input.confirmation));
      if (input.action === 'mkdir') return result(admin.mkdir(input.path, input.mode || '0750', input.approval_token, input.confirmation));
      if (input.action === 'move') return result(admin.move(input.source, input.destination, input.approval_token, input.confirmation));
      if (input.action === 'remove') return result(admin.remove(input.path, input.approval_token, input.confirmation));
      if (input.action === 'chmod') return result(admin.chmod(input.path, input.mode, input.approval_token, input.confirmation));
      if (input.action === 'chown') return result(admin.chown(input.path, input.uid, input.gid, input.approval_token, input.confirmation));
    } catch (e) { return fail(e); }
  }));

  // Systemd Services
  server.registerTool('system_services', {
    title: 'List systemd services',
    description: 'Lists systemd service units.',
    inputSchema: { filter: z.string().max(200).optional() },
    _meta: { securitySchemes: oauthScheme(['system:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:read', async ({ filter }) => result(await admin.listServices(filter))));

  server.registerTool('system_service_status', {
    title: 'Inspect systemd service status',
    description: 'Runs systemctl status on a service unit.',
    inputSchema: { service: z.string().regex(/^[A-Za-z0-9@_.:-]{1,200}$/) },
    _meta: { securitySchemes: oauthScheme(['system:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:read', async ({ service }) => result(await admin.serviceStatus(service))));

  server.registerTool('system_service_logs', {
    title: 'Read systemd service journal logs',
    description: 'Reads recent journalctl logs, which may contain sensitive data. Requires system:admin.',
    inputSchema: { service: z.string().regex(/^[A-Za-z0-9@_.:-]{1,200}$/), lines: z.number().int().min(1).max(1000).default(50) },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ service, lines }) => result(await admin.serviceLogs(service, lines))));

  server.registerTool('system_service_action', {
    title: 'Perform systemd service action',
    description: 'Start, stop, restart, reload, enable, or disable a systemd service. Requires system:admin and a local owner-approved one-time grant.',
    inputSchema: {
      service: z.string().regex(/^[A-Za-z0-9@_.:-]{1,200}$/),
      action: z.enum(['start', 'stop', 'restart', 'reload', 'enable', 'disable']),
      approval_token: z.string().min(20),
      confirmation: z.literal('ROOT_ACTION_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ service, action, approval_token, confirmation }) => {
    try { return result(await admin.serviceAction(service, action, approval_token, confirmation)); } catch (e) { return fail(e); }
  }));

  server.registerTool('system_service_manage', {
    title: 'Unified systemd service manager',
    description: 'List, status, logs, or lifecycle actions for systemd units.',
    inputSchema: {
      action: z.enum(['list','status','logs','start','stop','restart','reload','enable','disable']),
      service: z.string().regex(/^[A-Za-z0-9@_.:-]{1,200}$/).optional(),
      lines: z.number().int().min(1).max(1000).default(50),
      approval_token: z.string().min(20).optional(),
      confirmation: z.enum(['ROOT_ACTION_APPROVED']).optional()
    },
    _meta: { securitySchemes: oauthScheme(['system:read', 'system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:read', async (input) => {
    try {
      if (input.action === 'list') return result(await admin.listServices());
      if (input.action === 'status') return result(await admin.serviceStatus(input.service));
      if (input.action === 'logs') {
        if (!activeAuth(authInfo).scopes.includes('system:admin')) return fail('Missing OAuth scope: system:admin (service logs may contain secrets)');
        return result(await admin.serviceLogs(input.service, input.lines));
      }
      if (!activeAuth(authInfo).scopes.includes('system:admin')) return fail('Missing OAuth scope: system:admin');
      return result(await admin.serviceAction(input.service, input.action, input.approval_token, input.confirmation));
    } catch (e) { return fail(e); }
  }));

  // Processes & Signals
  server.registerTool('system_process', {
    title: 'Process inspection and signals',
    description: 'Send POSIX signals to a PID. Requires system:admin and a local owner-approved one-time grant.',
    inputSchema: {
      action: z.enum(['signal']),
      pid: z.number().int().min(2),
      signal: z.enum(['SIGTERM', 'SIGKILL', 'SIGHUP', 'SIGINT', 'SIGUSR1', 'SIGUSR2']).default('SIGTERM'),
      approval_token: z.string().min(20),
      confirmation: z.literal('ROOT_ACTION_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ pid, signal, approval_token, confirmation }) => {
    try { return result(admin.processSignal(pid, signal, approval_token, confirmation)); } catch (e) { return fail(e); }
  }));

  // Execution Engine Tools
  server.registerTool('system_command_execute', {
    title: 'Execute shell command with approval',
    description: 'Executes a bash command with timeout and output capture. Requires system:admin and a local owner-approved one-time grant.',
    inputSchema: {
      command: z.string().min(1).max(8192),
      timeout_seconds: z.number().int().min(1).max(300).default(30),
      approval_token: z.string().min(20),
      confirmation: z.literal('ROOT_ACTION_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ command, timeout_seconds, approval_token, confirmation }) => {
    try { return result(await admin.command(command, timeout_seconds, approval_token, confirmation)); } catch (e) { return fail(e); }
  }));

  server.registerTool('system_execute', {
    title: 'Execute script or executable in isolated execution engine',
    description: 'Multi-runner execution engine (bash, sh, python3, node, executable) with concurrency, process group control, and secret isolation. Every execution request requires a one-time grant issued by the VPS owner through the local CLI.',
    inputSchema: execRunInputSchema,
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async (input) => {
    try {
      const context = requestContext();
      admin.requireApproval('system_execute', canonicalExecutionApproval(input), input.approval_token, input.confirmation);
      return result(await executionEngine.execute(input, {
        subject: activeAuth(authInfo).subject,
        requestId: context?.requestId,
        authInfo: activeAuth(authInfo)
      }));
    } catch (e) { return fail(e); }
  }));

  server.registerTool('system_job_status', {
    title: 'Read execution job status',
    description: 'Polls status and paginated stdout/stderr for an execution job.',
    inputSchema: {
      execution_id: z.string().uuid(),
      stdout_offset: z.number().int().min(0).default(0),
      stderr_offset: z.number().int().min(0).default(0),
      max_bytes: z.number().int().min(1).max(1048576).default(262144)
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async (input) => {
    try { return result(executionEngine.status(input.execution_id, input)); } catch (e) { return fail(e); }
  }));

  server.registerTool('system_job_cancel', {
    title: 'Cancel execution job',
    description: 'Terminates the process group of a running job. Requires a one-time grant issued by the VPS owner through the local CLI.',
    inputSchema: {
      execution_id: z.string().uuid(),
      approval_token: z.string().min(20),
      confirmation: z.literal('ROOT_ACTION_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'system:admin', async ({ execution_id, approval_token, confirmation }) => {
    try {
      admin.requireApproval('job_cancel', { execution_id }, approval_token, confirmation);
      const context = requestContext();
      return result(executionEngine.cancel(execution_id, activeAuth(authInfo).subject, context?.requestId));
    } catch (e) { return fail(e); }
  }));

  // Network Engine
  server.registerTool('system_network', {
    title: 'Outbound network request dispatcher',
    description: 'Performs outbound HTTP/HTTPS requests with DNS pinning, secret injection, and SSRF protection. Elevated requests require a one-time grant issued by the VPS owner through the local CLI.',
    inputSchema: networkInputSchema,
    _meta: { securitySchemes: oauthScheme(['system:read', 'system:admin']) },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true }
  }, requireToolScope(authInfo, 'system:read', async (input) => {
    try {
      const needsAdmin = await networkNeedsApproval(input);
      if (needsAdmin && !activeAuth(authInfo).scopes.includes('system:admin')) {
        return fail('Missing OAuth scope: system:admin (private network request requires elevated approval)');
      }
      if (needsAdmin) admin.requireApproval('network_request', canonicalNetworkApproval(input), input.approval_token, input.confirmation);
      return result(await runNetwork(input, {
        clientId: activeAuth(authInfo).clientId,
        subject: activeAuth(authInfo).subject,
        requestId: requestContext()?.requestId
      }));
    } catch (e) { return fail(e); }
  }));

  // Managed Projects Tools
  server.registerTool('project_list', {
    title: 'List managed projects',
    description: 'Lists projects configured for managed staging and deployment.',
    inputSchema: {},
    _meta: { securitySchemes: oauthScheme(['project:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:read', async () => result(projects.listProjects())));

  server.registerTool('project_tree', {
    title: 'Inspect project directory tree',
    description: 'Returns file hierarchy of a managed project.',
    inputSchema: { project_id: z.string(), max_depth: z.number().int().min(1).max(10).default(5) },
    _meta: { securitySchemes: oauthScheme(['project:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:read', async ({ project_id, max_depth }) => result(projects.tree(project_id, max_depth))));

  server.registerTool('project_search', {
    title: 'Search in project files',
    description: 'Grep pattern in project files.',
    inputSchema: { project_id: z.string(), pattern: z.string().min(1).max(500), limit: z.number().int().min(1).max(100).default(30) },
    _meta: { securitySchemes: oauthScheme(['project:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:read', async ({ project_id, pattern, limit }) => result(projects.search(project_id, pattern, limit))));

  server.registerTool('project_file_read', {
    title: 'Read project file',
    description: 'Reads project file contents (including staged overlay if present).',
    inputSchema: { project_id: z.string(), relative_path: z.string().min(1), offset: z.number().int().min(0).default(0), max_bytes: z.number().int().min(1).max(1048576).default(262144), include_staged: z.boolean().default(true) },
    _meta: { securitySchemes: oauthScheme(['project:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:read', async ({ project_id, relative_path, offset, max_bytes, include_staged }) => result(projects.fileRead(project_id, relative_path, offset, max_bytes, include_staged))));

  server.registerTool('project_file_put', {
    title: 'Stage project file change',
    description: 'Stages a modified or new file in project staging.',
    inputSchema: { project_id: z.string(), relative_path: z.string().min(1), content: z.string().max(8388608), base_sha256: z.string().regex(/^[a-f0-9]{64}$/i).optional() },
    _meta: { securitySchemes: oauthScheme(['project:edit']) },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:edit', async ({ project_id, relative_path, content, base_sha256 }) => result(projects.filePut(project_id, relative_path, content, base_sha256))));

  server.registerTool('project_file_patch', {
    title: 'Apply patch to staged file',
    description: 'Applies unified diff patch to project file staging.',
    inputSchema: { project_id: z.string(), relative_path: z.string().min(1), patch_unified: z.string().max(4194304), base_sha256: z.string().regex(/^[a-f0-9]{64}$/i).optional() },
    _meta: { securitySchemes: oauthScheme(['project:edit']) },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:edit', async ({ project_id, relative_path, patch_unified, base_sha256 }) => result(projects.filePatch(project_id, relative_path, patch_unified, base_sha256))));

  server.registerTool('project_files_batch', {
    title: 'Stage multiple project files',
    description: 'Stages a batch of file updates atomically.',
    inputSchema: { project_id: z.string(), files: z.array(z.object({ relative_path: z.string().min(1), content: z.string().max(8388608), base_sha256: z.string().regex(/^[a-f0-9]{64}$/i).optional() })).min(1).max(30) },
    _meta: { securitySchemes: oauthScheme(['project:edit']) },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:edit', async ({ project_id, files }) => result(projects.filesBatch(project_id, files))));

  server.registerTool('project_diff', {
    title: 'Review staged project diff',
    description: 'Computes diff of staged changes against current production baseline.',
    inputSchema: { project_id: z.string() },
    _meta: { securitySchemes: oauthScheme(['project:preview']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:preview', async ({ project_id }) => result(projects.diff(project_id))));

  server.registerTool('project_validate', {
    title: 'Validate staged project changes in shadow workspace',
    description: 'Clones a shadow workspace and performs static syntax checks. Untrusted staged test scripts are not executed by the privileged service.',
    inputSchema: { project_id: z.string(), run_tests: z.boolean().default(false) },
    _meta: { securitySchemes: oauthScheme(['project:preview']) },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:preview', async ({ project_id, run_tests }) => result(projects.validate(project_id, run_tests))));

  server.registerTool('project_deploy_preview', {
    title: 'Preview project deployment',
    description: 'Inspects deployment preview with validation state.',
    inputSchema: { project_id: z.string(), validation_id: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/) },
    _meta: { securitySchemes: oauthScheme(['project:preview']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:preview', async ({ project_id, validation_id }) => result(projects.deployPreview(project_id, validation_id))));

  server.registerTool('project_deploy_approval_prepare', {
    title: 'Request local owner approval for project publish',
    description: 'Queues the validated staged change set for review and approval through the local serverops CLI. No token is issued to the MCP client.',
    inputSchema: { project_id: z.string(), validation_id: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/), change_set_id: z.string().regex(/^[a-f0-9]{64}$/i) },
    _meta: { securitySchemes: oauthScheme(['project:publish']) },
    annotations: { readOnlyHint: false, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:publish', async ({ project_id, validation_id, change_set_id }) => {
    const auth = activeAuth(authInfo);
    return result(projects.deployApprovalPrepare(project_id, validation_id, change_set_id, auth.clientId || auth.subject));
  }));

  server.registerTool('project_deploy_publish', {
    title: 'Publish staged project changes',
    description: 'Atomically publishes staged changes to production with an automatic rollback backup. Requires local owner approval for the exact validated change set.',
    inputSchema: {
      project_id: z.string(),
      validation_id: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/),
      change_set_id: z.string().regex(/^[a-f0-9]{64}$/i),
      approval_id: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/),
      approval_token: z.string().min(20),
      confirmation: z.literal('PUBLISH_PROJECT_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['project:publish']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:publish', async ({ project_id, validation_id, change_set_id, approval_id, approval_token, confirmation }) => result(projects.deployPublish(project_id, validation_id, change_set_id, approval_id, approval_token, confirmation))));

  server.registerTool('project_rollback_list', {
    title: 'List project rollback snapshots',
    description: 'Lists previous deployment backup snapshots available for instant rollback.',
    inputSchema: { project_id: z.string() },
    _meta: { securitySchemes: oauthScheme(['project:rollback']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:rollback', async ({ project_id }) => result(projects.rollbackList(project_id))));

  server.registerTool('project_rollback_approval_prepare', {
    title: 'Request local owner approval for project rollback',
    description: 'Queues a specific rollback snapshot for review and approval through the local serverops CLI. No token is issued to the MCP client.',
    inputSchema: { project_id: z.string(), backup_id: z.string().min(1) },
    _meta: { securitySchemes: oauthScheme(['project:rollback']) },
    annotations: { readOnlyHint: false, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:rollback', async ({ project_id, backup_id }) => {
    const auth = activeAuth(authInfo);
    return result(projects.rollbackApprovalPrepare(project_id, backup_id, auth.clientId || auth.subject));
  }));

  server.registerTool('project_rollback', {
    title: 'Rollback project to snapshot',
    description: 'Restores files to a previous deployment snapshot with a safety backup. Requires local owner approval for the exact snapshot.',
    inputSchema: {
      project_id: z.string(),
      backup_id: z.string().min(1),
      approval_id: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/),
      approval_token: z.string().min(20),
      confirmation: z.literal('ROLLBACK_PROJECT_APPROVED')
    },
    _meta: { securitySchemes: oauthScheme(['project:rollback']) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:rollback', async ({ project_id, backup_id, approval_id, approval_token, confirmation }) => result(projects.rollback(project_id, backup_id, approval_id, approval_token, confirmation))));

  server.registerTool('project_deploy_status', {
    title: 'Read project deployment status',
    description: 'Returns status of staged changes, validation, last deploy, and backups.',
    inputSchema: { project_id: z.string() },
    _meta: { securitySchemes: oauthScheme(['project:read']) },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }, requireToolScope(authInfo, 'project:read', async ({ project_id }) => result(projects.deployStatus(project_id))));

  server.toolScopeMap = Object.fromEntries(toolPermissionMatrix.map(item => [item.tool, item.required_oauth_scopes]));
  return server;
}

// Transports Map
const transports = new Map();

// HTTP Endpoints
app.get('/healthz', (_req, res) => res.json({
  ok: true,
  service: 'ServerOps MCP',
  server_id: 'serverops-mcp',
  version: APP_VERSION,
  execution: executionEngine.inspect()
}));

app.get(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'], (_req, res) => {
  res.json(oauth.protectedResourceMetadata());
});

app.get(['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp', '/.well-known/openid-configuration', '/.well-known/openid-configuration/mcp'], (_req, res) => {
  res.json(oauth.authorizationServerMetadata());
});

app.get('/docs', (_req, res) => {
  res.type('text/plain').send('ServerOps MCP — Self-hosted MCP server for Linux administration, deployment, monitoring, and automation. OAuth 2.1, PKCE S256, scoped access, local owner approvals, recoverable mutations, and audit logging.');
});

// Bootstrap Claim Endpoint
app.post('/bootstrap/claim', rateLimit(10, 60_000), (req, res) => {
  try {
    const { token, password } = req.body || {};
    const outcome = claimServer({ token, password });
    return res.status(200).json(outcome);
  } catch (err) {
    const status = err.message === 'server_already_claimed' || err.message === 'token_already_claimed' ? 409 : 400;
    return res.status(status).json({ ok: false, error: err.message });
  }
});

app.get('/bootstrap/status', (_req, res) => {
  return res.json({
    ok: true,
    claimed: store.isServerClaimed()
  });
});

// Dynamic Client Registration (RFC 7591)
app.post('/oauth/register', rateLimit(20, 60 * 60_000), async (req, res) => {
  try {
    res.status(201).json(oauth.registerClient(req.body));
  } catch (e) {
    res.status(400).json({ error: 'invalid_client_metadata', error_description: e.message });
  }
});

function authParams(params) {
  return {
    response_type: params.response_type,
    client_id: params.client_id,
    redirect_uri: params.redirect_uri,
    scope: params.scope || 'system:read',
    state: params.state || '',
    code_challenge: params.code_challenge,
    code_challenge_method: params.code_challenge_method,
    resource: params.resource || oauth.RESOURCE
  };
}

// OAuth Authorize UI (Password-only SaaS Tailwind screen)
app.get('/oauth/authorize', rateLimit(60, 60_000), async (req, res) => {
  try {
    const p = authParams(req.query);
    if (p.response_type !== 'code' || p.code_challenge_method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(p.code_challenge || '') || p.resource !== oauth.RESOURCE) {
      throw new Error('invalid_authorization_request');
    }
    const clientMeta = await oauth.validateClient(p.client_id, p.redirect_uri);
    const clientDisplayName = clientMeta?.client_name || 'ChatGPT / Gemini';
    const requestedScopes = oauth.validateRequestedScopes(p.scope, clientMeta);
    const nonce = crypto.randomBytes(18).toString('base64');

    res.set('Content-Security-Policy', `default-src 'none'; style-src 'self' 'nonce-${nonce}'; script-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`);

    const cancel = new URL(p.redirect_uri);
    cancel.searchParams.set('error', 'access_denied');
    if (p.state) cancel.searchParams.set('state', p.state);
    cancel.searchParams.set('iss', config.oauthIssuer);
    const cancelUrl = cancel.toString();

    const html = renderAuthorizePage({
      clientDisplayName,
      clientId: p.client_id,
      redirectUri: p.redirect_uri,
      requestedScopes,
      hiddenFields: p,
      nonce,
      cancelUrl
    });

    res.type('html').send(html);
  } catch (e) {
    res.status(400).json({ error: 'invalid_request', error_description: e.message });
  }
});

// OAuth Authorize Submission (Form has ONLY 1 field: password)
app.post('/oauth/authorize', rateLimit(10, 15 * 60_000), async (req, res) => {
  const p = authParams(req.body);
  let redirect;
  const wantsJson = String(req.get('accept') || '').toLowerCase().includes('application/json');
  try {
    if (p.response_type !== 'code' || p.code_challenge_method !== 'S256' ||
        !/^[A-Za-z0-9_-]{43}$/.test(p.code_challenge || '') || p.resource !== oauth.RESOURCE) {
      throw new Error('invalid_authorization_request');
    }
    const clientMeta = await oauth.validateClient(p.client_id, p.redirect_uri);
    const scopes = oauth.validateRequestedScopes(p.scope, clientMeta);
    redirect = new URL(p.redirect_uri);

    // Password-only authentication with scrypt timingSafeEqual
    if (!oauth.verifyPassword(req.body.password || '')) {
      throw new Error('access_denied');
    }

    const code = oauth.createAuthorizationCode({
      clientId: p.client_id,
      redirectUri: redirect.toString(),
      codeChallenge: p.code_challenge,
      scopes,
      resource: p.resource,
      subject: config.ownerSubject
    });

    redirect.searchParams.set('code', code);
    if (p.state) redirect.searchParams.set('state', p.state);
    redirect.searchParams.set('iss', config.oauthIssuer);

    if (wantsJson) {
      return res.set('Cache-Control', 'no-store').json({
        ok: true,
        status: 'authorization_code_issued',
        redirect_url: redirect.toString()
      });
    }
    return res.redirect(303, redirect.toString());
  } catch (e) {
    const error = e.message === 'access_denied' ? 'access_denied' : 'invalid_request';
    if (wantsJson) {
      return res.status(error === 'access_denied' ? 401 : 400).set('Cache-Control', 'no-store').json({
        ok: false,
        error,
        message: error === 'access_denied' ? 'Incorrect owner password.' : 'Invalid OAuth authorization request.'
      });
    }
    if (redirect) {
      redirect.searchParams.set('error', error);
      if (p.state) redirect.searchParams.set('state', p.state);
      redirect.searchParams.set('iss', config.oauthIssuer);
      return res.redirect(303, redirect.toString());
    }
    return res.status(400).json({ error: 'invalid_request', error_description: e.message });
  }
});

// OAuth Token Endpoint
app.post('/oauth/token', rateLimit(60, 60_000), async (req, res) => {
  try {
    const clientId = await oauth.authenticateTokenClient(req.body, req);
    let tokens;
    const effectiveResource = req.body.resource || oauth.RESOURCE;
    if (req.body.grant_type === 'authorization_code') {
      tokens = oauth.exchangeCode({
        code: req.body.code,
        clientId,
        redirectUri: req.body.redirect_uri,
        codeVerifier: req.body.code_verifier,
        resource: effectiveResource
      });
    } else if (req.body.grant_type === 'refresh_token') {
      tokens = oauth.refreshTokens({
        refreshToken: req.body.refresh_token,
        clientId,
        resource: effectiveResource,
        scope: req.body.scope
      });
    } else {
      throw new Error('unsupported_grant_type');
    }
    res.set('Cache-Control', 'no-store').set('Pragma', 'no-cache').json(tokens);
  } catch (e) {
    if (e.message === 'invalid_client') {
      return res.status(401).set('WWW-Authenticate', 'Basic realm="ServerOps OAuth token endpoint"').json({ error: 'invalid_client' });
    }
    if (e.message === 'invalid_scope') {
      return res.status(400).json({ error: 'invalid_scope' });
    }
    res.status(400).json({ error: e.message === 'unsupported_grant_type' ? e.message : 'invalid_grant' });
  }
});

app.post('/oauth/revoke', rateLimit(60, 60_000), (req, res) => {
  if (req.body.token) oauth.revokeToken(req.body.token);
  res.status(200).end();
});

// MCP Session Transport
app.all('/mcp', rateLimit(120, 60_000), checkOrigin, requireMcpAuth, async (req, res) => {
  return runWithRequestContext({
    requestId: req.requestId,
    authInfo: req.authInfo,
    tool: req.body?.method === 'tools/call' ? req.body?.params?.name : null
  }, async () => {
    try {
      const sessionId = req.headers['mcp-session-id'];
      let session = sessionId ? transports.get(sessionId) : undefined;
      if (session && (session.clientId !== req.authInfo.clientId || session.subject !== req.authInfo.subject)) {
        return res.status(403).json({ error: 'mcp_session_principal_mismatch' });
      }
      if (!session && req.method === 'POST' && isInitializeRequest(req.body)) {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => crypto.randomUUID(),
          onsessioninitialized: id => transports.set(id, session)
        });
        session = { transport, clientId: req.authInfo.clientId, subject: req.authInfo.subject };
        transport.onclose = () => {
          if (transport.sessionId) transports.delete(transport.sessionId);
        };
        await buildServer(req.authInfo).connect(transport);
      }
      if (!session) {
        return res.status(400).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Invalid or missing MCP session' }, id: null });
      }
      await session.transport.handleRequest(req, res, req.body);
    } catch (e) {
      console.error(JSON.stringify({
        event: 'mcp_request_error',
        service: 'ServerOps MCP',
        request_id: req.requestId,
        message: String(e?.message || 'internal_error').slice(0, 300)
      }));
      if (!res.headersSent) res.status(500).json({ error: 'internal_error', request_id: req.requestId });
    }
  });
});

setInterval(() => {
  const t = Date.now();
  for (const [k, v] of rateBuckets) {
    if (v.resetAt <= t) rateBuckets.delete(k);
  }
}, 5 * 60_000).unref();

setInterval(() => store.cleanup(), 60 * 60 * 1000).unref();

app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

app.use((error, _req, res, _next) => {
  console.error(JSON.stringify({
    event: 'request_error',
    service: 'ServerOps MCP',
    message: String(error?.message || 'internal_error').replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]')
  }));
  if (!res.headersSent) res.status(500).json({ error: 'internal_error' });
});

let httpServer = null;
if (process.env.NODE_ENV !== 'test') {
  httpServer = app.listen(config.port, config.host, () => {
    console.log(JSON.stringify({
      event: 'started',
      service: 'ServerOps MCP',
      server_id: 'serverops-mcp',
      version: APP_VERSION,
      bind: `${config.host}:${config.port}`
    }));
  });
}

let shuttingDown = false;
async function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(JSON.stringify({ event: 'shutdown_started', service: 'ServerOps MCP', signal }));
  if (httpServer) httpServer.close();
  for (const session of transports.values()) {
    await session.transport.close().catch(() => {});
  }
  await executionEngine.shutdown();
  store.db.close();
  console.log(JSON.stringify({ event: 'shutdown_completed', service: 'ServerOps MCP' }));
  process.exit(0);
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => gracefulShutdown(sig));
}

export { app, buildServer };
