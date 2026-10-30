#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-smoke-'));
let child;
let client;
let childOutput = '';

function wait(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function reservePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function waitForHealth(url, processRef, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (processRef.exitCode !== null) {
      throw new Error('Server process exited before becoming healthy. ' + childOutput.slice(-3000));
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (response.ok) return;
    } catch {}
    await wait(100);
  }
  throw new Error('Server did not become healthy within ' + timeoutMs + ' ms. ' + childOutput.slice(-3000));
}

async function stopChild(processRef) {
  if (!processRef || processRef.exitCode !== null) return;
  const exited = new Promise(resolve => processRef.once('exit', resolve));
  processRef.kill('SIGTERM');
  await Promise.race([exited, wait(3000)]);
  if (processRef.exitCode === null) {
    processRef.kill('SIGKILL');
    await exited;
  }
}

try {
  const port = await reservePort();
  const issuer = 'http://127.0.0.1:' + port;
  const signingKey = crypto.randomBytes(32).toString('hex');
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith('SERVEROPS_') && name !== 'NODE_OPTIONS')
  );
  const env = {
    ...inherited,
    NODE_ENV: 'development',
    HOME: tempDir,
    SERVEROPS_BIND_HOST: '127.0.0.1',
    SERVEROPS_PORT: String(port),
    SERVEROPS_PUBLIC_BASE_URL: issuer,
    SERVEROPS_OAUTH_ISSUER: issuer,
    SERVEROPS_DATA_DIR: path.join(tempDir, 'data'),
    SERVEROPS_BACKUP_DIR: path.join(tempDir, 'backups'),
    SERVEROPS_SECRET_DIR: path.join(tempDir, 'secrets'),
    SERVEROPS_OAUTH_SIGNING_KEY: signingKey,
    SERVEROPS_OWNER_SUBJECT: 'serverops-smoke-owner',
    SERVEROPS_NETWORK_ARTIFACT_TTL_SECONDS: '3600'
  };

  child = spawn(process.execPath, ['app/main.js'], {
    cwd: process.cwd(),
    env,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', chunk => { childOutput += String(chunk); });
  child.stderr.on('data', chunk => { childOutput += String(chunk); });
  await waitForHealth(issuer + '/healthz', child);

  for (const name of Object.keys(process.env)) {
    if (name.startsWith('SERVEROPS_') || name === 'NODE_OPTIONS') delete process.env[name];
  }
  Object.assign(process.env, env);
  const { jwt, RESOURCE } = await import('../app/oauth.js');
  const timestamp = Math.floor(Date.now() / 1000);
  const token = jwt({
    iss: issuer,
    aud: RESOURCE,
    sub: 'serverops-local-smoke-test',
    client_id: 'serverops-local-smoke-test',
    scope: 'system:read',
    iat: timestamp,
    nbf: timestamp,
    exp: timestamp + 300
  });

  client = new Client({ name: 'serverops-smoke-test', version: '1.0.0' }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(new URL(issuer + '/mcp'), {
    requestInit: { headers: { authorization: 'Bearer ' + token } }
  });
  await client.connect(transport);

  const tools = await client.listTools();
  const expected = ['health_check', 'system_diagnostics', 'system_resource_inspect'];
  const missing = expected.filter(name => !tools.tools.some(tool => tool.name === name));
  if (missing.length) throw new Error('missing_tools:' + missing.join(','));

  const healthResponse = await client.callTool({ name: 'health_check', arguments: {} });
  if (healthResponse.isError) throw new Error(healthResponse.content?.[0]?.text || 'health_check_failed');
  const healthText = healthResponse.content?.find(item => item.type === 'text')?.text || '{}';
  const health = healthResponse.structuredContent || JSON.parse(healthText);
  if (!health.ok || health.service !== 'ServerOps MCP') throw new Error('health_check_mismatch');

  const diagnosticsResponse = await client.callTool({ name: 'system_diagnostics', arguments: { limit: 5 } });
  if (diagnosticsResponse.isError) throw new Error(diagnosticsResponse.content?.[0]?.text || 'system_diagnostics_failed');

  console.log(JSON.stringify({
    ok: true,
    service: health.service,
    version: health.version,
    tools_available: tools.tools.length,
    read_only_smoke: 'passed'
  }));
} finally {
  if (client) await client.close().catch(() => {});
  await stopChild(child).catch(() => {});
  fs.rmSync(tempDir, { recursive: true, force: true });
}
