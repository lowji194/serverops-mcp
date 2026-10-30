import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.NODE_ENV = 'test';
process.env.SERVEROPS_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-mcp-test-'));
process.env.SERVEROPS_OAUTH_SIGNING_KEY = 'test-signing-key-for-mcp-tests-at-least-thirty-two-bytes';

const oauth = await import('../app/oauth.js');
const bootstrap = await import('../app/bootstrap.js');
const { app } = await import('../app/main.js');

bootstrap.resetPasswordLocally('McpServerTestPassword123!');

async function startServer() {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.once('listening', resolve);
  });
  return server;
}

async function closeServer(server) {
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

test('MCP: /healthz endpoint returns healthy status and system metrics', async () => {
  const server = await startServer();
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.ok, true);
    assert.equal(json.service, 'ServerOps MCP');
    assert.equal(json.server_id, 'serverops-mcp');
    assert.ok(json.execution);
  } finally {
    await closeServer(server);
  }
});

test('MCP: unauthenticated /mcp call returns 401 with WWW-Authenticate challenge', async () => {
  const server = await startServer();
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1 })
    });
    assert.equal(res.status, 401);
    const challenge = res.headers.get('www-authenticate');
    assert.ok(challenge.includes('Bearer resource_metadata='));
    assert.ok(challenge.includes('scope="system:read'));
  } finally {
    await closeServer(server);
  }
});

test('MCP: CORS preflight supports Streamable HTTP and ChatGPT/Gemini browser headers', async () => {
  const server = await startServer();
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const origin of ['https://chatgpt.com', 'https://gemini.google.com', 'https://aistudio.google.com']) {
      const response = await fetch(`${baseUrl}/mcp`, {
        method: 'OPTIONS',
        headers: {
          Origin: origin,
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'authorization,content-type,mcp-session-id,mcp-protocol-version,last-event-id'
        }
      });
      assert.equal(response.status, 204, origin);
      assert.equal(response.headers.get('access-control-allow-origin'), origin);
      const allowed = (response.headers.get('access-control-allow-headers') || '').toLowerCase();
      for (const header of ['authorization', 'mcp-session-id', 'mcp-protocol-version', 'last-event-id']) {
        assert.ok(allowed.includes(header), `missing allowed header ${header} for ${origin}`);
      }
      const exposed = (response.headers.get('access-control-expose-headers') || '').toLowerCase();
      assert.ok(exposed.includes('mcp-session-id'));
      assert.ok(exposed.includes('www-authenticate'));
      assert.ok((response.headers.get('vary') || '').includes('Origin'));
    }
    const denied = await fetch(`${baseUrl}/mcp`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' }
    });
    assert.equal(denied.status, 403);
  } finally {
    await closeServer(server);
  }
});

test('MCP: discovery metadata endpoints return RFC compliant structures', async () => {
  const server = await startServer();
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const resProtected = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
    assert.equal(resProtected.status, 200);
    const protJson = await resProtected.json();
    assert.ok(protJson.resource);
    assert.ok(protJson.scopes_supported.includes('system:read'));
    assert.ok(protJson.scopes_supported.includes('system:admin'));

    const resAuth = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
    assert.equal(resAuth.status, 200);
    const authJson = await resAuth.json();
    assert.ok(authJson.authorization_endpoint);
    assert.ok(authJson.token_endpoint);
    assert.ok(authJson.registration_endpoint);
    assert.ok(authJson.code_challenge_methods_supported.includes('S256'));
  } finally {
    await closeServer(server);
  }
});
