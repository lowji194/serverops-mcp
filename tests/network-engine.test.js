import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-network-test-'));
const salt = 'network-test-salt';
process.env.NODE_ENV = 'test';
process.env.SERVEROPS_OAUTH_SIGNING_KEY ||= 'network-test-signing-key-that-is-at-least-thirty-two-bytes';
process.env.SERVEROPS_DATA_DIR ||= path.join(root, 'data');

const { runNetwork, networkNeedsApproval, canonicalNetworkApproval, pinnedLookup, addressIsPrivate } = await import('../app/network-engine.js');

test('SSRF classifier blocks private, reserved, mapped and transition IPv6 ranges', () => {
  for (const address of [
    '0.0.0.0', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.169.254',
    '172.16.0.1', '192.0.0.8', '192.0.2.1', '192.168.1.1',
    '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '240.0.0.1',
    '::', '::1', 'fc00::1', 'fd00::1', 'fe80::1', 'ff02::1',
    '::ffff:127.0.0.1', '::ffff:7f00:1', '64:ff9b::7f00:1',
    '2001:db8::1', '2001:2::1', '2002:7f00:1::1', '2001:0::1'
  ]) assert.equal(addressIsPrivate(address), true, address);
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(addressIsPrivate(address), false, address);
  }
});

test('pinned DNS lookup supports Node 24 single and all-address callback modes', async () => {
  const lookup = pinnedLookup({ address: '203.0.113.10', family: 4 });
  const single = await new Promise((resolve, reject) => lookup('example.test', {}, (error, address, family) => error ? reject(error) : resolve({ address, family })));
  assert.deepEqual(single, { address: '203.0.113.10', family: 4 });
  const all = await new Promise((resolve, reject) => lookup('example.test', { all: true }, (error, addresses) => error ? reject(error) : resolve(addresses)));
  assert.deepEqual(all, [{ address: '203.0.113.10', family: 4 }]);
});

test('DNS is read-only and private HTTP requires explicit elevated intent', async () => {
  const lookup = await runNetwork({ action: 'dns_lookup', host: 'localhost' });
  assert.equal(lookup.records.length > 0, true);
  assert.equal(networkNeedsApproval({ action: 'dns_lookup' }), false);
  assert.equal(networkNeedsApproval({ action: 'http_request', method: 'GET', allow_private_network: true }), true);
  await assert.rejects(runNetwork({ action: 'http_request', method: 'GET', url: 'http://127.0.0.1:9/', allow_private_network: false, timeout_ms: 200 }, { clientId: 'test-client', subject: 'test-owner' }), /private_network_requires_admin_approval/);
  assert.throws(() => canonicalNetworkApproval({ action: 'http_request', method: 'POST', url: 'https://example.com/', multipart: [{ name: 'unsafe\r\nheader', text: 'x' }] }), /invalid_multipart_header/);
});

test('approved private HTTP streams into an owner-bound pageable artifact', async () => {
  const server = http.createServer((_req, res) => res.end('network-engine-ok'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const owner = { clientId: 'client-a', subject: 'owner-a' };
  try {
    const port = server.address().port;
    const input = { action: 'http_request', method: 'GET', url: `http://127.0.0.1:${port}/probe`, allow_private_network: true, timeout_ms: 2000, response_encoding: 'text' };
    const canonical = canonicalNetworkApproval(input);
    assert.equal(canonical.allow_private_network, true);
    const response = await runNetwork(input, owner);
    assert.equal(response.status_code, 200);
    assert.equal(response.private_destination, true);
    assert.equal(response.body_page.content, 'network-engine-ok');
    assert.ok(response.expires_at > Math.floor(Date.now() / 1000));
    const pageInput = { action: 'artifact_read', network_id: response.network_id, offset: 0, max_bytes: 7, response_encoding: 'text' };
    const page = await runNetwork(pageInput, owner);
    assert.equal(page.content, 'network');
    await assert.rejects(runNetwork(pageInput, { clientId: 'client-b', subject: 'owner-a' }), /network_artifact_not_found/);
    await assert.rejects(runNetwork(pageInput, { clientId: 'client-a', subject: 'owner-b' }), /network_artifact_not_found/);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('HTTP response limit is enforced per request', async () => {
  const server = http.createServer((_req, res) => res.end(Buffer.alloc(2048, 'x')));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = server.address().port;
    await assert.rejects(runNetwork({
      action: 'http_request',
      method: 'GET',
      url: `http://127.0.0.1:${port}/large`,
      allow_private_network: true,
      max_response_bytes: 1024,
      timeout_ms: 2000
    }, { clientId: 'client-limit', subject: 'owner-limit' }), /network_response_too_large/);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test.after(() => fs.rmSync(root, { recursive: true, force: true }));
