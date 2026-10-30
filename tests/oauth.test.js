import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.NODE_ENV = 'test';
process.env.SERVEROPS_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-oauth-test-'));
process.env.SERVEROPS_OAUTH_SIGNING_KEY = 'test-signing-key-for-oauth-tests-at-least-thirty-two-bytes';
process.env.SERVEROPS_GEMINI_CLIENT_ID = 'gemini-test-client.apps.googleusercontent.com';
process.env.SERVEROPS_GEMINI_CLIENT_SECRET = 'gemini-test-client-secret-for-unit-tests';
process.env.SERVEROPS_GEMINI_REDIRECT_URI = 'https://oauth-redirect.googleusercontent.com/r/gemini-test-app';

const oauth = await import('../app/oauth.js');
const storage = await import('../app/storage.js');
const bootstrap = await import('../app/bootstrap.js');

bootstrap.resetPasswordLocally('TestOwnerPassword888!');

test('safeRedirect: accepts official Google redirect URI patterns', () => {
  const patterns = [
    'https://oauth-redirect.googleusercontent.com/r/my-client-app',
    'https://oauth-redirect-sandbox.googleusercontent.com/r/my-client-app',
    'https://oauth-redirect-test.googleusercontent.com/r/my-client-app',
    'https://oauth-redirect.googleusercontent.com/a/my-client-app',
    'https://oauth-redirect-sandbox.googleusercontent.com/a/my-client-app',
    'https://oauth-redirect-test.googleusercontent.com/a/my-client-app'
  ];
  for (const uri of patterns) {
    assert.equal(oauth.safeRedirect(uri), uri);
    assert.equal(oauth.isGoogleRedirectUri(uri), true);
  }
});

test('safeRedirect: rejects HTTP (for external), fake hostnames, outside hosts, invalid paths, empty suffixes, userinfo and fragment', () => {
  const bad = [
    'http://oauth-redirect.googleusercontent.com/r/app',
    'https://fake-googleusercontent.com/r/app',
    'https://malicious.example.com/callback',
    'https://oauth-redirect.googleusercontent.com/',
    'https://oauth-redirect.googleusercontent.com/r/',
    'https://oauth-redirect.googleusercontent.com/other/app',
    'https://user:pass@oauth-redirect.googleusercontent.com/r/app',
    'https://oauth-redirect.googleusercontent.com/r/app#frag',
    'javascript:alert(1)',
    'not-a-url'
  ];
  for (const uri of bad) {
    assert.throws(() => oauth.safeRedirect(uri), /invalid_redirect_uri|redirect_host_not_allowed/);
  }
});

test('OAuth client metadata lookup is restricted to trusted hosts and unknown clients are rejected', async () => {
  assert.equal(await oauth.clientMetadata('https://127.0.0.1/oauth/client.json'), null);
  await assert.rejects(
    oauth.validateClient('https://example.com/oauth/client.json', 'https://chatgpt.com/aip/g-123/oauth/callback'),
    /invalid_client/
  );
});

test('OAuth scopes default to read-only and cannot exceed client metadata', () => {
  assert.deepEqual(oauth.normalizeScopes(''), ['system:read']);
  assert.deepEqual(oauth.validateRequestedScopes('system:read', { scope: 'system:read' }), ['system:read']);
  assert.throws(
    () => oauth.validateRequestedScopes('system:admin', { scope: 'system:read' }),
    /invalid_scope/
  );
});

test('validateClient requires exact redirect URI registration', async () => {
  const client = oauth.registerClient({
    client_name: 'Exact Redirect Test',
    redirect_uris: ['https://chatgpt.com/aip/g-123/oauth/callback'],
    scope: 'system:read'
  });
  assert.equal((await oauth.validateClient(client.client_id, client.redirect_uris[0])).client_id, client.client_id);
  await assert.rejects(
    oauth.validateClient(client.client_id, 'https://chatgpt.com/aip/g-456/oauth/callback'),
    /redirect_uri_mismatch/
  );
});

test('safeRedirect: accepts official ChatGPT callback patterns and localhost', () => {
  const allowed = [
    'https://chatgpt.com/aip/g-12345/oauth/callback',
    'https://auth.openai.com/oauth/callback',
    'http://localhost:3000/callback',
    'http://127.0.0.1:8080/callback'
  ];
  for (const uri of allowed) {
    assert.equal(oauth.safeRedirect(uri), uri);
  }
});

test('validateClient: rejects unregistered redirect URI', async () => {
  await assert.rejects(
    oauth.validateClient('https://chatgpt.com/oauth/client.json', 'https://evil.example.com/cb'),
    /redirect_host_not_allowed/
  );
});

test('DCR: accepts valid redirect_uris and returns RFC 7591 compliant response', () => {
  const uris = [
    'https://oauth-redirect.googleusercontent.com/r/my-registered-client',
    'https://chatgpt.com/oauth/callback'
  ];
  const client = oauth.registerClient({
    client_name: 'DCR Client Test',
    redirect_uris: uris,
    token_endpoint_auth_method: 'none',
    scope: 'system:read'
  });

  assert.ok(client.client_id);
  assert.equal(oauth.isGoogleClient(client.client_id), false);
  assert.equal(client.client_name, 'DCR Client Test');
  assert.deepEqual(client.redirect_uris, uris);
  assert.equal(client.token_endpoint_auth_method, 'none');

  const row = storage.db.prepare('SELECT metadata_json FROM oauth_clients WHERE client_id=?').get(client.client_id);
  assert.ok(row);
  const meta = JSON.parse(row.metadata_json);
  assert.equal(meta.client_id, client.client_id);
  assert.deepEqual(meta.redirect_uris, uris);
});

test('Gemini optional confidential OAuth client validates Client ID, secret, and exact redirect URI', async () => {
  const clientId = process.env.SERVEROPS_GEMINI_CLIENT_ID;
  const clientSecret = process.env.SERVEROPS_GEMINI_CLIENT_SECRET;
  const redirectUri = process.env.SERVEROPS_GEMINI_REDIRECT_URI;
  const metadata = await oauth.clientMetadata(clientId);
  assert.equal(metadata.client_id, clientId);
  assert.deepEqual(metadata.redirect_uris, [redirectUri]);
  assert.equal(metadata.token_endpoint_auth_method, 'client_secret_post');

  const validated = await oauth.validateClient(clientId, redirectUri);
  assert.equal(validated.client_name, 'Gemini MCP Client');

  const publicPost = { headers: {} };
  assert.equal(await oauth.authenticateTokenClient({ client_id: clientId, client_secret: clientSecret }, publicPost), clientId);

  const basic = Buffer.from(clientId + ':' + clientSecret).toString('base64');
  await assert.rejects(
    oauth.authenticateTokenClient({}, { headers: { authorization: 'Basic ' + basic } }),
    /invalid_client/
  );

  await assert.rejects(
    oauth.authenticateTokenClient({ client_id: clientId, client_secret: 'wrong-client-secret' }, publicPost),
    /invalid_client/
  );
  await assert.rejects(
    oauth.validateClient(clientId, 'https://oauth-redirect.googleusercontent.com/r/another-app'),
    /redirect_uri_mismatch/
  );
});

test('Configured Gemini client binds access tokens to its persistent refresh session', () => {
  const clientId = process.env.SERVEROPS_GEMINI_CLIENT_ID;
  const redirectUri = process.env.SERVEROPS_GEMINI_REDIRECT_URI;
  assert.equal(oauth.isGoogleClient(clientId), true);

  const verifier = 'c'.repeat(64);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const code = oauth.createAuthorizationCode({
    clientId,
    redirectUri,
    codeChallenge: challenge,
    scopes: ['system:read', 'project:read'],
    resource: oauth.RESOURCE,
    subject: 'serverops-owner'
  });
  const tokens1 = oauth.exchangeCode({
    code,
    clientId,
    redirectUri,
    codeVerifier: verifier,
    resource: oauth.RESOURCE
  });

  const originalRefresh = tokens1.refresh_token;
  assert.ok(originalRefresh);
  const hash1 = crypto.createHash('sha256').update(originalRefresh).digest('hex');
  const row1 = storage.db.prepare('SELECT * FROM oauth_refresh_tokens WHERE token_hash=?').get(hash1);
  assert.ok(row1);
  const initialExpiry = row1.expires_at;
  assert.equal(oauth.verifyAccessToken(tokens1.access_token).clientId, clientId);

  const tokens2 = oauth.refreshTokens({
    refreshToken: originalRefresh,
    clientId,
    resource: oauth.RESOURCE
  });
  assert.equal(tokens2.refresh_token, originalRefresh);
  assert.notEqual(tokens2.access_token, tokens1.access_token);
  assert.equal(oauth.verifyAccessToken(tokens1.access_token).clientId, clientId);
  assert.equal(oauth.verifyAccessToken(tokens2.access_token).clientId, clientId);

  const row2 = storage.db.prepare('SELECT * FROM oauth_refresh_tokens WHERE token_hash=?').get(hash1);
  assert.equal(row2.revoked_at, null);
  assert.ok(row2.expires_at >= initialExpiry);

  const tokens3 = oauth.refreshTokens({
    refreshToken: originalRefresh,
    clientId,
    resource: oauth.RESOURCE,
    scope: 'system:read'
  });
  assert.throws(() => oauth.verifyAccessToken(tokens2.access_token), /invalid_session/);
  assert.deepEqual(oauth.verifyAccessToken(tokens3.access_token).scopes, ['system:read']);

  oauth.revokeToken(originalRefresh);
  assert.throws(() => oauth.verifyAccessToken(tokens3.access_token), /invalid_session/);
  assert.throws(() => oauth.refreshTokens({
    refreshToken: originalRefresh,
    clientId,
    resource: oauth.RESOURCE
  }), /invalid_grant/);
});

test('Legacy access tokens without sid remain valid only until their normal expiry', () => {
  const client = oauth.registerClient({
    client_name: 'Legacy Compatibility Test',
    redirect_uris: ['https://chatgpt.com/legacy-callback'],
    token_endpoint_auth_method: 'none',
    scope: 'system:read'
  });
  const verifier = 'e'.repeat(64);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const code = oauth.createAuthorizationCode({
    clientId: client.client_id,
    redirectUri: client.redirect_uris[0],
    codeChallenge: challenge,
    scopes: ['system:read'],
    resource: oauth.RESOURCE,
    subject: 'serverops-owner'
  });
  const issued = oauth.exchangeCode({
    code,
    clientId: client.client_id,
    redirectUri: client.redirect_uris[0],
    codeVerifier: verifier,
    resource: oauth.RESOURCE
  });
  const legacyPayload = oauth.parseJwt(issued.access_token);
  delete legacyPayload.sid;
  const legacyToken = oauth.jwt(legacyPayload);
  assert.equal(oauth.verifyAccessToken(legacyToken).clientId, client.client_id);

  legacyPayload.iat = storage.now() - 120;
  legacyPayload.nbf = legacyPayload.iat;
  legacyPayload.exp = storage.now() - 1;
  assert.throws(() => oauth.verifyAccessToken(oauth.jwt(legacyPayload)), /token_expired/);
});

test('ChatGPT/standard client: rotates refresh token and revokes old one', () => {
  const client = oauth.registerClient({
    client_name: 'ChatGPT Client Test',
    redirect_uris: ['https://chatgpt.com/callback'],
    token_endpoint_auth_method: 'none'
  });
  assert.equal(oauth.isGoogleClient(client.client_id), false);

  const verifier = 'd'.repeat(64);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const code = oauth.createAuthorizationCode({
    clientId: client.client_id,
    redirectUri: client.redirect_uris[0],
    codeChallenge: challenge,
    scopes: ['system:read'],
    resource: oauth.RESOURCE,
    subject: 'serverops-owner'
  });

  const tokens1 = oauth.exchangeCode({
    code,
    clientId: client.client_id,
    redirectUri: client.redirect_uris[0],
    codeVerifier: verifier,
    resource: oauth.RESOURCE
  });

  const refresh1 = tokens1.refresh_token;

  // Perform refresh: must ROTATE
  const tokens2 = oauth.refreshTokens({
    refreshToken: refresh1,
    clientId: client.client_id,
    resource: oauth.RESOURCE
  });

  assert.notEqual(tokens2.refresh_token, refresh1);
  assert.throws(() => oauth.verifyAccessToken(tokens1.access_token), /invalid_session/);
  assert.equal(oauth.verifyAccessToken(tokens2.access_token).clientId, client.client_id);
  const oldHash = crypto.createHash('sha256').update(refresh1).digest('hex');
  const oldRow = storage.db.prepare('SELECT * FROM oauth_refresh_tokens WHERE token_hash=?').get(oldHash);
  assert.ok(oldRow.revoked_at !== null);

  // Replay of old refresh token fails
  assert.throws(() => oauth.refreshTokens({
    refreshToken: refresh1,
    clientId: client.client_id,
    resource: oauth.RESOURCE
  }), /invalid_grant/);
});
