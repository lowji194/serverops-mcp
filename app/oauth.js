import crypto from 'node:crypto';
import { config } from './config.js';
import { db, now, getOwnerPasswordHash } from './storage.js';
import { verifyPasswordHash } from './bootstrap.js';

export const RESOURCE = `${config.oauthIssuer}/mcp`;
export const SCOPES = [
  'system:read',
  'system:admin',
  'project:read',
  'project:edit',
  'project:preview',
  'project:publish',
  'project:rollback'
];

const scopeSet = new Set(SCOPES);
const b64u = value => Buffer.from(value).toString('base64url');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');

function jsonB64(value) {
  return b64u(JSON.stringify(value));
}

function sign(input) {
  return crypto.createHmac('sha256', config.oauthSigningKey).update(input).digest('base64url');
}

export function jwt(payload) {
  const input = `${jsonB64({ alg: 'HS256', typ: 'JWT' })}.${jsonB64(payload)}`;
  return `${input}.${sign(input)}`;
}

export function parseJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('malformed_token');
  const expected = sign(`${parts[0]}.${parts[1]}`);
  const aa = Buffer.from(parts[2]);
  const bb = Buffer.from(expected);
  if (aa.length !== bb.length || !crypto.timingSafeEqual(aa, bb)) {
    throw new Error('bad_signature');
  }
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
}

export function verifyAccessToken(token) {
  const p = parseJwt(token);
  const t = now();
  if (p.iss !== config.oauthIssuer || p.aud !== RESOURCE || !p.sub || !p.client_id) {
    throw new Error('claims_invalid');
  }
  if (!Number.isInteger(p.exp) || p.exp <= t || (p.nbf && p.nbf > t + 30) || !Number.isInteger(p.iat) || p.iat > t + 30) {
    throw new Error('token_expired');
  }
  if (p.exp - p.iat > 3600) throw new Error('token_lifetime_invalid');
  const scopes = String(p.scope || '').split(/\s+/).filter(Boolean);
  if (!scopes.length || scopes.some(s => !scopeSet.has(s))) {
    throw new Error('scope_invalid');
  }
  if (p.sid !== undefined) {
    if (typeof p.sid !== 'string' || !/^[a-f0-9]{64}$/.test(p.sid)) {
      throw new Error('invalid_session');
    }
    const session = db.prepare('SELECT client_id,scopes,resource,subject,expires_at,revoked_at FROM oauth_refresh_tokens WHERE token_hash=?').get(p.sid);
    const sessionScopes = String(session?.scopes || '').split(/\s+/).filter(Boolean);
    if (
      !session ||
      session.revoked_at !== null ||
      session.expires_at <= t ||
      session.client_id !== p.client_id ||
      session.resource !== p.aud ||
      session.subject !== p.sub ||
      scopes.some(scope => !sessionScopes.includes(scope))
    ) {
      throw new Error('invalid_session');
    }
  }
  const role = scopes.includes('system:admin') ? 'administrator' : 'observer';
  return { clientId: p.client_id, subject: p.sub, role, scopes, token: p };
}
export function normalizeScopes(value) {
  const requested = String(value || '').split(/\s+/).filter(Boolean);
  const scopes = requested.length ? requested : ['system:read'];
  if (scopes.some(s => !scopeSet.has(s))) {
    throw new Error('invalid_scope');
  }
  return [...new Set(scopes)];
}

export function verifyPassword(password) {
  const storedHash = getOwnerPasswordHash();
  if (!storedHash) return false;
  return verifyPasswordHash(password, storedHash);
}

export const GOOGLE_REDIRECT_HOSTS = new Set([
  'oauth-redirect.googleusercontent.com',
  'oauth-redirect-sandbox.googleusercontent.com',
  'oauth-redirect-test.googleusercontent.com'
]);

export function isGoogleRedirectUri(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol !== 'https:') return false;
    if (u.username || u.password || u.hash) return false;
    if (!GOOGLE_REDIRECT_HOSTS.has(u.hostname)) return false;
    const match = /^\/(r|a)\/(.+)$/.exec(u.pathname);
    return Boolean(match && match[2].trim());
  } catch {
    return false;
  }
}

export function isGoogleClient(clientId) {
  return Boolean(config.geminiOAuthConfigured && clientId === config.geminiClientId);
}
export function safeRedirect(uri) {
  let u;
  try {
    u = new URL(uri);
  } catch {
    throw new Error('invalid_redirect_uri');
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('invalid_redirect_uri');
  if (u.username || u.password || u.hash) throw new Error('invalid_redirect_uri');

  // Allow localhost/127.0.0.1 for development / local testing over http
  if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') {
    return u.toString();
  }

  // All external redirects MUST be https
  if (u.protocol !== 'https:') throw new Error('invalid_redirect_uri');

  if (GOOGLE_REDIRECT_HOSTS.has(u.hostname)) {
    const match = /^\/(r|a)\/(.+)$/.exec(u.pathname);
    if (!match || !match[2].trim()) throw new Error('invalid_redirect_uri');
    return u.toString();
  }

  if (
    u.hostname === 'chatgpt.com' ||
    u.hostname.endsWith('.chatgpt.com') ||
    u.hostname === 'openai.com' ||
    u.hostname.endsWith('.openai.com')
  ) {
    return u.toString();
  }

  // Check if client is registered via DCR with this exact redirect_uri
  const registered = db.prepare('SELECT client_id, metadata_json FROM oauth_clients').all();
  for (const client of registered) {
    try {
      const meta = JSON.parse(client.metadata_json);
      if (Array.isArray(meta?.redirect_uris) && meta.redirect_uris.includes(uri)) {
        return u.toString();
      }
    } catch {}
  }

  throw new Error('redirect_host_not_allowed');
}

export async function clientMetadata(clientId) {
  if (config.geminiOAuthConfigured && clientId === config.geminiClientId) {
    return {
      client_id: config.geminiClientId,
      client_name: 'Gemini MCP Client',
      redirect_uris: [config.geminiRedirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post',
      scope: SCOPES.join(' ')
    };
  }
  const saved = db.prepare('SELECT metadata_json FROM oauth_clients WHERE client_id=?').get(clientId);
  if (saved) return JSON.parse(saved.metadata_json);
  try {
    const u = new URL(clientId);
    const trustedHost = u.hostname === 'chatgpt.com' ||
      u.hostname.endsWith('.chatgpt.com') ||
      u.hostname === 'openai.com' ||
      u.hostname.endsWith('.openai.com');
    if (u.protocol !== 'https:' || !trustedHost || u.username || u.password || u.hash || (u.port && u.port !== '443')) return null;
    const res = await fetch(u.toString(), {
      headers: { Accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(4000)
    });
    if (!res.ok) return null;
    const raw = await res.text();
    if (raw.length > 65536) return null;
    const metadata = JSON.parse(raw);
    if (metadata?.client_id !== clientId || !Array.isArray(metadata?.redirect_uris)) return null;
    return metadata;
  } catch {
    return null;
  }
}

export async function validateClient(clientId, redirectUri) {
  if (!clientId) throw new Error('invalid_client');
  safeRedirect(redirectUri);
  const meta = await clientMetadata(clientId);
  if (!meta || meta.client_id !== clientId || !Array.isArray(meta.redirect_uris) || !meta.redirect_uris.length) {
    throw new Error('invalid_client');
  }
  if (!meta.redirect_uris.includes(redirectUri)) throw new Error('redirect_uri_mismatch');
  if (Array.isArray(meta.grant_types) && !meta.grant_types.includes('authorization_code')) throw new Error('unauthorized_client');
  if (Array.isArray(meta.response_types) && !meta.response_types.includes('code')) throw new Error('unauthorized_client');
  return meta;
}

export function validateRequestedScopes(value, metadata) {
  const requested = normalizeScopes(value);
  const allowed = normalizeScopes(metadata?.scope || 'system:read');
  if (requested.some(scope => !allowed.includes(scope))) throw new Error('invalid_scope');
  return requested;
}

export function registerClient(body) {
  if (!Array.isArray(body?.redirect_uris) || !body.redirect_uris.length) {
    throw new Error('redirect_uris_required');
  }
  for (const uri of body.redirect_uris) {
    safeRedirect(uri);
  }
  const clientId = crypto.randomUUID();
  const metadata = {
    client_id: clientId,
    client_name: body.client_name ? String(body.client_name).slice(0, 100) : 'Registered Client',
    redirect_uris: body.redirect_uris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope: normalizeScopes(body.scope).join(' ')
  };
  db.prepare('INSERT INTO oauth_clients VALUES(?,?,?)').run(clientId, JSON.stringify(metadata), now());
  return metadata;
}

export function createAuthorizationCode({ clientId, redirectUri, codeChallenge, scopes, resource, subject = config.ownerSubject }) {
  const effectiveResource = resource || RESOURCE;
  if (effectiveResource !== RESOURCE) throw new Error('invalid_resource');
  const code = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO oauth_codes VALUES(?,?,?,?,?,?,?,?,NULL)')
    .run(hash(code), clientId, redirectUri, codeChallenge, scopes.join(' '), effectiveResource, subject, now() + 300);
  return code;
}

function issueTokens({ clientId, scopes, resource = RESOURCE, subject = config.ownerSubject, includeRefresh = true }) {
  const effectiveResource = resource || RESOURCE;
  const t = now();
  const refresh = includeRefresh ? crypto.randomBytes(48).toString('base64url') : null;
  const refreshHash = refresh ? hash(refresh) : null;
  const payload = {
    iss: config.oauthIssuer,
    aud: effectiveResource,
    sub: subject,
    client_id: clientId,
    scope: scopes.join(' '),
    iat: t,
    nbf: t,
    exp: t + 3600,
    jti: crypto.randomUUID(),
    ...(refreshHash ? { sid: refreshHash } : {})
  };
  const output = {
    access_token: jwt(payload),
    token_type: 'Bearer',
    expires_in: 3600,
    scope: payload.scope
  };
  if (refresh) {
    db.prepare('INSERT INTO oauth_refresh_tokens VALUES(?,?,?,?,?,?,NULL)')
      .run(refreshHash, clientId, payload.scope, effectiveResource, subject, t + 30 * 86400);
    output.refresh_token = refresh;
  }
  return output;
}
export function exchangeCode({ code, clientId, redirectUri, codeVerifier, resource = RESOURCE }) {
  const effectiveResource = resource || RESOURCE;
  const row = db.prepare('SELECT * FROM oauth_codes WHERE code_hash=?').get(hash(code));
  const t = now();
  if (!row || row.used_at || row.expires_at < t || row.client_id !== clientId || row.redirect_uri !== redirectUri || row.resource !== effectiveResource) {
    throw new Error('invalid_grant');
  }
  if (typeof codeVerifier !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)) {
    throw new Error('invalid_code_verifier');
  }
  const challenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  if (challenge !== row.code_challenge) {
    throw new Error('invalid_code_verifier');
  }
  db.prepare('UPDATE oauth_codes SET used_at=? WHERE code_hash=?').run(t, row.code_hash);
  return issueTokens({ clientId, scopes: row.scopes.split(' '), resource: row.resource, subject: row.subject });
}

export function refreshTokens({ refreshToken, clientId, resource = RESOURCE, scope }) {
  const effectiveResource = resource || RESOURCE;
  const tokenHash = hash(refreshToken);
  const row = db.prepare('SELECT * FROM oauth_refresh_tokens WHERE token_hash=?').get(tokenHash);
  if (!row || row.revoked_at || row.expires_at < now() || row.client_id !== clientId || row.resource !== effectiveResource) {
    throw new Error('invalid_grant');
  }
  const original = row.scopes.split(' ');
  const requested = scope ? normalizeScopes(scope) : original;
  if (requested.some(s => !original.includes(s))) {
    throw new Error('invalid_scope');
  }

  const isGoogle = isGoogleClient(clientId);
  const t = now();

  if (isGoogle) {
    const newExpiresAt = t + 30 * 86400;
    const newScopes = requested.join(' ');
    const updateResult = db.prepare('UPDATE oauth_refresh_tokens SET expires_at=?, scopes=? WHERE token_hash=? AND revoked_at IS NULL')
      .run(newExpiresAt, newScopes, tokenHash);
    if (updateResult.changes !== 1) throw new Error('invalid_grant');

    const payload = {
      iss: config.oauthIssuer,
      aud: effectiveResource,
      sub: row.subject,
      client_id: clientId,
      scope: newScopes,
      iat: t,
      nbf: t,
      exp: t + 3600,
      jti: crypto.randomUUID(),
      sid: tokenHash
    };
    return {
      access_token: jwt(payload),
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: payload.scope
    };
  }

  const rotateResult = db.prepare('UPDATE oauth_refresh_tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL')
    .run(t, tokenHash);
  if (rotateResult.changes !== 1) throw new Error('invalid_grant');
  return issueTokens({ clientId, scopes: requested, resource: effectiveResource, subject: row.subject });
}

export function revokeToken(token) {
  db.prepare('UPDATE oauth_refresh_tokens SET revoked_at=? WHERE token_hash=?').run(now(), hash(token));
}

export async function authenticateTokenClient(body, req) {
  let clientId = String(body.client_id || '');
  let clientSecret = String(body.client_secret || '');
  let suppliedMethod = clientSecret ? 'client_secret_post' : 'none';
  const auth = req.headers.authorization || '';
  if (auth.toLowerCase().startsWith('basic ')) {
    let decoded;
    try { decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8'); } catch { throw new Error('invalid_client'); }
    const separator = decoded.indexOf(':');
    if (separator < 1) throw new Error('invalid_client');
    const basicId = decoded.slice(0, separator);
    const basicSecret = decoded.slice(separator + 1);
    if (clientId && clientId !== basicId) throw new Error('invalid_client');
    clientId = basicId;
    clientSecret = basicSecret;
    suppliedMethod = 'client_secret_basic';
  }
  if (!clientId) throw new Error('client_authentication_failed');

  const metadata = await clientMetadata(clientId);
  if (!metadata) throw new Error('invalid_client');
  const configuredMethod = metadata.token_endpoint_auth_method || 'none';

  if (configuredMethod === 'none') {
    if (suppliedMethod !== 'none') throw new Error('invalid_client');
    return clientId;
  }

  if (
    config.geminiOAuthConfigured &&
    clientId === config.geminiClientId &&
    suppliedMethod === configuredMethod
  ) {
    const expected = Buffer.from(config.geminiClientSecret, 'utf8');
    const actual = Buffer.from(clientSecret, 'utf8');
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
      throw new Error('invalid_client');
    }
    return clientId;
  }

  throw new Error('invalid_client');
}

export function protectedResourceMetadata() {
  return {
    resource: RESOURCE,
    authorization_servers: [config.oauthIssuer],
    scopes_supported: SCOPES,
    bearer_methods_supported: ['header'],
    resource_documentation: `${config.oauthIssuer}/docs`,
    service_name: 'ServerOps MCP',
    service_id: 'serverops-mcp'
  };
}

export function authorizationServerMetadata() {
  return {
    issuer: config.oauthIssuer,
    authorization_endpoint: `${config.oauthIssuer}/oauth/authorize`,
    token_endpoint: `${config.oauthIssuer}/oauth/token`,
    registration_endpoint: `${config.oauthIssuer}/oauth/register`,
    revocation_endpoint: `${config.oauthIssuer}/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: SCOPES,
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true
  };
}
