import crypto from 'node:crypto';
import { config } from './config.js';
import { SCOPES, verifyAccessToken } from './oauth.js';

export function bearerFrom(req) {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  return match?.[1]?.trim() || '';
}

export function requireMcpAuth(req, res, next) {
  const token = bearerFrom(req);

  try {
    req.authInfo = verifyAccessToken(token);
    return next();
  } catch {
    const challenge = `Bearer resource_metadata="${config.oauthIssuer}/.well-known/oauth-protected-resource", scope="${SCOPES.join(' ')}", error="invalid_token", error_description="${token ? 'The access token is invalid or expired' : 'Authentication is required'}"`;
    res.set('WWW-Authenticate', challenge);
    return res.status(401).json({
      error: 'unauthorized',
      error_description: token ? 'invalid_or_expired_token' : 'authentication_required'
    });
  }
}

export function requireScope(ctx, scope) {
  const scopes = Array.isArray(ctx?.authInfo?.scopes) ? ctx.authInfo.scopes : [];
  if (typeof scope !== 'string' || !scope.trim() || !scopes.includes(scope)) {
    throw new Error(`Missing OAuth scope: ${scope || 'unspecified'}`);
  }
  return true;
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function hashToken(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
