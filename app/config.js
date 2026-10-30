import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

function loadEnvironmentFile() {
  const explicitPath = process.env.SERVEROPS_ENV_FILE;
  if (process.env.NODE_ENV === 'test' && !explicitPath) return;
  const envFile = explicitPath || '/etc/serverops-mcp/serverops.env';
  try {
    const content = fs.readFileSync(envFile, 'utf8');
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
      if (!match || process.env[match[1]] !== undefined) continue;
      let value = match[2].trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      process.env[match[1]] = value;
    }
  } catch {}
}

loadEnvironmentFile();

function resolveDataDir() {
  if (process.env.SERVEROPS_DATA_DIR) {
    return path.resolve(process.env.SERVEROPS_DATA_DIR);
  }
  // If running in development / test without root privileges, allow local fallback
  if (process.env.NODE_ENV === 'test' && !process.env.SERVEROPS_DATA_DIR) {
    return path.resolve(process.cwd(), '.data-test');
  }
  return '/var/lib/serverops-mcp';
}

const dataDir = resolveDataDir();
const signingKeyFile = path.join(dataDir, '.signing_key');

function getOrGenerateSigningKey() {
  const envKey = process.env.SERVEROPS_OAUTH_SIGNING_KEY?.trim();
  if (envKey) {
    if (Buffer.byteLength(envKey) < 32) throw new Error('SERVEROPS_OAUTH_SIGNING_KEY must contain at least 32 bytes.');
    return envKey;
  }
  const readExisting = () => {
    let fd;
    try {
      fd = fs.openSync(signingKeyFile, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.nlink > 1 || (stat.mode & 0o077) !== 0 ||
          (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
        throw new Error('OAuth signing key file ownership or permissions are unsafe.');
      }
      const saved = fs.readFileSync(fd, 'utf8').trim();
      if (Buffer.byteLength(saved) < 32) throw new Error('OAuth signing key file is invalid.');
      return saved;
    } finally {
      if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    }
  };
  try {
    return readExisting();
  } catch (cause) {
    if (cause?.code !== 'ENOENT') throw new Error('OAuth signing key file is unsafe or unreadable; verify its owner and mode 0600.', { cause });
  }
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o750 });
  const generated = crypto.randomBytes(32).toString('hex');
  let fd;
  try {
    fd = fs.openSync(signingKeyFile, 'wx', 0o600);
    fs.writeFileSync(fd, generated, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    return generated;
  } catch (cause) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    if (cause?.code === 'EEXIST') return readExisting();
    throw new Error('Unable to securely create the OAuth signing key in the private data directory.', { cause });
  }
}
export const config = Object.freeze({
  host: process.env.SERVEROPS_BIND_HOST || '127.0.0.1',
  port: Number(process.env.SERVEROPS_PORT || 8790),
  publicBaseUrl: (process.env.SERVEROPS_PUBLIC_BASE_URL || 'https://mcp.example.com').replace(/\/$/, ''),
  oauthIssuer: (process.env.SERVEROPS_OAUTH_ISSUER || process.env.SERVEROPS_PUBLIC_BASE_URL || 'https://mcp.example.com').replace(/\/$/, ''),
  ownerSubject: process.env.SERVEROPS_OWNER_SUBJECT?.trim() || 'serverops-owner',
  ownerPasswordHash: process.env.SERVEROPS_OWNER_PASSWORD_HASH?.trim() || null,
  oauthSigningKey: getOrGenerateSigningKey(),
  // Optional confidential OAuth client used by Gemini integrations that require a Google Cloud Client ID/Secret.
  geminiClientId: process.env.SERVEROPS_GEMINI_CLIENT_ID?.trim() || null,
  geminiClientSecret: process.env.SERVEROPS_GEMINI_CLIENT_SECRET || null,
  geminiRedirectUri: process.env.SERVEROPS_GEMINI_REDIRECT_URI?.trim() || null,
  geminiOAuthConfigured: Boolean(
    process.env.SERVEROPS_GEMINI_CLIENT_ID?.trim() &&
    process.env.SERVEROPS_GEMINI_CLIENT_SECRET &&
    process.env.SERVEROPS_GEMINI_REDIRECT_URI?.trim()
  ),
  dataDir,
  backupDir: process.env.SERVEROPS_BACKUP_DIR || path.join(dataDir, 'backups'),
  secretDir: process.env.SERVEROPS_SECRET_DIR || '/etc/serverops-mcp/secrets',
  networkSecretDir: process.env.SERVEROPS_SECRET_DIR || '/etc/serverops-mcp/secrets',
  executionConcurrency: Number(process.env.SERVEROPS_EXECUTION_CONCURRENCY || 4),
  executionQueueLimit: Number(process.env.SERVEROPS_EXECUTION_QUEUE_LIMIT || 32),
  executionMaxTimeoutSeconds: Number(process.env.SERVEROPS_EXECUTION_MAX_TIMEOUT_SECONDS || 3600),
  executionMaxOutputBytes: Number(process.env.SERVEROPS_EXECUTION_MAX_OUTPUT_BYTES || 67108864),
  networkMaxResponseBytes: Math.min(268435456, Math.max(1024, Number(process.env.SERVEROPS_NETWORK_MAX_RESPONSE_BYTES) || 67108864)),
  networkArtifactTtlSeconds: Math.min(30 * 86400, Math.max(300, Number(process.env.SERVEROPS_NETWORK_ARTIFACT_TTL_SECONDS) || 86400)),
  bootstrapTokenTtlSeconds: 900 // 15 minutes TTL for single-use activation
});

export function ensureDataDirs() {
  for (const dir of [config.dataDir, path.join(config.dataDir, 'network'), config.backupDir, path.join(config.backupDir, 'admin'), path.join(config.backupDir, 'deploy'), path.join(config.dataDir, 'artifacts')]) {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
    } catch (e) {
      if (process.env.NODE_ENV !== 'test') {
        console.warn(`Warning: Could not create directory ${dir}: ${e.message}`);
      }
    }
  }
}
