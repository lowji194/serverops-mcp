#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { config, ensureDataDirs } from '../app/config.js';
import * as store from '../app/storage.js';
import {
  claimServer,
  resetPasswordLocally,
  initializeBootstrapToken,
  verifyPasswordHash
} from '../app/bootstrap.js';

ensureDataDirs();

function prompt(query) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(query, ans => { rl.close(); resolve(ans.trim()); }));
}

function promptHidden(query) {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== 'function') return prompt(query);
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    let value = '';
    process.stdout.write(query);
    input.setRawMode(true);
    input.resume();
    const cleanup = () => {
      input.removeListener('data', onData);
      input.setRawMode(false);
      input.pause();
      process.stdout.write('\n');
    };
    const onData = chunk => {
      for (const char of String(chunk)) {
        if (char === '\u0003') {
          cleanup();
          reject(new Error('Input cancelled.'));
          return;
        }
        if (char === '\r' || char === '\n') {
          cleanup();
          resolve(value);
          return;
        }
        if (char === '\u007f' || char === '\b') {
          value = value.slice(0, -1);
          continue;
        }
        if (char >= ' ') value += char;
      }
    };
    input.on('data', onData);
  });
}
function assertLocalRootAndTty() {
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) {
    throw new Error('Run privileged owner commands as root (sudo serverops ...).');
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Owner approval requires an interactive local terminal.');
  }
}

async function authenticateLocalOwner() {
  const storedHash = store.getOwnerPasswordHash();
  if (!storedHash) throw new Error('Server owner password has not been configured.');
  const password = await promptHidden('Owner password: ');
  if (!verifyPasswordHash(password, storedHash)) throw new Error('Owner authentication failed.');
}


async function promptConfirmedPassword(label = 'new owner password') {
  const password = await promptHidden('Enter ' + label + ' (min 8 characters): ');
  if (password.length < 8) throw new Error('Password must contain at least 8 characters.');
  const confirmation = await promptHidden('Confirm password: ');
  if (password !== confirmation) throw new Error('Password confirmation does not match.');
  return password;
}

async function confirmOwnerAction(expected, message) {
  await authenticateLocalOwner();
  const confirmation = await prompt(message + ' Type "' + expected + '" to continue: ');
  if (confirmation !== expected) throw new Error('Owner confirmation did not match. No change was made.');
}

function printPendingApproval(row) {
  console.log('');
  console.log('Approval ID: ' + row.approval_id);
  console.log('Action:      ' + row.action);
  console.log('Requested by: ' + row.actor);
  console.log('Status:      ' + row.status.toUpperCase());
  console.log('Expires:     ' + new Date(row.expires_at * 1000).toISOString());
  console.log('Payload SHA: ' + row.payload_hash);
  console.log('Review payload:');
  console.log(JSON.stringify(row.review, null, 2));
}

function printHelp() {
  console.log(`
ServerOps MCP Command Line Interface

Usage:
  serverops <command> [options]

Commands:
  sudo serverops bootstrap  Generate a one-time 256-bit activation token (15m TTL)
  sudo serverops claim      Interactively claim server using the one-time activation token
  sudo serverops reset-password  Privileged local password reset (no previous password needed)
  sudo serverops rotate-signing-key  Rotate the OAuth 2.1 HS256 signing secret
  sudo serverops token list  List token fingerprints, clients, scopes, and expiry (never shows secrets)
  sudo serverops token revoke <id>  Revoke one refresh token by its displayed fingerprint
  sudo serverops token revoke-all  Revoke all active OAuth refresh tokens
  sudo serverops token rotate  Rotate the signing key and revoke all existing refresh tokens
  sudo serverops clients list  List registered OAuth clients
  sudo serverops clients revoke <id>  Revoke a client and all of its refresh tokens
  sudo serverops approvals list  List pending privileged operations awaiting owner approval
  sudo serverops approvals approve <id>  Review an operation and issue a one-time grant locally
  sudo serverops approvals deny <id>   Deny a pending privileged operation
  sudo serverops status  Display server state, claim status, and storage information
  help                  Show this help text

OAuth access tokens are issued only by the OAuth authorization flow. The CLI never prints
or creates raw MCP bearer tokens. Re-authorize a client after its token has been revoked.

Examples:
  sudo serverops bootstrap
  sudo serverops claim
  sudo serverops reset-password
  sudo serverops approvals list
  sudo serverops approvals approve <approval-id>
  sudo serverops status
`);
}

function rotateSigningKey() {
  if (process.env.SERVEROPS_OAUTH_SIGNING_KEY?.trim()) {
    throw new Error('SERVEROPS_OAUTH_SIGNING_KEY is set in the environment. Update the protected environment file, revoke sessions, and restart the service to rotate it.');
  }
  const newKey = crypto.randomBytes(32).toString('hex');
  const keyFile = path.join(config.dataDir, '.signing_key');
  const temporary = keyFile + '.' + process.pid + '.' + crypto.randomBytes(6).toString('hex') + '.tmp';
  fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o750 });
  let fd;
  try {
    fd = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(fd, newKey, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temporary, keyFile);
  } catch (cause) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    try { fs.unlinkSync(temporary); } catch {}
    throw cause;
  }
  const t = store.now();
  const revoked = store.db.prepare('UPDATE oauth_refresh_tokens SET revoked_at=? WHERE revoked_at IS NULL').run(t);
  store.audit('signing_key_rotated', null, 'ok', 'OAuth signing key rotated; active refresh tokens revoked');
  console.log('[Success] OAuth signing key rotated.');
  console.log('[Success] Revoked ' + revoked.changes + ' active refresh tokens.');
  console.log('Restart the ServerOps service to load the new signing key. All clients must authorize again.');
}
async function main() {
  const [,, cmd, ...args] = process.argv;

  switch (cmd) {
    case 'bootstrap':
    case 'init': {
      assertLocalRootAndTty();
      if (store.isServerClaimed()) {
        console.error('[Error] Server is already claimed and initialized.');
        console.error('Use "sudo serverops reset-password" to change owner password.');
        process.exit(1);
      }
      const res = initializeBootstrapToken(true);
      if (!res?.token) {
        console.log('An activation token is already active and will not be displayed again.');
        console.log('Wait for its 15-minute expiry, then run "serverops bootstrap" to issue a replacement.');
        console.log('The active token file remains protected by filesystem permissions.');
        return;
      }
      console.log('       ServerOps MCP First-Run Activation Token       ');
      console.log('======================================================');
      console.log(`Token:      ${res.token}`);
      console.log(`Expires:    ${new Date(res.expiresAt * 1000).toISOString()} (15 minutes TTL)`);
      console.log(`Token File: ${res.tokenFile} (mode 0600)`);
      console.log('------------------------------------------------------');
      console.log('IMPORTANT: This single-use token allows setting your owner password.');
      console.log('It will NOT be shown again and cannot be used for MCP API calls.');
      console.log('\nClaim via CLI:');
      console.log('  sudo serverops claim');
      console.log('\nOr via Web UI during first login.');
      console.log('======================================================\n');
      break;
    }

    case 'claim': {
      assertLocalRootAndTty();
      if (args.length) throw new Error('Do not pass activation tokens or passwords as command-line arguments. Run "serverops claim" interactively.');
      let token = await promptHidden('Enter 256-bit activation token (press Enter to use the protected local token file): ');
      if (!token) {
        try {
          token = fs.readFileSync(path.join(config.dataDir, 'bootstrap.token'), 'utf8').trim();
        } catch {
          throw new Error('No activation token was entered and the protected local token file is unavailable. Run "sudo serverops bootstrap" first.');
        }
      }
      const password = await promptConfirmedPassword();
      const result = claimServer({ token, password });
      console.log('[Success] ' + result.message);
      break;
    }
    case 'reset-password': {
      assertLocalRootAndTty();
      if (args.length) throw new Error('Do not pass passwords as command-line arguments. Run "serverops reset-password" interactively.');
      const password = await promptConfirmedPassword();
      const result = resetPasswordLocally(password);
      console.log('[Success] ' + result.message);
      break;
    }
    case 'rotate-signing-key': {
      assertLocalRootAndTty();
      await confirmOwnerAction('ROTATE SIGNING KEY', 'Rotate the OAuth signing key and invalidate every active session?');
      rotateSigningKey();
      break;
    }

    case 'revoke-all-tokens': {
      assertLocalRootAndTty();
      await confirmOwnerAction('REVOKE ALL TOKENS', 'Revoke every active OAuth refresh session?');
      const t = store.now();
      const updated = store.db.prepare('UPDATE oauth_refresh_tokens SET revoked_at=? WHERE revoked_at IS NULL').run(t);
      store.audit('tokens_revoked_all', null, 'ok', 'Revoked ' + updated.changes + ' refresh tokens');
      console.log('[Success] Revoked ' + updated.changes + ' active refresh tokens.');
      break;
    }

    case 'approvals': {
      const action = args[0] || 'list';
      assertLocalRootAndTty();

      if (action === 'list') {
        const rows = store.listPendingAdminApprovals(100);
        if (!rows.length) {
          console.log('No pending owner approvals.');
          break;
        }
        for (const row of rows) printPendingApproval(row);
      } else if (action === 'approve') {
        const approvalId = String(args[1] || '');
        if (!/^[0-9a-f-]{36}$/i.test(approvalId)) throw new Error('Provide a valid approval UUID.');
        const row = store.getPendingAdminApproval(approvalId);
        if (!row) throw new Error('Approval request not found.');
        if (row.status !== 'pending') throw new Error('Approval request is not pending: ' + row.status);
        printPendingApproval(row);
        await authenticateLocalOwner();
        const expected = 'APPROVE ' + approvalId.slice(0, 8);
        const confirmation = await prompt('Type ' + expected + ' to issue a 5-minute one-time grant: ');
        if (confirmation !== expected) throw new Error('Owner confirmation did not match. Approval was not issued.');
        const issued = store.approvePendingAdminApproval(approvalId, 300);
        console.log('');
        console.log('[Success] Owner approval issued for ' + issued.action + '.');
        console.log('Expires: ' + new Date(issued.expiresAt * 1000).toISOString());
        console.log('One-time approval token (copy it into the matching MCP tool call):');
        console.log(issued.token);
      } else if (action === 'deny') {
        const approvalId = String(args[1] || '');
        if (!/^[0-9a-f-]{36}$/i.test(approvalId)) throw new Error('Provide a valid approval UUID.');
        const row = store.getPendingAdminApproval(approvalId);
        if (!row || row.status !== 'pending') throw new Error('Approval request is not pending.');
        printPendingApproval(row);
        await authenticateLocalOwner();
        const expected = 'DENY ' + approvalId.slice(0, 8);
        const confirmation = await prompt('Type ' + expected + ' to deny this operation: ');
        if (confirmation !== expected) throw new Error('Owner confirmation did not match. Request remains pending.');
        store.denyPendingAdminApproval(approvalId);
        console.log('[Success] Approval request denied.');
      } else {
        console.log('Usage: serverops approvals list | approve <approval-id> | deny <approval-id>');
      }
      break;
    }

    case 'token': {
      assertLocalRootAndTty();
      const action = args[0] || 'help';
      if (action === 'list') {
        const rows = store.db.prepare('SELECT token_hash, client_id, scopes, expires_at, revoked_at FROM oauth_refresh_tokens ORDER BY expires_at DESC LIMIT 200').all();
        if (!rows.length) console.log('No OAuth refresh tokens found.');
        for (const row of rows) {
          const state = row.revoked_at ? 'REVOKED' : (row.expires_at <= store.now() ? 'EXPIRED' : 'ACTIVE');
          console.log('Fingerprint: ' + row.token_hash.slice(0, 16) + ' | ' + state +
            ' | Client: ' + row.client_id + ' | Scopes: ' + row.scopes +
            ' | Expires: ' + new Date(row.expires_at * 1000).toISOString());
        }
      } else if (action === 'revoke') {
        const fingerprint = String(args[1] || '').toLowerCase();
        if (!/^[a-f0-9]{12,64}$/.test(fingerprint)) {
          throw new Error('Provide a token fingerprint from "serverops token list" (12-64 hexadecimal characters).');
        }
        const rows = store.db.prepare('SELECT token_hash FROM oauth_refresh_tokens WHERE token_hash LIKE ?').all(fingerprint + '%');
        if (rows.length !== 1) {
          throw new Error(rows.length ? 'Fingerprint is ambiguous; use more characters.' : 'No token matches that fingerprint.');
        }
        await confirmOwnerAction('REVOKE TOKEN ' + fingerprint.slice(0, 12), 'Revoke this OAuth refresh session?');
        const result = store.db.prepare('UPDATE oauth_refresh_tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL').run(store.now(), rows[0].token_hash);
        if (!result.changes) throw new Error('Token is already revoked.');
        store.audit('token_revoked', null, 'ok', 'Refresh token revoked by fingerprint ' + fingerprint);
        console.log('[Success] Refresh token revoked. The client must authorize again.');
      } else if (action === 'revoke-all') {
        await confirmOwnerAction('REVOKE ALL TOKENS', 'Revoke every active OAuth refresh session?');
        const updated = store.db.prepare('UPDATE oauth_refresh_tokens SET revoked_at=? WHERE revoked_at IS NULL').run(store.now());
        store.audit('tokens_revoked_all', null, 'ok', 'Revoked ' + updated.changes + ' refresh tokens');
        console.log('[Success] Revoked ' + updated.changes + ' active refresh tokens.');
      } else if (action === 'rotate') {
        await confirmOwnerAction('ROTATE SIGNING KEY', 'Rotate the OAuth signing key and invalidate every active session?');
        rotateSigningKey();
      } else {
        console.log('Usage: serverops token list | revoke <fingerprint> | revoke-all | rotate');
      }
      break;
    }

    case 'clients': {
      assertLocalRootAndTty();
      const action = args[0] || 'help';
      if (action === 'list') {
        const rows = store.db.prepare('SELECT client_id, metadata_json, created_at FROM oauth_clients ORDER BY created_at DESC').all();
        if (!rows.length) console.log('No OAuth clients registered.');
        for (const row of rows) {
          let meta = {};
          try { meta = JSON.parse(row.metadata_json); } catch {}
          console.log('Client: ' + row.client_id + ' | Name: ' + (meta.client_name || 'Unnamed') +
            ' | Redirect URIs: ' + (meta.redirect_uris || []).length +
            ' | Registered: ' + new Date(row.created_at * 1000).toISOString());
        }
      } else if (action === 'revoke') {
        const clientId = String(args[1] || '');
        if (!clientId || clientId.length > 1024) throw new Error('Provide a valid client ID.');
        const exists = store.db.prepare('SELECT client_id FROM oauth_clients WHERE client_id=?').get(clientId);
        if (!exists) throw new Error('OAuth client not found.');
        await confirmOwnerAction('REVOKE CLIENT ' + clientId.slice(0, 8), 'Remove this OAuth client and revoke all its refresh sessions?');
        const t = store.now();
        const tx = store.db.transaction(() => {
          const revoked = store.db.prepare('UPDATE oauth_refresh_tokens SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL').run(t, clientId);
          store.db.prepare('DELETE FROM oauth_codes WHERE client_id=?').run(clientId);
          store.db.prepare('DELETE FROM oauth_clients WHERE client_id=?').run(clientId);
          return revoked.changes;
        });
        const count = tx();
        store.audit('oauth_client_revoked', null, 'ok', 'OAuth client revoked; refresh tokens revoked: ' + count);
        console.log('[Success] OAuth client removed and ' + count + ' active refresh tokens revoked. Reconnect the client to register again.');
      } else {
        console.log('Usage: serverops clients list | revoke <client_id>');
      }
      break;
    }

    case 'status': {
      const isClaimed = store.isServerClaimed();
      const clientCount = store.db.prepare('SELECT COUNT(*) AS c FROM oauth_clients').get().c;
      const activeTokens = store.db.prepare('SELECT COUNT(*) AS c FROM oauth_refresh_tokens WHERE revoked_at IS NULL AND expires_at > ?').get(store.now()).c;
      console.log(`
ServerOps MCP Status:
  Status:           ${isClaimed ? 'INITIALIZED (Claimed)' : 'PENDING ACTIVATION'}
  Owner Subject:    ${config.ownerSubject}
  HTTP Bind:        ${config.host}:${config.port}
  Public Base URL:  ${config.publicBaseUrl}
  Data Directory:   ${config.dataDir}
  OAuth Clients:    ${clientCount}
  Active Tokens:    ${activeTokens}
  Gemini OAuth:     ${config.geminiOAuthConfigured ? 'CONFIGURED' : 'NOT CONFIGURED (Optional)'}
`);
      break;
    }

    case 'help':
    case '--help':
    case '-h':
    default:
      printHelp();
      break;
  }
}

main().catch(err => {
  console.error('[Fatal Error]', err);
  process.exit(1);
});
