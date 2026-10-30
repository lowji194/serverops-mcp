import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'serverops-cli-security-'));
const cliPath = path.resolve('bin/serverops.mjs');
const env = {
  ...process.env,
  NODE_ENV: 'test',
  SERVEROPS_DATA_DIR: path.join(tempRoot, 'data'),
  SERVEROPS_OAUTH_SIGNING_KEY: 'cli-security-test-signing-key-at-least-thirty-two-bytes'
};

function runCli(args) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: process.cwd(),
    env,
    encoding: 'utf8',
    timeout: 3000,
    stdio: ['ignore', 'pipe', 'pipe']
  });
}

test('privileged CLI commands require an interactive local terminal and ignore argv secrets', () => {
  const cases = [
    ['claim', 'activation-token-argv-marker', '--password', 'password-argv-marker'],
    ['reset-password', 'password-argv-marker'],
    ['bootstrap'],
    ['rotate-signing-key'],
    ['revoke-all-tokens'],
    ['token', 'revoke-all'],
    ['clients', 'revoke', 'client-id-argv-marker']
  ];
  for (const args of cases) {
    const result = runCli(args);
    assert.notEqual(result.status, 0, args.join(' '));
    const output = (result.stdout || '') + (result.stderr || '');
    assert.match(output, /root|interactive local terminal/i, args.join(' '));
    assert.doesNotMatch(output, /activation-token-argv-marker|password-argv-marker|client-id-argv-marker/);
  }
});

test.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
