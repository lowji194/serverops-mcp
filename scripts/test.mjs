#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const testDirectory = 'tests';
const files = fs.readdirSync(testDirectory, { withFileTypes: true })
  .filter(entry => entry.isFile() && entry.name.endsWith('.test.js'))
  .map(entry => path.join(testDirectory, entry.name))
  .sort();

if (!files.length) {
  process.stderr.write('No test files were found.\n');
  process.exitCode = 1;
} else {
  const env = { ...process.env, NODE_ENV: 'test' };
  for (const name of Object.keys(env)) {
    if (name.startsWith('SERVEROPS_') || name === 'NODE_OPTIONS') delete env[name];
  }
  env.NODE_ENV = 'test';
  const result = spawnSync(process.execPath, ['--test', ...files], {
    cwd: process.cwd(),
    env,
    shell: false,
    stdio: 'inherit'
  });
  process.exitCode = result.status ?? 1;
}
