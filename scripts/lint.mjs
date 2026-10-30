#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const roots = ['app', 'bin', 'tests', 'scripts'];
const extensions = new Set(['.js', '.mjs', '.cjs']);
const ignoredDirectories = new Set(['node_modules', '.git', 'coverage', '.cache', '.data-test']);
const files = [];

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) walk(path.join(directory, entry.name));
      continue;
    }
    if (entry.isFile() && extensions.has(path.extname(entry.name).toLowerCase())) {
      files.push(path.join(directory, entry.name));
    }
  }
}

for (const directory of roots) {
  if (fs.existsSync(directory) && fs.lstatSync(directory).isDirectory()) walk(directory);
}

let failed = 0;
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], {
    encoding: 'utf8',
    timeout: 30000,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  if (result.status !== 0) {
    failed += 1;
    process.stderr.write('FAIL ' + file + '\n' + (result.stderr || result.error?.message || 'Syntax check failed') + '\n');
  }
}

for (const file of ['package.json', 'package-lock.json']) {
  try {
    JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    failed += 1;
    process.stderr.write('FAIL ' + file + '\n' + error.message + '\n');
  }
}

if (failed) {
  process.stderr.write('Lint failed: ' + failed + ' of ' + files.length + ' JavaScript files failed.\n');
  process.exitCode = 1;
} else {
  process.stdout.write('Lint passed: ' + files.length + ' JavaScript files and 2 JSON manifests checked.\n');
}
