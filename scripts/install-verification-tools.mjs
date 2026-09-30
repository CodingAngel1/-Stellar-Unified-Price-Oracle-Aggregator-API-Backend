#!/usr/bin/env node
/**
 * Installs the pinned formal-verification toolchain into `verification/tools/`.
 *
 * The toolchain is pinned by `verification/tools.lock.json` (URL + SHA-256 per
 * platform) so CI and local runs solve the same SMT/TLA+ problems with the same
 * binaries.  Nothing here is optional: if a pinned artefact cannot be
 * downloaded and checksummed, or `java` (needed by TLC) is missing, the script
 * exits non-zero so callers fail instead of silently skipping verification.
 *
 * Usage:
 *   node scripts/install-verification-tools.mjs          # install/update
 *   node scripts/install-verification-tools.mjs --verify # check only
 */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const toolsDir = join(repoRoot, 'verification', 'tools');
const binDir = join(toolsDir, 'bin');
const lock = JSON.parse(readFileSync(join(repoRoot, 'verification', 'tools.lock.json'), 'utf8'));

const verifyOnly = process.argv.includes('--verify');

function fail(message) {
  process.stderr.write(`install-verification-tools: ${message}\n`);
  process.exit(1);
}

function run(command, args, options = {}) {
  return spawnSync(command, args, { encoding: 'utf8', ...options });
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex').toLowerCase();
}

function verifyChecksum(buffer, expected, label) {
  const actual = sha256(buffer);
  if (actual !== expected.toLowerCase()) {
    throw new Error(
      `checksum mismatch for ${label}\n  expected ${expected.toLowerCase()}\n  actual   ${actual}`,
    );
  }
}

async function fetchBuffer(url) {
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) throw new Error(`GET ${url} -> HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

function extractZip(zipPath, destination) {
  mkdirSync(destination, { recursive: true });
  const attempts = [
    ['unzip', ['-q', '-o', zipPath, '-d', destination]],
    ['tar', ['-xf', zipPath, '-C', destination]],
    [process.platform === 'win32' ? 'python' : 'python3', ['-m', 'zipfile', '-e', zipPath, destination]],
  ];
  for (const [command, args] of attempts) {
    if (run(command, ['--version']).error) continue;
    if (run(command, args).status === 0) return command;
  }
  throw new Error(`no working unzipper found (tried: ${attempts.map(([c]) => c).join(', ')})`);
}

function findZ3Binary(root) {
  const wanted = process.platform === 'win32' ? 'z3.exe' : 'z3';
  const queue = [root];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const entry of readdirSync(current)) {
      const full = join(current, entry);
      if (statSync(full).isDirectory()) queue.push(full);
      else if (entry === wanted) return full;
    }
  }
  return null;
}

function javaAvailable() {
  const probe = run(process.platform === 'win32' ? 'java.exe' : 'java', ['-version']);
  return !probe.error && probe.status === 0;
}

function installedZ3Reports(version) {
  const binaryName = process.platform === 'win32' ? 'z3.exe' : 'z3';
  const target = join(binDir, binaryName);
  if (!existsSync(target)) return false;
  const probe = run(target, ['--version']);
  return probe.status === 0 && probe.stdout.includes(version);
}

async function installZ3() {
  const platform = lock.z3.platforms[platformKey()];
  if (!platform) {
    fail(
      `no pinned z3 build for platform "${platformKey()}" (have: ${Object.keys(lock.z3.platforms).join(', ')}). ` +
        'Provide z3 on PATH or run on a supported platform.',
    );
  }

  if (installedZ3Reports(lock.z3.version)) return join(binDir, process.platform === 'win32' ? 'z3.exe' : 'z3');
  if (verifyOnly) {
    fail(`z3 ${lock.z3.version} is not installed; run: node scripts/install-verification-tools.mjs`);
  }

  mkdirSync(binDir, { recursive: true });
  const downloadDir = join(toolsDir, '.download');
  mkdirSync(downloadDir, { recursive: true });
  const zipPath = join(downloadDir, `z3-${lock.z3.version}-${platformKey()}.zip`);

  let buffer;
  if (existsSync(zipPath)) {
    buffer = readFileSync(zipPath);
  } else {
    process.stdout.write(`Downloading z3 ${lock.z3.version} (${platformKey()})\n`);
    buffer = await fetchBuffer(platform.url);
    verifyChecksum(buffer, platform.sha256, `z3 ${lock.z3.version} (${platformKey()})`);
    writeFileSync(zipPath, buffer);
  }
  verifyChecksum(buffer, platform.sha256, `z3 ${lock.z3.version} (${platformKey()})`);

  const extractDir = join(toolsDir, 'z3');
  rmSync(extractDir, { recursive: true, force: true });
  extractZip(zipPath, extractDir);
  const extracted = findZ3Binary(extractDir);
  if (!extracted) fail(`z3 binary missing from ${platform.url}`);

  const target = join(binDir, process.platform === 'win32' ? 'z3.exe' : 'z3');
  copyFileSync(extracted, target);
  if (process.platform !== 'win32') chmodSync(target, 0o755);
  rmSync(extractDir, { recursive: true, force: true });

  if (!installedZ3Reports(lock.z3.version)) {
    fail(`installed z3 did not report version ${lock.z3.version}`);
  }
  return target;
}

async function installTla2Tools() {
  const target = join(toolsDir, lock.tla2tools.jar);
  if (existsSync(target)) {
    const matches = sha256(readFileSync(target)) === lock.tla2tools.sha256.toLowerCase();
    if (matches) return target;
    if (verifyOnly) fail(`${target} exists but does not match the pinned checksum`);
    rmSync(target);
  } else if (verifyOnly) {
    fail(`${target} missing; run: node scripts/install-verification-tools.mjs`);
  }

  mkdirSync(toolsDir, { recursive: true });
  process.stdout.write(`Downloading tla2tools ${lock.tla2tools.version}\n`);
  const buffer = await fetchBuffer(lock.tla2tools.url);
  verifyChecksum(buffer, lock.tla2tools.sha256, `tla2tools ${lock.tla2tools.version}`);
  writeFileSync(target, buffer);
  return target;
}

function platformKey() {
  return `${process.platform}-${process.arch}`;
}

async function main() {
  mkdirSync(binDir, { recursive: true });
  const z3 = await installZ3();
  const jar = await installTla2Tools();

  if (!javaAvailable()) {
    fail(
      'java not found on PATH; TLC (tla2tools.jar) needs a JRE 11+.\n' +
        '  windows: winget install EclipseAdoptium.Temurin.21.JRE\n' +
        '  debian:  sudo apt-get install -y openjdk-21-jre-headless\n' +
        '  ci:      uses: actions/setup-java@v4 with distribution: temurin',
    );
  }

  process.stdout.write(`z3        ${z3}\n`);
  process.stdout.write(`tla2tools ${jar}\n`);
  process.stdout.write('java      available\n');
}

main().catch((error) => fail(error instanceof Error ? (error.stack ?? error.message) : String(error)));
