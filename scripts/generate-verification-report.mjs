#!/usr/bin/env node
/**
 * Generates verification/reports/latest.md (and latest.json).
 *
 * Rules this script exists to enforce (issue #610):
 *   - a check that could not be executed renders as NOT CHECKED, never as
 *     passed, and a required check that is NOT CHECKED fails the run;
 *   - a check that executed and failed fails the run;
 *   - every row records the exact command and git revision that produced it,
 *     so the claim is reproducible from the report alone.
 *
 * Usage:
 *   node scripts/generate-verification-report.mjs           # z3 + TLC + artefacts
 *   node scripts/generate-verification-report.mjs --cargo   # also run cargo test here
 *
 * CI sets CARGO_TEST_OUTCOME to the outcome of the workflow step that runs
 * `cargo test`, so the Rust property-test row carries the real result instead
 * of being re-executed inside the report job.
 */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(repoRoot);

const runCargo = process.argv.includes('--cargo');
const SMT_FILE = 'verification/smt/price-oracle-invariants.smt2';
const TLA_FILE = 'specs/PriceOracle.tla';
const TLA_CONFIG = 'specs/PriceOracle.cfg';
const TLA_TOOLS = 'verification/tools/tla2tools.jar';
// TLC rejects a module whose path uses '/' on Windows, so the invocation and
// the command recorded in the report use platform-native separators.
const TLA_FILE_PATH = join('specs', 'PriceOracle.tla');
const TLA_CONFIG_PATH = join('specs', 'PriceOracle.cfg');
const TLA_TOOLS_PATH = join('verification', 'tools', 'tla2tools.jar');
const Z3_BINARY = join('verification', 'tools', 'bin', process.platform === 'win32' ? 'z3.exe' : 'z3');
const REPORT_DIR = join(repoRoot, 'verification', 'reports');

const STATUS = {
  passed: 'PASSED',
  failed: 'FAILED',
  notChecked: 'NOT CHECKED',
};

function run(command, args, options = {}) {
  return spawnSync(command, args, { encoding: 'utf8', ...options });
}

function git(args) {
  const result = run('git', args);
  return { status: result.status ?? 1, stdout: (result.stdout ?? '').trim(), stderr: (result.stderr ?? '').trim() };
}

function commandToString(command, args) {
  return [command, ...args].map((part) => (/\s/.test(part) ? JSON.stringify(part) : part)).join(' ');
}

function hashFile(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function countCheckSatQueries(source) {
  return source
    .split(/\r?\n/)
    .map((line) => line.split(';')[0])
    .filter((line) => line.includes('(check-sat)')).length;
}

const rows = [];

function addRow({ name, status, command, notes, required = false }) {
  rows.push({ name, status, command, notes, required });
  return rows[rows.length - 1];
}

function toolVersion(command, args) {
  const probe = run(command, args);
  if (probe.error || probe.status !== 0) return null;
  return (probe.stdout || probe.stderr).split(/\r?\n/).find((line) => line.trim().length > 0) ?? 'unknown';
}

// ── Revision ────────────────────────────────────────────────────────────────
const head = git(['rev-parse', 'HEAD']);
if (head.status !== 0) {
  process.stderr.write(`generate-verification-report: not a git checkout: ${head.stderr}\n`);
  process.exit(1);
}
const revision = head.stdout;
const shortRevision = revision.slice(0, 7);
const worktree = git(['status', '--porcelain']);
const worktreeState = worktree.stdout === '' ? 'clean' : `dirty (${worktree.stdout.split('\n').length} path(s) modified)`;

// ── Checked-in artefacts ────────────────────────────────────────────────────
const artefacts = [
  { path: TLA_FILE, role: 'TLA+ specification (checked by TLC)' },
  { path: TLA_CONFIG, role: 'TLC model configuration (checked by TLC)' },
  { path: SMT_FILE, role: 'SMT2 invariants (checked by z3)' },
  { path: 'contracts/price-oracle/src/fuzz.rs', role: 'in-crate property tests (executed by `cargo test`)' },
  { path: 'docs/formal-verification/price-oracle-guarantees.md', role: 'verification scope and known gaps' },
];

for (const artefact of artefacts) {
  const tracked = git(['ls-files', '--error-unmatch', '--', artefact.path]);
  const exists = existsSync(artefact.path);
  const size = exists ? statSync(artefact.path).size : 0;
  const missing = [];
  if (tracked.status !== 0) missing.push('not tracked by git');
  if (!exists) missing.push('missing from the worktree');
  else if (size === 0) missing.push('empty file');
  addRow({
    name: artefact.path,
    status: missing.length === 0 ? 'passed' : 'failed',
    command: `git ls-files --error-unmatch -- ${artefact.path}`,
    notes: missing.length === 0 ? `${artefact.role}; ${size} bytes` : `${artefact.role}; ${missing.join(', ')}`,
    required: true,
  });
}

// ── z3 SMT invariants ───────────────────────────────────────────────────────
function resolveZ3() {
  if (existsSync(Z3_BINARY)) return Z3_BINARY;
  const probe = run('z3', ['--version']);
  return probe.error ? null : 'z3';
}

const z3 = resolveZ3();
if (!z3) {
  addRow({
    name: 'z3 SMT invariant check',
    status: STATUS.notChecked,
    command: `node scripts/install-verification-tools.mjs && z3 ${SMT_FILE}`,
    notes: 'z3 is not installed, so no invariant was solved in this run',
    required: true,
  });
} else {
  const z3Result = run(z3, [SMT_FILE]);
  const results = (z3Result.stdout ?? '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const expected = countCheckSatQueries(readFileSync(SMT_FILE, 'utf8'));
  const allUnsat = results.length > 0 && results.every((line) => line === 'unsat');
  const complete = results.length === expected;
  const version = toolVersion(z3, ['--version']);
  addRow({
    name: 'z3 SMT invariant check',
    status: z3Result.status === 0 && complete && allUnsat ? 'passed' : 'failed',
    command: `${z3} ${SMT_FILE}`,
    notes: `${results.filter((line) => line === 'unsat').length}/${expected} (check-sat) queries returned unsat; ${version}`,
    required: true,
  });
}

// ── TLC model check ─────────────────────────────────────────────────────────
function resolveJava() {
  const probe = run(process.platform === 'win32' ? 'java.exe' : 'java', ['-version']);
  return probe.error ? null : process.platform === 'win32' ? 'java.exe' : 'java';
}

const java = resolveJava();
const tlcCommand = `java -jar ${TLA_TOOLS_PATH} -config ${TLA_CONFIG_PATH} ${TLA_FILE_PATH}`;
if (!java) {
  addRow({
    name: 'TLC model check (PriceOracle.tla)',
    status: STATUS.notChecked,
    command: tlcCommand,
    notes: 'java is not installed, so no state was explored in this run',
    required: true,
  });
} else if (!existsSync(TLA_TOOLS)) {
  addRow({
    name: 'TLC model check (PriceOracle.tla)',
    status: STATUS.notChecked,
    command: `node scripts/install-verification-tools.mjs && ${tlcCommand}`,
    notes: `${TLA_TOOLS} is missing, so no state was explored in this run`,
    required: true,
  });
} else {
  const tlc = run(java, ['-jar', TLA_TOOLS_PATH, '-config', TLA_CONFIG_PATH, TLA_FILE_PATH], {
    cwd: repoRoot,
  });
  const output = `${tlc.stdout ?? ''}${tlc.stderr ?? ''}`;
  const completed = /Model checking completed\. No error has been found\./.test(output);
  const errored = /^\s*Error:/m.test(output);
  const states = output.match(/(\d+) states generated, (\d+) distinct states found/);
  const tlcVersion = (output.split(/\r?\n/).find((line) => line.includes('TLC2 Version')) ?? 'TLC2').trim();
  addRow({
    name: 'TLC model check (PriceOracle.tla)',
    status: tlc.status === 0 && completed && !errored ? 'passed' : 'failed',
    command: tlcCommand,
    notes: states
      ? `${states[1]} states generated, ${states[2]} distinct states; ${tlcVersion}`
      : completed
        ? tlcVersion
        : `exit ${tlc.status}: ${output.split(/\r?\n/).find((line) => line.trim().startsWith('Error')) ?? 'incomplete run'}`,
    required: true,
  });
}

// ── Rust property tests ─────────────────────────────────────────────────────
const cargoCommand = 'cargo test --manifest-path contracts/price-oracle/Cargo.toml';
if (runCargo) {
  const cargoProbe = run(process.platform === 'win32' ? 'cargo.exe' : 'cargo', ['--version']);
  if (cargoProbe.error) {
    addRow({
      name: 'Rust property tests (fuzz.rs)',
      status: STATUS.notChecked,
      command: cargoCommand,
      notes: 'cargo is not installed, so no property test was executed in this run',
      required: true,
    });
  } else {
    const cargo = run('cargo', ['test', '--manifest-path', join('contracts', 'price-oracle', 'Cargo.toml')], {
      cwd: repoRoot,
      maxBuffer: 32 * 1024 * 1024,
    });
    const output = `${cargo.stdout ?? ''}${cargo.stderr ?? ''}`;
    const summary = output.match(/test result: (\S+)/g)?.slice(-1)[0] ?? '';
    addRow({
      name: 'Rust property tests (fuzz.rs)',
      status: cargo.status === 0 ? 'passed' : 'failed',
      command: cargoCommand,
      notes: cargo.status === 0 ? summary || 'cargo test succeeded' : `cargo test exited ${cargo.status}`,
      required: true,
    });
  }
} else if (process.env.CARGO_TEST_OUTCOME) {
  const outcome = process.env.CARGO_TEST_OUTCOME;
  const status = outcome === 'success' ? 'passed' : outcome === 'skipped' ? STATUS.notChecked : 'failed';
  addRow({
    name: 'Rust property tests (fuzz.rs)',
    status,
    command: cargoCommand,
    notes:
      status === 'passed'
        ? `outcome of the workflow step that ran \`${cargoCommand}\``
        : status === 'failed'
          ? `workflow step outcome: ${outcome}`
          : `workflow step was ${outcome}; the step itself gates the job`,
    required: status === 'failed',
  });
} else {
  addRow({
    name: 'Rust property tests (fuzz.rs)',
    status: STATUS.notChecked,
    command: cargoCommand,
    notes: 'not executed by this script; run with --cargo or let CI supply CARGO_TEST_OUTCOME',
    required: false,
  });
}

// ── Render ──────────────────────────────────────────────────────────────────
const counts = {
  passed: rows.filter((row) => row.status === 'passed').length,
  failed: rows.filter((row) => row.status === 'failed').length,
  notChecked: rows.filter((row) => row.status === STATUS.notChecked).length,
};
const failed = counts.failed > 0 || rows.some((row) => row.required && row.status === STATUS.notChecked);
const overall = counts.failed > 0 ? 'FAILED' : counts.notChecked > 0 ? 'INCOMPLETE' : 'PASSED';

const lock = JSON.parse(readFileSync(join(repoRoot, 'verification', 'tools.lock.json'), 'utf8'));
const toolchain = {
  z3: z3 ? toolVersion(z3, ['--version']) : null,
  tla2tools: existsSync(TLA_TOOLS)
    ? `v${lock.tla2tools.version}, sha256 ${hashFile(TLA_TOOLS)}`
    : `v${lock.tla2tools.version}, not installed`,
  java: java ? toolVersion(java, ['-version']) : null,
};

const report = [
  '# Price Oracle Verification Report',
  '',
  `- Generated: ${new Date().toISOString()}`,
  `- Revision: \`${revision}\``,
  `- Worktree: ${worktreeState}`,
  `- Produced by: \`node scripts/generate-verification-report.mjs${runCargo ? ' --cargo' : ''}\``,
  '',
  `**Overall result: ${overall}** — ${counts.passed} passed, ${counts.failed} failed, ${counts.notChecked} not checked.`,
  'A `NOT CHECKED` row means the tool did not run in this environment; it is never counted as a pass.',
  '',
  '| Check | Status | Revision | Command | Result |',
  '| --- | --- | --- | --- | --- |',
  ...rows.map(
    (row) =>
      `| ${row.name} | ${STATUS[row.status] ?? row.status} | \`${shortRevision}\` | \`${row.command}\` | ${row.notes} |`,
  ),
  '',
  '## Reproduce this report',
  '',
  '```',
  'node scripts/install-verification-tools.mjs',
  `z3 ${SMT_FILE}`,
  `java -jar ${TLA_TOOLS_PATH} -config ${TLA_CONFIG_PATH} ${TLA_FILE_PATH}`,
  cargoCommand,
  'node scripts/generate-verification-report.mjs',
  '```',
  '',
  'The exact toolchain pins (URL + SHA-256) live in `verification/tools.lock.json`.',
  'The verification scope and its known gaps are documented in',
  '`docs/formal-verification/price-oracle-guarantees.md`.',
  '',
].join('\n');

mkdirSync(REPORT_DIR, { recursive: true });
writeFileSync(join(REPORT_DIR, 'latest.md'), report, 'utf8');
writeFileSync(
  join(REPORT_DIR, 'latest.json'),
  `${JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      revision,
      worktree: worktreeState,
      invokedAs: `node scripts/generate-verification-report.mjs${runCargo ? ' --cargo' : ''}`,
      overall,
      counts,
      rows,
      toolchain,
    },
    null,
    2,
  )}\n`,
  'utf8',
);

process.stdout.write(report);
if (failed) {
  process.stderr.write('\ngenerate-verification-report: one or more required checks did not pass\n');
  process.exit(1);
}
